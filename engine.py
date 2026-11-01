#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CachyGuard — Mesin pemindai malware (lapisan deteksi lokal).

Tiga lapis deteksi:
1. HASH      : SHA256 file dicocokkan dengan database signature lokal
               (bisa ditambah pengguna lewat ~/.cachyguard/signatures.json).
2. HEURISTIK : Pola konten & nama file yang mencurigakan
               (reverse shell, curl|sh, ekstensi ganda, executable tersembunyi).
3. CLAMAV    : Engine ClamAV (opsional) untuk database signature lengkap.

Semua pemrosesan terjadi LOKAL di komputermu — tidak ada file yang dikirim
ke mana pun.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

APP_NAME = "CachyGuard"
APP_VERSION = "1.0"

QUARANTINE_DIR = Path.home() / ".cachyguard" / "quarantine"
QUARANTINE_META = QUARANTINE_DIR / "metadata.json"
SIGNATURE_FILE = Path.home() / ".cachyguard" / "signatures.json"

# Batas ukuran file yang ikut dihitung hash & dibaca isinya.
MAX_HASH_SIZE = 64 * 1024 * 1024      # 64 MB
MAX_TEXT_READ = 2 * 1024 * 1024       # 2 MB

# ---------------------------------------------------------------------------
# Database hash bawaan.
# CATATAN JUJUR: database bawaan sengaja kecil dan hanya berisi hash yang
# terverifikasi (file uji EICAR). Deteksi malware lengkap diserahkan pada
# ClamAV. Pengguna bisa menambah entri sendiri di ~/.cachyguard/signatures.json
# ---------------------------------------------------------------------------
KNOWN_BAD_SHA256 = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR-Test-File (file uji antivirus standar internasional)",
}

# Ekstensi yang isinya layak dibaca sebagai teks untuk pengecekan heuristik.
TEXT_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".fish", ".py", ".pl", ".rb", ".php", ".js",
    ".ts", ".txt", ".conf", ".cfg", ".ini", ".service", ".desktop", ".timer",
    ".yaml", ".yml", ".json", ".md", ".lua", ".awk", ".c", ".cpp", ".h",
}

# Pola konten berbahaya: (regex, deskripsi, tingkat)
SUSPICIOUS_PATTERNS = [
    (re.compile(r"/dev/tcp/[0-9a-zA-Z\.]+/\d+", re.I),
     "Pola reverse shell bash (/dev/tcp/IP/PORT)", "TINGGI"),
    (re.compile(r"\bnc\b[^#\n]*-e\s+/bin/(?:ba)?sh", re.I),
     "Netcat reverse shell (nc -e /bin/sh)", "TINGGI"),
    (re.compile(r"base64\s+(?:-d|-decode|--decode)\b[^#\n]{0,200}\|\s*(?:ba)?sh\b", re.I),
     "Eksekusi perintah hasil dekode base64", "TINGGI"),
    (re.compile(r"os\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)", re.I),
     "Pengalihan stdin/stdout ke socket (ciri reverse shell Python)", "TINGGI"),
    (re.compile(r"pty\.spawn\s*\(\s*[\"'](?:/bin/)?(?:ba)?sh[\"']", re.I),
     "Spawn shell lewat pty (ciri reverse shell Python)", "TINGGI"),
    (re.compile(r"(?:curl|wget)\s+[^#\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.I),
     "Unduh lalu langsung eksekusi script dari internet (curl|sh)", "SEDANG"),
    (re.compile(r"rm\s+-rf\s+/(?:\s|$)", re.I),
     "Perintah destruktif rm -rf /", "SEDANG"),
    (re.compile(r"\bcrontab\b[^#\n]{0,80}\b(?:curl|wget)\b", re.I),
     "Pendaftaran cron yang mengunduh sesuatu", "SEDANG"),
    (re.compile(r"\bexec\s*\(\s*base64\.b64decode\s*\(", re.I),
     "Eksekusi kode hasil dekode base64 (Python)", "SEDANG"),
    (re.compile(r"\beval\s*\(\s*atob\s*\(", re.I),
     "Eksekusi kode hasil dekode base64 (JavaScript)", "SEDANG"),
]

# Kombinasi kata kunci yang bersama-sama menandakan reverse shell Python.
SHELL_COMBO_TOKENS = ("socket", "subprocess", "/bin/sh", "/bin/bash")

DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|mp3|mp4|avi)"
    r"\.(?:sh|exe|bin|py|scr|bat|cmd|jar)$", re.I)

SEVERITY_ORDER = {"TINGGI": 3, "SEDANG": 2, "RENDAH": 1}


@dataclass
class Finding:
    """Satu temuan pemindaian."""
    path: str
    source: str          # "HASH" | "HEURISTIK" | "CLAMAV"
    name: str            # nama deteksi
    severity: str        # TINGGI | SEDANG | RENDAH
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def load_user_signatures() -> dict:
    """Muat database hash tambahan dari ~/.cachyguard/signatures.json."""
    db: dict = {}
    if SIGNATURE_FILE.is_file():
        try:
            data = json.loads(SIGNATURE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                db = {str(k).lower(): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError):
            pass
    return db


def find_clamscan() -> str | None:
    """Cari binary clamscan. Prioritaskan clamdscan (lebih cepat)."""
    for name in ("clamdscan", "clamscan"):
        path = shutil.which(name)
        if path:
            return path
    return None


def sha256_of(path: Path) -> str | None:
    """Hitung SHA256 secara streaming. None kalau gagal dibaca."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def looks_like_text(path: Path) -> bool:
    """Tebak kasar: file ini teks atau bukan (cek 1 KB pertama)."""
    try:
        with path.open("rb") as f:
            head = f.read(1024)
    except OSError:
        return False
    if b"\x00" in head:
        return False
    if not head:
        return True
    printable = sum(b in (9, 10, 13) or 32 <= b < 127 or b >= 128 for b in head)
    return printable / len(head) > 0.85


class Scanner:
    """Pemindai direktori dengan callback progres + dukungan pembatalan.

    Callback yang dipanggil (dari thread scanner):
      on_phase(phase_str)                        -> ganti fase
      on_progress(done, total, current_path)     -> progres per file
      on_finding(finding: Finding)               -> ada temuan
      on_done(stats_dict)                        -> selesai
    """

    def __init__(self, on_phase=None, on_progress=None,
                 on_finding=None, on_done=None):
        self.on_phase = on_phase or (lambda *a: None)
        self.on_progress = on_progress or (lambda *a: None)
        self.on_finding = on_finding or (lambda *a: None)
        self.on_done = on_done or (lambda *a: None)
        self.cancelled = False
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------ #
    def cancel(self):
        self.cancelled = True

    # ------------------------------------------------------------------ #
    def scan(self, root: str | os.PathLike, *, include_hidden: bool = True,
             use_clamav: bool = True):
        root = Path(root).expanduser().resolve()
        stats = {"files": 0, "findings": 0, "clamav": False,
                 "start": time.time(), "root": str(root)}

        if not root.exists():
            stats["error"] = f"Direktori tidak ditemukan: {root}"
            self.on_done(stats)
            return

        user_db = load_user_signatures()
        sig_count = len(KNOWN_BAD_SHA256) + len(user_db)

        # ---- Fase 1: hitung total file untuk progress bar ----------------
        self.on_phase("Menghitung file…")
        all_files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if self.cancelled:
                break
            if not include_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fn in filenames:
                if not include_hidden and fn.startswith("."):
                    continue
                all_files.append(Path(dirpath) / fn)
        total = len(all_files)

        # ---- Fase 2: hash + heuristik ------------------------------------
        self.on_phase(f"Scan heuristik & hash ({total} file)…")
        clamav_candidates: list[str] = []
        for done, path in enumerate(all_files, 1):
            if self.cancelled:
                break
            self.on_progress(done, total, str(path))
            self._check_file(path, user_db, clamav_candidates)
        stats["files"] = total

        # ---- Fase 3: ClamAV (opsional) ------------------------------------
        if use_clamav and not self.cancelled:
            clamscan = find_clamscan()
            if clamscan and clamav_candidates:
                stats["clamav"] = True
                self._clamav_scan(clamscan, clamav_candidates)

        # ---- Selesai -------------------------------------------------------
        stats["findings"] = len(self.findings)
        stats["signatures"] = sig_count
        stats["seconds"] = round(time.time() - stats["start"], 1)
        self.on_done(stats)

    # ------------------------------------------------------------------ #
    def _check_file(self, path: Path, user_db: dict, clamav_candidates: list):
        try:
            st = path.lstat()
        except OSError:
            return
        if not stat_ok(st):
            return  # symlink, socket, dsb — lewati
        size = st.st_size
        name = path.name

        # -- Lapis HASH ----------------------------------------------------
        if 0 < size <= MAX_HASH_SIZE:
            digest = sha256_of(path)
            if digest:
                label = user_db.get(digest) or KNOWN_BAD_SHA256.get(digest)
                if label:
                    self._emit(Finding(str(path), "HASH", label, "TINGGI",
                                       f"SHA256 cocok: {digest[:16]}…"))
                    return  # sudah pasti — tidak perlu heuristik

        # -- Lapis HEURISTIK ------------------------------------------------
        severity_found: str | None = None

        # 2a. Ekstensi ganda (file.pdf.sh, invoice.doc.exe)
        if DOUBLE_EXT_RE.search(name):
            self._emit(Finding(str(path), "HEURISTIK",
                               "Ekstensi ganda mencurigakan", "SEDANG",
                               "Nama file menyamar sebagai dokumen/gambar "
                               "tetapi sebenarnya script/executable"))
            severity_found = "SEDANG"

        # 2b. File executable tersembunyi berukuran besar
        if (name.startswith(".") and os.access(path, os.X_OK)
                and size > 512 * 1024):
            self._emit(Finding(str(path), "HEURISTIK",
                               "Executable tersembunyi berukuran besar",
                               "SEDANG",
                               f"Ukuran {size // 1024} KB, permission "
                               "executable, nama diawali titik"))
            severity_found = "SEDANG"

        # 2c. Executable di dalam folder cache/tmp
        lowered = str(path).lower()
        if (os.access(path, os.X_OK) and size > 0 and not path.is_dir()
                and ("/.cache/" in lowered or "/tmp/" in lowered)):
            self._emit(Finding(str(path), "HEURISTIK",
                               "Program executable di folder cache/tmp",
                               "SEDANG",
                               "Tempat favorit malware menyembunyikan diri"))
            severity_found = "SEDANG"

        # 2d. Isi script mencurigakan
        if size <= MAX_TEXT_READ and (
                path.suffix.lower() in TEXT_EXTENSIONS or looks_like_text(path)):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            for rx, desc, sev in SUSPICIOUS_PATTERNS:
                if rx.search(text):
                    self._emit(Finding(str(path), "HEURISTIK", desc, sev,
                                       "Pola ditemukan di isi file"))
                    severity_found = sev
            # Kombinasi token reverse shell Python
            low = text.lower()
            if ("socket" in low and "dup2" in low
                    and ("/bin/sh" in low or "/bin/bash" in low)):
                self._emit(Finding(str(path), "HEURISTIK",
                                   "Reverse shell Python (socket+dup2+shell)",
                                   "TINGGI", "Kombinasi token berbahaya"))
                severity_found = "TINGGI"

        # Kirim ke ClamAV (semua file biasa, batas 64 MB)
        if size <= MAX_HASH_SIZE:
            clamav_candidates.append(str(path))

    # ------------------------------------------------------------------ #
    def _clamav_scan(self, clamscan: str, files: list[str]):
        self.on_phase(f"ClamAV memindai {len(files)} file… "
                      "(bisa memakan waktu)")
        # clamscan hanya menerima ~ribuan argumen; pecah per batch.
        BATCH = 500
        for i in range(0, len(files), BATCH):
            if self.cancelled:
                return
            batch = files[i:i + BATCH]
            cmd = [clamscan, "--infected", "--no-summary", "--"] + batch
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=3600)
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                # Format clamscan: /path/file: Nama-Signature FOUND
                if line.endswith("FOUND") and ": " in line:
                    fpath, _, rest = line.rpartition(": ")
                    sig = rest[:-6].strip() or "Signature ClamAV"
                    self._emit(Finding(fpath, "CLAMAV", sig, "TINGGI",
                                       "Terdeteksi oleh database ClamAV"))

    # ------------------------------------------------------------------ #
    def _emit(self, finding: Finding):
        self.findings.append(finding)
        self.on_finding(finding)


def stat_ok(st: os.stat_result) -> bool:
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


# ===========================================================================
# KARANTINA
# ===========================================================================
def _load_meta() -> list:
    if QUARANTINE_META.is_file():
        try:
            return json.loads(QUARANTINE_META.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_meta(items: list):
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_META.write_text(json.dumps(items, indent=2, ensure_ascii=False),
                               encoding="utf-8")


def quarantine_files(paths_with_reason: list[tuple[str, str]]) -> list[dict]:
    """Pindahkan file ke karantina (permission 000) + simpan metadata.

    Return daftar entri yang berhasil dikarantina.
    """
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    meta = _load_meta()
    moved = []
    stamp = int(time.time())
    for i, (path, reason) in enumerate(paths_with_reason):
        src = Path(path)
        if not src.is_file():
            continue
        try:
            st = src.stat()
            qname = f"{stamp}_{i:03d}_{src.name}.quar"
            dest = QUARANTINE_DIR / qname
            shutil.move(str(src), dest)
            os.chmod(dest, 0o000)  # matikan semua permission
            entry = {
                "quar_name": qname,
                "original_path": str(src),
                "reason": reason,
                "size": st.st_size,
                "mode": oct(st.st_mode),
                "mtime": st.st_mtime,
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            meta.append(entry)
            moved.append(entry)
        except OSError:
            continue
    _save_meta(meta)
    return moved


def list_quarantine() -> list[dict]:
    """Daftar isi karantina (hanya yang file-nya masih ada)."""
    meta = _load_meta()
    alive = []
    for e in meta:
        if (QUARANTINE_DIR / e.get("quar_name", "")).is_file():
            alive.append(e)
    return alive


def restore_quarantined(quar_name: str) -> bool:
    """Kembalikan file dari karantina ke lokasi asalnya."""
    meta = _load_meta()
    entry = next((e for e in meta if e.get("quar_name") == quar_name), None)
    if entry is None:
        return False
    src = QUARANTINE_DIR / quar_name
    dest = Path(entry["original_path"])
    if not src.is_file():
        return False
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(src, 0o600)  # supaya bisa dipindah kembali
        shutil.move(str(src), dest)
        try:
            os.chmod(dest, int(entry.get("mode", "0o600"), 8))
        except (ValueError, OSError):
            pass
        meta = [e for e in meta if e.get("quar_name") != quar_name]
        _save_meta(meta)
        return True
    except OSError:
        return False


def delete_quarantined(quar_name: str) -> bool:
    """Hapus permanen file dari karantina."""
    meta = _load_meta()
    src = QUARANTINE_DIR / quar_name
    try:
        if src.is_file():
            os.chmod(src, 0o600)
            src.unlink()
        meta = [e for e in meta if e.get("quar_name") != quar_name]
        _save_meta(meta)
        return True
    except OSError:
        return False
