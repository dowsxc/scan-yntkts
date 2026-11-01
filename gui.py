#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CachyGuard — Antarmuka GUI (Tkinter)."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import engine
from .engine import Scanner, Finding, SEVERITY_ORDER

BG = "#0f172a"        # biru gelap
PANEL = "#1e293b"
FG = "#e2e8f0"
ACCENT = "#22d3ee"
DANGER = "#f87171"
WARN = "#fbbf24"
OK = "#4ade80"

SEV_COLOR = {"TINGGI": DANGER, "SEDANG": WARN, "RENDAH": "#94a3b8"}


class CachyGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{engine.APP_NAME} v{engine.APP_VERSION} — "
                   "Pemindai Malware untuk Linux")
        self.geometry("980x640")
        self.minsize(820, 520)
        self.configure(bg=BG)
        self._q: queue.Queue = queue.Queue()
        self._scanner: Scanner | None = None
        self._last_findings: dict[str, Finding] = {}

        self._build_style()
        self._build_ui()
        self._poll_queue()
        self.after(200, self._update_clamav_status)

    # ------------------------------------------------------------------ #
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=FG,
                        fieldbackground=PANEL, borderwidth=0)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Sans", 10))
        style.configure("Title.TLabel", font=("Sans", 16, "bold"),
                        foreground=ACCENT, background=BG)
        style.configure("Status.TLabel", background=BG, foreground="#94a3b8")
        style.configure("TButton", background=PANEL, foreground=FG,
                        padding=8, font=("Sans", 10, "bold"))
        style.map("TButton",
                  background=[("active", "#334155")],
                  foreground=[("active", ACCENT)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#082f49")
        style.map("Accent.TButton",
                  background=[("active", "#67e8f9")],
                  foreground=[("active", "#082f49")])
        style.configure("Danger.TButton", background="#7f1d1d", foreground=FG)
        style.map("Danger.TButton", background=[("active", "#b91c1c")])
        style.configure("TCheckbutton", background=BG, foreground=FG)
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("TProgressbar", troughcolor=PANEL,
                        background=ACCENT, borderwidth=0)
        style.configure("Treeview", background=PANEL, foreground=FG,
                        fieldbackground=PANEL, rowheight=26, font=("Sans", 9))
        style.configure("Treeview.Heading", background="#334155",
                        foreground=FG, font=("Sans", 9, "bold"))
        style.map("Treeview", background=[("selected", "#155e75")])

    # ------------------------------------------------------------------ #
    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        # ---- Judul -------------------------------------------------------
        ttk.Label(self, text="🛡 CachyGuard", style="Title.TLabel"
                  ).pack(anchor="w", **pad)
        ttk.Label(self, text="Pemindai malware lokal — hash, heuristik & "
                             "ClamAV. Semua proses berjalan di komputermu.",
                  style="Status.TLabel").pack(anchor="w", padx=12)

        # ---- Baris pilihan ------------------------------------------------
        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Direktori:").pack(side="left")
        self.path_var = tk.StringVar(value=str(engine.Path.home() / "Downloads"))
        ttk.Entry(top, textvariable=self.path_var, width=52).pack(
            side="left", padx=6, ipady=3)
        ttk.Button(top, text="Pilih…", command=self._choose_dir
                   ).pack(side="left")

        self.hidden_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="File tersembunyi",
                        variable=self.hidden_var).pack(side="left", padx=(12, 0))
        self.clamav_var = tk.BooleanVar(value=True)
        self.clamav_check = ttk.Checkbutton(top, text="Pakai ClamAV",
                                            variable=self.clamav_var)
        self.clamav_check.pack(side="left", padx=(12, 0))

        # ---- Kontrol & progres ---------------------------------------------
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", **pad)
        self.btn_start = ttk.Button(ctrl, text="▶  Mulai Scan",
                                    style="Accent.TButton",
                                    command=self._start_scan)
        self.btn_start.pack(side="left")
        self.btn_cancel = ttk.Button(ctrl, text="■  Batal",
                                     style="Danger.TButton",
                                     command=self._cancel_scan, state="disabled")
        self.btn_cancel.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(ctrl, mode="determinate", length=380)
        self.progress.pack(side="left", padx=12, fill="x", expand=True)

        self.status_var = tk.StringVar(value="Siap. Pilih direktori lalu klik Mulai Scan.")
        ttk.Label(self, textvariable=self.status_var,
                  style="Status.TLabel").pack(anchor="w", padx=12)

        self.clamav_status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.clamav_status_var,
                  style="Status.TLabel").pack(anchor="w", padx=12)

        # ---- Tabel hasil -----------------------------------------------------
        table = ttk.Frame(self)
        table.pack(fill="both", expand=True, **pad)
        cols = ("file", "deteksi", "sumber", "tingkat")
        self.tree = ttk.Treeview(table, columns=cols, show="headings",
                                 selectmode="extended")
        for col, text, w in (("file", "File", 420), ("deteksi", "Deteksi", 240),
                             ("sumber", "Sumber", 90), ("tingkat", "Tingkat", 80)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="w",
                             stretch=(col == "file"))
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")
        self.tree.tag_configure("TINGGI", foreground=DANGER)
        self.tree.tag_configure("SEDANG", foreground=WARN)
        self.tree.tag_configure("RENDAH", foreground="#94a3b8")

        # ---- Tombol aksi -------------------------------------------------------
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        ttk.Button(bottom, text="🔒  Karantina Pilihan",
                   command=self._quarantine_selected).pack(side="left")
        ttk.Button(bottom, text="🔒  Karantina Semua Temuan",
                   command=self._quarantine_all).pack(side="left", padx=8)
        ttk.Button(bottom, text="📦  Kelola Karantina…",
                   command=self._open_quarantine_manager).pack(side="left")
        self.summary_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.summary_var,
                  style="Status.TLabel").pack(side="right")

    # ------------------------------------------------------------------ #
    # Aksi pengguna
    # ------------------------------------------------------------------ #
    def _choose_dir(self):
        d = filedialog.askdirectory(title="Pilih direktori yang akan discan",
                                    initialdir=str(engine.Path.home()))
        if d:
            self.path_var.set(d)

    def _start_scan(self):
        root = self.path_var.get().strip()
        if not root:
            messagebox.showwarning("CachyGuard", "Pilih direktori dulu ya.")
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._last_findings.clear()
        self.summary_var.set("")
        self.progress["value"] = 0
        self.btn_start["state"] = "disabled"
        self.btn_cancel["state"] = "normal"

        self._scanner = Scanner(
            on_phase=lambda p: self._q.put(("phase", p)),
            on_progress=lambda d, t, cur: self._q.put(("progress", d, t, cur)),
            on_finding=lambda f: self._q.put(("finding", f)),
            on_done=lambda s: self._q.put(("done", s)),
        )
        threading.Thread(
            target=self._scanner.scan,
            args=(root,),
            kwargs={"include_hidden": self.hidden_var.get(),
                    "use_clamav": self.clamav_var.get()},
            daemon=True).start()

    def _cancel_scan(self):
        if self._scanner:
            self._scanner.cancel()
            self.status_var.set("Membatalkan…")

    # ------------------------------------------------------------------ #
    # Poll hasil dari thread scanner
    # ------------------------------------------------------------------ #
    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "phase":
                    self.status_var.set(msg[1])
                elif kind == "progress":
                    _, done, total, cur = msg
                    self.progress["maximum"] = max(total, 1)
                    self.progress["value"] = done
                    self.status_var.set(f"{done}/{total}  {cur}")
                elif kind == "finding":
                    self._add_finding(msg[1])
                elif kind == "done":
                    self._scan_done(msg[1])
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _add_finding(self, f: Finding):
        self._last_findings[f.path] = f
        name = f.path.rsplit("/", 1)[-1]
        self.tree.insert("", "end", iid=f.path,
                         values=(f.path, f.name, f.source, f.severity),
                         tags=(f.severity,))

    def _scan_done(self, stats: dict):
        self.btn_start["state"] = "normal"
        self.btn_cancel["state"] = "disabled"
        if stats.get("error"):
            self.status_var.set(f"Error: {stats['error']}")
            messagebox.showerror("CachyGuard", stats["error"])
            return
        n, findings = stats.get("files", 0), stats.get("findings", 0)
        engine_flag = ("ClamAKTIF" if stats.get("clamav") else "ClamAV tidak aktif")
        engine_flag = engine_flag.replace("ClamAKTIF", "ClamAV AKTIF")
        secs = stats.get("seconds", 0)
        self.status_var.set(
            f"Selesai — {n} file diperiksa dalam {secs} detik "
            f"({engine_flag}, {stats.get('signatures', 0)} signature lokal)")
        self.summary_var.set(f"Temuan: {findings}")
        if findings == 0:
            messagebox.showinfo(
                "Scan selesai",
                f"Tidak ada temuan. {n} file diperiksa.\n\n"
                "Catatan: deteksi lokal bersifat pencegahan, bukan jaminan "
                "100%. Pastikan ClamAV terinstall & database-nya segar "
                "(sudo freshclam) untuk perlindungan penuh.")
        else:
            messagebox.showwarning(
                "Scan selesai",
                f"{findings} temuan dari {n} file.\n\n"
                "Periksa tabel hasil. Temuan HEURISTIK bisa jadi false "
                "positive — baca kolom Deteksi dulu sebelum dikarantina.")

    # ------------------------------------------------------------------ #
    # Karantina
    # ------------------------------------------------------------------ #
    def _quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Karantina", "Pilih baris di tabel dulu.")
            return
        self._do_quarantine(sel)

    def _quarantine_all(self):
        items = list(self._last_findings.keys())
        if not items:
            messagebox.showinfo("Karantina", "Belum ada temuan.")
            return
        if not messagebox.askyesno(
                "Karantina semua",
                f"Karantina {len(items)} file?\n\n"
                "File dipindah (bukan dihapus) dan bisa dipulihkan lewat "
                "'Kelola Karantina'."):
            return
        self._do_quarantine(items, ask=False)

    def _do_quarantine(self, paths: list[str], ask: bool = True):
        if ask and not messagebox.askyesno(
                "Karantina",
                f"Karantina {len(paths)} file?\n\n"
                "File dipindah (bukan dihapus) dan bisa dipulihkan."):
            return
        pairs = [(p, self._last_findings[p].name) for p in paths
                 if p in self._last_findings]
        moved = engine.quarantine_files(pairs)
        for entry in moved:
            self.tree.delete(entry["original_path"])
            self._last_findings.pop(entry["original_path"], None)
        messagebox.showinfo(
            "Karantina",
            f"{len(moved)} file dikarantina di:\n{engine.QUARANTINE_DIR}\n\n"
            "File tidak dihapus — buka 'Kelola Karantina' untuk memulihkan "
            "atau menghapus permanen.")

    def _open_quarantine_manager(self):
        QuarantineManager(self)

    # ------------------------------------------------------------------ #
    def _update_clamav_status(self):
        clam = engine.find_clamscan()
        if clam:
            self.clamav_status_var.set(
                f"✔ ClamAV tersedia ({clam.split('/')[-1]}) — "
                "scan signature penuh aktif")
            self.clamav_check["state"] = "normal"
        else:
            self.clamav_status_var.set(
                "✖ ClamAV tidak ditemukan — hanya hash + heuristik. "
                "Install: sudo pacman -S clamav && sudo freshclam")
            self.clamav_check["state"] = "disabled"
            self.clamav_var.set(False)


class QuarantineManager(tk.Toplevel):
    """Dialog kelola karantina: pulihkan / hapus permanen."""

    def __init__(self, master):
        super().__init__(master)
        self.title("Kelola Karantina")
        self.geometry("760x420")
        self.configure(bg=BG)
        ttk.Label(self, text="📦 Isi Karantina", style="Title.TLabel"
                  ).pack(anchor="w", padx=12, pady=8)

        cols = ("file", "asal", "alasan", "waktu")
        self.tree = ttk.Treeview(self, columns=cols, show="headings",
                                 selectmode="extended")
        for col, text, w in (("file", "Nama", 200), ("asal", "Lokasi Asal", 240),
                             ("alasan", "Alasan", 180), ("waktu", "Waktu", 120)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w)
        self.tree.pack(fill="both", expand=True, padx=12)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=12, pady=8)
        ttk.Button(btns, text="↩  Pulihkan", command=self._restore
                   ).pack(side="left")
        ttk.Button(btns, text="🗑  Hapus Permanen", style="Danger.TButton",
                   command=self._delete).pack(side="left", padx=8)
        ttk.Button(btns, text="Tutup", command=self.destroy).pack(side="right")

        self.refresh()

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._meta = {e["quar_name"]: e for e in engine.list_quarantine()}
        for qname, e in self._meta.items():
            self.tree.insert("", "end", iid=qname, values=(
                e.get("quar_name", ""),
                e.get("original_path", ""),
                e.get("reason", ""),
                e.get("quarantined_at", "")))

    def _selected(self) -> list[str]:
        return self.tree.selection()

    def _restore(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo("Pulihkan", "Pilih item dulu.", parent=self)
            return
        ok = sum(1 for q in sel if engine.restore_quarantined(q))
        messagebox.showinfo("Pulihkan",
                            f"{ok} file dipulihkan ke lokasi asalnya.",
                            parent=self)
        self.refresh()

    def _delete(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo("Hapus", "Pilih item dulu.", parent=self)
            return
        if not messagebox.askyesno(
                "Hapus permanen",
                f"Hapus {len(sel)} file secara PERMANEN?\n\n"
                "Tindakan ini tidak bisa dibatalkan.", parent=self):
            return
        ok = sum(1 for q in sel if engine.delete_quarantined(q))
        messagebox.showinfo("Hapus", f"{ok} file dihapus permanen.",
                            parent=self)
        self.refresh()


def main():
    app = CachyGuardApp()
    app.mainloop()
