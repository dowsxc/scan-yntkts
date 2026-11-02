# 🛡 CachyGuard — Panduan Lengkap

> Pemindai malware lokal untuk Linux (dibuat & diuji untuk **CachyOS / Arch-based**).
> Semua proses berjalan 100% lokal — tidak ada file yang dikirim ke internet.

---

## Daftar Isi

1. [Tentang CachyGuard](#1-tentang-cachyguard)
2. [Instalasi](#2-instalasi)
3. [Menjalankan Aplikasi](#3-menjalankan-aplikasi)
4. [Cara Pakai GUI](#4-cara-pakai-gui)
5. [Mode Terminal (CLI)](#5-mode-terminal-cli)
6. [Tiga Lapis Deteksi](#6-tiga-lapis-deteksi)
7. [Heuristik Itu Apa?](#7-heuristik-itu-apa)
8. [Scan Cerdas — Jangan Scan Semua](#8-scan-cerdas--jangan-scan-semua)
9. [ClamAV: Database, Daemon & Auto-Update](#9-clamav-database-daemon--auto-update)
10. [Karantina & Restore](#10-karantina--restore)
11. [Ransomware & Backup 3-2-1](#11-ransomware--backup-3-2-1)
12. [Troubleshooting](#12-troubleshooting)
13. [Struktur File](#13-struktur-file)

---

## 1. Tentang CachyGuard

Aplikasi GUI desktop untuk memindai malware dengan **3 lapis deteksi**:

| Lapis | Sumber | Menangkap apa |
|---|---|---|
| `HASH` | Database signature lokal (SHA256) | File yang persis cocok dengan database (termasuk EICAR, file uji standar internasional) |
| `HEURISTIK` | Pola perilaku buatan sendiri | Malware **baru** yang belum ada di database mana pun |
| `CLAMAV` | Engine ClamAV (opsional) | Ratusan ribu keluarga malware yang sudah dikenal |

- **Karantina** (bukan hapus) — file bisa dipulihkan kalau salah tangkap
- **Restore & hapus permanen** lewat dialog Kelola Karantina
- Tambahan signature sendiri bisa lewat `~/.cachyguard/signatures.json`

---

## 2. Instalasi

```bash
cd ~/Unduhan/CachyGuard-v1.0    # atau folder hasil ekstrak zip
chmod +x install.sh cachyguard.py
./install.sh
```

Installer akan:
1. Menawarkan install `python`, `tk`, `clamav` via pacman
2. Menyalin aplikasi ke `~/.local/share/cachyguard/`
3. Membuat menu launcher **CachyGuard**
4. Menyiapkan database ClamAV

**Selesai install, jalankan sekali:**

```bash
sudo freshclam          # unduh database virus (±200 MB, satu kali)
```

---

## 3. Menjalankan Aplikasi

| Cara | Perintah / langkah |
|---|---|
| Menu aplikasi | Cari **CachyGuard** (kalau belum muncul, logout-login) |
| Terminal | `python3 ~/.local/share/cachyguard/cachyguard.py` |
| Uji cepat mesin | `python3 ~/.local/share/cachyguard/cachyguard.py --selftest` |
| Scan tanpa GUI | `python3 ~/.local/share/cachyguard/cachyguard.py --scan ~/Unduhan` |

Kalau status di bawah aplikasi menunjukkan:

```
✔ ClamAV tersedia — scan signature penuh aktif
```

berarti ketiga lapis deteksi aktif. Kalau `✖ ClamAV tidak ditemukan`,
lihat bagian [Troubleshooting](#12-troubleshooting).

---

## 4. Cara Pakai GUI

1. **Direktori** — ketik atau pilih folder yang mau discan
   (mulai dari `~/Unduhan` dulu, jangan langsung `~`)
2. Opsi:
   - **File tersembunyi** — sertakan file titik (`.`) — biarkan aktif
   - **Pakai ClamAV** — aktif otomatis kalau ClamAV terpasang
3. Klik **▶ Mulai Scan** — bar biru = progres, temuan langsung masuk tabel
4. Baca kolom **Sumber** dan **Tingkat**:
   - 🔴 **TINGGI** — segera periksa (hash cocok malware / reverse shell / ClamAV)
   - 🟡 **SEDANG** — pola mencurigakan, bisa false positive — baca dulu
5. Pilih baris → **🔒 Karantina Pilihan**, atau **Karantina Semua Temuan**
6. Salah tangkap? **📦 Kelola Karantina** → **↩ Pulihkan**

---

## 5. Mode Terminal (CLI)

```bash
# scan folder, hasil teks
python3 ~/.local/share/cachyguard/cachyguard.py --scan ~/Unduhan

# paksa tanpa ClamAV (hanya hash + heuristik)
python3 ~/.local/share/cachyguard/cachyguard.py --scan ~/Unduhan --no-clamav

# selftest: buat file uji, pastikan semua terdeteksi
python3 ~/.local/share/cachyguard/cachyguard.py --selftest
```

Keluaran CLI contoh:

```
[TINGGI ] [HEURISTIK] /home/nix/Unduhan/evil.sh
           -> Pola reverse shell bash (/dev/tcp/IP/PORT)
Selesai: 1 temuan.
```

---

## 6. Tiga Lapis Deteksi

### HASH (persis)
SHA256 file dicocokkan dengan database. Akurat 100%, tapi hanya untuk file
yang **persis sama** dengan yang sudah dikenal.

Tambah signature sendiri — buat `~/.cachyguard/signatures.json`:

```json
{
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "contoh: EICAR"
}
```

### HEURISTIK (pola)
Deteksi **pola perilaku berbahaya** — bisa menangkap malware baru.
Lihat bagian berikutnya.

### CLAMAV (lengkap)
Database ratusan ribu signature malware sungguhan dari jutaan sampel
(Skandal jutaan sampel, update tiap hari via freshclam). Ini lapis terkuat.

---

## 7. Heuristik Itu Apa?

**Analogi**: signature = foto pelaku lama di database polisi;
heuristik = petugas yang curiga pada **perilaku** (orang bermasker tengah malam
bawa linggis — belum tentu maling, tapi wajar dicurigai).

Pola yang dicek CachyGuard:

| Pola | Kenapa curiga |
|---|---|
| `/dev/tcp/IP/PORT` di script | Ciri **reverse shell** — pintu belakang ke penyerang |
| `nc -e /bin/sh` | Netcat reverse shell |
| `socket` + `dup2` + `/bin/sh` (Python) | Reverse shell Python |
| `base64 -d ... \| sh` | Perintah **disamarkan** lalu dieksekusi |
| `curl/wget ... \| sh` | Unduh & eksekusi langsung tanpa review |
| `invoice.pdf.sh` | **Ekstensi ganda** — menyamar jadi dokumen |
| Executable di `~/.cache`, `/tmp` | Tempat favorit malware sembunyi |
| Executable tersembunyi (awalan titik) > 512 KB | Menyamar sebagai file sistem |
| `rm -rf /` | Perintah destruktif |
| `eval(atob(...))` / `exec(base64.b64decode(...))` | Kode terenkode dieksekusi |

**Kelemahan heuristik**: false positive. Installer resmi pun sering pakai
`curl | sh`. Makanya hasilnya diberi tingkat dan kamu yang memutuskan.

---

## 8. Scan Cerdas — Jangan Scan Semua

⚠️ Scan seluruh `~` (bisa 1,7 juta file) makan **berjam-jam**. Malware masuk
lewat file yang kamu **unduh/jalankan**, jadi scan folder yang berisiko saja:

| Prioritas | Folder | Alasan |
|---|---|---|
| 1 | `~/Unduhan` | Semua file internet masuk sini |
| 2 | `~/Desktop` | File yang sering dibuka |
| 3 | `/tmp` | File sementara, tempat nyembunyiian |

**Skip saja** (sudah diverifikasi package manager, jutaan file kecil):
`node_modules`, `.cargo`, `venv`, `~/.cache/pip`, cache pacman.

Aturan praktis: **scan targeted = menit-menit, cakupan 95%+ risiko.**

---

## 9. ClamAV: Database, Daemon & Auto-Update

### Unduh database (wajib sekali)

```bash
sudo freshclam
```

### Auto-update database

```bash
systemctl list-unit-files | grep -i clam   # lihat unit yang tersedia
sudo systemctl enable --now clamav-freshclam.service
```

### Daemon ClamAV (scan 10–50x lebih cepat)

```bash
sudo systemctl enable --now clamav-daemon.socket
```

Supaya aplikasi memakai daemon (lewati masalah izin file di home), jalankan
patch satu baris ini:

```bash
python3 -c "p='$HOME/.local/share/cachyguard/cachyguard/engine.py'; s=open(p).read(); s=s.replace('\"--infected\", \"--no-summary\", \"--\"', '\"--infected\", \"--no-summary\", \"--fdpass\", \"--\"'); open(p,'w').write(s); print('PATCH OK')"
```

Uji daemon:

```bash
clamdscan --fdpass ~/Unduhan
```

> Scan pertama setelah daemon nyala agak lama (database dimuat ke RAM
> ±1–2 menit), scan berikutnya jauh lebih cepat.

---

## 10. Karantina & Restore

- File dikarantina = **dipindah** ke `~/.cachyguard/quarantine/`
  dengan permission `000` (tidak bisa dibuka/dijalankan apa pun)
- Metadata disimpan di `metadata.json` (lokasi asal, alasan, waktu)
- **Pulihkan**: GUI → 📦 Kelola Karantina → pilih → **↩ Pulihkan**
- **Hapus permanen**: GUI → 📦 Kelola Karantina → **🗑 Hapus Permanen**
  (tidak bisa dibatalkan!)

---

## 11. Ransomware & Backup 3-2-1

Ransomware = malware yang **mengenkripsi filemu lalu memeras tebusan**.
Siklusnya: masuk (phishing/dropper) → cari file → enkripsi (AES+RSA) →
hapus backup → catatan pemerasan.

Yang terdeteksi CachyGuard:
- ✅ Keluarga ransomware **dikenal** → ClamAV signature
- ✅ Dropper/instalernya (reverse shell, `curl | sh`) → heuristik
- ❌ Ransomware **baru** → butuh proteksi perilaku real-time (di luar
  cakupan scanner statis)

**Pertahanan terkuat = backup 3-2-1**:
- **3** salinan data
- **2** media berbeda (laptop + HDD eksternal)
- **1** salinan di luar lokasi (cloud, HDD yang tidak selalu tersambung)

Ransomware tidak bisa memeras orang yang punya backup.

---

## 12. Troubleshooting

| Masalah | Solusi |
|---|---|
| `No module named tkinter` | `sudo pacman -S tk` |
| Status: ClamAV tidak ditemukan padahal sudah install | Restart aplikasi; cek `which clamscan` |
| `Unit freshclam.timer does not exist` | Nama unit di Arch: `clamav-freshclam.service` — `sudo systemctl enable --now clamav-freshclam.service` |
| Scan lama sekali | Scan folder target saja (bagian 8); aktifkan daemon (bagian 9) |
| Temuan SEDANG tapi file-nya installer resmi | False positive heuristik — abaikan / jangan karantina |
| File terkarantina ternyata penting | 📦 Kelola Karantina → ↩ Pulihkan |
| Menu CachyGuard tidak muncul | Logout-login, atau jalankan lewat terminal |
| Mau hapus aplikasi | `rm -rf ~/.local/share/cachyguard ~/.cachyguard ~/.local/share/applications/cachyguard.desktop` |

---

## 13. Struktur File

```
~/.local/share/cachyguard/          # aplikasi terpasang
├── cachyguard.py                   # launcher (GUI / CLI / selftest)
└── cachyguard/
    ├── engine.py                   # mesin deteksi + karantina
    └── gui.py                      # antarmuka Tkinter

~/.cachyguard/
├── quarantine/                     # file terkarantina (permission 000)
│   └── metadata.json               # catatan lokasi asal & alasan
└── signatures.json                 # (opsional) hash tambahan buatanmu

~/.local/share/applications/cachyguard.desktop   # menu launcher
```

---

*CachyGuard v1.0 — dibuat untuk keamanan defensif pribadi. Alat pencegahan,
bukan jaminan 100%. Kombinasikan dengan update sistem rutin (`sudo pacman -Syu`)
dan backup 3-2-1.* 🛡
