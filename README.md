<h1 align="center">🎯 Verdamt-Snipe v1.3.0 NEXUS</h1>
<h4 align="center">Framework Keamanan Web Async-First, Playwright Automation Engine & Vulnerability Assessment</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg">
  <img src="https://img.shields.io/badge/Playwright-10--Module%20Suite-green.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/Powered%20by-AsyncIO-orange.svg">
</p>

<p align="center">
  <a href="#-ringkasan-cepat">Ringkasan</a> •
  <a href="#-fitur-utama">Fitur Utama</a> •
  <a href="#-playwright-security-suite-10-modul">Playwright Suite</a> •
  <a href="#%EF%B8%8F-cara-install">Instalasi</a> •
  <a href="#-cara-penggunaan">Cara Pakai</a> •
  <a href="#-opsec--safety">OpSec & Audit</a>
</p>

---

## 🎯 Ringkasan Cepat

**Verdamt-Snipe** adalah framework audit keamanan web modern yang menggabungkan kecepatan **Python AsyncIO** dengan kedalaman otomasi browser **Playwright Chromium**:

1. **Apa ini?** — Tool pemindaian dan verifikasi keamanan web asinkron dengan 10 modul Playwright terintegrasi.
2. **Untuk apa?** — Digunakan oleh Penetration Tester dan Bug Bounty Hunter untuk menemukan, memvalidasi PoC (Proof-of-Concept), dan menganalisis Single Page Application (SPA).
3. **Mengapa cepat & aman?** — Ditenagai arsitektur **Shared Browser Singleton Pool** (tanpa CPU/RAM bottleneck), proteksi scope otomatis (`ScanPolicy`), mode `--dry-run`, dan logging audit `.jsonl`.

---

## ✨ Fitur Utama

- ⚡ **Turbo Concurrency (`--turbo`)**: Mengolah ribuan request asinkron dengan kontrol konkurensi aman.
- 🌐 **10-Module Playwright Engine**: Validasi PoC live di browser Chromium (DOM XSS, CSRF, Clickjacking, PostMessage, CORS, Prototype Pollution, WebSocket, OAuth).
- 🔒 **Secure Secret Management**: Mendukung `--bearer-file /tmp/token.txt` dan `--bearer env:MY_TOKEN` agar rahasia tidak bocor di `ps aux` atau `.bash_history`.
- 🛡️ **Scope Guard & Policy Boundary (`ScanPolicy`)**: Otomatis mencegah request keluar dari domain target yang diizinkan.
- 🧪 **Mode Simulasi (`--dry-run`)**: Menjalankan mutasi payload dan aturan kebijakan tanpa mengirimkan request aktif ke jaringan.
- 📊 **Structured Audit Log (`--audit-log`)**: Merekam jejak audit `.jsonl` lengkap dengan status autorisasi, waktu respons, dan CVSS score.

---

## 🎭 Playwright Security Suite (10 Modul Automation)

Verdamt-Snipe dilengkapi dengan 10 modul otomasi browser berbasis Playwright yang berjalan di atas **Shared Browser Singleton Pool** tanpa beban CPU/RAM tambahan:

| No | Modul | Deskripsi Singkat |
|:---|:---|:---|
| 1 | **DOM XSS PoC Verifier** | Verifikasi live PoC XSS dengan JS sink hooking (`eval`, `innerHTML`, `document.write`). |
| 2 | **SPA Recon Engine** | Mengurai Single Page App, menangkap XHR/Fetch API endpoints, & ekstraksi JWT dari LocalStorage. |
| 3 | **CSRF Live Verifier** | Simulasi auto-submitting form cross-origin dengan cookie sesi aktif. |
| 4 | **PostMessage Inspector** | Interseptor `window.postMessage()`, audit `event.origin`, & kebocoran data `*`. |
| 5 | **Clickjacking Inspector** | Live iframe rendering check & evaluasi header `X-Frame-Options` / CSP `frame-ancestors`. |
| 6 | **WebSocket Sniffer** | Merekam koneksi real-time `wss://`/`ws://`, auth handshake headers, & frame sniffing. |
| 7 | **Proto Pollution Verifier** | Dynamic injection `__proto__` & audit pembajakan `Object.prototype` di runtime browser. |
| 8 | **OAuth / OIDC Auditor** | Inspeksi redirect URI chain & kebocoran token via Referer header cross-domain. |
| 9 | **CORS Live Verifier** | Cross-origin fetch live test dari domain terisolasi dengan `credentials: include`. |
| 10 | **Dynamic SPA Crawler** | Simulasi klik tombol, pengisian input form, & navigasi router SPA otomatis. |

---

## ⚙️ Cara Install

**Persyaratan:** Linux / macOS, Python 3.10+, Memory 2GB+.

```bash
# 1. Clone repository & masuk ke direktori
git clone https://github.com/verdammt/verdamt-snipe.git
cd verdamt-snipe

# 2. Buat virtual environment & install dependensi
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Install Playwright Chromium Driver
playwright install chromium
```

---

## 🚀 Cara Penggunaan

### Perintah Dasar
```bash
# Tampilan Menu Interaktif (TUI)
python3 verd.py target.com

# Pindai Aplikasi (Crawl, SPA, Parameter, API, Playwright Suite)
python3 verd.py https://target.com --app

# Mode Verifikasi Tanpa Trafik Jaringan (Simulasi)
python3 verd.py https://target.com --app --dry-run
```

### Opsi CLI Populer
```bash
# 1. Menjaga Kerahasian Token (Aman untuk Shell History & Process Listing)
python3 verd.py target.com --bearer-file /tmp/token.txt
python3 verd.py target.com --bearer env:VERDAMT_BEARER

# 2. Mengaktifkan Audit Logging (.jsonl)
python3 verd.py target.com --audit-log outputs/audit_target.jsonl

# 3. Pemuatan Paralel Cepat (Turbo Mode)
python3 verd.py target.com --full --turbo

# 4. Melanjutkan Pemindaian Terhenti (Resume)
python3 verd.py --resume outputs/target.com.state
```

---

## 🛡️ OpSec & Safety Policy

Setiap pemindaian dilindungi oleh batas operasional yang ketat:

- `--dry-run` : Membuat payload dan memvalidasi kebijakan tanpa mengirim request ke server.
- `--passive` : Hanya mengizinkan metode HTTP pasif (`GET`, `HEAD`, `OPTIONS`).
- `--max-requests N` : Membatasi total request HTTP (default: `10000`).
- `--max-concurrency N` : Membatasi jumlah request bersamaan (default: `100`).
- `--allowed-hosts H1,H2` : Mengunci host/IP spesifik dalam cakupan izin.

---

## 🧪 Menjalankan Unit Tests

Untuk memverifikasi stabilitas seluruh 129 test case internal:
```bash
python3 -m unittest discover tests
```

---

## ⚠️ Perhatian Legal

> **Verdamt-Snipe adalah framework pengujian keamanan berorientasi profesional.**
> Gunakan tool ini **HANYA** pada sistem yang Anda miliki atau yang telah memberikan izin resmi (Bug Bounty Program / Penetration Testing Agreement). Selalu patuhi batas cakupan (scope) dan hukum yang berlaku.

<p align="center"><i>"Precision strikes, maximum impact."</i> — <b>Verdammt</b></p>
