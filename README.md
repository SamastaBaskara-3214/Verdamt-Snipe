<h1 align="center">🎯 Verdamt-Snipe v1.4.5 NEXUS</h1>
<h4 align="center">Framework Keamanan Web Async-First, TLS Impersonation, Playwright Automation Engine & Vulnerability Assault</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue.svg">
  <img src="https://img.shields.io/badge/Playwright-10--Module%20Suite-green.svg">
  <img src="https://img.shields.io/badge/TLS%20Spoofing-curl__cffi-purple.svg">
  <img src="https://img.shields.io/badge/UI-Tactical%20Rich%20TUI-gold.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
</p>

<p align="center">
  <a href="#-ringkasan-cepat">Ringkasan</a> •
  <a href="#-teknologi--tenaga-penggerak">Teknologi</a> •
  <a href="#-kelebihan--kekurangan">Kelebihan & Kekurangan</a> •
  <a href="#-7-mode-pemindaian">Mode Pemindaian</a> •
  <a href="#-playwright-security-suite-10-modul">Playwright Suite</a> •
  <a href="#%EF%B8%8F-cara-install">Instalasi</a> •
  <a href="#-cara-penggunaan">Cara Pakai</a> •
  <a href="#-opsec--audit">OpSec & Audit</a>
</p>

---

## 🎯 Ringkasan Cepat

**Verdamt-Snipe** adalah framework audit keamanan web modern berkinerja tinggi yang menggabungkan kecepatan **Python AsyncIO**, jembatan **Go Native Bridge**, penyamaran **TLS Fingerprint (`curl_cffi`)**, serta otomasi browser kedalaman tinggi **Playwright Chromium**:

1. **Apa ini?** — Tools pemindaian, rekognisi, dan verifikasi kerentanan web otomatis serba async dengan dasbor konsol taktis militer (TUI real-time).
2. **Untuk apa?** — Digunakan oleh Penetration Tester dan Bug Bounty Hunter profesional untuk menemukan celah keamanan, meng-hunt *Origin IP* di balik WAF, memvalidasi PoC (Proof-of-Concept) live di browser, serta mengekstrak data *Blind SQLi*.
3. **Mengapa cepat & aman?** — Menggunakan arsitektur dual-engine (Python Async + Go Native), **Shared Browser Singleton Pool** (bebas memory leak), proteksi cakupan otomatis (`ScanPolicy`), mode `--dry-run`, serta logging audit `.jsonl` yang mendukung generasi replay `curl`.

---

## ⚡ Teknologi & Tenaga Penggerak

Verdamt-Snipe ditenagai oleh kombinasi teknologi modern yang dirancang untuk performa dan akurasi pengujian:

| Komponen / Engine | Teknologi yang Digunakan | Peran & Keunggulan |
| :--- | :--- | :--- |
| **Async Network Engine** | `Python AsyncIO` + `httpx` [HTTP/2] | Menangani ribuan request asinkron bersamaan tanpa blocking event loop, dilengkapi *host rate-limiting* dan *circuit breaker*. |
| **TLS Impersonation** | `curl_cffi` (JA3/JA4 Spoofing) | Memalsukan TLS fingerprint agar terdeteksi sebagai browser asli (Chrome, Firefox, Safari) untuk menembus proteksi anti-bot/WAF. |
| **Go Native Bridge** | `core/go_bridge.py` + ProjectDiscovery Go Binaries | Menghubungkan eksekusi fuzzer Python secara langsung ke binary Go (`subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, `gau`) untuk throughput maksimal. |
| **Browser Automation** | `Playwright Chromium` + `SharedBrowserPool` | Menjalankan 10 modul verifikasi kerentanan berorientasi browser (DOM XSS, CSRF, PostMessage, Prototype Pollution) menggunakan pool browser singleton yang efisien RAM/CPU. |
| **Tactical TUI Dashboard** | `rich` Live Engine (15 FPS) + `psutil` | Menampilkan dasbor konsol 3-kolom interaktif secara live: alur pipeline, grafik sparkline kecepatan request (RPS), hitung metrik target, distribusi severitas temuan, dan penggunaan resource hardware. |
| **Policy & Audit Engine** | `ScanPolicy` + `AuditLogger` (`.jsonl`) | Menjaga pengujian tetap berada dalam batas *scope*, mendukung batas *budget request*, serta mencatat setiap request HTTP ke log audit yang dapat di-replay menjadi perintah `curl`. |
| **State Management** | `SessionManager` + `ProjectState` | Mengelola token autentikasi (Bearer/Basic), cookie jar eTLD+1 per domain, serta menyimpan status sesi pemindaian (`.state`) agar dapat di-*resume* kapan saja. |

---

## ⚖️ Kelebihan & Kekurangan

### 🟢 Kelebihan

- **Kecepatan Ekstrem (Dual Async + Go Bridge)**: Menggabungkan efisiensi AsyncIO Python dengan kecepatan pemrosesan paralel native dari binary Go.
- **Kemampuan Anti-WAF & Impersonation**: Memiliki fitur khusus pemburu *Origin IP* (`hunt_origin`) untuk melewati Cloudflare/WAF, serta *TLS fingerprint spoofing*.
- **Shared Browser Pool Bebas Memory Leak**: Eksekusi otomasi Playwright menggunakan manajemen pool singleton sehingga tidak membuat CPU/RAM komputer membeku.
- **Dasbor Konsol Taktis Real-Time**: Tampilan terminal Rich 3-kolom modern dengan pembaruan 15 FPS yang informatif tanpa membebani proses scanning.
- **Verifikasi PoC Otomatis & Ekstraksi Data**: Setiap kerentanan diproses melalui tahap konfirmasi (*Phase 4 Verification*) dan dilengkapi otomatisasi ekstraksi data *Blind SQLi*.
- **Audit Trail & Replayable PoC**: Otomatis menghasilkan perintah `curl` asli dari log audit `.jsonl` untuk mempermudah pelaporan bug bounty.
- **State Save & Resume**: Sesi pemindaian yang terhenti dapat dilanjutkan kembali tanpa kehilangan data (*checkpoint* `.state`).

### 🔴 Kekurangan & Batasan

- **Ketergantungan Tool Eksternal**: Untuk performa rekognisi optimal, memerlukan binary eksternal Go (`subfinder`, `httpx`, `katana`, `nuclei`) yang sudah terinstall di sistem.
- **Konsumsi Resource pada Mode Turbo**: Penggunaan `--turbo` (50 threads paralel + Playwright Headless Browser) membutuhkan RAM minimal 2GB–4GB.
- **Terbatas pada Protokol Layer Web**: Berfokus pada HTTP/HTTPS/WebSocket — tidak mencakup pemindaian port TCP/UDP tingkat jaringan bawah (seperti SYN scan Nmap).
- **Potensi Traffic Tinggi**: Pemindaian aktif pada mode `ASSAULT` atau `POISONING` dapat memicu alert pada sistem IDS/WAF target jika tidak menggunakan `--stealth` atau `--proxy`.

---

## 🔍 7 Mode Pemindaian

Verdamt-Snipe menyediakan 7 mode pemindaian utama yang dapat dipanggil via CLI atau TUI:

| No | Flag CLI | Shortcut TUI | Deskripsi Mode |
| :--- | :--- | :--- | :--- |
| 1 | `--recon` | `1` | **Passive Intel**: Pengumpulan intelijen pasif, pencarian URL arsip (Wayback/GAU), & Google Dorking. |
| 2 | `--app` | `2` | **App Analysis**: Pemburu Origin IP (WAF bypass), crawling endpoint Katana, & penemuan parameter tersembunyi. |
| 3 | `--assault` | `3` | **Vuln Assault**: Auto pipeline recon $\rightarrow$ app $\rightarrow$ pengujian kerentanan mendalam (XSS, SQLi, IDOR, CRLF, Host Injection). |
| 4 | `--poisoning` | `4` | **Poisoning**: Pengujian *Cache Poisoning*, *HTTP Request Smuggling*, bruteforce direktori/auth, & OOB flood. |
| 5 | `--full` | `5` | **Full Pipeline**: Pemindaian menyeluruh mencakup gabungan Recon, App Analysis, dan Vulnerability Assault. |
| 6 | `--recon-light` | `6` | **Recon Light**: Crawling cepat, probing HTTPX, dan audit konfigurasi baseline keamanan dasar. |
| 7 | `--nuclei` | `7` | **Nuclei Engine**: Eksekusi pemindaian berbasis template Nuclei secara efisien. |

---

## 🎭 Playwright Security Suite (10 Modul Automation)

Verdamt-Snipe dilengkapi dengan 10 modul otomasi browser berbasis Playwright yang berjalan di atas **Shared Browser Singleton Pool**:

| No | Modul | Deskripsi Singkat |
| :--- | :--- | :--- |
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
git clone https://github.com/SamastaBaskara-3214/Verdamt-Snipe.git
cd Verdamt-Snipe

# 2. Buat virtual environment & install dependensi
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Install Playwright Chromium Driver
playwright install chromium
```

---

## 🚀 Cara Penggunaan

### 1. Launcher Praktis (`snipe`)
```bash
# Tampilan Menu Interaktif (TUI)
./snipe target.com

# Jalankan Mode 5 (FULL) dengan Stealth & Proxy
./snipe 5 target.com -s -p socks5://127.0.0.1:9050

# Jalankan Mode 2 (APP) dengan Impersonate Browser Chrome
./snipe 2 target.com -i chrome
```

### 2. Python Direct Execution (`verd.py`)
```bash
# Mode Interaktif TUI
python3 verd.py target.com

# Pemindaian Mode Assault Berulisan Full
python3 verd.py target.com --full

# Otentikasi dengan Bearer Token (Kelebihan: Aman dari ps aux / bash history)
python3 verd.py target.com --full --bearer-file /tmp/token.txt
python3 verd.py target.com --full --bearer env:MY_AUTH_TOKEN

# Melanjutkan Pemindaian Terhenti (Resume)
python3 verd.py --resume outputs/target.com.state
```

---

## 🛡️ OpSec & Safety Policy

Setiap pemindaian dilindungi oleh batas operasional yang ketat:

- `--dry-run` : Membuat payload dan memvalidasi kebijakan tanpa mengirim request ke jaringan.
- `--passive` : Hanya mengizinkan metode HTTP pasif (`GET`, `HEAD`, `OPTIONS`).
- `--max-requests N` : Membatasi total request HTTP (default: `10000`).
- `--max-concurrency N` : Membatasi jumlah request bersamaan (default: `100`).
- `--allowed-hosts H1,H2` : Mengunci host/IP spesifik dalam cakupan izin.
- `--audit-log PATH` : Merekam log `.jsonl` yang dapat direplay menjadi perintah `curl` via `core/audit.py`.

---

## 🧪 Menjalankan Unit Tests

Untuk memverifikasi stabilitas seluruh test case internal:
```bash
python3 -m unittest discover tests
```

---

## ⚠️ Perhatian Legal

> **Verdamt-Snipe adalah framework pengujian keamanan berorientasi profesional.**
> Gunakan tool ini **HANYA** pada sistem yang Anda miliki atau yang telah memberikan izin resmi (Bug Bounty Program / Penetration Testing Agreement). Selalu patuhi batas cakupan (scope) dan hukum yang berlaku.

<p align="center"><i>"Silent · Precise · Relentless."</i> — <b>Samasta Baskara</b></p>
