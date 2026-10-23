# CVE-2026-109619 exploit progress (PHP 8.1.34, FPM, aarch64)

Status 2026-10-23. Everything below was measured in the php81-fpm lab
container (php:8.1-fpm, memory_limit=4M pool, pm=static/1 worker,
session.upload_progress=1).

## Proven, with signatures

1. **CVE-2026-109618 OOM-bailout trigger fires.**
   `unserialize(a:200000{...})` at 4M -> `Fatal error: Allowed memory size of
   4194304 bytes exhausted (tried to allocate 1601536 bytes) in
   /tmp/poctest/producer.php` — the bailout skips
   `PHP_VAR_UNSERIALIZE_DESTROY` and `BG(unserialize)` keeps a pointer into
   request memory freed at request end (the vulnerable reuse is present in
   PHP-8.1's var_unserializer.re verbatim).

2. **CVE-2026-109619 UAF fires.** Producer (OOM mid-unserialize) + consumer
   (pre-RINIT session upload-progress decode) on the same worker -> the
   consumer's `php_var_unserialize_init()` reuses the dangling pointer ->
   worker **SIGSEGV** (`child N exited on signal 11`), reproducible across
   runs (FPM log 08:43:26, 09:10:16, 09:23:19, 09:30:25).

3. **Stage 1 — controlled reclaim of the freed `php_unserialize_data`.**
   `sizeof(struct php_unserialize_data)` = 8216 on 8.1 (8.5's layout is
   different: pointer-chain `last`/`first_dtor`/`last_dtor` + inline
   `var_entries` at +56) -> ZendMM block 8232. A session file of EXACTLY
   8191 bytes (`big|s:8177:"…";`) makes the consumer's pre-RINIT session
   read allocate emalloc(8216) -> the freed d's block -> d = the
   attacker-controlled file buffer. INIT then writes `d->last = &d->entries`
   into buffer[0..8] and NULLs buffer[8..24]. Signature (both observed):
   the session decode breaks (consumer response body = 0 bytes, vs the
   8192-byte control which echoes the session intact) and the worker dies
   with SIGSEGV (var_destroy's efree(d) double-frees the buffer).

## In progress — the leak stage

* **Channel A (session-buffer):** the corrupted 24-byte file prefix (pointer
  + NULLs) becomes the session key when the content places `|` at file
  offset 24; `consumer.php`'s `json_encode($_SESSION)` would serialize the
  key — including the INIT-written heap pointer. The two-pair content that
  parses cleanly to endptr is built (`12A + | + s:4:"AAAA"; + B|s:8141:"…`).
  Current blocker: with the parse surviving, the double-free crashes the
  request BEFORE the app's echo.
* **Channel B (form-field):** the t[] field string is a single exact-size
  malloc(8216); the INIT write (d->last = &d->entries) lands at content[0..8].
  Under `USE_ZEND_ALLOC=0` + `MALLOC_CHECK_=3` the arm is confirmed per-run
  (the worker SIGSEGVs at request end — the double-free's downstream
  corruption — after delivering the echo). Observed variability: some runs
  echo the 8296B field intact, others die before the echo — the remaining
  race to pin is the field's malloc taking d vs. the request-startup
  allocations consuming the freed chunk first (body-buffer growth /
  session-read ordering). The next iterations: force the field allocation to
  be the first 8216-byte malloc after the producer (pre-groom with a
  sacrificial field), or leak via the session-buffer channel with the echo
  moved before the flush.

## Remaining stages

4. **Leak** (channel A or B) -> the buffer address (pointer written by INIT
   at offset 0).
5. **Control:** with the address, the dtor chain (first_dtor/last_dtor at
   d+8/+16, built during the parse by var_push_dtor) is pointed at a fake
   var_dtor_entries inside the buffer; its data[0] zval is a forged
   IS_OBJECT whose ce->destructor/handlers chain reaches
   zend_call_function/system (the classic forged-object stage).

## Mechanics required for reproduction

* php -S cannot arm the OOM (post_max_size applies to chunked bodies);
  FPM required.
* 8.1's early session-id lookup ignores the multipart PHPSESSID field under
  use_only_cookies=1 — the sid must come from the Cookie header.
* Single static worker (pm=static, max_children=1) so producer/consumer
  share the worker state.
* Drivers: research/fcgi_stale.py (producer/consumer), lab scripts under
  research/lab/php81-fpm/. The OOM producer is the public kit's
  producer.php (joshuarosato/php2shell-poc, Apache-2.0); everything else is
  lab-built.
