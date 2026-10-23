# Breakpoint trace for the BG(unserialize) arm/use (CVE-2026-109619) on 8.1.
# Usage: gdb -batch -x gdb_trace.gdb --args php-fpm -F
set follow-fork-mode child
set detach-on-fork on
set pagination off
set breakpoint pending on
handle SIGSEGV stop print pass

break php_var_unserialize_init
commands 1
silent
printf "INIT level=%d data=%p\n", BG(unserialize).level, BG(unserialize).data
continue
end

break php_var_unserialize_destroy
commands 2
silent
printf "DESTROY level=%d data=%p\n", BG(unserialize).level, BG(unserialize).data
continue
end

run
continue
echo ===CRASH===\n
bt 30
info registers
