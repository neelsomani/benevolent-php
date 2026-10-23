<?php
// Producer: OOM inside unserialize() -> bailout -> PHP_VAR_UNSERIALIZE_DESTROY()
// is skipped -> BG(unserialize) keeps a pointer into freed request memory.
$n = 200000;
$payload = 'a:' . $n . ':{' . str_repeat('i:0;i:0;', $n) . '}';
unserialize($payload);
echo "not reached\n";
