<?php
// Leak-stage victim: echoes the reclaimed field verbatim. The stale decode
// writes d->last = var_hashx into the reclaimed zend_string content.
header('Content-Type: application/octet-stream');
if (isset($_POST['t']) && is_array($_POST['t'])) {
    echo $_POST['t'][0];
}
