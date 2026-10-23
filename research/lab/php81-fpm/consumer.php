<?php
// Victim script.  The RCE happens *before* this file is executed
// (during request startup, in the session upload-progress handler).
echo "SESSION: ", json_encode($_SESSION ?? null), "\n";
