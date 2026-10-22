#!/usr/bin/env php
<?php
/**
 * PHP2Shell before/after patch verifier, written in PHP (no Python).
 * CVE-2026-109618 and CVE-2026-109619.
 *
 * Non-exploitative: does NOT trigger memory corruption or execute payloads.
 * Checks official fixed version, known Ubuntu backports, or the pinned-image
 * install receipt created by the accompanying php2shell_updater.php.
 * Also records the SHA-256 of the actual PHP binary and detects stale FPM/CLI
 * server executables on Linux where /proc access is available.
 *
 * Run: php php2shell_verify.php --before
 *      php php2shell_updater.php --apply
 *      php php2shell_verify.php --after
 */
error_reporting(E_ALL);

$FIXED = array('8.2'=>'8.2.35', '8.3'=>'8.3.36', '8.4'=>'8.4.27', '8.5'=>'8.5.12');
$UPDATER_SOURCE = 'ghcr.io/mpyw/php-eol-cve-2026-109618-109619';
// Immutable release image digests from the companion updater. SHA-256 does
// not by itself constitute a vendor security attestation. See verdict notes.
$PINNED = array(
    '8.1.34|trixie|cli'      => 'f9aed0c995fdc32878d6238804502e4fae66bbd5c8df29b2cdb6bc01b8cc82b7',
    '8.1.34|trixie|fpm'      => '495f2022a38713f78db43e5e9faeb1203ca1548bbcbcdd0b53901061fbca8ce0',
    '8.1.34|bookworm|cli'    => '6ea140bdb6104571cb09b7e8cc87904b29c5574bdf2e3762ca78138f624ea4fa',
    '8.1.34|bookworm|fpm'    => 'b0cf8257049069d49ba773c60f1e1edfb2e13e21456ee0ec853e2f07568300f2',
    '8.1.34|alpine3.22|cli' => '9921615a08034d230f835029009bfd96eabcea1f67eb53cf8ab84744b1a91511',
    '8.1.34|alpine3.22|fpm' => '61dc151780cbe7872bdc30ad2531aa7513151db13e3d8e5a17f2707a8038810e',
    '8.0.30|bullseye|cli'   => 'c7233748bf542858169d82392bbfdf7fa84229fd9ddaff7843f3172f5727373e',
    '8.0.30|bullseye|fpm'   => '045431a31f3e25778e0c8ac0e5c17d7d3d92a30fc97d983185b15ed00a378454',
    '8.0.30|alpine3.16|cli' => '6cdfea515b0cfbc54edafed6a0486389fc31504bd871637419a88b8b425fc393',
    '8.0.30|alpine3.16|fpm' => '2921f136ca09e10605662ff5678d0a1446997b217da1b7877007c28de2b23822',
    '7.4.33|bullseye|cli'   => 'e16af23235c1724cff737fde2e79cd7978d4bda118fe003e01a976cee75e96b9',
    '7.4.33|bullseye|fpm'   => 'e7387ea53ae2a329ee2a4289dba3b77047e913e0e93ea405e8a999dc62010332',
    '7.4.33|alpine3.16|cli' => '280890f2987a37d6364131141a92c849e7bdb7b000246ccc3395cdbd58c8eab6',
    '7.4.33|alpine3.16|fpm' => '12f40ec8abd8fcddb85718e34466e4f12afe315dbed836e89d3a19d2b2188564'
);
function read_os_release() {
    $out = array();
    if (!is_readable('/etc/os-release')) return $out;
    foreach (file('/etc/os-release', FILE_IGNORE_NEW_LINES) as $line) {
        if (!preg_match('/^([A-Z_]+)=(.*)$/', $line, $m)) continue;
        $out[$m[1]] = trim($m[2], ' "\'');
    }
    return $out;
}
function image_flavor($os) {
    if (isset($os['ID']) && $os['ID'] === 'debian') return isset($os['VERSION_CODENAME']) ? $os['VERSION_CODENAME'] : '';
    if (isset($os['ID'], $os['VERSION_ID']) && $os['ID'] === 'alpine'
            && preg_match('/^\d+\.\d+/', $os['VERSION_ID'], $m)) return 'alpine'.$m[0];
    return '';
}
function digest_file($path) {
    if (!is_file($path) || !is_readable($path)) return null;
    $hash = @hash_file('sha256', $path);
    return is_string($hash) ? $hash : null;
}
function run_dpkg_compare($actual,$minimum) {
    if (!function_exists('proc_open')) return null;
    // Arguments originate from local package state / constant table only.
    $parts = array('dpkg','--compare-versions',$actual,'ge',$minimum);
    $quoted = array(); foreach ($parts as $part) $quoted[] = escapeshellarg($part);
    $desc = array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));
    $pipes = array();
    $p = @proc_open(implode(' ', $quoted), $desc, $pipes);
    if (!is_resource($p)) return null;
    fclose($pipes[0]); stream_get_contents($pipes[1]); fclose($pipes[1]);
    stream_get_contents($pipes[2]); fclose($pipes[2]);
    $ret = proc_close($p);
    if ($ret === 0) return true;
    if ($ret === 1) return false;
    return null;
}
function deb_package_versions() {
    $found = array();
    $path='/var/lib/dpkg/status';
    if (!is_readable($path)) return $found;
    $raw = @file_get_contents($path);
    if ($raw === false) return $found;
    foreach (preg_split('/\n\s*\n/', $raw) as $stanza) {
        if (!preg_match('/^Package:\s*(\S+)/m',$stanza,$m)) continue;
        if (!preg_match('/^Status:\s*install ok installed$/m',$stanza)) continue;
        if (!preg_match('/^Version:\s*(\S+)/m',$stanza,$v)) continue;
        $found[$m[1]]=$v[1];
    }
    return $found;
}
function ubuntu_patch_status($os, $branch, $binary) {
    $ret=array('status'=>'unknown','detail'=>null);
    if (!isset($os['ID'], $os['VERSION_ID']) || $os['ID']!=='ubuntu') return $ret;
    $known=array(
        '22.04|8.1'=>array('php8.1-cli','8.1.2-1ubuntu2.28'),
        '24.04|8.3'=>array('php8.3-cli','8.3.6-0ubuntu0.24.04.13'),
        '26.04|8.5'=>array('php8.5-cli','8.5.4-0ubuntu1.5'),
        '26.10|8.5'=>array('php8.5-cli','8.5.9-0ubuntu2.1')
    );
    $key=$os['VERSION_ID'].'|'.$branch;
    if (!isset($known[$key])) return $ret;
    // A package backport attests only to the package-managed binary, not an
    // unrelated /usr/local version or a custom binary shadowing the distro PHP.
    if (strpos($binary, '/usr/bin/php') !== 0) return $ret;
    $packages=deb_package_versions();
    $pkg=$known[$key][0]; $minimum=$known[$key][1];
    if (!isset($packages[$pkg])) return $ret;
    $ver=$packages[$pkg];
    $ret['detail']=$pkg.' '.$ver.' (Ubuntu USN-8948-1 baseline: '.$minimum.')';
    if (!preg_match('/^(?:\d+:)?\d+\.\d+\.\d+-.*ubuntu/', $ver)) return $ret;
    $cmp=run_dpkg_compare($ver,$minimum);
    if ($cmp === true) $ret['status']='patched';
    elseif ($cmp === false) $ret['status']='old';
    return $ret;
}
function check_receipt($binary,$version) {
    global $UPDATER_SOURCE,$PINNED;
    $result=array('status'=>'absent','detail'=>'No recognized /usr/local prebuilt-backport receipt');
    if ($binary !== '/usr/local/bin/php') return $result;
    $path='/usr/local/share/php2shell/installed.json';
    if (!is_readable($path)) return $result;
    $json=json_decode((string)@file_get_contents($path),true);
    if (!is_array($json) || !isset($json['source'],$json['digest'],$json['key'],$json['arch'],$json['files'])
        || !is_array($json['files'])) {
        return array('status'=>'invalid','detail'=>'Receipt missing required fields');
    }
    $key=$json['key'];
    if (!isset($PINNED[$key]) || $json['source']!==$UPDATER_SOURCE ||
        $json['digest']!== 'sha256:'.$PINNED[$key] ||
        strpos($key, $version.'|')!==0) {
        return array('status'=>'invalid','detail'=>'Receipt does not match a recognized pinned image/version');
    }
    if (!isset($json['files']['bin/php']) || !is_array($json['files']) || count($json['files'])<1) {
        return array('status'=>'invalid','detail'=>'Receipt does not cover the PHP executable');
    }
    $os=read_os_release();
    $flavor=image_flavor($os);
    $parts=explode('|',$key);
    if (count($parts)!==3 || $parts[1]!==$flavor) {
        return array('status'=>'invalid','detail'=>'Receipt OS flavor does not match this environment');
    }
    $machine=php_uname('m');
    if ($machine==='x86_64') $machine='amd64';
    elseif ($machine==='aarch64'||$machine==='arm64') $machine='arm64';
    if ($machine!==$json['arch']) {
        return array('status'=>'invalid','detail'=>'Receipt CPU architecture does not match');
    }
    if ($parts[2]==='fpm' && !isset($json['files']['sbin/php-fpm'])) {
        return array('status'=>'invalid','detail'=>'FPM receipt does not cover the FPM executable');
    }
    foreach ($json['files'] as $rel=>$expected) {
        if (!is_string($rel) || !preg_match('#^(?:bin|sbin|lib/php/extensions)/[a-zA-Z0-9./_-]+$#',$rel) ||
            strpos($rel,'..')!==false ||
            !is_string($expected) || !preg_match('/^[a-f0-9]{64}$/',$expected)) {
            return array('status'=>'invalid','detail'=>'Receipt contains invalid file path/checksum');
        }
        $actual=digest_file('/usr/local/'.$rel);
        if ($actual===null || !hash_equals($expected,$actual)) {
            return array('status'=>'invalid','detail'=>'Receipt mismatch: /usr/local/'.$rel);
        }
    }
    return array('status'=>'matched',
        'detail'=>'Pinned community image '.$json['digest'].'; '.count($json['files']).' runtime file hashes match');
}
function php_worker_scan($cliBinary, $receipt) {
    $out=array('checked'=>false,'stale'=>array(),'unverified'=>array(),'matched'=>0,'found'=>0,'verified_sapi'=>0);
    if (PHP_OS_FAMILY === 'Windows' || !is_dir('/proc')) return $out;
    $out['checked']=true;
    $files=glob('/proc/[0-9]*/cmdline');
    if (!is_array($files)) return $out;
    foreach ($files as $file) {
        $text=@file_get_contents($file);
        if (!is_string($text)||$text==='') continue;
        $tokens=explode("\0",$text);
        $base=basename($tokens[0]);
        $pid=basename(dirname($file));
        $isFpm = preg_match('/^php-fpm(?:\d+(?:\.\d+)?)?$/', $base) || strpos($text,'php-fpm:')!==false;
        $isCliServer = ($base==='php' && preg_match('/(?:^|\s)-S\s/',str_replace("\0",' ',$text)));
        $isApache = in_array($base,array('apache2','httpd','lshttpd','lsws'),true);
        if (!$isFpm && !$isCliServer && !$isApache) continue;
        $out['found']++;
        if ($isApache) {
            $out['unverified'][]=$pid.': Apache/web server (PHP may be a loaded module; cannot validate it here)';
            continue;
        }
        $exe='/proc/'.$pid.'/exe';
        $target=@readlink($exe);
        if ($target===false) { $out['unverified'][]=$pid.': inaccessible executable'; continue; }
        if (strpos($target,' (deleted)')!==false) {
            $out['stale'][]=$pid.': old deleted executable '.$target;
            continue;
        }
        // Match against the corresponding installed executable, not against
        // the CLI binary (FPM and CLI are different executables).
        $current=$target;
        $fileHash=digest_file($current);
        $procHash=digest_file($exe);
        if ($fileHash===null||$procHash===null) {
            $out['unverified'][]=$pid.': cannot hash active and on-disk executables';
        } elseif (!hash_equals($fileHash,$procHash)) {
            $out['stale'][]=$pid.': running PHP executable differs from on-disk '.$target;
        } else {
            $out['matched']++;
            // For a separate FPM binary, unchanged-on-disk is insufficient:
            // it must be tied to the same verified pinned PHP distribution.
            if ($isCliServer && $target === $cliBinary) {
                $out['verified_sapi']++;
            } elseif ($isFpm && $target === '/usr/local/sbin/php-fpm'
                && $receipt['status']==='matched'
                && is_readable('/usr/local/share/php2shell/installed.json')) {
                $r=json_decode((string)file_get_contents('/usr/local/share/php2shell/installed.json'),true);
                if (isset($r['files']['sbin/php-fpm'])) $out['verified_sapi']++;
                else $out['unverified'][]=$pid.': FPM executable is not covered by the patch receipt';
            } else {
                $out['unverified'][]=$pid.': web PHP executable is not independently established as patched ('.$target.')';
            }
        }
    }
    return $out;
}
function assess($version,$os,$binary) {
    global $FIXED;
    $segments=explode('.',$version);
    $branch=(count($segments)>=2 ? $segments[0].'.'.$segments[1] : $version);
    $upstream=isset($FIXED[$branch]) && version_compare($version,$FIXED[$branch],'>=');
    $receipt=check_receipt($binary,$version);
    $vendor=ubuntu_patch_status($os,$branch,$binary);
    if ($upstream) {
        return array('verdict'=>'PATCHED_UPSTREAM','reason'=>'Official PHP '.$branch.' fixed in '.$FIXED[$branch],
                    'receipt'=>$receipt,'vendor'=>$vendor);
    }
    if ($receipt['status']==='matched') {
        return array('verdict'=>'PATCHED_VERIFIED_BACKPORT',
            'reason'=>'Recognized pinned community backport and all files match the updater receipt (provenance-based; not a behavioral exploit test)',
            'receipt'=>$receipt,'vendor'=>$vendor);
    }
    if ($vendor['status']==='patched') {
        return array('verdict'=>'PATCHED_VENDOR_BACKPORT',
            'reason'=>'Installed Ubuntu package meets USN-8948-1 security baseline',
            'receipt'=>$receipt,'vendor'=>$vendor);
    }
    if (isset($FIXED[$branch])) {
        return array('verdict'=>'LIKELY_VULNERABLE',
            'reason'=>'Below upstream fixed release '.$FIXED[$branch].'; no recognized verified backport',
            'receipt'=>$receipt,'vendor'=>$vendor);
    }
    if (version_compare($version,'5.4.0','>=') && version_compare($version,'8.2.0','<')) {
        return array('verdict'=>'LIKELY_VULNERABLE',
            'reason'=>'End-of-life PHP branch; no upstream patched version or recognized backport found',
            'receipt'=>$receipt,'vendor'=>$vendor);
    }
    return array('verdict'=>'UNKNOWN',
        'reason'=>'Version outside the fixed-release table; no recognized proof of a complete fix',
        'receipt'=>$receipt,'vendor'=>$vendor);
}
function snapshot() {
    $binary=realpath(PHP_BINARY);
    if ($binary===false) $binary=PHP_BINARY;
    $os=read_os_release();
    $version=PHP_VERSION;
    $assessment=assess($version,$os,$binary);
    $workers=php_worker_scan($binary,$assessment['receipt']);
    if (count($workers['stale'])>0 && strpos($assessment['verdict'],'PATCHED')===0) {
        $assessment['verdict']='STALE_PHP_WORKERS';
        $assessment['reason']='On-disk PHP is patched, but running PHP workers still use an old executable';
    } elseif (count($workers['unverified'])>0 && strpos($assessment['verdict'],'PATCHED')===0) {
        $assessment['verdict']='WEB_RUNTIME_UNVERIFIED';
        $assessment['reason']='CLI PHP has patch evidence, but a running web PHP executable/module is not independently verified';
    }
    return array(
        'time_utc'=>gmdate('c'),
        'php_version'=>$version,
        'php_sapi'=>PHP_SAPI,
        'php_binary'=>$binary,
        'binary_sha256'=>digest_file($binary),
        'os'=>isset($os['PRETTY_NAME']) ? $os['PRETTY_NAME'] : PHP_OS,
        'config_file'=>php_ini_loaded_file(),
        'verdict'=>$assessment['verdict'],
        'reason'=>$assessment['reason'],
        'receipt'=>$assessment['receipt'],
        'vendor'=>$assessment['vendor'],
        'workers'=>$workers
    );
}
function display_snapshot($s) {
    echo "PHP2Shell CVE-2026-109618 / CVE-2026-109619 verification\n";
    echo "PHP:      ".$s['php_version']." (".$s['php_sapi'].")\n";
    echo "Binary:   ".$s['php_binary']."\n";
    echo "SHA-256:  ".($s['binary_sha256'] ? $s['binary_sha256'] : '(unavailable)')."\n";
    echo "OS:       ".$s['os']."\n";
    echo "Status:   ".$s['verdict']."\n";
    echo "Reason:   ".$s['reason']."\n";
    echo "Backport: ".$s['receipt']['status']." (".$s['receipt']['detail'].")\n";
    if ($s['vendor']['detail']) echo "Package:  ".$s['vendor']['detail']."\n";
    if ($s['workers']['checked']) {
        echo 'Workers:  '.$s['workers']['found'].' found; '.$s['workers']['matched']." executable hashes match disk\n";
        foreach ($s['workers']['stale'] as $item) echo "STALE:    $item\n";
        foreach ($s['workers']['unverified'] as $item) echo "UNKNOWN:  $item\n";
    } else echo "Workers:  Not checked on this OS\n";
    if ($s['workers']['found']===0) {
        echo "NOTE:     No running PHP web workers detected; this verifies CLI PHP, not a separate web SAPI.\n";
    }
}
function main($argv) {
    $mode='check';
    if (count($argv)>2 || (isset($argv[1]) && !in_array($argv[1],array('--before','--after','--check'),true))) {
        fwrite(STDERR,"Usage: php php2shell_verify.php [--before|--after|--check]\n"); return 2;
    }
    if (isset($argv[1])) $mode=substr($argv[1],2);
    $baseline=__DIR__.'/php2shell_before.json';
    $current=snapshot();
    display_snapshot($current);
    if ($mode==='before') {
        if (file_put_contents($baseline,json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))===false) {
            fwrite(STDERR,"ERROR: cannot save baseline to $baseline\n"); return 2;
        }
        echo "BASELINE: saved to $baseline\n";
    }
    if ($mode==='after') {
        if (!is_readable($baseline)) {
            fwrite(STDERR,"ERROR: no baseline at $baseline; run --before first\n"); return 2;
        }
        $old=json_decode((string)file_get_contents($baseline),true);
        if (!is_array($old) || !isset($old['binary_sha256'],$old['verdict'])) {
            fwrite(STDERR,"ERROR: invalid baseline file\n"); return 2;
        }
        $changed=($old['binary_sha256']!==null && $current['binary_sha256']!==null
            && !hash_equals($old['binary_sha256'],$current['binary_sha256']));
        echo "\nBEFORE / AFTER\n";
        echo 'Before: '.$old['verdict'].'; sha256 '.($old['binary_sha256'] ? $old['binary_sha256'] : 'unknown')."\n";
        echo 'After:  '.$current['verdict'].'; sha256 '.($current['binary_sha256'] ? $current['binary_sha256'] : 'unknown')."\n";
        echo 'Binary changed: '.($changed ? 'YES' : 'NO')."\n";
        if (!$changed && strpos($current['verdict'],'PATCHED')!==0) {
            echo "RESULT: FAIL — same unverified PHP executable; patch not demonstrated.\n";
        } elseif ($changed && strpos($current['verdict'],'PATCHED')!==0) {
            echo "RESULT: INCONCLUSIVE — executable changed, but its security fix is not verified.\n";
        } elseif (strpos($current['verdict'],'PATCHED')===0) {
            echo "RESULT: PASS (with the evidence level stated above); confirm web workers separately.\n";
        } else {
            echo "RESULT: INCONCLUSIVE.\n";
        }
    }
    // Exit code 0 only with evidence of a patch; 1 for vulnerable/unknown.
    return strpos($current['verdict'],'PATCHED')===0 ? 0 : 1;
}
if (PHP_SAPI!=='cli') { http_response_code(403); exit('Run this script from PHP CLI only.'); }
exit(main($argv));
