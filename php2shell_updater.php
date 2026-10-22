#!/usr/bin/env php
<?php
/**
 * PHP2Shell binary-only updater (CVE-2026-109618, CVE-2026-109619).
 *
 * No Python, compiler, source patching, or PHP branch upgrades.
 * Standalone php -S restarts do not require the pcntl or posix PHP extensions.
 * Supported managed installations: Debian/Ubuntu APT and macOS Homebrew.
 * Pinned OCI-image binary transplant supports specific official Docker-style
 * /usr/local PHP 7.4 / 8.0 / 8.1 Linux builds (matching distro/arch).
 * Container installations are allowed. Arbitrary custom builds, unknown
 * binary provenance and unsupported PHP configurations fail closed.
 *
 * Usage: php php2shell_updater.php [--apply] [--external-restart]
 * Dry-run by default. Requires PHP 7.0+ CLI, proc_open, and normal OS tools.
 * Back up/snapshot your system and test in staging before using --apply.
 *
 * IMPORTANT: Version checks validate OFFICIAL upstream fixed releases only.
 * A lower PHP_VERSION may still be secure via a vendor backport; we do NOT
 * infer that without authenticated distribution security metadata.
 */

error_reporting(E_ALL);

define('PHP2SHELL_UPDATER_REVISION', 'v5-shell-restart-no-pcntl-posix');

$FIXED = array('8.2' => '8.2.35', '8.3' => '8.3.36',
               '8.4' => '8.4.27', '8.5' => '8.5.12');

function fail_update($code, $message) {
    throw new RuntimeException($code . ': ' . $message);
}
function out($message) { echo $message . "\n"; }
function warn_msg($message) { fwrite(STDERR, $message . "\n"); }

// Input is an array, assembled as safely quoted OS command arguments.
// No shell pipelines, custom source code, or arbitrary downloaded programs.
function run_cmd($argv, $mustSucceed, $verbose) {
    if (!function_exists('proc_open')) {
        fail_update('NO_PROCESS_EXECUTION', 'PHP proc_open() is disabled');
    }
    if (!is_array($argv) || !count($argv)) {
        fail_update('INTERNAL_ERROR', 'Empty command');
    }
    $parts = array();
    foreach ($argv as $arg) { $parts[] = escapeshellarg((string)$arg); }
    $shellCommand = implode(' ', $parts) . ' 2>&1';
    if ($verbose) out('RUN: ' . implode(' ', $argv));
    $desc = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'));
    $pipes = array();
    $proc = @proc_open($shellCommand, $desc, $pipes);
    if (!is_resource($proc)) {
        fail_update('EXECUTION_FAILED', 'Could not start ' . $argv[0]);
    }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $status = proc_close($proc);
    if ($mustSucceed && $status !== 0) {
        fail_update('COMMAND_FAILED', implode(' ', $argv) . ': ' . trim($output));
    }
    return array('code' => $status, 'output' => (string)$output);
}
function cmd($argv) { return run_cmd($argv, true, false)['output']; }
function invoke($argv) {
    $result = run_cmd($argv, true, true);
    if (trim($result['output']) !== '') out(trim($result['output']));
}
function find_exe($name) {
    $result = run_cmd(array('command', '-v', $name), false, false);
    // `command` is a shell builtin. This path is for POSIX systems only.
    return $result['code'] === 0;
}
function os_name() {
    if (stripos(PHP_OS, 'WIN') === 0) return 'windows';
    if (stripos(PHP_OS, 'DARWIN') === 0) return 'darwin';
    if (stripos(PHP_OS, 'LINUX') === 0) return 'linux';
    return 'other';
}
function manager() {
    if (os_name() === 'darwin') return find_exe('brew') ? 'brew' : 'unsupported';
    if (os_name() !== 'linux') return 'unsupported';
    if (find_exe('apt-get') && find_exe('dpkg-query')) return 'apt';
    foreach (array('dnf', 'yum', 'zypper', 'apk', 'pacman') as $tool) {
        if (find_exe($tool)) return 'unsupported-' . $tool;
    }
    return 'unsupported';
}
function ver_of($text) {
    if (preg_match('/(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9])/', $text, $m)) {
        return $m[1];
    }
    return null;
}
function branch_of($version) {
    if (!preg_match('/^([0-9]+\.[0-9]+)\./', (string)$version, $m)) return null;
    return $m[1];
}
function patched_vendor_package($packageVersion, $branch) {
    // USN-8948-1 fixes both CVEs, even when the upstream PHP_VERSION is older.
    // Only accept matching Ubuntu official package version on the indicated OS.
    $os = read_os_release();
    if (!isset($os['ID'], $os['VERSION_ID']) || $os['ID'] !== 'ubuntu') return false;
    $minimums = array(
       '22.04|8.1' => '8.1.2-1ubuntu2.28',
       '24.04|8.3' => '8.3.6-0ubuntu0.24.04.13',
       '26.04|8.5' => '8.5.4-0ubuntu1.5',
       '26.10|8.5' => '8.5.9-0ubuntu2.1'
    );
    $key = $os['VERSION_ID'] . '|' . $branch;
    if (!isset($minimums[$key])) return false;
    // Reject PPA versions whose version strings compare high by accident.
    if (!preg_match('/^(?:[0-9]+:)?[0-9]+\.[0-9]+\.[0-9]+-.*ubuntu/', $packageVersion)) return false;
    return compare_dpkg($packageVersion, 'ge', $minimums[$key]);
}
function package_patched($packageVersion, $branch) {
    return (is_patched(ver_of($packageVersion)) || patched_vendor_package($packageVersion, $branch));
}
function is_patched($version) {
    global $FIXED;
    $branch = branch_of($version);
    return isset($FIXED[$branch]) && version_compare($version, $FIXED[$branch], '>=');
}
/** Identify the effective UID without requiring the optional POSIX PHP extension. */
function php2shell_effective_ids($pid) {
    $status=@file_get_contents('/proc/'.(int)$pid.'/status');
    if (!is_string($status) ||
        !preg_match('/^Uid:\s+\d+\s+(\d+)/m',$status,$u) ||
        !preg_match('/^Gid:\s+\d+\s+(\d+)/m',$status,$g)) return null;
    $groups=array();
    if (preg_match('/^Groups:\s*([^\r\n]*)/m',$status,$m)) {
        foreach (preg_split('/\s+/',trim($m[1])) as $v) {
            if ($v!=='') $groups[]=(int)$v;
        }
    }
    return array('uid'=>(int)$u[1],'gid'=>(int)$g[1],'groups'=>$groups);
}
function is_root() {
    if (os_name()==='linux') {
        $ids=php2shell_effective_ids(getmypid());
        return $ids!==null && $ids['uid']===0;
    }
    $r=run_cmd(array('id','-u'),false,false);
    return $r['code']===0 && trim($r['output'])==='0';
}

function installed_apt_packages() {
    $data = cmd(array('dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Abbrev}\n'));
    $items = array();
    foreach (preg_split('/\r?\n/', trim($data)) as $line) {
        $pieces = explode("\t", $line);
        if (count($pieces) !== 3 || substr($pieces[2], 0, 2) !== 'ii') continue;
        $name = $pieces[0];
        if (!preg_match('/^(?:php([0-9]+\.[0-9]+)(?:-[a-z0-9+.-]+)?|libapache2-mod-php([0-9]+\.[0-9]+))$/', $name, $m)) continue;
        $branch = !empty($m[1]) ? $m[1] : $m[2];
        $items[$name] = array('name' => $name, 'installed' => $pieces[1], 'branch' => $branch);
    }
    if (!$items) fail_update('UNSUPPORTED_INSTALLATION', 'No versioned APT PHP packages found');
    ksort($items);
    return $items;
}
function apt_candidate($name) {
    $policy = cmd(array('apt-cache', 'policy', $name));
    if (!preg_match('/^\s*Candidate:\s*(\S+)/m', $policy, $m) || $m[1] === '(none)') {
        fail_update('NO_COMPATIBLE_PATCH_AVAILABLE', 'No APT candidate for ' . $name);
    }
    return $m[1];
}
function compare_dpkg($left, $op, $right) {
    return run_cmd(array('dpkg', '--compare-versions', $left, $op, $right), false, false)['code'] === 0;
}
function apt_plan() {
    global $FIXED;
    $plan = array();
    foreach (installed_apt_packages() as $p) {
        $installedVer = ver_of($p['installed']);
        if ($installedVer === null || branch_of($installedVer) !== $p['branch']) {
            fail_update('UNVERIFIABLE_PACKAGE', $p['name'] . ' version ' . $p['installed']);
        }
        // Legacy PHP is allowed only if the distro has a specifically
        // documented, verifiable vendor security backport.
        $candidate = apt_candidate($p['name']);
        $candidateVer = ver_of($candidate);
        if ($candidateVer === null || branch_of($candidateVer) !== $p['branch']) {
            fail_update('INCOMPATIBLE_PACKAGE', $p['name'] . ' candidate ' . $candidate);
        }
        if (!package_patched($candidate, $p['branch'])) {
            fail_update('NO_COMPATIBLE_PATCH_AVAILABLE', $p['name'] . ' candidate ' . $candidate .
                ' does not match an upstream fixed release or a verified distro backport');
        }
        if (compare_dpkg($candidate, 'lt', $p['installed'])) {
            fail_update('UNSAFE_DOWNGRADE', $p['name'] . ' ' . $p['installed'] . ' -> ' . $candidate);
        }
        if (!package_patched($p['installed'], $p['branch']) && !compare_dpkg($candidate, 'gt', $p['installed'])) {
            fail_update('NO_COMPATIBLE_PATCH_AVAILABLE', $p['name'] . ' would remain at ' . $p['installed']);
        }
        $p['candidate'] = $candidate;
        $p['changed'] = compare_dpkg($candidate, 'gt', $p['installed']);
        $plan[$p['name']] = $p;
    }
    return $plan;
}
function apt_simulate($plan) {
    $names = array();
    foreach ($plan as $p) if ($p['changed']) $names[] = $p['name'] . '=' . $p['candidate'];
    if (!$names) return;
    $args = array_merge(array('apt-get', '-s', 'install', '--only-upgrade'), $names);
    $output = cmd($args);
    foreach (preg_split('/\r?\n/', $output) as $line) {
        if (preg_match('/^(Remv|Purg)\s/', $line)) {
            fail_update('UNSAFE_DEPENDENCY_PLAN', $line);
        }
        if (preg_match('/^Inst\s+(\S+)/', $line, $m) && !isset($plan[$m[1]])) {
            // Dependencies changing independently may require broader approval.
            fail_update('UNSAFE_DEPENDENCY_PLAN', 'Unexpected package change: ' . $line);
        }
    }
}
function brew_installed() {
    $output = cmd(array('brew', 'list', '--formula', '--versions'));
    $result = array();
    foreach (preg_split('/\r?\n/', trim($output)) as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if (count($fields) < 2 || !preg_match('/^php(?:@([0-9]+\.[0-9]+))?$/', $fields[0])) continue;
        $v = ver_of($fields[1]);
        if (!$v) fail_update('UNVERIFIABLE_PACKAGE', $line);
        $result[$fields[0]] = array('name' => $fields[0], 'installed' => $fields[1], 'branch' => branch_of($v));
    }
    if (!$result) fail_update('UNSUPPORTED_INSTALLATION', 'No Homebrew PHP formula found');
    return $result;
}
function brew_plan() {
    global $FIXED;
    $plan = array();
    foreach (brew_installed() as $p) {
        $branch = $p['branch'];
        if (!isset($FIXED[$branch])) {
            fail_update('NO_COMPATIBLE_PATCH_AVAILABLE', 'No verified Homebrew binary for legacy PHP ' . $branch);
        }
        $raw = cmd(array('brew', 'info', '--json=v2', $p['name']));
        $obj = json_decode($raw, true);
        if (!is_array($obj) || !isset($obj['formulae'][0]['versions']['stable'])) {
            fail_update('UNVERIFIABLE_PACKAGE', 'Cannot inspect ' . $p['name']);
        }
        $f = $obj['formulae'][0];
        $candidate = $f['versions']['stable'];
        if (branch_of($candidate) !== $branch || !is_patched($candidate)) {
            fail_update('NO_COMPATIBLE_PATCH_AVAILABLE', $p['name'] . ' candidate ' . $candidate .
                ' is not a patched release of PHP ' . $branch);
        }
        if (empty($f['bottle']['stable']['files'])) {
            fail_update('NO_COMPATIBLE_BINARY', 'No published bottle metadata for ' . $p['name']);
        }
        if (version_compare($candidate, $p['installed'], '<')) {
            fail_update('UNSAFE_DOWNGRADE', $p['name'] . ' ' . $p['installed'] . ' -> ' . $candidate);
        }
        $p['candidate'] = $candidate;
        $p['changed'] = version_compare($candidate, $p['installed'], '>');
        $plan[$p['name']] = $p;
    }
    return $plan;
}
function running_systemd_services() {
    if (!find_exe('systemctl')) return array();
    $res = run_cmd(array('systemctl', 'list-units', '--type=service', '--state=running',
        '--no-legend', '--no-pager', '--plain'), false, false);
    if ($res['code'] !== 0) return array();
    $items = array();
    foreach (preg_split('/\r?\n/', $res['output']) as $line) {
        if (!preg_match('/^\s*([^\s]+\.service)\s/', $line, $m)) continue;
        if (preg_match('/^(?:php(?:[0-9]+(?:\.[0-9]+)?)?-fpm|php-fpm(?:[0-9]+(?:\.[0-9]+)?)?|apache2|httpd|lsws|lshttpd)\.service$/', $m[1])) {
            $items[$m[1]] = true;
        }
    }
    return array_keys($items);
}
function brew_running_services($plan) {
    $result = run_cmd(array('brew', 'services', 'list'), false, false);
    if ($result['code'] !== 0) fail_update('UNVERIFIABLE_RUNTIME', 'Cannot query Homebrew services');
    $names = array();
    foreach (preg_split('/\r?\n/', $result['output']) as $line) {
        $cols = preg_split('/\s+/', trim($line));
        if (count($cols) >= 2 && isset($plan[$cols[0]]) && $cols[1] === 'started') {
            $names[] = $cols[0];
        }
    }
    return $names;
}
/** Containers are legitimate update targets. Never reject merely because this
 * process runs in Docker/Podman, or because other containers are running.
 * Instead, prove the executing PHP binary is managed by the selected package
 * manager. The official php:* Docker images use /usr/local builds and cannot
 * be safely replaced by distribution packages.
 */
function is_container() {
    if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) return true;
    foreach (array('/proc/1/cgroup', '/proc/self/cgroup') as $path) {
        if (is_readable($path)) {
            $value = @file_get_contents($path);
            if (is_string($value) && preg_match('/docker|containerd|kubepods|podman|libpod/i', $value)) return true;
        }
    }
    return false;
}
function check_environment($mgr) {
    if (is_container()) out('Container detected: package-managed installs are permitted.');
    if ($mgr === 'apt') {
        $phpPath = realpath(PHP_BINARY);
        if ($phpPath === false) fail_update('UNVERIFIABLE_RUNTIME', 'Cannot locate PHP executable');
        $owner = run_cmd(array('dpkg-query', '-S', $phpPath), false, false);
        if ($owner['code'] !== 0) {
            fail_update('NO_COMPATIBLE_BINARY',
                'PHP at ' . $phpPath . ' is not owned by an APT package. ' .
                'This is typical of official php:* Docker images. ' .
                'A replacement from APT cannot safely overwrite it; no build or branch switch will be attempted.');
        }
    }
}
/**
 * Binary-only updater for official /usr/local Docker-style PHP installations.
 * These are immutable-digest-pinned community images, not PHP-project builds.
 * Only original-release official Docker image variants with identical version,
 * distro and configuration are considered. No arbitrary binary downloads.
 */
function prebuilt_image_catalogue() {
    return array(
      '8.1.34|trixie|cli'     => 'f9aed0c995fdc32878d6238804502e4fae66bbd5c8df29b2cdb6bc01b8cc82b7',
      '8.1.34|trixie|fpm'     => '495f2022a38713f78db43e5e9faeb1203ca1548bbcbcdd0b53901061fbca8ce0',
      '8.1.34|bookworm|cli'   => '6ea140bdb6104571cb09b7e8cc87904b29c5574bdf2e3762ca78138f624ea4fa',
      '8.1.34|bookworm|fpm'   => 'b0cf8257049069d49ba773c60f1e1edfb2e13e21456ee0ec853e2f07568300f2',
      '8.1.34|alpine3.22|cli'=> '9921615a08034d230f835029009bfd96eabcea1f67eb53cf8ab84744b1a91511',
      '8.1.34|alpine3.22|fpm'=> '61dc151780cbe7872bdc30ad2531aa7513151db13e3d8e5a17f2707a8038810e',
      '8.0.30|bullseye|cli'  => 'c7233748bf542858169d82392bbfdf7fa84229fd9ddaff7843f3172f5727373e',
      '8.0.30|bullseye|fpm'  => '045431a31f3e25778e0c8ac0e5c17d7d3d92a30fc97d983185b15ed00a378454',
      '8.0.30|alpine3.16|cli'=> '6cdfea515b0cfbc54edafed6a0486389fc31504bd871637419a88b8b425fc393',
      '8.0.30|alpine3.16|fpm'=> '2921f136ca09e10605662ff5678d0a1446997b217da1b7877007c28de2b23822',
      '7.4.33|bullseye|cli'  => 'e16af23235c1724cff737fde2e79cd7978d4bda118fe003e01a976cee75e96b9',
      '7.4.33|bullseye|fpm'  => 'e7387ea53ae2a329ee2a4289dba3b77047e913e0e93ea405e8a999dc62010332',
      '7.4.33|alpine3.16|cli'=> '280890f2987a37d6364131141a92c849e7bdb7b000246ccc3395cdbd58c8eab6',
      '7.4.33|alpine3.16|fpm'=> '12f40ec8abd8fcddb85718e34466e4f12afe315dbed836e89d3a19d2b2188564'
    );
}
function read_os_release() {
    $v = array();
    if (!is_readable('/etc/os-release')) return $v;
    foreach (file('/etc/os-release', FILE_IGNORE_NEW_LINES) as $line) {
        if (!preg_match('/^([A-Z_]+)=(.*)$/', $line, $m)) continue;
        $v[$m[1]] = trim($m[2], " \"'");
    }
    return $v;
}
function os_image_flavor() {
    $os = read_os_release();
    if (isset($os['ID']) && $os['ID'] === 'alpine') {
        if (empty($os['VERSION_ID'])) return null;
        if (preg_match('/^(\d+\.\d+)/', $os['VERSION_ID'], $m)) return 'alpine' . $m[1];
        return null;
    }
    if (isset($os['ID']) && $os['ID'] === 'debian') {
        return isset($os['VERSION_CODENAME']) ? $os['VERSION_CODENAME'] : null;
    }
    return null;
}
function serving_processes() {
    $result = array();
    foreach (glob('/proc/[0-9]*/cmdline') ?: array() as $path) {
        $raw = @file_get_contents($path);
        if (!is_string($raw) || $raw === '') continue;
        $tokens = array_values(array_filter(explode("\0", $raw), 'strlen'));
        $first = isset($tokens[0]) ? $tokens[0] : '';
        $base = basename($first);
        $pid = (int)basename(dirname($path));
        $text = implode(' ', $tokens);
        if (preg_match('/php-fpm/i', $base) || strpos($text, 'php-fpm: master process') !== false) {
            $result[] = array('pid'=>$pid, 'type'=>'fpm', 'cmd'=>$text);
        } elseif (preg_match('/^(apache2|httpd|lshttpd|lsws)$/', $base)) {
            $result[] = array('pid'=>$pid, 'type'=>'apache', 'cmd'=>$text);
        } elseif (($base === 'php' || preg_match('/^php[0-9]+(?:\.[0-9]+)?$/', $base)) &&
                  in_array('-S', $tokens, true)) {
            $result[] = array('pid'=>$pid, 'type'=>'cli_server', 'cmd'=>$text);
        } elseif ($base === 'php-cgi') {
            $result[] = array('pid'=>$pid, 'type'=>'unmanaged', 'cmd'=>$text);
        }
    }
    return $result;
}
/** Linux /proc starttime identifies a process across PID reuse. */
function php2shell_proc_identity($pid) {
    $stat = @file_get_contents('/proc/' . (int)$pid . '/stat');
    if (!is_string($stat)) return null;
    $end = strrpos($stat, ')');
    if ($end === false) return null;
    $fields = preg_split('/\s+/', trim(substr($stat, $end + 1)));
    // Field 22 (starttime) is index 19 when indexing from field 3.
    if (count($fields) < 20) return null;
    return array('starttime'=>$fields[19], 'state'=>$fields[0]);
}
function php2shell_proc_is_same($pid, $starttime) {
    $identity = php2shell_proc_identity($pid);
    return $identity !== null && $identity['starttime'] === $starttime && $identity['state'] !== 'Z';
}
function php2shell_server_probe_addr($args) {
    $pos = array_search('-S', $args, true);
    if ($pos === false || !isset($args[$pos + 1])) {
        fail_update('RESTART_UNAVAILABLE','Cannot identify php -S listen address');
    }
    $listen = $args[$pos + 1];
    if (!preg_match('/^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9._-]+):([0-9]{1,5})$/', $listen, $m)) {
        fail_update('RESTART_UNAVAILABLE','Unsupported php -S listen address ' . $listen);
    }
    $port = (int)$m[2];
    if ($port < 1 || $port > 65535) fail_update('RESTART_UNAVAILABLE','Invalid php -S listen port');
    $host = $m[1];
    if ($host === '0.0.0.0' || $host === '*' || $host === 'localhost') $host = '127.0.0.1';
    if ($host === '[::]') $host = '[::1]';
    return 'tcp://' . $host . ':' . $port;
}
/** Capture everything necessary to re-exec a PHP CLI development server.
 * Only the matching /usr/local PHP is eligible, and only one server is supported.
 */
/** Linux /proc + PHP proc_open + /bin/sh are enough for php -S restart.
 * No pcntl, POSIX PHP extension, setsid, nohup, or external supervisor.
 * If root must change to an unprivileged server user, setpriv is optional but
 * required in that configuration; absent setpriv, fail before touching PHP.
 */
function php2shell_cli_server_plan($pid) {
    if ($pid===1) fail_update('RESTART_UNAVAILABLE','php -S is PID 1');
    if (!function_exists('proc_open') || !is_executable('/bin/sh') || !is_dir('/proc')) {
        fail_update('RESTART_UNAVAILABLE','Standalone restart needs proc_open, /bin/sh and Linux /proc');
    }
    $exe=@readlink('/proc/'.$pid.'/exe');
    if ($exe!=='/usr/local/bin/php' && $exe!=='/usr/local/bin/php (deleted)') {
        fail_update('RESTART_UNAVAILABLE','php -S is not using /usr/local/bin/php: '.($exe?:'unknown'));
    }
    $identity=php2shell_proc_identity($pid);
    $ids=php2shell_effective_ids($pid);
    $myIds=php2shell_effective_ids(getmypid());
    $raw=@file_get_contents('/proc/'.$pid.'/cmdline');
    $rawenv=@file_get_contents('/proc/'.$pid.'/environ');
    $cwd=@readlink('/proc/'.$pid.'/cwd');
    $status=@file_get_contents('/proc/'.$pid.'/status');
    if ($identity===null || $ids===null || $myIds===null ||
        !is_string($raw) || $raw==='' || !is_string($rawenv) ||
        !is_string($cwd) || !is_dir($cwd) || !is_string($status)) {
        fail_update('RESTART_UNAVAILABLE','Cannot capture target process identity/configuration');
    }
    $args=array_values(array_filter(explode("\0",$raw),'strlen'));
    if (!in_array('-S',$args,true)) fail_update('RESTART_UNAVAILABLE','Target is not php -S');
    if ($myIds['uid']!==0 && ($myIds['uid']!==$ids['uid'] || $myIds['gid']!==$ids['gid'])) {
        fail_update('RESTART_UNAVAILABLE','Updater cannot adopt the original server UID/GID');
    }
    $needsDrop=($myIds['uid']===0 && $ids['uid']!==0);
    if ($needsDrop && run_cmd(array('/bin/sh','-c','command -v setpriv >/dev/null 2>&1'),false,false)['code']!==0) {
        fail_update('RESTART_UNAVAILABLE','setpriv required to restore original nonroot UID/GID (pcntl/posix not required)');
    }
    $environment=array();
    foreach (explode("\0",$rawenv) as $entry) {
        $sep=strpos($entry,'=');
        if ($entry==='' || $sep===false || $sep===0) continue;
        $environment[substr($entry,0,$sep)]=substr($entry,$sep+1);
    }
    $mask=null;
    if (preg_match('/^Umask:\s+([0-7]{4})/m',$status,$m)) $mask=octdec($m[1]);
    return array('pid'=>$pid,'starttime'=>$identity['starttime'],'args'=>$args,'cwd'=>$cwd,
        'env'=>$environment,'uid'=>$ids['uid'],'gid'=>$ids['gid'],'groups'=>$ids['groups'],
        'needs_drop'=>$needsDrop,'umask'=>$mask,
        'address'=>php2shell_server_probe_addr($args),'binary'=>'/usr/local/bin/php');
}

function plan_prebuilt_installation($externalRestart = false) {
    if (os_name() !== 'linux') fail_update('NO_COMPATIBLE_BINARY','Prebuilt image replacement requires Linux');
    $path = realpath(PHP_BINARY);
    if ($path !== '/usr/local/bin/php') {
        fail_update('NO_COMPATIBLE_BINARY', 'Prebuilt path is restricted to official Docker-style /usr/local/bin/php; got ' . PHP_BINARY);
    }
    if (!is_file('/usr/local/bin/php')) fail_update('UNSUPPORTED_INSTALLATION', 'PHP binary missing');
    $flavor = os_image_flavor();
    if ($flavor === null) fail_update('NO_COMPATIBLE_BINARY','No matching base distro for /usr/local build');
    $servers = serving_processes();
    $variant = 'cli';
    $cliServers = array();
    foreach ($servers as $p) {
        if ($p['type'] === 'apache' || $p['type'] === 'unmanaged') {
            fail_update('RESTART_UNAVAILABLE','Cannot safely restart running ' . $p['type'] . ' process ' . $p['pid']);
        }
        if ($p['type'] === 'fpm') $variant = 'fpm';
        if ($p['type'] === 'cli_server') $cliServers[] = $p;
    }
    if (count($cliServers) > 1) {
        fail_update('RESTART_UNAVAILABLE','Multiple php -S processes detected; cannot safely recreate worker pools');
    }
    if ($variant === 'fpm' && $cliServers) {
        fail_update('RESTART_UNAVAILABLE','Mixed PHP-FPM and php -S processes need coordinated restarts');
    }
    if ($externalRestart && !is_container()) {
        fail_update('RESTART_UNAVAILABLE', '--external-restart requires a container');
    }
    if ($externalRestart && $variant !== 'cli') {
        fail_update('RESTART_UNAVAILABLE', '--external-restart supports only a php -S container');
    }
    $cliRestart = ($cliServers && !$externalRestart) ? php2shell_cli_server_plan($cliServers[0]['pid']) : null;
    if ($variant === 'fpm' && !is_executable('/usr/local/sbin/php-fpm')) {
        fail_update('UNSUPPORTED_INSTALLATION','Running PHP-FPM is not /usr/local/sbin/php-fpm');
    }
    if ($variant === 'fpm' && !is_executable('/bin/sh')) {
        fail_update('RESTART_UNAVAILABLE','/bin/sh is required to signal PHP-FPM');
    }
    $key = PHP_VERSION . '|' . $flavor . '|' . $variant;
    $catalogue = prebuilt_image_catalogue();
    if (!isset($catalogue[$key])) {
        fail_update('NO_COMPATIBLE_BINARY','No pinned patched image matches ' . $key . '. No source build or branch switch attempted.');
    }
    $arch = php_uname('m');
    if ($arch === 'x86_64') $arch = 'amd64';
    elseif ($arch === 'aarch64' || $arch === 'arm64') $arch = 'arm64';
    else fail_update('NO_COMPATIBLE_BINARY','No image matching CPU: ' . $arch);
    if (!is_executable('/usr/bin/tar') && !is_executable('/bin/tar')) {
        fail_update('MISSING_TOOL','tar is required to unpack a precompiled image');
    }
    // The transplant requires GNU tar for its safe selective extraction flags.
    $tar = run_cmd(array('tar','--version'),false,false);
    if ($tar['code'] !== 0 || strpos($tar['output'],'GNU tar') === false) {
        fail_update('MISSING_TOOL','GNU tar required for OCI extraction (no build tools required)');
    }
    $plan = array('key'=>$key,'arch'=>$arch,'digest'=>'sha256:'.$catalogue[$key],
        'variant'=>$variant,'servers'=>$servers,'cli_restart'=>$cliRestart,
        'external_restart'=>$externalRestart && count($cliServers) === 1,'flavor'=>$flavor,
        'image'=>'ghcr.io/mpyw/php-eol-cve-2026-109618-109619');
    return $plan;
}
function get_http($url, $headers, $outputFile) {
    if (!preg_match('#^https://(?:ghcr\.io|pkg-containers\.githubusercontent\.com|github\.com)/#', $url)) {
        fail_update('UNTRUSTED_URL', 'Unexpected image registry host: ' . $url);
    }
    $opts = array('http'=>array('method'=>'GET',
        'header'=>implode("\r\n",$headers), 'timeout'=>80, 'follow_location'=>1, 'max_redirects'=>5,
        'ignore_errors'=>false, 'user_agent'=>'php2shell-binary-updater/2'),
        'ssl'=>array('verify_peer'=>true,'verify_peer_name'=>true));
    $ctx = stream_context_create($opts);
    $input = @fopen($url,'rb',false,$ctx);
    if ($input === false) fail_update('DOWNLOAD_FAILED','HTTPS request failed: ' . $url);
    if ($outputFile === null) {
        $data = stream_get_contents($input, 8*1024*1024+1);
        fclose($input);
        if (!is_string($data) || strlen($data) > 8*1024*1024) fail_update('BAD_REGISTRY_RESPONSE','Unexpected response size');
        return $data;
    }
    $out = @fopen($outputFile,'wb');
    if ($out === false) { fclose($input); fail_update('WRITE_FAILED','Cannot create: '.$outputFile); }
    $total = @stream_copy_to_stream($input,$out);
    fclose($out);
    fclose($input);
    if ($total === false || $total === 0 || $total > 1024*1024*1024) {
        fail_update('DOWNLOAD_FAILED','Empty or excessively large layer at '.$url);
    }
    return $total;
}
function verified_json($url,$token,$digest) {
    $accept='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';
    $data=get_http($url,array('Authorization: Bearer '.$token,'Accept: '.$accept),null);
    if (!hash_equals(substr($digest,7), hash('sha256',$data))) {
        fail_update('DIGEST_MISMATCH','Manifest SHA256 mismatch (refusing replacement)');
    }
    $json=json_decode($data,true);
    if (!is_array($json)) fail_update('BAD_REGISTRY_RESPONSE','Invalid JSON manifest');
    return $json;
}
function fetch_prebuilt_php($plan, $temp) {
    $repo='mpyw/php-eol-cve-2026-109618-109619';
    $base='https://ghcr.io/v2/'.$repo;
    out('Prebuilt source: '.$plan['image'].'@'.$plan['digest'].' (third-party; immutable digest)');
    $auth=get_http('https://ghcr.io/token?scope=repository%3Ampyw%2Fphp-eol-cve-2026-109618-109619%3Apull&service=ghcr.io',array('Accept: application/json'),null);
    $obj=json_decode($auth,true);
    $token=isset($obj['token']) ? $obj['token'] : (isset($obj['access_token']) ? $obj['access_token'] : null);
    if (!is_string($token)||$token==='') fail_update('DOWNLOAD_FAILED','Could not obtain anonymous GHCR token');
    $index=verified_json($base.'/manifests/'.$plan['digest'],$token,$plan['digest']);
    if (empty($index['manifests']) || !is_array($index['manifests'])) {
        fail_update('BAD_REGISTRY_RESPONSE','Pinned image does not contain multi-arch index');
    }
    $child=null;
    foreach ($index['manifests'] as $entry) {
        if (!isset($entry['platform']['os'],$entry['platform']['architecture'],$entry['digest'])) continue;
        if ($entry['platform']['os']==='linux' && $entry['platform']['architecture']===$plan['arch']) {
            $child=$entry['digest']; break;
        }
    }
    if ($child === null || !preg_match('/^sha256:[0-9a-f]{64}$/',$child)) {
        fail_update('NO_COMPATIBLE_BINARY','Pinned image has no linux/'.$plan['arch'].' manifest');
    }
    $manifest=verified_json($base.'/manifests/'.$child,$token,$child);
    if (empty($manifest['layers']) || !is_array($manifest['layers'])) {
        fail_update('BAD_REGISTRY_RESPONSE','No image layers');
    }
    $root=$temp.'/image';
    if (!@mkdir($root,0700,true)) fail_update('WRITE_FAILED','Cannot make image staging directory');
    $n=0;
    foreach ($manifest['layers'] as $layer) {
        if (!isset($layer['digest'],$layer['mediaType']) || !preg_match('/^sha256:[0-9a-f]{64}$/',$layer['digest'])) {
            fail_update('BAD_REGISTRY_RESPONSE','Invalid image layer');
        }
        if (!preg_match('#(?:tar\+gzip|gzip)$#',$layer['mediaType'])) {
            fail_update('UNSUPPORTED_IMAGE_FORMAT','Only gzip OCI layers are supported: '.$layer['mediaType']);
        }
        $n++;
        $archive=$temp.'/layer-'.$n.'.tar.gz';
        out('Downloading verified image layer '.$n.'/'.count($manifest['layers']));
        get_http($base.'/blobs/'.$layer['digest'],array('Authorization: Bearer '.$token),$archive);
        if (!hash_equals(substr($layer['digest'],7),hash_file('sha256',$archive))) {
            fail_update('DIGEST_MISMATCH','Image layer '.$n.' failed SHA256 verification');
        }
        // Apply only usr/local/ paths. This is an immutable-pinned image from a
        // source known to build the same Docker image variant; the rest of its
        // operating system and configuration are deliberately not installed.
        $listing=cmd(array('tar','-tzf',$archive));
        $pattern=null;
        foreach (preg_split('/\r?\n/',trim($listing)) as $entry) {
            if ($entry==='' || preg_match('#(^/|(^|/)\.\.(/|$))#',$entry)) {
                fail_update('UNSAFE_IMAGE_LAYER','Archive contains an unsafe pathname');
            }
            if (strpos($entry,'usr/local/')===0) $pattern='usr/local/*';
            elseif (strpos($entry,'./usr/local/')===0 && $pattern===null) $pattern='./usr/local/*';
        }
        if ($pattern !== null) {
            $r=run_cmd(array('tar','-xzf',$archive,'-C',$root,'--no-same-owner','--wildcards',$pattern),true,false);
        }
        @unlink($archive);
    }
    $php=$root.'/usr/local/bin/php';
    if (!is_executable($php)) fail_update('NO_COMPATIBLE_BINARY','Pinned image lacks an executable /usr/local/bin/php');
    return $root.'/usr/local';
}
function php_feature_probe($phpPath) {
    $code = 'echo PHP_VERSION,"|",PHP_SAPI,"|",(ini_get("max_multipart_body_parts")===false?"absent":"present"),"|",PHP_ZTS,"|",PHP_DEBUG;';
    $r=run_cmd(array($phpPath,'-n','-r',$code),false,false);
    if ($r['code']!==0) fail_update('INCOMPATIBLE_BINARY','Could not run '.$phpPath.': '.trim($r['output']));
    return explode('|',trim($r['output']));
}
function list_php_payload($source, $variant) {
    $list=array();
    $bin=array('bin/php','bin/php-cgi','bin/phpdbg','bin/php-config','bin/phpize');
    if ($variant==='fpm') $bin[]='sbin/php-fpm';
    foreach ($bin as $relative) {
        if (is_file($source.'/'.$relative) && ($relative==='bin/php' || file_exists('/usr/local/'.$relative))) {
            $list[$relative]=$source.'/'.$relative;
        }
    }
    if ($variant==='fpm' && !isset($list['sbin/php-fpm'])) fail_update('INCOMPATIBLE_BINARY','No prebuilt PHP-FPM executable');
    $extensions=$source.'/lib/php/extensions';
    if (is_dir($extensions)) {
        $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extensions,FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (!$file->isFile() || substr($file->getFilename(),-3)!=='.so') continue;
            $relative=substr($file->getPathname(),strlen($source)+1);
            if (!preg_match('#^lib/php/extensions/[a-zA-Z0-9._/-]+$#',$relative)) continue;
            $list[$relative]=$file->getPathname();
        }
    }
    return $list;
}
/**
 * Probe ABI and the actually available PHP functionality.  A byte-for-byte
 * comparison of configure flags is NOT an ABI check: harmless build-directory,
 * option-order, and packaging differences can produce unequal strings.
 *
 * All probes execute the proposed PHP executable, not the interpreter running
 * this installer.  Use -n for a clean built-in/module ABI check and a second
 * normal run to ensure the site's existing ini files/extensions still load.
 */
function php_runtime_probe($binary, $ignoreIni) {
    $source = 'echo json_encode(array(' .
        '"version"=>PHP_VERSION,"sapi"=>PHP_SAPI,' .
        '"zts"=>PHP_ZTS,"debug"=>PHP_DEBUG,' .
        '"int_size"=>PHP_INT_SIZE,"extension_dir"=>ini_get("extension_dir"),' .
        '"modules"=>get_loaded_extensions(false),' .
        '"zend_modules"=>get_loaded_extensions(true)));';
    $args = array($binary);
    if ($ignoreIni) $args[] = '-n';
    $args[] = '-r';
    $args[] = $source;
    $r = run_cmd($args, false, false);
    $probe = json_decode(trim($r['output']), true);
    if ($r['code'] !== 0 || !is_array($probe) || !isset($probe['version'],$probe['modules'],$probe['extension_dir'])) {
        fail_update('INCOMPATIBLE_BINARY', 'Startup failed for ' . $binary .
            ($ignoreIni ? ' without ini' : ' with current ini/extensions') . ': ' . trim($r['output']));
    }
    return $probe;
}
function php_module_check($before, $after, $kind) {
    $old = array_map('strtolower', isset($before[$kind]) ? $before[$kind] : array());
    $new = array_map('strtolower', isset($after[$kind]) ? $after[$kind] : array());
    $missing = array_values(array_diff($old, $new));
    if ($missing) {
        fail_update('INCOMPATIBLE_BINARY', 'Candidate lacks existing ' . $kind . ': ' . implode(', ', $missing));
    }
}
function php_abi_build_id($binary) {
    // PHP itself reports the extension and Zend-extension ABI IDs.  These are
    // stronger signals than an exact textual comparison of configure flags.
    $r = run_cmd(array($binary, '-n', '-i'), false, false);
    if ($r['code'] !== 0) fail_update('INCOMPATIBLE_BINARY', 'Cannot inspect PHP ABI: ' . $binary);
    $ids = array();
    foreach (array('PHP Extension Build', 'Zend Extension Build') as $label) {
        if (!preg_match('/^' . preg_quote($label, '/') . '\s*=>\s*(\S[^\r\n]*)/mi', $r['output'], $m)) {
            fail_update('INCOMPATIBLE_BINARY', 'Cannot establish ' . $label . ' for ' . $binary);
        }
        $ids[$label] = trim($m[1]);
    }
    return $ids;
}
function preflight_prebuilt($source,$plan) {
    $candidate = $source . '/bin/php';
    $probe = php_feature_probe($candidate);
    if (count($probe)!==5 || $probe[0]!==PHP_VERSION || $probe[1]!=='cli' || $probe[2]!=='present') {
        fail_update('INCOMPATIBLE_BINARY','Image PHP mismatch or missing patched feature: '.implode('|',$probe));
    }
    $existing = php_feature_probe(PHP_BINARY);
    if ($existing[3]!==$probe[3] || $existing[4]!==$probe[4]) {
        fail_update('INCOMPATIBLE_BINARY','Thread-safety / debug mode differs');
    }

    $oldClean = php_runtime_probe(PHP_BINARY, true);
    $newClean = php_runtime_probe($candidate, true);
    foreach (array('version','sapi','zts','debug','int_size','extension_dir') as $key) {
        if ($oldClean[$key] !== $newClean[$key]) {
            fail_update('INCOMPATIBLE_BINARY', $key . ' differs: installed=' .
                var_export($oldClean[$key], true) . ', candidate=' . var_export($newClean[$key], true));
        }
    }
    $oldAbi = php_abi_build_id(PHP_BINARY);
    $newAbi = php_abi_build_id($candidate);
    if ($oldAbi !== $newAbi) {
        fail_update('INCOMPATIBLE_BINARY', 'Extension ABI differs: installed=' .
            json_encode($oldAbi) . ', candidate=' . json_encode($newAbi));
    }
    php_module_check($oldClean, $newClean, 'modules');
    php_module_check($oldClean, $newClean, 'zend_modules');

    // IMPORTANT: third-party extensions and existing php.ini are part of the
    // installation.  The new runtime must load all of them before we replace
    // anything.  A startup warning makes the JSON unparseable and fails closed.
    $oldLive = php_runtime_probe(PHP_BINARY, false);
    $newLive = php_runtime_probe($candidate, false);
    foreach (array('version','zts','debug','int_size','extension_dir') as $key) {
        if ($oldLive[$key] !== $newLive[$key]) {
            fail_update('INCOMPATIBLE_BINARY', 'Configured PHP runtime differs in ' . $key);
        }
    }
    php_module_check($oldLive, $newLive, 'modules');
    php_module_check($oldLive, $newLive, 'zend_modules');

    $oldConfig='/usr/local/bin/php-config';
    $newConfig=$source.'/bin/php-config';
    if (is_executable($oldConfig) && is_executable($newConfig)) {
        $oldOpts=trim(cmd(array($oldConfig,'--configure-options')));
        $newOpts=trim(cmd(array($newConfig,'--configure-options')));
        if ($oldOpts!==$newOpts) {
            out('NOTICE: Build configure options differ; runtime ABI and existing extension checks passed.');
            out('        Raw configure-option string equality is not an ABI requirement.');
        }
    }
    $payload=list_php_payload($source,$plan['variant']);
    if (!isset($payload['bin/php'])) fail_update('INCOMPATIBLE_BINARY','No PHP executable found');
    if ($plan['variant'] === 'fpm') {
        $fpm = $source . '/sbin/php-fpm';
        $fpmTest = run_cmd(array($fpm, '-t'), false, false);
        if ($fpmTest['code'] !== 0) {
            fail_update('INCOMPATIBLE_BINARY', 'Candidate PHP-FPM cannot parse the existing pool configuration: ' . trim($fpmTest['output']));
        }
    }
    return $payload;
}
function stage_install_prebuilt($payload,$temp) {
    $backup='/usr/local/share/php2shell-backup-'.date('Ymd-His').'-'.getmypid();
    if (!@mkdir($backup,0700,true)) fail_update('WRITE_FAILED','Cannot create rollback directory');
    $done=array();
    try {
        foreach ($payload as $rel=>$source) {
            $dest='/usr/local/'.$rel;
            $folder=dirname($dest);
            if (!is_dir($folder) && !@mkdir($folder,0755,true)) fail_update('WRITE_FAILED','Cannot make '.$folder);
            if (file_exists($dest) && is_link($dest)) fail_update('UNSUPPORTED_INSTALLATION','Refusing to replace symlink '.$dest);
            $saved=$backup.'/'.$rel;
            if (file_exists($dest)) {
                if (!is_dir(dirname($saved)) && !@mkdir(dirname($saved),0700,true)) fail_update('WRITE_FAILED','Cannot back up '.$rel);
                if (!@copy($dest,$saved)) fail_update('WRITE_FAILED','Cannot back up '.$dest);
                @chmod($saved, fileperms($dest)&0777);
            }
            $new=$dest.'.php2shell-'.getmypid().'.tmp';
            if (!@copy($source,$new)) fail_update('WRITE_FAILED','Cannot stage '.$dest);
            @chmod($new,fileperms($source)&0777);
            if (!@rename($new,$dest)) {
                @unlink($new);
                fail_update('WRITE_FAILED','Cannot atomically install '.$dest);
            }
            $done[]=array($dest,file_exists($saved)?$saved:null);
        }
        $probe=php_feature_probe('/usr/local/bin/php');
        if ($probe[0]!==PHP_VERSION || $probe[2]!=='present') {
            fail_update('POST_UPDATE_VERIFICATION_FAILED','New binary lacks verified patched feature');
        }
    } catch (Exception $e) {
        foreach (array_reverse($done) as $change) {
            if ($change[1]!==null) {
                $restore=$change[0].'.php2shell-restore-'.getmypid();
                if (@copy($change[1],$restore)) {
                    @chmod($restore,fileperms($change[1])&0777);
                    @rename($restore,$change[0]);
                }
            } else @unlink($change[0]);
        }
        throw $e;
    }
    out('Rollback copies: '.$backup);
    return $backup;
}
/** Restore an earlier PHP installation if verification or reload fails.
 * The backup directory is private and was created within this same run.
 */
function rollback_prebuilt_install($backup, $payload) {
    foreach (array_reverse(array_keys($payload)) as $rel) {
        $target = '/usr/local/' . $rel;
        $saved = $backup . '/' . $rel;
        if (is_file($saved)) {
            $tmp = $target . '.php2shell-rollback-' . getmypid();
            if (!@copy($saved, $tmp)) {
                fail_update('ROLLBACK_FAILED','Cannot restore ' . $target . ' from ' . $saved);
            }
            @chmod($tmp, fileperms($saved) & 0777);
            if (!@rename($tmp, $target)) {
                @unlink($tmp);
                fail_update('ROLLBACK_FAILED','Cannot replace ' . $target . ' during rollback');
            }
        } elseif (file_exists($target)) {
            if (!@unlink($target)) fail_update('ROLLBACK_FAILED','Cannot remove newly installed ' . $target);
        }
    }
    @unlink(receipt_file());
    out('RESTORED: original PHP runtime from ' . $backup);
}
function fpm_master_pids($servers) {
    $masters=array();
    foreach ($servers as $server) {
        if ($server['type']!=='fpm') continue;
        if (strpos($server['cmd'],'master process')!==false || preg_match('/(^|\s)php-fpm(\d+\.\d+)?(\s|$)/',$server['cmd'])) {
            $masters[$server['pid']]=true;
        }
    }
    return array_keys($masters);
}
function restart_docker_fpm($plan) {
    if ($plan['variant']!=='fpm') return;
    $masters=fpm_master_pids($plan['servers']);
    if (!$masters) fail_update('RESTART_UNAVAILABLE','Could not identify FPM master to signal');
    foreach ($masters as $pid) {
        if (!is_dir('/proc/'.$pid)) continue;
        if (!php2shell_shell_signal((int)$pid,'USR2')) {
            fail_update('RESTART_FAILED','SIGUSR2 to PHP-FPM PID '.$pid.' failed');
        }
        out('Sent SIGUSR2 (graceful binary reload) to PHP-FPM PID '.$pid);
    }
    // SIGUSR2 requests a graceful binary reload; wait for every PHP-FPM
    // worker to be on the new inode. Merely replacing disk files is not enough.
    $expected=@hash_file('sha256','/usr/local/sbin/php-fpm');
    if (!$expected) fail_update('RESTART_FAILED','Cannot hash installed PHP-FPM binary');
    $deadline=time()+45;
    while (time()<=$deadline) {
        $running=serving_processes();
        $fpmCount=0;
        $allNew=true;
        foreach ($running as $p) {
            if ($p['type']!=='fpm') continue;
            $fpmCount++;
            $exe='/proc/'.$p['pid'].'/exe';
            $target=@readlink($exe);
            if (!$target || strpos($target,' (deleted)')!==false) { $allNew=false; break; }
            $hash=@hash_file('sha256',$exe);
            if (!$hash || !hash_equals($expected,$hash)) { $allNew=false; break; }
        }
        if ($fpmCount>0 && $allNew) {
            out('PASS: all running PHP-FPM processes use the installed patched binary.');
            return;
        }
        sleep(1);
    }
    fail_update('RESTART_INCOMPLETE','PHP-FPM reload was requested but one or more processes still use an old/unknown binary');
}
/** Restart implementation using core PHP plus POSIX /bin/sh builtins.
 * The helper is its own independent PHP CLI process, spawned with proc_open
 * and SIGHUP ignored. It holds a root-private ticket until it starts, then
 * erases it; the ticket may contain server environment secrets.
 */
function php2shell_restart_journal($path,$state,$detail,$newPid) {
    $value=array('state'=>$state,'updated_utc'=>gmdate('c'),
        'detail'=>$detail,'new_pid'=>$newPid);
    $temp=$path.'.'.getmypid().'.tmp';
    if (@file_put_contents($temp,json_encode($value,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))===false ||
        !@rename($temp,$path)) { @unlink($temp); return false; }
    @chmod($path,0600);
    return true;
}
/** Require an HTTP response, rather than a mere open TCP socket. */
function php2shell_restart_probe_socket($address) {
    $errno=0; $errstr='';
    $conn=@stream_socket_client($address,$errno,$errstr,0.5,STREAM_CLIENT_CONNECT);
    if (!is_resource($conn)) return false;
    stream_set_timeout($conn,1);
    $written=@fwrite($conn,"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $head=$written===false ? false : @fgets($conn,256);
    fclose($conn);
    return is_string($head) && preg_match('#^HTTP/1\.[01] [1-5][0-9]{2}#',$head)===1;
}
function php2shell_shell_signal($pid,$signal) {
    if (!is_int($pid) || $pid<=1 || !in_array($signal,array('TERM','KILL','USR2'),true)) return false;
    return run_cmd(array('/bin/sh','-c','kill -'.$signal.' "$1"','sh',(string)$pid),false,false)['code']===0;
}
/** Spawn with a shell subshell that execs into PHP, so $! is its actual PID.
 * The child ignores SIGHUP; all file descriptors go to /dev/null or a log.
 */
function php2shell_shell_launch($args,$cwd,$env,$logfile,$umask) {
    if (!is_array($args) || !count($args)) fail_update('RESTART_FAILED','Missing server command');
    $words=array();
    foreach ($args as $word) $words[]=escapeshellarg((string)$word);
    $command=implode(' ',$words);
    $body='(trap "" HUP; exec '.$command.') </dev/null >>'.escapeshellarg($logfile).' 2>&1 & echo $!';
    $opts=array(0=>array('file','/dev/null','r'),1=>array('pipe','w'),2=>array('pipe','w'));
    $pipes=array();
    $original=umask();
    if ($umask!==null) umask($umask);
    try { $process=@proc_open('/bin/sh -c '.escapeshellarg($body),$opts,$pipes,$cwd,$env); }
    finally { umask($original); }
    if (!is_resource($process)) fail_update('RESTART_FAILED','Cannot spawn /bin/sh');
    $output=stream_get_contents($pipes[1]); fclose($pipes[1]);
    $errors=stream_get_contents($pipes[2]); fclose($pipes[2]);
    $rc=proc_close($process);
    if ($rc!==0 || !preg_match('/^([1-9][0-9]*)\s*$/',(string)$output,$m)) {
        fail_update('RESTART_FAILED','Shell launch failed: '.trim((string)$errors).' '.trim((string)$output));
    }
    return (int)$m[1];
}
function php2shell_restart_daemon($info,$journal,$logfile) {
    if (!php2shell_restart_journal($journal,'ready','Detached PHP restart helper initialized',null)) return 121;
    sleep(3);
    $pid=(int)$info['pid']; $start=$info['starttime'];
    if (!php2shell_proc_is_same($pid,$start)) {
        php2shell_restart_journal($journal,'failed','Original PHP server process changed before handoff',null);
        return 122;
    }
    if (!php2shell_shell_signal($pid,'TERM')) {
        php2shell_restart_journal($journal,'failed','Cannot terminate original PHP server PID '.$pid,null);
        return 123;
    }
    $deadline=microtime(true)+7;
    while (php2shell_proc_is_same($pid,$start) && microtime(true)<$deadline) usleep(100000);
    if (php2shell_proc_is_same($pid,$start)) {
        if (!php2shell_shell_signal($pid,'KILL')) {
            php2shell_restart_journal($journal,'failed','Old PHP server did not exit after SIGTERM',null);
            return 124;
        }
        $deadline=microtime(true)+3;
        while (php2shell_proc_is_same($pid,$start) && microtime(true)<$deadline) usleep(100000);
        if (php2shell_proc_is_same($pid,$start)) {
            php2shell_restart_journal($journal,'failed','Cannot release old PHP server process',null);
            return 125;
        }
    }
    $argv=array($info['binary']);
    foreach (array_slice($info['args'],1) as $arg) $argv[]=$arg;
    // Privilege dropping is a conditional dependency. Never restart a
    // formerly unprivileged server as root.
    if (!empty($info['needs_drop'])) {
        $groups=isset($info['groups']) ? $info['groups'] : array();
        $prefix=array('setpriv','--reuid='.(int)$info['uid'],'--regid='.(int)$info['gid'],
            $groups ? '--groups='.implode(',',$groups) : '--clear-groups');
        $argv=array_merge($prefix,$argv);
    }
    try { $newPid=php2shell_shell_launch($argv,$info['cwd'],$info['env'],$logfile,$info['umask']); }
    catch (Exception $e) {
        php2shell_restart_journal($journal,'failed','Cannot launch replacement PHP: '.$e->getMessage(),null);
        return 126;
    }
    php2shell_restart_journal($journal,'starting','Launched replacement PHP server',$newPid);
    $binaryHash=@hash_file('sha256',$info['binary']);
    $deadline=microtime(true)+15;
    while (microtime(true)<$deadline) {
        $exe='/proc/'.$newPid.'/exe';
        $link=@readlink($exe);
        $activeHash=($link && strpos($link,' (deleted)')===false) ? @hash_file('sha256',$exe) : false;
        if ($binaryHash && $activeHash && hash_equals($binaryHash,$activeHash) &&
            php2shell_restart_probe_socket($info['address'])) {
            php2shell_restart_journal($journal,'success','Replacement server uses patched PHP executable and responds to HTTP',$newPid);
            return 0;
        }
        if (!php2shell_proc_identity($newPid) || !is_dir('/proc/'.$newPid)) {
            php2shell_restart_journal($journal,'failed','New PHP server exited; inspect '.$logfile,$newPid);
            return 127;
        }
        usleep(200000);
    }
    php2shell_restart_journal($journal,'failed','New server did not pass verification; inspect '.$logfile,$newPid);
    return 128;
}
/** Private entry point executed in a detached PHP CLI process. */
function php2shell_restart_helper_entry($ticket) {
    $directory='/usr/local/share/php2shell/restarts/';
    if (strncmp($ticket,$directory,strlen($directory))!==0 ||
        !preg_match('#^/usr/local/share/php2shell/restarts/[0-9]+-[a-f0-9]{12}\.ticket$#',$ticket) ||
        !is_file($ticket) || is_link($ticket)) return 130;
    $contents=@file_get_contents($ticket);
    @unlink($ticket);
    $record=json_decode((string)$contents,true);
    if (!is_array($record) || !isset($record['info'],$record['journal'],$record['log']) ||
        !is_array($record['info'])) return 131;
    return php2shell_restart_daemon($record['info'],$record['journal'],$record['log']);
}
function restart_cli_server($plan) {
    if (!isset($plan['cli_restart']) || $plan['cli_restart']===null) return null;
    $info=$plan['cli_restart']; $pid=$info['pid'];
    $installed=@hash_file('sha256',$info['binary']);
    $active=@hash_file('sha256','/proc/'.$pid.'/exe');
    if ($installed && $active && hash_equals($installed,$active)) {
        out('PASS: running php -S PID '.$pid.' already uses the installed PHP executable.');
        return null;
    }
    if (!php2shell_proc_is_same($pid,$info['starttime'])) {
        fail_update('RESTART_UNAVAILABLE','Original PHP process changed during patching');
    }
    $dir='/usr/local/share/php2shell/restarts';
    if (!is_dir($dir) && !@mkdir($dir,0700,true)) {
        fail_update('RESTART_UNAVAILABLE','Cannot create private restart directory');
    }
    if (is_link($dir) || !@chmod($dir,0700) || (fileperms($dir)&0077)!==0) {
        fail_update('RESTART_UNAVAILABLE','Restart directory is not private');
    }
    $tag=$pid.'-'.bin2hex(random_bytes(6));
    $journal=$dir.'/'.$tag.'.json'; $logfile=$dir.'/'.$tag.'.log';
    $ticket=$dir.'/'.$tag.'.ticket';
    if (!php2shell_restart_journal($journal,'queued','Scheduling independent restart',null)) {
        fail_update('RESTART_UNAVAILABLE','Cannot create restart status record');
    }
    @touch($logfile); @chmod($logfile,0600);
    $data=json_encode(array('info'=>$info,'journal'=>$journal,'log'=>$logfile));
    $original=umask(0077);
    try { $ok=@file_put_contents($ticket,$data,LOCK_EX)!==false; }
    finally { umask($original); }
    if (!$ok) fail_update('RESTART_UNAVAILABLE','Cannot create private restart ticket');
    @chmod($ticket,0600);
    $launcher='/usr/local/bin/php';
    $call='(trap "" HUP; exec '.escapeshellarg($launcher).' -n '.escapeshellarg(__FILE__).
        ' --restart-helper '.escapeshellarg($ticket).') </dev/null >>'.escapeshellarg($logfile).' 2>&1 & echo $!';
    $r=run_cmd(array('/bin/sh','-c',$call),false,false);
    if ($r['code']!==0 || !preg_match('/^([1-9][0-9]*)\s*$/',trim($r['output']))) {
        @unlink($ticket);
        fail_update('RESTART_UNAVAILABLE','Could not detach PHP helper: '.trim($r['output']));
    }
    $deadline=microtime(true)+3;
    do {
        $state=json_decode((string)@file_get_contents($journal),true);
        if (isset($state['state']) && $state['state']==='ready') {
            out('SERVER_RESTART_SCHEDULED: php -S PID '.$pid.' will be replaced automatically.');
            out('Restart status: '.$journal);
            out('Restart log: '.$logfile);
            return $journal;
        }
        if (isset($state['state']) && $state['state']==='failed') {
            fail_update('RESTART_FAILED',$state['detail']);
        }
        usleep(100000);
    } while (microtime(true)<$deadline);
    fail_update('RESTART_UNAVAILABLE','Detached PHP helper did not initialize; inspect '.$journal.' and '.$logfile);
}

function receipt_file() { return '/usr/local/share/php2shell/installed.json'; }
function verified_prebuilt_receipt($plan) {
    $file=receipt_file();
    if (!is_readable($file)) return false;
    $j=json_decode((string)@file_get_contents($file),true);
    if (!is_array($j) || !isset($j['digest'],$j['key'],$j['files']) ||
        $j['digest']!==$plan['digest'] || $j['key']!==$plan['key'] || !is_array($j['files'])) return false;
    if (count($j['files'])<1) return false;
    foreach ($j['files'] as $relative=>$sha) {
        if (!preg_match('#^(?:bin|sbin|lib/php/extensions)/[a-zA-Z0-9./_-]+$#',$relative) ||
            !preg_match('/^[0-9a-f]{64}$/',$sha)) return false;
        $file='/usr/local/'.$relative;
        if (!is_file($file) || !hash_equals($sha,(string)@hash_file('sha256',$file))) return false;
    }
    $probe=php_feature_probe('/usr/local/bin/php');
    return count($probe)===5 && $probe[0]===PHP_VERSION && $probe[2]==='present';
}
function write_prebuilt_receipt($plan,$payload) {
    $dir=dirname(receipt_file());
    if (!is_dir($dir) && !@mkdir($dir,0750,true)) fail_update('WRITE_FAILED','Cannot make receipt directory');
    $files=array();
    foreach ($payload as $rel=>$file) {
        $sourceHash = @hash_file('sha256', $file);
        $installedHash = @hash_file('sha256', '/usr/local/'.$rel);
        if (!$sourceHash || !$installedHash || !hash_equals($sourceHash, $installedHash)) {
            fail_update('POST_UPDATE_VERIFICATION_FAILED','Installed file differs from verified image: '.$rel);
        }
        $files[$rel] = $installedHash;
    }
    $receipt=array('source'=>$plan['image'],'digest'=>$plan['digest'],
        'key'=>$plan['key'],'arch'=>$plan['arch'],'installed_utc'=>gmdate('c'),
        'files'=>$files,
        'note'=>'Community image, pinned SHA256; CVE-2026-109618 and CVE-2026-109619 backport');
    $temp=$dir.'/.installed-'.getmypid();
    if (file_put_contents($temp,json_encode($receipt,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))===false ||
        !@rename($temp,receipt_file())) fail_update('WRITE_FAILED','Cannot persist patch receipt');
}
function apply_prebuilt_patch($plan,$apply) {
    out('Docker-style /usr/local PHP: '.$plan['key'].', platform linux/'.$plan['arch']);
    out('Image pinned to '.$plan['image'].'@'.$plan['digest']);
    if (verified_prebuilt_receipt($plan)) {
        // A correct binary on disk is not proof that long-running workers
        // have stopped executing the old (deleted) inode.
        if ($plan['variant'] === 'fpm') restart_docker_fpm($plan);
        restart_cli_server($plan);
        out(($plan['cli_restart'] === null ? 'PASS' : 'FILES_VERIFIED') . ': installed patched-binary checksums and feature probe (' . receipt_file() . ')');
        if ($plan['external_restart']) out('SERVER_RESTART_REQUIRED: restart this container before treating the web server as patched.');
        out('PHP_VERSION remains '.PHP_VERSION.' for this backport.');
        return;
    }
    if (!$apply) {
        out('DRY_RUN: would fetch digest-pinned precompiled image, check same version/configuration, back up /usr/local PHP binaries and extension modules, atomically replace files, then restart PHP-FPM or an eligible standalone php -S server if running.');
        if ($plan['external_restart']) out('DRY_RUN: an external container restart is required after installation.');
        out('Note: provenance is a community-maintained image, not an official PHP project binary.');
        return;
    }
    $temp=rtrim(sys_get_temp_dir(),'/').'/php2shell-'.getmypid().'-'.bin2hex(random_bytes(6));
    if (!@mkdir($temp,0700,true)) fail_update('WRITE_FAILED','Cannot create temporary directory');
    try {
        $source=fetch_prebuilt_php($plan,$temp);
        $payload=preflight_prebuilt($source,$plan);
        out('Verified compatible prebuilt PHP: '.count($payload).' runtime files');
        $backup = stage_install_prebuilt($payload,$temp);
        try {
            // Smoke-test the installed PHP again, with production ini/extension
            // settings. A successful file copy is not proof of a usable runtime.
            php_runtime_probe('/usr/local/bin/php', false);
            restart_docker_fpm($plan);
            write_prebuilt_receipt($plan,$payload);
            if (!verified_prebuilt_receipt($plan)) {
                fail_update('POST_UPDATE_VERIFICATION_FAILED','Installed payload checksum verification failed');
            }
            restart_cli_server($plan);
        } catch (Exception $error) {
            warn_msg('Update validation failed; restoring pre-update binaries: ' . $error->getMessage());
            rollback_prebuilt_install($backup, $payload);
            if ($plan['variant'] === 'fpm') {
                // After restoration, request that FPM return to the original
                // executable. Restart may still require operator intervention.
                try { restart_docker_fpm($plan); }
                catch (Exception $restartError) {
                    warn_msg('WARNING: Original binaries restored, but FPM reload could not be verified: ' . $restartError->getMessage());
                }
            }
            throw $error;
        }
        out(($plan['cli_restart'] === null ? 'PASS' : 'FILES_PATCHED') . ': installed patched runtime and verified all file hashes against patch receipt.');
        if ($plan['cli_restart'] !== null) out('SERVER_RESTART_PENDING: inspect restart status and run the verifier after the handoff.');
        if ($plan['external_restart']) out('SERVER_RESTART_REQUIRED: restart this container and run the verifier before treating the web server as patched.');
        out('PHP_VERSION remains '.PHP_VERSION.' for legacy backports; check `php -n -r "var_dump(ini_get(\'max_multipart_body_parts\'));"`.');
    } finally {
        // Never wipe temp if debugging a partially failed install; symlink-safe
        // recursive deletion is intentionally omitted. The location is printed.
        out('Staging directory (may be removed after verification): '.$temp);
    }
}

/** If there is no service manager, allow CLI-only environments (common in
 * containers). Refuse to update active PHP-serving processes we cannot
 * restart. A package installed on disk is not enough to patch old workers.
 */
function unmanaged_php_servers() {
    if (os_name() !== 'linux' || !is_dir('/proc')) return array();
    $found = array();
    foreach (glob('/proc/[0-9]*/comm') ?: array() as $path) {
        $comm = trim((string)@file_get_contents($path));
        if (!preg_match('/^(?:php-fpm(?:[0-9.]*)?|apache2|httpd|lshttpd|litespeed|lsws)$/i', $comm)) continue;
        $pid = basename(dirname($path));
        $found[$pid] = $comm . ' (PID ' . $pid . ')';
    }
    return array_values($found);
}
function apt_services_to_restart() {
    $services = running_systemd_services();
    if (!$services) {
        $processes = unmanaged_php_servers();
        if ($processes) {
            fail_update('RESTART_UNAVAILABLE',
                'PHP/web server processes are running but no supported active service manager is available: ' .
                implode(', ', $processes) . '. Refusing to leave running workers unpatched.');
        }
        out('No running PHP/web server found: CLI-only environment; no service restart necessary.');
    }
    return $services;
}
function check_plan_after($mgr, $plan) {
    $now = $mgr === 'apt' ? installed_apt_packages() : brew_installed();
    foreach ($plan as $p) {
        if (!isset($now[$p['name']])) {
            fail_update('POST_UPDATE_VERIFICATION_FAILED', 'Missing package ' . $p['name']);
        }
        $v = ver_of($now[$p['name']]['installed']);
        if (!$v || branch_of($v) !== $p['branch'] || !package_patched($now[$p['name']]['installed'], $p['branch'])) {
            fail_update('POST_UPDATE_VERIFICATION_FAILED', $p['name'] . ' is ' . $now[$p['name']]['installed']);
        }
    }
    out('PASS: installed PHP packages match upstream fixes or explicitly verified vendor backports.');
    out('NOTE: This does not verify separate unmanaged PHP runtimes or container images.');
}
function main($argv) {
    if (isset($argv[1]) && $argv[1]==='--restart-helper') {
        if (PHP_SAPI!=='cli' || !isset($argv[2]) || count($argv)!==3 ||
            realpath(PHP_BINARY)!=='/usr/local/bin/php') return 132;
        return php2shell_restart_helper_entry($argv[2]);
    }
    if (PHP_SAPI !== 'cli') fail_update('CLI_ONLY', 'Run this updater with the PHP CLI, not as an HTTP request');
    $apply = false;
    $externalRestart = false;
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--apply') $apply = true;
        elseif ($arg === '--external-restart') $externalRestart = true;
        elseif ($arg === '--help' || $arg === '-h') {
            out('PHP2Shell updater ' . PHP2SHELL_UPDATER_REVISION);
            out('Usage: php php2shell_updater.php [--apply] [--external-restart]');
            out('Dry-run by default. Installs only verified prebuilt binaries; never compiles PHP.');
            return 0;
        } else fail_update('INVALID_ARGUMENT', $arg);
    }
    if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID < 70000) {
        fail_update('UNSUPPORTED_INTERPRETER', 'PHP 7.0+ required to run this updater');
    }
    $mgr = manager();
    out('Updater: ' . PHP2SHELL_UPDATER_REVISION);
    out('OS: ' . PHP_OS . ', manager: ' . $mgr . ', executing PHP: ' . PHP_VERSION);
    // Official php:* Docker images use /usr/local/bin/php, even when apt/apk
    // happens to be installed in the container. Never modify the unrelated
    // system-package PHP instead of the runtime actually executing this file.
    if (os_name() === 'linux' && realpath(PHP_BINARY) === '/usr/local/bin/php') {
        if ($apply && !is_root()) fail_update('PERMISSION_DENIED','Root is required for /usr/local binary replacement');
        $binaryPlan = plan_prebuilt_installation($externalRestart);
        apply_prebuilt_patch($binaryPlan, $apply);
        return 0;
    }
    if ($externalRestart) fail_update('INVALID_ARGUMENT', '--external-restart requires a Docker-style /usr/local PHP installation');
    if ($mgr !== 'apt' && $mgr !== 'brew') {
        fail_update('UNSUPPORTED_OS_OR_MANAGER', 'No audited binary-only updater for ' . $mgr);
    }
    if ($apply && $mgr === 'apt' && !is_root()) {
        fail_update('PERMISSION_DENIED', 'Run APT installation with sudo');
    }
    if ($apply && $mgr === 'brew' && is_root()) {
        fail_update('PERMISSION_DENIED', 'Homebrew should run as the owning non-root user');
    }
    check_environment($mgr);
    if ($apply) {
        invoke($mgr === 'apt' ? array('apt-get', 'update') : array('brew', 'update'));
    } else {
        out('DRY RUN: repository metadata may be stale; --apply refreshes it first.');
    }
    $plan = $mgr === 'apt' ? apt_plan() : brew_plan();
    if ($mgr === 'apt') apt_simulate($plan);
    $changed = array();
    foreach ($plan as $p) {
        out($p['name'] . ': ' . $p['installed'] . ' -> ' . $p['candidate'] .
            ($p['changed'] ? ' (update)' : ' (already patched)'));
        if ($p['changed']) $changed[] = $p;
    }
    if (!$changed) {
        out('NO_CHANGE: all inventoried packages are already at an upstream fixed version.');
        return 0;
    }
    $services = $mgr === 'apt' ? apt_services_to_restart() : brew_running_services($plan);
    if ($mgr === 'brew' && !$services) {
        out('No active Homebrew PHP service: CLI-only environment; no service restart necessary.');
    }
    if ($services) out('Restart services: ' . implode(', ', $services));
    if (!$apply) {
        out('DRY_RUN: nothing installed or restarted; use --apply to execute.');
        return 0;
    }
    if ($mgr === 'apt') {
        $cmdline = array('apt-get', 'install', '-y', '--only-upgrade');
        foreach ($changed as $p) $cmdline[] = $p['name'] . '=' . $p['candidate'];
        invoke($cmdline);
        foreach ($services as $service) invoke(array('systemctl', 'restart', $service));
    } else {
        foreach ($changed as $p) {
            // Fetch bottle and all dependency bottles first. Never fall back to source.
            invoke(array('brew', 'fetch', '--bottle', '--deps', $p['name']));
        }
        $cmdline = array('brew', 'upgrade', '--force-bottle');
        foreach ($changed as $p) $cmdline[] = $p['name'];
        invoke($cmdline);
        foreach ($services as $service) invoke(array('brew', 'services', 'restart', $service));
    }
    check_plan_after($mgr, $plan);
    return 0;
}
try {
    exit(main($argv));
} catch (Exception $e) {
    warn_msg('ERROR: ' . $e->getMessage());
    warn_msg('No compilation, source builds, or PHP branch switches were attempted.');
    exit(2);
}
