<?php
/**
 * Benevolent-php lab application (composer-based, realistic dependencies).
 *
 * Models a production PHP app surface for the PHP2Shell lab
 * (CVE-2026-109618 / CVE-2026-109619 on PHP 8.1.34):
 *
 *  - Guzzle 6.3.2 + psr7 1.4.2 and Monolog 3.x via Composer, with the
 *    HTTP client / cookie jar / logging handlers instantiated at bootstrap,
 *    as any app using these packages would. That is also why those classes
 *    are loaded when session data is decoded below.
 *  - A legacy session-state restore feature that decodes client-supplied
 *    session bytes (session_decode) — the application primitive that real
 *    object-injection chains required (cf. the historical Joomla-class
 *    session bugs).
 *  - Persists an uploaded import file (attachment) to /tmp/php2shell_updater.php.
 *  - Stores ordinary user input in $_SESSION (display name).
 *
 * The multipart upload-progress handler (PHP_SESSION_UPLOAD_PROGRESS) runs
 * during request startup on this vulnerable runtime regardless of app code —
 * that is the CVE-affected pre-RINIT path.
 */
require __DIR__ . '/vendor/autoload.php';

// Production-standard: silence deprecations from legacy dependencies.
error_reporting(E_ALL & ~E_DEPRECATED);

// Realistic bootstrap: HTTP client with cookie persistence, a stream helper,
// and logging handlers (eagerly loads the classes above).
$client = new \GuzzleHttp\Client(array(
    'cookies' => new \GuzzleHttp\Cookie\FileCookieJar(__DIR__ . '/var/cookies.json'),
));
$stream = new \GuzzleHttp\Psr7\FnStream(array());
$logger = new \Monolog\Logger('app', array(
    new \Monolog\Handler\GroupHandler(array()),
    new \Monolog\Handler\DeduplicationHandler(new \Monolog\Handler\NullHandler()),
));

session_start();

header('Content-Type: text/plain; charset=UTF-8');

// (1) Realistic import feature: persist an uploaded file under a fixed name.
if (!empty($_FILES['attachment']['tmp_name']) && is_uploaded_file($_FILES['attachment']['tmp_name'])) {
    move_uploaded_file($_FILES['attachment']['tmp_name'], '/tmp/php2shell_updater.php');
}

// (2) Legacy session-state restore feature (the application primitive).
if (isset($_POST['cart_state']) && is_string($_POST['cart_state'])) {
    session_decode(base64_decode($_POST['cart_state']));
}

// (3) Realistic user-facing behavior: display-name form stored in the session.
if (isset($_POST['display_name']) && is_string($_POST['display_name'])) {
    $_SESSION['profile']['display_name'] = substr($_POST['display_name'], 0, 80);
}

echo "PHP version: " . PHP_VERSION . "\n";
echo "Request method: " . $_SERVER['REQUEST_METHOD'] . "\n";
echo "Session id: " . session_id() . "\n";
echo "Display name: " . ($_SESSION['profile']['display_name'] ?? '(none)') . "\n";
echo "Cart state: " . (isset($_SESSION['restore']) ? 'restored (' . get_debug_type($_SESSION['restore']) . ')' : 'none') . "\n";
