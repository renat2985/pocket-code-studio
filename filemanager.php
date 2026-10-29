<?php

/**
 * Pocket Code Studio v1.0.0
 * A single-file PHP file manager and browser-based code editor.
 * Maintained by Renat2985 — https://github.com/Renat2985/pocket-code-studio
 * Based on Joseph Chuks' PHP File Manager and CWP Code Editor.
 * Original author: Joseph Chuks; see CREDITS.md and THIRD_PARTY_NOTICES.md.
 * Independent project; not affiliated with Microsoft or Visual Studio Code.
 */

// Authentication configuration. Store only a password_hash(), never a plain password.
$authPasswordHash = '$2y$12$qlzLQ1kcv15WIeFIIxdkcup8BQJijLSb.bjncLIHr1LL/HgrqKTo6';
// Default password: admin123. Change it in File > Settings before public use.

// Base64-encoded JSON, maintained by File > Settings. Empty uses defaults/legacy settings.
$workspaceSettingsBase64 = '';


function fmAuthReply($code, $message, $extra = [])
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(array_merge(['status' => $code < 400 ? 'success' : 'error', 'message' => $message], $extra));
    exit;
}
function fmPrivateAuthDirectory()
{
    $directory = sys_get_temp_dir() . '/fm-auth-' . substr(hash('sha256', __FILE__), 0, 24);
    if (is_link($directory) || (!is_dir($directory) && !@mkdir($directory, 0700)) || !@chmod($directory, 0700)) fmAuthReply(503, 'Cannot prepare private authentication storage. Access denied.');
    return $directory;
}
function fmReadAuthData($path, $default = [])
{
    if (is_link($path)) throw new RuntimeException('Invalid authentication data file.');
    if (!is_file($path)) return $default;
    $json = @file_get_contents($path, false, null, 0, 1048577);
    if (!is_string($json) || strlen($json) > 1048576) throw new RuntimeException('Authentication data unavailable.');
    $data = json_decode($json, true);
    if (!is_array($data)) throw new RuntimeException('Invalid authentication data.');
    return $data;
}
function fmWriteAuthData($path, $data)
{
    if (is_link($path)) throw new RuntimeException('Invalid authentication data file.');
    $json = json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    if (strlen($json) > 1048576) throw new RuntimeException('Authentication data exceeds its size limit.');
    $temp = @tempnam(dirname($path), '.login-');
    if (!$temp) throw new RuntimeException('Cannot prepare authentication data.');
    try {
        if (realpath(dirname($temp)) !== realpath(dirname($path))) throw new RuntimeException('Cannot prepare authentication data.');
        if (!@chmod($temp, 0600) || @file_put_contents($temp, $json) !== strlen($json) || !@rename($temp, $path)) throw new RuntimeException('Cannot store authentication data.');
    } finally { if (is_file($temp)) @unlink($temp); }
}
function fmLoginPolicy()
{
    $default = ['per_ip' => 8, 'global' => 64, 'window_minutes' => 15];
    try { return fmValidateLoginPolicy(fmReadAuthData(fmPrivateAuthDirectory() . '/login-policy.json', $default)); }
    catch (Throwable $error) { return $default; }
}
function fmValidateLoginPolicy($data)
{
    $result = [];
    foreach (['per_ip' => [1,100], 'global' => [1,1000], 'window_minutes' => [1,1440]] as $key => $limits) {
        $value = $data[$key] ?? null;
        if ((!is_int($value) && !is_string($value)) || !preg_match('/^[0-9]+$/D', (string) $value) || $value < $limits[0] || $value > $limits[1]) throw new RuntimeException('Invalid login limit: ' . $key . '.');
        $result[$key] = (int) $value;
    }
    if ($result['global'] < $result['per_ip']) throw new RuntimeException('The global limit must be at least the per-IP limit.');
    return $result;
}
function fmWithActivityLock($callback)
{
    $directory = fmPrivateAuthDirectory(); $path = $directory . '/activity.lock';
    if (is_link($path)) throw new RuntimeException('Invalid activity lock.');
    $handle = @fopen($path, 'c');
    if (!$handle) throw new RuntimeException('Cannot open activity lock.');
    try {
        if (!@chmod($path, 0600) || !flock($handle, LOCK_EX)) throw new RuntimeException('Cannot lock login activity.');
        return $callback($directory);
    } finally { flock($handle, LOCK_UN); fclose($handle); }
}
function fmRecordLoginEvent($ip, $result, $agent = '', $actor = null)
{
    fmWithActivityLock(function ($directory) use ($ip, $result, $agent, $actor) {
        $now = time(); $path = $directory . '/login-activity.json';
        $events = array_values(array_filter(fmReadAuthData($path), function ($event) use ($now) { return is_array($event) && ($event['last'] ?? 0) >= $now - 604800; }));
        $merged = false;
        if ($result === 'blocked') {
            for ($i = count($events) - 1; $i >= max(0, count($events) - 50); $i--) {
                if ($events[$i]['ip'] === $ip && $events[$i]['result'] === 'blocked' && $events[$i]['first'] >= $now - 60) {
                    $events[$i]['last'] = $now; $events[$i]['count']++; $events[$i]['agent'] = substr($agent, 0, 180); $merged = true; break;
                }
            }
        }
        if (!$merged) $events[] = ['ip' => $ip, 'result' => $result, 'first' => $now, 'last' => $now, 'count' => 1, 'agent' => substr($agent, 0, 180), 'actor' => $actor];
        usort($events, function ($a, $b) { return $a['last'] <=> $b['last']; });
        $events = array_slice($events, -2000);
        while (strlen(json_encode($events, JSON_INVALID_UTF8_SUBSTITUTE)) > 1000000) $events = array_slice($events, (int) ceil(count($events) / 5));
        fmWriteAuthData($path, $events);
    });
}
function fmLoginActivitySnapshot()
{
    $directory = fmPrivateAuthDirectory(); $policy = fmLoginPolicy(); $now = time();
    $path = $directory . '/attempts.json'; $state = [];
    if (is_link($path)) throw new RuntimeException('Invalid login counters.');
    if (is_file($path)) {
        $handle = @fopen($path, 'r');
        if (!$handle) throw new RuntimeException('Cannot read login counters.');
        try { if (!flock($handle, LOCK_SH)) throw new RuntimeException('Cannot lock login counters.'); $state = fmReadAuthData($path); }
        finally { flock($handle, LOCK_UN); fclose($handle); }
    }
    $events = fmReadAuthData($directory . '/login-activity.json');
    $rows = []; $failures = 0; $lastSuccess = null; $blockedIPs = 0;
    foreach ($events as $event) {
        if (!is_array($event) || ($event['last'] ?? 0) < $now - 604800) continue;
        $key = hash('sha256', $event['ip']);
        if (!isset($rows[$key])) $rows[$key] = ['key' => $key, 'ip' => $event['ip'], 'first' => $event['first'], 'last' => 0, 'failures' => 0, 'agent' => '', 'last_success' => null, 'events' => []];
        $row = &$rows[$key]; $row['first'] = min($row['first'], $event['first']); $row['last'] = max($row['last'], $event['last']);
        if ($event['agent'] !== '') $row['agent'] = $event['agent'];
        if ($event['last'] >= $now - 86400 && in_array($event['result'], ['wrong_password','blocked'], true)) { $failures += $event['count']; $row['failures'] += $event['count']; }
        if ($event['result'] === 'success') { $row['last_success'] = max($row['last_success'] ?? 0, $event['last']); $lastSuccess = max($lastSuccess ?? 0, $event['last']); }
        $row['events'][] = $event; $row['events'] = array_slice($row['events'], -20); unset($row);
    }
    foreach ($state as $key => $counter) {
        if ($key === 'global' || ($counter['since'] ?? 0) < $now - $policy['window_minutes'] * 60) continue;
        if (!isset($rows[$key])) $rows[$key] = ['key' => $key, 'ip' => $counter['ip'] ?? 'Unknown (legacy counter)', 'first' => $counter['since'], 'last' => $counter['last'] ?? $counter['since'], 'failures' => $counter['count'], 'agent' => '', 'last_success' => null, 'events' => []];
        $rows[$key]['attempts'] = $counter['count'];
        $rows[$key]['blocked_until'] = $counter['count'] >= $policy['per_ip'] ? $counter['since'] + $policy['window_minutes'] * 60 : null;
        if ($rows[$key]['blocked_until']) $blockedIPs++;
    }
    foreach ($rows as &$row) { $row += ['attempts' => 0, 'blocked_until' => null]; $row['events'] = array_reverse($row['events']); } unset($row);
    $rows = array_values($rows); usort($rows, function ($a, $b) { return $b['last'] <=> $a['last']; });
    $global = $state['global'] ?? [];
    $globalUntil = ($global['count'] ?? 0) >= $policy['global'] && ($global['since'] ?? 0) + $policy['window_minutes'] * 60 > $now ? $global['since'] + $policy['window_minutes'] * 60 : null;
    return ['rows' => $rows, 'policy' => $policy, 'failures_24h' => $failures, 'blocked_ips' => $blockedIPs, 'last_success' => $lastSuccess, 'global_blocked_until' => $globalUntil, 'now' => $now, 'current_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'];
}
function fmResetLoginLimit($key)
{
    if ($key !== 'global' && (!is_string($key) || !preg_match('/^[a-f0-9]{64}$/D', $key))) throw new RuntimeException('Invalid login counter.');
    $path = fmPrivateAuthDirectory() . '/attempts.json';
    if (is_link($path)) throw new RuntimeException('Invalid login counters.');
    $handle = @fopen($path, 'c+');
    if (!$handle) throw new RuntimeException('Cannot read login counters.');
    try {
        if (!@chmod($path, 0600) || !flock($handle, LOCK_EX)) throw new RuntimeException('Cannot lock login counters.');
        $state = fmReadAuthData($path, []); $ip = $key === 'global' ? ($_SERVER['REMOTE_ADDR'] ?? 'unknown') : ($state[$key]['ip'] ?? 'unknown'); unset($state[$key]);
        $json = json_encode($state); rewind($handle);
        if (fwrite($handle, $json) !== strlen($json) || !ftruncate($handle, strlen($json)) || !fflush($handle)) throw new RuntimeException('Cannot reset login counter.');
    } finally { flock($handle, LOCK_UN); fclose($handle); }
    fmRecordLoginEvent($ip, $key === 'global' ? 'global_limit_reset' : 'limit_reset', '', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
}
function fmLoginAttempt($password, $hash)
{
    $directory = fmPrivateAuthDirectory();
    $path = $directory . '/attempts.json';
    if (is_link($path)) fmAuthReply(503, 'Invalid authentication storage.');
    $handle = @fopen($path, 'c+');
    if (!$handle || !@chmod($path, 0600) || !flock($handle, LOCK_EX)) fmAuthReply(503, 'Cannot lock authentication storage.');
    $state = json_decode(stream_get_contents($handle), true) ?: [];
    $now = time(); $policy = fmLoginPolicy();
    foreach ($state as $key => $value) if ($value['since'] < $now - $policy['window_minutes'] * 60) unset($state[$key]);
    $key = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $blocked = ($state[$key]['count'] ?? 0) >= $policy['per_ip'] || ($state['global']['count'] ?? 0) >= $policy['global'];
    $valid = !$blocked && is_string($password) && strlen($password) <= 72 && password_verify($password, $hash);
    if (!$valid && !$blocked) {
        foreach ([$key, 'global'] as $counter) {
            $state[$counter] = ['since' => $state[$counter]['since'] ?? $now, 'count' => ($state[$counter]['count'] ?? 0) + 1];
        }
    }
    if (isset($state[$key])) { $state[$key]['ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown'; $state[$key]['last'] = $now; }
    if ($valid) unset($state[$key]);
    $json = json_encode($state);
    rewind($handle);
    $written = fwrite($handle, $json);
    $stored = $written === strlen($json) && ftruncate($handle, strlen($json)) && fflush($handle);
    flock($handle, LOCK_UN); fclose($handle);
    if (!$stored) fmAuthReply(503, 'Cannot record login attempt. Access denied.');
    try { fmRecordLoginEvent($_SERVER['REMOTE_ADDR'] ?? 'unknown', $valid ? 'success' : ($blocked ? 'blocked' : 'wrong_password'), $_SERVER['HTTP_USER_AGENT'] ?? ''); }
    catch (Throwable $ignored) { error_log('Pocket Code Studio: login activity could not be recorded.'); }
    return [$valid, $blocked];
}
// Password and UI settings share one lock so simultaneous changes preserve each other.
function fmRewriteConfiguration($transform)
{
    $directory = fmPrivateAuthDirectory();
    $lockPath = $directory . '/configuration.lock';
    if (is_link($lockPath)) throw new RuntimeException('Invalid configuration lock.');
    $lock = @fopen($lockPath, 'c');
    if (!$lock || !@chmod($lockPath, 0600) || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) fclose($lock);
        throw new RuntimeException('Cannot lock configuration.');
    }
    $temporary = null;
    try {
        clearstatcache(true, __FILE__);
        $stat = @stat(__FILE__);
        $source = @file_get_contents(__FILE__);
        if (!$stat || $stat['nlink'] !== 1 || !is_string($source)) throw new RuntimeException('Cannot read configuration safely.');
        $updated = $transform($source);
        if (!is_string($updated) || $updated === '') throw new RuntimeException('Invalid configuration update.');
        if ($updated === $source) return;
        token_get_all($updated, TOKEN_PARSE);
        $backup = $directory . '/configuration-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(5)) . '.bak';
        if (@file_put_contents($backup, $source, LOCK_EX) !== strlen($source) || !@chmod($backup, 0600) || @hash_file('sha256', $backup) !== hash('sha256', $source)) throw new RuntimeException('Cannot verify configuration backup. Nothing changed.');
        $temporary = @tempnam(dirname(__FILE__), '.fm-auth-save-');
        if (!$temporary || dirname($temporary) !== dirname(__FILE__)) throw new RuntimeException('Cannot create temporary configuration.');
        $handle = @fopen($temporary, 'wb');
        if (!$handle) throw new RuntimeException('Cannot write temporary configuration.');
        try {
            $offset = 0;
            while ($offset < strlen($updated)) {
                $written = fwrite($handle, substr($updated, $offset));
                if ($written === false || $written === 0) throw new RuntimeException('Configuration write failed.');
                $offset += $written;
            }
            if (!fflush($handle) || (function_exists('fsync') && !fsync($handle))) throw new RuntimeException('Cannot flush configuration.');
        } finally { fclose($handle); }
        if (@hash_file('sha256', $temporary) !== hash('sha256', $updated)) throw new RuntimeException('Configuration verification failed.');
        $tempStat = stat($temporary);
        if ($stat['uid'] !== $tempStat['uid'] && !@chown($temporary, $stat['uid'])) throw new RuntimeException('Cannot preserve configuration owner.');
        if ($stat['gid'] !== $tempStat['gid'] && !@chgrp($temporary, $stat['gid'])) throw new RuntimeException('Cannot preserve configuration group.');
        if (!@chmod($temporary, $stat['mode'] & 0777)) throw new RuntimeException('Cannot preserve configuration permissions.');
        clearstatcache(true, __FILE__);
        $latest = @stat(__FILE__);
        if (!$latest || $latest['ino'] !== $stat['ino'] || @hash_file('sha256', __FILE__) !== hash('sha256', $source) || !@rename($temporary, __FILE__)) throw new RuntimeException('Configuration changed or cannot be replaced safely. Reload and try again.');
        $temporary = null;
        if (function_exists('opcache_invalidate')) @opcache_invalidate(__FILE__, true);
    } finally {
        if ($temporary && is_file($temporary)) @unlink($temporary);
        flock($lock, LOCK_UN); fclose($lock);
    }
}
function fmUpdatePasswordHash($oldHash, $newHash)
{
    fmRewriteConfiguration(function ($source) use ($oldHash, $newHash) {
        $pattern = '/^\$authPasswordHash = \'[^\']*\';$/m';
        if (preg_match_all($pattern, $source, $matches) !== 1 || $matches[0][0] !== '$authPasswordHash = ' . var_export($oldHash, true) . ';') throw new RuntimeException('Password configuration changed. Reload and try again.');
        return preg_replace_callback($pattern, function () use ($newHash) { return '$authPasswordHash = ' . var_export($newHash, true) . ';'; }, $source, 1);
    });
}
function fmUpdateWorkspaceConfiguration($data, $oldHash, $newHash = null)
{
    $data = fmValidateWorkspaceSettings($data);
    fmRewriteConfiguration(function ($source) use ($data, $oldHash, $newHash) {
        // Preserve a root selected by another settings request under the same lock.
        if (!array_key_exists('root_path', $data) && preg_match('/^\$workspaceSettingsBase64 = \'([A-Za-z0-9+\/=]*)\';$/m', $source, $match)) {
            $previous = json_decode(base64_decode($match[1]), true);
            if (isset($previous['root_path'])) $data['root_path'] = $previous['root_path'];
        }
        $encoded = base64_encode(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
        $passwordPattern = '/^\$authPasswordHash = \'[^\']*\';$/m';
        $settingsPattern = '/^\$workspaceSettingsBase64 = \'[A-Za-z0-9+\/=]*\';$/m';
        if (preg_match_all($passwordPattern, $source, $matches) !== 1 || $matches[0][0] !== '$authPasswordHash = ' . var_export($oldHash, true) . ';') throw new RuntimeException('Password configuration changed. Reload and try again.');
        if (preg_match_all($settingsPattern, $source) !== 1) throw new RuntimeException('Settings configuration changed. Reload and try again.');
        $updated = preg_replace_callback($settingsPattern, function () use ($encoded) { return '$workspaceSettingsBase64 = ' . var_export($encoded, true) . ';'; }, $source, 1);
        if ($newHash !== null) $updated = preg_replace_callback($passwordPattern, function () use ($newHash) { return '$authPasswordHash = ' . var_export($newHash, true) . ';'; }, $updated, 1);
        return $updated;
    });
}
function fmValidateWorkspaceSettings($data)
{
    if (!is_array($data)) throw new RuntimeException('Invalid settings.');
    $timezone = $data['timezone'] ?? null;
    $format = $data['date_format'] ?? null;
    $font = $data['font_size'] ?? null;
    if (!is_string($timezone) || !in_array($timezone, timezone_identifiers_list(DateTimeZone::ALL_WITH_BC), true)) throw new RuntimeException('Select a valid timezone.');
    try { new DateTimeZone($timezone); } catch (Throwable $error) { throw new RuntimeException('This timezone is not supported by the server.'); }
    if (!is_string($format) || $format === '' || strlen($format) > 128 || !preg_match('//u', $format) || preg_match('/[\x00-\x1f\x7f]/', $format)) throw new RuntimeException('Date format must be 1–128 bytes without control characters.');
    if (!is_string($font) || !preg_match('/^(1[0-9]|2[0-9]|3[0-2])px$/D', $font)) throw new RuntimeException('Font size must be between 10px and 32px.');
    $result = ['timezone' => $timezone, 'date_format' => $format, 'font_size' => $font];
    if (array_key_exists('root_path', $data)) {
        if (!is_string($data['root_path']) || strlen($data['root_path']) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $data['root_path']) || !preg_match('//u', $data['root_path'])) throw new RuntimeException('Invalid workspace folder.');
        if ($data['root_path'] !== '') $result['root_path'] = $data['root_path'];
    }
    return $result;
}

// Read the current hash from disk so OPcache cannot keep an old password valid.
$authHeader = @file_get_contents(__FILE__, false, null, 0, 8192);
if ($authHeader === false || preg_match('/^\$authPasswordHash = \'([^\']+)\';$/m', $authHeader, $authMatch) !== 1 || password_get_info($authMatch[1])['algoName'] === 'unknown') fmAuthReply(503, 'Authentication is not configured. Access denied.');
$authPasswordHash = $authMatch[1];

header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
$authHTTPS = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$authLocal = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);
if (!$authHTTPS && !$authLocal) {
    http_response_code(403);
    die('HTTPS is required.');
}
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
session_name('FM' . substr(hash('sha256', __FILE__), 0, 12));
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $authHTTPS, 'httponly' => true, 'samesite' => 'Strict']);
if (!session_start()) fmAuthReply(503, 'Cannot start a secure session. Access denied.');
if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$fmCSRFToken = $_SESSION['csrf'];
$authFingerprint = hash('sha256', $authPasswordHash);
$authNow = time();
$authenticated = isset($_SESSION['auth'], $_SESSION['auth_started'], $_SESSION['auth_seen']) && hash_equals($authFingerprint, $_SESSION['auth']) && $authNow - $_SESSION['auth_seen'] < 1800 && $authNow - $_SESSION['auth_started'] < 43200;
$authAction = $_POST['fm_auth_action'] ?? '';
$isPostRequest = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
if ($isPostRequest) {
    $submittedCSRF = $_SERVER['HTTP_X_FM_CSRF'] ?? $_POST['fm_csrf'] ?? '';
    if (!is_string($submittedCSRF) || !hash_equals($fmCSRFToken, $submittedCSRF)) fmAuthReply(403, 'Invalid request token. Reload the page and try again.');
}
$loginError = '';
if (!$authenticated && $authAction === 'login' && $isPostRequest) {
    [$valid, $blocked] = fmLoginAttempt($_POST['password'] ?? '', $authPasswordHash);
    if ($valid) {
        session_regenerate_id(true);
        $_SESSION['auth'] = $authFingerprint;
        $_SESSION['auth_started'] = $_SESSION['auth_seen'] = $authNow;

        $_SESSION['login_notice_pending'] = true;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        session_write_close();
        header('Location: ' . $_SERVER['SCRIPT_NAME'], true, 303);
        exit;
    }
    $loginError = $blocked ? 'Too many attempts. Try again later.' : 'Incorrect password.';
    http_response_code($blocked ? 429 : 401);
}
if (!$authenticated) {
    unset($_SESSION['auth'], $_SESSION['auth_started'], $_SESSION['auth_seen']);
    $isDataRequest = isset($_GET['editor'], $_GET['filename']) || isset($_GET['action']) || ($isPostRequest && $authAction !== 'login');
    if ($isDataRequest) fmAuthReply(401, 'Authentication required.');
    if (!$loginError) http_response_code(401);
    ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#21252b;color:#abb2bf;font:14px system-ui}form{width:min(340px,80vw);padding:28px;background:#282c34;border:1px solid #3b4048;border-radius:8px}h1{font-size:20px;margin:0 0 24px}label{display:block;margin-bottom:8px}input,button{box-sizing:border-box;width:100%;padding:10px;border-radius:4px;font:inherit}input{background:#21252b;color:#abb2bf;border:1px solid #495162}button{margin-top:16px;background:#528bff;color:white;border:0;cursor:pointer}.error{color:#ef596f}small{display:block;margin-top:18px;color:#7f848e}</style></head><body>
<form method="post" action="<?= htmlspecialchars($_SERVER['SCRIPT_NAME'], ENT_QUOTES, 'UTF-8') ?>">
<h1>Sign in</h1><input type="hidden" name="fm_auth_action" value="login"><input type="hidden" name="fm_csrf" value="<?= htmlspecialchars($fmCSRFToken, ENT_QUOTES, 'UTF-8') ?>">
<label for="login-password">Password</label><input type="password" id="login-password" name="password" autocomplete="current-password" maxlength="72" required autofocus>
<?php if ($loginError): ?><p class="error" role="alert"><?= htmlspecialchars($loginError, ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?>
<button type="submit">Sign in</button></form></body></html>
<?php session_write_close(); exit;
}
$_SESSION['auth_seen'] = $authNow;
if ($isPostRequest && ($_POST['action'] ?? '') === 'login_activity') {
    try {
        $operation = $_POST['operation'] ?? 'read';
        if ($operation === 'reset') fmResetLoginLimit($_POST['key'] ?? null);
        elseif ($operation === 'policy') {
            $policy = fmValidateLoginPolicy($_POST);
            fmWithActivityLock(function ($directory) use ($policy) { fmWriteAuthData($directory . '/login-policy.json', $policy); });
            fmRecordLoginEvent($_SERVER['REMOTE_ADDR'] ?? 'unknown', 'policy_changed');
        } elseif ($operation !== 'read') throw new RuntimeException('Unknown login activity action.');
        fmAuthReply(200, 'Login activity loaded.', fmLoginActivitySnapshot());
    } catch (Throwable $error) { fmAuthReply(400, $error->getMessage()); }
}

if ($authAction === 'logout' && $isPostRequest) {
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $authHTTPS, 'httponly' => true, 'samesite' => 'Strict']);
    fmAuthReply(200, 'Signed out.');
}
if ($authAction === 'save_settings' && $isPostRequest) {
    try {
        $data = fmValidateWorkspaceSettings([
            'timezone' => $_POST['timezone'] ?? null,
            'date_format' => $_POST['dateformat'] ?? null,
            'font_size' => $_POST['fontSize'] ?? null,
        ]);
        if (array_key_exists('workspace_root', $_POST)) {
            $requestedRoot = $_POST['workspace_root'];
            if (!is_string($requestedRoot) || strpos($requestedRoot, "\0") !== false) throw new RuntimeException('Invalid workspace folder.');
            $resolvedRoot = @realpath($requestedRoot === '' ? $_SERVER['DOCUMENT_ROOT'] : $requestedRoot);
            if (!$resolvedRoot || !is_dir($resolvedRoot) || !is_readable($resolvedRoot) || @scandir($resolvedRoot) === false) throw new RuntimeException('This folder is not accessible. Check folder permissions or hosting restrictions.');
            $data['root_path'] = $resolvedRoot;
        }
        $current = $_POST['current_password'] ?? '';
        $new = $_POST['new_password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';
        if (!is_string($current) || !is_string($new) || !is_string($confirm)) fmAuthReply(400, 'Invalid password fields. Nothing was saved.');
        $changePassword = $current !== '' || $new !== '' || $confirm !== '';
        $newHash = null;
        if ($changePassword) {
            if (!password_verify($current, $authPasswordHash)) fmAuthReply(403, 'Current password is incorrect. Nothing was saved.');
            if (strlen($new) < 12 || strlen($new) > 72 || strpos($new, "\0") !== false || $new !== $confirm) fmAuthReply(400, 'New passwords must match and contain 12–72 bytes. Nothing was saved.');
            $newHash = password_hash($new, PASSWORD_DEFAULT);
        }
        fmUpdateWorkspaceConfiguration($data, $authPasswordHash, $newHash);
        if ($newHash !== null) {
            session_regenerate_id(true);
            $_SESSION['auth'] = hash('sha256', $newHash);
            $_SESSION['auth_started'] = $_SESSION['auth_seen'] = time();
        }
        session_write_close();
        fmAuthReply(200, $changePassword ? 'Settings and password saved. Other sessions have been signed out.' : 'Settings saved.', ['password_changed' => $changePassword]);
    } catch (Throwable $error) { fmAuthReply(400, $error->getMessage()); }
}
if ($authAction === 'change_password' && $isPostRequest) {
    $current = $_POST['current_password'] ?? null;
    $new = $_POST['new_password'] ?? null;
    $confirm = $_POST['confirm_password'] ?? null;
    if (!is_string($current) || !is_string($new) || !is_string($confirm) || !password_verify($current, $authPasswordHash)) fmAuthReply(403, 'Current password is incorrect.');
    if (strlen($new) < 12 || strlen($new) > 72 || strpos($new, "\0") !== false || $new !== $confirm) fmAuthReply(400, 'New passwords must match and contain 12–72 bytes.');
    try {
        $newHash = password_hash($new, PASSWORD_DEFAULT);
        fmUpdatePasswordHash($authPasswordHash, $newHash);
        session_regenerate_id(true);
        $_SESSION['auth'] = hash('sha256', $newHash);
        $_SESSION['auth_started'] = $_SESSION['auth_seen'] = time();
        session_write_close();
        fmAuthReply(200, 'Password changed. Other sessions have been signed out.');
    } catch (Throwable $error) { fmAuthReply(500, $error->getMessage()); }
}
if (!$isPostRequest && isset($_GET['action']) && (!is_string($_GET['action']) || !in_array($_GET['action'], ['list', 'tree', 'search', 'download'], true))) fmAuthReply(405, 'File changes require a protected POST request.');
$loginBlockedNotice = null;
if (!$isPostRequest && !isset($_GET['editor']) && !isset($_GET['action']) && !empty($_SESSION['login_notice_pending'])) {
    unset($_SESSION['login_notice_pending']);
    try {
        $activity = fmLoginActivitySnapshot();
        if ($activity['blocked_ips'] > 0) $loginBlockedNotice = $activity['blocked_ips'];
    } catch (Throwable $ignored) {}
}
session_write_close();
// No application code or file operation executes before this authentication gate.

$username = "Renat2985";
$root_path = $_SERVER['DOCUMENT_ROOT'];

// Configuration
$config = [
    "root_path" => $root_path,
    "allowed_extensions" => ["*"],
    "timezone" => "Africa/Lagos",
    "date_format" => "M j Y, H:i:s",
    "font_size" => "16px",
];

// Read settings from disk as data, never eval, so OPcache cannot retain old values.
if (preg_match('/^\$workspaceSettingsBase64 = \'([A-Za-z0-9+\/=]*)\';$/m', $authHeader, $settingsMatch) !== 1) fmAuthReply(503, 'Settings configuration unavailable.');
try {
    if ($settingsMatch[1] !== '') {
        $decoded = base64_decode($settingsMatch[1], true);
        $storedSettings = fmValidateWorkspaceSettings($decoded === false ? null : json_decode($decoded, true));
        $config = array_replace($config, $storedSettings);
    } elseif (is_file("$root_path/.fm-config")) {
        // Existing installations keep their settings until the next Settings save.
        $legacy = @file_get_contents("$root_path/.fm-config", false, null, 0, 4097);
        $legacy = is_string($legacy) && strlen($legacy) <= 4096 ? json_decode($legacy, true) : null;
        if (is_array($legacy)) {
            try { $config = array_replace($config, fmValidateWorkspaceSettings(array_replace($config, $legacy))); }
            catch (Throwable $ignored) { /* Invalid legacy settings cannot inject markup or CSS. */ }
        }
    }
} catch (Throwable $error) { fmAuthReply(503, 'Settings configuration unavailable.'); }

// Map the workspace to its public URL only when it is inside the document root.
$publicDocumentRoot = realpath($_SERVER['DOCUMENT_ROOT']);
$publicWorkspaceRoot = realpath($config['root_path']);
$publicWorkspaceBase = null;
$publicWebsitePrefix = null;
if ($publicDocumentRoot && $publicWorkspaceRoot && strpos($publicDocumentRoot, rtrim($publicWorkspaceRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
    $publicWebsitePrefix = str_replace(DIRECTORY_SEPARATOR, '/', substr($publicDocumentRoot, strlen(rtrim($publicWorkspaceRoot, DIRECTORY_SEPARATOR))));
}
if ($publicDocumentRoot && $publicWorkspaceRoot && ($publicWorkspaceRoot === $publicDocumentRoot || strpos($publicWorkspaceRoot, rtrim($publicDocumentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0)) {
    $publicRelativeRoot = substr($publicWorkspaceRoot, strlen(rtrim($publicDocumentRoot, DIRECTORY_SEPARATOR)));
    $publicWorkspaceBase = rtrim(implode('/', array_map('rawurlencode', explode('/', str_replace(DIRECTORY_SEPARATOR, '/', $publicRelativeRoot)))), '/');
}

// Only this read-only picker may explore outside the selected workspace.
if ($isPostRequest && ($_POST['action'] ?? '') === 'browse_folders') {
    $scope = $_POST['scope'] ?? 'workspace';
    if (!in_array($scope, ['workspace', 'server'], true)) fmAuthReply(400, 'Invalid folder browser scope.');
    $root = realpath($config['root_path']);
    $requested = $_POST['folder'] ?? '';
    if (!is_string($requested) || strpos($requested, "\0") !== false) fmAuthReply(400, 'Invalid folder path.');
    $candidate = $scope === 'server' ? ($requested === '' ? $config['root_path'] : $requested) : $root . '/' . ltrim($requested, '/');
    $folder = @realpath($candidate);
    if (!$folder || !is_dir($folder) || !is_readable($folder)) fmAuthReply(403, 'Folder unavailable. Check permissions or hosting restrictions.');
    if ($scope === 'workspace' && !securityCheck($folder)) fmAuthReply(403, 'Choose a folder inside the current workspace.');
    $entries = @scandir($folder);
    if ($entries === false) fmAuthReply(403, 'The server does not allow listing this folder.');
    $displayPath = function ($path) use ($scope, $root) { return $scope === 'server' ? $path : (substr($path, strlen(rtrim($root, '/'))) ?: '/'); };
    $folders = [];
    foreach ($entries as $name) {
        if ($name === '.' || $name === '..' || !preg_match('//u', $name)) continue;
        $child = $folder . '/' . $name;
        if (!@is_dir($child)) continue;
        if ($scope === 'workspace' && !securityCheck($child)) continue;
        $folders[] = ['name' => $name, 'path' => $displayPath($child), 'readable' => @is_readable($child)];
    }
    usort($folders, function ($a, $b) { return strnatcasecmp($a['name'], $b['name']); });
    $parent = dirname($folder);
    if ($parent === $folder || ($scope === 'workspace' && !securityCheck($parent))) $parent = null;
    fmAuthReply(200, 'Folders loaded.', ['folder' => $displayPath($folder), 'parent' => $parent === null ? null : $displayPath($parent), 'folders' => $folders]);
}

// Set timezone
date_default_timezone_set($config["timezone"]);

/*
Seti icon mappings from microsoft/vscode/extensions/theme-seti.
Font loaded from jsDelivr, pinned to revision 8993bc4913b5ecd98a639457ac1dabf5e4c58787.

THIRD-PARTY SOFTWARE NOTICES AND INFORMATION
For Microsoft vscode-theme-seti

This file is based on or incorporates material from the projects listed below ("Third Party OSS"). The original copyright
notice and the license under which Microsoft received such Third Party OSS, are set forth below. Such licenses and notice
are provided for informational purposes only. Microsoft licenses the Third Party OSS to you under the licensing terms for
the Microsoft product or service. Microsoft reserves all other rights not expressly granted under this agreement, whether
by implication, estoppel or otherwise.†

1.       Seti UI - A subtle dark colored UI theme for Atom. (https://github.com/jesseweed/seti-ui)

Copyright (c) 2014 Jesse Weed

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
$fileIconData = json_decode(<<<'SETI_JSON'
{"icons":{"_R_light":{"char":"\ue001","color":"#498ba7"},"_R":{"char":"\ue001","color":"#519aba"},"_argdown_light":{"char":"\ue003","color":"#498ba7"},"_argdown":{"char":"\ue003","color":"#519aba"},"_asm_light":{"char":"\ue004","color":"#b8383d"},"_asm":{"char":"\ue004","color":"#cc3e44"},"_audio_light":{"char":"\ue005","color":"#9068b0"},"_audio":{"char":"\ue005","color":"#a074c4"},"_babel_light":{"char":"\ue006","color":"#b7b73b"},"_babel":{"char":"\ue006","color":"#cbcb41"},"_bazel_light":{"char":"\ue007","color":"#7fae42"},"_bazel":{"char":"\ue007","color":"#8dc149"},"_bazel_1_light":{"char":"\ue007","color":"#455155"},"_bazel_1":{"char":"\ue007","color":"#4d5a5e"},"_bicep_light":{"char":"\ue008","color":"#498ba7"},"_bicep":{"char":"\ue008","color":"#519aba"},"_bower_light":{"char":"\ue009","color":"#cc6d2e"},"_bower":{"char":"\ue009","color":"#e37933"},"_bsl_light":{"char":"\ue00a","color":"#b8383d"},"_bsl":{"char":"\ue00a","color":"#cc3e44"},"_c_light":{"char":"\ue00c","color":"#498ba7"},"_c":{"char":"\ue00c","color":"#519aba"},"_c-sharp_light":{"char":"\ue00b","color":"#498ba7"},"_c-sharp":{"char":"\ue00b","color":"#519aba"},"_c_1_light":{"char":"\ue00c","color":"#9068b0"},"_c_1":{"char":"\ue00c","color":"#a074c4"},"_c_2_light":{"char":"\ue00c","color":"#b7b73b"},"_c_2":{"char":"\ue00c","color":"#cbcb41"},"_cake_light":{"char":"\ue00d","color":"#b8383d"},"_cake":{"char":"\ue00d","color":"#cc3e44"},"_cake_php_light":{"char":"\ue00e","color":"#b8383d"},"_cake_php":{"char":"\ue00e","color":"#cc3e44"},"_clock_light":{"char":"\ue012","color":"#498ba7"},"_clock":{"char":"\ue012","color":"#519aba"},"_clock_1_light":{"char":"\ue012","color":"#627379"},"_clock_1":{"char":"\ue012","color":"#6d8086"},"_clojure_light":{"char":"\ue013","color":"#7fae42"},"_clojure":{"char":"\ue013","color":"#8dc149"},"_clojure_1_light":{"char":"\ue013","color":"#498ba7"},"_clojure_1":{"char":"\ue013","color":"#519aba"},"_code-climate_light":{"char":"\ue014","color":"#7fae42"},"_code-climate":{"char":"\ue014","color":"#8dc149"},"_code-search_light":{"char":"\ue015","color":"#9068b0"},"_code-search":{"char":"\ue015","color":"#a074c4"},"_coffee_light":{"char":"\ue016","color":"#b7b73b"},"_coffee":{"char":"\ue016","color":"#cbcb41"},"_coldfusion_light":{"char":"\ue018","color":"#498ba7"},"_coldfusion":{"char":"\ue018","color":"#519aba"},"_config_light":{"char":"\ue019","color":"#627379"},"_config":{"char":"\ue019","color":"#6d8086"},"_cpp_light":{"char":"\ue01a","color":"#498ba7"},"_cpp":{"char":"\ue01a","color":"#519aba"},"_cpp_1_light":{"char":"\ue01a","color":"#9068b0"},"_cpp_1":{"char":"\ue01a","color":"#a074c4"},"_cpp_2_light":{"char":"\ue01a","color":"#b7b73b"},"_cpp_2":{"char":"\ue01a","color":"#cbcb41"},"_crystal_light":{"char":"\ue01b","color":"#bfc2c1"},"_crystal":{"char":"\ue01b","color":"#d4d7d6"},"_crystal_embedded_light":{"char":"\ue01c","color":"#bfc2c1"},"_crystal_embedded":{"char":"\ue01c","color":"#d4d7d6"},"_css_light":{"char":"\ue01d","color":"#498ba7"},"_css":{"char":"\ue01d","color":"#519aba"},"_csv_light":{"char":"\ue01e","color":"#7fae42"},"_csv":{"char":"\ue01e","color":"#8dc149"},"_cu_light":{"char":"\ue01f","color":"#7fae42"},"_cu":{"char":"\ue01f","color":"#8dc149"},"_cu_1_light":{"char":"\ue01f","color":"#9068b0"},"_cu_1":{"char":"\ue01f","color":"#a074c4"},"_d_light":{"char":"\ue020","color":"#b8383d"},"_d":{"char":"\ue020","color":"#cc3e44"},"_dart_light":{"char":"\ue021","color":"#498ba7"},"_dart":{"char":"\ue021","color":"#519aba"},"_db_light":{"char":"\ue022","color":"#dd4b78"},"_db":{"char":"\ue022","color":"#f55385"},"_db_1_light":{"char":"\ue022","color":"#498ba7"},"_db_1":{"char":"\ue022","color":"#519aba"},"_default_light":{"char":"\ue023","color":"#bfc2c1"},"_default":{"char":"\ue023","color":"#d4d7d6"},"_docker_light":{"char":"\ue025","color":"#498ba7"},"_docker":{"char":"\ue025","color":"#519aba"},"_docker_1_light":{"char":"\ue025","color":"#455155"},"_docker_1":{"char":"\ue025","color":"#4d5a5e"},"_docker_2_light":{"char":"\ue025","color":"#7fae42"},"_docker_2":{"char":"\ue025","color":"#8dc149"},"_docker_3_light":{"char":"\ue025","color":"#dd4b78"},"_docker_3":{"char":"\ue025","color":"#f55385"},"_ejs_light":{"char":"\ue027","color":"#b7b73b"},"_ejs":{"char":"\ue027","color":"#cbcb41"},"_elixir_light":{"char":"\ue028","color":"#9068b0"},"_elixir":{"char":"\ue028","color":"#a074c4"},"_elixir_script_light":{"char":"\ue029","color":"#9068b0"},"_elixir_script":{"char":"\ue029","color":"#a074c4"},"_elm_light":{"char":"\ue02a","color":"#498ba7"},"_elm":{"char":"\ue02a","color":"#519aba"},"_eslint_light":{"char":"\ue02c","color":"#9068b0"},"_eslint":{"char":"\ue02c","color":"#a074c4"},"_eslint_1_light":{"char":"\ue02c","color":"#455155"},"_eslint_1":{"char":"\ue02c","color":"#4d5a5e"},"_ethereum_light":{"char":"\ue02d","color":"#498ba7"},"_ethereum":{"char":"\ue02d","color":"#519aba"},"_f-sharp_light":{"char":"\ue02e","color":"#498ba7"},"_f-sharp":{"char":"\ue02e","color":"#519aba"},"_favicon_light":{"char":"\ue02f","color":"#b7b73b"},"_favicon":{"char":"\ue02f","color":"#cbcb41"},"_firebase_light":{"char":"\ue030","color":"#cc6d2e"},"_firebase":{"char":"\ue030","color":"#e37933"},"_firefox_light":{"char":"\ue031","color":"#cc6d2e"},"_firefox":{"char":"\ue031","color":"#e37933"},"_font_light":{"char":"\ue033","color":"#b8383d"},"_font":{"char":"\ue033","color":"#cc3e44"},"_git_light":{"char":"\ue034","color":"#3b4b52"},"_git":{"char":"\ue034","color":"#41535b"},"_github_light":{"char":"\ue037","color":"#bfc2c1"},"_github":{"char":"\ue037","color":"#d4d7d6"},"_gitlab_light":{"char":"\ue038","color":"#cc6d2e"},"_gitlab":{"char":"\ue038","color":"#e37933"},"_go_light":{"char":"\ue039","color":"#498ba7"},"_go":{"char":"\ue039","color":"#519aba"},"_go2_light":{"char":"\ue03a","color":"#498ba7"},"_go2":{"char":"\ue03a","color":"#519aba"},"_godot_light":{"char":"\ue03b","color":"#498ba7"},"_godot":{"char":"\ue03b","color":"#519aba"},"_godot_1_light":{"char":"\ue03b","color":"#b8383d"},"_godot_1":{"char":"\ue03b","color":"#cc3e44"},"_godot_2_light":{"char":"\ue03b","color":"#b7b73b"},"_godot_2":{"char":"\ue03b","color":"#cbcb41"},"_godot_3_light":{"char":"\ue03b","color":"#9068b0"},"_godot_3":{"char":"\ue03b","color":"#a074c4"},"_gradle_light":{"char":"\ue03c","color":"#498ba7"},"_gradle":{"char":"\ue03c","color":"#519aba"},"_grails_light":{"char":"\ue03d","color":"#7fae42"},"_grails":{"char":"\ue03d","color":"#8dc149"},"_graphql_light":{"char":"\ue03e","color":"#dd4b78"},"_graphql":{"char":"\ue03e","color":"#f55385"},"_grunt_light":{"char":"\ue03f","color":"#cc6d2e"},"_grunt":{"char":"\ue03f","color":"#e37933"},"_gulp_light":{"char":"\ue040","color":"#b8383d"},"_gulp":{"char":"\ue040","color":"#cc3e44"},"_hacklang_light":{"char":"\ue041","color":"#cc6d2e"},"_hacklang":{"char":"\ue041","color":"#e37933"},"_haml_light":{"char":"\ue042","color":"#b8383d"},"_haml":{"char":"\ue042","color":"#cc3e44"},"_happenings_light":{"char":"\ue043","color":"#498ba7"},"_happenings":{"char":"\ue043","color":"#519aba"},"_haskell_light":{"char":"\ue044","color":"#9068b0"},"_haskell":{"char":"\ue044","color":"#a074c4"},"_haxe_light":{"char":"\ue045","color":"#cc6d2e"},"_haxe":{"char":"\ue045","color":"#e37933"},"_haxe_1_light":{"char":"\ue045","color":"#b7b73b"},"_haxe_1":{"char":"\ue045","color":"#cbcb41"},"_haxe_2_light":{"char":"\ue045","color":"#498ba7"},"_haxe_2":{"char":"\ue045","color":"#519aba"},"_haxe_3_light":{"char":"\ue045","color":"#9068b0"},"_haxe_3":{"char":"\ue045","color":"#a074c4"},"_heroku_light":{"char":"\ue046","color":"#9068b0"},"_heroku":{"char":"\ue046","color":"#a074c4"},"_hex_light":{"char":"\ue047","color":"#b8383d"},"_hex":{"char":"\ue047","color":"#cc3e44"},"_html_light":{"char":"\ue048","color":"#498ba7"},"_html":{"char":"\ue048","color":"#519aba"},"_html_1_light":{"char":"\ue048","color":"#7fae42"},"_html_1":{"char":"\ue048","color":"#8dc149"},"_html_2_light":{"char":"\ue048","color":"#b7b73b"},"_html_2":{"char":"\ue048","color":"#cbcb41"},"_html_3_light":{"char":"\ue048","color":"#cc6d2e"},"_html_3":{"char":"\ue048","color":"#e37933"},"_html_erb_light":{"char":"\ue049","color":"#b8383d"},"_html_erb":{"char":"\ue049","color":"#cc3e44"},"_ignored_light":{"char":"\ue04a","color":"#3b4b52"},"_ignored":{"char":"\ue04a","color":"#41535b"},"_illustrator_light":{"char":"\ue04b","color":"#b7b73b"},"_illustrator":{"char":"\ue04b","color":"#cbcb41"},"_image_light":{"char":"\ue04c","color":"#9068b0"},"_image":{"char":"\ue04c","color":"#a074c4"},"_info_light":{"char":"\ue04d","color":"#498ba7"},"_info":{"char":"\ue04d","color":"#519aba"},"_ionic_light":{"char":"\ue04e","color":"#498ba7"},"_ionic":{"char":"\ue04e","color":"#519aba"},"_jade_light":{"char":"\ue04f","color":"#b8383d"},"_jade":{"char":"\ue04f","color":"#cc3e44"},"_java_light":{"char":"\ue050","color":"#b8383d"},"_java":{"char":"\ue050","color":"#cc3e44"},"_java_1_light":{"char":"\ue050","color":"#498ba7"},"_java_1":{"char":"\ue050","color":"#519aba"},"_javascript_light":{"char":"\ue051","color":"#b7b73b"},"_javascript":{"char":"\ue051","color":"#cbcb41"},"_javascript_1_light":{"char":"\ue051","color":"#cc6d2e"},"_javascript_1":{"char":"\ue051","color":"#e37933"},"_javascript_2_light":{"char":"\ue051","color":"#498ba7"},"_javascript_2":{"char":"\ue051","color":"#519aba"},"_jenkins_light":{"char":"\ue052","color":"#b8383d"},"_jenkins":{"char":"\ue052","color":"#cc3e44"},"_jinja_light":{"char":"\ue053","color":"#b8383d"},"_jinja":{"char":"\ue053","color":"#cc3e44"},"_json_light":{"char":"\ue055","color":"#b7b73b"},"_json":{"char":"\ue055","color":"#cbcb41"},"_json_1_light":{"char":"\ue055","color":"#7fae42"},"_json_1":{"char":"\ue055","color":"#8dc149"},"_julia_light":{"char":"\ue056","color":"#9068b0"},"_julia":{"char":"\ue056","color":"#a074c4"},"_karma_light":{"char":"\ue057","color":"#7fae42"},"_karma":{"char":"\ue057","color":"#8dc149"},"_kotlin_light":{"char":"\ue058","color":"#cc6d2e"},"_kotlin":{"char":"\ue058","color":"#e37933"},"_less_light":{"char":"\ue059","color":"#498ba7"},"_less":{"char":"\ue059","color":"#519aba"},"_license_light":{"char":"\ue05a","color":"#b7b73b"},"_license":{"char":"\ue05a","color":"#cbcb41"},"_license_1_light":{"char":"\ue05a","color":"#cc6d2e"},"_license_1":{"char":"\ue05a","color":"#e37933"},"_license_2_light":{"char":"\ue05a","color":"#b8383d"},"_license_2":{"char":"\ue05a","color":"#cc3e44"},"_liquid_light":{"char":"\ue05b","color":"#7fae42"},"_liquid":{"char":"\ue05b","color":"#8dc149"},"_livescript_light":{"char":"\ue05c","color":"#498ba7"},"_livescript":{"char":"\ue05c","color":"#519aba"},"_lock_light":{"char":"\ue05d","color":"#7fae42"},"_lock":{"char":"\ue05d","color":"#8dc149"},"_lua_light":{"char":"\ue05e","color":"#498ba7"},"_lua":{"char":"\ue05e","color":"#519aba"},"_makefile_light":{"char":"\ue05f","color":"#cc6d2e"},"_makefile":{"char":"\ue05f","color":"#e37933"},"_makefile_1_light":{"char":"\ue05f","color":"#9068b0"},"_makefile_1":{"char":"\ue05f","color":"#a074c4"},"_makefile_2_light":{"char":"\ue05f","color":"#627379"},"_makefile_2":{"char":"\ue05f","color":"#6d8086"},"_makefile_3_light":{"char":"\ue05f","color":"#498ba7"},"_makefile_3":{"char":"\ue05f","color":"#519aba"},"_markdown_light":{"char":"\ue060","color":"#498ba7"},"_markdown":{"char":"\ue060","color":"#519aba"},"_maven_light":{"char":"\ue061","color":"#b8383d"},"_maven":{"char":"\ue061","color":"#cc3e44"},"_mdo_light":{"char":"\ue062","color":"#b8383d"},"_mdo":{"char":"\ue062","color":"#cc3e44"},"_mustache_light":{"char":"\ue063","color":"#cc6d2e"},"_mustache":{"char":"\ue063","color":"#e37933"},"_nim_light":{"char":"\ue065","color":"#b7b73b"},"_nim":{"char":"\ue065","color":"#cbcb41"},"_notebook_light":{"char":"\ue066","color":"#498ba7"},"_notebook":{"char":"\ue066","color":"#519aba"},"_npm_light":{"char":"\ue067","color":"#3b4b52"},"_npm":{"char":"\ue067","color":"#41535b"},"_npm_1_light":{"char":"\ue067","color":"#b8383d"},"_npm_1":{"char":"\ue067","color":"#cc3e44"},"_npm_ignored_light":{"char":"\ue068","color":"#3b4b52"},"_npm_ignored":{"char":"\ue068","color":"#41535b"},"_nunjucks_light":{"char":"\ue069","color":"#7fae42"},"_nunjucks":{"char":"\ue069","color":"#8dc149"},"_ocaml_light":{"char":"\ue06a","color":"#cc6d2e"},"_ocaml":{"char":"\ue06a","color":"#e37933"},"_odata_light":{"char":"\ue06b","color":"#cc6d2e"},"_odata":{"char":"\ue06b","color":"#e37933"},"_pddl_light":{"char":"\ue06c","color":"#9068b0"},"_pddl":{"char":"\ue06c","color":"#a074c4"},"_pdf_light":{"char":"\ue06d","color":"#b8383d"},"_pdf":{"char":"\ue06d","color":"#cc3e44"},"_perl_light":{"char":"\ue06e","color":"#498ba7"},"_perl":{"char":"\ue06e","color":"#519aba"},"_photoshop_light":{"char":"\ue06f","color":"#498ba7"},"_photoshop":{"char":"\ue06f","color":"#519aba"},"_php_light":{"char":"\ue070","color":"#9068b0"},"_php":{"char":"\ue070","color":"#a074c4"},"_pipeline_light":{"char":"\ue071","color":"#cc6d2e"},"_pipeline":{"char":"\ue071","color":"#e37933"},"_plan_light":{"char":"\ue072","color":"#7fae42"},"_plan":{"char":"\ue072","color":"#8dc149"},"_platformio_light":{"char":"\ue073","color":"#cc6d2e"},"_platformio":{"char":"\ue073","color":"#e37933"},"_powershell_light":{"char":"\ue074","color":"#498ba7"},"_powershell":{"char":"\ue074","color":"#519aba"},"_prisma_light":{"char":"\ue075","color":"#498ba7"},"_prisma":{"char":"\ue075","color":"#519aba"},"_prolog_light":{"char":"\ue077","color":"#cc6d2e"},"_prolog":{"char":"\ue077","color":"#e37933"},"_pug_light":{"char":"\ue078","color":"#b8383d"},"_pug":{"char":"\ue078","color":"#cc3e44"},"_puppet_light":{"char":"\ue079","color":"#b7b73b"},"_puppet":{"char":"\ue079","color":"#cbcb41"},"_purescript_light":{"char":"\ue07a","color":"#bfc2c1"},"_purescript":{"char":"\ue07a","color":"#d4d7d6"},"_python_light":{"char":"\ue07b","color":"#498ba7"},"_python":{"char":"\ue07b","color":"#519aba"},"_react_light":{"char":"\ue07d","color":"#498ba7"},"_react":{"char":"\ue07d","color":"#519aba"},"_react_1_light":{"char":"\ue07d","color":"#cc6d2e"},"_react_1":{"char":"\ue07d","color":"#e37933"},"_reasonml_light":{"char":"\ue07e","color":"#b8383d"},"_reasonml":{"char":"\ue07e","color":"#cc3e44"},"_rescript_light":{"char":"\ue07f","color":"#b8383d"},"_rescript":{"char":"\ue07f","color":"#cc3e44"},"_rescript_1_light":{"char":"\ue07f","color":"#dd4b78"},"_rescript_1":{"char":"\ue07f","color":"#f55385"},"_rollup_light":{"char":"\ue080","color":"#b8383d"},"_rollup":{"char":"\ue080","color":"#cc3e44"},"_ruby_light":{"char":"\ue081","color":"#b8383d"},"_ruby":{"char":"\ue081","color":"#cc3e44"},"_rust_light":{"char":"\ue082","color":"#627379"},"_rust":{"char":"\ue082","color":"#6d8086"},"_salesforce_light":{"char":"\ue083","color":"#498ba7"},"_salesforce":{"char":"\ue083","color":"#519aba"},"_sass_light":{"char":"\ue084","color":"#dd4b78"},"_sass":{"char":"\ue084","color":"#f55385"},"_sbt_light":{"char":"\ue085","color":"#498ba7"},"_sbt":{"char":"\ue085","color":"#519aba"},"_scala_light":{"char":"\ue086","color":"#b8383d"},"_scala":{"char":"\ue086","color":"#cc3e44"},"_shell_light":{"char":"\ue089","color":"#7fae42"},"_shell":{"char":"\ue089","color":"#8dc149"},"_slim_light":{"char":"\ue08a","color":"#cc6d2e"},"_slim":{"char":"\ue08a","color":"#e37933"},"_smarty_light":{"char":"\ue08b","color":"#b7b73b"},"_smarty":{"char":"\ue08b","color":"#cbcb41"},"_spring_light":{"char":"\ue08c","color":"#7fae42"},"_spring":{"char":"\ue08c","color":"#8dc149"},"_stylelint_light":{"char":"\ue08d","color":"#bfc2c1"},"_stylelint":{"char":"\ue08d","color":"#d4d7d6"},"_stylelint_1_light":{"char":"\ue08d","color":"#455155"},"_stylelint_1":{"char":"\ue08d","color":"#4d5a5e"},"_stylus_light":{"char":"\ue08e","color":"#7fae42"},"_stylus":{"char":"\ue08e","color":"#8dc149"},"_sublime_light":{"char":"\ue08f","color":"#cc6d2e"},"_sublime":{"char":"\ue08f","color":"#e37933"},"_svelte_light":{"char":"\ue090","color":"#b8383d"},"_svelte":{"char":"\ue090","color":"#cc3e44"},"_svg_light":{"char":"\ue091","color":"#9068b0"},"_svg":{"char":"\ue091","color":"#a074c4"},"_svg_1_light":{"char":"\ue091","color":"#498ba7"},"_svg_1":{"char":"\ue091","color":"#519aba"},"_swift_light":{"char":"\ue092","color":"#cc6d2e"},"_swift":{"char":"\ue092","color":"#e37933"},"_terraform_light":{"char":"\ue093","color":"#9068b0"},"_terraform":{"char":"\ue093","color":"#a074c4"},"_tex_light":{"char":"\ue094","color":"#498ba7"},"_tex":{"char":"\ue094","color":"#519aba"},"_tex_1_light":{"char":"\ue094","color":"#b7b73b"},"_tex_1":{"char":"\ue094","color":"#cbcb41"},"_tex_2_light":{"char":"\ue094","color":"#cc6d2e"},"_tex_2":{"char":"\ue094","color":"#e37933"},"_tex_3_light":{"char":"\ue094","color":"#bfc2c1"},"_tex_3":{"char":"\ue094","color":"#d4d7d6"},"_todo":{"char":"\ue096","color":"#9da5b4"},"_tsconfig_light":{"char":"\ue097","color":"#498ba7"},"_tsconfig":{"char":"\ue097","color":"#519aba"},"_twig_light":{"char":"\ue098","color":"#7fae42"},"_twig":{"char":"\ue098","color":"#8dc149"},"_typescript_light":{"char":"\ue099","color":"#498ba7"},"_typescript":{"char":"\ue099","color":"#519aba"},"_typescript_1_light":{"char":"\ue099","color":"#cc6d2e"},"_typescript_1":{"char":"\ue099","color":"#e37933"},"_vala_light":{"char":"\ue09a","color":"#627379"},"_vala":{"char":"\ue09a","color":"#6d8086"},"_video_light":{"char":"\ue09b","color":"#dd4b78"},"_video":{"char":"\ue09b","color":"#f55385"},"_vite_light":{"char":"\ue09c","color":"#b7b73b"},"_vite":{"char":"\ue09c","color":"#cbcb41"},"_vue_light":{"char":"\ue09d","color":"#7fae42"},"_vue":{"char":"\ue09d","color":"#8dc149"},"_wasm_light":{"char":"\ue09e","color":"#9068b0"},"_wasm":{"char":"\ue09e","color":"#a074c4"},"_wat_light":{"char":"\ue09f","color":"#9068b0"},"_wat":{"char":"\ue09f","color":"#a074c4"},"_webpack_light":{"char":"\ue0a0","color":"#498ba7"},"_webpack":{"char":"\ue0a0","color":"#519aba"},"_wgt_light":{"char":"\ue0a1","color":"#498ba7"},"_wgt":{"char":"\ue0a1","color":"#519aba"},"_windows_light":{"char":"\ue0a2","color":"#498ba7"},"_windows":{"char":"\ue0a2","color":"#519aba"},"_word_light":{"char":"\ue0a3","color":"#498ba7"},"_word":{"char":"\ue0a3","color":"#519aba"},"_xls_light":{"char":"\ue0a4","color":"#7fae42"},"_xls":{"char":"\ue0a4","color":"#8dc149"},"_xml_light":{"char":"\ue0a5","color":"#cc6d2e"},"_xml":{"char":"\ue0a5","color":"#e37933"},"_yarn_light":{"char":"\ue0a6","color":"#498ba7"},"_yarn":{"char":"\ue0a6","color":"#519aba"},"_yml_light":{"char":"\ue0a7","color":"#9068b0"},"_yml":{"char":"\ue0a7","color":"#a074c4"},"_zig_light":{"char":"\ue0a8","color":"#cc6d2e"},"_zig":{"char":"\ue0a8","color":"#e37933"},"_zip_light":{"char":"\ue0a9","color":"#b8383d"},"_zip":{"char":"\ue0a9","color":"#cc3e44"},"_zip_1_light":{"char":"\ue0a9","color":"#627379"},"_zip_1":{"char":"\ue0a9","color":"#6d8086"}},"extensions":{"bsl":"_bsl","mdo":"_mdo","cls":"_salesforce","apex":"_salesforce","asm":"_asm","s":"_asm","bicep":"_bicep","bzl":"_bazel","bazel":"_bazel","build":"_bazel","workspace":"_bazel","bazelignore":"_bazel","bazelversion":"_bazel","h":"_c_1","aspx":"_html","ascx":"_html_1","asax":"_html_2","master":"_html_2","hh":"_cpp_1","hpp":"_cpp_1","hxx":"_cpp_1","h++":"_cpp_1","edn":"_clojure_1","cfc":"_coldfusion","cfm":"_coldfusion","litcoffee":"_coffee","config":"_config","cr":"_crystal","ecr":"_crystal_embedded","slang":"_crystal_embedded","cson":"_json","css.map":"_css","sss":"_css","csv":"_csv","xls":"_xls","xlsx":"_xls","cuh":"_cu_1","hu":"_cu_1","cake":"_cake","ctp":"_cake_php","d":"_d","doc":"_word","docx":"_word","ejs":"_ejs","ex":"_elixir","exs":"_elixir_script","elm":"_elm","ico":"_favicon","gitconfig":"_git","gitkeep":"_git","gitattributes":"_git","gitmodules":"_git","slide":"_go","article":"_go","gd":"_godot","godot":"_godot_1","tres":"_godot_2","tscn":"_godot_3","gradle":"_gradle","gsp":"_grails","gql":"_graphql","graphql":"_graphql","graphqls":"_graphql","hack":"_hacklang","haml":"_haml","hs":"_haskell","lhs":"_haskell","hx":"_haxe","hxs":"_haxe_1","hxp":"_haxe_2","hxml":"_haxe_3","jade":"_jade","class":"_java_1","classpath":"_java","js.map":"_javascript","cjs.map":"_javascript","mjs.map":"_javascript","spec.js":"_javascript_1","spec.cjs":"_javascript_1","spec.mjs":"_javascript_1","test.js":"_javascript_1","test.cjs":"_javascript_1","test.mjs":"_javascript_1","es":"_javascript","es5":"_javascript","es7":"_javascript","jinja":"_jinja","jinja2":"_jinja","kt":"_kotlin","kts":"_kotlin","liquid":"_liquid","ls":"_livescript","argdown":"_argdown","ad":"_argdown","mustache":"_mustache","stache":"_mustache","nim":"_nim","nims":"_nim","github-issues":"_github","ipynb":"_notebook","njk":"_nunjucks","nunjucks":"_nunjucks","nunjs":"_nunjucks","nunj":"_nunjucks","njs":"_nunjucks","nj":"_nunjucks","npm-debug.log":"_npm","npmignore":"_npm_1","npmrc":"_npm_1","ml":"_ocaml","mli":"_ocaml","cmx":"_ocaml","cmxa":"_ocaml","odata":"_odata","php.inc":"_php","pipeline":"_pipeline","pddl":"_pddl","plan":"_plan","happenings":"_happenings","prisma":"_prisma","pp":"_puppet","epp":"_puppet","purs":"_purescript","spec.jsx":"_react_1","test.jsx":"_react_1","cjsx":"_react","spec.tsx":"_react_1","test.tsx":"_react_1","re":"_reasonml","res":"_rescript","resi":"_rescript_1","r":"_R","rmd":"_R","erb":"_html_erb","erb.html":"_html_erb","html.erb":"_html_erb","sass":"_sass","springbeans":"_spring","slim":"_slim","smarty.tpl":"_smarty","tpl":"_smarty","sbt":"_sbt","scala":"_scala","sol":"_ethereum","styl":"_stylus","svelte":"_svelte","soql":"_db_1","tf":"_terraform","tf.json":"_terraform","tfvars":"_terraform","tfvars.json":"_terraform","dtx":"_tex_2","ins":"_tex_3","toml":"_config","twig":"_twig","spec.ts":"_typescript_1","test.ts":"_typescript_1","vala":"_vala","vapi":"_vala","component":"_html_3","vue":"_vue","wasm":"_wasm","wat":"_wat","pro":"_prolog","zig":"_zig","jar":"_zip","zip":"_zip_1","wgt":"_wgt","ai":"_illustrator","psd":"_photoshop","pdf":"_pdf","eot":"_font","ttf":"_font","woff":"_font","woff2":"_font","otf":"_font","avif":"_image","gif":"_image","jpg":"_image","jpeg":"_image","png":"_image","pxm":"_image","svg":"_svg","svgx":"_image","tiff":"_image","webp":"_image","sublime-project":"_sublime","sublime-workspace":"_sublime","mov":"_video","ogv":"_video","webm":"_video","avi":"_video","mpg":"_video","mp4":"_video","mp3":"_audio","ogg":"_audio","wav":"_audio","flac":"_audio","3ds":"_svg_1","3dm":"_svg_1","stl":"_svg_1","obj":"_svg_1","dae":"_svg_1","babelrc":"_babel","babelrc.js":"_babel","babelrc.cjs":"_babel","bazelrc":"_bazel_1","bowerrc":"_bower","dockerignore":"_docker_1","codeclimate.yml":"_code-climate","eslintrc":"_eslint","eslintrc.js":"_eslint","eslintrc.cjs":"_eslint","eslintrc.yaml":"_eslint","eslintrc.yml":"_eslint","eslintrc.json":"_eslint","eslintignore":"_eslint_1","firebaserc":"_firebase","gitlab-ci.yml":"_gitlab","jshintrc":"_javascript_2","jscsrc":"_javascript_2","stylelintrc":"_stylelint","stylelintrc.json":"_stylelint","stylelintrc.yaml":"_stylelint","stylelintrc.yml":"_stylelint","stylelintrc.js":"_stylelint","stylelintignore":"_stylelint_1","direnv":"_config","static":"_config","slugignore":"_config","tmp":"_clock_1","htaccess":"_config","key":"_lock","cert":"_lock","cer":"_lock","crt":"_lock","pem":"_lock","ds_store":"_ignored","html":"_html_3","htm":"_html_3","php":"_php","js":"_javascript","mjs":"_javascript","cjs":"_javascript","jsx":"_react","ts":"_typescript","tsx":"_react","py":"_python","sh":"_shell","bash":"_shell","sql":"_db","db":"_db","sqlite":"_db","sqlite3":"_db","css":"_css","scss":"_sass","less":"_less","json":"_json","jsonc":"_json","md":"_markdown","xml":"_xml","yaml":"_yml","yml":"_yml","c":"_c","cpp":"_cpp","java":"_java","go":"_go2","rs":"_rust","rb":"_ruby","cs":"_c-sharp","swift":"_swift","dart":"_dart"},"names":{"mix":"_hex","karma.conf.js":"_karma","karma.conf.cjs":"_karma","karma.conf.mjs":"_karma","karma.conf.coffee":"_karma","readme.md":"_info","readme.txt":"_info","readme":"_info","changelog.md":"_clock","changelog.txt":"_clock","changelog":"_clock","changes.md":"_clock","changes.txt":"_clock","changes":"_clock","version.md":"_clock","version.txt":"_clock","version":"_clock","mvnw":"_maven","pom.xml":"_maven","tsconfig.json":"_tsconfig","vite.config.js":"_vite","vite.config.ts":"_vite","vite.config.mjs":"_vite","vite.config.mts":"_vite","vite.config.cjs":"_vite","vite.config.cts":"_vite","swagger.json":"_json_1","swagger.yml":"_json_1","swagger.yaml":"_json_1","mime.types":"_config","jenkinsfile":"_jenkins","babel.config.js":"_babel","babel.config.json":"_babel","babel.config.cjs":"_babel","build":"_bazel","build.bazel":"_bazel","workspace":"_bazel","workspace.bazel":"_bazel","bower.json":"_bower","docker-healthcheck":"_docker_2","eslint.config.js":"_eslint","firebase.json":"_firebase","geckodriver":"_firefox","gruntfile.js":"_grunt","gruntfile.babel.js":"_grunt","gruntfile.coffee":"_grunt","gulpfile":"_gulp","gulpfile.js":"_gulp","ionic.config.json":"_ionic","ionic.project":"_ionic","platformio.ini":"_platformio","rollup.config.js":"_rollup","sass-lint.yml":"_sass","stylelint.config.js":"_stylelint","stylelint.config.cjs":"_stylelint","stylelint.config.mjs":"_stylelint","yarn.clean":"_yarn","yarn.lock":"_yarn","webpack.config.js":"_webpack","webpack.config.cjs":"_webpack","webpack.config.mjs":"_webpack","webpack.config.ts":"_webpack","webpack.config.build.js":"_webpack","webpack.config.build.cjs":"_webpack","webpack.config.build.mjs":"_webpack","webpack.config.build.ts":"_webpack","webpack.common.js":"_webpack","webpack.common.cjs":"_webpack","webpack.common.mjs":"_webpack","webpack.common.ts":"_webpack","webpack.dev.js":"_webpack","webpack.dev.cjs":"_webpack","webpack.dev.mjs":"_webpack","webpack.dev.ts":"_webpack","webpack.prod.js":"_webpack","webpack.prod.cjs":"_webpack","webpack.prod.mjs":"_webpack","webpack.prod.ts":"_webpack","license":"_license","licence":"_license","license.txt":"_license","licence.txt":"_license","license.md":"_license","licence.md":"_license","copying":"_license","copying.txt":"_license","copying.md":"_license","compiling":"_license_1","compiling.txt":"_license_1","compiling.md":"_license_1","contributing":"_license_2","contributing.txt":"_license_2","contributing.md":"_license_2","qmakefile":"_makefile_1","omakefile":"_makefile_2","cmakelists.txt":"_makefile_3","procfile":"_heroku","todo":"_todo","todo.txt":"_todo","todo.md":"_todo","npm-debug.log":"_npm_ignored"},"default":"_default","lightExtensions":{"bsl":"_bsl_light","mdo":"_mdo_light","cls":"_salesforce_light","apex":"_salesforce_light","asm":"_asm_light","s":"_asm_light","bicep":"_bicep_light","bzl":"_bazel_light","bazel":"_bazel_light","build":"_bazel_light","workspace":"_bazel_light","bazelignore":"_bazel_light","bazelversion":"_bazel_light","h":"_c_1_light","aspx":"_html_light","ascx":"_html_1_light","asax":"_html_2_light","master":"_html_2_light","hh":"_cpp_1_light","hpp":"_cpp_1_light","hxx":"_cpp_1_light","h++":"_cpp_1_light","edn":"_clojure_1_light","cfc":"_coldfusion_light","cfm":"_coldfusion_light","litcoffee":"_coffee_light","config":"_config_light","cr":"_crystal_light","ecr":"_crystal_embedded_light","slang":"_crystal_embedded_light","cson":"_json_light","css.map":"_css_light","sss":"_css_light","csv":"_csv_light","xls":"_xls_light","xlsx":"_xls_light","cuh":"_cu_1_light","hu":"_cu_1_light","cake":"_cake_light","ctp":"_cake_php_light","d":"_d_light","doc":"_word_light","docx":"_word_light","ejs":"_ejs_light","ex":"_elixir_light","exs":"_elixir_script_light","elm":"_elm_light","ico":"_favicon_light","gitconfig":"_git_light","gitkeep":"_git_light","gitattributes":"_git_light","gitmodules":"_git_light","slide":"_go_light","article":"_go_light","gd":"_godot_light","godot":"_godot_1_light","tres":"_godot_2_light","tscn":"_godot_3_light","gradle":"_gradle_light","gsp":"_grails_light","gql":"_graphql_light","graphql":"_graphql_light","graphqls":"_graphql_light","hack":"_hacklang_light","haml":"_haml_light","hs":"_haskell_light","lhs":"_haskell_light","hx":"_haxe_light","hxs":"_haxe_1_light","hxp":"_haxe_2_light","hxml":"_haxe_3_light","jade":"_jade_light","class":"_java_1_light","classpath":"_java_light","js.map":"_javascript_light","cjs.map":"_javascript_light","mjs.map":"_javascript_light","spec.js":"_javascript_1_light","spec.cjs":"_javascript_1_light","spec.mjs":"_javascript_1_light","test.js":"_javascript_1_light","test.cjs":"_javascript_1_light","test.mjs":"_javascript_1_light","es":"_javascript_light","es5":"_javascript_light","es7":"_javascript_light","jinja":"_jinja_light","jinja2":"_jinja_light","kt":"_kotlin_light","kts":"_kotlin_light","liquid":"_liquid_light","ls":"_livescript_light","argdown":"_argdown_light","ad":"_argdown_light","mustache":"_mustache_light","stache":"_mustache_light","nim":"_nim_light","nims":"_nim_light","github-issues":"_github_light","ipynb":"_notebook_light","njk":"_nunjucks_light","nunjucks":"_nunjucks_light","nunjs":"_nunjucks_light","nunj":"_nunjucks_light","njs":"_nunjucks_light","nj":"_nunjucks_light","npm-debug.log":"_npm_light","npmignore":"_npm_1_light","npmrc":"_npm_1_light","ml":"_ocaml_light","mli":"_ocaml_light","cmx":"_ocaml_light","cmxa":"_ocaml_light","odata":"_odata_light","php.inc":"_php_light","pipeline":"_pipeline_light","pddl":"_pddl_light","plan":"_plan_light","happenings":"_happenings_light","prisma":"_prisma_light","pp":"_puppet_light","epp":"_puppet_light","purs":"_purescript_light","spec.jsx":"_react_1_light","test.jsx":"_react_1_light","cjsx":"_react_light","spec.tsx":"_react_1_light","test.tsx":"_react_1_light","re":"_reasonml_light","res":"_rescript_light","resi":"_rescript_1_light","r":"_R_light","rmd":"_R_light","erb":"_html_erb_light","erb.html":"_html_erb_light","html.erb":"_html_erb_light","sass":"_sass_light","springbeans":"_spring_light","slim":"_slim_light","smarty.tpl":"_smarty_light","tpl":"_smarty_light","sbt":"_sbt_light","scala":"_scala_light","sol":"_ethereum_light","styl":"_stylus_light","svelte":"_svelte_light","soql":"_db_1_light","tf":"_terraform_light","tf.json":"_terraform_light","tfvars":"_terraform_light","tfvars.json":"_terraform_light","dtx":"_tex_2_light","ins":"_tex_3_light","toml":"_config_light","twig":"_twig_light","spec.ts":"_typescript_1_light","test.ts":"_typescript_1_light","vala":"_vala_light","vapi":"_vala_light","component":"_html_3_light","vue":"_vue_light","wasm":"_wasm_light","wat":"_wat_light","pro":"_prolog_light","zig":"_zig_light","jar":"_zip_light","zip":"_zip_1_light","wgt":"_wgt_light","ai":"_illustrator_light","psd":"_photoshop_light","pdf":"_pdf_light","eot":"_font_light","ttf":"_font_light","woff":"_font_light","woff2":"_font_light","otf":"_font_light","avif":"_image_light","gif":"_image_light","jpg":"_image_light","jpeg":"_image_light","png":"_image_light","pxm":"_image_light","svg":"_svg_light","svgx":"_image_light","tiff":"_image_light","webp":"_image_light","sublime-project":"_sublime_light","sublime-workspace":"_sublime_light","mov":"_video_light","ogv":"_video_light","webm":"_video_light","avi":"_video_light","mpg":"_video_light","mp4":"_video_light","mp3":"_audio_light","ogg":"_audio_light","wav":"_audio_light","flac":"_audio_light","3ds":"_svg_1_light","3dm":"_svg_1_light","stl":"_svg_1_light","obj":"_svg_1_light","dae":"_svg_1_light","babelrc":"_babel_light","babelrc.js":"_babel_light","babelrc.cjs":"_babel_light","bazelrc":"_bazel_1_light","bowerrc":"_bower_light","dockerignore":"_docker_1_light","codeclimate.yml":"_code-climate_light","eslintrc":"_eslint_light","eslintrc.js":"_eslint_light","eslintrc.cjs":"_eslint_light","eslintrc.yaml":"_eslint_light","eslintrc.yml":"_eslint_light","eslintrc.json":"_eslint_light","eslintignore":"_eslint_1_light","firebaserc":"_firebase_light","gitlab-ci.yml":"_gitlab_light","jshintrc":"_javascript_2_light","jscsrc":"_javascript_2_light","stylelintrc":"_stylelint_light","stylelintrc.json":"_stylelint_light","stylelintrc.yaml":"_stylelint_light","stylelintrc.yml":"_stylelint_light","stylelintrc.js":"_stylelint_light","stylelintignore":"_stylelint_1_light","direnv":"_config_light","static":"_config_light","slugignore":"_config_light","tmp":"_clock_1_light","htaccess":"_config_light","key":"_lock_light","cert":"_lock_light","cer":"_lock_light","crt":"_lock_light","pem":"_lock_light","ds_store":"_ignored_light","html":"_html_3_light","htm":"_html_3_light","php":"_php_light","js":"_javascript_light","mjs":"_javascript_light","cjs":"_javascript_light","jsx":"_react_light","ts":"_typescript_light","tsx":"_react_light","py":"_python_light","sh":"_shell_light","bash":"_shell_light","sql":"_db_light","db":"_db_light","sqlite":"_db_light","sqlite3":"_db_light","css":"_css_light","scss":"_sass_light","less":"_less_light","json":"_json_light","jsonc":"_json_light","md":"_markdown_light","xml":"_xml_light","yaml":"_yml_light","yml":"_yml_light","c":"_c_light","cpp":"_cpp_light","java":"_java_light","go":"_go2_light","rs":"_rust_light","rb":"_ruby_light","cs":"_c-sharp_light","swift":"_swift_light","dart":"_dart_light"},"lightNames":{"mix":"_hex_light","karma.conf.js":"_karma_light","karma.conf.cjs":"_karma_light","karma.conf.mjs":"_karma_light","karma.conf.coffee":"_karma_light","readme.md":"_info_light","readme.txt":"_info_light","readme":"_info_light","changelog.md":"_clock_light","changelog.txt":"_clock_light","changelog":"_clock_light","changes.md":"_clock_light","changes.txt":"_clock_light","changes":"_clock_light","version.md":"_clock_light","version.txt":"_clock_light","version":"_clock_light","mvnw":"_maven_light","pom.xml":"_maven_light","tsconfig.json":"_tsconfig_light","vite.config.js":"_vite_light","vite.config.ts":"_vite_light","vite.config.mjs":"_vite_light","vite.config.mts":"_vite_light","vite.config.cjs":"_vite_light","vite.config.cts":"_vite_light","swagger.json":"_json_1_light","swagger.yml":"_json_1_light","swagger.yaml":"_json_1_light","mime.types":"_config_light","jenkinsfile":"_jenkins_light","babel.config.js":"_babel_light","babel.config.json":"_babel_light","babel.config.cjs":"_babel_light","build":"_bazel_light","build.bazel":"_bazel_light","workspace":"_bazel_light","workspace.bazel":"_bazel_light","bower.json":"_bower_light","docker-healthcheck":"_docker_2_light","eslint.config.js":"_eslint_light","firebase.json":"_firebase_light","geckodriver":"_firefox_light","gruntfile.js":"_grunt_light","gruntfile.babel.js":"_grunt_light","gruntfile.coffee":"_grunt_light","gulpfile":"_gulp_light","gulpfile.js":"_gulp_light","ionic.config.json":"_ionic_light","ionic.project":"_ionic_light","platformio.ini":"_platformio_light","rollup.config.js":"_rollup_light","sass-lint.yml":"_sass_light","stylelint.config.js":"_stylelint_light","stylelint.config.cjs":"_stylelint_light","stylelint.config.mjs":"_stylelint_light","yarn.clean":"_yarn_light","yarn.lock":"_yarn_light","webpack.config.js":"_webpack_light","webpack.config.cjs":"_webpack_light","webpack.config.mjs":"_webpack_light","webpack.config.ts":"_webpack_light","webpack.config.build.js":"_webpack_light","webpack.config.build.cjs":"_webpack_light","webpack.config.build.mjs":"_webpack_light","webpack.config.build.ts":"_webpack_light","webpack.common.js":"_webpack_light","webpack.common.cjs":"_webpack_light","webpack.common.mjs":"_webpack_light","webpack.common.ts":"_webpack_light","webpack.dev.js":"_webpack_light","webpack.dev.cjs":"_webpack_light","webpack.dev.mjs":"_webpack_light","webpack.dev.ts":"_webpack_light","webpack.prod.js":"_webpack_light","webpack.prod.cjs":"_webpack_light","webpack.prod.mjs":"_webpack_light","webpack.prod.ts":"_webpack_light","license":"_license_light","licence":"_license_light","license.txt":"_license_light","licence.txt":"_license_light","license.md":"_license_light","licence.md":"_license_light","copying":"_license_light","copying.txt":"_license_light","copying.md":"_license_light","compiling":"_license_1_light","compiling.txt":"_license_1_light","compiling.md":"_license_1_light","contributing":"_license_2_light","contributing.txt":"_license_2_light","contributing.md":"_license_2_light","qmakefile":"_makefile_1_light","omakefile":"_makefile_2_light","cmakelists.txt":"_makefile_3_light","procfile":"_heroku_light","npm-debug.log":"_npm_ignored_light"},"lightDefault":"_default_light"}
SETI_JSON
, true);

// One palette drives the manager and every integrated editor tab.
$workspaceThemeScript = <<<'JS'
<script>
(function () {
    // Paint new editor frames with the current workspace palette before CDN scripts finish loading.
    if (window.parent !== window) {
        try {
            const host = window.parent.document.documentElement, root = document.documentElement;
            for (let i = 0; i < host.style.length; i++) {
                const key = host.style.item(i);
                if (key.startsWith('--')) root.style.setProperty(key, host.style.getPropertyValue(key));
            }
            root.style.colorScheme = host.style.colorScheme;
            root.dataset.workspaceTheme = host.dataset.workspaceTheme || '';
            root.dataset.workspaceLight = host.dataset.workspaceLight || '';
        } catch (_) { /* A standalone cross-origin embedding cannot share its parent's palette. */ }
    }
    function workspaceIconURL(hostname) {
        let hash = 2166136261;
        for (const char of hostname.toLowerCase()) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
        const hue = (hash >>> 0) % 360;
        const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="hsl(' + hue + ',65%,38%)"/><path d="m23 20-12 12 12 12m18-24 12 12-12 12m-6-28-6 32" fill="none" stroke="white" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        return 'data:image/svg+xml,' + encodeURIComponent(svg);
    }
    function badgeSiteIcon(url) {
        return new Promise((resolve, reject) => {
            const image = new Image();
            image.crossOrigin = 'anonymous'; image.referrerPolicy = 'no-referrer';
            const timeout = setTimeout(() => { image.onload = image.onerror = null; reject(new Error('Icon timeout')); }, 2500);
            image.onerror = () => { clearTimeout(timeout); reject(new Error('Icon unavailable')); };
            image.onload = () => {
                clearTimeout(timeout);
                try {
                    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 64;
                    const ctx = canvas.getContext('2d');
                    const scale = Math.min(64 / image.naturalWidth, 64 / image.naturalHeight);
                    const width = image.naturalWidth * scale, height = image.naturalHeight * scale;
                    ctx.drawImage(image, (64 - width) / 2, (64 - height) / 2, width, height);
                    let hash = 2166136261;
                    for (const char of location.hostname.toLowerCase()) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
                    ctx.beginPath(); ctx.arc(51, 51, 11, 0, Math.PI * 2);
                    ctx.fillStyle = 'hsl(' + ((hash >>> 0) % 360) + ',75%,50%)'; ctx.fill();
                    ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 3; ctx.stroke();
                    resolve(canvas.toDataURL('image/png'));
                } catch (error) { reject(error); }
            };
            image.src = url;
        });
    }
    async function loadSiteIcon() {
        const cacheKey = 'fm_site_favicon_v1';
        try { const cached = sessionStorage.getItem(cacheKey); if (cached?.startsWith('data:image/png;base64,')) return cached; } catch (_) {}
        const urls = [];
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);
        try {
            const response = await fetch(new URL('/', location.href), {signal: controller.signal});
            if (response.ok) {
                const html = new DOMParser().parseFromString(await response.text(), 'text/html');
                const base = new URL(html.querySelector('base[href]')?.getAttribute('href') || response.url, response.url);
                for (const link of html.querySelectorAll('link[rel~="icon"][href]')) {
                    const url = new URL(link.getAttribute('href'), base);
                    if (['http:', 'https:'].includes(url.protocol)) urls.push(url.href);
                }
            }
        } catch (_) {} finally { clearTimeout(timeout); }
        urls.push(new URL('/favicon.ico', location.href).href);
        for (const url of [...new Set(urls)].slice(0, 4)) {
            try {
                const icon = await badgeSiteIcon(url);
                try { sessionStorage.setItem(cacheKey, icon); } catch (_) {}
                return icon;
            } catch (_) {}
        }
        return workspaceIconURL(location.hostname);
    }
    window.setWorkspaceDocumentTitle = function(name = 'Files', dirty = false) {
        document.title = location.hostname + ' — ' + (dirty ? '● ' : '') + name;
    };
    document.addEventListener('DOMContentLoaded', () => {
        const filename = new URL(location.href).searchParams.get('filename');
        window.setWorkspaceDocumentTitle(filename ? filename.split('/').pop() : 'Files');
        document.querySelectorAll('link[rel="icon"]').forEach(icon => icon.remove());
        const icon = document.createElement('link');
        icon.rel = 'icon'; icon.type = 'image/svg+xml'; icon.href = workspaceIconURL(location.hostname);
        document.head.append(icon);
        const host = window.parent !== window ? window.parent : window;
        if (!host.workspaceSiteIconPromise) host.workspaceSiteIconPromise = loadSiteIcon();
        host.workspaceSiteIconPromise.then(url => {
            icon.type = url.startsWith('data:image/png') ? 'image/png' : 'image/svg+xml'; icon.href = url;
        }).catch(() => {});
    });
    const fmCSRF = __FM_CSRF_TOKEN__;
    const nativeFetch = window.fetch.bind(window);
    window.fetch = function(input, options = {}) {
        const target = new URL(typeof input === 'string' ? input : input.url, location.href);
        const method = (options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (target.origin === location.origin && target.pathname === location.pathname && !['GET','HEAD'].includes(method)) {
            const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
            headers.set('X-FM-CSRF', fmCSRF);
            options = {...options, headers};
        }
        return nativeFetch(input, options);
    };
    const nativeOpen = XMLHttpRequest.prototype.open;
    const nativeSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        const target = new URL(url, location.href);
        this.fmNeedsCSRF = target.origin === location.origin && target.pathname === location.pathname && !['GET','HEAD'].includes(method.toUpperCase());
        return nativeOpen.call(this, method, url, ...args);
    };
    XMLHttpRequest.prototype.send = function(body) {
        if (this.fmNeedsCSRF) this.setRequestHeader('X-FM-CSRF', fmCSRF);
        return nativeSend.call(this, body);
    };
    window.fmCSRFToken = fmCSRF;
    const editorThemes = {"Light":[["chrome","Chrome"],["clouds","Clouds"],["crimson_editor","Crimson Editor"],["dawn","Dawn"],["dreamweaver","Dreamweaver"],["eclipse","Eclipse"],["github_light_default","GitHub Light Default"],["github","GitHub (Legacy)"],["iplastic","IPlastic"],["solarized_light","Solarized Light"],["textmate","TextMate"],["tomorrow","Tomorrow"],["xcode","XCode"],["kuroir","Kuroir"],["katzenmilch","KatzenMilch"],["sqlserver","SQL Server"],["cloud_editor","CloudEditor"]],"Dark":[["ambiance","Ambiance"],["chaos","Chaos"],["clouds_midnight","Clouds Midnight"],["dracula","Dracula"],["cobalt","Cobalt"],["gruvbox","Gruvbox"],["gob","Green on Black"],["idle_fingers","idle Fingers"],["kr_theme","krTheme"],["merbivore","Merbivore"],["merbivore_soft","Merbivore Soft"],["mono_industrial","Mono Industrial"],["monokai","Monokai"],["nord_dark","Nord Dark"],["one_dark","One Dark"],["pastel_on_dark","Pastel on dark"],["solarized_dark","Solarized Dark"],["terminal","Terminal"],["tomorrow_night","Tomorrow Night"],["tomorrow_night_blue","Tomorrow Night Blue"],["tomorrow_night_bright","Tomorrow Night Bright"],["tomorrow_night_eighties","Tomorrow Night 80s"],["twilight","Twilight"],["vibrant_ink","Vibrant Ink"],["github_dark","GitHub Dark"],["cloud_editor_dark","CloudEditor Dark"]]};
    window.editorThemeNames = Object.values(editorThemes).flat().map(item => item[0]);
    window.getEditorTheme = function() {
        const saved = localStorage.getItem('ke_editor_theme');
        const legacy = localStorage.getItem('ke_theme');
        return window.editorThemeNames.includes(saved) ? saved : window.editorThemeNames.includes(legacy) ? legacy : 'one_dark';
    };
    const themeLoads = new Map();
    function loadThemeScript(url) {
        if (!themeLoads.has(url)) themeLoads.set(url, new Promise((resolve, reject) => {
            const script = document.createElement('script');
            const timer = setTimeout(() => { script.remove(); themeLoads.delete(url); reject(new Error('Theme loading timed out.')); }, 15000);
            script.src = url;
            script.onload = () => { clearTimeout(timer); resolve(); };
            script.onerror = () => { clearTimeout(timer); script.remove(); themeLoads.delete(url); reject(new Error('Cannot load theme from CDN.')); };
            document.head.append(script);
        }));
        return themeLoads.get(url);
    }
    function paletteFromAce(module) {
        // Ace defers theme CSS until an editor exists; the file manager also needs it before probing.
        ace.require('ace/lib/dom').importCssString(module.cssText, module.cssClass, document);
        const probe = document.createElement('div');
        probe.className = 'ace_editor ' + module.cssClass;
        probe.style.cssText = 'position:fixed;visibility:hidden;pointer-events:none';
        document.body.append(probe);
        const color = (classes, property = 'color') => {
            const node = document.createElement('span'); node.className = classes; probe.append(node);
            const result = getComputedStyle(node)[property]; node.remove(); return result;
        };
        const rgb = value => value.startsWith('#') ? (value.length === 4 ? [...value.slice(1)].map(v => v+v) : value.slice(1).match(/../g)).map(v => parseInt(v,16)) : (value.match(/[\d.]+/g) || []).slice(0,3).map(Number);
        const mix = (a,b,t) => 'rgb(' + rgb(a).map((v,i) => Math.round(v*(1-t)+rgb(b)[i]*t)).join(',') + ')';
        const luminance = value => rgb(value).map(v => { v/=255; return v<=0.04045 ? v/12.92 : ((v+0.055)/1.055)**2.4; }).reduce((sum,v,i) => sum+v*[0.2126,0.7152,0.0722][i],0);
        const contrast = (a,b) => (Math.max(luminance(a),luminance(b))+0.05)/(Math.min(luminance(a),luminance(b))+0.05);
        const readable = (value,bg) => { for(let i=0; i<12 && contrast(value,bg)<4.5; i++) value=mix(value,text,0.25); return value; };
        const style = getComputedStyle(probe), deep = style.backgroundColor, text = style.color;
        let main = color('ace_gutter','backgroundColor');
        if (main === 'rgba(0, 0, 0, 0)') main = deep;
        const surface = mix(main,text,0.035), elevated = mix(main,text,0.08);
        const tokens = ['ace_support ace_function','ace_entity ace_name ace_function','ace_keyword','ace_constant ace_numeric'].map(classes => color(classes));
        const accent = readable(tokens.find(value => Math.max(...rgb(value))-Math.min(...rgb(value)) > 25) || text,main);
        const secondary = readable(mix(text,main,0.25),main), muted = readable(color('ace_comment'),main);
        const folder = readable(color('ace_constant ace_numeric'),main);
        const selection = mix(deep,accent,0.18), danger = module.isDark ? '#ef596f' : '#cf222e';
        const onColor = bg => contrast(bg,'rgb(255,255,255)') > contrast(bg,'rgb(0,0,0)') ? '#fff' : '#000';
        const vars = {'bg-deep':deep,'bg-main':main,'bg-surface':surface,'bg-elevated':elevated,
            'bg-hover':mix(main,text,0.055),'bg-selected':selection,'border-subtle':mix(main,text,0.12),'border-default':mix(main,text,0.22),
            'border-accent':accent,'text-primary':text,'text-secondary':secondary,'text-muted':muted,'text-link':accent,'text-link-hover':accent,
            'accent':accent,'accent-hover':accent,'accent-success':module.isDark ? '#89ca78' : '#1a7f37','accent-danger':danger,
            'accent-contrast':onColor(accent),'danger-contrast':onColor(danger),'accent-warning':folder,'folder-color':folder,'scrollbar-gold':muted,'scrollbar-gold-hover':accent};
        probe.remove(); return {vars,light:!module.isDark};
    }
    let themeRequest = 0;
    window.setWorkspaceTheme = async function(theme = window.getEditorTheme(), persist = true) {
        theme = window.editorThemeNames.includes(theme) ? theme : 'one_dark';
        const request = ++themeRequest;
        try {
            if (!window.ace) await loadThemeScript('https://cdn.jsdelivr.net/npm/ace-builds@1.45.2/src-min-noconflict/ace.js');
            if (!ace.require('ace/theme/'+theme)) await loadThemeScript('https://cdn.jsdelivr.net/npm/ace-builds@1.45.2/src-min-noconflict/theme-'+theme+'.js');
            const module = ace.require('ace/theme/'+theme);
            if (!module) throw new Error('Theme module is unavailable.');
            if (request !== themeRequest) return;
            const palette = paletteFromAce(module);
            for (const [key,value] of Object.entries(palette.vars)) document.documentElement.style.setProperty('--'+key,value);
            document.documentElement.style.colorScheme = palette.light ? 'light' : 'dark';
            document.documentElement.dataset.workspaceTheme = theme;
            document.documentElement.dataset.workspaceLight = String(palette.light);
            const select = document.getElementById('workspace-theme'); if (select) select.value = theme;
            if (persist) { localStorage.setItem('ke_theme',theme); localStorage.removeItem('ke_editor_theme'); }
            if (typeof window.applySelectedTheme === 'function') window.applySelectedTheme(theme);
            document.querySelectorAll('iframe.editor-panel').forEach(frame => {
                if (typeof frame.contentWindow.setWorkspaceTheme === 'function') frame.contentWindow.setWorkspaceTheme(theme,false);
            });
        } catch (error) {
            if (request !== themeRequest) return;
            const select = document.getElementById('workspace-theme'); if (select) select.value = document.documentElement.dataset.workspaceTheme || '';
            if (persist) window.workspaceAlert(error.message, 'Cannot load theme', 'error');
            else console.error(error);
            if (typeof window.finishEditorLoading === 'function') {
                if (window.editor) { window.editor.container.style.backgroundColor = 'var(--bg-deep)'; window.editor.container.style.color = 'var(--text-primary)'; }
                window.finishEditorLoading();
            }
        }
    };
    document.addEventListener('DOMContentLoaded', () => {
        const select = document.getElementById('workspace-theme');
        if (select) for (const [label,themes] of Object.entries(editorThemes)) {
            const group = document.createElement('optgroup'); group.label = label;
            for (const [name,caption] of themes) group.append(new Option(caption,name));
            select.append(group);
        }
        window.setWorkspaceTheme(window.getEditorTheme(),false);
    });
    function escapeAlertText(value) {
        return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    }
    window.workspaceAlert = function(message, title = 'Editor', icon = /error|failed/i.test(title) ? 'error' : 'info') {
        if (window.parent !== window && typeof window.parent.workspaceAlert === 'function') return window.parent.workspaceAlert(message, title, icon);
        if (typeof CoolAlert !== 'undefined') return CoolAlert.show({title: escapeAlertText(title), text: escapeAlertText(message), icon, showCancelButton: false, confirmButtonText: 'OK'});
        window.alert(message);
        return Promise.resolve({isConfirmed: true});
    };
    function startToastCountdown(toast, duration) {
        if (!toast) return;
        const timer = toast.querySelector('.cool-alert-toast-progress, .workspace-toast-timer');
        if (!timer) return;
        timer.setAttribute('aria-hidden', 'true');
        const deadline = performance.now() + duration;
        clearInterval(toast.fmCountdownInterval);
        const update = () => {
            if (!toast.isConnected || toast.style.display === 'none' || toast.classList.contains('hide')) {
                clearInterval(toast.fmCountdownInterval);
                return;
            }
            const remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
            timer.textContent = remaining + 's';
            if (!remaining) clearInterval(toast.fmCountdownInterval);
        };
        update();
        toast.fmCountdownInterval = setInterval(update, 200);
    }
    window.workspaceToast = function(message, title = 'Saved', type = 'success') {
        if (window.parent !== window && typeof window.parent.workspaceToast === 'function') return window.parent.workspaceToast(message, title, type);
        const duration = type === 'success' ? 3000 : 5000;
        if (typeof CoolAlert !== 'undefined') {
            try {
                const result = CoolAlert.show({toast: true, icon: type, title: escapeAlertText(title), text: escapeAlertText(message), duration});
                startToastCountdown(document.querySelector('#cool-alert-toast-container .cool-alert-toast:last-child'), duration);
                return result;
            } catch (_) {}
        }
        let toast = document.getElementById('save-toast');
        if (!toast) { toast = document.createElement('div'); toast.id = 'save-toast'; document.body.append(toast); }
        toast.classList.add('workspace-toast');
        toast.dataset.type = type;
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
        const icon = document.createElement('i');
        icon.className = 'fas ' + ({success: 'fa-check-circle', error: 'fa-times-circle', warning: 'fa-exclamation-triangle', info: 'fa-info-circle'}[type] || 'fa-info-circle'); icon.setAttribute('aria-hidden', 'true');
        const text = document.createElement('span'); text.textContent = title + ': ' + String(message);
        const timer = document.createElement('span'); timer.className = 'workspace-toast-timer'; timer.setAttribute('aria-hidden', 'true');
        toast.replaceChildren(icon, text, timer);
        clearTimeout(window.workspaceToastTimer);
        toast.style.display = 'flex';
        startToastCountdown(toast, duration);
        window.workspaceToastTimer = setTimeout(() => { toast.style.display = 'none'; clearInterval(toast.fmCountdownInterval); }, duration);
        return Promise.resolve();
    };
    window.loadInlineDiff = () => loadThemeScript('https://cdn.jsdelivr.net/npm/ace-builds@1.45.2/src-min-noconflict/ext-diff.js');
    window.setInlineChangesPreference = function(enabled, persist = true) {
        if (persist) localStorage.setItem('ke_inline_changes', String(!!enabled));
        if (typeof window.setInlineChanges === 'function') window.setInlineChanges(!!enabled);
        document.querySelectorAll('iframe.editor-panel').forEach(frame => {
            if (typeof frame.contentWindow.setInlineChanges === 'function') frame.contentWindow.setInlineChanges(!!enabled);
        });
    };
    window.setEditorPreference = function(option, enabled, persist = true) {
        const options = {showInvisibles:['ke_invisibles','invisibles'], displayIndentGuides:['ke_indent_guides','indentguides'], enableLiveAutocompletion:['ke_live_autocomplete','autocomplete']};
        if (!Object.hasOwn(options, option)) return;
        const [key, command] = options[option];
        enabled = !!enabled;
        if (persist) localStorage.setItem(key, String(enabled));
        const apply = target => {
            if (!target.editor) return;
            target.editor.setOption(option, enabled);
            if (option === 'enableLiveAutocompletion' && !enabled) target.editor.completer?.detach();
        };
        apply(window);
        document.querySelectorAll('iframe.editor-panel').forEach(frame => apply(frame.contentWindow));
        document.querySelectorAll('[data-editor-command="'+command+'"]').forEach(button => button.setAttribute('aria-pressed', String(enabled)));
    };
    window.setShowInvisibles = function(enabled, persist = true) { window.setEditorPreference('showInvisibles', enabled, persist); };
    window.workspaceConfirm = function(message) {
        if (window.parent !== window && typeof window.parent.workspaceConfirm === 'function') return window.parent.workspaceConfirm(message);
        if (typeof CoolAlert !== 'undefined') return CoolAlert.show({title: 'Unsaved changes', text: escapeAlertText(message), icon: 'warning', showCancelButton: true, confirmButtonText: 'Discard changes', cancelButtonText: 'Keep editing'}).then(result => result.isConfirmed);
        return Promise.resolve(window.confirm(message));
    };
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            const files = document.getElementById('files-list');
            if (!files || window.fmWorkspaceReady) return;
            const message = 'The page did not finish initializing. Reload the page; if this continues, check the end of the HTML response and the server PHP error log.';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 8; cell.style.padding = '20px'; cell.textContent = message;
            row.append(cell); files.replaceChildren(row);
            const tree = document.querySelector('#directory-tree .file-tree');
            if (tree) { const item = document.createElement('li'); item.className = 'tree-message'; item.textContent = 'Page initialization incomplete. Please reload.'; tree.replaceChildren(item); }
            console.error('Pocket Code Studio: initialization incomplete. The HTML response may be truncated or a required script failed.');
        }, 1500);
    });
    window.addEventListener('storage', event => {
        if (event.key === 'ke_inline_changes' || event.key === null) window.setInlineChangesPreference(localStorage.getItem('ke_inline_changes') === 'true', false);
        for (const [key,option,defaultValue] of [['ke_invisibles','showInvisibles',false],['ke_indent_guides','displayIndentGuides',true],['ke_live_autocomplete','enableLiveAutocompletion',true]]) {
            if (event.key === key || event.key === null) window.setEditorPreference(option, localStorage.getItem(key) === null ? defaultValue : localStorage.getItem(key) === 'true', false);
        }
        if (event.key === 'ke_theme' || event.key === 'ke_editor_theme' || event.key === null) window.setWorkspaceTheme(window.getEditorTheme(),false);
    });
})();
</script>

<style>
    /* One text scale for menus and floating UI, independent of Bootstrap defaults. */
    :root {--workspace-ui-font-size: 0.78rem;}
    .modal, .modal .modal-content, #git-diff-dialog, .cool-alert-modal, .cool-alert-toast {font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;font-size: var(--workspace-ui-font-size) !important;line-height: 1.5;}
    .modal .modal-title, .modal .modal-body, .modal .modal-footer, .modal .modal-body :is(p, li, label, h1, h2, h3, h4, h5, h6, small, .form-text, .alert, .list-group-item), .modal :is(.form-control, .form-select, .btn, .table th, .table td, kbd), .cool-alert-modal-title, .cool-alert-toast-title, .cool-alert-title, .cool-alert-modal-message, .cool-alert-toast-message, .cool-alert-text, .cool-alert-modal-btn, .context-menu .context-menu-item, .ace_tooltip {font-size: var(--workspace-ui-font-size) !important;}
    @media (max-width: 760px) {
        /* Avoid browser zoom while typing in mobile dialogs. */
        .modal :is(input.form-control, textarea.form-control, select.form-select) {font-size: 16px !important;}
    }
    .workspace-toast {position: fixed;top: 48px;right: 16px;max-width: min(380px, calc(100vw - 32px));padding: 12px 16px 22px;gap: 10px;align-items: center;z-index: 9999;background: var(--bg-main);color: var(--text-primary);border: 1px solid var(--border-default);border-radius: 6px;box-shadow: 0 8px 32px #00000040;font: 400 var(--workspace-ui-font-size)/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;}
    .workspace-toast > i {color: var(--accent-success);}
    .workspace-toast[data-type="error"] > i {color: var(--accent-danger);}
    .workspace-toast[data-type="warning"] > i {color: var(--accent-warning);}
    .workspace-toast[data-type="info"] > i {color: var(--accent);}
    #folder-picker {width:min(540px,calc(100vw - 24px));max-height:85dvh;padding:0;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-main);color:var(--text-primary);font:var(--workspace-ui-font-size)/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
    #folder-picker::backdrop {background:#0007;}
    .folder-picker-head, .folder-picker-footer {padding:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
    #folder-picker-path {flex-basis:100%;overflow-wrap:anywhere;}
    #folder-picker-list {max-height:48dvh;overflow:auto;border-block:1px solid var(--border-subtle);}
    #folder-picker button {padding:7px 10px;border:1px solid var(--border-default);border-radius:4px;background:var(--bg-elevated);color:var(--text-primary);font:inherit;cursor:pointer;}
    #folder-picker button:disabled {opacity:.45;cursor:default;}
    #folder-picker-list button {display:flex;gap:8px;width:100%;text-align:left;background:transparent;border:0;border-radius:0;overflow-wrap:anywhere;min-height:38px;}
    #folder-picker-list button:hover {background:var(--bg-selected);}
    #folder-picker-message {padding:0 12px;color:var(--text-secondary);}
    /* Shared floating surfaces follow the workspace theme, including light palettes. */
    .modal {--bs-body-color: var(--text-primary);--bs-body-bg: var(--bg-main);--bs-border-color: var(--border-default);}
    .modal .table {--bs-table-color: var(--text-primary);--bs-table-bg: var(--bg-surface);--bs-table-border-color: var(--border-subtle);--bs-table-striped-color: var(--text-primary);--bs-table-striped-bg: var(--bg-hover);--bs-table-hover-color: var(--text-primary);--bs-table-hover-bg: var(--bg-selected);--bs-table-active-color: var(--text-primary);--bs-table-active-bg: var(--bg-selected);color: var(--text-primary);}
    .modal .table thead th {background: var(--bg-elevated);color: var(--text-secondary);border-color: var(--border-subtle);font-size: 0.75rem;font-weight: 500;position: sticky;top: 0;z-index: 1;}
    .modal .table td {font-size: 0.8rem;border-color: var(--border-subtle);vertical-align: middle;}
    .modal .table-responsive {max-height: 65vh;overflow: auto;}
    .modal .text-muted, .modal .form-text, .modal small {color: var(--text-muted) !important;}
    .modal .form-select option {background: var(--bg-deep);color: var(--text-primary);}
    .modal .form-control:focus, .modal .form-select:focus {box-shadow: 0 0 0 2px var(--bg-selected);}
    .modal :is(.form-control, .form-select):disabled {background-color: var(--bg-deep);color: var(--text-secondary);border-color: var(--border-default);opacity: 1;}
    .modal .btn-primary {--bs-btn-bg: var(--accent);--bs-btn-border-color: var(--accent);--bs-btn-hover-bg: var(--accent-hover);--bs-btn-hover-border-color: var(--accent-hover);--bs-btn-active-bg: var(--accent-hover);--bs-btn-active-border-color: var(--accent-hover);color: var(--accent-contrast) !important;}
    .modal .btn-secondary, .modal .btn[data-bs-dismiss="modal"] {background: var(--bg-elevated) !important;border-color: var(--border-default) !important;color: var(--text-secondary) !important;}
    .modal .btn-secondary:hover, .modal .btn[data-bs-dismiss="modal"]:hover {background: var(--bg-hover) !important;color: var(--text-primary) !important;}
    .modal .btn-danger:not([data-bs-dismiss]) {background: var(--accent-danger);border-color: var(--accent-danger);color: var(--danger-contrast);}
    .modal .btn-close {filter: invert(1) grayscale(1);opacity: 0.75;}
    :root[data-workspace-light="true"] .modal .btn-close, :root[data-workspace-light="true"] .modal .btn-close, :root[data-workspace-light="true"] .modal .btn-close {filter: none;}
    .cool-alert-modal, .cool-alert-toast {background: var(--bg-main) !important;color: var(--text-primary) !important;border: 1px solid var(--border-default) !important;box-shadow: 0 8px 32px #00000040 !important;}
    /* The empty drag handle must not paint over the alert icon. */
    .cool-alert-modal-header, .cool-alert-modal-header:hover {height: 16px !important;background: transparent !important;border: 0 !important;box-shadow: none !important;}
    .cool-alert-modal-title, .cool-alert-toast-title, .cool-alert-title {color: var(--text-primary) !important;}
    .cool-alert-modal-message, .cool-alert-toast-message, .cool-alert-text {color: var(--text-secondary) !important;white-space: pre-line;overflow-wrap: anywhere;}
    .cool-alert-modal-btn {border-radius: 4px !important;font-size: 0.8rem !important;}
    .cool-alert-modal-btn.cool-alert-primary {background: var(--accent) !important;color: var(--accent-contrast) !important;border-color: var(--accent) !important;}
    .cool-alert-modal-btn.cool-alert-secondary {background: var(--bg-elevated) !important;color: var(--text-secondary) !important;border: 1px solid var(--border-default) !important;}
    .cool-alert-modal-btn.cool-alert-danger {background: var(--accent-danger) !important;color: var(--danger-contrast) !important;}
    .cool-alert-close, .cool-alert-toast-close {background: transparent !important;color: var(--text-secondary) !important;}
    /* Quiet notification chrome: no colored edge or sweeping timer bar. */
    .cool-alert-toast::before, .cool-alert-modal::after {content: none !important;display: none !important;}
    .cool-alert-toast {padding-bottom: 22px !important;}
    .cool-alert-toast-progress, .workspace-toast-timer {position: absolute !important;left: auto !important;right: 12px !important;bottom: 5px !important;width: auto !important;min-width: 22px;height: 14px !important;background: none !important;border: 0 !important;transition: none !important;pointer-events: none;color: var(--text-muted);font: 11px/14px -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;font-variant-numeric: tabular-nums;text-align: right;}
    .cool-alert-toast-progress::after, .workspace-toast-timer::after {content: none !important;}
    .cool-alert-spinner {border-color: var(--border-default) !important;border-top-color: var(--text-secondary) !important;}
    .modal .alert-info {background: var(--bg-selected);color: var(--text-primary);border-color: var(--border-default);}
    .modal .alert-warning, .modal .alert-danger {background: var(--bg-elevated);color: var(--text-primary);border-color: var(--border-default);}
    .modal .alert-warning {border-left: 3px solid var(--accent-warning);}
    .modal .alert-danger {border-left: 3px solid var(--accent-danger);}
    .ace_tooltip {background: var(--bg-elevated) !important;color: var(--text-primary) !important;border-color: var(--border-default) !important;}
    .ace_search {background: var(--bg-main) !important;color: var(--text-primary) !important;border-color: var(--border-default) !important;box-shadow: 0 4px 16px #00000030;}
    .ace_search_field {background: var(--bg-deep) !important;color: var(--text-primary) !important;border-color: var(--border-default) !important;}
    .ace_searchbtn, .ace_replacebtn {background: var(--bg-elevated) !important;color: var(--text-secondary) !important;border-color: var(--border-default) !important;}
    .ace_search_options {color: var(--text-secondary) !important;}
    .ace_search_options .ace_button {color: var(--text-secondary) !important;}
    .ace_search_options .ace_button.checked {background: var(--bg-selected) !important;color: var(--text-link) !important;border-color: var(--accent) !important;}
    .ace_editor.ace_autocomplete {background: var(--bg-main) !important;color: var(--text-primary) !important;border-color: var(--border-default) !important;}
    .ace_autocomplete .ace_marker-layer .ace_active-line {background: var(--bg-selected) !important;}
</style>

JS;
$workspaceThemeScript = str_replace('__FM_CSRF_TOKEN__', json_encode($fmCSRFToken), $workspaceThemeScript);

// Git process runner. Argument arrays avoid shell interpretation.
function fmGitRun($directory, $arguments, $accepted = [0], $environment = [], $timeout = 8) {
    if (!function_exists('proc_open')) throw new RuntimeException('PHP proc_open is disabled; Git integration is unavailable.');
    $command = array_merge(['git', '--literal-pathspecs', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'color.ui=false', '-C', $directory], $arguments);
    $env = null;
    if ($environment) {
        $env = getenv();
        foreach (array_keys($env) as $key) if (strpos($key,'GIT_') === 0 || strpos($key,'FM_GITHUB_') === 0) unset($env[$key]);
        $env = array_merge($env, ['GIT_CONFIG_NOSYSTEM'=>'1','GIT_CONFIG_GLOBAL'=>'/dev/null','GIT_TERMINAL_PROMPT'=>'0'], $environment);
    }
    $process = @proc_open($command, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes, null, $env, ['bypass_shell'=>true]);
    if (!is_resource($process)) throw new RuntimeException('Cannot start Git on this server.');
    fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $out = ''; $err = ''; $start = microtime(true); $code = -1;
    try {
        while (true) {
            $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
            if (strlen($out)+strlen($err)>12*1024*1024 || microtime(true)-$start>$timeout) throw new RuntimeException('Git operation exceeded its time or size limit.');
            $state = proc_get_status($process);
            if (!$state['running']) { $code=$state['exitcode']; break; }
            usleep(10000);
        }
        $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
    } finally {
        if (isset($state) && $state['running']) proc_terminate($process);
        fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
    }
    if (!in_array($code, $accepted, true)) throw new RuntimeException('Git unavailable or operation failed: ' . substr(trim($err),0,700));
    return $out;
}
// GitHub writes use explicit HTTPS destinations and a private index; no shell commands or hooks.
function fmGitHubSettingsPath($root) { return fmPrivateAuthDirectory() . '/github-' . hash('sha256', $root) . '.json'; }
function fmGitHubValidate($input) {
    $url = trim($input['url'] ?? '');
    if (!preg_match('~^https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$~D', $url, $match) || in_array($match[2], ['.','..'], true)) throw new RuntimeException('Use https://github.com/OWNER/REPOSITORY.git without credentials.');
    $branch = trim($input['branch'] ?? '');
    if ($branch === '' || strlen($branch) > 200 || strpos($branch, '-') === 0) throw new RuntimeException('Enter a valid branch.');
    $name = trim($input['name'] ?? ''); $email = trim($input['email'] ?? '');
    if ($name === '' || strlen($name) > 100 || preg_match('/[\x00-\x1f<>]/', $name) || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 200) throw new RuntimeException('Enter a commit author name and valid email.');
    return ['url'=>'https://github.com/'.$match[1].'/'.$match[2].'.git','branch'=>$branch,'name'=>$name,'email'=>$email];
}
function fmGitHubState($root, $hashPaths = [], $includeFiles = true) {
    $branch = trim(fmGitRun($root, ['symbolic-ref','--quiet','--short','HEAD']));
    $head = trim(fmGitRun($root, ['rev-parse','--verify','HEAD']));
    if (!preg_match('/^[a-f0-9]{40,64}$/D', $head)) throw new RuntimeException('An existing repository with at least one commit is required.');
    if (!$includeFiles) return ['branch'=>$branch,'head'=>$head,'files'=>[]];
    $hashPaths = array_fill_keys($hashPaths,true);
    foreach (['MERGE_HEAD','CHERRY_PICK_HEAD','REVERT_HEAD','rebase-merge','rebase-apply'] as $marker) {
        $path = trim(fmGitRun($root, ['rev-parse','--git-path',$marker]));
        if (file_exists($path[0] === '/' ? $path : $root.'/'.$path)) throw new RuntimeException('Finish the current merge, rebase or cherry-pick before pushing.');
    }
    if (fmGitRun($root, ['diff','--cached','--name-only','-z']) !== '') throw new RuntimeException('The repository already has staged changes. Commit or unstage them outside this dialog first.');
    $raw = fmGitRun($root, ['-c','status.renames=false','status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=none']);
    $files = []; $bytes = 0;
    foreach (explode("\0", $raw) as $entry) {
        if (strlen($entry) < 4) continue;
        $xy = substr($entry,0,2); $path = substr($entry,3); $full = $root.'/'.$path;
        if (strpos($xy,'U') !== false && $xy !== '??') throw new RuntimeException('Resolve Git conflicts first.');
        $allowed = !preg_match('~(^|/)\.git(/|$)|(^|/)\.\.?(/|$)|[\x00-\x1f\\\\]~', $path) && $path[0] !== '/';
        if (file_exists($full) || is_link($full)) {
            $size = @filesize($full); $resolved = realpath($full);
            $allowed = $allowed && !is_link($full) && is_file($full) && $resolved && strpos($resolved,$root.'/') === 0 && $size !== false && $size <= 32*1024*1024;
            $hash = $allowed ? null : 'unsupported';
            if ($allowed && isset($hashPaths[$path])) { $bytes += $size; $hash = @hash_file('sha256',$full); if (!$hash) throw new RuntimeException('Cannot read a selected file: ' . $path); }
        } else { $hash = 'deleted'; $allowed = $allowed && strpos($xy,'D') !== false; }
        if ($bytes > 128*1024*1024) throw new RuntimeException('Selected files exceed 128 MB. Select a smaller batch.');
        $stat = @lstat($full);
        $version = $stat ? hash('sha256',json_encode([$stat['ino'],$stat['mode'],$stat['size'],$stat['mtime'],$stat['ctime']])) : 'deleted';
        $files[] = ['path'=>$path,'status'=>$xy,'allowed'=>$allowed,'hash'=>$hash,'version'=>$version];
    }
    $revision = hash('sha256', json_encode([$head,$branch,$files],JSON_INVALID_UTF8_SUBSTITUTE));
    return ['branch'=>$branch,'head'=>$head,'files'=>$files,'revision'=>$revision];
}
function fmGitHubCheckSelection($state, $paths, $preview, $verifyHash = true) {
    if (!is_array($preview)) throw new RuntimeException('Refresh the file list before committing.');
    $available = array_column($state['files'],null,'path');
    $reviewed = array_column($preview,null,'path');
    foreach ($paths as $path) {
        if (!is_string($path) || !isset($available[$path]) || !$available[$path]['allowed']) throw new RuntimeException('Selected file is missing or unsupported. Refresh the list: ' . (is_string($path) ? $path : 'invalid path'));
        $old = $reviewed[$path] ?? [];
        if (($verifyHash && ($old['hash'] ?? null) !== $available[$path]['hash']) || ($old['version'] ?? null) !== $available[$path]['version'] || ($old['status'] ?? null) !== $available[$path]['status']) throw new RuntimeException('Selected file changed. Refresh and review: ' . $path);
    }
}
function fmGitHubPush($root, $settings, $head) {
    if (empty($settings['token'])) throw new RuntimeException('Save a GitHub token first.');
    if (fmGitRun($root,['config','--local','--get-regexp','^(url|http|credential)\.'],[0,1]) !== '') throw new RuntimeException('Repository-local URL, HTTP or credential overrides are not supported. Remove them with a Git client before pushing.');
    $script = tempnam(fmPrivateAuthDirectory(), '.askpass-');
    if (!$script) throw new RuntimeException('Cannot prepare GitHub authentication.');
    try {
        $helper = "#!/bin/sh\ncase \"\$1\" in *Username*) printf '%s\\n' 'x-access-token' ;; *) printf '%s\\n' \"\$FM_GITHUB_TOKEN\" ;; esac\n";
        if (!chmod($script,0700) || file_put_contents($script,$helper) !== strlen($helper)) throw new RuntimeException('Cannot prepare GitHub authentication.');
        $environment = ['GIT_ASKPASS'=>$script,'GIT_TERMINAL_PROMPT'=>'0','LC_ALL'=>'C','FM_GITHUB_TOKEN'=>$settings['token']];
        fmGitRun($root, ['-c','credential.helper=','-c','http.extraHeader=','-c','http.followRedirects=false','-c','http.sslVerify=true','-c','protocol.allow=never','-c','protocol.https.allow=always','-c','push.followTags=false','push','--porcelain','--no-verify','--recurse-submodules=no',$settings['url'],$head.':refs/heads/'.$settings['branch']], [0], $environment, 60);
    } catch (Throwable $error) {
        // Never send credentials or credential-bearing server diagnostics back to the browser.
        throw new RuntimeException('Push failed or could not be confirmed. The local commit is kept. Check the token, repository access, branch rules and remote history, then use Push existing commits.');
    } finally { @unlink($script); }
}
if ($isPostRequest && ($_POST['action'] ?? '') === 'github') {
    $lock = null; $indexLock = null; $temporaryIndex = null; $indexHandle = null;
    $commit = null; $updated = false; $oldHead = null;
    try {
        $root = realpath($config['root_path']);
        if (!$root || realpath(trim(fmGitRun($root,['rev-parse','--show-toplevel']))) !== $root) throw new RuntimeException('Set Workspace root to an existing Git repository root. Git and PHP proc_open must be available.');
        $storage = fmGitHubSettingsPath($root);
        if (is_link($storage.'.lock')) throw new RuntimeException('Invalid Git operation lock.');
        $lock = fopen($storage.'.lock','c');
        if (!$lock || !chmod($storage.'.lock',0600) || !flock($lock,LOCK_EX|LOCK_NB)) throw new RuntimeException('Another Git operation is running. Try again shortly.');
        $settings = fmReadAuthData($storage); $operation = $_POST['operation'] ?? 'read';
        if ($operation === 'save') {
            $next = fmGitHubValidate($_POST);
            fmGitRun($root,['check-ref-format','--branch',$next['branch']]);
            $token = $_POST['token'] ?? '';
            if (!is_string($token) || strlen($token)>300 || ($token!=='' && !preg_match('/^[A-Za-z0-9_]+$/D',$token))) throw new RuntimeException('Invalid GitHub token.');
            $sameRepo = ($settings['url'] ?? '') === $next['url'];
            $next['token'] = !empty($_POST['remove_token']) ? '' : ($token !== '' ? $token : ($sameRepo ? ($settings['token'] ?? '') : ''));
            fmWriteAuthData($storage,$next); $settings = $next;
        } elseif (!in_array($operation,['read','prepare','commit_push','push'],true)) throw new RuntimeException('Unknown Git operation.');
        $paths = [];
        if (in_array($operation,['prepare','commit_push'],true)) {
            $paths = json_decode($_POST['files'] ?? '',true);
            if (!is_array($paths) || !$paths || count($paths)>2000 || count(array_filter($paths,'is_string')) !== count($paths)) throw new RuntimeException('Select between 1 and 2000 files per commit.');
        }
        $state = fmGitHubState($root,$paths,$operation !== 'push');
        if (in_array($operation,['prepare','commit_push','push'],true)) {
            $validated = fmGitHubValidate($settings);
            fmGitRun($root,['check-ref-format','--branch',$validated['branch']]);
            if (empty($settings['token'])) throw new RuntimeException('Save a GitHub token first.');
            if ($state['branch'] !== $settings['branch']) throw new RuntimeException('The configured branch must match the current local branch. Branch switching is not performed here.');
            if (!hash_equals($state['head'], $_POST['head'] ?? '') || $state['branch'] !== ($_POST['branch'] ?? '')) throw new RuntimeException('The branch or latest commit changed. Refresh before retrying.');
            if ($operation === 'prepare') fmGitHubCheckSelection($state,$paths,json_decode($_POST['preview'] ?? '',true),false);
            if ($operation === 'commit_push') {
                $message = trim($_POST['message'] ?? '');
                if ($message==='' || strlen($message)>4000 || strpos($message,"\0")!==false) throw new RuntimeException('Select files and enter a commit message (up to 4000 bytes).');
                $preview = json_decode($_POST['preview'] ?? '',true);
                fmGitHubCheckSelection($state,$paths,$preview);
                // Refuse configured clean/process filters: staging must not run repository-provided commands.
                if (fmGitRun($root,['config','--get-regexp','^filter\..*\.(clean|process)$'],[0,1]) !== '') throw new RuntimeException('This repository uses Git clean filters. Commit with a Git client.');
                $index = trim(fmGitRun($root,['rev-parse','--git-path','index']));
                if ($index[0] !== '/') $index = $root.'/'.$index;
                if (is_link($index) || !is_dir(dirname($index))) throw new RuntimeException('Invalid Git index.');
                $indexLock = $index.'.lock'; $indexHandle = @fopen($indexLock,'x');
                if (!$indexHandle) { $indexLock=null; throw new RuntimeException('Git index is busy. Try again shortly.'); }
                chmod($indexLock,0600);
                if (fmGitRun($root,['diff','--cached','--name-only','-z']) !== '') throw new RuntimeException('Staged changes appeared. Refresh the repository.');
                $temporaryIndex = tempnam(fmPrivateAuthDirectory(),'.git-index-');
                if (!$temporaryIndex || !chmod($temporaryIndex,0600)) throw new RuntimeException('Cannot prepare Git index.');
                unlink($temporaryIndex);
                $env = ['GIT_INDEX_FILE'=>$temporaryIndex,'GIT_AUTHOR_NAME'=>$settings['name'],'GIT_AUTHOR_EMAIL'=>$settings['email'],'GIT_COMMITTER_NAME'=>$settings['name'],'GIT_COMMITTER_EMAIL'=>$settings['email']];
                fmGitRun($root,['read-tree',$state['head']],[0],$env);
                fmGitRun($root,array_merge(['add','--all','--'],array_values(array_unique($paths))),[0],$env);
                $latestState = fmGitHubState($root,$paths);
                if ($latestState['head'] !== $state['head'] || $latestState['branch'] !== $state['branch']) throw new RuntimeException('The branch or latest commit changed during staging. Refresh before retrying.');
                fmGitHubCheckSelection($latestState,$paths,$preview);
                $tree = trim(fmGitRun($root,['write-tree'],[0],$env));
                if ($tree === trim(fmGitRun($root,['rev-parse','HEAD^{tree}']))) throw new RuntimeException('Selected files have no changes to commit.');
                $commit = trim(fmGitRun($root,['-c','commit.gpgSign=false','commit-tree',$tree,'-p',$state['head'],'-m',$message],[0],$env));
                if (!preg_match('/^[a-f0-9]{40,64}$/D',$commit)) throw new RuntimeException('Cannot verify the new commit.');
                $indexBytes = file_get_contents($temporaryIndex);
                if (fwrite($indexHandle,$indexBytes)!==strlen($indexBytes) || !fflush($indexHandle)) throw new RuntimeException('Cannot prepare the updated index.');
                $oldHead=$state['head'];
                fmGitRun($root,['update-ref','refs/heads/'.$state['branch'],$commit,$oldHead]); $updated=true;
                fclose($indexHandle); $indexHandle=null;
                if (!rename($indexLock,$index)) {
                    fmGitRun($root,['update-ref','refs/heads/'.$state['branch'],$oldHead,$commit]); $updated=false;
                    throw new RuntimeException('Cannot install the updated index; commit was not applied.');
                }
                $indexLock=null;
                $state['head']=$commit;
            }
            if ($operation !== 'prepare') fmGitHubPush($root,$settings,$state['head']);
        }
        // Password is never returned, including after saving it.
        $public = array_intersect_key($settings,array_flip(['url','branch','name','email']));
        $public['has_token']=!empty($settings['token']);
        $result = ['status'=>'success','settings'=>$public,'repository'=>($operation === 'prepare' || $operation === 'push' ? $state : fmGitHubState($root)),'message'=>$operation==='save' ? 'GitHub settings saved.' : (in_array($operation,['push','commit_push'],true) ? 'Pushed to GitHub.' : '')];
    } catch (Throwable $error) {
        http_response_code(400);
        $result=['status'=>'error','message'=>$error->getMessage(),'committed'=>$updated];
    } finally {
        if (is_resource($indexHandle)) fclose($indexHandle);
        if ($indexLock) @unlink($indexLock);
        if ($temporaryIndex) { @unlink($temporaryIndex); @unlink($temporaryIndex.'.lock'); }
        if (is_resource($lock)) {flock($lock,LOCK_UN);fclose($lock);}
    }
    header('Content-Type: application/json; charset=utf-8'); echo json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

if ($isPostRequest && in_array($_POST['action'] ?? '', ['git_status','git_diff'], true)) {
    header('Content-Type: application/json; charset=utf-8');
    $temporaryFiles = [];
    try {
        $root = realpath($config['root_path']);
        if (!$root) throw new RuntimeException('Invalid workspace.');
        $repository = realpath(trim(fmGitRun($root, ['rev-parse','--show-toplevel'])));
        if ($repository !== $root) throw new RuntimeException('The workspace root must be the Git repository root.');
        if ($_POST['action'] === 'git_status') {
            $raw = fmGitRun($root, ['status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=all']);
            $entries=explode("\0", $raw); $statuses=[];
            for ($i=0;$i<count($entries);$i++) {
                if (strlen($entries[$i])<4) continue;
                $xy=substr($entries[$i],0,2); $name=substr($entries[$i],3);
                $statuses[$name]=$xy==='??' ? 'U' : (strpos($xy,'D')!==false ? 'D' : (strpos($xy,'A')!==false ? 'A' : 'M'));
                if (strpbrk($xy,'RC')!==false) $i++;
            }
            $result=['status'=>'success','available'=>true,'files'=>(object)$statuses];
        } else {
            $requested=$_POST['file'] ?? null;
            $file=is_string($requested) ? realpath($requested) : false;
            if (!$file || !is_file($file) || strpos($file,$root.DIRECTORY_SEPARATOR)!==0) throw new RuntimeException('Invalid file.');
            $relative=substr($file,strlen($root)+1);
            if (in_array('.git',explode(DIRECTORY_SEPARATOR,$relative),true)) throw new RuntimeException('Git metadata cannot be compared.');
            $content=base64_decode($_POST['content_base64'] ?? '',true);
            if ($content===false || strlen($content)>8*1024*1024 || strpos($content,"\0")!==false || !preg_match('//u',$content)) throw new RuntimeException('Only UTF-8 text up to 8 MB can be compared.');
            $tracked = fmGitRun($root,['ls-tree','-z','HEAD','--',$relative],[0,128]);
            $baseline='';
            if ($tracked!=='') {
                if (!preg_match('/^100[0-7]{3} blob ([a-f0-9]{40,64})\t/', $tracked,$blob)) throw new RuntimeException('Only regular text files can be compared.');
                $baseline=fmGitRun($root,['cat-file','blob',$blob[1]]);
                if (strlen($baseline)>8*1024*1024 || strpos($baseline,"\0")!==false || !preg_match('//u',$baseline)) throw new RuntimeException('The committed file is binary or too large.');
            }
            foreach ([$baseline,$content] as $text) {
                $temp=tempnam(sys_get_temp_dir(),'fm-git-');
                if (!$temp) throw new RuntimeException('Cannot prepare comparison.');
                $temporaryFiles[]=$temp; chmod($temp,0600);
                if (file_put_contents($temp,$text)!==strlen($text)) throw new RuntimeException('Cannot prepare comparison.');
            }
            $diff=fmGitRun($root,['diff','--no-index','--no-ext-diff','--no-textconv','--text','--unified=3','--',$temporaryFiles[0],$temporaryFiles[1]],[0,1]);
            // Remove temporary names from displayed diff headers.
            $lines=explode("\n",$diff);
            $lines=array_values(array_filter($lines,function($line){return strpos($line,'diff --git ')!==0 && strpos($line,'index ')!==0;}));
            foreach ($lines as &$line) {
                if (strpos($line,'--- ')===0) $line='--- HEAD';
                elseif (strpos($line,'+++ ')===0) $line='+++ Current editor (including unsaved changes)';
            } unset($line);
            $result=['status'=>'success','diff'=>implode("\n",$lines),'untracked'=>$tracked===''];
        }
    } catch (Throwable $error) {
        if (($_POST['action'] ?? '') === 'git_status') {
            // Git is optional; an unavailable repository is not a failed file operation.
            $result = ['status' => 'success', 'available' => false, 'files' => (object) [], 'message' => $error->getMessage()];
        } else {
            http_response_code(400);
            $result = ['status' => 'error', 'message' => $error->getMessage()];
        }
    }
    finally { foreach ($temporaryFiles as $temp) @unlink($temp); }
    echo json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE); exit;
}

/* Original CWP Code Editor license (retained for single-file deployment):
MIT License

Copyright (c) 2024 Joseph Chuks

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// Serve the integrated code editor before handling file-manager requests.
if (isset($_GET["editor"]) && $_GET["editor"] === "1") {
/*
CWP Code Editor
Version: 2.0.1
Author: @JosephChuks
GitHub: https://github.com/JosephChuks/cwp-codeEditor
*/

function editorReply($statusCode, $status, $message, $extra = [])
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    echo json_encode(array_merge(['status' => $status, 'message' => $message], $extra));
    exit();
}

function editorOpenError($message, $statusCode = 400)
{
    global $workspaceThemeScript;
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && isset($_GET['check'])) editorReply($statusCode, 'error', $message);
    http_response_code($statusCode);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store');
    $json = json_encode($message, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cannot open file</title>' . $workspaceThemeScript;
    echo '<style>body{margin:0;background:var(--bg-deep);color:var(--text-primary);font:14px system-ui}</style></head><body>';
    echo '<script src="https://cdn.jsdelivr.net/npm/coolalertjs@latest/dist/coolalert.min.js"></script>';
    echo '<script>window.fmEditorOpenError=' . $json . ';if(window.parent===window){window.workspaceAlert(window.fmEditorOpenError,"Cannot open file","warning");}</script></body></html>';
    exit;
}

function editorTextFormat($text)
{
    if (strpos($text, "\0") !== false || preg_match('//u', $text) !== 1) {
        throw new RuntimeException('Only UTF-8 text files can be edited safely. Binary files and other encodings are not converted.');
    }
    preg_match_all('/\r\n|\r|\n/', $text, $matches);
    $endings = array_values(array_unique($matches[0]));
    if (count($endings) > 1) {
        throw new RuntimeException('This file has mixed line endings. Saving is blocked to avoid changing them automatically.');
    }
    return $endings[0] ?? "\n";
}

function editorWriteVerified($path, $bytes, $exclusive = false)
{
    $stream = @fopen($path, $exclusive ? 'xb' : 'wb');
    if ($stream === false) throw new RuntimeException('Cannot create the save or backup file. Original file was not changed.');
    try {
        $length = strlen($bytes);
        $offset = 0;
        while ($offset < $length) {
            $written = @fwrite($stream, substr($bytes, $offset, 1048576));
            if ($written === false || $written === 0) throw new RuntimeException('Incomplete write. Original file was not changed.');
            $offset += $written;
        }
        if (!@fflush($stream) || (function_exists('fsync') && !@fsync($stream))) {
            throw new RuntimeException('Cannot flush the saved data. Original file was not changed.');
        }
    } finally {
        fclose($stream);
    }
    if (@filesize($path) !== strlen($bytes) || @hash_file('sha256', $path) !== hash('sha256', $bytes)) {
        throw new RuntimeException('Saved bytes did not pass verification. Original file was not changed.');
    }
}

$isEditorSave = $_SERVER['REQUEST_METHOD'] === 'POST';
$requestedFilename = $_GET['filename'] ?? null;
$editorRoot = realpath($config['root_path']);
$filename = is_string($requestedFilename) && strpos($requestedFilename, "\0") === false ? realpath($requestedFilename) : false;
if (!$editorRoot || !$filename || !is_file($filename) || ($filename !== $editorRoot && strpos($filename, rtrim($editorRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) !== 0)) {
    if ($isEditorSave) editorReply(400, 'error', 'Invalid file specified.');
    editorOpenError('Invalid file specified.', 404);
}
header('Cache-Control: no-store');
$imageTypes = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'webp' => 'image/webp', 'bmp' => 'image/bmp', 'ico' => 'image/x-icon', 'avif' => 'image/avif', 'svg' => 'image/svg+xml'];
$imageExtension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (isset($imageTypes[$imageExtension])) {
    if ($isEditorSave) editorReply(405, 'error', 'Images are available for preview only.');
    if (!is_readable($filename)) editorOpenError('Cannot read image.', 403);
    if (isset($_GET['check'])) editorReply(200, 'success', 'Image preview available.', ['kind' => 'image']);
    if (isset($_GET['image'])) {
        header('Content-Type: ' . $imageTypes[$imageExtension]);
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'");
        readfile($filename);
        exit;
    }
    $imageName = htmlspecialchars(basename($filename), ENT_QUOTES, 'UTF-8');
    $imageURL = htmlspecialchars('?editor=1&image=1&filename=' . rawurlencode($filename), ENT_QUOTES, 'UTF-8');
    ?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $imageName ?> — Image preview</title>
<?= $workspaceThemeScript ?>
<style>
html,body {margin:0;height:100%;background:var(--bg-deep);color:var(--text-primary);font:13px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
body {display:flex;flex-direction:column;}
header {padding:10px 16px;background:var(--bg-main);border-bottom:1px solid var(--border-default);overflow-wrap:anywhere;}
main {flex:1;min-height:0;overflow:auto;display:flex;align-items:center;justify-content:center;padding:20px;}
img {display:block;max-width:100%;max-height:100%;object-fit:contain;background:repeating-conic-gradient(#ffffff14 0% 25%,transparent 0% 50%) 0/20px 20px;}
#image-error {color:var(--accent-danger);}
</style></head><body><header><?= $imageName ?> <span id="image-size"></span></header>
<main><img id="image-preview" src="<?= $imageURL ?>" alt="<?= $imageName ?>"><p id="image-error" hidden>Cannot display this image. The file may be damaged or its format is not supported by your browser.</p></main>
<script>
const preview = document.getElementById('image-preview');
function imageLoaded() { document.getElementById('image-size').textContent = ' · ' + preview.naturalWidth + ' × ' + preview.naturalHeight; }
preview.addEventListener('load', imageLoaded);
preview.addEventListener('error', () => { preview.hidden = true; preview.style.display = 'none'; document.getElementById('image-error').hidden = false; });
if (preview.complete && preview.naturalWidth) imageLoaded();
window.fmImagePreview = true;
</script></body></html>
    <?php
    exit;
}
$maxEditorBytes = 8 * 1024 * 1024;
if ($isEditorSave) {
    $payloadLimit = 12 * 1024 * 1024;
    $input = file_get_contents('php://input', false, null, 0, $payloadLimit + 1);
    if ($input === false || strlen($input) > $payloadLimit) editorReply(413, 'error', 'Save request is too large. Original file was not changed.');
    $payload = json_decode($input, true);
    if (!is_array($payload) || !isset($payload['content_base64'], $payload['base_hash'], $payload['byte_length']) || !is_string($payload['content_base64']) || !is_string($payload['base_hash']) || !preg_match('/^[a-f0-9]{64}$/', $payload['base_hash']) || !is_int($payload['byte_length'])) {
        editorReply(400, 'error', 'Invalid or incomplete save request. Original file was not changed.');
    }
    $content = base64_decode($payload['content_base64'], true);
    if ($content === false || strlen($content) !== $payload['byte_length'] || strlen($content) > $maxEditorBytes) editorReply(400, 'error', 'Save data failed length verification. Original file was not changed.');
    $lock = null;
    $temporary = null;
    try {
        editorTextFormat($content);
        $backupDirectory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . '/fm-editor-' . substr(hash('sha256', __FILE__ . '|' . $editorRoot), 0, 24);
        if (is_link($backupDirectory) || (!is_dir($backupDirectory) && !@mkdir($backupDirectory, 0700))) throw new RuntimeException('Cannot prepare private backups. Original file was not changed.');
        if (!@chmod($backupDirectory, 0700)) throw new RuntimeException('Cannot protect backup directory. Original file was not changed.');
        $backupReal = realpath($backupDirectory);
        if ($backupReal === $editorRoot || strpos($backupReal, rtrim($editorRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) throw new RuntimeException('Backups must be outside the web root. Original file was not changed.');
        $fileKey = hash('sha256', $filename);
        $lockPath = $backupDirectory . '/' . $fileKey . '.lock';
        if (is_link($lockPath)) throw new RuntimeException('Invalid save lock.');
        $lock = @fopen($lockPath, 'c');
        if (!$lock || !@chmod($lockPath, 0600) || !flock($lock, LOCK_EX)) throw new RuntimeException('Cannot acquire save lock. Original file was not changed.');
        clearstatcache(true, $filename);
        if (!is_file($filename) || !is_writable($filename)) throw new RuntimeException('File is missing or read-only. Original file was not changed.');
        $stat = stat($filename);
        if ($stat['nlink'] !== 1) throw new RuntimeException('Files with hard links cannot be saved safely by this editor.');
        $original = @file_get_contents($filename);
        if ($original === false) throw new RuntimeException('Cannot read original file.');
        $originalHash = hash('sha256', $original);
        if (!hash_equals($originalHash, $payload['base_hash'])) {
            throw new RuntimeException('CONFLICT: File changed on disk since it was opened. Save blocked; your edits remain in the tab.');
        }
        $ending = editorTextFormat($original);
        // Keep BOM and newline convention even when code was formatted or pasted.
        $hasBOM = substr($original, 0, 3) === "\xEF\xBB\xBF";
        if ($hasBOM !== (substr($content, 0, 3) === "\xEF\xBB\xBF")) throw new RuntimeException('UTF-8 BOM changed. Save blocked to preserve the original encoding.');
        preg_match_all('/\r\n|\r|\n/', $content, $newEndings);
        if (count($newEndings[0]) && array_values(array_unique($newEndings[0])) !== [$ending]) throw new RuntimeException('Line endings changed. Save blocked to preserve the original format.');
        if ($content !== $original) {
            $backupPath = $backupDirectory . '/' . $fileKey . '-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(6)) . '.bak';
            editorWriteVerified($backupPath, $original, true);
            if (!@chmod($backupPath, 0600)) throw new RuntimeException('Cannot protect backup file. Original file was not changed.');
            $temporary = @tempnam(dirname($filename), '.fm-save-');
            if ($temporary === false || dirname($temporary) !== dirname($filename)) throw new RuntimeException('Cannot create a temporary file alongside the original.');
            editorWriteVerified($temporary, $content);
            $tempStat = stat($temporary);
            if ($tempStat['uid'] !== $stat['uid'] && !@chown($temporary, $stat['uid'])) throw new RuntimeException('Cannot preserve file owner. Original file was not changed.');
            if ($tempStat['gid'] !== $stat['gid'] && !@chgrp($temporary, $stat['gid'])) throw new RuntimeException('Cannot preserve file group. Original file was not changed.');
            if (!@chmod($temporary, $stat['mode'] & 0777)) throw new RuntimeException('Cannot preserve file permissions. Original file was not changed.');
            clearstatcache(true, $filename);
            $latestStat = @stat($filename);
            if (!$latestStat || $latestStat['ino'] !== $stat['ino'] || @hash_file('sha256', $filename) !== $originalHash) throw new RuntimeException('CONFLICT: File changed during saving. Original file was not replaced.');
            if (!@rename($temporary, $filename)) throw new RuntimeException('Cannot replace original file. Your previous version is intact.');
            $temporary = null;
        }
        $result = ['hash' => hash('sha256', $content), 'byte_length' => strlen($content), 'backup_created' => $content !== $original];
    } catch (Throwable $error) {
        if ($temporary && is_file($temporary)) @unlink($temporary);
        if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
        editorReply(strpos($error->getMessage(), 'CONFLICT:') === 0 ? 409 : 400, 'error', $error->getMessage());
    }
    if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
    editorReply(200, 'success', 'File saved and verified.', $result);
}
if (filesize($filename) > $maxEditorBytes) editorOpenError('File is too large for safe editing (maximum 8 MB).', 413);
$fileContents = @file_get_contents($filename);
if ($fileContents === false) editorOpenError('Cannot read file. Saving is disabled.', 403);
try { $originalNewline = editorTextFormat($fileContents); }
catch (Throwable $error) { editorOpenError($error->getMessage()); }
if (isset($_GET['check'])) editorReply(200, 'success', 'Text editor available.', ['kind' => 'text']);
$fileHash = hash('sha256', $fileContents);
$fileExtension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$basename = basename($filename);

$languageModes = [
    "html"  => "html",
    "htm"   => "html",
    "php"   => "php",
    "js"    => "javascript",
    "ts"    => "typescript",
    "jsx"   => "jsx",
    "tsx"   => "tsx",
    "css"   => "css",
    "scss"  => "scss",
    "sass"  => "sass",
    "less"  => "less",
    "json"  => "json",
    "sh"    => "sh",
    "bash"  => "sh",
    "py"    => "python",
    "sql"   => "sql",
    "md"    => "markdown",
    "xml"   => "xml",
    "yaml"  => "yaml",
    "yml"   => "yaml",
    "ini"   => "ini",
    "conf"  => "sh",
    "txt"   => "text",
    "htaccess" => "apache_conf",
];
$editorMode = $languageModes[$fileExtension] ?? "sh";

$modeOptions = [
    "html"       => "HTML",
    "php"        => "PHP",
    "javascript" => "JavaScript",
    "typescript" => "TypeScript",
    "jsx"        => "JSX",
    "css"        => "CSS",
    "scss"       => "SCSS",
    "json"       => "JSON",
    "sh"         => "Bash / Shell",
    "python"     => "Python",
    "sql"        => "SQL",
    "markdown"   => "Markdown",
    "xml"        => "XML",
    "yaml"       => "YAML",
    "ini"        => "INI",
    "text"       => "Plain Text",
    "apache_conf" => "Apache Config",
];

$fileSize = strlen($fileContents);
$lastModified = date("M j Y, H:i:s", filemtime($filename));
$lineCount = substr_count($fileContents, "\n") + 1;
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <?= $workspaceThemeScript ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($basename) ?> — Pocket Code Studio</title>
    <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiMyMTI1MmIiLz48cGF0aCBkPSJtMjMgMjAtMTIgMTIgMTIgMTJtMTgtMjQgMTIgMTItMTIgMTJtLTYtMjgtNiAzMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNjFhZmVmIiBzdHJva2Utd2lkdGg9IjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==" type="image/svg+xml">

    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">

    <style>
        /* ── Design Tokens (matches filemanager v3.0) ────────────── */
        :root {--bg-deep: #0f1117;--bg-main: #1a1d2e;--bg-surface: #1e2235;--bg-elevated: #242840;--bg-hover: rgba(255, 255, 255, 0.04);--border-subtle: rgba(255, 255, 255, 0.06);--border-default: rgba(255, 255, 255, 0.10);--border-accent: #3b82f6;--text-primary: #e2e8f0;--text-secondary: #94a3b8;--text-muted: #64748b;--text-link: #60a5fa;--accent: #3b82f6;--accent-hover: #2563eb;--accent-success: #10b981;--accent-danger: #ef4444;--accent-warning: #f59e0b;--scrollbar-gold: #c9a227;--scrollbar-gold-hover: #f0c040;--radius-sm: 4px;--radius-md: 6px;--shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);--font-mono: 'Fira Code', 'Cascadia Code', 'Courier New', monospace;}
        /* ── Reset ───────────────────────────────────────────────── */
        *, *::before, *::after {box-sizing: border-box;margin: 0;padding: 0;}
        html, body {height: 100%;overflow: hidden;font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;font-size: 16px;background: var(--bg-deep);color: var(--text-primary);}
        ::-webkit-scrollbar {width: 5px;height: 5px;}
        ::-webkit-scrollbar-track {background: transparent;}
        ::-webkit-scrollbar-thumb {background: var(--scrollbar-gold);border-radius: 10px;}
        ::-webkit-scrollbar-thumb:hover {background: var(--scrollbar-gold-hover);}
        /* ── Top Bar ─────────────────────────────────────────────── */
        #topbar {position: fixed;top: 0;left: 0;right: 0;height: 46px;background: var(--bg-main);border-bottom: 1px solid var(--border-subtle);display: flex;align-items: center;justify-content: space-between;padding: 0 12px;z-index: 200;gap: 8px;}
        .topbar-left {display: flex;align-items: center;gap: 8px;min-width: 0;flex: 1;}
        .brand-logo {display: flex;align-items: center;}
        .brand-logo img {height: 24px;display: block;}
        .file-badge {display: flex;align-items: center;gap: 6px;background: var(--bg-elevated);border: 1px solid var(--border-default);border-radius: var(--radius-sm);padding: 3px 10px;font-size: 0.8rem;color: var(--text-secondary);min-width: 0;max-width: 500px;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;}
        .file-badge i {color: var(--accent);font-size: 0.72rem;flex-shrink: 0;}
        .file-badge .fname {color: var(--text-link);font-weight: 600;}
        .unsaved-dot {width: 7px;height: 7px;background: var(--accent-warning);border-radius: 50%;flex-shrink: 0;display: none;}
        .unsaved-dot.visible {display: inline-block;}
        .topbar-right {display: flex;align-items: center;gap: 4px;flex-shrink: 0;}
        /* ── Toolbar Selects ─────────────────────────────────────── */
        .tb-select {background: var(--bg-elevated);border: 1px solid var(--border-default);color: var(--text-secondary);font-size: 0.75rem;padding: 3px 8px;border-radius: var(--radius-sm);cursor: pointer;outline: none;transition: border-color 0.15s;-webkit-appearance: none;appearance: none;padding-right: 20px;background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2364748b'/%3E%3C/svg%3E");background-repeat: no-repeat;background-position: right 6px center;}
        .tb-select:focus, .tb-select:hover {border-color: var(--accent);color: var(--text-primary);}
        .tb-select option {background: var(--bg-elevated);color: var(--text-primary);}
        /* ── Toolbar Buttons ─────────────────────────────────────── */
        .tb-btn {display: inline-flex;align-items: center;gap: 5px;padding: 4px 10px;font-size: 0.75rem;font-weight: 500;border: 1px solid var(--border-default);border-radius: var(--radius-sm);background: transparent;color: var(--text-secondary);cursor: pointer;transition: all 0.15s;white-space: nowrap;}
        .tb-btn i {font-size: 0.68rem;}
        .tb-btn:hover {background: var(--bg-hover);color: var(--text-primary);border-color: var(--border-default);}
        .tb-btn.primary {background: var(--accent);border-color: var(--accent);color: #fff;}
        .tb-btn.primary:hover {background: var(--accent-hover);border-color: var(--accent-hover);}
        .tb-btn.primary:disabled {opacity: 0.5;cursor: not-allowed;}
        .tb-btn.success {background: var(--accent-success);border-color: var(--accent-success);color: #fff;}
        .tb-btn.success:hover {background: #059669;border-color: #059669;}
        .tb-btn.success:disabled {opacity: 0.5;cursor: not-allowed;}
        .tb-divider {width: 1px;height: 18px;background: var(--border-subtle);margin: 0 2px;}
        /* ── Second toolbar (sub-bar) ────────────────────────────── */
        #subbar {position: fixed;top: 46px;left: 0;right: 0;height: 34px;background: var(--bg-surface);border-bottom: 1px solid var(--border-subtle);display: flex;align-items: center;padding: 0 12px;gap: 4px;z-index: 199;}
        /* ── Editor Area ─────────────────────────────────────────── */
        #editor-wrap {position: fixed;top: 80px;bottom: 24px; /* status bar */ left: 0;right: 0;}
        #editor {width: 100%;height: 100%;font-size: 12px;}
        /* ── Status Bar ──────────────────────────────────────────── */
        #statusbar {position: fixed;bottom: 0;left: 0;right: 0;height: 24px;background: var(--bg-elevated);border-top: 1px solid var(--border-subtle);display: flex;align-items: center;justify-content: space-between;padding: 0 12px;font-size: 0.68rem;color: var(--text-muted);z-index: 200;gap: 12px;}
        .statusbar-left, .statusbar-right {display: flex;align-items: center;gap: 12px;}
        .status-item {display: flex;align-items: center;gap: 4px;}
        .status-item i {font-size: 0.6rem;}
        #status-saved {color: var(--accent-success);font-weight: 600;display: flex;}
        #status-cursor {color: var(--text-secondary);}
        /* ── Save notification toast ─────────────────────────────── */
        #save-toast {display: none;animation: slideIn 0.2s ease;}
        @keyframes slideIn {
            from {opacity: 0;transform: translateY(-8px);}
            to {opacity: 1;transform: translateY(0);}
        }
        /* ── Spinner (initial load) ───────────────────────────────── */
        #spinner-overlay {position: fixed;inset: 0;background: var(--bg-deep);display: flex;flex-direction: column;align-items: center;justify-content: center;z-index: 9999;gap: 16px;}
        .spinner {width: 32px;height: 32px;border: 3px solid var(--border-default);border-top-color: var(--accent);border-radius: 50%;animation: spin 0.7s linear infinite;}
        @keyframes spin {
            to {transform: rotate(360deg);}
        }
        .spinner-label {font-size: 0.8rem;color: var(--text-muted);}
        /* ── Kbd shortcuts hint ──────────────────────────────────── */
        kbd {display: inline-block;background: var(--bg-deep);border: 1px solid var(--border-default);border-radius: 3px;padding: 1px 5px;font-size: 0.65rem;color: var(--text-muted);font-family: var(--font-mono);}
        #git-diff-dialog {margin: auto;width: min(1000px, 94vw);max-height: 88vh;background: var(--bg-main);color: var(--text-primary);border: 1px solid var(--border-default);border-radius: 6px;padding: 0;}
        #git-diff-dialog::backdrop {background: #0008;}
        .git-diff-title {display: flex;justify-content: space-between;align-items: center;padding: 10px 14px;background: var(--bg-elevated);}
        #git-diff-close {background: transparent;border: 0;color: var(--text-primary);font-size: 24px;cursor: pointer;}
        #git-diff-output {margin: 0;padding: 12px;max-height: 72vh;overflow: auto;font: 12px/1.6 monospace;white-space: pre;}
        .git-diff-lines {width: max-content;min-width: 100%;}
        .git-diff-row {display: flex;box-sizing: border-box;border-left: 3px solid transparent;}
        .git-diff-gutter {display: flex;flex-shrink: 0;position: sticky;left: 0;background: var(--bg-main);color: var(--text-muted);border-right: 1px solid var(--border-subtle);user-select: none;}
        .git-diff-number {display: block;box-sizing: border-box;width: 9ch;padding: 0 1ch;text-align: right;font-variant-numeric: tabular-nums;}
        .git-diff-code {display: block;padding-left: 12px;}
        .git-diff-column-head {color: var(--text-secondary);border-bottom: 1px solid var(--border-subtle);}
        .git-added .git-diff-gutter {color: var(--accent-success);}
        .git-removed .git-diff-gutter {color: var(--accent-danger);}
        .git-added {background: #33995522;color: var(--text-primary);border-left: 3px solid #43a866;}
        .git-removed {background: #dd445522;color: var(--text-primary);border-left: 3px solid #e06c75;}
        .git-hunk {color: var(--text-link);}
        .mobile-code-keys, #mobile-status-toggle, #mobile-keys-toggle {display: none;}
        @media (max-width: 760px) {
            html, body {height: var(--mobile-viewport-height, 100dvh);}
            #statusbar {min-height: 36px;height: auto;padding: 2px 8px;gap: 4px;flex-wrap: wrap;}
            .statusbar-left, .statusbar-right {gap: 4px;}
            #statusbar .statusbar-right > .status-item, #fontSize, #indentation {display: none !important;}
            body.mobile-status-details #statusbar .statusbar-right > .status-item {display: flex !important;}
            body.mobile-status-details #fontSize, body.mobile-status-details #indentation {display: block !important;}
            .status-language {max-width: 110px;min-height: 32px;font-size: 13px;}
            #mobile-status-toggle, #mobile-keys-toggle {display: inline-flex;align-items: center;justify-content: center;width: 36px;height: 32px;background: transparent;color: var(--text-primary);border: 1px solid var(--border-subtle);border-radius: 4px;}
            .mobile-code-keys {display: flex;gap: 4px;padding: 4px 6px;flex-shrink: 0;background: var(--bg-elevated);overflow-x: auto;}
            body.mobile-keys-hidden .mobile-code-keys {display: none;}
            .mobile-code-keys button {flex: 1 0 38px;min-height: 36px;padding: 4px 7px;background: var(--bg-main);color: var(--text-primary);border: 1px solid var(--border-default);border-radius: 4px;font: 13px monospace;touch-action: manipulation;}
            #git-diff-dialog {width: 100vw;max-width: 100vw;max-height: 95%;}
            #git-diff-output {max-height: 75vh;}
            #editor .ace_search {left: 0 !important;right: 0 !important;max-width: 100% !important;width: 100%;box-sizing: border-box;font-size: 16px;}
            #editor .ace_search_field {font-size: 16px;max-width: 55vw;}
            #editor .ace_searchbtn, #editor .ace_replacebtn {padding: 5px;}
        }
        /* Fit the editor inside narrow internal tabs. */
        body {display: flex;flex-direction: column;overflow: hidden;}
        #topbar {position: static;height: auto;min-height: 36px;flex-shrink: 0;flex-wrap: wrap;justify-content: flex-start;gap: 4px;padding: 4px 8px;}
        #topbar .file-badge {max-width: 160px;flex-shrink: 1;padding: 3px 6px;}
        #topbar .tb-select {max-width: 125px;}
        .topbar-left {flex-basis: 100%;}
        .topbar-right {flex-wrap: wrap;flex-shrink: 1;}
        #subbar {position: static;flex-shrink: 0;overflow: hidden;white-space: nowrap;}
        #subbar > span:first-child {overflow: hidden;text-overflow: ellipsis;}
        #editor-wrap {position: relative;inset: auto;flex: 1;min-height: 0;display: flex;overflow: hidden;}
        #editor {flex: 1;min-width: 0;width: auto;}
        /* The minimap handles vertical navigation; keep Ace's own bar as a fallback. */
        #editor .ace_scrollbar-v {visibility: hidden;pointer-events: none;}
        body.minimap-hidden #editor .ace_scrollbar-v {visibility: visible;pointer-events: auto;}
        #editor .ace_scrollbar {scrollbar-width: thin;scrollbar-color: var(--scrollbar-gold) var(--bg-main);}
        #editor .ace_scrollbar::-webkit-scrollbar {width: 10px;height: 10px;}
        #editor .ace_scrollbar::-webkit-scrollbar-track {background: var(--bg-main);}
        #editor .ace_scrollbar::-webkit-scrollbar-thumb {background: var(--scrollbar-gold);border: 2px solid var(--bg-main);border-radius: 5px;}
        #editor .ace_scrollbar::-webkit-scrollbar-thumb:hover {background: var(--scrollbar-gold-hover);}
        #editor .ace_scrollbar::-webkit-scrollbar-corner {background: var(--bg-main);}
        #minimap {position: absolute;top: 0;right: 12px;bottom: 10px;z-index: 5;background: transparent;width: 112px;flex-shrink: 0;overflow: hidden;touch-action: none;cursor: pointer;border-left: 1px solid var(--border-subtle);}
        #minimap[hidden] {display: none;}
        #occurrence-rail {width: 12px;flex-shrink: 0;position: relative;background: var(--bg-main);border-left: 1px solid var(--border-subtle);cursor: pointer;touch-action: none;outline: none;}
        #occurrence-rail:focus-visible {outline: 1px solid var(--accent);outline-offset: -1px;}
        #occurrence-rail canvas {width: 100%;height: 100%;display: block;pointer-events: none;}
        #minimap canvas {display: block;width: 100%;height: 100%;pointer-events: none;}
        #minimap-viewport {position: absolute;left: 0;right: 0;background: #abb2bf20;border: 1px solid #abb2bf40;pointer-events: none;}
        #minimap:hover #minimap-viewport {background: #abb2bf35;}
        #minimapBtn[aria-pressed="true"] {color: var(--text-link);border-color: var(--accent);}
        .minimap-color-probe {position: absolute;visibility: hidden;pointer-events: none;}
        @media (max-width: 600px) {
            #minimap {width: 70px;}
        }
        .status-language {appearance: none;-webkit-appearance: none;background: transparent;color: var(--text-primary);border: 0;padding: 2px 8px;font: inherit;cursor: pointer;max-width: 140px;}
        .status-language:hover, .status-language:focus-visible {background: var(--bg-hover);outline: 1px solid var(--accent);}
        .status-language option {background: var(--bg-elevated);color: var(--text-primary);}
        .status-action {background:transparent;border:0;padding:2px 4px;color:inherit;font:inherit;cursor:pointer;}
        .status-action:hover {background:var(--bg-hover);}
        #status-saved[data-state="unsaved"], #status-saved[data-state="saving"] {color:var(--accent-warning);}
        #goto-dialog {background:var(--bg-main);color:var(--text-primary);border:1px solid var(--border-default);border-radius:6px;padding:18px;width:min(320px,90vw);font:13px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
        #goto-dialog::backdrop {background:#0006;}
        #goto-dialog input {width:100%;margin:10px 0;padding:8px;background:var(--bg-deep);color:var(--text-primary);border:1px solid var(--border-default);font-size:16px;}
        #goto-dialog button {background:var(--bg-elevated);color:var(--text-primary);border:1px solid var(--border-default);border-radius:4px;padding:6px 12px;}
        .statusbar-right {min-width: 0;}
        .status-language {flex-shrink: 0;}
        #statusbar {position: static;flex-shrink: 0;overflow: hidden;white-space: nowrap;}
    </style>
</head>

<body>

    <dialog id="git-diff-dialog"><div class="git-diff-title"><strong id="git-diff-heading">Git changes</strong><button type="button" id="git-diff-close" aria-label="Close comparison">×</button></div><pre id="git-diff-output"></pre></dialog>
    <!-- ── Spinner ───────────────────────────────────────────────── -->
    <div id="spinner-overlay">
        <div class="spinner"></div>
        <span class="spinner-label">Loading editor…</span>
    </div>

    <!-- ── Save Toast ────────────────────────────────────────────── -->
    <div id="save-toast" class="workspace-toast" role="status" aria-live="polite">
        <i class="fas fa-check-circle"></i> File saved successfully
    </div>

    <!-- ── Editor ────────────────────────────────────────────────── -->
    <div id="editor-wrap">
        <div id="editor"></div>
        <div id="minimap" role="slider" tabindex="0" aria-label="Code minimap" aria-valuemin="1" aria-valuenow="1" title="Click or drag to navigate; arrow keys to scroll">
            <canvas aria-hidden="true"></canvas>
            <div id="minimap-viewport"></div>
        </div>
        <div id="occurrence-rail" tabindex="0" role="slider" aria-label="Selected text occurrences" aria-valuemin="1" aria-valuemax="1" aria-valuenow="1" title="Select a word to see its occurrences across the file">
            <canvas aria-hidden="true"></canvas>
        </div>
    </div>

    <div class="mobile-code-keys" role="toolbar" aria-label="Code keyboard shortcuts">
        <button type="button" data-code-command="indent" aria-label="Indent">Tab</button><button type="button" data-code-command="outdent" aria-label="Outdent">⇤</button>
        <button type="button" data-code-text="{">{</button><button type="button" data-code-text="}">}</button>
        <button type="button" data-code-text="(">(</button><button type="button" data-code-text=")">)</button>
        <button type="button" data-code-command="undo" aria-label="Undo">↶</button><button type="button" data-code-command="redo" aria-label="Redo">↷</button>
    </div>
    <!-- ── Status Bar ────────────────────────────────────────────── -->
    <div id="statusbar">
        <div class="statusbar-left">
            <button type="button" class="status-item status-action" id="status-cursor" title="Go to line" aria-label="Go to line">Ln 1, Col 1</button>
            <span class="status-item" id="status-saved" role="status">Saved</span>
        </div>
        <div class="statusbar-right">
            <button type="button" id="mobile-keys-toggle" aria-label="Toggle code keyboard shortcuts" aria-pressed="true">⌨</button>
            <button type="button" id="mobile-status-toggle" aria-label="More editor settings" aria-expanded="false">…</button>
            <select class="status-language" id="fontSize" onchange="changeFontSize(this.value)" title="Font size" aria-label="Font size">
                <option value="10px">10px</option>
                <option value="11px">11px</option>
                <option value="12px" selected>12px</option>
                <option value="13px">13px</option>
                <option value="14px">14px</option>
                <option value="15px">15px</option>
                <option value="16px">16px</option>
                <option value="18px">18px</option>
                <option value="20px">20px</option>
            </select>
            <span class="status-item" title="File encoding"><?= substr($fileContents, 0, 3) === "\xEF\xBB\xBF" ? 'UTF-8 BOM' : 'UTF-8' ?></span>
            <span class="status-item" title="Line endings"><?= $originalNewline === "\r\n" ? 'CRLF' : ($originalNewline === "\r" ? 'CR' : 'LF') ?></span>
            <select id="indentation" class="status-language status-detail" aria-label="Indentation" title="Indentation for typing; existing text stays unchanged">
                <option value="spaces:2">Spaces: 2</option><option value="spaces:4">Spaces: 4</option><option value="spaces:8">Spaces: 8</option>
                <option value="tabs:2">Tab Size: 2</option><option value="tabs:4">Tab Size: 4</option><option value="tabs:8">Tab Size: 8</option>
            </select>
            <span class="status-item">
                <i class="fas fa-weight-hanging"></i>
                <?= $fileSize < 1024 ? $fileSize . ' B' : round($fileSize / 1024, 1) . ' KB' ?>
            </span>
            <span class="status-item">
                <i class="fas fa-lines-leaning"></i>
                <?= number_format($lineCount) ?> lines
            </span>
            <select class="status-language" id="mode" onchange="changeMode(this.value)" title="Select language mode" aria-label="Language mode">
                <?php foreach ($modeOptions as $val => $label): ?>
                    <option value="<?= $val ?>" <?= $editorMode === $val ? 'selected' : '' ?>><?= $label ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </div>

    <dialog id="goto-dialog" aria-labelledby="goto-title"><form id="goto-form">
        <label id="goto-title" for="goto-line">Go to line</label>
        <input id="goto-line" type="number" min="1" step="1" required inputmode="numeric">
        <div style="display:flex;justify-content:flex-end;gap:8px"><button type="button" id="goto-cancel">Cancel</button><button type="submit">Go</button></div>
    </form></dialog>
    <!-- Ace Editor -->
    <script src="https://cdn.jsdelivr.net/npm/ace-builds@1.45.2/src-min-noconflict/ace.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/ace-builds@1.45.2/src-min-noconflict/ext-language_tools.js"></script>

    <!-- Prettier -->
    <script src="https://unpkg.com/prettier@2.7.1/standalone.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-html.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-babel.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-postcss.js"></script>
    <script src="https://unpkg.com/@prettier/plugin-php@0.19.0/standalone.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-markdown.js"></script>

    <!-- Font Awesome 6 (matches file manager) -->
    <script>
        // ── Init ──────────────────────────────────────────────────────
        window.finishEditorLoading = function() {
            document.getElementById('spinner-overlay').style.display = 'none';
            window.fmEditorThemeReady = true;
            if (window.frameElement) {
                delete window.frameElement.dataset.loading;
                window.frameElement.style.visibility = '';
            }
        };

        // ── Ace Editor ───────────────────────────────────────────────
        const originalContent = <?= json_encode($fileContents, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const originalNewline = <?= json_encode($originalNewline) ?>;
        const editorFilename = <?= json_encode($basename, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        let fileRevision = <?= json_encode($fileHash) ?>;
        var editor = ace.edit("editor");
        editor.setValue(originalContent, -1);
        editor.session.setNewLineMode(originalNewline === "\r\n" ? 'windows' : 'unix');
        let savedEditorValue = editor.getValue();
        let lastSavedContent = originalContent;
        let savingFile = false;
        editor.session.setMode("ace/mode/<?= $editorMode ?>");
        // Ace includes multi_select: Ctrl-click (Cmd-click on macOS), Escape to exit.
        ace.require('ace/multi_select');
        editor.setOptions({
            enableMultiselect: true,
            enableBasicAutocompletion: true,
            enableSnippets: true,
            enableLiveAutocompletion: localStorage.getItem('ke_live_autocomplete') !== 'false',
            fontSize: "12px",
            wrap: false,
            highlightActiveLine: true,
            highlightSelectedWord: true,
            enableAutoIndent: true,
            showPrintMargin: false,
            showInvisibles: localStorage.getItem('ke_invisibles') === 'true',
            displayIndentGuides: localStorage.getItem('ke_indent_guides') !== 'false',
            scrollPastEnd: 0.5,
            tabSize: 4,
            useSoftTabs: true,
        });

        // Remove Ace's default border
        editor.container.style.lineHeight = '1.6';

        const mobileEditorQuery = matchMedia('(max-width: 760px)');
        var wrapEnabled = mobileEditorQuery.matches;
        editor.session.setUseWrapMode(wrapEnabled);
        function editorMobileViewport() {
            if (window.parent === window && window.visualViewport) document.documentElement.style.setProperty('--mobile-viewport-height', window.visualViewport.height + 'px');
            editor.resize();
            if (editor.isFocused()) editor.renderer.scrollCursorIntoView();
        }
        new ResizeObserver(() => requestAnimationFrame(editorMobileViewport)).observe(document.getElementById('editor-wrap'));
        if (window.parent === window && window.visualViewport) {
            visualViewport.addEventListener('resize', editorMobileViewport);
            visualViewport.addEventListener('scroll', editorMobileViewport);
        }
        document.querySelectorAll('[data-code-command], [data-code-text]').forEach(button => {
            button.addEventListener('pointerdown', event => event.preventDefault());
            button.addEventListener('click', () => {
                editor.focus();
                if (button.dataset.codeCommand) editor.execCommand(button.dataset.codeCommand);
                else editor.insert(button.dataset.codeText);
            });
        });
        document.getElementById('mobile-status-toggle').addEventListener('click', event => {
            const expanded = document.body.classList.toggle('mobile-status-details');
            event.currentTarget.setAttribute('aria-expanded', String(expanded));
            editor.resize();
        });
        function setMobileKeysHidden(hidden) {
            document.body.classList.toggle('mobile-keys-hidden', hidden);
            document.getElementById('mobile-keys-toggle').setAttribute('aria-pressed', String(!hidden));
            editor.resize();
        }
        setMobileKeysHidden(localStorage.getItem('pcs_mobile_keys_hidden') === 'true');
        document.getElementById('mobile-keys-toggle').addEventListener('click', () => {
            const hidden = !document.body.classList.contains('mobile-keys-hidden');
            localStorage.setItem('pcs_mobile_keys_hidden', String(hidden));
            setMobileKeysHidden(hidden);
        });
        var isFullscreen = false;
        var hasUnsavedChanges = false;

        function notifyWorkspace() {
            if (window.parent !== window && typeof window.parent.updateEditorTab === 'function') {
                window.parent.updateEditorTab(window, hasUnsavedChanges);
            }
        }

        // ── Track unsaved changes ─────────────────────────────────────
        editor.session.on('change', function() {
            if (!hasUnsavedChanges) {
                hasUnsavedChanges = true;
                window.setWorkspaceDocumentTitle(editorFilename, true);
            }
            updateSaveStatus();
            notifyWorkspace();
        });

        // ── Cursor / selection status ─────────────────────────────────
        editor.selection.on('changeCursor', updateCursorStatus);

        function updateCursorStatus() {
            const pos = editor.getCursorPosition();
            document.getElementById('status-cursor').innerHTML =
                `<i class="fas fa-location-crosshairs"></i> Ln ${pos.row + 1}, Col ${pos.column + 1}`;

        }

        const gotoDialog = document.getElementById('goto-dialog');
        const gotoInput = document.getElementById('goto-line');
        document.getElementById('status-cursor').addEventListener('click', () => {
            gotoInput.max = editor.session.getLength();
            gotoInput.value = editor.getCursorPosition().row + 1;
            gotoDialog.showModal(); gotoInput.select();
        });
        gotoDialog.addEventListener('close', () => editor.focus());
        document.getElementById('goto-cancel').addEventListener('click', () => { gotoDialog.close(); editor.focus(); });
        document.getElementById('goto-form').addEventListener('submit', event => {
            event.preventDefault();
            if (!event.currentTarget.reportValidity()) return;
            editor.gotoLine(Number(gotoInput.value), 0, true);
            gotoDialog.close(); editor.focus();
        });
        const indentation = document.getElementById('indentation');
        const indentedLines = originalContent.split(/\r\n|\r|\n/).filter(line => /^[ \t]+\S/.test(line));
        const tabLines = indentedLines.filter(line => line.startsWith('\t')).length;
        const spaceWidths = indentedLines.map(line => /^( +)\S/.exec(line)?.[1].length).filter(Boolean);
        const width = spaceWidths.length ? spaceWidths.reduce((minimum, value) => Math.min(minimum, value), Infinity) : 4;
        indentation.value = tabLines > indentedLines.length / 2 ? 'tabs:4' : 'spaces:' + ([2,4,8].includes(width) ? width : 4);
        function applyIndentation() {
            const [kind, size] = indentation.value.split(':');
            editor.session.setTabSize(Number(size));
            editor.session.setUseSoftTabs(kind === 'spaces');
        }
        indentation.addEventListener('change', () => { applyIndentation(); editor.focus(); });
        applyIndentation();
        let lastSavedAt = null;
        function updateSaveStatus() {
            const status = document.getElementById('status-saved');
            status.dataset.state = savingFile ? 'saving' : hasUnsavedChanges ? 'unsaved' : 'saved';
            status.textContent = savingFile ? 'Saving…' : hasUnsavedChanges ? 'Unsaved' : 'Saved' + (lastSavedAt ? ' ' + lastSavedAt.toLocaleTimeString('en-GB', {hour12:false}) : '');
        }

        // ── Theme / Mode / Font ───────────────────────────────────────
        window.applySelectedTheme = function(theme) {
            editor.setTheme('ace/theme/' + theme, () => {
                requestAnimationFrame(() => {
                    if (inlineDiffView) inlineDiffView.otherEditor.setTheme(editor.getTheme());
                    mapColors.clear(); scheduleMinimap();
                    if (typeof scheduleOccurrenceDraw === 'function') scheduleOccurrenceDraw();
                    window.finishEditorLoading();
                });
            });
        };

        function changeMode(mode) {
            editor.session.setMode("ace/mode/" + mode);
            document.getElementById('mode').value = mode;
            localStorage.setItem('ke_mode', mode);
        }

        function changeFontSize(size) {
            editor.setOptions({
                fontSize: size
            });
            if (inlineDiffView) inlineDiffView.otherEditor.setOptions({fontSize:size});
            localStorage.setItem('ke_font', size);
        }

        // ── Restore preferences ───────────────────────────────────────
        (function restorePrefs() {
            const font = localStorage.getItem('ke_font');
            if (font) {
                document.getElementById('fontSize').value = font;
                changeFontSize(font);
            }
        })();

        // Inline comparison uses the last verified save, never the Git index or HEAD.
        var inlineDiffView = null;
        let inlineDiffRequest = 0;
        window.inlineChangesEnabled = false;
        function refreshInlineChangesBaseline() {
            try { if (inlineDiffView) inlineDiffView.sessionA.setValue(savedEditorValue); }
            catch (error) { console.error('Could not refresh inline comparison after save:', error); }
        }
        window.setInlineChanges = async function(enabled) {
            const request = ++inlineDiffRequest;
            window.inlineChangesEnabled = !!enabled;
            try {
                if (!enabled) {
                    if (inlineDiffView) {
                        const baseline = inlineDiffView.sessionA;
                        const selection = editor.selection.toJSON(), top = editor.session.getScrollTop(), left = editor.session.getScrollLeft();
                        inlineDiffView.detach(); inlineDiffView = null;
                        baseline.destroy();
                        editor.selection.fromJSON(selection); editor.session.setScrollTop(top); editor.session.setScrollLeft(left);
                    }
                    return;
                }
                if (inlineDiffView) return;
                if (Math.max(new TextEncoder().encode(editor.getValue()).byteLength, new TextEncoder().encode(savedEditorValue).byteLength) > 1024*1024 || editor.session.getLength() > 20000 || savedEditorValue.split(/\r\n|\r|\n/).length > 20000) throw new Error('Inline changes are available for files up to 1 MiB and 20,000 lines.');
                await window.loadInlineDiff();
                if (request !== inlineDiffRequest || !window.inlineChangesEnabled) return;
                const module = ace.require('ace/ext/diff');
                if (!module) throw new Error('The inline comparison module could not be loaded.');
                const options = editor.getOptions();
                inlineDiffView = module.createDiffView({inline:'b',editorB:editor,valueA:savedEditorValue});
                inlineDiffView.sessionA.setMode(editor.session.getMode());
                editor.setOptions({animatedScroll:options.animatedScroll,highlightActiveLine:options.highlightActiveLine,highlightGutterLine:options.highlightGutterLine,selectionStyle:options.selectionStyle});
            } catch (error) {
                window.inlineChangesEnabled = false;
                window.workspaceAlert(error.message || 'Cannot show inline changes.', 'Cannot show changes', 'warning');
            } finally {
                editor.resize(); scheduleMinimap();
                const host = window.parent !== window ? window.parent : window;
                if (window.parent === window || !window.frameElement?.hidden) host.document.querySelectorAll('[data-editor-command="inlinechanges"]').forEach(button => button.setAttribute('aria-pressed',String(window.inlineChangesEnabled)));
            }
        };
        function toggleInlineChanges() {
            const host = window.parent !== window ? window.parent : window;
            host.setInlineChangesPreference(!window.inlineChangesEnabled);
        }
        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('ke_inline_changes') === 'true') window.setInlineChanges(true);
        });
        editor.session.on('changeMode', () => { if (inlineDiffView) inlineDiffView.sessionA.setMode(editor.session.getMode()); });

        // ── Verified save; successful HTTP alone is not proof of a successful write ──
        async function saveFile() {
            if (savingFile) return;
            savingFile = true;
            updateSaveStatus();
            const editorValue = editor.getValue();
            // Preserve untouched original bytes, including final newline and BOM.
            const content = editorValue === savedEditorValue ? lastSavedContent : editorValue.replace(/\r\n|\r|\n/g, originalNewline);
            try {
                const bytes = new TextEncoder().encode(content);
                let binary = '';
                for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
                const response = await fetch(window.location.pathname + '?editor=1&filename=<?= urlencode($filename) ?>', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({content_base64: btoa(binary), base_hash: fileRevision, byte_length: bytes.length})
                });
                let result;
                try { result = await response.json(); }
                catch (_) { throw new Error('Server returned an invalid response. Save was not confirmed; your edits remain in the tab.'); }
                if (!response.ok || result.status !== 'success' || !/^[a-f0-9]{64}$/.test(result.hash || '') || result.byte_length !== bytes.length) {
                    throw new Error(result.message || 'Save verification failed. Your edits remain in the tab.');
                }
                fileRevision = result.hash;
                savedEditorValue = editorValue;
                refreshInlineChangesBaseline();
                lastSavedContent = content;
                hasUnsavedChanges = editor.getValue() !== savedEditorValue;
                notifyWorkspace();
                window.setWorkspaceDocumentTitle(editorFilename, hasUnsavedChanges);
                window.workspaceToast('File saved and verified.', 'Saved');
                lastSavedAt = new Date();
            } catch (error) {
                window.workspaceAlert(error.message || 'Save failed. Your edits remain in the tab.', 'Save failed');
            } finally {
                savingFile = false;
                updateSaveStatus();
            }
        }

        // ── Format ────────────────────────────────────────────────────
        function formatCode() {
            const code = editor.getValue();
            const mode = "<?= $fileExtension ?>";
            let formatted;
            try {
                switch (mode) {
                    case 'html':
                    case 'htm':
                        formatted = prettier.format(code, {
                            parser: "html",
                            plugins: prettierPlugins
                        });
                        break;
                    case 'js':
                    case 'jsx':
                    case 'ts':
                    case 'tsx':
                        formatted = prettier.format(code, {
                            parser: "babel",
                            plugins: prettierPlugins
                        });
                        break;
                    case 'css':
                    case 'scss':
                    case 'less':
                        formatted = prettier.format(code, {
                            parser: "css",
                            plugins: prettierPlugins
                        });
                        break;
                    case 'php':
                        formatted = prettier.format(code, {
                            parser: "php",
                            plugins: prettierPlugins
                        });
                        break;
                    case 'md':
                        formatted = prettier.format(code, {
                            parser: "markdown",
                            plugins: prettierPlugins
                        });
                        break;
                    default:
                        window.workspaceAlert('Auto-format not available for this file type.', 'Format');
                        return;
                }
                editor.setValue(formatted, -1);
            } catch (e) {
                console.error("Format error:", e);
                window.workspaceAlert("Formatting failed: " + e.message, "Format failed");
            }
        }

        // ── Word wrap toggle ──────────────────────────────────────────
        function toggleWrap() {
            wrapEnabled = !wrapEnabled;
            editor.session.setUseWrapMode(wrapEnabled);
        }

        function toggleEditorPreference(option) {
            const host = window.parent !== window ? window.parent : window;
            host.setEditorPreference(option, !editor.getOption(option));
        }

        function toggleInvisibles() {
            const host = window.parent !== window ? window.parent : window;
            host.setShowInvisibles(!editor.getOption('showInvisibles'));
        }

        // ── Copy all ──────────────────────────────────────────────────
        function copyAll() {
            navigator.clipboard.writeText(editor.getValue()).then(() => {
                window.workspaceToast('Copied to clipboard.', 'Copied');
            });
        }

        // ── Fullscreen ────────────────────────────────────────────────
        function toggleFullscreen() {
            if (!isFullscreen) {
                document.documentElement.requestFullscreen?.();
            } else {
                document.exitFullscreen?.();
            }
        }
        document.addEventListener('fullscreenchange', () => {
            isFullscreen = !!document.fullscreenElement;
        });

        // ── Keyboard shortcuts ────────────────────────────────────────
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                e.preventDefault();
                saveFile();
            }
            if (e.key === 'F11') {
                e.preventDefault();
                toggleFullscreen();
            }
            if (e.shiftKey && e.altKey && e.key === 'F') {
                e.preventDefault();
                formatCode();
            }
        });

        function renderGitDiff(diff) {
            const lines = document.createElement('div');
            lines.className = 'git-diff-lines';
            function appendRow(text, before = '', after = '', type = '') {
                const row = document.createElement('div'); row.className = 'git-diff-row' + (type ? ' ' + type : '');
                const gutter = document.createElement('span'); gutter.className = 'git-diff-gutter';
                for (const value of [before, after]) {
                    const number = document.createElement('span'); number.className = 'git-diff-number'; number.textContent = String(value); gutter.append(number);
                }
                const code = document.createElement('span'); code.className = 'git-diff-code'; code.textContent = text || ' ';
                row.append(gutter, code); lines.append(row);
            }
            appendRow('', 'HEAD', 'Current', 'git-diff-column-head');
            let before = 0, after = 0, inHunk = false;
            const rows = diff.split('\n');
            if (rows[rows.length - 1] === '') rows.pop();
            for (const line of rows) {
                const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
                if (hunk) { before = Number(hunk[1]); after = Number(hunk[2]); inHunk = true; appendRow(line, '', '', 'git-hunk'); }
                else if (inHunk && line.startsWith('+')) appendRow(line, '', after++, 'git-added');
                else if (inHunk && line.startsWith('-')) appendRow(line, before++, '', 'git-removed');
                else if (inHunk && line.startsWith(' ')) appendRow(line, before++, after++);
                else appendRow(line);
            }
            return lines;
        }

        async function showGitDiff() {
            const dialog = document.getElementById('git-diff-dialog');
            const output = document.getElementById('git-diff-output');
            const heading = document.getElementById('git-diff-heading');
            output.textContent = 'Loading Git comparison…';
            heading.textContent = 'Changes compared with HEAD';
            if (!dialog.open) dialog.showModal();
            try {
                const body = new FormData();
                body.append('action','git_diff');
                body.append('file', <?= json_encode($filename, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>);
                const editorValue = editor.getValue();
                const content = editorValue === savedEditorValue ? lastSavedContent : editorValue.replace(/\r\n|\r|\n/g, originalNewline);
                const bytes = new TextEncoder().encode(content);
                let binary = '';
                for (let i=0;i<bytes.length;i+=8192) binary += String.fromCharCode(...bytes.subarray(i,i+8192));
                body.append('content_base64',btoa(binary));
                const response = await fetch(window.location.pathname,{method:'POST',body});
                const data = await response.json();
                if (!response.ok || data.status !== 'success') throw new Error(data.message || 'Git comparison failed.');
                heading.textContent = data.untracked ? 'New file — compared with an empty document' : 'HEAD → current editor (including unsaved changes)';
                output.replaceChildren();
                if (!data.diff.trim()) output.textContent = 'No changes compared with HEAD.';
                else output.append(renderGitDiff(data.diff));
            } catch (error) { output.textContent = error.message; }
        }
        document.getElementById('git-diff-close').addEventListener('click', () => document.getElementById('git-diff-dialog').close());

        // ── Code minimap: a small, syntax-colored window into the document ──
        const minimap = document.getElementById('minimap');
        const mapCanvas = minimap.querySelector('canvas');
        const mapViewport = document.getElementById('minimap-viewport');
        const mapContext = mapCanvas.getContext('2d');
        const mapColors = new Map();
        const mapProbe = document.createElement('span');
        mapProbe.className = 'minimap-color-probe';
        editor.container.append(mapProbe);
        let mapStartRow = 0;
        let mapLineHeight = 2;
        let mapFrame = null;
        let mapDragging = false;

        function minimapColor(type) {
            if (!mapColors.has(type)) {
                mapProbe.className = 'minimap-color-probe ' + type.split('.').map(part => 'ace_' + part).join(' ');
                mapColors.set(type, getComputedStyle(mapProbe).color);
            }
            return mapColors.get(type);
        }

        function drawMinimap() {
            mapFrame = null;
            if (minimap.hidden || !minimap.clientHeight) return;
            const width = minimap.clientWidth;
            const height = minimap.clientHeight;
            const ratio = window.devicePixelRatio || 1;
            mapCanvas.width = Math.round(width * ratio);
            mapCanvas.height = Math.round(height * ratio);
            mapContext.setTransform(ratio, 0, 0, ratio, 0, 0);
            mapContext.fillStyle = getComputedStyle(editor.container).backgroundColor;
            // Dim underlying editor text independently from the miniature code.
            mapContext.globalAlpha = 0.88;
            mapContext.fillRect(0, 0, width, height);
            mapContext.globalAlpha = 0.5;
            const count = editor.session.getLength();
            const first = editor.getFirstVisibleRow();
            const last = Math.min(count - 1, editor.getLastVisibleRow());
            const visible = Math.max(1, last - first + 1);
            // Long files use a moving overview, keeping miniature lines legible.
            mapLineHeight = Math.min(2, height / visible);
            const capacity = Math.max(1, Math.floor(height / mapLineHeight));
            mapStartRow = Math.round(Math.min(1, first / Math.max(1, count - visible)) * Math.max(0, count - capacity));
            const charWidth = 0.85;
            const maxColumns = Math.floor((width - 8) / charWidth);
            for (let row = mapStartRow; row < Math.min(count, mapStartRow + capacity); row++) {
                let column = 0;
                for (const token of editor.session.getTokens(row)) {
                    mapContext.fillStyle = minimapColor(token.type);
                    for (const char of token.value) {
                        if (char === '\t') column += 4 - column % 4;
                        else {
                            if (!/\s/.test(char)) mapContext.fillRect(4 + column * charWidth, (row - mapStartRow) * mapLineHeight, 0.7, Math.max(0.6, mapLineHeight - 0.5));
                            column++;
                        }
                        if (column >= maxColumns) break;
                    }
                    if (column >= maxColumns) break;
                }
            }
            mapContext.globalAlpha = 1;
            const top = Math.max(0, (first - mapStartRow) * mapLineHeight);
            const viewportHeight = Math.min(height, Math.max(8, visible * mapLineHeight));
            mapViewport.style.top = Math.min(height - viewportHeight, top) + 'px';
            mapViewport.style.height = viewportHeight + 'px';
            minimap.setAttribute('aria-valuemax', String(count));
            minimap.setAttribute('aria-valuenow', String(first + 1));
            minimap.setAttribute('aria-valuetext', 'Lines ' + (first + 1) + '–' + (last + 1));
        }

        function scheduleMinimap() {
            if (mapFrame === null) mapFrame = requestAnimationFrame(drawMinimap);
        }
        function toggleMinimap() {
            minimap.hidden = !minimap.hidden;
            document.body.classList.toggle('minimap-hidden', minimap.hidden);
            localStorage.setItem(mobileEditorQuery.matches ? 'ke_minimap_mobile' : 'ke_minimap', String(!minimap.hidden));

            editor.resize();
            scheduleMinimap();
        }
        function navigateMinimap(event) {
            const rect = minimap.getBoundingClientRect();
            const row = Math.max(0, Math.min(editor.session.getLength() - 1,
                mapStartRow + Math.floor((event.clientY - rect.top) / mapLineHeight)));
            editor.scrollToLine(row, true, false);
            scheduleMinimap();
        }
        minimap.addEventListener('pointerdown', event => {
            if (event.button !== 0) return;
            event.preventDefault();
            mapDragging = true;
            minimap.setPointerCapture(event.pointerId);
            navigateMinimap(event);
        });
        minimap.addEventListener('pointermove', event => { if (mapDragging) navigateMinimap(event); });
        minimap.addEventListener('pointerup', () => { mapDragging = false; editor.focus(); });
        minimap.addEventListener('pointercancel', () => { mapDragging = false; });
        minimap.addEventListener('keydown', event => {
            const first = editor.getFirstVisibleRow();
            const page = Math.max(1, editor.getLastVisibleRow() - first);
            const rows = {ArrowDown: first + 1, ArrowUp: first - 1, PageDown: first + page, PageUp: first - page, Home: 0, End: editor.session.getLength() - 1};
            if (event.key in rows) {
                event.preventDefault();
                editor.scrollToRow(Math.max(0, rows[event.key]));
            }
        });
        editor.session.on('change', scheduleMinimap);
        editor.session.on('changeScrollTop', scheduleMinimap);
        editor.session.on('tokenizerUpdate', scheduleMinimap);
        editor.session.on('changeMode', () => { mapColors.clear(); scheduleMinimap(); });
        editor.renderer.on('afterRender', scheduleMinimap);
        editor.renderer.on('themeLoaded', () => { mapColors.clear(); scheduleMinimap(); });
        new ResizeObserver(scheduleMinimap).observe(document.getElementById('editor-wrap'));
        function applyResponsiveEditor() {
            const mobile = mobileEditorQuery.matches;
            const saved = localStorage.getItem(mobile ? 'ke_minimap_mobile' : 'ke_minimap');
            minimap.hidden = saved === 'false' || (mobile && saved !== 'true');
            document.body.classList.toggle('minimap-hidden', minimap.hidden);
            wrapEnabled = mobile;
            editor.session.setUseWrapMode(wrapEnabled);
            editor.resize();
            scheduleMinimap();
        }
        mobileEditorQuery.addEventListener('change', applyResponsiveEditor);
        applyResponsiveEditor();
        scheduleMinimap();

        // ── Whole-document overview of selected text occurrences ─────────
        function findSelectionOccurrences(lines, needle) {
            const matches = [];
            if (!needle || needle.length > 256 || /[\r\n]/.test(needle) || !needle.trim()) return matches;
            const wordCharacter = character => !!character && /[\p{L}\p{N}_$]/u.test(character);
            const wholeWord = [...needle].every(wordCharacter);
            lines.forEach((line, row) => {
                let column = line.indexOf(needle);
                while (column !== -1) {
                    const before = [...line.slice(Math.max(0, column - 2), column)].pop();
                    const after = [...line.slice(column + needle.length, column + needle.length + 2)][0];
                    if (!wholeWord || (!wordCharacter(before) && !wordCharacter(after))) {
                        matches.push({row, column});
                        break; // One marker per matching line.
                    }
                    column = line.indexOf(needle, column + needle.length);
                }
            });
            return matches;
        }
        const occurrenceRail = document.getElementById('occurrence-rail');
        const occurrenceCanvas = occurrenceRail.querySelector('canvas');
        const occurrenceContext = occurrenceCanvas.getContext('2d');
        let occurrenceMatches = [];
        let occurrenceText = '';
        let occurrenceTimer = null;
        let occurrenceFrame = null;

        function drawOccurrences() {
            occurrenceFrame = null;
            const height = occurrenceRail.clientHeight;
            if (!height) return;
            const width = occurrenceRail.clientWidth;
            const ratio = window.devicePixelRatio || 1;
            occurrenceCanvas.width = Math.round(width * ratio);
            occurrenceCanvas.height = Math.round(height * ratio);
            occurrenceContext.setTransform(ratio, 0, 0, ratio, 0, 0);
            const count = Math.max(1, editor.session.getLength());
            const first = editor.getFirstVisibleRow();
            const visible = Math.max(1, editor.getLastVisibleRow() - first + 1);
            const styles = getComputedStyle(document.documentElement);
            const color = styles.getPropertyValue('--accent').trim() || '#528bff';
            occurrenceContext.fillStyle = color;
            occurrenceContext.globalAlpha = 0.12;
            occurrenceContext.fillRect(0, first / count * height, width, Math.max(8, visible / count * height));
            occurrenceContext.globalAlpha = 0.8;
            occurrenceMatches.forEach(match => {
                const y = Math.min(height - 3, match.row / count * (height - 3));
                occurrenceContext.fillRect(2, y, width - 4, 3);
            });
            occurrenceContext.globalAlpha = 1;
            occurrenceRail.setAttribute('aria-valuemax', String(count));
            occurrenceRail.setAttribute('aria-valuenow', String(editor.getCursorPosition().row + 1));
            occurrenceRail.setAttribute('aria-valuetext', occurrenceMatches.length ? occurrenceMatches.length + ' matching lines for ' + occurrenceText : 'No selection matches');
        }
        function scheduleOccurrenceDraw() {
            if (occurrenceFrame === null) occurrenceFrame = requestAnimationFrame(drawOccurrences);
        }
        function updateOccurrences() {
            occurrenceText = editor.getSelectedText();
            occurrenceMatches = findSelectionOccurrences(editor.session.getDocument().getAllLines(), occurrenceText);
            occurrenceRail.title = occurrenceMatches.length ? occurrenceMatches.length + ' matching lines — click a marker to navigate' : 'Select a word to see its occurrences across the file';
            scheduleOccurrenceDraw();
        }
        function scheduleOccurrences() {
            clearTimeout(occurrenceTimer);
            occurrenceTimer = setTimeout(updateOccurrences, 120);
        }
        function revealOccurrence(match) {
            if (!match) return;
            const Range = ace.require('ace/range').Range;
            editor.selection.setSelectionRange(new Range(match.row, match.column, match.row, match.column + occurrenceText.length));
            editor.scrollToLine(match.row, true, false);
            editor.focus();
            scheduleOccurrenceDraw();
        }
        occurrenceRail.addEventListener('pointerdown', event => {
            if (event.button !== 0 || !occurrenceMatches.length) return;
            event.preventDefault();
            const rect = occurrenceRail.getBoundingClientRect();
            const row = (event.clientY - rect.top) / rect.height * editor.session.getLength();
            const nearest = occurrenceMatches.reduce((best, match) => Math.abs(match.row - row) < Math.abs(best.row - row) ? match : best);
            revealOccurrence(nearest);
        });
        occurrenceRail.addEventListener('keydown', event => {
            if (!occurrenceMatches.length || !['ArrowDown','ArrowUp','Home','End'].includes(event.key)) return;
            event.preventDefault();
            const row = editor.getCursorPosition().row;
            let match;
            if (event.key === 'Home') match = occurrenceMatches[0];
            else if (event.key === 'End') match = occurrenceMatches[occurrenceMatches.length - 1];
            else if (event.key === 'ArrowDown') match = occurrenceMatches.find(item => item.row > row) || occurrenceMatches[0];
            else match = [...occurrenceMatches].reverse().find(item => item.row < row) || occurrenceMatches[occurrenceMatches.length - 1];
            revealOccurrence(match);
        });
        editor.selection.on('changeSelection', scheduleOccurrences);
        editor.session.on('change', scheduleOccurrences);
        editor.session.on('changeScrollTop', scheduleOccurrenceDraw);
        editor.renderer.on('afterRender', scheduleOccurrenceDraw);
        new ResizeObserver(scheduleOccurrenceDraw).observe(occurrenceRail);
        scheduleOccurrenceDraw();

        // ── Warn before leaving with unsaved changes ──────────────────
        window.addEventListener('beforeunload', function(e) {
            if (hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Leave anyway?';
            }
        });
    </script>
</body>

</html>
<?php
    exit();
}


// Canonical containment, including destinations that do not exist yet.
function securityCheck($path)
{
    global $config;
    if (!is_string($path) || strpos($path, "\0") !== false || in_array('..', preg_split('~[/\\\\]+~', $path), true)) return false;
    $root = realpath($config['root_path']);
    if ($root === false) return false;
    $candidate = $path;
    while (!file_exists($candidate) && !is_link($candidate)) {
        $parent = dirname($candidate);
        if ($parent === $candidate) return false;
        $candidate = $parent;
    }
    $resolved = realpath($candidate);
    return $resolved !== false && ($resolved === $root || strpos($resolved, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0);
}

// Helper function to format file size
function formatSize($bytes)
{
    $units = ["bytes", "KB", "MB", "GB", "TB"];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 2) . " " . $units[$i];
}

// Use identical Seti icons in the listing, sidebar and tabs.
/* Material Icon Theme SVGs loaded from jsDelivr. Source: https://github.com/material-extensions/vscode-material-icon-theme
Revision: 13025adc5ad10a5cc649528a2c1edec93069f1b9
The MIT License (MIT)
Copyright (c) 2025 Material Extensions

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
$materialIconData = json_decode(<<<'MATERIAL_ICONS_JSON'
{"icons":{"php":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/php.svg","android":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/android.svg","git":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/git.svg","xml":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/xml.svg","json":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/json.svg","zip":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/zip.svg","favicon":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/favicon.svg","image":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/image.svg","document":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/document.svg","robots":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/robots.svg","html":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/html.svg","css":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/css.svg","javascript":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/javascript.svg","typescript":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/typescript.svg","python":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/python.svg","database":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/database.svg","console":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/console.svg","markdown":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/markdown.svg","pdf":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/pdf.svg","folder-base":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-base.svg","folder-template":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-template.svg","folder-upload":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-upload.svg","folder-packages":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-packages.svg","folder-config":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-config.svg","folder-images":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-images.svg","folder-backup":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-backup.svg","folder-public":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-public.svg","folder-database":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-database.svg","folder-src":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-src.svg","folder-test":"https://cdn.jsdelivr.net/gh/material-extensions/vscode-material-icon-theme@13025adc5ad10a5cc649528a2c1edec93069f1b9/icons/folder-test.svg"},"names":{".gitignore":"git",".gitattributes":"git",".gitmodules":"git",".htaccess":"xml",".whitesource":"json","composer.json":"json","composer.lock":"json","favicon.ico":"favicon","robots.txt":"robots"},"extensions":{"php":"php","php3":"php","php4":"php","php5":"php","php7":"php","php8":"php","phtml":"php","apk":"android","aab":"android","json":"json","jsonc":"json","json5":"json","zip":"zip","7z":"zip","rar":"zip","gz":"zip","tar":"zip","bz2":"zip","xz":"zip","png":"image","jpg":"image","jpeg":"image","gif":"image","webp":"image","svg":"image","bmp":"image","ico":"image","avif":"image","txt":"document","log":"document","html":"html","htm":"html","css":"css","scss":"css","sass":"css","less":"css","js":"javascript","mjs":"javascript","cjs":"javascript","ts":"typescript","tsx":"typescript","py":"python","pyw":"python","db":"database","sqlite":"database","sqlite3":"database","sql":"database","sh":"console","bash":"console","zsh":"console","bat":"console","cmd":"console","md":"markdown","markdown":"markdown","pdf":"pdf","xml":"xml"},"folders":{"template":"folder-template","templates":"folder-template","views":"folder-template","upload":"folder-upload","uploads":"folder-upload","vendor":"folder-packages","packages":"folder-packages","node_modules":"folder-packages","config":"folder-config","configs":"folder-config",".vscode":"folder-config",".github":"folder-config","images":"folder-images","img":"folder-images","pictures":"folder-images","icons":"folder-images","backup":"folder-backup","backups":"folder-backup","public":"folder-public","www":"folder-public","htdocs":"folder-public","database":"folder-database","databases":"folder-database","src":"folder-src","source":"folder-src","test":"folder-test","tests":"folder-test"}}
MATERIAL_ICONS_JSON
, true);

function materialIconSource($name, $directory = false)
{
    global $materialIconData;
    $name = strtolower(basename($name));
    $id = $directory ? ($materialIconData['folders'][$name] ?? 'folder-base') : ($materialIconData['names'][$name] ?? $materialIconData['extensions'][pathinfo($name, PATHINFO_EXTENSION)] ?? null);
    return $id === null ? null : $materialIconData['icons'][$id];
}

function getFileIcon($file)
{
    global $fileIconData;
    $materialSource = materialIconSource($file, is_dir($file));
    if ($materialSource !== null) return '<span class="file-type-icon" aria-hidden="true"><img src="' . $materialSource . '" alt="" width="20" height="20"></span>';
    if (is_dir($file)) return '<span class="file-type-icon folder-type-icon"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M2 5h8l2 2h10v13H2z"/></svg></span>';
    $name = strtolower(basename($file));
    $id = $fileIconData['names'][$name] ?? null;
    $lightId = $fileIconData['lightNames'][$name] ?? null;
    $parts = explode('.', $name);
    for ($i = 1; $i < count($parts); $i++) {
        $extension = implode('.', array_slice($parts, $i));
        if ($id === null && isset($fileIconData['extensions'][$extension])) {
            $id = $fileIconData['extensions'][$extension];
            $lightId = $fileIconData['lightExtensions'][$extension] ?? $id;
            break;
        }
    }
    $icon = $fileIconData['icons'][$id ?? $fileIconData['default']];
    $light = $fileIconData['icons'][$lightId ?? $id ?? $fileIconData['lightDefault']];
    return '<span class="file-type-icon" aria-hidden="true" style="--file-icon-color:' . $icon['color'] . ';--file-icon-light-color:' . $light['color'] . '">' . $icon['char'] . '</span>';
}

// Function to get file permissions as string
function getPermissions($file)
{
    $perms = fileperms($file);

    if (($perms & 0xc000) == 0xc000) {
        $info = "s";
    } elseif (($perms & 0xa000) == 0xa000) {
        $info = "l";
    } elseif (($perms & 0x8000) == 0x8000) {
        $info = "-";
    } elseif (($perms & 0x6000) == 0x6000) {
        $info = "b";
    } elseif (($perms & 0x4000) == 0x4000) {
        $info = "d";
    } elseif (($perms & 0x2000) == 0x2000) {
        $info = "c";
    } elseif (($perms & 0x1000) == 0x1000) {
        $info = "p";
    } else {
        $info = "u";
    }

    $info .= $perms & 0x0100 ? "r" : "-";
    $info .= $perms & 0x0080 ? "w" : "-";
    $info .= $perms & 0x0040 ? ($perms & 0x0800 ? "s" : "x") : ($perms & 0x0800 ? "S" : "-");
    $info .= $perms & 0x0020 ? "r" : "-";
    $info .= $perms & 0x0010 ? "w" : "-";
    $info .= $perms & 0x0008 ? ($perms & 0x0400 ? "s" : "x") : ($perms & 0x0400 ? "S" : "-");
    $info .= $perms & 0x0004 ? "r" : "-";
    $info .= $perms & 0x0002 ? "w" : "-";
    $info .= $perms & 0x0001 ? ($perms & 0x0200 ? "t" : "x") : ($perms & 0x0200 ? "T" : "-");

    return $info;
}

// Load one level of the explorer; folders are expanded on demand.
function buildDirectoryTree($dir, $relativePath = "")
{
    global $config;
    $root = realpath($config["root_path"]);
    $result = [];
    foreach (scandir($dir) as $name) {
        if ($name === "." || $name === "..") continue;
        $fullPath = $dir . DIRECTORY_SEPARATOR . $name;
        $realPath = realpath($fullPath);
        if ($realPath === false || ($realPath !== $root && strpos($realPath, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) !== 0)) continue;
        $result[] = [
            "name" => $name,
            "type" => is_dir($fullPath) ? "dir" : "file",
            "path" => "/" . ltrim($relativePath . "/" . $name, "/"),
        ];
    }
    usort($result, function ($a, $b) {
        if ($a["type"] !== $b["type"]) return $a["type"] === "dir" ? -1 : 1;
        return strnatcasecmp($a["name"], $b["name"]);
    });
    return $result;
}

// Resolve repeated UID/GID values once per request; POSIX names are optional.
function getFileOwnership($file)
{
    static $users = [], $groups = [];
    $uid = @fileowner($file); $gid = @filegroup($file);
    if ($uid !== false && !array_key_exists($uid, $users)) {
        $record = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
        $users[$uid] = $record && isset($record['name']) ? $record['name'] : (string) $uid;
    }
    if ($gid !== false && !array_key_exists($gid, $groups)) {
        $record = function_exists('posix_getgrgid') ? @posix_getgrgid($gid) : false;
        $groups[$gid] = $record && isset($record['name']) ? $record['name'] : (string) $gid;
    }
    return ['owner' => $uid === false ? '—' : $users[$uid], 'group' => $gid === false ? '—' : $groups[$gid],
        'uid' => $uid === false ? null : $uid, 'gid' => $gid === false ? null : $gid];
}

// Function to get directory contents
function getDirectoryContents($dir, $sort = "name", $order = "asc")
{
    $result = [];
    $cdir = scandir($dir);

    foreach ($cdir as $key => $value) {
        if (!in_array($value, [".", ".."])) {
            $fullPath = $dir . DIRECTORY_SEPARATOR . $value;

            $fileInfo = [
                "name" => $value,
                "type" => is_dir($fullPath) ? "dir" : "file",
                "size" => is_dir($fullPath) ? "" : formatSize(filesize($fullPath)),
                "size_raw" => is_dir($fullPath) ? 0 : filesize($fullPath),
                "extension" => is_dir($fullPath) ? "" : pathinfo($value, PATHINFO_EXTENSION),
                "date_added" => date($GLOBALS["config"]["date_format"], filectime($fullPath)),
                "last_modified" => date($GLOBALS["config"]["date_format"], filemtime($fullPath)),
                "permissions" => getPermissions($fullPath),
                "permissions_octal" => decoct(fileperms($fullPath) & 07777),
                "icon" => getFileIcon($fullPath),
            ];

            $fileInfo = array_merge($fileInfo, getFileOwnership($fullPath));
            $result[] = $fileInfo;
        }
    }

    usort($result, function ($a, $b) use ($sort, $order) {
        if ($a["type"] != $b["type"]) {
            return $a["type"] == "dir" ? -1 : 1;
        }
        $valA = $a[$sort];
        $valB = $b[$sort];
        if ($sort == "size") {
            $valA = $a["size_raw"];
            $valB = $b["size_raw"];
        }
        if ($order == "asc") {
            return $valA <=> $valB;
        } else {
            return $valB <=> $valA;
        }
    });

    return $result;
}

function createDirectory($path, $name)
{
    $dirPath = $path . DIRECTORY_SEPARATOR . $name;
    if (!file_exists($dirPath)) {
        if (mkdir($dirPath, 0755)) {
            return ["status" => "success", "message" => "Directory created successfully"];
        } else {
            return ["status" => "error", "message" => "Failed to create directory"];
        }
    } else {
        return ["status" => "error", "message" => "Directory already exists"];
    }
}

function createFile($path, $name, $content = "")
{
    $filePath = $path . DIRECTORY_SEPARATOR . $name;
    if (!file_exists($filePath)) {
        if (file_put_contents($filePath, $content) !== false) {
            return ["status" => "success", "message" => "File created successfully"];
        } else {
            return ["status" => "error", "message" => "Failed to create file"];
        }
    } else {
        return ["status" => "error", "message" => "File already exists"];
    }
}

function updateSettings($timezone, $dateFormat, $fontSize)
{
    global $config;
    if ($timezone === '' && $dateFormat === '' && $fontSize === '') return ['status' => 'error', 'message' => 'No changes made'];
    try {
        $data = fmValidateWorkspaceSettings([
            'timezone' => $timezone === '' ? $config['timezone'] : $timezone,
            'date_format' => $dateFormat === '' ? $config['date_format'] : $dateFormat,
            'font_size' => $fontSize === '' ? $config['font_size'] : $fontSize,
        ]);
        fmRewriteConfiguration(function ($source) use ($data) {
            if (preg_match('/^\$workspaceSettingsBase64 = \'([A-Za-z0-9+\/=]*)\';$/m', $source, $match)) {
                $previous = json_decode(base64_decode($match[1]), true);
                if (isset($previous['root_path'])) $data['root_path'] = $previous['root_path'];
            }
            $encoded = base64_encode(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
            $pattern = '/^\$workspaceSettingsBase64 = \'[A-Za-z0-9+\/=]*\';$/m';
            if (preg_match_all($pattern, $source) !== 1) throw new RuntimeException('Settings configuration changed. Reload and try again.');
            return preg_replace_callback($pattern, function () use ($encoded) { return '$workspaceSettingsBase64 = ' . var_export($encoded, true) . ';'; }, $source, 1);
        });
        return ['status' => 'success', 'message' => 'Settings saved in filemanager.php', 'type' => 'confirm'];
    } catch (Throwable $error) {
        return ['status' => 'error', 'message' => $error->getMessage()];
    }
}

function renameItem($path, $oldName, $newName)
{
    $oldPath = $path . DIRECTORY_SEPARATOR . $oldName;
    $newPath = $path . DIRECTORY_SEPARATOR . $newName;
    if (file_exists($oldPath) && !file_exists($newPath)) {
        if (rename($oldPath, $newPath)) {
            return ["status" => "success", "message" => "Item renamed successfully"];
        } else {
            return ["status" => "error", "message" => "Failed to rename item"];
        }
    } else {
        return ["status" => "error", "message" => "Source does not exist or destination already exists"];
    }
}

function deleteItem($path)
{
    if (is_link($path) || !is_dir($path)) return @unlink($path);
    $files = @scandir($path);
    if ($files === false) return false;
    $success = true;
    foreach (array_diff($files, ['.', '..']) as $file) {
        if (!deleteItem($path . DIRECTORY_SEPARATOR . $file)) $success = false;
    }
    return $success && @rmdir($path);
}

function copyItem($source, $destination)
{
    if (is_dir($source)) {
        if (!file_exists($destination)) {
            mkdir($destination, 0755);
        }
        $files = array_diff(scandir($source), [".", ".."]);
        foreach ($files as $file) {
            copyItem($source . DIRECTORY_SEPARATOR . $file, $destination . DIRECTORY_SEPARATOR . $file);
        }
        return ["status" => "success", "message" => "Directory copied successfully"];
    } else {
        if (copy($source, $destination)) {
            return ["status" => "success", "message" => "File copied successfully"];
        } else {
            return ["status" => "error", "message" => "Failed to copy file"];
        }
    }
}

function changePermissions($path, $mode)
{
    if (chmod($path, octdec($mode))) {
        return ["status" => "success", "message" => "Permissions changed successfully"];
    } else {
        return ["status" => "error", "message" => "Failed to change permissions"];
    }
}

function compressItems($items, $destination, $type = "zip")
{
    global $config;

    if (count($items) < 1) {
        return ["status" => "error", "message" => "No selected items to compress"];
    }

    switch ($type) {
        case "empty_trash":
            $trashDir = $config["root_path"] . "/.trash";
            if (!is_dir($trashDir)) {
                $response = ["status" => "error", "message" => "Trash directory not found"];
                break;
            }
            $items = scandir($trashDir);
            $deleted = 0;
            foreach ($items as $item) {
                if ($item !== "." && $item !== "..") {
                    $path = $trashDir . "/" . $item;
                    if (is_file($path) || is_link($path)) {
                        if (@unlink($path)) $deleted++;
                    } elseif (is_dir($path)) {
                        $cmd = "rm -rf " . escapeshellarg($path);
                        @exec($cmd, $out, $code);
                        if ($code === 0) $deleted++;
                    }
                }
            }
            $response = ["status" => "success", "message" => "Trash emptied ($deleted item(s) deleted)"];
            break;
        case "zip":
            $zip = new ZipArchive();
            if ($zip->open($destination, ZipArchive::CREATE) === true) {
                foreach ($items as $item) {
                    if (is_dir($item)) {
                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($item), RecursiveIteratorIterator::LEAVES_ONLY);
                        foreach ($files as $file) {
                            if (!$file->isDir()) {
                                $filePath = $file->getRealPath();
                                $relativePath = substr($filePath, strlen(dirname($item)) + 1);
                                $zip->addFile($filePath, $relativePath);
                            }
                        }
                    } else {
                        $zip->addFile($item, basename($item));
                    }
                }
                $zip->close();
                return ["status" => "success", "message" => "Files compressed successfully (ZIP)"];
            } else {
                return ["status" => "error", "message" => "Failed to create ZIP archive"];
            }
            break;
        case "tar":
            $phar = new PharData($destination);
            foreach ($items as $item) {
                $phar->addFile($item, basename($item));
            }
            return ["status" => "success", "message" => "Files compressed successfully (TAR)"];
            break;
        case "gzip":
            if (count($items) > 1) {
                return ["status" => "error", "message" => "GZip can only compress one file at a time"];
            }
            $content = file_get_contents($items[0]);
            $gzContent = gzencode($content, 9);
            file_put_contents($destination, $gzContent);
            return ["status" => "success", "message" => "File compressed successfully (GZip)"];
            break;
        default:
            return ["status" => "error", "message" => "Unknown compression type"];
    }
}

// Remove only recognized sidecars whose corresponding trash item no longer exists.
function fmCleanupTrashMetadata($config)
{
    $root = realpath($config['root_path']);
    $trash = $root . '/.trash';
    if (!$root || is_link($trash) || !is_dir($trash)) return 0;
    $entries = @scandir($trash);
    if ($entries === false) return 1;
    $failed = 0;
    foreach ($entries as $name) {
        if (substr($name, -10) !== '.trashinfo') continue;
        $metadataPath = $trash . '/' . $name;
        $itemPath = substr($metadataPath, 0, -10);
        clearstatcache(true, $itemPath);
        if (file_exists($itemPath) || is_link($itemPath) || is_link($metadataPath) || !is_file($metadataPath)) continue;
        $json = @file_get_contents($metadataPath, false, null, 0, 65537);
        if (!is_string($json) || strlen($json) > 65536) continue;
        $metadata = json_decode($json, true);
        if (!is_array($metadata) || !is_string($metadata['original_path'] ?? null) || !is_string($metadata['original_name'] ?? null) || !is_string($metadata['deletion_date'] ?? null)) continue;
        if (!@unlink($metadataPath)) $failed++;
    }
    return $failed;
}

function moveToTrash($source, $currentPath, $config)
{
    $trashDir = $config["root_path"] . "/.trash";
    if (!file_exists($trashDir)) {
        mkdir($trashDir, 0755, true);
    }
    $itemName = basename($source);
    $destinationPath = $trashDir . "/" . $itemName;
    $counter = 1;
    $originalName = pathinfo($itemName, PATHINFO_FILENAME);
    $extension = pathinfo($itemName, PATHINFO_EXTENSION);
    while (file_exists($destinationPath)) {
        if ($extension) {
            $destinationPath = $trashDir . "/" . $originalName . " (" . $counter . ")." . $extension;
        } else {
            $destinationPath = $trashDir . "/" . $originalName . " (" . $counter . ")";
        }
        $counter++;
    }
    if (rename($source, $destinationPath)) {
        $metaFilename = $destinationPath . ".trashinfo";
        $metadata = [
            "original_path" => str_replace($config["root_path"], "", $currentPath) . "/" . $itemName,
            "deletion_date" => date("Y-m-d H:i:s"),
            "original_name" => $itemName,
        ];
        file_put_contents($metaFilename, json_encode($metadata, JSON_PRETTY_PRINT));
        return true;
    }
    return false;
}

function restoreFromTrash($source, $config)
{
    $metaFilename = $source . ".trashinfo";
    if (!file_exists($metaFilename)) {
        return ["status" => "error", "message" => "Trash metadata not found"];
    }
    $metadata = json_decode(file_get_contents($metaFilename), true);
    if (!$metadata || !isset($metadata["original_path"])) {
        return ["status" => "error", "message" => "Invalid trash metadata"];
    }
    $destPath = $config["root_path"] . $metadata["original_path"];
    $destDir = dirname($destPath);
    if (!file_exists($destDir)) {
        if (!mkdir($destDir, 0755, true)) {
            return ["status" => "error", "message" => "Failed to create destination directory"];
        }
    }
    if (file_exists($destPath)) {
        $originalName = pathinfo($destPath, PATHINFO_FILENAME);
        $extension = pathinfo($destPath, PATHINFO_EXTENSION);
        $counter = 1;
        $newDestPath = $destPath;
        while (file_exists($newDestPath)) {
            if ($extension) {
                $newDestPath = $destDir . "/" . $originalName . " (restored " . $counter . ")." . $extension;
            } else {
                $newDestPath = $destDir . "/" . $originalName . " (restored " . $counter . ")";
            }
            $counter++;
        }
        $destPath = $newDestPath;
    }
    if (rename($source, $destPath)) {
        if (file_exists($metaFilename)) {
            unlink($metaFilename);
        }
        return ["status" => "success", "message" => "Item restored successfully"];
    }
    return ["status" => "error", "message" => "Failed to restore item"];
}

function extractArchive($source, $destination, $config)
{
    if (!file_exists($destination)) {
        if (!mkdir($destination, 0755, true)) {
            return ["status" => "error", "message" => "Failed to create destination directory"];
        }
    }
    $extension = strtolower(pathinfo($source, PATHINFO_EXTENSION));
    switch ($extension) {
        case "zip":
            return extractZip($source, $destination);
        case "tar":
            return extractTar($source, $destination);
        case "gz":
        case "gzip":
            return extractGzip($source, $destination);
        case "bz2":
        case "bzip2":
            return extractBzip2($source, $destination);
        case "rar":
            return extractRar($source, $destination);
        case "7z":
            return extract7Zip($source, $destination);
        default:
            return ["status" => "error", "message" => "Unsupported archive type: " . $extension];
    }
}

function extractZip($source, $destination)
{
    $zip = new ZipArchive();
    $res = $zip->open($source);
    if ($res === true) {
        $zip->extractTo($destination);
        $zip->close();
        return ["status" => "success", "message" => "ZIP archive extracted successfully"];
    } else {
        return ["status" => "error", "message" => "Failed to open ZIP archive (Error code: " . $res . ")"];
    }
}

function extractTar($source, $destination)
{
    try {
        $phar = new PharData($source);
        $phar->extractTo($destination, null, true);
        return ["status" => "success", "message" => "TAR archive extracted successfully"];
    } catch (Exception $e) {
        return ["status" => "error", "message" => "Failed to extract TAR archive: " . $e->getMessage()];
    }
}

function extractGzip($source, $destination)
{
    $basename = basename($source, ".gz");
    if (substr($basename, -4) === ".tar") {
        try {
            $phar = new PharData($source);
            $phar->extractTo($destination, null, true);
            return ["status" => "success", "message" => "TAR.GZ archive extracted successfully"];
        } catch (Exception $e) {
            return ["status" => "error", "message" => "Failed to extract TAR.GZ archive: " . $e->getMessage()];
        }
    } else {
        $destFile = $destination . DIRECTORY_SEPARATOR . $basename;
        $sfp = gzopen($source, "rb");
        $fp = fopen($destFile, "wb");
        if (!$sfp || !$fp) {
            return ["status" => "error", "message" => "Failed to open files for extraction"];
        }
        while (!gzeof($sfp)) {
            fwrite($fp, gzread($sfp, 4096));
        }
        gzclose($sfp);
        fclose($fp);
        return ["status" => "success", "message" => "GZIP file extracted successfully"];
    }
}

function extractBzip2($source, $destination)
{
    $basename = basename($source, ".bz2");
    if (substr($basename, -4) === ".tar") {
        try {
            $phar = new PharData($source);
            $phar->extractTo($destination, null, true);
            return ["status" => "success", "message" => "TAR.BZ2 archive extracted successfully"];
        } catch (Exception $e) {
            return ["status" => "error", "message" => "Failed to extract TAR.BZ2 archive: " . $e->getMessage()];
        }
    } else {
        $destFile = $destination . DIRECTORY_SEPARATOR . $basename;
        $sfp = bzopen($source, "r");
        $fp = fopen($destFile, "w");
        if (!$sfp || !$fp) {
            return ["status" => "error", "message" => "Failed to open files for extraction"];
        }
        while (!feof($sfp)) {
            fwrite($fp, bzread($sfp, 4096));
        }
        bzclose($sfp);
        fclose($fp);
        return ["status" => "success", "message" => "BZIP2 file extracted successfully"];
    }
}

function extractRar($source, $destination)
{
    if (class_exists("RarArchive")) {
        $rar = RarArchive::open($source);
        if ($rar === false) {
            return ["status" => "error", "message" => "Failed to open RAR archive"];
        }
        $entries = $rar->getEntries();
        foreach ($entries as $entry) {
            $entry->extract($destination);
        }
        $rar->close();
        return ["status" => "success", "message" => "RAR archive extracted successfully"];
    } elseif (function_exists("exec")) {
        $command = "unrar x -o+ " . escapeshellarg($source) . " " . escapeshellarg($destination);
        $output = [];
        $returnVar = 0;
        exec($command, $output, $returnVar);
        if ($returnVar === 0) {
            return ["status" => "success", "message" => "RAR archive extracted successfully using unrar command"];
        } else {
            return ["status" => "error", "message" => "Failed to extract RAR archive using unrar command"];
        }
    } else {
        return ["status" => "error", "message" => "RAR extraction not supported - PHP RAR extension or exec() function required"];
    }
}

function extract7Zip($source, $destination)
{
    if (function_exists("exec")) {
        $command = "7z x " . escapeshellarg($source) . " -o" . escapeshellarg($destination) . " -y";
        $output = [];
        $returnVar = 0;
        exec($command, $output, $returnVar);
        if ($returnVar === 0) {
            return ["status" => "success", "message" => "7Zip archive extracted successfully"];
        } else {
            return ["status" => "error", "message" => "Failed to extract 7Zip archive: " . implode("\n", $output)];
        }
    } else {
        return ["status" => "error", "message" => "7Zip extraction not supported - exec() function required"];
    }
}

// Handle File Manager Operations
// Names are single path components, never user-controlled traversal paths.
foreach (['name', 'old_name', 'new_name', 'item', 'file'] as $field) {
    $value = $_POST[$field] ?? $_GET[$field] ?? null;
    if ($value !== null && (!is_string($value) || $value === '.' || $value === '..' || strpbrk($value, "/\\\0") !== false)) fmAuthReply(400, 'Invalid file name.');
}
if (isset($_POST['items'])) {
    if (!is_string($_POST['items'])) fmAuthReply(400, 'Invalid file selection.');
    foreach (explode(',', $_POST['items']) as $item) {
        if ($item === '.' || $item === '..' || strpbrk($item, "/\\\0") !== false) fmAuthReply(400, 'Invalid file selection.');
    }
}
if (isset($_POST["action"]) || isset($_GET["action"])) {
    $action = isset($_POST["action"]) ? $_POST["action"] : $_GET["action"];
    $response = ["status" => "error", "message" => "Unknown action"];

    $currentPath = isset($_POST["path"]) ? $config["root_path"] . $_POST["path"] : $config["root_path"];
    if (isset($_GET["path"])) {
        $currentPath = $config["root_path"] . $_GET["path"];
    }

    if (!securityCheck($currentPath)) {
        http_response_code(403);
        $response = ["status" => "error", "message" => "Security violation"];
    } else {
        foreach (['name', 'old_name', 'new_name', 'item', 'file'] as $field) {
            $targetName = $_POST[$field] ?? $_GET[$field] ?? '';
            if ($targetName !== '' && !securityCheck($currentPath . DIRECTORY_SEPARATOR . $targetName)) fmAuthReply(403, 'File is outside the configured root.');
        }
        foreach (explode(',', $_POST['items'] ?? '') as $item) {
            if ($item !== '' && !securityCheck($currentPath . DIRECTORY_SEPARATOR . $item)) fmAuthReply(403, 'Selected file is outside the configured root.');
        }
        switch ($action) {
            case "settings":
                $tmz = isset($_POST["timezone"]) ? $_POST["timezone"] : "";
                $dt = isset($_POST["dateformat"]) ? $_POST["dateformat"] : "";
                $font = isset($_POST["fontSize"]) ? $_POST["fontSize"] : "";
                $response = updateSettings($tmz, $dt, $font);
                break;
            case "list":
                if ($isPostRequest && !is_link($config['root_path'].'/.trash') && realpath($currentPath) === realpath($config['root_path'].'/.trash') && fmCleanupTrashMetadata($config)) fmAuthReply(500, 'Cannot remove orphaned trash metadata. Check trash folder permissions.');
                $sort = isset($_POST["sort"]) ? $_POST["sort"] : (isset($_GET["sort"]) ? $_GET["sort"] : "name");
                $order = isset($_POST["order"]) ? $_POST["order"] : (isset($_GET["order"]) ? $_GET["order"] : "asc");
                $response = [
                    "status" => "success",
                    "data" => getDirectoryContents($currentPath, $sort, $order),
                    "current_path" => str_replace($config["root_path"], "", $currentPath),
                ];
                break;
            case "upload_check":
                try {
                    $entries = json_decode($_POST['files'] ?? '', true);
                    if (!is_array($entries) || !$entries || count($entries) > (int) ini_get('max_file_uploads')) throw new RuntimeException('Select fewer files. Server limit: ' . ini_get('max_file_uploads') . ' files per upload.');
                    $resolved = realpath($currentPath);
                    if (!$resolved || !is_dir($resolved) || !is_writable($resolved)) throw new RuntimeException('Destination folder is not writable.');
                    $checks = []; $total = 0;
                    foreach ($entries as $entry) {
                        if (!is_array($entry) || !isset($entry['name'], $entry['size']) || !is_int($entry['size']) || $entry['size'] < 0) throw new RuntimeException('Invalid upload request.');
                        $target = fmUploadTarget($resolved, $entry['name']);
                        if (array_key_exists($entry['name'], $checks)) throw new RuntimeException('Duplicate file names in this upload.');
                        $limit = parseSize(ini_get('upload_max_filesize'));
                        if ($limit > 0 && $entry['size'] > $limit) throw new RuntimeException($entry['name'] . ': exceeds the server upload size limit.');
                        $hash = file_exists($target) ? @hash_file('sha256', $target) : null;
                        if ($hash === false) throw new RuntimeException($entry['name'] . ': cannot read the existing file.');
                        $checks[$entry['name']] = $hash; $total += $entry['size'] + 1024;
                    }
                    $postLimit = parseSize(ini_get('post_max_size'));
                    if ($postLimit > 0 && $total > $postLimit) throw new RuntimeException('Upload exceeds the server request size limit. Select fewer or smaller files.');
                    $response = ['status' => 'success', 'files' => (object) $checks];
                } catch (Throwable $error) { http_response_code(400); $response = ['status' => 'error', 'message' => $error->getMessage()]; }
                break;
            case "tree":
                $resolvedTreePath = realpath($currentPath);
                $resolvedRoot = realpath($config["root_path"]);
                if ($resolvedTreePath === false || !is_dir($resolvedTreePath) || ($resolvedTreePath !== $resolvedRoot && strpos($resolvedTreePath, rtrim($resolvedRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) !== 0)) {
                    $response = ["status" => "error", "message" => "Invalid directory"];
                } else {
                    $relativeTreePath = substr($resolvedTreePath, strlen($resolvedRoot));
                    $response = ["status" => "success", "data" => buildDirectoryTree($resolvedTreePath, $relativeTreePath)];
                }
                break;
            case "create_dir":
                $name = isset($_POST["name"]) ? $_POST["name"] : "";
                $response = createDirectory($currentPath, $name);
                break;
            case "create_file":
                $name = isset($_POST["name"]) ? $_POST["name"] : "";
                $content = isset($_POST["content"]) ? $_POST["content"] : "";
                $response = createFile($currentPath, $name, $content);
                break;
            case "rename":
                $oldName = isset($_POST["old_name"]) ? $_POST["old_name"] : "";
                $newName = isset($_POST["new_name"]) ? $_POST["new_name"] : "";
                $response = renameItem($currentPath, $oldName, $newName);
                break;
            case "trash":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $items = explode(",", $itemsArray);
                $status = true;
                $movedCount = 0;
                $failedCount = 0;
                if ($itemsArray == "") {
                    $response = ["status" => "error", "message" => "No items selected"];
                    break;
                }
                foreach ($items as $item) {
                    $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                    if (!file_exists($itemPath)) {
                        continue;
                    }
                    if (moveToTrash($itemPath, $currentPath, $config)) {
                        $movedCount++;
                    } else {
                        $failedCount++;
                        $status = false;
                    }
                }
                $response = ["status" => $status ? "success" : "error", "message" => "Moved $movedCount item(s) to trash" . ($failedCount > 0 ? ", Failed $failedCount item(s)" : "")];
                break;
            case "delete":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $status = true;
                $movedCount = 0;
                $failedCount = 0;
                $items = explode(",", $itemsArray);
                if ($itemsArray == "") {
                    $response = ["status" => "error", "message" => "No items selected"];
                    break;
                }
                foreach ($items as $item) {
                    $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                    if (!file_exists($itemPath)) {
                        continue;
                    }
                    if (deleteItem($itemPath)) {
                        $movedCount++;
                    } else {
                        $failedCount++;
                        $status = false;
                    }
                }
                $response = ["status" => $status ? "success" : "error", "message" => "Deleted $movedCount item(s) successfully" . ($failedCount > 0 ? ", $failedCount item(s) Failed to delete" : "")];
                if (fmCleanupTrashMetadata($config)) $response = ['status'=>'error','message'=>"Deleted $movedCount item(s), but some orphaned trash metadata could not be removed. Check trash folder permissions."];
                break;
            case "restore":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $items = explode(",", $itemsArray);
                if ($itemsArray == "") {
                    $response = ["status" => "error", "message" => "No items selected"];
                    break;
                }
                $status = true;
                $restoredCount = 0;
                $failedCount = 0;
                $messages = [];
                foreach ($items as $item) {
                    $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                    $result = restoreFromTrash($itemPath, $config);
                    if ($result["status"] === "success") {
                        $restoredCount++;
                        $messages[] = "$item restored successfully";
                    } else {
                        $failedCount++;
                        $status = false;
                        $messages[] = "Failed to restore $item: " . $result["message"];
                    }
                }
                $response = ["status" => $status ? "success" : "error", "message" => "Restored $restoredCount item(s)" . ($failedCount > 0 ? ", Failed $failedCount item(s)" : "")];
                break;
            case "copy":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $items = explode(",", $itemsArray);
                if ($itemsArray == "") {
                    $response = ["status" => "error", "message" => "No items selected"];
                    break;
                }
                $destination = isset($_POST["destination"]) ? $config["root_path"] . $_POST["destination"] : "";
                if (!securityCheck($destination)) {
                    $response = ["status" => "error", "message" => "Security violation on destination"];
                    break;
                }
                $status = true;
                $messages = [];
                foreach ($items as $item) {
                    $sourcePath = $currentPath . DIRECTORY_SEPARATOR . $item;
                    $destPath = $destination . DIRECTORY_SEPARATOR . $item;
                    $result = copyItem($sourcePath, $destPath);
                    if ($result["status"] != "success") {
                        $status = false;
                    }
                    $messages[] = $result["message"];
                }
                $response = ["status" => $status ? "success" : "error", "message" => implode(", ", $messages)];
                break;
            case "move":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $items = explode(",", $itemsArray);
                if ($itemsArray == "") {
                    $response = ["status" => "error", "message" => "No items selected"];
                    break;
                }
                $destination = isset($_POST["destination"]) ? $config["root_path"] . $_POST["destination"] : "";
                if (!securityCheck($destination)) {
                    $response = ["status" => "error", "message" => "Security violation on destination"];
                    break;
                }
                $status = true;
                $messages = [];
                foreach ($items as $item) {
                    $sourcePath = $currentPath . DIRECTORY_SEPARATOR . $item;
                    $destPath = $destination . DIRECTORY_SEPARATOR . $item;
                    if (!file_exists($destPath)) {
                        if (rename($sourcePath, $destPath)) {
                            $messages[] = "Moved $item successfully";
                        } else {
                            $status = false;
                            $messages[] = "Failed to move $item";
                        }
                    } else {
                        $status = false;
                        $messages[] = "$item already exists in destination";
                    }
                }
                $response = ["status" => $status ? "success" : "error", "message" => implode(", ", $messages)];
                break;
            case "permissions":
                $item = isset($_POST["item"]) ? $_POST["item"] : "";
                $mode = isset($_POST["mode"]) ? $_POST["mode"] : "0644";
                $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                $response = changePermissions($itemPath, $mode);
                break;
            case "compress":
                $itemsArray = isset($_POST["items"]) ? $_POST["items"] : "";
                $type = isset($_POST["type"]) ? $_POST["type"] : "zip";
                $name = isset($_POST["name"]) ? $_POST["name"] : "archive_" . time();
                $items = explode(",", $itemsArray);
                $itemPaths = [];
                foreach ($items as $item) {
                    $itemPaths[] = $currentPath . DIRECTORY_SEPARATOR . $item;
                }
                $extension = "";
                switch ($type) {
                    case "zip":
                        $extension = ".zip";
                        break;
                    case "tar":
                        $extension = ".tar";
                        break;
                    case "gzip":
                        $extension = ".gz";
                        break;
                }
                $destination = $currentPath . DIRECTORY_SEPARATOR . $name . $extension;
                $response = compressItems($itemPaths, $destination, $type);
                break;
            case "read_file":
                $item = isset($_POST["item"]) ? $_POST["item"] : "";
                $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                if (file_exists($itemPath) && is_file($itemPath)) {
                    $content = file_get_contents($itemPath);
                    $response = ["status" => "success", "data" => ["content" => $content, "editable" => true]];
                } else {
                    $response = ["status" => "error", "message" => "File not found"];
                }
                break;
            case "save_file":
                $item = isset($_POST["item"]) ? $_POST["item"] : "";
                $content = isset($_POST["content"]) ? $_POST["content"] : "";
                $itemPath = $currentPath . DIRECTORY_SEPARATOR . $item;
                if (file_exists($itemPath) && is_file($itemPath)) {
                    if (file_put_contents($itemPath, $content) !== false) {
                        $response = ["status" => "success", "message" => "File saved successfully"];
                    } else {
                        $response = ["status" => "error", "message" => "Failed to save file"];
                    }
                } else {
                    $response = ["status" => "error", "message" => "File not found"];
                }
                break;
            case "search":
                $query = isset($_POST["query"]) ? $_POST["query"] : "";
                $path = isset($_POST["path"]) ? $config["root_path"] . $_POST["path"] : $config["root_path"];
                if (!securityCheck($path)) {
                    $response = ["status" => "error", "message" => "Security violation"];
                    break;
                }
                $results = [];
                if (!empty($query)) {
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($iterator as $file) {
                        if (stripos($file->getFilename(), $query) !== false) {
                            $relativePath = str_replace($config["root_path"], "", $file->getPathname());
                            $results[] = ["name" => $file->getFilename(), "path" => $relativePath, "type" => $file->isDir() ? "dir" : "file", "size" => $file->isDir() ? "" : formatSize($file->getSize()), "last_modified" => date($config["date_format"], $file->getMTime()), "icon" => getFileIcon($file->getPathname())];
                        }
                    }
                }
                $response = ["status" => "success", "data" => $results];
                break;
            case "extract":
                $file = isset($_POST["file"]) ? $_POST["file"] : "";
                $destination = isset($_POST["destination"]) ? $_POST["destination"] : "";
                if (empty($file)) {
                    $response = ["status" => "error", "message" => "No file specified for extraction"];
                    break;
                }
                $filePath = $currentPath . DIRECTORY_SEPARATOR . $file;
                if (empty($destination)) {
                    $fileInfo = pathinfo($file);
                    $destination = $currentPath . DIRECTORY_SEPARATOR . $fileInfo["filename"];
                } else {
                    $destination = $config["root_path"] . $destination;
                }
                if (!file_exists($destination)) {
                    if (!mkdir($destination, 0755, true)) {
                        $response = ["status" => "error", "message" => "Failed to create destination directory"];
                        break;
                    }
                }
                $result = extractArchive($filePath, $destination, $config);
                $response = $result;
                break;
            case "download":
                $file = isset($_GET["file"]) ? $_GET["file"] : "";
                $filePath = $currentPath . DIRECTORY_SEPARATOR . $file;
                if (file_exists($filePath) && is_file($filePath)) {
                    header("Content-Description: File Transfer");
                    header("Content-Type: application/octet-stream");
                    header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate");
                    header("Pragma: public");
                    header("Content-Length: " . filesize($filePath));
                    readfile($filePath);
                    exit();
                } else {
                    $response = ["status" => "error", "message" => "File not found"];
                }
                break;
        }
    }

    if ($action != "download") {
        header("Content-Type: application/json");
        echo json_encode($response);
        exit();
    }
}


function fmUploadTarget($directory, $name)
{
    if (!is_string($name) || $name === '' || $name === '.' || $name === '..' || strpbrk($name, "/\\\0") !== false || !preg_match('//u', $name)) throw new RuntimeException('Invalid file name.');
    $target = $directory . DIRECTORY_SEPARATOR . $name;
    if (!securityCheck($target) || is_link($target)) throw new RuntimeException('Symbolic links or files outside the workspace cannot be replaced.');
    if (file_exists($target) && (!is_file($target) || !is_readable($target) || !is_writable($target))) throw new RuntimeException('Existing file is not a readable, writable regular file.');
    return $target;
}
function fmInstallUpload($uploadedFile, $target, $expectedHash)
{
    global $config;
    $root = realpath($config['root_path']);
    $directory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . '/fm-editor-' . substr(hash('sha256', __FILE__ . '|' . $root), 0, 24);
    if (is_link($directory) || (!is_dir($directory) && !@mkdir($directory, 0700)) || !@chmod($directory, 0700)) throw new RuntimeException('Cannot prepare private upload backups.');
    $real = realpath($directory);
    if ($real === $root || strpos($real, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) throw new RuntimeException('Upload backups must be outside the workspace.');
    $key = hash('sha256', $target);
    $lockPath = $directory . '/' . $key . '.lock';
    if (is_link($lockPath)) throw new RuntimeException('Invalid upload lock.');
    $lock = @fopen($lockPath, 'c');
    if (!$lock) throw new RuntimeException('Cannot acquire upload lock.');
    $temporary = null;
    try {
        if (!@chmod($lockPath, 0600) || !flock($lock, LOCK_EX)) throw new RuntimeException('Cannot acquire upload lock.');
        clearstatcache(true, $target);
        fmUploadTarget(dirname($target), basename($target));
        $exists = file_exists($target);
        if ($exists && (!is_string($expectedHash) || !preg_match('/^[a-f0-9]{64}$/D', $expectedHash) || !hash_equals($expectedHash, (string) @hash_file('sha256', $target)))) throw new RuntimeException('File already exists or changed since confirmation. Choose the file again to confirm replacement.');
        if (!$exists && $expectedHash !== null) throw new RuntimeException('File disappeared since confirmation. Choose the file again.');
        $stat = $exists ? @stat($target) : null;
        if ($exists && (!$stat || $stat['nlink'] !== 1)) throw new RuntimeException('Files with hard links cannot be replaced safely.');
        $hash = @hash_file('sha256', $uploadedFile); $size = @filesize($uploadedFile);
        if ($hash === false || $size === false || !is_uploaded_file($uploadedFile)) throw new RuntimeException('Invalid or unreadable uploaded file.');
        $temporary = @tempnam(dirname($target), '.fm-upload-');
        if (!$temporary || dirname($temporary) !== dirname($target)) throw new RuntimeException('Cannot create a temporary file in the destination folder.');
        if (!@move_uploaded_file($uploadedFile, $temporary)) throw new RuntimeException('Cannot write uploaded file to the destination folder.');
        $tempStat = @stat($temporary);
        if ($stat && $tempStat['uid'] !== $stat['uid'] && !@chown($temporary, $stat['uid'])) throw new RuntimeException('Cannot preserve file owner. Original file was not changed.');
        if ($stat && $tempStat['gid'] !== $stat['gid'] && !@chgrp($temporary, $stat['gid'])) throw new RuntimeException('Cannot preserve file group. Original file was not changed.');
        $mode = $stat ? ($stat['mode'] & 07777) : (0666 & ~umask());
        if (!@chmod($temporary, $mode) || !is_readable($temporary) || @filesize($temporary) !== $size || @hash_file('sha256', $temporary) !== $hash) throw new RuntimeException('Upload failed content or permission verification. Original file was not changed.');
        if ($exists) {
            $backup = $directory . '/' . $key . '-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(6)) . '.bak';
            if (is_link($backup) || !@copy($target, $backup) || !@chmod($backup, 0600) || @hash_file('sha256', $backup) !== $expectedHash) throw new RuntimeException('Cannot verify a backup. Original file was not changed.');
            clearstatcache(true, $target); $latest = @stat($target);
            if (is_link($target) || !$latest || $latest['ino'] !== $stat['ino'] || @hash_file('sha256', $target) !== $expectedHash) throw new RuntimeException('File changed during upload. Original file was not replaced.');
            if (!@rename($temporary, $target)) throw new RuntimeException('Cannot replace the file. Original file was not changed.');
        } else {
            // Hard-link installation refuses a file that appeared after the check.
            if (!@link($temporary, $target)) throw new RuntimeException('Cannot create file, or a file with this name already exists.');
            @unlink($temporary);
        }
        $temporary = null;
        clearstatcache(true, $target);
        if (!is_readable($target) || @filesize($target) !== $size || @hash_file('sha256', $target) !== $hash || (fileperms($target) & 07777) !== $mode) throw new RuntimeException('Upload completed but final verification failed. Check the file before continuing.');
        if (function_exists('opcache_invalidate')) @opcache_invalidate($target, true);
    } finally {
        if ($temporary && is_file($temporary)) @unlink($temporary);
        flock($lock, LOCK_UN); fclose($lock);
    }
}

function parseSize($size)
{
    $unit = preg_replace('/[^bkmgtpezy]/i', '', $size);
    $size = preg_replace('/[^0-9\.]/', '', $size);
    if ($unit) {
        return round($size * pow(1024, stripos('bkmgtpezy', $unit[0])));
    }
    return round($size);
}


if (isset($_POST['upload_manifest']) && !isset($_FILES['files'])) fmAuthReply(400, 'No files received. Check server upload limits and choose the files again.');

if (isset($_FILES["files"])) {
    header("Content-Type: application/json");
    $currentPath = isset($_POST["path"]) ? $config["root_path"] . $_POST["path"] : $config["root_path"];
    if (!securityCheck($currentPath)) {
        echo json_encode(["status" => "error", "message" => "Security violation"]);
        exit();
    }
    $currentPath = realpath($currentPath);
    if (!$currentPath || !is_dir($currentPath) || !is_writable($currentPath)) fmAuthReply(403, 'Destination folder is not writable.');
    $manifest = json_decode($_POST['upload_manifest'] ?? '', true);
    if (!is_array($manifest)) fmAuthReply(400, 'Upload confirmation is missing. Choose the files again.');
    $files = $_FILES["files"];
    if (!isset($files['name'], $files['tmp_name'], $files['error'], $files['size']) || !is_array($files['name']) || !count($files['name'])) fmAuthReply(400, 'No valid upload files received.');
    $uploaded = 0;
    $failed = 0;
    $failedFiles = [];
    $uploadedNames = [];
    $received = [];
    for ($i = 0; $i < count($files["name"]); $i++) {
        $fileName = $files["name"][$i];
        try {
            $filePath = fmUploadTarget($currentPath, $fileName);
            if (!array_key_exists($fileName, $manifest) || isset($received[$fileName])) throw new RuntimeException('Missing confirmation or duplicate file name.');
            $received[$fileName] = true;
        } catch (Throwable $error) { $failed++; $failedFiles[] = (is_string($fileName) ? $fileName : 'File') . ': ' . $error->getMessage(); continue; }
        if ($files["error"][$i] !== UPLOAD_ERR_OK) {
            $failed++;
            $errorMsg = "";
            switch ($files["error"][$i]) {
                case UPLOAD_ERR_INI_SIZE:
                    $errorMsg = "File exceeds upload_max_filesize directive in php.ini";
                    break;
                case UPLOAD_ERR_FORM_SIZE:
                    $errorMsg = "File exceeds MAX_FILE_SIZE directive specified in the HTML form";
                    break;
                case UPLOAD_ERR_PARTIAL:
                    $errorMsg = "File was only partially uploaded";
                    break;
                case UPLOAD_ERR_NO_FILE:
                    $errorMsg = "No file was uploaded";
                    break;
                case UPLOAD_ERR_NO_TMP_DIR:
                    $errorMsg = "Missing a temporary folder";
                    break;
                case UPLOAD_ERR_CANT_WRITE:
                    $errorMsg = "Failed to write file to disk";
                    break;
                case UPLOAD_ERR_EXTENSION:
                    $errorMsg = "File upload stopped by extension";
                    break;
                default:
                    $errorMsg = "Unknown upload error";
            }
            $failedFiles[] = $fileName . " (" . $errorMsg . ")";
            continue;
        }
        $maxFileSize = parseSize(ini_get('upload_max_filesize'));
        if ($maxFileSize > 0 && $files["size"][$i] > $maxFileSize) {
            $failed++;
            $failedFiles[] = $fileName . " (Exceeds maximum file size limit)";
            continue;
        }
        if ($config["allowed_extensions"][0] !== "*") {
            $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
            if (!in_array($extension, $config["allowed_extensions"])) {
                $failed++;
                $failedFiles[] = $fileName . " (File type not allowed)";
                continue;
            }
        }
        try {
            fmInstallUpload($files['tmp_name'][$i], $filePath, $manifest[$fileName]);
            $uploaded++; $uploadedNames[] = $fileName;
        } catch (Throwable $error) {
            $failed++; $failedFiles[] = $fileName . ': ' . $error->getMessage();
        }
    }
    foreach ($manifest as $name => $_) {
        if (!isset($received[$name])) { $failed++; $failedFiles[] = $name . ': not received by the server. Check upload limits.'; }
    }
    $response = ['status' => $failed === 0 ? 'success' : ($uploaded > 0 ? 'partial' : 'error'),
        'message' => "Uploaded and verified $uploaded file(s)" . ($failed ? "; failed $failed file(s)." : '.'), 'uploaded' => $uploadedNames];
    if ($failed && !$uploaded) http_response_code(400);
    if (!empty($failedFiles)) {
        $response["failedFiles"] = $failedFiles;
    }
    echo json_encode($response);
    exit();
}

$versionInfo = 'Pocket Code Studio v1.0.0';
$version = '1.0.0';

if ($username == null) {
    $username = "";
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <style>
        @font-face {font-family: 'Embedded Seti';src: url('https://cdn.jsdelivr.net/gh/microsoft/vscode@8993bc4913b5ecd98a639457ac1dabf5e4c58787/extensions/theme-seti/icons/seti.woff') format('woff');font-weight: normal;font-style: normal;font-display: block;}
        .file-type-icon {font-family: 'Embedded Seti' !important;font-size: 24px;font-style: normal;font-weight: normal;line-height: 1;width: 20px;height: 20px;display: inline-flex;align-items: center;justify-content: center;flex-shrink: 0;color: var(--file-icon-color, #9da5b4);}
        :root[data-workspace-light="true"] .file-type-icon, :root[data-workspace-light="true"] .file-type-icon, :root[data-workspace-light="true"] .file-type-icon {color: var(--file-icon-light-color, #57606a);}
        .file-type-icon img {width: 20px;height: 20px;object-fit: contain;display: block;}
        .file-type-icon.folder-type-icon {color: var(--text-secondary);}
        .folder-type-icon svg {width: 16px;height: 16px;}
        .workspace-tab button[role="tab"] {display: inline-flex;align-items: center;gap: 6px;}
    </style>

    <?= $workspaceThemeScript ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pocket Code Studio</title>
    <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiMyMTI1MmIiLz48cGF0aCBkPSJtMjMgMjAtMTIgMTIgMTIgMTJtMTgtMjQgMTIgMTItMTIgMTJtLTYtMjgtNiAzMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNjFhZmVmIiBzdHJva2Utd2lkdGg9IjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==" type="image/svg+xml">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script defer src="https://cdn.jsdelivr.net/npm/coolalertjs@latest/dist/coolalert.min.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"></script>
    <style>
        /* ── Design Tokens ───────────────────────────────────────── */
        :root {--bg-deep: #0f1117;--bg-main: #1a1d2e;--bg-surface: #1e2235;--bg-elevated: #242840;--bg-hover: rgba(255, 255, 255, 0.04);--bg-selected: var(--bg-selected);--border-subtle: rgba(255, 255, 255, 0.06);--border-default: rgba(255, 255, 255, 0.10);--border-accent: #3b82f6;--text-primary: #e2e8f0;--text-secondary: #94a3b8;--text-muted: #64748b;--text-link: #60a5fa;--text-link-hover: #93c5fd;--accent: #3b82f6;--accent-hover: #2563eb;--accent-success: #10b981;--accent-danger: #ef4444;--accent-warning: #f59e0b;--folder-color: #fbbf24;--radius-sm: 4px;--radius-md: 6px;--radius-lg: 8px;--shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);--shadow-md: 0 4px 12px rgba(0, 0, 0, 0.5);--shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);--font-size: <?= $config["font_size"] ?>;--font-mono: 'Fira Code', 'Cascadia Code', 'Courier New', monospace;}
        /* ── Reset & Base ────────────────────────────────────────── */
        *, *::before, *::after {box-sizing: border-box;}
        html, body {font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;font-size: var(--font-size);background-color: var(--bg-deep);color: var(--text-primary);height: 100%;margin: 0;overflow: hidden;}
        ::-webkit-scrollbar {width: 5px;height: 5px;}
        ::-webkit-scrollbar-track {background: transparent;}
        ::-webkit-scrollbar-thumb {background: var(--bg-elevated);border-radius: 10px;}
        ::-webkit-scrollbar-thumb:hover {background: var(--accent);}
        /* ── Top Header ──────────────────────────────────────────── */
        .top-header {background: var(--bg-main);border-bottom: 1px solid var(--border-subtle);padding: 7px 16px;display: flex;align-items: center;justify-content: space-between;height: 46px;position: sticky;top: 0;z-index: 100;}
        .main-toolbar .brand img {display: block;}
        .search-container .input-group .form-control {background: var(--bg-elevated);border: 1px solid var(--border-default);color: var(--text-primary);font-size: 0.8rem;border-radius: var(--radius-sm) 0 0 var(--radius-sm);}
        .search-container .input-group .form-control:focus {background: var(--bg-elevated);border-color: var(--accent);color: var(--text-primary);box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);}
        .search-container .input-group .form-control::placeholder {color: var(--text-muted);}
        .btn-search {background: var(--accent);border: none;color: #fff;font-size: 0.8rem;padding: 4px 10px;border-radius: 0 var(--radius-sm) var(--radius-sm) 0;cursor: pointer;transition: background 0.15s;}
        .btn-search:hover {background: var(--accent-hover);color: #fff;}
        .btn-settings {background: transparent;border: 1px solid var(--border-default);color: var(--text-secondary);font-size: 0.8rem;padding: 4px 10px;border-radius: var(--radius-sm);cursor: pointer;transition: all 0.15s;white-space: nowrap;}
        .btn-settings:hover {border-color: var(--accent);color: var(--text-link);background: var(--bg-selected);}
        /* ── Main Toolbar ────────────────────────────────────────── */
        .main-toolbar {background: var(--bg-surface);border-bottom: 1px solid var(--border-subtle);padding: 2px 10px;display: grid;grid-template-columns: minmax(max-content, 1fr) minmax(220px, min(46vw, 640px)) minmax(max-content, 1fr);align-items: center;flex-shrink: 0;flex-wrap: nowrap;gap: 2px 12px;min-height: 30px;}
        .header-btns {display: inline-flex;align-items: center;gap: 5px;text-decoration: none;font-size: 0.78rem;color: var(--text-secondary);padding: 4px 8px;border-radius: var(--radius-sm);transition: all 0.15s;white-space: nowrap;border: 1px solid transparent;}
        .header-btns i {font-size: 0.72rem;}
        .header-btns:hover {color: var(--text-link);background: var(--bg-selected);border-color: rgba(59, 130, 246, 0.2);}
        .header-btns.disabled {color: var(--text-muted) !important;pointer-events: none;opacity: 0.45;}
        .toolbar-divider {width: 1px;height: 18px;background: var(--border-subtle);margin: 0 4px;}
        /* ── Progress Bar ────────────────────────────────────────── */
        .progress {height: 18px;border-radius: var(--radius-sm);display: none;background: var(--bg-elevated);border: 1px solid var(--border-default);overflow: hidden;}
        .progress-bar {transition: width 0.3s ease;font-size: 0.7rem;font-weight: 600;line-height: 18px;text-align: center;color: #fff;white-space: nowrap;background: linear-gradient(90deg, var(--accent-success), #059669);text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);}
        /* ── Layout Shell ────────────────────────────────────────── */
        .fm-layout {display: flex;flex: 1;min-height: 0;height: auto;overflow: hidden;}
        /* ── Sidebar ─────────────────────────────────────────────── */
        .sidebar {width: var(--sidebar-width, 220px);min-width: 0;flex-shrink: 0;background: var(--bg-main);border-right: 1px solid var(--border-subtle);display: flex;flex-direction: column;overflow: hidden;}
        .sidebar-resizer {width: 5px;flex-shrink: 0;cursor: col-resize;touch-action: none;background: var(--bg-main);outline: none;}
        .sidebar-resizer:hover, .sidebar-resizer:focus-visible, body.resizing-sidebar .sidebar-resizer {background: var(--accent);}
        body.resizing-sidebar {cursor: col-resize;user-select: none;}
        body.resizing-sidebar iframe {pointer-events: none;}
        .file-path-control {display: flex;flex: 1 1 180px;min-width: 120px;max-width: 460px;gap: 0;margin: 0 6px;}
        .file-path-control .form-control {min-width: 0;background: var(--bg-elevated);color: var(--text-primary);border: 1px solid var(--border-default);border-radius: 4px 0 0 4px;font-size: 0.78rem;padding: 3px 8px;}
        .file-path-control .form-control:focus {border-color: var(--accent);box-shadow: none;}
        .file-path-control .btn-icon {background: var(--bg-elevated);color: var(--text-secondary);border: 1px solid var(--border-default);border-left: 0;border-radius: 0 4px 4px 0;font-size: 0.78rem;padding: 3px 9px;}
        .file-path-control .btn-icon:hover {background: var(--bg-hover);color: var(--text-primary);}
        .collapse-all-btn {font-size: 0.72rem;color: var(--text-muted);text-align: center;padding: 4px;cursor: pointer;border-bottom: 1px solid var(--border-subtle);transition: color 0.15s;letter-spacing: 0.03em;}
        .collapse-all-btn:hover {color: var(--text-link);}
        .tree-scroll {overflow-y: auto;flex: 1;padding: 6px 0;}
        /* ── File Tree ───────────────────────────────────────────── */
        .file-tree {list-style: none;padding: 0;margin: 0;}
        .file-tree li {margin: 0;}
        .tree-name {overflow: hidden;text-overflow: ellipsis;}
        .tree-loading {display: flex;align-items: center;gap: 6px;padding: 3px 10px;font-size: 0.8rem;line-height: 20px;color: var(--text-muted);}
        .tree-loading-spinner {width: 12px;height: 12px;flex-shrink: 0;border: 2px solid var(--border-default);border-top-color: var(--accent);border-radius: 50%;animation: tree-loading-spin 0.8s linear infinite;}
        @keyframes tree-loading-spin {
            to {transform: rotate(360deg);}
        }
        @media (prefers-reduced-motion: reduce) {
            .tree-loading-spinner {animation: none;}
        }
        .tree-message {padding: 4px 10px;color: var(--text-muted);font-size: 0.75rem;}
        .tree-file {padding-left: 25px !important;}
        .file-tree .folder-item {display: flex;width: 100%;border: 0;background: transparent;text-align: left;align-items: center;gap: 5px;padding: 3px 10px;font-size: 0.8rem;color: var(--text-secondary);cursor: pointer;border-radius: 0;transition: all 0.12s;white-space: nowrap;overflow: hidden;text-overflow: ellipsis;}
        .file-tree .folder-item:hover {background: var(--bg-hover);color: var(--text-primary);}
        .file-tree .folder-item.active {background: var(--bg-selected);color: var(--text-link);border-left: 2px solid var(--accent);}
        .file-tree .folder-item .fa-folder {color: var(--folder-color);font-size: 0.75rem;}
        .file-tree .folder-item .caret {font-size: 0.6rem;color: var(--text-muted);transition: transform 0.15s;min-width: 10px;}
        .file-tree .folder-item .caret.expanded {transform: rotate(90deg);}
        .file-tree .nested {display: none;padding-left: 16px;}
        .file-tree .nested.active {display: block;}
        body {display: flex;flex-direction: column;}
        .toolbar-actions {display: flex;align-items: center;gap: 2px;flex: none;min-width: 0;overflow: visible;grid-column: 1;grid-row: 1;}
        .toolbar-actions > * {flex-shrink: 0;}
        .toolbar-actions .header-btns {padding: 4px 5px;font-size: 0.74rem;}
        .toolbar-utilities #workspace-theme {height: 25px;padding: 1px 6px;font-size: 0.75rem;}
        .toolbar-utilities .input-group .form-control {height: 25px;min-height: 25px;padding: 1px 7px;font-size: 0.75rem;}
        .toolbar-utilities .btn-search {height: 25px;padding: 1px 8px;font-size: 0.75rem;}
        #workspace-theme {max-width: 130px;background: var(--bg-elevated);color: var(--text-primary);}
        .menu-heading {background: transparent;border: 0;border-radius: 4px;padding: 3px 8px;color: var(--text-primary);font-size: var(--workspace-ui-font-size);}
        .menu-heading:hover, .menu-heading[aria-expanded="true"] {background: var(--bg-hover);}
        .toolbar-more .header-btns > i, .workspace-theme-choice > span > i {width: 16px;flex: 0 0 16px;text-align: center;font-size: var(--workspace-ui-font-size);}
        .menu-shortcut {margin-left: auto;padding-left: 20px;font-size: 0.7rem;color: var(--text-muted);}
        .editor-menu-action[aria-pressed="true"] {color: var(--accent) !important;background: var(--bg-selected) !important;}
        .editor-menu-action:disabled {opacity: 0.45;cursor: default;}
        .toolbar-more .dropdown-divider {border-color: var(--border-subtle);}
        .toolbar-more .dropdown-menu {background: var(--bg-main);border-color: var(--border-default);padding: 5px;min-width: 160px;box-shadow: var(--shadow-md);}
        .toolbar-more .dropdown-menu .header-btns {appearance: none;-webkit-appearance: none;display: flex;width: 100%;padding: 7px 10px;background: transparent;background-image: none;border: 0;box-shadow: none;text-align: left;font: inherit;font-size: 0.78rem;color: var(--text-secondary);}
        .toolbar-more .dropdown-menu .header-btns:not(:disabled):not(.disabled):hover, .toolbar-more .dropdown-menu .header-btns:not(:disabled):not(.disabled):focus-visible {background: var(--bg-hover);color: var(--text-primary);}
        .toolbar-more .dropdown-menu .header-btns:disabled, .toolbar-more .dropdown-menu .header-btns.disabled {background: transparent;opacity: 0.45;color: var(--text-muted);}
        @media (max-width: 900px) {
            .toolbar-actions .action-label {display: none;}
            .toolbar-actions .header-btns {padding: 6px 8px;}
        }
        #workspace-theme option {background: var(--bg-elevated);color: var(--text-primary);}
        /* Internal editor tabs */
        .workspace {flex: 1;min-width: 0;display: flex;flex-direction: column;}
        .workspace-tabs {display: flex;flex-shrink: 0;overflow-x: auto;background: var(--bg-main);border-bottom: 1px solid var(--border-subtle);}
        .workspace-tab {display: flex;align-items: center;flex-shrink: 0;border-right: 1px solid var(--border-subtle);border-top: 2px solid transparent;}
        .workspace-tab.active {background: var(--bg-deep);border-top-color: var(--accent);}
        .workspace-tab button {border: 0;background: transparent;color: var(--text-secondary);cursor: pointer;padding: 9px 12px;font-size: 0.8rem;white-space: nowrap;}
        .workspace-tab.active button {color: var(--text-primary);}
        .workspace-tab .tab-close {padding: 5px 8px;margin-right: 4px;border-radius: 4px;}
        .workspace-tab .tab-close:hover {background: var(--bg-elevated);}
        .tab-dirty {color: var(--accent);margin-left: 6px;}
        .workspace-panels {position: relative;flex: 1;min-height: 0;display: flex;background: var(--bg-deep);}
        .workspace-panels:has(> .editor-panel[data-loading="true"]:not([hidden]))::after {content: "Loading editor…";position: absolute;inset: 0;z-index: 2;display: grid;place-items: center;background: var(--bg-deep);color: var(--text-muted);font-size: 0.8rem;}
        .editor-panel {flex: 1;min-width: 0;border: 0;background: var(--bg-deep);}
        .workspace-panels > [hidden] {display: none !important;}
        /* ── Main Content Area ───────────────────────────────────── */
        .main-content {flex: 1;background: var(--bg-deep);display: flex;flex-direction: column;overflow: hidden;}
        /* ── Navigation Bar ──────────────────────────────────────── */
        .navigation-bar {background: var(--bg-surface);border-bottom: 1px solid var(--border-subtle);padding: 5px 12px;display: flex;align-items: center;flex-wrap: wrap;gap: 2px;}
        .nav-links {display: inline-flex;align-items: center;gap: 5px;text-decoration: none;font-size: 0.78rem;color: var(--text-secondary);padding: 3px 8px;border-radius: var(--radius-sm);transition: all 0.15s;white-space: nowrap;}
        .nav-links i {font-size: 0.72rem;}
        .nav-links:hover {color: var(--text-link);background: var(--bg-selected);}
        .nav-links.disabled {color: var(--text-muted) !important;pointer-events: none;opacity: 0.45;}
        .git-status-badge {margin-left: 8px;font-size: 0.7rem;font-weight: 600;color: var(--text-link);}
        /* Keep search central and sign-out independent from the application menus. */
        .toolbar-utilities {grid-column: 2;grid-row: 1;width: 100%;min-width: 0;margin: 0;padding: 0;flex-shrink: 0;}
        .toolbar-utilities .search-container {width: 100%;min-width: 0;}
        #logout-form {grid-column: 3;grid-row: 1;justify-self: end;margin: 0;}
        #logout-form .menu-heading {white-space: nowrap;}
        .main-toolbar > #upload-progress {grid-row: 2;grid-column: 1 / -1;width: 100% !important;margin: 0 !important;}
        .workspace-theme-choice {display: flex;flex-direction: column;gap: 6px;margin: 0;padding: 8px 10px;font-size: var(--workspace-ui-font-size);color: var(--text-secondary);}
        .workspace-theme-choice select {width: 100%;max-width: none;min-height: 30px;border: 1px solid var(--border-default);border-radius: 4px;padding: 3px 6px;font: inherit;}
        @media (min-width: 761px) and (max-width: 1050px) {
            .main-toolbar {grid-template-columns: max-content minmax(150px, 1fr) max-content;column-gap: 8px;}
        }
        .mobile-workspace-controls {display: none;}
        @media (max-width: 760px) {
            html, body {height: var(--mobile-viewport-height, 100dvh);}
            .main-toolbar {display: flex;position: relative;height: auto;min-height: 46px;padding: 4px 8px;flex-wrap: wrap;gap: 4px;}
            #logout-form {position: absolute;right: 8px;top: 4px;}
            #logout-form .menu-heading {min-height: 38px;}
            .workspace-theme-choice select {min-height: 38px;font-size: 16px;}
            .mobile-workspace-controls {display: flex;align-items: center;gap: 5px;width: 100%;min-width: 0;padding-right: 76px;}
            .mobile-workspace-controls button, #mobile-tabs-select {min-height: 38px;border: 1px solid var(--border-default);border-radius: 4px;background: var(--bg-main);color: var(--text-primary);padding: 5px 9px;font: inherit;}
            #mobile-tabs-select {flex: 1;min-width: 0;max-width: 100%;font-size: 16px;}
            .toolbar-actions {display: none;flex: 1 0 100%;max-height: 40vh;overflow-y: auto;flex-direction: column;align-items: stretch;}
            .toolbar-utilities {display: none !important;}
            body.mobile-menu-open .toolbar-actions {display: flex;}
            body.mobile-menu-open .toolbar-utilities {display: flex !important;width: 100%;margin: 0;padding: 0;flex-wrap: wrap;}
            .toolbar-utilities .search-container {flex: 1;min-width: 150px;}
            .toolbar-utilities #workspace-theme, .toolbar-utilities .input-group .form-control {height: 38px;font-size: 16px;}
            .toolbar-utilities .btn-search {height: 38px;}
            .toolbar-actions .menu-heading {width: 100%;text-align: left;min-height: 38px;}
            .toolbar-actions .dropdown-menu {position: static !important;transform: none !important;width: 100%;border: 0;box-shadow: none;}
            .toolbar-actions .header-btns {min-height: 40px;font-size: 14px;}
            .sidebar {width: 100% !important;min-width: 0 !important;max-width: none;}
            .sidebar-resizer, .workspace {display: none;}
            body.mobile-editor .sidebar, body.mobile-file-list .sidebar {display: none;}
            body.mobile-editor .workspace, body.mobile-file-list .workspace {display: flex;width: 100%;min-width: 0;}
            .file-tree .folder-item {min-height: 42px;font-size: 14px;}
            .file-path-control .form-control, .modal input, .modal select {font-size: 16px;}
            .file-path-control {flex-basis: 100%;max-width: none;order: 1;margin: 3px 0 0;}
            .file-path-control .btn-icon, .file-path-control .form-control {min-height: 38px;}
            .workspace-tabs {min-width: 0;width: 100%;}
            .workspace-tab button {min-height: 38px;}
            .workspace-tab .tab-close {min-width: 36px;}
            .navigation-bar {flex-wrap: wrap;padding: 4px;gap: 3px;}
            .navigation-bar a {min-height: 36px;}
            .file-table th:nth-child(n+5), .file-table td:nth-child(n+5) {display: none;}
            .file-table .file-name {overflow-wrap: anywhere;}
            .file-table tbody td {padding: 9px 6px;}
            .fm-footer {font-size: 10px;}
            .modal-dialog {margin: 8px;max-width: calc(100vw - 16px);}
            .modal-content {max-height: calc(var(--mobile-viewport-height, 100dvh) - 16px);}
            .modal-body {overflow-y: auto;min-height: 0;}
            .modal .table-responsive {max-height: 50vh;}
            .modal .btn {min-height: 38px;}
            #context-menu {max-width: 95vw;max-height: 65vh;overflow-y: auto;}
        }
        /* Match the editor scrollbar in the file list and explorer. */
        .file-table-wrap, .tree-scroll {scrollbar-width: thin;scrollbar-color: var(--scrollbar-gold) var(--bg-main);}
        .file-table-wrap::-webkit-scrollbar, .tree-scroll::-webkit-scrollbar {width: 10px;height: 10px;}
        .file-table-wrap::-webkit-scrollbar-track, .tree-scroll::-webkit-scrollbar-track {background: var(--bg-main);}
        .file-table-wrap::-webkit-scrollbar-thumb, .tree-scroll::-webkit-scrollbar-thumb {background: var(--scrollbar-gold);border: 2px solid var(--bg-main);border-radius: 5px;}
        .file-table-wrap::-webkit-scrollbar-thumb:hover, .tree-scroll::-webkit-scrollbar-thumb:hover {background: var(--scrollbar-gold-hover);}
        .file-table-wrap::-webkit-scrollbar-corner, .tree-scroll::-webkit-scrollbar-corner {background: var(--bg-main);}
        /* ── File Table ──────────────────────────────────────────── */
        .file-table-wrap {flex: 1;overflow-y: auto;padding: 0;}
        .file-table {width: 100%;border-collapse: collapse;font-size: 0.8rem;}
        .file-table thead th {background: var(--bg-surface);border-bottom: 1px solid var(--border-default);padding: 7px 10px;font-weight: 600;font-size: 0.72rem;text-transform: uppercase;letter-spacing: 0.06em;color: var(--text-muted);position: sticky;top: 0;z-index: 10;white-space: nowrap;}
        .file-table tbody tr.file-item {border-bottom: 1px solid var(--border-subtle);transition: background 0.1s;cursor: pointer;}
        .file-table tbody tr.file-item:hover {background: var(--bg-hover);}
        .file-table tbody tr.file-item.selected {background: var(--bg-selected);}
        .file-table td {padding: 5px 10px;vertical-align: middle;color: var(--text-primary);}
        .checkbox-col {width: 32px;}
        .icon-col {width: 32px;padding-right: 0;}
        .file-name {color: var(--text-primary);text-decoration: none;font-weight: 500;}
        .file-name:hover {color: var(--text-primary);text-decoration: none;}
        .folder-icon {color: var(--folder-color);}
        .file-size, .file-date, .file-type {color: var(--text-secondary);font-size: 0.75rem;}
        .file-type {color: var(--text-muted);font-size: 0.7rem;}
        .file-ownership {max-width: 170px;width: 1%;overflow: hidden;text-overflow: ellipsis;white-space: nowrap;font-family: var(--font-mono);font-size: 0.68rem;color: var(--text-muted) !important;}
        .permissions {font-family: var(--font-mono);font-size: 0.68rem;color: var(--text-muted);letter-spacing: 0.02em;}
        .form-check-input {background-color: var(--bg-elevated);border-color: var(--border-default);cursor: pointer;}
        .form-check-input:checked {background-color: var(--accent);border-color: var(--accent);}
        .form-check-input:focus {box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);}
        /* ── Footer bar ──────────────────────────────────────────── */
        .fm-footer {background: var(--bg-surface);border-top: 1px solid var(--border-subtle);padding: 4px 14px;font-size: 0.72rem;color: var(--text-muted);text-align: center;}
        .fm-footer a {color: var(--text-link);text-decoration: none;}
        .fm-footer a:hover {color: var(--text-link-hover);text-decoration: underline;}
        #search-results .search-result-item {cursor: pointer;}
        #search-results .search-result-item:focus-visible {outline: 1px solid var(--accent);outline-offset: -1px;}
        .search-result-name {display: flex;align-items: center;gap: 6px;min-width: 0;}
        .search-result-label {overflow-wrap: anywhere;}
        .search-result-path {color: var(--text-muted) !important;}
        /* ── Context Menu ────────────────────────────────────────── */
        .context-menu {position: fixed;z-index: 9999;background: var(--bg-elevated);border: 1px solid var(--border-default);border-radius: var(--radius-md);box-shadow: var(--shadow-lg);min-width: 170px;display: none;padding: 4px 0;backdrop-filter: blur(8px);}
        .context-menu-item {padding: 6px 14px;cursor: pointer;font-size: 0.8rem;color: var(--text-secondary);display: flex;align-items: center;gap: 8px;transition: all 0.12s;}
        .context-menu-item i {font-size: 0.72rem;color: var(--text-muted);width: 14px;}
        .context-menu-item:hover {background: var(--bg-selected);color: var(--text-primary);}
        .context-menu-item:hover i {color: var(--text-link);}
        .context-menu-item.danger, .context-menu-item.danger i {color: #f87171;}
        .context-menu-item.danger:hover {background: rgba(239, 68, 68, 0.1);}
        .context-menu-divider {border-top: 1px solid var(--border-subtle);margin: 3px 0;}
        /* ── Drag-over ───────────────────────────────────────────── */
        .drag-over {background: rgba(59, 130, 246, 0.05) !important;outline: 2px dashed var(--accent) !important;outline-offset: -4px;}
        /* ── Modals ──────────────────────────────────────────────── */
        .modal-content {background: var(--bg-surface);border: 1px solid var(--border-default);border-radius: var(--radius-lg);color: var(--text-primary);box-shadow: var(--shadow-lg);}
        .modal-header {background: var(--bg-elevated);border-bottom: 1px solid var(--border-subtle);padding: 10px 16px;border-radius: var(--radius-lg) var(--radius-lg) 0 0;}
        .modal-title {font-size: 0.875rem;font-weight: 600;color: var(--text-primary);}
        .modal-body {padding: 16px;}
        .modal-footer {background: var(--bg-elevated);border-top: 1px solid var(--border-subtle);padding: 10px 16px;border-radius: 0 0 var(--radius-lg) var(--radius-lg);}
        .form-label {font-size: 0.8rem;color: var(--text-secondary);margin-bottom: 4px;}
        .form-control, .form-select {background: var(--bg-deep);border: 1px solid var(--border-default);color: var(--text-primary);font-size: 0.82rem;border-radius: var(--radius-sm);transition: border-color 0.15s, box-shadow 0.15s;}
        .form-control:focus, .form-select:focus {background: var(--bg-deep);border-color: var(--accent);color: var(--text-primary);box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);}
        .form-control::placeholder {color: var(--text-muted);}
        .form-control-sm {font-size: 0.78rem;padding: 4px 8px;}
        .form-text, small {color: var(--text-muted);font-size: 0.72rem;}
        /* Buttons */
        .btn {border-radius: var(--radius-sm);font-size: 0.8rem;padding: 5px 12px;font-weight: 500;transition: all 0.15s;}
        .btn-primary {background: var(--accent);border-color: var(--accent);color: #fff;}
        .btn-primary:hover, .btn-primary:focus {background: var(--accent-hover);border-color: var(--accent-hover);color: #fff;box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);}
        .btn-danger {background: var(--accent-danger);border-color: var(--accent-danger);color: #fff;}
        .btn-danger:hover {background: #dc2626;border-color: #dc2626;color: #fff;}
        .btn-outline-secondary, .btn-outline-light {border-color: var(--border-default);color: var(--text-secondary);background: transparent;}
        .btn-outline-secondary:hover, .btn-outline-light:hover {background: var(--bg-elevated);color: var(--text-primary);border-color: var(--border-default);}
        .btn-sm {padding: 3px 8px;font-size: 0.75rem;}
        /* Alert boxes inside modals */
        .alert {font-size: 0.8rem;border-radius: var(--radius-sm);padding: 8px 12px;}
        .alert-info {background: var(--bg-selected);border: 1px solid rgba(59, 130, 246, 0.25);color: #93c5fd;}
        .alert-danger {background: rgba(239, 68, 68, 0.1);border: 1px solid rgba(239, 68, 68, 0.25);color: #fca5a5;}
        /* Radio/Checkbox in modals */
        .form-check-label {font-size: 0.8rem;color: var(--text-secondary);}
        .form-check {margin-bottom: 3px;}
        /* Border in permissions boxes */
        .border {border-color: var(--border-default) !important;}
        .border.p-2 {background: var(--bg-deep);border-radius: var(--radius-sm);}
        /* Code editor textarea */
        .code-editor {font-family: var(--font-mono);font-size: 0.75rem;line-height: 1.6;color: #93c5fd;background: var(--bg-deep);border: 1px solid var(--border-default);border-radius: var(--radius-sm);padding: 10px;resize: vertical;width: 100%;}
        .code-editor:focus {border-color: var(--accent);box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);outline: none;}
        /* Table inside modals */
        .table {color: var(--text-primary);font-size: 0.8rem;}
        .table thead th {background: var(--bg-elevated);color: var(--text-muted);border-bottom: 1px solid var(--border-default);font-size: 0.72rem;text-transform: uppercase;letter-spacing: 0.05em;padding: 7px 10px;}
        .table tbody td {border-bottom: 1px solid var(--border-subtle);padding: 6px 10px;}
        .table-hover tbody tr:hover {background: var(--bg-hover);}
        /* Spinner */
        .spinner-container {display: flex;align-items: center;justify-content: center;}
        .spinners {width: 16px;height: 16px;border: 2px solid rgba(255, 255, 255, 0.3);border-top-color: #fff;border-radius: 50%;animation: spin 0.7s linear infinite;}
        @keyframes spin {
            to {transform: rotate(360deg);}
        }
        .my-indicator {display: none;}
        .htmx-request .my-indicator, .htmx-request.my-indicator {display: inline;}
        /* Empty state */
        .empty-state {text-align: center;padding: 48px 16px;color: var(--text-muted);}
        .empty-state i {font-size: 2rem;margin-bottom: 10px;opacity: 0.3;}
        .empty-state p {font-size: 0.82rem;}
    </style>
</head>

<body>

    <!-- ── Main Toolbar ─────────────────────────────────────────── -->
    <div class="main-toolbar">
        <div class="mobile-workspace-controls">
            <button type="button" id="mobile-menu-toggle" aria-controls="mobile-app-menus" aria-expanded="false" aria-label="Application menu">☰</button>
            <button type="button" id="mobile-files-btn">Files</button>
            <button type="button" id="mobile-list-btn">List</button>
            <select id="mobile-tabs-select" aria-label="Open files"><option value="">Open files</option></select>
        </div>
        <nav id="mobile-app-menus" class="toolbar-actions" aria-label="Application menus"><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-file" data-bs-toggle="dropdown" aria-expanded="false">File</button><div class="dropdown-menu" aria-labelledby="menu-file"><a href="#" class="header-btns" id="new-file-btn" title="New File" aria-label="New File"><i class="fas fa-file"></i> New File</a><a href="#" class="header-btns" id="new-folder-btn" title="New Folder" aria-label="New Folder"><i class="fas fa-folder-plus"></i> New Folder</a><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="edit-btn" title="Open selected file" aria-label="Open selected file"><i class="fas fa-code"></i> Open selected file</a><a href="#" class="header-btns disabled" id="open-browser-btn"><i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i> Open in browser</a><a href="#" class="header-btns disabled" id="open-phone-btn"><i class="fas fa-qrcode" aria-hidden="true"></i> Open on phone</a><button type="button" class="header-btns editor-menu-action" data-editor-command="save" disabled><i class="fas fa-floppy-disk" aria-hidden="true"></i> Save <span class="menu-shortcut">Ctrl / ⌘ S</span></button><div class="dropdown-divider"></div><a href="#" class="header-btns" id="upload-btn" title="Upload" aria-label="Upload"><i class="fas fa-upload"></i> Upload</a><a href="#" class="header-btns disabled" id="download-btn" title="Download" aria-label="Download"><i class="fas fa-download"></i> Download</a><div class="dropdown-divider"></div><button type="button" class="header-btns" data-bs-toggle="modal" data-bs-target="#settingsModal"><i class="fas fa-cog" aria-hidden="true"></i> Settings…</button></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-edit" data-bs-toggle="dropdown" aria-expanded="false">Edit</button><div class="dropdown-menu" aria-labelledby="menu-edit"><button type="button" class="header-btns editor-menu-action" data-editor-command="undo" disabled><i class="fas fa-undo" aria-hidden="true"></i> Undo</button><button type="button" class="header-btns editor-menu-action" data-editor-command="redo" disabled><i class="fas fa-redo" aria-hidden="true"></i> Redo</button><button type="button" class="header-btns editor-menu-action" data-editor-command="copyall" disabled><i class="fas fa-copy" aria-hidden="true"></i> Copy document text</button><button type="button" class="header-btns editor-menu-action" data-editor-command="find" disabled><i class="fas fa-search" aria-hidden="true"></i> Find / Replace</button><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="copy-btn" title="Copy" aria-label="Copy"><i class="fas fa-copy"></i> Copy</a><a href="#" class="header-btns disabled" id="move-btn" title="Move" aria-label="Move"><i class="fas fa-arrows-alt"></i> Move</a><a href="#" class="header-btns disabled" id="rename-btn" title="Rename" aria-label="Rename"><i class="fas fa-tag"></i> Rename</a><a href="#" class="header-btns disabled" id="delete-btn" title="Delete" aria-label="Delete"><i class="fas fa-trash"></i> Delete</a><a href="#" class="header-btns disabled" id="restore-btn" title="Restore" aria-label="Restore"><i class="fas fa-undo"></i> Restore</a></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-view" data-bs-toggle="dropdown" aria-expanded="false">View</button><div class="dropdown-menu" aria-labelledby="menu-view"><label class="workspace-theme-choice" for="workspace-theme"><span><i class="fas fa-palette" aria-hidden="true"></i> Color theme</span><select id="workspace-theme" class="btn-settings" aria-label="Color theme" onchange="setWorkspaceTheme(this.value)"></select></label><div class="dropdown-divider"></div><button type="button" class="header-btns" id="menu-show-files"><i class="fas fa-list" aria-hidden="true"></i> File list</button><button type="button" class="header-btns editor-menu-action" data-editor-command="map" aria-pressed="false" disabled><i class="fas fa-map" aria-hidden="true"></i> Toggle minimap</button><button type="button" class="header-btns editor-menu-action" data-editor-command="wrap" aria-pressed="false" disabled><i class="fas fa-align-left" aria-hidden="true"></i> Toggle word wrap</button><button type="button" class="header-btns editor-menu-action" data-editor-command="invisibles" aria-pressed="false" disabled><i class="fas fa-paragraph" aria-hidden="true"></i> Show Invisibles</button><button type="button" class="header-btns editor-menu-action" data-editor-command="indentguides" aria-pressed="false" disabled><i class="fas fa-indent" aria-hidden="true"></i> Show Indent Guides</button><button type="button" class="header-btns editor-menu-action" data-editor-command="autocomplete" aria-pressed="false" disabled><i class="fas fa-wand-magic-sparkles" aria-hidden="true"></i> Live Autocompletion</button><button type="button" class="header-btns editor-menu-action" data-editor-command="inlinechanges" aria-pressed="false" disabled><i class="fas fa-code-compare" aria-hidden="true"></i> Show Changes Since Save</button><div class="dropdown-divider"></div><button type="button" class="header-btns editor-menu-action" data-editor-command="foldall" disabled><i class="fas fa-compress-arrows-alt" aria-hidden="true"></i> Fold All</button><button type="button" class="header-btns editor-menu-action" data-editor-command="unfoldall" disabled><i class="fas fa-expand-arrows-alt" aria-hidden="true"></i> Unfold All</button><div class="dropdown-divider"></div><button type="button" class="header-btns editor-menu-action" data-editor-command="fullscreen" aria-pressed="false" disabled><i class="fas fa-expand" aria-hidden="true"></i> Fullscreen</button></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-tools" data-bs-toggle="dropdown" aria-expanded="false">Tools</button><div class="dropdown-menu" aria-labelledby="menu-tools"><button type="button" class="header-btns" id="login-activity-btn" data-bs-toggle="modal" data-bs-target="#loginActivityModal"><i class="fas fa-shield-halved" aria-hidden="true"></i> Login activity</button><div class="dropdown-divider"></div><button type="button" class="header-btns" data-bs-toggle="modal" data-bs-target="#githubModal"><i class="fa-brands fa-github" aria-hidden="true"></i> GitHub: Commit &amp; Push…</button><button type="button" class="header-btns editor-menu-action" data-editor-command="gitdiff" disabled><i class="fas fa-code-branch" aria-hidden="true"></i> Git: View changes against HEAD</button><div class="dropdown-divider"></div><button type="button" class="header-btns editor-menu-action" data-editor-command="format" disabled><i class="fas fa-code" aria-hidden="true"></i> Format document</button><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="permissions-btn" title="Permission" aria-label="Permission"><i class="fas fa-shield-alt"></i> Permission</a><a href="#" class="header-btns disabled" id="compress-btn" title="Compress" aria-label="Compress"><i class="fas fa-file-archive"></i> Compress</a><a href="#" class="header-btns disabled" id="extract-btn" title="Extract" aria-label="Extract"><i class="fas fa-box-open"></i> Extract</a></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-help" data-bs-toggle="dropdown" aria-expanded="false">Help</button><div class="dropdown-menu" aria-labelledby="menu-help"><button type="button" class="header-btns" data-bs-toggle="modal" data-bs-target="#editorHelpModal"><i class="fas fa-keyboard" aria-hidden="true"></i> Keyboard shortcuts &amp; help</button></div></div></nav>
        <div class="toolbar-utilities d-flex align-items-center gap-2">
            <div class="search-container">
                <div class="input-group input-group-sm">
                    <input type="text" class="form-control" id="search-input" placeholder="Search files…">
                    <button class="btn-search" id="search-btn"><i class="fas fa-search"></i></button>
                </div>
            </div>
        </div>
        <form method="post" id="logout-form"><input type="hidden" name="fm_auth_action" value="logout"><button type="submit" class="menu-heading">Sign out</button></form>
        <input type="file" id="file-upload" multiple style="display:none">

        <!-- Upload progress -->
        <div class="progress ms-auto" style="width:220px" id="upload-progress">
            <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width:0%"
                aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
                Preparing…
            </div>
        </div>
    </div>

    <!-- ── App Layout ────────────────────────────────────────────── -->
    <div class="fm-layout">

        <!-- Sidebar -->
        <div class="sidebar" id="file-sidebar" style="--sidebar-width: <?= max(140, min(700, (int) ($_COOKIE['fm_sidebar_width'] ?? 220))) ?>px">
            <div class="collapse-all-btn" id="collapse-all-btn">
                <i class="fas fa-compress-alt"></i> Collapse All
            </div>
            <div class="tree-scroll">
                <div id="directory-tree">
                    <ul class="file-tree">
                        <li class="tree-loading" role="status"><span class="tree-loading-spinner" aria-hidden="true"></span>Loading…</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="sidebar-resizer" id="sidebar-resizer" role="separator" tabindex="0" aria-label="Resize file sidebar" aria-orientation="vertical" aria-controls="file-sidebar" aria-valuemin="140" aria-valuemax="700" aria-valuenow="220" title="Drag to resize; double-click to reset"></div>
        <div class="workspace">
            <div class="workspace-tabs" id="workspace-tabs" role="tablist" aria-label="Open files">
                <div class="workspace-tab active" data-files-tab>
                    <button type="button" id="files-tab" role="tab" aria-selected="true" aria-controls="dropzone">Files</button>
                </div>
            </div>
            <div class="workspace-panels" id="workspace-panels">
        <!-- Main File Area -->
        <div class="main-content" id="dropzone">
            <!-- Nav bar -->
            <div class="navigation-bar">
                <a href="#" class="nav-links" id="home-btn"><i class="fas fa-home"></i> Home</a>
                <a href="#" class="nav-links" id="up-btn"><i class="fas fa-level-up-alt"></i> Up</a>
                <a href="#" class="nav-links" id="reload-btn"><i class="fas fa-sync-alt"></i> Reload</a>
                <div class="file-path-control" role="group" aria-label="Current folder">
                    <input type="text" class="form-control" id="breadcrumb" value="/" placeholder="/" aria-label="Current folder path" title="Current folder — enter a path and press Enter" autocomplete="off" spellcheck="false">
                    <button type="button" class="btn-icon" id="breadcrumb-search-btn" title="Open folder path">Go</button>
                </div>
                <a href="#" class="nav-links" id="select-all-btn"><i class="fas fa-check-square"></i> Select All</a>
                <a href="#" class="nav-links disabled" id="unselect-all-btn"><i class="fas fa-square"></i> Unselect</a>
                <a href="#" class="nav-links" id="view-trash-btn"><i class="fas fa-trash-alt"></i> Trash</a>
                <a href="#" class="nav-links" id="sort-btn"><i class="fas fa-sort-amount-down"></i> Sort</a>
            </div>

            <!-- File table -->
            <div class="file-table-wrap">
                <table class="file-table">
                    <thead>
                        <tr>
                            <th class="checkbox-col">
                                <input type="checkbox" class="form-check-input" id="select-all-checkbox">
                            </th>
                            <th class="icon-col"></th>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Type</th>
                            <th>Permissions</th>
                            <th>Owner / Group</th>
                        </tr>
                    </thead>
                    <tbody id="files-list">
                        <tr>
                            <td colspan="8" class="text-center" style="padding: 32px; color: var(--text-muted);">
                                <i class="fas fa-spinner fa-spin me-2"></i> Loading files…
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Footer -->
            <div class="fm-footer py-2 pb-3">
                &copy; <?= date('Y') ?> <a href="https://github.com/Renat2985" target="_blank" rel="noopener noreferrer">Renat2985</a>
                &nbsp;·&nbsp; <?= htmlspecialchars($versionInfo) ?>
                &nbsp;·&nbsp; <a href="https://github.com/Renat2985/pocket-code-studio"
                    target="_blank" rel="noopener noreferrer"><i class="fa-brands fa-github"></i> GitHub</a>
                &nbsp;·&nbsp; <a href="#" data-bs-toggle="modal" data-bs-target="#aboutPocketModal">About &amp; credits</a>
            </div>
        </div>
    </div>

            </div>
        </div>

    <div class="modal fade" id="editorHelpModal" tabindex="-1" aria-labelledby="editorHelpTitle" aria-hidden="true">
        <div class="modal-dialog"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="editorHelpTitle">Editor help</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">
                <p>Click a folder in the sidebar to expand it; click a file to open an editor tab. Drag the sidebar border to resize it.</p>
                <p><strong>Ctrl / ⌘ S</strong> — Save<br><strong>Ctrl / ⌘ Z</strong> — Undo<br><strong>Ctrl / ⌘ + click</strong> — Add cursor<br><strong>Escape</strong> — Return to one cursor<br><strong>Ctrl H</strong> — Find / Replace<br><strong>Shift Alt F</strong> — Format<br><strong>F11</strong> — Fullscreen</p>
                <p>Choose a color theme in View. Use View to toggle the minimap and word wrap. Unsaved tabs show a dot.</p>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
        </div></div>
    </div>

    <!-- ── Context Menu ──────────────────────────────────────────── -->
    <div class="context-menu" id="context-menu">
        <div class="context-menu-item" id="ctx-open"><i class="fas fa-folder-open"></i> Open</div>
        <div class="context-menu-item" id="ctx-edit"><i class="fas fa-code"></i> Edit</div>
        <div class="context-menu-item" id="ctx-download"><i class="fas fa-download"></i> Download</div>
        <div class="context-menu-divider" id="ctx-open-divider"></div>
        <div class="context-menu-item" id="ctx-browser"><i class="fas fa-arrow-up-right-from-square"></i> Open in browser</div>
        <div class="context-menu-item" id="ctx-phone"><i class="fas fa-qrcode"></i> Open on phone</div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" id="ctx-copy"><i class="fas fa-copy"></i> Copy</div>
        <div class="context-menu-item" id="ctx-cut"><i class="fas fa-arrows-alt"></i> Move</div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" id="ctx-rename"><i class="fas fa-tag"></i> Rename</div>
        <div class="context-menu-item" id="ctx-permissions"><i class="fas fa-shield-alt"></i> Permissions</div>
        <div class="context-menu-item" id="ctx-compress"><i class="fas fa-file-archive"></i> Compress</div>
        <div class="context-menu-item" id="ctx-extract"><i class="fas fa-box-open"></i> Extract</div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item danger" id="ctx-delete"><i class="fas fa-trash"></i> Delete</div>
    </div>

    <!-- ── Modals ─────────────────────────────────────────────────── -->

    <!-- Extract -->
    <div class="modal fade" id="extractModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-box-open me-2 text-warning"></i>Extract Archive</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Archive: <strong id="extractFileName"
                                    style="color:var(--text-link)"></strong></label>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Extract to</label>
                            <input type="text" class="form-control" id="extractPath" name="destination"
                                placeholder="Extraction path">
                            <input type="hidden" name="action" value="extract">
                            <input type="hidden" name="path" id="extractPathName">
                            <input type="hidden" name="file" id="extractFileNameValue">
                            <div class="form-text mt-1">Leave empty to extract into a folder matching the archive name
                            </div>
                        </div>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-1"></i>
                            The destination directory will be created if it doesn't exist.
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Extract</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- New Folder -->
    <div class="modal fade" id="newFolderModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-folder-plus me-2"
                                style="color:var(--folder-color)"></i>Create New Folder</h5>
                    </div>
                    <div class="modal-body">
                        <label class="form-label">Folder Name</label>
                        <input type="text" name="name" class="form-control" id="folderName" placeholder="my-new-folder"
                            autofocus>
                        <input type="hidden" name="path" id="currenPathValue">
                        <input type="hidden" name="action" value="create_dir">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Create</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- New File -->
    <div class="modal fade" id="newFileModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-file-plus me-2" style="color:var(--accent)"></i>Create
                            New File</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">File Name</label>
                            <input type="text" name="name" class="form-control" id="fileName" placeholder="index.php">
                            <input type="hidden" name="path" id="filePath">
                            <input type="hidden" name="action" value="create_file">
                        </div>
                        <div class="mb-1">
                            <label class="form-label">Content</label>
                        </div>
                        <textarea class="code-editor" name="content" id="fileContent" rows="12"
                            placeholder="// File contents..."></textarea>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Create</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Rename -->
    <div class="modal fade" id="renameModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-tag me-2" style="color:var(--accent)"></i>Rename Item
                        </h5>
                    </div>
                    <div class="modal-body">
                        <label class="form-label">New Name</label>
                        <input type="text" name="new_name" class="form-control" id="newName">
                        <input type="hidden" name="old_name" id="oldName">
                        <input type="hidden" name="path" id="renamePath">
                        <input type="hidden" name="action" value="rename">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Rename</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Settings -->
    <div class="modal fade" id="settingsModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="post" id="workspace-settings-form">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-cog me-2" style="color:var(--accent)"></i>File Manager
                            Settings</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label" for="settings-root">Workspace root</label>
                            <div class="input-group"><input class="form-control" id="settings-root" name="workspace_root" value="<?= htmlspecialchars($config['root_path'], ENT_QUOTES, 'UTF-8') ?>" readonly><button type="button" class="btn btn-secondary" id="browse-workspace">Browse…</button></div>
                            <div class="form-text">Choose a folder accessible to PHP. Applied after Save Settings.</div>
                        </div><div class="mb-3">
                            <label class="form-label" for="settings-timezone">Timezone</label>
                            <select class="form-select" id="settings-timezone" name="timezone" required aria-describedby="timezone-preview timezone-browser-hint">
                                <?php foreach (array_unique(array_merge(timezone_identifiers_list(DateTimeZone::ALL), [$config['timezone']])) as $zone): ?>
                                    <option value="<?= htmlspecialchars($zone, ENT_QUOTES, 'UTF-8') ?>" <?= $config['timezone'] === $zone ? 'selected' : '' ?>><?= htmlspecialchars(str_replace('_', ' ', $zone), ENT_QUOTES, 'UTF-8') ?></option>
                                <?php endforeach; ?>
                            </select>
                            <div class="form-text" id="timezone-preview"></div>
                            <div class="form-text" id="timezone-browser-hint"></div>
                            <button type="button" class="btn btn-secondary mt-2" id="use-browser-timezone" hidden>Use browser timezone</button>
                            <input type="hidden" name="fm_auth_action" value="save_settings">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Date Format</label>
                            <input type="text" class="form-control" name="dateformat"
                                value="<?= htmlspecialchars($config['date_format']) ?>" placeholder="M j Y, H:i:s"
                                required>
                            <div class="form-text">PHP date() format string</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Font Size</label>
                            <input type="text" class="form-control" name="fontSize"
                                value="<?= htmlspecialchars($config['font_size']) ?>" placeholder="14px" required>
                        </div>
                        <section aria-labelledby="settings-password-heading" style="border-top:1px solid var(--border-subtle);margin-top:16px;padding-top:12px">
                            <h6 id="settings-password-heading">Change password</h6>
                            <p class="form-text">Leave all password fields empty to keep your current password.</p>
                            <label class="form-label" for="current-password">Current password</label><input class="form-control mb-2" type="password" id="current-password" name="current_password" autocomplete="current-password" maxlength="72">
                            <label class="form-label" for="new-password">New password</label><input class="form-control mb-2" type="password" id="new-password" name="new_password" autocomplete="new-password" minlength="12" maxlength="72">
                            <label class="form-label" for="confirm-password">Repeat new password</label><input class="form-control mb-3" type="password" id="confirm-password" name="confirm_password" autocomplete="new-password" minlength="12" maxlength="72">
                        </section>
                        <p class="form-text mb-0" id="settings-result" role="status" aria-live="polite"></p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Save Settings</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>

            </div>
        </div>
    </div>

    <!-- Permissions -->
    <div class="modal fade" id="permissionsModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-shield-alt me-2" style="color:var(--accent)"></i>Change
                            Permissions</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Item: <span id="permItem"
                                    style="color:var(--text-link)"></span></label>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Octal Value</label>
                            <input type="text" name="mode" class="form-control" id="permValue" placeholder="0755">
                            <input type="hidden" name="path" id="permissionPath">
                            <input type="hidden" name="item" id="permItemValue">
                            <input type="hidden" name="action" value="permissions">
                        </div>
                        <div class="row mb-2 g-2">
                            <div class="col-4">
                                <div class="border p-2" style="border-radius:var(--radius-sm)">
                                    <div class="form-text mb-1" style="color:var(--text-muted);font-weight:600">Owner
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="ownerRead" data-value="400"><label class="form-check-label">Read</label>
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="ownerWrite" data-value="200"><label
                                            class="form-check-label">Write</label></div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="ownerExec" data-value="100"><label
                                            class="form-check-label">Execute</label></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="border p-2" style="border-radius:var(--radius-sm)">
                                    <div class="form-text mb-1" style="color:var(--text-muted);font-weight:600">Group
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="groupRead" data-value="40"><label class="form-check-label">Read</label>
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="groupWrite" data-value="20"><label
                                            class="form-check-label">Write</label></div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="groupExec" data-value="10"><label
                                            class="form-check-label">Execute</label></div>
                                </div>
                            </div>
                            <div class="col-4">
                                <div class="border p-2" style="border-radius:var(--radius-sm)">
                                    <div class="form-text mb-1" style="color:var(--text-muted);font-weight:600">Public
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="publicRead" data-value="4"><label class="form-check-label">Read</label>
                                    </div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="publicWrite" data-value="2"><label
                                            class="form-check-label">Write</label></div>
                                    <div class="form-check"><input class="form-check-input perm-check" type="checkbox"
                                            id="publicExec" data-value="1"><label
                                            class="form-check-label">Execute</label></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Apply</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Compress -->
    <div class="modal fade" id="compressModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-file-archive me-2"
                                style="color:var(--accent-warning)"></i>Compress Items</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Archive Name</label>
                            <input type="text" class="form-control" name="name" id="compressName" placeholder="archive">
                            <input type="hidden" name="items" id="compressItems">
                            <input type="hidden" name="path" id="compressPath">
                            <input type="hidden" name="action" value="compress">
                        </div>
                        <div class="mb-2">
                            <label class="form-label mb-2">Format</label>
                            <div class="d-flex gap-3">
                                <div class="form-check"><input class="form-check-input" type="radio" name="type"
                                        id="compressZip" value="zip" checked><label class="form-check-label"
                                        for="compressZip">ZIP</label></div>
                                <div class="form-check"><input class="form-check-input" type="radio" name="type"
                                        id="compressTar" value="tar"><label class="form-check-label"
                                        for="compressTar">TAR</label></div>
                                <div class="form-check"><input class="form-check-input" type="radio" name="type"
                                        id="compressGzip" value="gzip"><label class="form-check-label"
                                        for="compressGzip">GZip (single file)</label></div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Compress</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Delete -->
    <div class="modal fade" id="deleteModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-trash me-2"
                                style="color:var(--accent-danger)"></i>Confirm Delete</h5>
                    </div>
                    <div class="modal-body">
                        <p style="font-size:0.82rem;color:var(--text-secondary)">Are you sure you want to delete the
                            selected item(s)?</p>
                        <ul id="delete-item-names" aria-label="Items to delete" style="max-height:180px;overflow:auto;padding-left:20px;overflow-wrap:anywhere;color:var(--text-primary)"></ul>
                        <input type="hidden" name="items" id="deleteItems">
                        <input type="hidden" name="path" id="deletePath">
                        <input type="hidden" name="action" id="deleteAction" value="trash">
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" id="permanentDeleteCheck">
                            <label class="form-check-label" for="permanentDeleteCheck">Permanently delete (skip
                                trash)</label>
                        </div>
                        <div class="alert alert-info" id="deleteInfoAlert">
                            <i class="fas fa-recycle me-1"></i> Items will be moved to trash and can be restored.
                        </div>
                        <div class="alert alert-danger" id="permanentDeleteAlert" style="display:none">
                            <i class="fas fa-exclamation-triangle me-1"></i> <strong>Warning:</strong> This cannot be
                            undone.
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span id="deleteButtonText">Move to Trash</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="modal fade" id="phoneModal" tabindex="-1" aria-labelledby="phoneModalTitle" aria-hidden="true">
        <div class="modal-dialog"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="phoneModalTitle"><i class="fas fa-qrcode me-2"></i>Open on phone</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body text-center">
                <p id="phone-file-name" style="overflow-wrap:anywhere"></p>
                <p id="phone-qr-status" role="status" aria-live="polite"></p>
                <button type="button" id="phone-qr-retry" class="btn btn-secondary mb-3" hidden>Retry</button>
                <canvas hidden id="phone-qr" role="img" aria-label="QR code with the file URL" style="width:min(280px,100%);height:auto;margin:0 auto 16px;background:white"></canvas>
                <p>Scan with your phone camera to open this file.</p>
                <a id="phone-file-link" target="_blank" rel="noopener noreferrer" style="overflow-wrap:anywhere"></a>
                <p class="form-text mt-2">Opens the saved file on the website, just like Open in browser.</p>
            </div>
            <div class="modal-footer"><button type="button" id="phone-copy-link" class="btn btn-primary">Copy link</button><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
        </div></div>
    </div>

    <dialog id="folder-picker" aria-labelledby="folder-picker-title">
        <div class="folder-picker-head"><strong id="folder-picker-title">Choose folder</strong><span id="folder-picker-path"></span>
        <button type="button" id="folder-picker-home">Home</button><button type="button" id="folder-picker-up">Up</button><button type="button" id="folder-picker-website">Website folder</button></div>
        <div id="folder-picker-list"></div><p id="folder-picker-message" role="status"></p>
        <div class="folder-picker-footer" style="justify-content:flex-end"><button type="button" id="folder-picker-cancel">Cancel</button><button type="button" id="folder-picker-use">Use this folder</button></div>
    </dialog>

    <div class="modal fade" id="uploadReplaceModal" tabindex="-1" aria-labelledby="uploadReplaceTitle" aria-hidden="true">
        <div class="modal-dialog"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="uploadReplaceTitle">Replace existing files?</h5></div>
            <div class="modal-body"><p>These files already exist in the destination folder. Replace them with the uploaded versions?</p><ul id="upload-replace-names" style="max-height:40vh;overflow:auto;overflow-wrap:anywhere"></ul></div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-primary" id="upload-replace-confirm">Replace</button></div>
        </div></div>
    </div>

    <div class="modal fade" id="githubModal" tabindex="-1" aria-labelledby="githubTitle" aria-hidden="true" data-bs-backdrop="static">
        <div class="modal-dialog modal-lg"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="githubTitle"><i class="fa-brands fa-github me-2"></i>GitHub · Commit &amp; Push</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">
                <p id="github-branch" class="form-text"></p>
                <details><summary>Connection settings</summary>
                    <form id="github-settings" class="mt-2">
                        <label class="form-label" for="github-url">Repository URL</label><input id="github-url" name="url" class="form-control mb-2" placeholder="https://github.com/owner/repository.git" required>
                        <label class="form-label" for="github-target-branch">Branch (must match local branch)</label><input id="github-target-branch" name="branch" class="form-control mb-2" required>
                        <div class="row"><div class="col-sm-6"><label class="form-label" for="github-name">Commit author</label><input id="github-name" name="name" class="form-control mb-2" required></div><div class="col-sm-6"><label class="form-label" for="github-email">Author email</label><input id="github-email" name="email" type="email" class="form-control mb-2" required></div></div>
                        <label class="form-label" for="github-token">GitHub token</label><input id="github-token" name="token" type="password" class="form-control" autocomplete="new-password" placeholder="Leave blank to keep the saved token">
                        <p id="github-token-state" class="form-text"></p>
                        <p class="form-text"><a href="https://github.com/settings/personal-access-tokens/new?name=Pocket%20Code%20Studio&amp;contents=write&amp;expires_in=90" target="_blank" rel="noopener noreferrer"><i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i> Create GitHub token</a> — choose Only select repositories and select your repository.</p>
                        <p class="form-text">Use a fine-grained token for this repository with Contents: Read and write. Workflow files may also require Workflows permission. Stored privately on this server, never in the repository.</p>
                        <label class="form-check-label mb-2"><input type="checkbox" name="remove_token" value="1" class="form-check-input"> Remove saved token</label><br>
                        <button type="submit" class="btn btn-secondary">Save connection</button>
                    </form>
                </details>
                <hr><p class="form-text">Select saved files to commit. No files are selected automatically. Unsaved editor changes are not included.</p>
                <button type="button" id="github-select-all" class="btn btn-secondary btn-sm mb-2"><i class="fas fa-check-square" aria-hidden="true"></i> Select all</button>
                <div id="github-files" class="border rounded p-2" style="max-height:30vh;overflow:auto"></div>
                <label class="form-label mt-2" for="github-message">Commit message</label><textarea id="github-message" class="form-control" rows="2" maxlength="4000"></textarea>
                <p id="github-feedback" class="form-text mt-2" role="status" aria-live="polite" style="white-space:pre-line;overflow-wrap:anywhere"></p>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" id="github-refresh">Refresh</button><button type="button" class="btn btn-secondary" id="github-push">Push existing commits</button><button type="button" class="btn btn-primary" id="github-commit">Commit &amp; Push</button><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
        </div></div>
    </div>

    <div class="modal fade" id="loginActivityModal" tabindex="-1" aria-labelledby="loginActivityTitle" aria-hidden="true">
        <div class="modal-dialog modal-lg"><div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="loginActivityTitle"><i class="fas fa-shield-halved me-2"></i>Login activity</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">
                <p id="login-activity-summary"></p><div id="login-global-limit" class="alert alert-warning" hidden></div>
                <div class="table-responsive"><table class="table table-hover"><thead><tr><th>IP</th><th>Last attempt</th><th>Failed · 24h</th><th>Status</th><th></th></tr></thead><tbody id="login-activity-rows"></tbody></table></div>
                <div id="login-activity-details" class="border rounded p-2 my-2" style="overflow-wrap:anywhere;max-height:35vh;overflow:auto" hidden></div>
                <p class="form-text">Select an IP for details. Times use your browser timezone. The journal keeps up to 7 days, 2,000 entries and 1 MB; repeated blocked requests are grouped. Statistics use retained entries.</p>
                <form id="login-policy-form" class="border rounded p-2 mt-3">
                    <strong>Login limits</strong>
                    <div class="row g-2 mt-1">
                        <label class="col-sm-4 form-label">Failed attempts per IP<input class="form-control" type="number" name="per_ip" min="1" max="100" required></label>
                        <label class="col-sm-4 form-label">Global failed attempts<input class="form-control" type="number" name="global" min="1" max="1000" required></label>
                        <label class="col-sm-4 form-label">Window (minutes)<input class="form-control" type="number" name="window_minutes" min="1" max="1440" required></label>
                    </div><button type="submit" class="btn btn-primary mt-2">Save limits</button>
                    <p class="form-text mt-2 mb-0">The global limit can block all new logins. Resetting an IP does not reset the global limit. IPs are recorded as reported by PHP; proxies may share one address. Limits and activity use private server temporary storage and may be cleared by hosting cleanup.</p>
                </form>
                <p id="login-activity-feedback" class="form-text mt-2 mb-0" role="status"></p>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" id="login-activity-refresh">Refresh</button><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
        </div></div>
    </div>

    <!-- Search Results -->
    <div class="modal fade" id="searchModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-search me-2" style="color:var(--accent)"></i>Search Results
                    </h5>
                </div>
                <div class="modal-body" style="padding:0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0" id="search-results-table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Path</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th>Modified</th>
                                </tr>
                            </thead>
                            <tbody id="search-results">
                                <tr>
                                    <td colspan="5" class="text-center" style="padding:24px;color:var(--text-muted)">
                                        Searching…</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Copy / Move -->
    <div class="modal fade" id="fileOperationModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title" id="fileOpTitle">File Operation</h5>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" name="action" id="fileOpType" value="copy">
                        <div class="mb-3" id="fileOpItems" style="font-size:0.8rem;color:var(--text-secondary)"></div>
                        <div class="mb-2">
                            <label class="form-label">Destination Path</label>
                            <div class="input-group"><input type="text" name="destination" class="form-control" id="destinationPath"
                                placeholder="/path/to/destination" required><button type="button" class="btn btn-secondary" id="browse-destination">Browse…</button></div>
                            <input type="hidden" name="path" id="copyPath">
                            <input type="hidden" name="items" id="copyItems">
                            <div class="form-text">Current: <span id="currentPathDisplay"
                                    style="color:var(--text-link)"></span></div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Execute</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Restore -->
    <div class="modal fade" id="restoreModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
        <div class="modal-dialog">
            <div class="modal-content">
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <input type="hidden" name="path" id="restorePath">
                    <input type="hidden" name="items" id="restoreItems">
                    <input type="hidden" name="action" value="restore">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-undo me-2"
                                style="color:var(--accent-success)"></i>Restore Items</h5>
                    </div>
                    <div class="modal-body">
                        <p style="font-size:0.82rem;color:var(--text-secondary)">Restore selected items to their
                            original locations?</p>
                        <ul id="restoreItemsList" class="list-group mb-3" style="font-size:0.8rem"></ul>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-1"></i> If an item exists at the destination, it will be
                            renamed automatically.
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary d-flex align-items-center gap-2">
                            <span>Restore</span>
                            <div class="spinner-container my-indicator">
                                <div class="spinners"></div>
                            </div>
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- ── Scripts ───────────────────────────────────────────────── -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        var SERVER_ROOT_PATH = <?= json_encode($config['root_path'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const PUBLIC_WORKSPACE_BASE = <?= json_encode($publicWorkspaceBase, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const PUBLIC_WEBSITE_PREFIX = <?= json_encode($publicWebsitePrefix, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const WEBSITE_FOLDER = <?= json_encode(realpath($_SERVER['DOCUMENT_ROOT']), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    </script>

    <div class="modal fade" id="aboutPocketModal" tabindex="-1" aria-labelledby="aboutPocketTitle" aria-hidden="true"><div class="modal-dialog"><div class="modal-content">
        <div class="modal-header"><h5 class="modal-title" id="aboutPocketTitle">Pocket Code Studio</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
        <div class="modal-body"><p>A single-file PHP workspace maintained by <a href="https://github.com/Renat2985" target="_blank" rel="noopener noreferrer">Renat2985</a>.</p>
        <p><a href="https://github.com/Renat2985/pocket-code-studio" target="_blank" rel="noopener noreferrer">Project, documentation &amp; issues</a></p>
        <p>Based on Joseph Chuks’ <a href="https://github.com/JosephChuks/php-file-manager-with-code-editor" target="_blank" rel="noopener noreferrer">PHP File Manager</a> and <a href="https://github.com/JosephChuks/cwp-codeEditor" target="_blank" rel="noopener noreferrer">CWP Code Editor</a>. Editor powered by Ace; icons from Material Icon Theme and Seti UI.</p>
        <p>Interface inspired by Visual Studio Code. Independent project, not affiliated with Microsoft. Original authorship and license notices are retained in the source and repository.</p></div>
    </div></div></div>
    <script>

        const fileIconData = <?= json_encode($fileIconData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        const materialIconData = <?= json_encode($materialIconData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        function materialIconSource(name, directory = false) {
            const lower = name.toLowerCase();
            const extension = lower.includes('.') ? lower.split('.').pop() : '';
            const id = directory ? (materialIconData.folders[lower] || 'folder-base') : (materialIconData.names[lower] || materialIconData.extensions[extension]);
            return id ? materialIconData.icons[id] : null;
        }
        function updateFolderIcon(element, name) {
            const image = document.createElement('img');
            image.src = materialIconSource(name, true);
            image.alt = '';
            image.width = image.height = 20;
            element.replaceChildren(image);
        }
        function createFileIcon(name, directory = false) {
            const element = document.createElement('span');
            element.className = 'file-type-icon';
            element.setAttribute('aria-hidden', 'true');
            if (directory) {
                element.classList.add('folder-type-icon');
                updateFolderIcon(element, name);
                return element;
            }
            const materialSource = materialIconSource(name);
            if (materialSource) {
                const image = document.createElement('img');
                image.src = materialSource;
                image.alt = '';
                image.width = image.height = 20;
                element.append(image);
                return element;
            }
            const lower = name.toLowerCase();
            let id = fileIconData.names[lower];
            let lightId = fileIconData.lightNames[lower];
            const parts = lower.split('.');
            if (!id) {
                for (let i = 1; i < parts.length; i++) {
                    const ext = parts.slice(i).join('.');
                    if (fileIconData.extensions[ext]) {
                        id = fileIconData.extensions[ext];
                        lightId = fileIconData.lightExtensions[ext] || id;
                        break;
                    }
                }
            }
            const icon = fileIconData.icons[id || fileIconData.default];
            const light = fileIconData.icons[lightId || id || fileIconData.lightDefault];
            element.textContent = icon.char;
            element.style.setProperty('--file-icon-color', icon.color);
            element.style.setProperty('--file-icon-light-color', light.color);
            return element;
        }

        document.addEventListener('DOMContentLoaded', function() {

            const settingsForm = document.getElementById('workspace-settings-form');
            const settingsResult = document.getElementById('settings-result');
            const timezoneSelect = document.getElementById('settings-timezone');
            const timezonePreview = document.getElementById('timezone-preview');
            const timezoneHint = document.getElementById('timezone-browser-hint');
            const useBrowserTimezone = document.getElementById('use-browser-timezone');
            let browserTimezone = null;
            let timezonePreviewTimer = null;
            try { browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch (_) {}
            function updateTimezonePreview() {
                try {
                    timezonePreview.textContent = 'Current time: ' + new Intl.DateTimeFormat('en-GB', {
                        timeZone: timezoneSelect.value, year: 'numeric', month: 'short', day: '2-digit',
                        hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short'
                    }).format(new Date());
                } catch (_) { timezonePreview.textContent = 'Time preview is unavailable for this timezone.'; }
                const supported = browserTimezone && [...timezoneSelect.options].some(option => option.value === browserTimezone);
                timezoneHint.textContent = !browserTimezone ? 'Your browser did not provide a timezone. Choose one from the list.'
                    : 'Browser timezone: ' + browserTimezone + (supported ? '. Applied only after Save Settings.' : ' (not supported by this server).');
                useBrowserTimezone.hidden = !supported || timezoneSelect.value === browserTimezone;
            }
            useBrowserTimezone.addEventListener('click', () => {
                if ([...timezoneSelect.options].some(option => option.value === browserTimezone)) {
                    timezoneSelect.value = browserTimezone;
                    updateTimezonePreview();
                }
            });
            timezoneSelect.addEventListener('change', updateTimezonePreview);
            document.getElementById('settingsModal').addEventListener('show.bs.modal', () => {
                updateTimezonePreview();
                clearInterval(timezonePreviewTimer);
                timezonePreviewTimer = setInterval(updateTimezonePreview, 1000);
            });

            let settingsSaving = false;
            settingsForm.addEventListener('submit', async event => {
                event.preventDefault();
                if (settingsSaving) return;
                const rootChanged = document.getElementById('settings-root').value !== SERVER_ROOT_PATH;
                if (rootChanged && [...editorTabs.values()].some(tabHasChanges)) { window.workspaceAlert('Save your open files before switching the workspace folder.', 'Unsaved changes', 'warning'); return; }
                settingsSaving = true;
                const buttons = [...settingsForm.querySelectorAll('button')];
                buttons.forEach(button => { button.disabled = true; });
                settingsResult.textContent = 'Saving settings…';
                try {
                    const response = await fetch(location.pathname, {method: 'POST', body: new FormData(settingsForm)});
                    const data = await response.json();
                    settingsResult.textContent = data.message || 'Could not save settings.';
                    if (response.ok && data.status === 'success') {
                        if (rootChanged) { location.reload(); return; }
                        settingsForm.querySelectorAll('input:not([type="password"])').forEach(input => { input.defaultValue = input.value; });
                        settingsForm.querySelectorAll('select').forEach(select => {
                            const selected = select.value;
                            [...select.options].forEach(option => { option.defaultSelected = option.value === selected; });
                            select.value = selected;
                        });
                        settingsForm.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
                        document.documentElement.style.setProperty('--font-size', settingsForm.elements.fontSize.value);
                        loadFileList();
                        bootstrap.Modal.getOrCreateInstance(document.getElementById('settingsModal')).hide();
                    }
                } catch (_) { settingsResult.textContent = 'Could not confirm saving. Your values remain in the form; reload to check the current settings.'; }
                finally { settingsSaving = false; buttons.forEach(button => { button.disabled = false; }); }
            });
            document.getElementById('settingsModal').addEventListener('hidden.bs.modal', () => {
                clearInterval(timezonePreviewTimer);
                settingsForm.reset();
                settingsForm.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
                settingsResult.textContent = '';
            });
            document.getElementById('logout-form').addEventListener('submit', async event => {
                event.preventDefault();
                const data = new FormData(event.currentTarget);
                const response = await fetch(location.pathname, {method: 'POST', body: data});
                if (response.ok) location.replace(location.pathname);
            });

            const sidebar = document.getElementById('file-sidebar');
            const sidebarResizer = document.getElementById('sidebar-resizer');
            const layout = document.querySelector('.fm-layout');
            let preferredSidebarWidth = parseInt(sidebar.style.getPropertyValue('--sidebar-width'), 10) || 220;
            let resizingPointer = null;
            let resizeStartX = 0;
            let resizeStartWidth = 0;
            function resizeSidebar(width, remember = false) {
                const maximum = Math.max(140, Math.min(700, layout.clientWidth - 285));
                const applied = Math.round(Math.max(140, Math.min(maximum, width)));
                sidebar.style.setProperty('--sidebar-width', applied + 'px');
                sidebarResizer.setAttribute('aria-valuemax', String(maximum));
                sidebarResizer.setAttribute('aria-valuenow', String(applied));
                if (remember) {
                    preferredSidebarWidth = applied;
                    document.cookie = 'fm_sidebar_width=' + applied + '; Max-Age=31536000; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
                }
            }
            sidebarResizer.addEventListener('pointerdown', event => {
                if (event.button !== 0) return;
                event.preventDefault();
                resizingPointer = event.pointerId;
                resizeStartX = event.clientX;
                resizeStartWidth = sidebar.getBoundingClientRect().width;
                sidebarResizer.setPointerCapture(event.pointerId);
                document.body.classList.add('resizing-sidebar');
            });
            sidebarResizer.addEventListener('pointermove', event => {
                if (event.pointerId === resizingPointer) resizeSidebar(resizeStartWidth + event.clientX - resizeStartX);
            });
            function finishSidebarResize(event) {
                if (event.pointerId !== resizingPointer) return;
                resizingPointer = null;
                document.body.classList.remove('resizing-sidebar');
                resizeSidebar(sidebar.getBoundingClientRect().width, true);
            }
            sidebarResizer.addEventListener('pointerup', finishSidebarResize);
            sidebarResizer.addEventListener('pointercancel', finishSidebarResize);
            sidebarResizer.addEventListener('lostpointercapture', finishSidebarResize);
            sidebarResizer.addEventListener('dblclick', () => resizeSidebar(220, true));
            sidebarResizer.addEventListener('keydown', event => {
                const width = sidebar.getBoundingClientRect().width;
                const step = event.shiftKey ? 50 : 10;
                if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
                    event.preventDefault();
                    resizeSidebar(width + (event.key === 'ArrowLeft' ? -step : step), true);
                }
            });
            new ResizeObserver(() => resizeSidebar(preferredSidebarWidth)).observe(layout);
            resizeSidebar(preferredSidebarWidth);

            let currentPath = '';
            let selectedItems = [];
            let fileList = [];
            let currentSort = 'name';
            let currentOrder = 'asc';
            let contextTarget = null;
            let treeContextSelection = null;
            let clickedBtn = null;
            let hasResponseError = false;

            function createGitStatusBadge(status) {
                if (status.length > 1) status = status === '??' ? 'U' : status.includes('D') ? 'D' : status.includes('A') ? 'A' : 'M';
                const badge = document.createElement('span');
                badge.className = 'git-status-badge'; badge.textContent = status;
                badge.title = {M:'Modified compared with Git',U:'Untracked file',A:'Added to Git',D:'Deleted'}[status] || status;
                return badge;
            }
            const githubModal = document.getElementById('githubModal');
            const githubForm = document.getElementById('github-settings');
            const githubFeedback = document.getElementById('github-feedback');
            let githubState = null, githubBusy = false;
            function renderGitHub(data) {
                githubState = data.repository;
                document.getElementById('github-branch').textContent = 'Local branch: ' + githubState.branch + ' · HEAD: ' + githubState.head.slice(0, 8);
                for (const key of ['url','branch','name','email']) githubForm.elements[key].value = data.settings[key] || (key === 'branch' ? githubState.branch : '');
                githubForm.elements.token.value = ''; githubForm.elements.remove_token.checked = false;
                document.getElementById('github-token-state').textContent = data.settings.has_token ? 'Token saved. Leave blank to keep it.' : 'No token saved.';
                githubForm.closest('details').open = !data.settings.has_token;
                const list = document.getElementById('github-files'); list.replaceChildren();
                if (!githubState.files.length) list.textContent = 'No changed files. Use Push existing commits to retry a previous push.';
                githubState.files.forEach(file => {
                    const label = document.createElement('label'); label.className = 'd-flex align-items-center gap-2 py-1';
                    const input = document.createElement('input'); input.type = 'checkbox'; input.className = 'form-check-input'; input.value = file.path; input.disabled = !file.allowed;
                    const text = document.createElement('span'); text.textContent = file.path + (file.allowed ? '' : ' (unsupported: directory, symlink or large file)'); text.style.overflowWrap = 'anywhere';
                    label.append(input, text, createGitStatusBadge(file.status)); list.append(label);
                });
            }
            async function githubOperation(operation, fields = {}) {
                if (githubBusy) return;
                githubBusy = true;
                const controls = [...githubModal.querySelectorAll('button,input,textarea,summary')];
                const disabled = controls.map(control => control.disabled);
                controls.forEach(control => { control.disabled = true; });
                githubFeedback.textContent = operation === 'commit_push' ? 'Creating commit and pushing…' : operation === 'push' ? 'Pushing…' : 'Loading…';
                try {
                    if (operation === 'commit_push') {
                        const prepared = await requestWorkspace('github', {operation:'prepare', files:fields.files, preview:fields.preview, head:fields.head, branch:fields.branch});
                        const selected = new Set(JSON.parse(fields.files));
                        fields.preview = JSON.stringify(prepared.repository.files.filter(file => selected.has(file.path)));
                    }
                    const data = await requestWorkspace('github', {operation, ...fields});
                    if (operation === 'push') {
                        githubState.head = data.repository.head; githubState.branch = data.repository.branch;
                    } else renderGitHub(data);
                    githubFeedback.textContent = data.message || '';
                    if (operation === 'commit_push' || operation === 'push') {
                        document.getElementById('github-message').value = '';
                        gitStatusUnavailable = false; refreshGitStatus();
                        window.workspaceToast('Changes pushed to GitHub.', 'GitHub');
                    }
                } catch (error) {
                    const hint = operation === 'commit_push' && error.committed === false ? '\nNo new commit was created. Refresh the list and review the selected files.' : (operation === 'commit_push' || operation === 'push' ? '\nRefresh before retrying. Use Push existing commits if the local commit already exists.' : '');
                    githubFeedback.textContent = error.message + hint;
                    if (operation === 'commit_push' || operation === 'push') githubState = null;
                } finally {
                    controls.forEach((control, index) => { control.disabled = disabled[index]; });
                    // Rendering may replace the file checkboxes while the request is in progress.
                    githubBusy = false;
                }
            }
            githubModal.addEventListener('shown.bs.modal', () => githubOperation('read'));
            githubModal.addEventListener('hide.bs.modal', event => { if (githubBusy) event.preventDefault(); });
            githubModal.addEventListener('hidden.bs.modal', () => { githubForm.elements.token.value = ''; });
            githubForm.addEventListener('submit', event => {
                event.preventDefault();
                const fields = Object.fromEntries(new FormData(githubForm));
                githubForm.elements.token.value = '';
                githubOperation('save', fields);
            });
            document.getElementById('github-refresh').addEventListener('click', () => githubOperation('read'));
            document.getElementById('github-select-all').addEventListener('click', () => {
                if (githubBusy) return;
                document.querySelectorAll('#github-files input:not(:disabled)').forEach(input => { input.checked = true; });
            });
            function startGitHubPush(commit) {
                if (!githubState) { githubFeedback.textContent = 'Refresh the repository first.'; return; }
                if (commit && [...editorTabs.values()].some(tab => tab.dirty)) { githubFeedback.textContent = 'Save or close unsaved editor tabs before pushing.'; return; }
                const files = [...document.querySelectorAll('#github-files input:checked')].map(input => input.value);
                const message = document.getElementById('github-message').value.trim();
                if (commit && (!files.length || !message)) { githubFeedback.textContent = 'Select files and enter a commit message.'; return; }
                githubOperation(commit ? 'commit_push' : 'push', {head: githubState.head, branch: githubState.branch, preview: JSON.stringify(githubState.files.filter(file => files.includes(file.path))), files: JSON.stringify(files), message});
            }
            document.getElementById('github-commit').addEventListener('click', () => startGitHubPush(true));
            document.getElementById('github-push').addEventListener('click', () => startGitHubPush(false));

            const loginActivityModal = document.getElementById('loginActivityModal');
            const loginActivityRows = document.getElementById('login-activity-rows');
            const loginActivityFeedback = document.getElementById('login-activity-feedback');
            const loginPolicyForm = document.getElementById('login-policy-form');
            let loginActivityBusy = false, loginActivityClock = null, loginActivityOffset = 0;
            const loginDate = timestamp => timestamp ? new Date(timestamp * 1000).toLocaleString('en-GB') : '—';
            const loginResultLabels = {success:'Success', wrong_password:'Wrong password', blocked:'Blocked', limit_reset:'Limit reset', global_limit_reset:'Global limit reset', policy_changed:'Limits changed'};
            function updateLoginActivityTimers() {
                const now = Date.now() / 1000 + loginActivityOffset;
                loginActivityModal.querySelectorAll('[data-login-until]').forEach(label => {
                    const remaining = Math.max(0, Math.ceil(Number(label.dataset.loginUntil) - now));
                    label.textContent = remaining ? (label.dataset.loginScope === 'global' ? 'Global block · ' : 'Blocked · ') + Math.ceil(remaining / 60) + ' min' : 'Expired · refresh';
                });
            }
            function showLoginDetails(row) {
                const panel = document.getElementById('login-activity-details'); panel.hidden = false; panel.replaceChildren();
                const heading = document.createElement('strong'); heading.textContent = row.ip; panel.append(heading);
                for (const [label, value] of [['First recorded',loginDate(row.first)],['Last attempt',loginDate(row.last)],['Last success',loginDate(row.last_success)],['Browser',row.agent || 'Not recorded']]) {
                    const line = document.createElement('p'); line.className = 'mb-1'; line.textContent = label + ': ' + value; panel.append(line);
                }
                const events = document.createElement('ul'); events.className = 'mt-2 mb-0';
                row.events.forEach(event => {
                    const item = document.createElement('li');
                    item.textContent = loginDate(event.last) + ' · ' + (loginResultLabels[event.result] || event.result) + (event.count > 1 ? ' × ' + event.count : '') + (event.actor ? ' · by ' + event.actor : '');
                    events.append(item);
                });
                panel.append(events);
            }
            function renderLoginActivity(data) {
                loginActivityOffset = data.now - Date.now() / 1000;
                document.getElementById('login-activity-summary').textContent = 'Failures (24h): ' + data.failures_24h + ' · Blocked IPs: ' + data.blocked_ips + ' · Last success: ' + loginDate(data.last_success);
                const global = document.getElementById('login-global-limit'); global.hidden = !data.global_blocked_until; global.replaceChildren();
                if (data.global_blocked_until) {
                    const text = document.createElement('span'); text.textContent = 'Global login limit is active until ' + loginDate(data.global_blocked_until) + '. ';
                    const reset = document.createElement('button'); reset.type = 'button'; reset.className = 'btn btn-secondary btn-sm'; reset.textContent = 'Reset global limit';
                    reset.addEventListener('click', () => loadLoginActivity('reset', {key:'global'})); global.append(text, reset);
                }
                loginActivityRows.replaceChildren();
                if (!data.rows.length) {
                    const row = document.createElement('tr'), cell = document.createElement('td'); cell.colSpan = 5; cell.textContent = 'No login activity recorded yet.'; row.append(cell); loginActivityRows.append(row);
                }
                data.rows.forEach(item => {
                    const row = document.createElement('tr'); row.tabIndex = 0; row.style.cursor = 'pointer';
                    const values = [item.ip + (item.ip === data.current_ip ? ' (you)' : ''),loginDate(item.last),String(item.failures)];
                    values.forEach(value => { const cell = document.createElement('td'); cell.textContent = value; row.append(cell); });
                    const state = document.createElement('td');
                    if (item.blocked_until || data.global_blocked_until) {
                        const badge = document.createElement('span'); badge.dataset.loginUntil = item.blocked_until || data.global_blocked_until; badge.dataset.loginScope = item.blocked_until ? 'ip' : 'global'; badge.style.color = 'var(--accent-warning)'; state.append(badge);
                    } else state.textContent = 'Allowed';
                    row.append(state);
                    const actions = document.createElement('td');
                    if (item.attempts > 0) {
                        const reset = document.createElement('button'); reset.type = 'button'; reset.className = 'btn btn-secondary btn-sm'; reset.textContent = 'Reset limit';
                        reset.addEventListener('click', event => { event.stopPropagation(); loadLoginActivity('reset', {key:item.key}); }); actions.append(reset);
                    }
                    row.append(actions);
                    row.addEventListener('click', () => showLoginDetails(item));
                    row.addEventListener('keydown', event => { if (event.target !== row) return; if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); showLoginDetails(item); } });
                    loginActivityRows.append(row);
                });
                for (const key of ['per_ip','global','window_minutes']) loginPolicyForm.elements[key].value = data.policy[key];
                document.getElementById('login-activity-details').hidden = true;
                updateLoginActivityTimers();
            }
            async function loadLoginActivity(operation = 'read', fields = {}) {
                if (loginActivityBusy) return;
                loginActivityBusy = true; loginActivityFeedback.textContent = operation === 'read' ? 'Loading…' : 'Saving…';
                loginActivityModal.querySelectorAll('button:not([data-bs-dismiss])').forEach(button => { button.disabled = true; });
                try {
                    const data = await requestWorkspace('login_activity', {operation, ...fields});
                    renderLoginActivity(data); loginActivityFeedback.textContent = operation === 'read' ? '' : 'Saved.';
                } catch (error) { loginActivityFeedback.textContent = error.message || 'Could not load login activity.'; }
                finally { loginActivityBusy = false; loginActivityModal.querySelectorAll('button:not([data-bs-dismiss])').forEach(button => { button.disabled = false; }); }
            }
            loginActivityModal.addEventListener('shown.bs.modal', () => {
                loadLoginActivity(); clearInterval(loginActivityClock); loginActivityClock = setInterval(updateLoginActivityTimers, 1000);
            });
            loginActivityModal.addEventListener('hidden.bs.modal', () => { clearInterval(loginActivityClock); });
            document.getElementById('login-activity-refresh').addEventListener('click', () => loadLoginActivity());
            loginPolicyForm.addEventListener('submit', event => {
                event.preventDefault();
                if (!loginPolicyForm.reportValidity()) return;
                loadLoginActivity('policy', {per_ip:loginPolicyForm.elements.per_ip.value, global:loginPolicyForm.elements.global.value, window_minutes:loginPolicyForm.elements.window_minutes.value});
            });

            const folderPicker = document.getElementById('folder-picker');
            const pickerList = document.getElementById('folder-picker-list');
            const pickerMessage = document.getElementById('folder-picker-message');
            const pickerUse = document.getElementById('folder-picker-use');
            const pickerUp = document.getElementById('folder-picker-up');
            let pickerScope, pickerTarget, pickerFolder, pickerParent, pickerRequest = 0;
            async function loadPickerFolder(folder) {
                const request = ++pickerRequest;
                pickerUse.disabled = true; pickerUp.disabled = true;
                pickerMessage.textContent = 'Loading folders…'; pickerList.replaceChildren();
                try {
                    const data = await requestWorkspace('browse_folders', {scope: pickerScope, folder});
                    if (request !== pickerRequest || !folderPicker.open) return;
                    pickerFolder = data.folder; pickerParent = data.parent;
                    document.getElementById('folder-picker-path').textContent = pickerFolder;
                    pickerUp.disabled = pickerParent === null; pickerUse.disabled = false;
                    pickerMessage.textContent = data.folders.length ? '' : 'No subfolders. You can select this folder.';
                    data.folders.forEach(item => {
                        const button = document.createElement('button'); button.type = 'button'; button.disabled = !item.readable;
                        const icon = document.createElement('i'); icon.className = 'fas fa-folder'; icon.setAttribute('aria-hidden', 'true');
                        button.append(icon, document.createTextNode(item.name + (item.readable ? '' : ' (no access)')));
                        button.addEventListener('click', () => loadPickerFolder(item.path)); pickerList.append(button);
                    });
                } catch (error) {
                    if (request !== pickerRequest || !folderPicker.open) return;
                    pickerMessage.textContent = error.message;
                    pickerUp.disabled = !pickerFolder || pickerParent === null;
                }
            }
            function openFolderPicker(input, scope) {
                pickerScope = scope; pickerTarget = input; pickerFolder = null; pickerParent = null;
                (input.closest('.modal') || document.body).append(folderPicker);
                document.getElementById('folder-picker-title').textContent = scope === 'server' ? 'Choose workspace folder' : 'Choose destination folder';
                document.getElementById('folder-picker-website').hidden = scope !== 'server';
                folderPicker.showModal();
                loadPickerFolder(input.value || (scope === 'server' ? SERVER_ROOT_PATH : '/'));
            }
            document.getElementById('browse-workspace').addEventListener('click', () => openFolderPicker(document.getElementById('settings-root'), 'server'));
            document.getElementById('browse-destination').addEventListener('click', () => openFolderPicker(document.getElementById('destinationPath'), 'workspace'));
            document.getElementById('folder-picker-home').addEventListener('click', () => loadPickerFolder(pickerScope === 'server' ? SERVER_ROOT_PATH : '/'));
            document.getElementById('folder-picker-website').addEventListener('click', () => loadPickerFolder(WEBSITE_FOLDER));
            pickerUp.addEventListener('click', () => { if (pickerParent !== null) loadPickerFolder(pickerParent); });
            document.getElementById('folder-picker-cancel').addEventListener('click', () => folderPicker.close());
            pickerUse.addEventListener('click', () => {
                if (pickerUse.disabled) return;
                pickerTarget.value = pickerFolder;
                pickerTarget.dispatchEvent(new Event('input', {bubbles:true}));
                folderPicker.close();
            });
            folderPicker.addEventListener('close', () => { pickerRequest++; pickerTarget?.focus(); });

            // ── File list ─────────────────────────────────────────────
            async function requestWorkspace(action, fields = {}, options = {}) {
                const body = fields instanceof FormData ? fields : new FormData();
                body.set('action', action);
                if (!(fields instanceof FormData)) for (const [key, value] of Object.entries(fields)) body.set(key, value);
                const response = await fetch(window.location.pathname, {...options, method: 'POST', body});
                let data;
                try { data = await response.json(); }
                catch (_) { throw new Error('The server returned an invalid response (HTTP ' + response.status + '). Reload the page and try again.'); }
                if (!response.ok || data?.status !== 'success') {
                    const error = new Error(data?.message || 'Request failed (HTTP ' + response.status + ')');
                    if (typeof data?.committed === 'boolean') error.committed = data.committed;
                    throw error;
                }
                return data;
            }

            let fileListController = null;
            let fileListRequest = 0;
            async function loadFileList() {
                const request = ++fileListRequest;
                fileListController?.abort();
                fileListController = new AbortController();
                refreshGitStatus();
                const tbody = document.getElementById('files-list');
                tbody.innerHTML = `<tr><td colspan="8" style="padding:32px;text-align:center;color:var(--text-muted)">
                <i class="fas fa-spinner fa-spin me-2"></i> Loading files…</td></tr>`;
                selectedItems = [];
                fileList = [];
                updateButtonStates();
                try {
                    const data = await requestWorkspace('list', {path: currentPath, sort: currentSort, order: currentOrder}, {signal: fileListController.signal});
                    if (request !== fileListRequest) return;
                    fileList = data.data;
                    if (data.current_path !== undefined) currentPath = data.current_path;
                    updateBreadcrumb(currentPath);
                    showFiles(fileList);
                } catch (error) {
                    if (request !== fileListRequest || error.name === 'AbortError') return;
                    const row = document.createElement('tr');
                    const cell = document.createElement('td');
                    cell.colSpan = 8; cell.style.padding = '20px';
                    cell.textContent = error.message || 'Failed to load file list';
                    row.append(cell); tbody.replaceChildren(row);
                    showAlert('Error', cell.textContent);
                }
            }

            function updateBreadcrumb(path) {
                document.getElementById('breadcrumb').value = path || '/';
            }

            const fileMimeTypes = {
                    txt: 'text/plain',
                    html: 'text/html',
                    htm: 'text/html',
                    css: 'text/css',
                    js: 'application/javascript',
                    json: 'application/json',
                    xml: 'application/xml',
                    csv: 'text/csv',
                    md: 'text/markdown',
                    jpg: 'image/jpeg',
                    jpeg: 'image/jpeg',
                    png: 'image/png',
                    gif: 'image/gif',
                    webp: 'image/webp',
                    svg: 'image/svg+xml',
                    ico: 'image/x-icon',
                    mp3: 'audio/mpeg',
                    wav: 'audio/wav',
                    mp4: 'video/mp4',
                    mov: 'video/quicktime',
                    avi: 'video/x-msvideo',
                    webm: 'video/webm',
                    pdf: 'application/pdf',
                    doc: 'application/msword',
                    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    xls: 'application/vnd.ms-excel',
                    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    zip: 'application/zip',
                    tar: 'application/x-tar',
                    gz: 'application/gzip',
                    rar: 'application/vnd.rar',
                    '7z': 'application/x-7z-compressed',
                    php: 'application/x-httpd-php',
                    py: 'text/x-python',
                    sh: 'application/x-sh',
                    c: 'text/x-c',
                    cpp: 'text/x-c++',
                    java: 'text/x-java-source',
                };
            function getMimeType(filename) {
                return fileMimeTypes[filename.split('.').pop().toLowerCase()] || 'application/octet-stream';
            }

            let gitStatusRequest = 0;
            let gitStatusTimer = null;
            let gitStatusUnavailable = false;
            function refreshGitStatus() {
                if (gitStatusUnavailable) return;
                clearTimeout(gitStatusTimer);
                gitStatusTimer = setTimeout(loadGitStatus, 200);
            }
            async function loadGitStatus() {
                if (gitStatusUnavailable) return;
                const request = ++gitStatusRequest;
                try {
                    const body = new FormData(); body.append('action','git_status');
                    const response = await fetch(window.location.pathname,{method:'POST',body});
                    const data = await response.json();
                    if (request !== gitStatusRequest) return;
                    document.querySelectorAll('.git-status-badge').forEach(element => element.remove());
                    if (!response.ok || data.status !== 'success') return;
                    if (data.available === false) { gitStatusUnavailable = true; return; }
                    const appendBadge = (element, path) => {
                        const status = data.files[path.replace(/^\/+/, '')];
                        if (!status) return;
                        element.append(createGitStatusBadge(status));
                    };
                    document.querySelectorAll('#files-list .file-item').forEach(row => {
                        if (row.dataset.type !== 'dir') appendBadge(row.querySelector('.file-name'), currentPath + '/' + row.dataset.name);
                    });
                    document.querySelectorAll('[data-git-path]').forEach(element => appendBadge(element,element.dataset.gitPath));
                } catch (_) { /* Ordinary file browsing remains available without Git. */ }
            }
            function showFiles(files) {
                const tbody = document.getElementById('files-list');

                if (files.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="8">
                    <div class="empty-state">
                        <i class="fas fa-folder-open d-block"></i>
                        <p>This directory is empty</p>
                    </div></td></tr>`;
                    return;
                }

                tbody.innerHTML = files.map(file => `
                <tr class="file-item" data-name="${file.name}" data-type="${file.type}">
                    <td class="checkbox-col"><input type="checkbox" class="form-check-input item-check"></td>
                    <td class="icon-col">${file.name === 'public_html' ? "<i class='fas fa-globe' style='color:var(--accent)'></i>" : file.icon}</td>
                    <td><a href="#" class="file-name">${file.name}</a></td>
                    <td class="file-size">${file.size}</td>
                    <td class="file-date">${file.last_modified}</td>
                    <td class="file-type">${file.type === 'dir' ? 'directory' : getMimeType(file.name)}</td>
                    <td class="permissions">${file.permissions} (${file.permissions_octal.padStart(3, '0')})</td>
                    <td class="file-ownership"></td>
                </tr>`).join('');

                document.querySelectorAll('#files-list .file-item').forEach((row, index) => {
                    const file = files[index], cell = row.querySelector('.file-ownership');
                    cell.textContent = (file.owner ?? '—') + ':' + (file.group ?? '—');
                    cell.title = 'Owner: ' + (file.owner ?? '—') + ' (UID ' + (file.uid ?? 'unknown') + ') · Group: ' + (file.group ?? '—') + ' (GID ' + (file.gid ?? 'unknown') + ')';
                });
                document.querySelectorAll('.file-item').forEach(row => {
                    row.addEventListener('click', function(e) {
                        if (e.target.closest('.checkbox-col')) return;
                        e.preventDefault();
                        // Modifier clicks and trash rows retain selection behavior.
                        if (e.ctrlKey || e.metaKey || e.shiftKey || currentPath === '/.trash') {
                            const cb = this.querySelector('.item-check');
                            cb.checked = !cb.checked;
                            cb.dispatchEvent(new Event('change'));
                            return;
                        }
                        const name = this.dataset.name;
                        if (this.dataset.type === 'dir') navigateTo(currentPath + '/' + name);
                        else openFileEditor(name);
                    });

                    row.addEventListener('contextmenu', function(e) {
                        e.preventDefault();
                        restoreTreeContextSelection();
                        selectedItems = [this.dataset.name];
                        document.querySelectorAll('#files-list .file-item').forEach(row => {
                            const selected = row === this;
                            row.classList.toggle('selected', selected);
                            row.querySelector('.item-check').checked = selected;
                        });
                        updateButtonStates();
                        contextTarget = {name: this.dataset.name, type: this.dataset.type, directory: currentPath};
                        showContextMenu(e.clientX, e.clientY, this.dataset.type);
                    });

                    const cb = row.querySelector('.item-check');
                    cb.addEventListener('change', function() {
                        const name = row.dataset.name;
                        if (this.checked) {
                            row.classList.add('selected');
                            if (!selectedItems.includes(name)) selectedItems.push(name);
                        } else {
                            row.classList.remove('selected');
                            const i = selectedItems.indexOf(name);
                            if (i !== -1) selectedItems.splice(i, 1);
                        }
                        updateButtonStates();
                    });
                });
            }

            function showContextMenu(x, y, type) {
                const menu = document.getElementById('context-menu');
                document.getElementById('ctx-download').style.display = type === 'file' ? 'flex' : 'none';
                document.getElementById('ctx-open-divider').style.display = type === 'file' && canOpenBrowserFile(contextTarget) ? 'block' : 'none';
                document.getElementById('ctx-browser').style.display = type === 'file' && canOpenBrowserFile(contextTarget) ? 'flex' : 'none';
                document.getElementById('ctx-phone').style.display = type === 'file' && canOpenBrowserFile(contextTarget) ? 'flex' : 'none';
                document.getElementById('ctx-extract').style.display = type === 'file' && /\.(zip|tar|gz|gzip|bz2|bzip2|rar|7z)$/i.test(contextTarget.name) ? 'flex' : 'none';
                document.getElementById('ctx-edit').style.display = type === 'file' ? 'flex' : 'none';
                document.getElementById('ctx-open').style.display = type === 'dir' ? 'flex' : 'none';
                menu.style.visibility = 'hidden';
                menu.style.display = 'block';
                const mw = menu.offsetWidth,
                    mh = menu.offsetHeight;
                const vw = window.innerWidth,
                    vh = window.innerHeight;
                if (x + mw > vw) x = Math.max(8, vw - mw - 8);
                if (y + mh > vh) y = Math.max(8, y - mh);
                menu.style.left = x + 'px';
                menu.style.top = y + 'px';
                menu.style.visibility = 'visible';

                document.getElementById('ctx-edit').style.display = type === 'file' ? 'flex' : 'none';
                document.getElementById('ctx-open').style.display = type === 'dir' ? 'flex' : 'none';

            }
            function restoreTreeContextSelection() {
                if (!treeContextSelection) return;
                treeContextSelection.target.classList.remove('active');
                treeContextSelection.previous.forEach(element => {
                    if (element.isConnected) element.classList.add('active');
                });
                treeContextSelection = null;
            }
            function highlightTreeContextTarget(button) {
                restoreTreeContextSelection();
                const previous = [...document.querySelectorAll('#directory-tree .folder-item.active')];
                previous.forEach(element => element.classList.remove('active'));
                treeContextSelection = {target: button, previous};
                button.classList.add('active');
            }
            function hideContextMenu() {
                document.getElementById('context-menu').style.display = 'none';
                restoreTreeContextSelection();
            }
            document.addEventListener('pointerdown', event => {
                if (!event.target.closest('#context-menu')) hideContextMenu();
            }, true);
            document.addEventListener('click', event => {
                if (!event.target.closest('#context-menu')) hideContextMenu();
            });
            document.addEventListener('keydown', event => { if (event.key === 'Escape') hideContextMenu(); });
            window.addEventListener('resize', hideContextMenu);

            function closeWorkspaceMenus() {
                hideContextMenu();
                document.querySelectorAll('.toolbar-actions .menu-heading[data-bs-toggle="dropdown"][aria-expanded="true"]').forEach(heading => {
                    bootstrap.Dropdown.getInstance(heading)?.hide();
                });
                closeMobileMenu();
            }

            function updateButtonStates() {
                const n = selectedItems.length;
                const inTrash = currentPath === '/.trash';

                const selectedFile = n === 1 ? fileList.find(item => item.name === selectedItems[0]) : null;
                const isFile = selectedFile?.type === 'file';
                const isArchive = isFile && ['zip', 'tar', 'gz', 'gzip', 'bz2', 'bzip2', 'rar', '7z'].includes((selectedFile.extension || '').toLowerCase());

                const browserFile = selectedBrowserFile();
                const publicFile = browserFile && canOpenBrowserFile(browserFile);
                const states = {
                    'permissions-btn': n === 1 && !inTrash,
                    'edit-btn': n === 1 && !inTrash,
                    'rename-btn': n === 1 && !inTrash,
                    'copy-btn': n > 0 && !inTrash,
                    'move-btn': n > 0 && !inTrash,
                    'delete-btn': n > 0 && !inTrash,
                    'compress-btn': n > 0 && !inTrash,
                    'download-btn': isFile && !inTrash,
                    'open-browser-btn': publicFile && !inTrash && (activeEditorPath !== null || isFile),
                    'open-phone-btn': publicFile && !inTrash && (activeEditorPath !== null || isFile),
                    'extract-btn': isArchive && !inTrash,
                    'restore-btn': n > 0 && inTrash,
                    'unselect-all-btn': n > 0,
                };
                if (activeEditorPath !== null) {
                    const ready = tabCanManageFile(editorTabs.get(activeEditorPath));
                    ['copy-btn', 'move-btn', 'rename-btn', 'delete-btn'].forEach(id => { states[id] = ready; });
                }
                Object.entries(states).forEach(([id, on]) => {
                    document.getElementById(id)?.classList.toggle('disabled', !on);
                });
            }

            // ── Sidebar explorer ─────────────────────────────────────
            async function loadTreeLevel(container, path) {
                const loading = document.createElement('li');
                loading.className = 'tree-loading';
                loading.setAttribute('role', 'status');
                const spinner = document.createElement('span');
                spinner.className = 'tree-loading-spinner';
                spinner.setAttribute('aria-hidden', 'true');
                loading.append(spinner, document.createTextNode('Loading…'));
                container.replaceChildren(loading);
                try {
                    const data = await requestWorkspace('tree', {path});
                    container.replaceChildren();
                    if (!data.data.length) {
                        const empty = document.createElement('li');
                        empty.className = 'tree-message';
                        empty.textContent = 'Empty folder';
                        container.append(empty);
                    }
                    data.data.forEach(item => {
                        const li = document.createElement('li');
                        const button = document.createElement('button');
                        button.type = 'button';
                        button.className = 'folder-item';
                        button.dataset.path = item.path;
                        button.title = item.path;
                        button.addEventListener('contextmenu', event => {
                            event.preventDefault();
                            event.stopPropagation();
                            highlightTreeContextTarget(button);
                            contextTarget = {name: item.name, type: item.type, directory: item.path.substring(0, item.path.lastIndexOf('/'))};
                            showContextMenu(event.clientX, event.clientY, item.type);
                        });
                        const icon = createFileIcon(item.name, item.type === 'dir');
                        const label = document.createElement('span');
                        label.className = 'tree-name';
                        label.textContent = item.name;
                        if (item.type !== 'dir') label.dataset.gitPath = item.path;
                        if (item.type === 'dir') {
                            const caret = document.createElement('i');
                            caret.className = 'fas fa-caret-right caret';
                            caret.setAttribute('aria-hidden', 'true');
                            button.setAttribute('aria-expanded', 'false');
                            button.append(caret, icon, label);
                            const nested = document.createElement('ul');
                            nested.className = 'file-tree nested';
                            let loaded = false;
                            let loading = false;
                            button.addEventListener('click', async () => {
                                if (loading) return;
                                const expand = button.getAttribute('aria-expanded') !== 'true';
                                button.setAttribute('aria-expanded', String(expand));
                                caret.classList.toggle('expanded', expand);
                                nested.classList.toggle('active', expand);
                                updateFolderIcon(icon, item.name);
                                if (expand && !loaded) {
                                    loading = true;
                                    loaded = await loadTreeLevel(nested, item.path);
                                    loading = false;
                                }
                            });
                            li.append(button, nested);
                        } else {
                            button.classList.add('tree-file');
                            button.append(icon, label);
                            button.addEventListener('click', () => {
                                document.querySelectorAll('#directory-tree .folder-item.active').forEach(el => el.classList.remove('active'));
                                button.classList.add('active');
                                openFileEditor(item.name, item.path.substring(0, item.path.lastIndexOf('/')));
                            });
                            li.append(button);
                        }
                        container.append(li);
                    });
                    refreshGitStatus();
                    return true;
                } catch (error) {
                    container.replaceChildren();
                    const retry = document.createElement('button');
                    retry.type = 'button';
                    retry.className = 'folder-item';
                    retry.textContent = 'Failed to load — retry';
                    retry.title = error.message;
                    retry.addEventListener('click', () => loadTreeLevel(container, path));
                    container.append(retry);
                    return false;
                }
            }

            function loadDirectoryTree() {
                return loadTreeLevel(document.querySelector('#directory-tree .file-tree'), '');
            }

            function navigateTo(path) {
                path = path.replace(/^\/\//, '/').replace(/\/+/g, '/');
                currentPath = path;
                loadFileList();
            }

            // ── Alert ─────────────────────────────────────────────────
            function showAlert(title, message, confirm = null) {
                const type = title === 'Success' ? 'success' : title === 'Error' ? 'error' : 'warning';
                if (confirm !== null) {
                    window.workspaceAlert(message, title, type).then(result => {
                        if (result.isConfirmed) window.location.reload();
                    });
                } else {
                    window.workspaceToast(message, title, type);
                }

                document.querySelectorAll('.modal.show').forEach(el => {
                    const m = bootstrap.Modal.getInstance(el);
                    if (m) m.hide();
                });
            }

            // ── Permissions init ──────────────────────────────────────
            function initPermissionsModal() {
                const permValue = document.getElementById('permValue');
                const checks = document.querySelectorAll('.perm-check');
                checks.forEach(c => c.addEventListener('change', () => {
                    let v = 0;
                    checks.forEach(x => {
                        if (x.checked) v += parseInt(x.dataset.value);
                    });
                    permValue.value = '0' + v.toString(8).padStart(3, '0');
                }));
                permValue.addEventListener('input', function() {
                    const m = this.value.match(/^0([0-7]{3})$/);
                    if (m) {
                        const dec = parseInt(m[1], 8);
                        checks.forEach(c => {
                            c.checked = (dec & parseInt(c.dataset.value)) === parseInt(c.dataset
                                .value);
                        });
                    }
                });
            }

            // ── Drag & Drop ───────────────────────────────────────────
            function initDragAndDrop() {
                const dz = document.getElementById('dropzone');
                ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => {
                    e.preventDefault();
                    e.stopPropagation();
                }));
                ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, () => dz.classList.add(
                    'drag-over')));
                ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, () => dz.classList.remove(
                    'drag-over')));
                dz.addEventListener('drop', e => uploadFiles(e.dataTransfer.files));
            }

            // ── Init ──────────────────────────────────────────────────
            function init() {
                initPermissionsModal();
                initDragAndDrop();
                loadDirectoryTree();
                loadFileList();
            }

            // ── Navigation ────────────────────────────────────────────
            let pathHistory = [''];
            let historyIndex = 0;

            function navigateToPath(path) {
                activateTab(null);
                currentPath = path;
                loadFileList();
            }

            document.getElementById('home-btn').addEventListener('click', e => {
                e.preventDefault();
                navigateToPath('');
            });

            document.getElementById('breadcrumb-search-btn').addEventListener('click', e => {
                e.preventDefault();
                const v = document.getElementById('breadcrumb').value.trim();
                if (v) navigateToPath(v);
            });
            document.getElementById('breadcrumb').addEventListener('keydown', e => {
                if (e.key === 'Enter') {
                    const v = e.target.value.trim();
                    if (v) navigateToPath(v);
                }
            });

            document.getElementById('up-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!currentPath) return;
                navigateToPath(currentPath.split('/').slice(0, -1).join('/') || '');
            });
            document.getElementById('reload-btn').addEventListener('click', e => {
                e.preventDefault();
                loadFileList();
            });
            document.getElementById('view-trash-btn').addEventListener('click', e => {
                e.preventDefault();
                navigateToPath('/.trash');
            });
            document.getElementById('sort-btn').addEventListener('click', e => {
                e.preventDefault();
                currentOrder = currentOrder === 'asc' ? 'desc' : 'asc';
                loadFileList();
            });

            // ── Select all ────────────────────────────────────────────
            document.getElementById('select-all-checkbox').addEventListener('change', function() {
                document.querySelectorAll('.item-check').forEach(c => {
                    c.checked = this.checked;
                    c.dispatchEvent(new Event('change'));
                });
            });
            document.getElementById('select-all-btn').addEventListener('click', e => {
                e.preventDefault();
                const cb = document.getElementById('select-all-checkbox');
                cb.checked = true;
                cb.dispatchEvent(new Event('change'));
            });
            document.getElementById('unselect-all-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled')) {
                    const cb = document.getElementById('select-all-checkbox');
                    cb.checked = false;
                    cb.dispatchEvent(new Event('change'));
                }
            });

            // ── Toolbar actions ───────────────────────────────────────
            document.getElementById('new-file-btn').addEventListener('click', e => {
                e.preventDefault();
                document.getElementById('fileName').value = '';
                document.getElementById('fileContent').value = '';
                document.getElementById('filePath').value = currentPath;
                new bootstrap.Modal(document.getElementById('newFileModal')).show();
            });

            document.getElementById('new-folder-btn').addEventListener('click', e => {
                e.preventDefault();
                document.getElementById('folderName').value = '';
                document.getElementById('currenPathValue').value = currentPath;
                new bootstrap.Modal(document.getElementById('newFolderModal')).show();
            });

            document.getElementById('extract-btn').addEventListener('click', e => {
                e.preventDefault();
                const f = fileList.find(i => i.name === selectedItems[0]);
                if (f && f.type === 'file') {
                    document.getElementById('extractFileName').textContent = f.name;
                    document.getElementById('extractFileNameValue').value = f.name;
                    document.getElementById('extractPathName').value = currentPath;
                    document.getElementById('extractPath').value = currentPath + '/' + f.name.replace(
                        /\.[^/.]+$/, '');
                    new bootstrap.Modal(document.getElementById('extractModal')).show();
                } else {
                    showAlert('Error', 'Please select a file to extract');
                }
            });

            function fileActionSelection() {
                if (activeEditorPath === null) return {directory: currentPath, names: [...selectedItems], target: null};
                const path = activeEditorPath;
                const tab = editorTabs.get(path);
                if (!tabCanManageFile(tab)) return null;
                if (tabHasChanges(tab)) {
                    showAlert('Unsaved changes', 'Save this file before copying, moving, renaming or deleting it.');
                    return null;
                }
                const relative = path.substring(workspaceRoot.length);
                const directory = relative.substring(0, relative.lastIndexOf('/'));
                const name = relative.substring(relative.lastIndexOf('/') + 1);
                return {directory, names: [name], target: {path, tab, directory, name}};
            }
            function setEditorFileTarget(modalId, selection) {
                document.getElementById(modalId).querySelector('form').fmEditorFileTarget = selection.target;
            }

            document.getElementById('rename-btn').addEventListener('click', e => {
                e.preventDefault();
                if (e.currentTarget.classList.contains('disabled')) return;
                const selection = fileActionSelection();
                if (!selection || selection.names.length !== 1) return;
                setEditorFileTarget('renameModal', selection);
                document.getElementById('oldName').value = selection.names[0];
                document.getElementById('newName').value = selection.names[0];
                document.getElementById('renamePath').value = selection.directory;
                new bootstrap.Modal(document.getElementById('renameModal')).show();
            });

            document.getElementById('permissions-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled') && selectedItems.length === 1) {
                    document.getElementById('permItem').textContent = selectedItems[0];
                    document.getElementById('permItemValue').value = selectedItems[0];
                    const item = fileList.find(i => i.name === selectedItems[0]);
                    if (item) {
                        const ps = item.permissions;
                        let o = 0,
                            g = 0,
                            w = 0;
                        if (ps.length >= 10) {
                            if (ps[1] === 'r') o += 4;
                            if (ps[2] === 'w') o += 2;
                            if (ps[3] === 'x' || ps[3] === 's') o += 1;
                            if (ps[4] === 'r') g += 4;
                            if (ps[5] === 'w') g += 2;
                            if (ps[6] === 'x' || ps[6] === 's') g += 1;
                            if (ps[7] === 'r') w += 4;
                            if (ps[8] === 'w') w += 2;
                            if (ps[9] === 'x' || ps[9] === 't') w += 1;
                        }
                        const octal = '0' + o + g + w;
                        document.getElementById('permValue').value = octal;
                        const dec = parseInt(octal.substring(1), 8);
                        document.querySelectorAll('.perm-check').forEach(c => {
                            c.checked = (dec & parseInt(c.dataset.value)) === parseInt(c.dataset
                                .value);
                        });
                    }
                    new bootstrap.Modal(document.getElementById('permissionsModal')).show();
                }
            });

            document.getElementById('compress-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled') && selectedItems.length > 0) {
                    document.getElementById('compressName').value = selectedItems.length === 1 ?
                        selectedItems[0] : 'archive_' + Math.floor(Date.now() / 1000);
                    document.getElementById('compressPath').value = currentPath;
                    document.getElementById('compressItems').value = selectedItems;
                    new bootstrap.Modal(document.getElementById('compressModal')).show();
                }
            });

            document.getElementById('delete-btn').addEventListener('click', function(e) {
                e.preventDefault();
                if (this.classList.contains('disabled')) return;
                const selection = fileActionSelection();
                if (!selection || !selection.names.length) return;
                if (selection.target && selection.names[0].includes(',')) { showAlert('Cannot delete', 'Files containing commas cannot use this operation.'); return; }
                setEditorFileTarget('deleteModal', selection);
                document.getElementById('deletePath').value = selection.directory;
                document.getElementById('deleteItems').value = selection.names.join(',');
                const names = document.getElementById('delete-item-names');
                names.replaceChildren(...selection.names.map(name => {
                    const item = document.createElement('li');
                    item.textContent = name;
                    return item;
                }));
                document.getElementById('deleteAction').value = 'trash';
                document.getElementById('deleteButtonText').textContent = 'Move to Trash';
                document.getElementById('deleteInfoAlert').style.display = 'block';
                document.getElementById('permanentDeleteAlert').style.display = 'none';
                document.getElementById('permanentDeleteCheck').checked = false;
                new bootstrap.Modal(document.getElementById('deleteModal')).show();
            });

            document.getElementById('permanentDeleteCheck').addEventListener('change', function() {
                const perm = this.checked;
                document.getElementById('deleteAction').value = perm ? 'delete' : 'trash';
                document.getElementById('deleteInfoAlert').style.display = perm ? 'none' : 'block';
                document.getElementById('permanentDeleteAlert').style.display = perm ? 'block' : 'none';
                document.getElementById('deleteButtonText').textContent = perm ? 'Delete Permanently' :
                    'Move to Trash';
            });

            document.getElementById('restore-btn')?.addEventListener('click', function(e) {
                e.preventDefault();
                if (selectedItems.length === 0) {
                    showAlert('Error', 'Please select items to restore');
                    return;
                }
                if (!currentPath.includes('/.trash')) {
                    showAlert('Error', 'Restore is only available inside the Trash folder');
                    return;
                }
                document.getElementById('restorePath').value = currentPath;
                document.getElementById('restoreItems').value = selectedItems;
                new bootstrap.Modal(document.getElementById('restoreModal')).show();
            });

            // ── Copy / Move ───────────────────────────────────────────
            function performFileOperation(op) {
                const selection = fileActionSelection();
                if (!selection || !selection.names.length) return;
                if (selection.target && selection.names[0].includes(',')) { showAlert('Cannot ' + op, 'Files containing commas cannot use this operation.'); return; }
                setEditorFileTarget('fileOperationModal', selection);
                document.getElementById('fileOpTitle').textContent = op === 'copy' ? 'Copy Items' : 'Move Items';
                document.getElementById('fileOpType').value = op;
                document.getElementById('destinationPath').value = selection.directory || '/';
                document.getElementById('copyPath').value = selection.directory;
                document.getElementById('copyItems').value = selection.names.join(',');
                document.getElementById('fileOpItems').textContent = selection.target ? selection.target.name : `Selected: ${selection.names.length} item(s)`;
                document.getElementById('currentPathDisplay').textContent = selection.directory || '/';
                new bootstrap.Modal(document.getElementById('fileOperationModal')).show();
            }

            document.getElementById('copy-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled')) performFileOperation('copy');
            });
            document.getElementById('move-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled')) performFileOperation('move');
            });

            // ── Upload ────────────────────────────────────────────────
            document.getElementById('upload-btn').addEventListener('click', e => {
                e.preventDefault();
                document.getElementById('file-upload').click();
            });
            document.getElementById('file-upload').addEventListener('change', function() {
                uploadFiles(this.files);
                this.value = '';
            });

            let uploadBusy = false;
            function confirmUploadReplacement(names) {
                const element = document.getElementById('uploadReplaceModal');
                const list = document.getElementById('upload-replace-names');
                list.replaceChildren(...names.map(name => { const item = document.createElement('li'); item.textContent = name; return item; }));
                return new Promise(resolve => {
                    let confirmed = false;
                    const modal = bootstrap.Modal.getOrCreateInstance(element);
                    const button = document.getElementById('upload-replace-confirm');
                    button.onclick = () => { confirmed = true; modal.hide(); };
                    element.addEventListener('hidden.bs.modal', () => { button.onclick = null; resolve(confirmed); }, {once:true});
                    modal.show();
                });
            }
            async function uploadFiles(files) {
                const selected = Array.from(files);
                if (!selected.length) return;
                if (uploadBusy) { showAlert('Error', 'Another upload is still in progress.'); return; }
                uploadBusy = true;
                const directory = currentPath;
                const bar = document.getElementById('upload-progress');
                const fill = bar.querySelector('.progress-bar');
                try {
                    const check = await requestWorkspace('upload_check', {path: directory, files: JSON.stringify(selected.map(file => ({name:file.name, size:file.size})))});
                    const replacements = Object.keys(check.files).filter(name => check.files[name] !== null);
                    for (const name of replacements) {
                        const tab = editorTabs.get(editorFilePath(name, directory));
                        if (tabHasChanges(tab)) throw new Error('Save or close unsaved edits in ' + name + ' before replacing it.');
                    }
                    if (replacements.length && !await confirmUploadReplacement(replacements)) return;
                    const fd = new FormData(); fd.append('path', directory);
                    fd.append('upload_manifest', JSON.stringify(check.files));
                    selected.forEach(file => fd.append('files[]', file));
                    bar.style.display = 'block'; fill.style.width = '0%'; fill.textContent = 'Preparing…';
                    fill.classList.add('progress-bar-animated');
                    const response = await new Promise((resolve, reject) => {
                        const xhr = new XMLHttpRequest(); xhr.open('POST', window.location.pathname, true);
                        xhr.upload.addEventListener('progress', event => {
                            if (!event.lengthComputable) return;
                            const percent = Math.round(event.loaded / event.total * 100);
                            fill.style.width = percent + '%'; fill.textContent = percent >= 100 ? 'Verifying…' : percent + '%';
                        });
                        xhr.addEventListener('load', () => {
                            try {
                                const result = JSON.parse(xhr.responseText);
                                if (xhr.status >= 400 && !result.failedFiles) throw new Error(result.message || 'Upload failed (HTTP ' + xhr.status + ').');
                                resolve(result);
                            } catch (error) { reject(new Error(error instanceof SyntaxError ? 'Invalid server response. Upload was not confirmed.' : error.message)); }
                        });
                        xhr.addEventListener('error', () => reject(new Error('Network error. Upload was not confirmed.')));
                        xhr.addEventListener('abort', () => reject(new Error('Upload cancelled.')));
                        xhr.send(fd);
                    });
                    const detail = response.failedFiles?.length ? '\n' + response.failedFiles.join('\n') : '';
                    const keptEdits = [];
                    if (response.status === 'success' || response.status === 'partial') {
                        loadFileList(); loadDirectoryTree();
                        for (const name of response.uploaded || []) {
                            const path = editorFilePath(name, directory), tab = editorTabs.get(path);
                            // Do not discard edits made while the transfer was in progress.
                            if (!tab) continue;
                            if (tabHasChanges(tab)) { keptEdits.push(name); continue; }
                            const active = activeEditorPath === path, point = tabLocation(tab);
                            removeEditorTab(path, tab);
                            openFileEditor(name, directory, point, active);
                        }
                    }
                    if (response.status === 'success' && keptEdits.length) window.workspaceAlert(response.message + '\nUnsaved edits were kept in these tabs: ' + keptEdits.join(', ') + '. Reopen the file to see the uploaded version.', 'Upload completed', 'warning');
                    else if (response.status === 'success') showAlert('Success', response.message);
                    else window.workspaceAlert((response.message || 'Upload failed.') + detail, 'Upload failed', 'error');
                } catch (error) { window.workspaceAlert(error.message || 'Upload failed.', 'Upload failed', 'error'); }
                finally { uploadBusy = false; bar.style.display = 'none'; fill.classList.add('progress-bar-animated'); }
            }

            // ── Download ──────────────────────────────────────────────
            document.getElementById('download-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled') && selectedItems.length === 1) {
                    window.location.href =
                        `${window.location.pathname}?action=download&path=${encodeURIComponent(currentPath)}&file=${encodeURIComponent(selectedItems[0])}`;
                }
            });

            // ── Search ────────────────────────────────────────────────
            let searchRequest = 0;
            let searchController = null;
            function searchFiles() {
                const q = document.getElementById('search-input').value.trim();
                if (!q) {
                    showAlert('Error', 'Please enter a search query');
                    return;
                }

                const tbody = document.getElementById('search-results');
                tbody.innerHTML =
                    `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted)"><i class="fas fa-spinner fa-spin me-2"></i>Searching…</td></tr>`;

                const request = ++searchRequest;
                searchController?.abort();
                searchController = new AbortController();
                requestWorkspace('search', {path: currentPath, query: q}, {signal: searchController.signal})
                    .then(data => {
                        if (request !== searchRequest) return;
                        if (data.status === 'success') {
                            if (!data.data.length) {
                                tbody.innerHTML =
                                    `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted)">No results found</td></tr>`;
                            } else {
                                tbody.replaceChildren();
                                data.data.forEach(result => {
                                    const row = document.createElement('tr');
                                    row.className = 'search-result-item';
                                    row.tabIndex = 0;
                                    row.title = 'Open ' + result.name;
                                    const nameCell = document.createElement('td');
                                    const name = document.createElement('span');
                                    name.className = 'search-result-name';
                                    const label = document.createElement('span');
                                    label.className = 'search-result-label';
                                    label.textContent = result.name;
                                    name.append(createFileIcon(result.name, result.type === 'dir'), label);
                                    nameCell.append(name);
                                    row.append(nameCell);
                                    [result.path, result.type === 'dir' ? 'Folder' : 'File', result.size || '', result.last_modified].forEach((value, index) => {
                                        const cell = document.createElement('td');
                                        cell.textContent = value;
                                        if (index === 0) cell.className = 'search-result-path';
                                        row.append(cell);
                                    });
                                    const openResult = () => {
                                        if (result.type === 'dir') {
                                            navigateToPath(result.path);
                                            if (matchMedia('(max-width: 760px)').matches) document.body.classList.add('mobile-file-list');
                                        } else {
                                            const directory = result.path.substring(0, result.path.lastIndexOf('/'));
                                            openFileEditor(result.name, directory);
                                        }
                                    };
                                    const activateResult = () => {
                                        const modal = document.getElementById('searchModal');
                                        if (modal.classList.contains('show')) {
                                            modal.addEventListener('hidden.bs.modal', openResult, {once: true});
                                            bootstrap.Modal.getOrCreateInstance(modal).hide();
                                        } else openResult();
                                    };
                                    row.addEventListener('click', activateResult);
                                    row.addEventListener('keydown', event => {
                                        if (event.key === 'Enter' || event.key === ' ') {
                                            event.preventDefault();
                                            activateResult();
                                        }
                                    });
                                    tbody.append(row);
                                });
                            }
                        }
                    }).catch(error => {
                        if (request !== searchRequest || error.name === 'AbortError') return;
                        const row = document.createElement('tr');
                        const cell = document.createElement('td');
                        cell.colSpan = 5; cell.style.padding = '24px'; cell.style.color = 'var(--accent-danger)';
                        cell.textContent = error.message || 'Search failed';
                        row.append(cell); tbody.replaceChildren(row);
                    });

                bootstrap.Modal.getOrCreateInstance(document.getElementById('searchModal')).show();
            }

            document.getElementById('search-btn').addEventListener('click', e => {
                e.preventDefault();
                searchFiles();
            });
            document.getElementById('search-input').addEventListener('keypress', e => {
                if (e.key === 'Enter') searchFiles();
            });

            // ── Internal editor tabs ─────────────────────────────────
            const editorTabs = new Map();
            const tabsBar = document.getElementById('workspace-tabs');
            const panels = document.getElementById('workspace-panels');
            const filesPanel = document.getElementById('dropzone');
            const filesTab = document.getElementById('files-tab');
            let activeEditorPath = null;
            let openRequestSerial = 0;
            const pendingEditorOpens = new Map();
            let nextTabId = 0;
            // A bounded, per-workspace cookie contains locations only, never file text.
            const workspaceRoot = SERVER_ROOT_PATH.replace(/\/+$/, '');
            let workspaceHash = 2166136261;
            for (const char of window.location.pathname + '|' + workspaceRoot) workspaceHash = Math.imul(workspaceHash ^ char.charCodeAt(0), 16777619);
            const tabsCookieName = 'fm_tabs_' + (workspaceHash >>> 0).toString(36);
            let restoringTabs = false;
            let saveTabsTimer = null;
            function tabLocation(tab) {
                const source = tab.frame.contentWindow.editor;
                if (!tab.loaded || !source) return tab.savedLocation || {row: 0, column: 0, top: 0, left: 0};
                const cursor = source.getCursorPosition();
                return {row: cursor.row, column: cursor.column, top: Math.round(source.session.getScrollTop()), left: Math.round(source.session.getScrollLeft())};
            }
            function saveWorkspaceTabs() {
                if (restoringTabs) return;
                clearTimeout(saveTabsTimer);
                const entries = [...editorTabs.entries()].map(([path, tab]) => {
                    const point = tabLocation(tab);
                    return [path.substring(workspaceRoot.length), point.row, point.column, point.top, point.left];
                });
                const active = activeEditorPath ? activeEditorPath.substring(workspaceRoot.length) : null;
                let saved = entries.slice();
                let value = encodeURIComponent(JSON.stringify({v: 1, active, tabs: saved}));
                // Browsers limit individual cookies to roughly 4 KB; retain the active tab.
                while (value.length + tabsCookieName.length > 3800 && saved.length) {
                    const discard = saved.findIndex(item => item[0] !== active);
                    if (discard < 0) { saved = []; break; }
                    saved.splice(discard, 1);
                    value = encodeURIComponent(JSON.stringify({v: 1, active, tabs: saved}));
                }
                value = encodeURIComponent(JSON.stringify({v: 1, active: saved.some(item => item[0] === active) ? active : null, tabs: saved}));
                document.cookie = tabsCookieName + '=' + value + '; Max-Age=31536000; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
            }
            function scheduleSaveTabs() {
                if (restoringTabs) return;
                clearTimeout(saveTabsTimer);
                saveTabsTimer = setTimeout(saveWorkspaceTabs, 400);
            }
            async function restoreWorkspaceTabs() {
                const cookie = document.cookie.split('; ').find(item => item.startsWith(tabsCookieName + '='));
                if (!cookie) return;
                try {
                    const state = JSON.parse(decodeURIComponent(cookie.substring(tabsCookieName.length + 1)));
                    if (state.v !== 1 || !Array.isArray(state.tabs)) return;
                    restoringTabs = true;
                    const interaction = openRequestSerial;
                    for (const item of state.tabs.slice(0, 50)) {
                        if (!Array.isArray(item) || typeof item[0] !== 'string' || !item[0].startsWith('/') || item[0].split('/').some(part => part === '..' || part === '.') || item[0].includes('\0')) continue;
                        const split = item[0].lastIndexOf('/');
                        const name = item[0].substring(split + 1);
                        if (!name) continue;
                        const number = n => Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
                        await openFileEditor(name, item[0].substring(0, split), {row: number(item[1]), column: number(item[2]), top: number(item[3]), left: number(item[4])}, false);
                    }
                    const activePath = typeof state.active === 'string' ? workspaceRoot + state.active : null;
                    if (interaction === openRequestSerial) activateTab(editorTabs.has(activePath) ? activePath : null);
                } catch (_) {
                    // Ignore stale or malformed cookies.
                } finally {
                    restoringTabs = false;
                    scheduleSaveTabs();
                }
            }
            window.addEventListener('pagehide', saveWorkspaceTabs);


            const mobileTabsSelect = document.getElementById('mobile-tabs-select');
            function refreshMobileTabs() {
                const placeholder = document.createElement('option');
                placeholder.value = ''; placeholder.textContent = 'Open files (' + editorTabs.size + ')';
                mobileTabsSelect.replaceChildren(placeholder);
                editorTabs.forEach((tab, path) => {
                    const option = document.createElement('option');
                    option.value = path;
                    option.textContent = (tab.dirty ? '● ' : '') + path.split('/').pop();
                    mobileTabsSelect.append(option);
                });
                mobileTabsSelect.value = activeEditorPath || '';
            }
            function closeMobileMenu() {
                document.body.classList.remove('mobile-menu-open');
                document.getElementById('mobile-menu-toggle').setAttribute('aria-expanded','false');
                document.querySelectorAll('.toolbar-actions .dropdown-menu.show').forEach(menu => {
                    const heading = menu.parentElement.querySelector('[data-bs-toggle="dropdown"]');
                    if (heading && window.bootstrap) bootstrap.Dropdown.getInstance(heading)?.hide();
                });
            }
            mobileTabsSelect.addEventListener('change', () => activateTab(mobileTabsSelect.value || null));
            document.getElementById('mobile-files-btn').addEventListener('click', () => activateTab(null));
            document.getElementById('mobile-list-btn').addEventListener('click', () => {
                activateTab(null);
                document.body.classList.add('mobile-file-list');
            });
            document.getElementById('mobile-menu-toggle').addEventListener('click', event => {
                const expanded = document.body.classList.toggle('mobile-menu-open');
                event.currentTarget.setAttribute('aria-expanded',String(expanded));
            });
            document.querySelectorAll('.toolbar-actions .header-btns').forEach(button => button.addEventListener('click',closeMobileMenu));
            document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMobileMenu(); });
            function resizeMobileWorkspace() {
                if (window.visualViewport) document.documentElement.style.setProperty('--mobile-viewport-height', visualViewport.height + 'px');
                const target = editorTabs.get(activeEditorPath)?.frame.contentWindow;
                requestAnimationFrame(() => { if (target?.editor) { target.editor.resize(); if (target.editor.isFocused()) target.editor.renderer.scrollCursorIntoView(); } });
            }
            if (window.visualViewport) {
                visualViewport.addEventListener('resize', resizeMobileWorkspace);
                visualViewport.addEventListener('scroll', resizeMobileWorkspace);
            }
            window.addEventListener('resize', resizeMobileWorkspace);
            resizeMobileWorkspace();
            function updateWorkspaceTitle() {
                const name = activeEditorPath ? activeEditorPath.split('/').pop() : 'Files';
                window.setWorkspaceDocumentTitle(name, activeEditorPath !== null && !!editorTabs.get(activeEditorPath)?.dirty);
            }
            function activateTab(path) {
                openRequestSerial++;
                document.body.classList.toggle('mobile-editor', path !== null);
                document.body.classList.remove('mobile-file-list');
                closeMobileMenu();
                activeEditorPath = path;
                updateWorkspaceTitle();
                scheduleSaveTabs();
                updateEditorMenu();
                refreshMobileTabs();
                filesPanel.hidden = path !== null;
                filesTab.setAttribute('aria-selected', String(path === null));
                filesTab.parentElement.classList.toggle('active', path === null);
                editorTabs.forEach((tab, key) => {
                    const active = key === path;
                    tab.frame.hidden = !active;
                    tab.element.classList.toggle('active', active);
                    tab.button.setAttribute('aria-selected', String(active));
                    if (active && tab.frame.contentWindow.editor) {
                        tab.frame.contentWindow.editor.resize();
                        tab.frame.contentWindow.editor.focus();
                    }
                });
            }
            function tabHasChanges(tab) {
                return !!tab && (tab.dirty || !!tab.frame.contentWindow.hasUnsavedChanges);
            }
            function tabCanManageFile(tab) {
                const content = tab?.frame.contentWindow;
                return !!content && (!!content.editor || content.fmImagePreview === true);
            }
            function removeEditorTab(path, expectedTab, activateNeighbor = false) {
                const tab = editorTabs.get(path);
                if (!tab || tab !== expectedTab) return;
                const keys = [...editorTabs.keys()];
                const index = keys.indexOf(path);
                const next = activateNeighbor ? keys[index - 1] || keys[index + 1] || null : null;
                editorTabs.delete(path);
                tab.element.remove();
                tab.frame.remove();
                if (activeEditorPath === path) activateTab(next);
                refreshMobileTabs();
                scheduleSaveTabs();
            }
            ['renameModal', 'deleteModal', 'fileOperationModal'].forEach(modalId => {
                const modal = document.getElementById(modalId);
                const form = modal.querySelector('form');
                modal.addEventListener('hidden.bs.modal', () => { form.fmEditorFileTarget = null; });
                form.addEventListener('submit', async event => {
                    const target = form.fmEditorFileTarget;
                    if (!target) return;
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    if (form.fmEditorFileBusy) return;
                    if (tabHasChanges(target.tab)) {
                        showAlert('Unsaved changes', 'Save the file before applying this operation.');
                        return;
                    }
                    if (!form.reportValidity()) return;
                    const body = new FormData(form);
                    // Always bind the request to the file chosen when this dialog opened.
                    body.set('path', target.directory);
                    if (body.get('action') === 'rename') body.set('old_name', target.name);
                    else body.set('items', target.name);
                    const action = body.get('action');
                    const buttons = [...form.querySelectorAll('button')];
                    form.fmEditorFileBusy = true;
                    buttons.forEach(button => { button.disabled = true; });
                    try {
                        const data = await requestWorkspace(action, body);
                        const point = tabLocation(target.tab);
                        const changedPath = ['rename', 'move', 'trash', 'delete'].includes(action);
                        if (changedPath && tabHasChanges(target.tab)) {
                            // An unexpected edit during the request must never be silently discarded.
                            target.tab.frame.contentWindow.saveFile = () => window.workspaceAlert('The file path changed. Copy your edits into the new file before saving.');
                            showAlert('File path changed', 'Your unsaved text remains in the old tab. Copy it before closing.');
                        } else if (changedPath) {
                            removeEditorTab(target.path, target.tab);
                            if (action === 'rename') openFileEditor(body.get('new_name'), target.directory, point);
                            else if (action === 'move') openFileEditor(target.name, body.get('destination').replace(/\/+$/, ''), point);
                        }
                        bootstrap.Modal.getOrCreateInstance(modal).hide();
                        loadFileList();
                        loadDirectoryTree();
                        showAlert('Success', data.message);
                    } catch (error) { showAlert('Error', error.message || 'Could not confirm the file operation.'); }
                    finally { form.fmEditorFileBusy = false; buttons.forEach(button => { button.disabled = false; }); }
                }, true);
            });
            const editorCommands = {
                save: {run: target => target.saveFile()},
                undo: {run: target => target.editor.undo()},
                redo: {run: target => target.editor.redo()},
                copyall: {run: target => target.copyAll()},
                find: {run: target => target.editor.execCommand('replace')},
                map: {run: target => target.toggleMinimap(), pressed: target => !target.document.getElementById('minimap').hidden, keepFocus: true},
                gitdiff: {run: target => target.showGitDiff()},
                inlinechanges: {run: target => target.toggleInlineChanges(), pressed: target => target.inlineChangesEnabled, keepFocus: true},
                wrap: {run: target => target.toggleWrap(), pressed: target => target.editor.session.getUseWrapMode(), keepFocus: true},
                foldall: {run: target => target.editor.session.foldAll()},
                unfoldall: {run: target => target.editor.session.unfold()},
                invisibles: {run: target => target.toggleInvisibles(), pressed: target => target.editor.getOption('showInvisibles'), keepFocus: true},
                indentguides: {run: target => target.toggleEditorPreference('displayIndentGuides'), pressed: target => target.editor.getOption('displayIndentGuides'), keepFocus: true},
                autocomplete: {run: target => target.toggleEditorPreference('enableLiveAutocompletion'), pressed: target => target.editor.getOption('enableLiveAutocompletion'), keepFocus: true},
                fullscreen: {run: target => target.toggleFullscreen(), pressed: target => !!target.document.fullscreenElement, keepFocus: true},
                format: {run: target => target.formatCode()}
            };
            function updateEditorMenu() {
                const ready = activeEditorPath !== null && !!editorTabs.get(activeEditorPath)?.frame.contentWindow.editor;
                document.querySelectorAll('.editor-menu-action').forEach(button => {
                    button.disabled = !ready || !Object.hasOwn(editorCommands, button.dataset.editorCommand);
                    const command = editorCommands[button.dataset.editorCommand];
                    if (command?.pressed) button.setAttribute('aria-pressed', String(ready && !!command.pressed(editorTabs.get(activeEditorPath).frame.contentWindow)));
                });
                updateButtonStates();
            }
            function runEditorCommand(name) {
                if (!Object.hasOwn(editorCommands, name)) return;
                const target = editorTabs.get(activeEditorPath)?.frame.contentWindow;
                if (!target?.editor) return;
                const command = editorCommands[name];
                command.run(target);
                updateEditorMenu();
                if (!command.keepFocus) target.editor.focus();
            }
            document.addEventListener('show.bs.dropdown', updateEditorMenu);
            document.addEventListener('fullscreenchange', updateEditorMenu);
            document.getElementById('menu-show-files').addEventListener('click', () => activateTab(null));
            document.querySelectorAll('.editor-menu-action').forEach(button => {
                button.addEventListener('click', () => runEditorCommand(button.dataset.editorCommand));
            });
            // Move between menu headings with the keyboard or pointer while a menu is open.
            document.querySelectorAll('.toolbar-actions .menu-heading[data-bs-toggle="dropdown"]').forEach(heading => {
                heading.addEventListener('mouseenter', () => {
                    if (document.querySelector('.toolbar-actions .menu-heading[aria-expanded="true"]') && heading.getAttribute('aria-expanded') !== 'true') {
                        document.querySelectorAll('.toolbar-actions .menu-heading[aria-expanded="true"]').forEach(open => bootstrap.Dropdown.getOrCreateInstance(open).hide());
                        bootstrap.Dropdown.getOrCreateInstance(heading).show();
                    }
                });
                heading.addEventListener('keydown', event => {
                    if (!['ArrowLeft','ArrowRight'].includes(event.key)) return;
                    event.preventDefault();
                    const headings = [...document.querySelectorAll('.toolbar-actions .menu-heading[data-bs-toggle="dropdown"]')];
                    const index = headings.indexOf(heading);
                    const next = headings[(index + (event.key === 'ArrowRight' ? 1 : headings.length - 1)) % headings.length];
                    bootstrap.Dropdown.getOrCreateInstance(heading).hide();
                    next.focus();
                    bootstrap.Dropdown.getOrCreateInstance(next).show();
                });
            });
            filesTab.addEventListener('click', () => activateTab(null));

            window.updateEditorTab = function(editorWindow, dirty) {
                if (!dirty) refreshGitStatus();
                editorTabs.forEach(tab => {
                    if (tab.frame.contentWindow === editorWindow) {
                        tab.dirty = dirty;
                        tab.dot.hidden = !dirty;
                        tab.close.title = dirty ? 'Close — unsaved changes' : 'Close';
                        updateWorkspaceTitle();
                        refreshMobileTabs();
                    }
                });
            };
            window.addEventListener('beforeunload', event => {
                saveWorkspaceTabs();
                if ([...editorTabs.values()].some(tabHasChanges)) {
                    event.preventDefault();
                    event.returnValue = '';
                }
            });

            function editorFilePath(name, directory) {
                const full = SERVER_ROOT_PATH + (directory.startsWith('/') ? directory : '/' + directory);
                return full.replace(/\/+$/, '') + '/' + name;
            }
            function openFileEditor(name, directory = currentPath, savedLocation = null, activate = true) {
                const path = editorFilePath(name, directory);
                const serial = activate ? ++openRequestSerial : null;
                if (editorTabs.has(path)) {
                    if (activate) activateTab(path);
                    return Promise.resolve();
                }
                const pending = pendingEditorOpens.get(path);
                if (pending) {
                    if (activate) pending.serial = serial;
                    return pending.promise;
                }
                const entry = {serial, promise: null};
                entry.promise = (async () => {
                    try {
                        const response = await fetch(window.location.pathname + '?editor=1&check=1&filename=' + encodeURIComponent(path));
                        let result;
                        try { result = await response.json(); }
                        catch (_) { throw new Error('Could not check this file. Reload the page and try again.'); }
                        if (!response.ok || result.status !== 'success') throw new Error(result.message || 'Cannot open this file.');
                        createEditorTab(name, directory, savedLocation, entry.serial !== null && entry.serial === openRequestSerial);
                    } catch (error) {
                        window.workspaceAlert(error.message || 'Cannot open this file.', 'Cannot open file', 'warning');
                    } finally { pendingEditorOpens.delete(path); }
                })();
                pendingEditorOpens.set(path, entry);
                return entry.promise;
            }
            function createEditorTab(name, directory, savedLocation, activate = true) {
                const path = editorFilePath(name, directory);
                if (editorTabs.has(path)) {
                    if (activate) activateTab(path);
                    return;
                }
                const id = 'editor-panel-' + (++nextTabId);
                const element = document.createElement('div');
                element.className = 'workspace-tab';
                const button = document.createElement('button');
                button.type = 'button';
                button.setAttribute('role', 'tab');
                button.setAttribute('aria-controls', id);
                button.title = path;
                button.append(createFileIcon(name), document.createTextNode(name));
                const dot = document.createElement('span');
                dot.className = 'tab-dirty';
                dot.textContent = '●';
                dot.hidden = true;
                button.append(dot);
                const close = document.createElement('button');
                close.type = 'button';
                close.className = 'tab-close';
                close.textContent = '×';
                close.title = 'Close';
                close.setAttribute('aria-label', 'Close ' + name);
                const frame = document.createElement('iframe');
                frame.id = id;
                frame.className = 'editor-panel';
                frame.dataset.loading = 'true';
                frame.style.visibility = 'hidden';
                frame.hidden = !activate;
                frame.title = 'Editor: ' + name;
                frame.src = window.location.pathname + '?editor=1&filename=' + encodeURIComponent(path);
                frame.setAttribute('allow', 'fullscreen');
                const tab = {element, button, close, frame, dot, dirty: false, loaded: false, savedLocation};
                editorTabs.set(path, tab);
                button.addEventListener('click', () => activateTab(path));
                close.addEventListener('click', async () => {
                    if (tabHasChanges(tab) && !await window.workspaceConfirm('Discard unsaved changes in ' + name + '?')) return;
                    removeEditorTab(path, tab, true);
                });
                element.append(button, close);
                tabsBar.append(element);
                panels.append(frame);
                frame.addEventListener('load', () => {
                    // Events inside an iframe do not bubble to the workspace document.
                    frame.contentDocument.addEventListener('pointerdown', closeWorkspaceMenus, true);
                    frame.contentDocument.addEventListener('fullscreenchange', updateEditorMenu);
                    frame.contentDocument.addEventListener('keydown', event => {
                        if (event.key === 'Escape') closeWorkspaceMenus();
                    }, true);
                    const source = frame.contentWindow.editor;
                    if (!source || frame.contentWindow.fmEditorThemeReady) {
                        delete frame.dataset.loading;
                        frame.style.visibility = '';
                    }
                    if (!source) {
                        if (frame.contentWindow.fmImagePreview) { tab.loaded = true; updateEditorMenu(); scheduleSaveTabs(); }
                        const error = frame.contentWindow.fmEditorOpenError;
                        if (typeof error === 'string' && editorTabs.get(path) === tab) {
                            removeEditorTab(path, tab, true);
                            window.workspaceAlert(error, 'Cannot open file', 'warning');
                        }
                        return;
                    }
                    tab.loaded = true;
                    if (savedLocation) {
                        const row = Math.min(savedLocation.row, source.session.getLength() - 1);
                        const column = Math.min(savedLocation.column, source.session.getLine(row).length);
                        source.moveCursorTo(row, column);
                        source.clearSelection();
                        source.session.setScrollTop(savedLocation.top);
                        source.session.setScrollLeft(savedLocation.left);
                    }
                    source.selection.on('changeCursor', scheduleSaveTabs);
                    source.session.on('changeScrollTop', scheduleSaveTabs);
                    source.session.on('changeScrollLeft', scheduleSaveTabs);
                    updateEditorMenu();
                    if (activeEditorPath === path) source.resize();
                    scheduleSaveTabs();
                });
                if (activate) {
                    activateTab(path);
                    button.scrollIntoView({block: 'nearest', inline: 'nearest'});
                } else {
                    refreshMobileTabs(); scheduleSaveTabs();
                }
            }

            document.getElementById('edit-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled') && selectedItems.length === 1)
                    openFileEditor(selectedItems[0]);
            });

            // ── Collapse tree ─────────────────────────────────────────
            document.getElementById('collapse-all-btn').addEventListener('click', () => {
                document.querySelectorAll('#directory-tree button[aria-expanded="true"]').forEach(button => button.click());
            });

            function browserFileURL(name, directory) {
                let segments = (directory + '/' + name).split('/').filter(Boolean);
                if (segments.some(segment => segment === '.' || segment === '..' || segment.includes('\\'))) throw new Error('Invalid file path.');
                let base = PUBLIC_WORKSPACE_BASE;
                if (base === null) {
                    const prefix = typeof PUBLIC_WEBSITE_PREFIX === 'string' ? PUBLIC_WEBSITE_PREFIX.split('/').filter(Boolean) : null;
                    if (!prefix || !prefix.every((part, index) => segments[index] === part) || segments.length <= prefix.length) throw new Error('This file has no public URL under the web document root.');
                    segments = segments.slice(prefix.length); base = '';
                }
                return location.origin + base + '/' + segments.map(encodeURIComponent).join('/');
            }
            function canOpenBrowserFile(file) {
                if (!file) return false;
                try { browserFileURL(file.name, file.directory); return true; }
                catch (_) { return false; }
            }
            function openFileInBrowser(name, directory) {
                try { window.open(browserFileURL(name, directory), '_blank', 'noopener,noreferrer'); }
                catch (error) { showAlert('Error', error.message); }
            }
            let phoneQRLibraryPromise = null;
            let phoneQRRequest = 0;
            let phoneQRFile = null;
            function loadPhoneQRLibrary() {
                if (typeof window.qrcode === 'function') return Promise.resolve();
                if (phoneQRLibraryPromise) return phoneQRLibraryPromise;
                phoneQRLibraryPromise = new Promise((resolve, reject) => {
                    const script = document.createElement('script');
                    const timer = setTimeout(() => finish(new Error('Loading timed out.')), 15000);
                    function finish(error) {
                        clearTimeout(timer);
                        script.onload = script.onerror = null;
                        if (error) { script.remove(); phoneQRLibraryPromise = null; reject(error); }
                        else resolve();
                    }
                    script.src = 'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';
                    script.onload = () => finish(typeof window.qrcode === 'function' ? null : new Error('QR library unavailable.'));
                    script.onerror = () => finish(new Error('Could not load the QR library.'));
                    document.head.appendChild(script);
                });
                return phoneQRLibraryPromise;
            }
            async function showPhoneQR(name, directory) {
                let url;
                try { url = browserFileURL(name, directory); }
                catch (error) { showAlert('Error', error.message); return; }
                const request = ++phoneQRRequest;
                const status = document.getElementById('phone-qr-status');
                const retry = document.getElementById('phone-qr-retry');
                const preview = document.getElementById('phone-qr');
                try {
                    phoneQRFile = {name, directory};
                    document.getElementById('phone-file-name').textContent = name;
                    const link = document.getElementById('phone-file-link'); link.href = url; link.textContent = url;
                    preview.hidden = true; retry.hidden = true;
                    status.textContent = 'Loading QR code…';
                    bootstrap.Modal.getOrCreateInstance(document.getElementById('phoneModal')).show();
                    await loadPhoneQRLibrary();
                    if (request !== phoneQRRequest) return;
                    const code = window.qrcode(0, 'M');
                    code.addData(url, 'Byte');
                    code.make();
                    const canvas = document.getElementById('phone-qr');
                    const modules = code.getModuleCount(), quiet = 4, scale = 6;
                    canvas.width = canvas.height = (modules + quiet * 2) * scale;
                    const ctx = canvas.getContext('2d');
                    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
                    ctx.fillStyle = '#000000';
                    for (let row = 0; row < modules; row++) for (let column = 0; column < modules; column++) {
                        if (code.isDark(row, column)) ctx.fillRect((column + quiet) * scale, (row + quiet) * scale, scale, scale);
                    }
                    preview.hidden = false;
                    status.textContent = '';
                } catch (error) {
                    if (request !== phoneQRRequest) return;
                    status.textContent = 'Could not create QR code. You can retry or copy the link.';
                    retry.hidden = false;
                }
            }
            document.getElementById('phone-qr-retry').addEventListener('click', () => {
                if (phoneQRFile) showPhoneQR(phoneQRFile.name, phoneQRFile.directory);
            });
            document.getElementById('phoneModal').addEventListener('hidden.bs.modal', () => { ++phoneQRRequest; });
            document.getElementById('phone-copy-link').addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(document.getElementById('phone-file-link').href);
                    window.workspaceToast('Link copied.', 'Copied');
                } catch (_) { showAlert('Copy link', 'Select and copy the link shown in this window.'); }
            });
            function selectedBrowserFile() {
                if (activeEditorPath !== null) {
                    const relative = activeEditorPath.substring(workspaceRoot.length);
                    const split = relative.lastIndexOf('/');
                    return {name: relative.substring(split + 1), directory: relative.substring(0, split)};
                }
                if (selectedItems.length === 1) return {name: selectedItems[0], directory: currentPath};
                return null;
            }
            [['open-browser-btn', openFileInBrowser], ['open-phone-btn', showPhoneQR]].forEach(([id, action]) => {
                document.getElementById(id).addEventListener('click', event => {
                    event.preventDefault();
                    if (event.currentTarget.classList.contains('disabled')) return;
                    const file = selectedBrowserFile();
                    if (file) action(file.name, file.directory);
                });
            });

            // ── Context menu actions ──────────────────────────────────
            const contextActions = {
                'ctx-copy': 'copy-btn', 'ctx-cut': 'move-btn', 'ctx-rename': 'rename-btn',
                'ctx-delete': 'delete-btn', 'ctx-permissions': 'permissions-btn', 'ctx-compress': 'compress-btn', 'ctx-extract': 'extract-btn'
            };
            let contextActionBusy = false;
            document.getElementById('context-menu').addEventListener('click', async event => {
                const id = event.target.closest('.context-menu-item')?.id;
                const target = contextTarget;
                if (!id || !target || contextActionBusy) return;
                hideContextMenu();
                const path = (target.directory + '/' + target.name).replace(/\/+/g, '/');
                if (id === 'ctx-open') { activateTab(null); navigateTo(path); return; }
                if (id === 'ctx-edit') { openFileEditor(target.name, target.directory); return; }
                if (id === 'ctx-browser') { openFileInBrowser(target.name, target.directory); return; }
                if (id === 'ctx-phone') { showPhoneQR(target.name, target.directory); return; }
                if (id === 'ctx-download') {
                    if (target.type === 'file') window.location.href = window.location.pathname + '?action=download&path=' + encodeURIComponent(target.directory) + '&file=' + encodeURIComponent(target.name);
                    return;
                }
                const action = contextActions[id];
                if (!action) return;
                contextActionBusy = true;
                try {
                    const editorPath = workspaceRoot + path;
                    const tab = editorTabs.get(editorPath);
                    if (tabHasChanges(tab)) { showAlert('Unsaved changes', 'Save this file before applying this operation.'); return; }
                    activateTab(null);
                    currentPath = target.directory;
                    await loadFileList();
                    // Do not apply a late menu action after navigation to another folder.
                    if ((currentPath || '/') !== (target.directory || '/')) return;
                    if (!fileList.some(item => item.name === target.name)) throw new Error('The selected file is no longer available.');
                    selectedItems = [target.name];
                    document.querySelectorAll('#files-list .file-item').forEach(row => {
                        const selected = row.dataset.name === target.name;
                        row.classList.toggle('selected', selected);
                        row.querySelector('.item-check').checked = selected;
                    });
                    updateButtonStates();
                    if (tab && ['ctx-copy', 'ctx-cut', 'ctx-rename', 'ctx-delete'].includes(id)) activateTab(editorPath);
                    document.getElementById(action).click();
                } catch (error) { showAlert('Error', error.message || 'Could not open file action.'); }
                finally { contextActionBusy = false; }
            });

            // ── HTMX hooks ────────────────────────────────────────────
            document.addEventListener('submit', evt => {
                evt.target.querySelectorAll("button[type='submit']").forEach(btn => {
                    if (btn.offsetParent !== null) {
                        btn.disabled = true;
                        btn.style.opacity = '0.5';
                    }
                });
            });

            document.addEventListener('htmx:afterRequest', evt => {
                if (hasResponseError) {
                    hasResponseError = false;
                    return;
                }

                document.querySelectorAll("button[type='submit']").forEach(btn => {
                    btn.disabled = false;
                    btn.style.opacity = '1';
                });

                const raw = evt.detail.xhr.response;
                if (!raw || !raw.trim()) return;

                try {
                    const data = JSON.parse(raw);
                    document.querySelectorAll('.modal.fade.show').forEach(el => {
                        (bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el)).hide();
                    });
                    if (data.status === 'success') {
                        if (data.type && data.type == 'confirm') {
                            loadFileList();
                            loadDirectoryTree();
                            showAlert('Success', data.message, 'confirm');
                        } else {
                            loadFileList();
                            loadDirectoryTree();
                            showAlert('Success', data.message);
                        }


                    } else {
                        showAlert('Error', data.message);
                    }
                } catch (e) {
                    showAlert('Error', e.message);
                }
            });

            document.body.addEventListener('htmx:responseError', e => {
                hasResponseError = true;
                document.querySelectorAll("button[type='submit']").forEach(btn => {
                    btn.disabled = false;
                    btn.style.opacity = '1';
                });
                try {
                    const data = JSON.parse(e.detail.xhr.response);
                    window.workspaceToast(data.text || data.message || 'Something went wrong!', data.title || 'Error', 'error');
                } catch {
                    window.workspaceToast('Request failed', 'Error', 'error');
                }
            });

            init();
            restoreWorkspaceTabs();
            window.fmWorkspaceReady = true;
            const blockedLoginIPs = <?= json_encode($loginBlockedNotice) ?>;
            if (blockedLoginIPs > 0) window.workspaceToast(blockedLoginIPs + (blockedLoginIPs === 1 ? ' IP address is' : ' IP addresses are') + ' temporarily blocked. See Tools → Login activity.', 'Login activity', 'warning');
        });
    </script>
</body>

</html>
