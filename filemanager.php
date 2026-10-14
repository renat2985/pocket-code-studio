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
function fmLoginAttempt($password, $hash)
{
    $directory = fmPrivateAuthDirectory();
    $path = $directory . '/attempts.json';
    if (is_link($path)) fmAuthReply(503, 'Invalid authentication storage.');
    $handle = @fopen($path, 'c+');
    if (!$handle || !@chmod($path, 0600) || !flock($handle, LOCK_EX)) fmAuthReply(503, 'Cannot lock authentication storage.');
    $state = json_decode(stream_get_contents($handle), true) ?: [];
    $now = time();
    foreach ($state as $key => $value) if ($value['since'] < $now - 900) unset($state[$key]);
    $key = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $blocked = ($state[$key]['count'] ?? 0) >= 8 || ($state['global']['count'] ?? 0) >= 64;
    $valid = !$blocked && is_string($password) && strlen($password) <= 72 && password_verify($password, $hash);
    if (!$valid && !$blocked) {
        foreach ([$key, 'global'] as $counter) {
            $state[$counter] = ['since' => $state[$counter]['since'] ?? $now, 'count' => ($state[$counter]['count'] ?? 0) + 1];
        }
    }
    if ($valid) unset($state[$key]);
    $json = json_encode($state);
    rewind($handle);
    $written = fwrite($handle, $json);
    $stored = $written === strlen($json) && ftruncate($handle, strlen($json)) && fflush($handle);
    flock($handle, LOCK_UN); fclose($handle);
    if (!$stored) fmAuthReply(503, 'Cannot record login attempt. Access denied.');
    return [$valid, $blocked];
}
function fmUpdatePasswordHash($oldHash, $newHash)
{
    $directory = fmPrivateAuthDirectory();
    $lockPath = $directory . '/password.lock';
    if (is_link($lockPath)) throw new RuntimeException('Invalid password lock.');
    $lock = @fopen($lockPath, 'c');
    if (!$lock || !@chmod($lockPath, 0600) || !flock($lock, LOCK_EX)) throw new RuntimeException('Cannot lock password configuration.');
    $temporary = null;
    try {
        $source = file_get_contents(__FILE__);
        $pattern = '/^\$authPasswordHash = \'[^\']*\';$/m';
        if (preg_match_all($pattern, $source, $matches) !== 1 || $matches[0][0] !== '$authPasswordHash = ' . var_export($oldHash, true) . ';') throw new RuntimeException('Password configuration changed. Reload and try again.');
        $replacement = '$authPasswordHash = ' . var_export($newHash, true) . ';';
        $updated = preg_replace_callback($pattern, function () use ($replacement) { return $replacement; }, $source, 1);
        $backup = $directory . '/password-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(5)) . '.bak';
        if (@file_put_contents($backup, $source, LOCK_EX) !== strlen($source) || !@chmod($backup, 0600) || hash_file('sha256', $backup) !== hash('sha256', $source)) throw new RuntimeException('Cannot verify configuration backup. Password unchanged.');
        $temporary = tempnam(dirname(__FILE__), '.fm-auth-save-');
        if (!$temporary || dirname($temporary) !== dirname(__FILE__)) throw new RuntimeException('Cannot create temporary configuration.');
        if (@file_put_contents($temporary, $updated, LOCK_EX) !== strlen($updated) || hash_file('sha256', $temporary) !== hash('sha256', $updated)) throw new RuntimeException('Configuration write failed.');
        $stat = stat(__FILE__); $tempStat = stat($temporary);
        if ($stat['uid'] !== $tempStat['uid'] && !@chown($temporary, $stat['uid'])) throw new RuntimeException('Cannot preserve configuration owner.');
        if ($stat['gid'] !== $tempStat['gid'] && !@chgrp($temporary, $stat['gid'])) throw new RuntimeException('Cannot preserve configuration group.');
        if (!@chmod($temporary, $stat['mode'] & 0777) || hash_file('sha256', __FILE__) !== hash('sha256', $source) || !@rename($temporary, __FILE__)) throw new RuntimeException('Cannot replace configuration safely.');
        $temporary = null;
        if (function_exists('opcache_invalidate')) @opcache_invalidate(__FILE__, true);
    } finally {
        if ($temporary && is_file($temporary)) @unlink($temporary);
        flock($lock, LOCK_UN); fclose($lock);
    }
}

// Read the current hash from disk so OPcache cannot keep an old password valid.
$authHeader = @file_get_contents(__FILE__, false, null, 0, 8192);
if ($authHeader === false || preg_match('/^\$authPasswordHash = \'([^\']+)\';$/m', $authHeader, $authMatch) !== 1 || password_get_info($authMatch[1])['algoName'] === 'unknown') fmAuthReply(503, 'Pocket Code Studio is not configured. Set a unique password hash in filemanager.php before use. Access denied.');
$authPasswordHash = $authMatch[1];

header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
$authHTTPS = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$authLocal = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);
if (!$authHTTPS && !$authLocal) {
    http_response_code(403);
    die('HTTPS is required for this file manager.');
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
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        session_write_close();
        header('Location: ' . $_SERVER['SCRIPT_NAME'], true, 303);
        exit;
    }
    $loginError = $blocked ? 'Too many attempts. Try again in 15 minutes.' : 'Incorrect password.';
    http_response_code($blocked ? 429 : 401);
}
if (!$authenticated) {
    unset($_SESSION['auth'], $_SESSION['auth_started'], $_SESSION['auth_seen']);
    $isDataRequest = isset($_GET['editor'], $_GET['filename']) || isset($_GET['action']) || ($isPostRequest && $authAction !== 'login');
    if ($isDataRequest) fmAuthReply(401, 'Authentication required.');
    if (!$loginError) http_response_code(401);
    ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in — Pocket Code Studio</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#21252b;color:#abb2bf;font:14px system-ui}form{width:min(340px,80vw);padding:28px;background:#282c34;border:1px solid #3b4048;border-radius:8px}h1{font-size:20px;margin:0 0 24px}label{display:block;margin-bottom:8px}input,button{box-sizing:border-box;width:100%;padding:10px;border-radius:4px;font:inherit}input{background:#21252b;color:#abb2bf;border:1px solid #495162}button{margin-top:16px;background:#528bff;color:white;border:0;cursor:pointer}.error{color:#ef596f}small{display:block;margin-top:18px;color:#7f848e}</style></head><body>
<form method="post" action="<?= htmlspecialchars($_SERVER['SCRIPT_NAME'], ENT_QUOTES, 'UTF-8') ?>">
<h1>Pocket Code Studio</h1><input type="hidden" name="fm_auth_action" value="login"><input type="hidden" name="fm_csrf" value="<?= htmlspecialchars($fmCSRFToken, ENT_QUOTES, 'UTF-8') ?>">
<label for="login-password">Password</label><input type="password" id="login-password" name="password" autocomplete="current-password" maxlength="72" required autofocus>
<?php if ($loginError): ?><p class="error" role="alert"><?= htmlspecialchars($loginError, ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?>
<button type="submit">Sign in</button><small>File access requires authentication.</small></form></body></html>
<?php session_write_close(); exit;
}
$_SESSION['auth_seen'] = $authNow;
if ($authAction === 'logout' && $isPostRequest) {
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $authHTTPS, 'httponly' => true, 'samesite' => 'Strict']);
    fmAuthReply(200, 'Signed out.');
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
session_write_close();
// No application code or file operation executes before this authentication gate.

$username = "Renat2985";
$root_path = $_SERVER['DOCUMENT_ROOT'];

// Configuration
$config = [
    "root_path" => $root_path,
    "allowed_extensions" => ["*"],
    "timezone" => "Africa/Lagos",
    "date_format" => "M j Y, g:i A",
    "font_size" => "16px",
];

if (file_exists("$root_path/.fm-config")) {
    $userConfig = "$root_path/.fm-config";
    $settings = json_decode(file_get_contents($userConfig), true);

    $config['timezone'] = $settings['timezone'] ?? $config['timezone'];
    $config['date_format'] = $settings['date_format'] ?? $config['date_format'];
    $config['font_size'] = $settings['font_size'] ?? $config['font_size'];
}

// Set timezone
date_default_timezone_set($config["timezone"]);

/*
Embedded Seti file icons from microsoft/vscode/extensions/theme-seti.

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
    const palettes = {
        theme_mix: ['#282c34','#21252b','#252a32','#2c313c','#abb2bf','#9da5b4','#7f848e','#528bff','#d19a66'],
        one_dark: ['#282c34','#21252b','#252a32','#2c313c','#abb2bf','#9da5b4','#7f848e','#61afef','#e5c07b'],
        nord_dark: ['#2e3440','#272d38','#343c4a','#434c5e','#d8dee9','#c4cbd7','#a2adbf','#88c0d0','#ebcb8b'],
        tomorrow_night_eighties: ['#2d2d2d','#252525','#333333','#414141','#cccccc','#b7b7b7','#999999','#6699cc','#ffcc66'],
        cobalt: ['#002240','#001b33','#002c50','#00375f','#ffffff','#b7cee5','#83a5c6','#0088ff','#ffc600'],
        monokai: ['#272822','#20211c','#2c2d27','#3e3d32','#f8f8f2','#cfcfc2','#939387','#a6e22e','#e6db74'],
        dracula: ['#282a36','#21222c','#2c2e3c','#44475a','#f8f8f2','#c7c9df','#9296b3','#bd93f9','#f1fa8c'],
        tomorrow_night: ['#1d1f21','#181a1c','#252729','#373b41','#c5c8c6','#aeb2b0','#909592','#81a2be','#f0c674'],
        github_dark: ['#0d1117','#161b22','#1c2128','#30363d','#c9d1d9','#b1bac4','#8b949e','#58a6ff','#d29922'],
        github: ['#ffffff','#f6f8fa','#eef1f4','#e1e5eb','#24292f','#414a53','#57606a','#0969da','#9a6700'],
        tomorrow: ['#ffffff','#f3f3f3','#ececec','#dddddd','#4d4d4c','#60605e','#71716e','#4271ae','#a37b00'],
        kuroir: ['#e8e9e8','#dedfdd','#d4d6d3','#c5c8c3','#363636','#4b504b','#61675e','#316e8a','#88610e']
    };
    function applyPalette(theme) {
        if (!palettes[theme]) theme = 'theme_mix';
        const [deep, main, surface, elevated, text, secondary, muted, accent, folder] = palettes[theme];
        const light = ['github','tomorrow','kuroir'].includes(theme);
        function contrastColor(hex) {
            const rgb = [1,3,5].map(offset => parseInt(hex.slice(offset, offset+2),16)/255).map(value => value <= 0.04045 ? value/12.92 : Math.pow((value+0.055)/1.055,2.4));
            return 0.2126*rgb[0]+0.7152*rgb[1]+0.0722*rgb[2] > 0.179 ? '#18202b' : '#ffffff';
        }
        const vars = {
            'bg-deep':deep, 'bg-main':main, 'bg-surface':surface, 'bg-elevated':elevated,
            'bg-hover':light ? '#00000008' : '#ffffff08', 'bg-selected':accent+'20',
            'border-subtle':light ? '#00000012' : '#ffffff12', 'border-default':light ? '#00000026' : '#ffffff26',
            'border-accent':accent, 'text-primary':text, 'text-secondary':secondary, 'text-muted':muted,
            'text-link':accent, 'text-link-hover':accent, 'accent':accent, 'accent-hover':accent,
            'accent-success':light ? '#1a7f37' : '#89ca78', 'accent-danger':light ? '#cf222e' : '#ef596f',
            'accent-contrast':contrastColor(accent), 'danger-contrast':contrastColor(light ? '#cf222e' : '#ef596f'), 'accent-warning':folder, 'folder-color':folder, 'scrollbar-gold':muted, 'scrollbar-gold-hover':accent
        };
        for (const [key,value] of Object.entries(vars)) document.documentElement.style.setProperty('--'+key,value);
        document.documentElement.style.colorScheme = light ? 'light' : 'dark';
        document.documentElement.dataset.workspaceTheme = theme;
        const select = document.getElementById('workspace-theme');
        if (select) select.value = theme;
        return theme;
    }
    window.setWorkspaceTheme = function(theme) {
        theme = applyPalette(theme);
        localStorage.setItem('ke_theme', theme);
        document.cookie = 'fm_theme='+encodeURIComponent(theme)+'; Max-Age=31536000; Path=/; SameSite=Lax'+(location.protocol === 'https:' ? '; Secure' : '');
        if (typeof window.applySelectedTheme === 'function') window.applySelectedTheme(theme);
        document.querySelectorAll('iframe.editor-panel').forEach(frame => {
            if (typeof frame.contentWindow.applySelectedTheme === 'function') frame.contentWindow.applySelectedTheme(theme);
        });
    };
    window.workspaceAlert = function(message, title = 'Editor') {
        if (window.parent !== window && typeof window.parent.workspaceAlert === 'function') return window.parent.workspaceAlert(message, title);
        if (typeof CoolAlert !== 'undefined') return CoolAlert.show({title, text: String(message), icon: 'info', showCancelButton: false, confirmButtonText: 'OK'});
        window.alert(message);
        return Promise.resolve({isConfirmed: true});
    };
    window.workspaceConfirm = function(message) {
        if (window.parent !== window && typeof window.parent.workspaceConfirm === 'function') return window.parent.workspaceConfirm(message);
        if (typeof CoolAlert !== 'undefined') return CoolAlert.show({title: 'Unsaved changes', text: String(message), icon: 'warning', showCancelButton: true, confirmButtonText: 'Discard changes', cancelButtonText: 'Keep editing'}).then(result => result.isConfirmed);
        return Promise.resolve(window.confirm(message));
    };
    window.applyWorkspacePalette = applyPalette;
    const cookie = document.cookie.split('; ').find(item => item.startsWith('fm_theme='));
    const saved = localStorage.getItem('ke_theme') || (cookie ? decodeURIComponent(cookie.substring(9)) : 'theme_mix');
    applyPalette(saved);
    document.addEventListener('DOMContentLoaded', () => applyPalette(document.documentElement.dataset.workspaceTheme));
    window.addEventListener('storage', event => {
        if (event.key === 'ke_theme' && event.newValue) {
            applyPalette(event.newValue);
            if (typeof window.applySelectedTheme === 'function') window.applySelectedTheme(event.newValue);
        }
    });
})();
</script>

<style>
    /* Shared floating surfaces follow the workspace theme, including light palettes. */
    .modal { --bs-body-color: var(--text-primary); --bs-body-bg: var(--bg-main); --bs-border-color: var(--border-default); }
    .modal .table {
        --bs-table-color: var(--text-primary); --bs-table-bg: var(--bg-surface);
        --bs-table-border-color: var(--border-subtle); --bs-table-striped-color: var(--text-primary);
        --bs-table-striped-bg: var(--bg-hover); --bs-table-hover-color: var(--text-primary);
        --bs-table-hover-bg: var(--bg-selected); --bs-table-active-color: var(--text-primary);
        --bs-table-active-bg: var(--bg-selected); color: var(--text-primary);
    }
    .modal .table thead th { background: var(--bg-elevated); color: var(--text-secondary); border-color: var(--border-subtle); font-size: 0.75rem; font-weight: 500; }
    .modal .table td { font-size: 0.8rem; border-color: var(--border-subtle); vertical-align: middle; }
    .modal .table-responsive { max-height: 65vh; overflow: auto; }
    .modal .table thead th { position: sticky; top: 0; z-index: 1; }
    .modal .text-muted, .modal .form-text, .modal small { color: var(--text-muted) !important; }
    .modal .form-select option { background: var(--bg-deep); color: var(--text-primary); }
    .modal .form-control:focus, .modal .form-select:focus { box-shadow: 0 0 0 2px var(--bg-selected); }
    .modal .btn-primary {
        --bs-btn-bg: var(--accent); --bs-btn-border-color: var(--accent);
        --bs-btn-hover-bg: var(--accent-hover); --bs-btn-hover-border-color: var(--accent-hover);
        --bs-btn-active-bg: var(--accent-hover); --bs-btn-active-border-color: var(--accent-hover);
        color: var(--accent-contrast) !important;
    }
    .modal .btn-secondary, .modal .btn[data-bs-dismiss="modal"] {
        background: var(--bg-elevated) !important; border-color: var(--border-default) !important; color: var(--text-secondary) !important;
    }
    .modal .btn-secondary:hover, .modal .btn[data-bs-dismiss="modal"]:hover { background: var(--bg-hover) !important; color: var(--text-primary) !important; }
    .modal .btn-danger:not([data-bs-dismiss]) { background: var(--accent-danger); border-color: var(--accent-danger); color: var(--danger-contrast); }
    .modal .btn-close { filter: invert(1) grayscale(1); opacity: 0.75; }
    :root[data-workspace-theme="github"] .modal .btn-close,
    :root[data-workspace-theme="tomorrow"] .modal .btn-close,
    :root[data-workspace-theme="kuroir"] .modal .btn-close { filter: none; }
    .cool-alert-modal, .cool-alert-toast { background: var(--bg-main) !important; color: var(--text-primary) !important; border: 1px solid var(--border-default) !important; box-shadow: 0 8px 32px #00000040 !important; }
    .cool-alert-modal-header { background: var(--bg-surface) !important; border-color: var(--border-subtle) !important; }
    .cool-alert-modal-title, .cool-alert-toast-title, .cool-alert-title { color: var(--text-primary) !important; }
    .cool-alert-modal-message, .cool-alert-toast-message, .cool-alert-text { color: var(--text-secondary) !important; }
    .cool-alert-modal-btn { border-radius: 4px !important; font-size: 0.8rem !important; }
    .cool-alert-modal-btn.cool-alert-primary { background: var(--accent) !important; color: var(--accent-contrast) !important; border-color: var(--accent) !important; }
    .cool-alert-modal-btn.cool-alert-secondary { background: var(--bg-elevated) !important; color: var(--text-secondary) !important; border: 1px solid var(--border-default) !important; }
    .cool-alert-modal-btn.cool-alert-danger { background: var(--accent-danger) !important; color: var(--danger-contrast) !important; }
    .cool-alert-close, .cool-alert-toast-close { background: transparent !important; color: var(--text-secondary) !important; }
    .modal .alert-info { background: var(--bg-selected); color: var(--text-primary); border-color: var(--border-default); }
    .modal .alert-warning, .modal .alert-danger { background: var(--bg-elevated); color: var(--text-primary); border-color: var(--border-default); }
    .modal .alert-warning { border-left: 3px solid var(--accent-warning); }
    .modal .alert-danger { border-left: 3px solid var(--accent-danger); }
    .ace_tooltip { background: var(--bg-elevated) !important; color: var(--text-primary) !important; border-color: var(--border-default) !important; }
    .ace_search { background: var(--bg-main) !important; color: var(--text-primary) !important; border-color: var(--border-default) !important; box-shadow: 0 4px 16px #00000030; }
    .ace_search_field { background: var(--bg-deep) !important; color: var(--text-primary) !important; border-color: var(--border-default) !important; }
    .ace_searchbtn, .ace_replacebtn { background: var(--bg-elevated) !important; color: var(--text-secondary) !important; border-color: var(--border-default) !important; }
    .ace_search_options { color: var(--text-secondary) !important; }
    .ace_search_options .ace_button { color: var(--text-secondary) !important; }
    .ace_search_options .ace_button.checked { background: var(--bg-selected) !important; color: var(--text-link) !important; border-color: var(--accent) !important; }
    .ace_editor.ace_autocomplete { background: var(--bg-main) !important; color: var(--text-primary) !important; border-color: var(--border-default) !important; }
    .ace_autocomplete .ace_marker-layer .ace_active-line { background: var(--bg-selected) !important; }
</style>

JS;
$workspaceThemeScript = str_replace('__FM_CSRF_TOKEN__', json_encode($fmCSRFToken), $workspaceThemeScript);

// Read-only Git integration. Argument arrays avoid shell interpretation.
function fmGitRun($directory, $arguments, $accepted = [0]) {
    if (!function_exists('proc_open')) throw new RuntimeException('PHP proc_open is disabled; Git integration is unavailable.');
    $command = array_merge(['git', '--literal-pathspecs', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'color.ui=false', '-C', $directory], $arguments);
    $process = @proc_open($command, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes, null, null, ['bypass_shell'=>true]);
    if (!is_resource($process)) throw new RuntimeException('Cannot start Git on this server.');
    fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    $out = ''; $err = ''; $start = microtime(true); $code = -1;
    try {
        while (true) {
            $out .= stream_get_contents($pipes[1]); $err .= stream_get_contents($pipes[2]);
            if (strlen($out)+strlen($err)>12*1024*1024 || microtime(true)-$start>8) throw new RuntimeException('Git operation exceeded its time or size limit.');
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
            $result=['status'=>'success','files'=>$statuses];
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
    } catch (Throwable $error) { http_response_code(400); $result=['status'=>'error','message'=>$error->getMessage()]; }
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
    die('Invalid file specified.');
}
header('Cache-Control: no-store');
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
if (filesize($filename) > $maxEditorBytes) die('File is too large for safe editing (maximum 8 MB).');
$fileContents = @file_get_contents($filename);
if ($fileContents === false) die('Cannot read file. Saving is disabled.');
try { $originalNewline = editorTextFormat($fileContents); }
catch (Throwable $error) { die(htmlspecialchars($error->getMessage(), ENT_QUOTES, 'UTF-8')); }
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

$fileSize = filesize($filename);
$lastModified = date("M j Y, g:i A", filemtime($filename));
$lineCount = substr_count(file_get_contents($filename), "\n") + 1;
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <?= $workspaceThemeScript ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($basename) ?> — Pocket Code Studio</title>
    <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiMyMTI1MmIiLz48cGF0aCBkPSJtMjMgMjAtMTIgMTIgMTIgMTJtMTgtMjQgMTIgMTItMTIgMTJtLTYtMjgtNiAzMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNjFhZmVmIiBzdHJva2Utd2lkdGg9IjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==" type="image/svg+xml">

    <!-- Ace Editor -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ext-language_tools.js"></script>

    <!-- Prettier -->
    <script src="https://unpkg.com/prettier@2.7.1/standalone.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-html.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-babel.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-postcss.js"></script>
    <script src="https://unpkg.com/@prettier/plugin-php@0.19.0/standalone.js"></script>
    <script src="https://unpkg.com/@prettier/plugin-php@0.19.0/parser-php.js"></script>
    <script src="https://unpkg.com/prettier@2.7.1/parser-markdown.js"></script>

    <!-- Font Awesome 6 (matches file manager) -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">

    <style>
        /* ── Design Tokens (matches filemanager v3.0) ────────────── */
        :root {
            --bg-deep: #0f1117;
            --bg-main: #1a1d2e;
            --bg-surface: #1e2235;
            --bg-elevated: #242840;
            --bg-hover: rgba(255, 255, 255, 0.04);

            --border-subtle: rgba(255, 255, 255, 0.06);
            --border-default: rgba(255, 255, 255, 0.10);
            --border-accent: #3b82f6;

            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --text-link: #60a5fa;

            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
            --accent-warning: #f59e0b;

            --scrollbar-gold: #c9a227;
            --scrollbar-gold-hover: #f0c040;

            --radius-sm: 4px;
            --radius-md: 6px;
            --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);

            --font-mono: 'Fira Code', 'Cascadia Code', 'Courier New', monospace;
        }

        /* ── Reset ───────────────────────────────────────────────── */
        *,
        *::before,
        *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html,
        body {
            height: 100%;
            overflow: hidden;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 16px;
            background: var(--bg-deep);
            color: var(--text-primary);
        }

        ::-webkit-scrollbar {
            width: 5px;
            height: 5px;
        }

        ::-webkit-scrollbar-track {
            background: transparent;
        }

        ::-webkit-scrollbar-thumb {
            background: var(--scrollbar-gold);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--scrollbar-gold-hover);
        }

        /* ── Top Bar ─────────────────────────────────────────────── */
        #topbar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 46px;
            background: var(--bg-main);
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 12px;
            z-index: 200;
            gap: 8px;
        }

        .topbar-left {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 0;
            flex: 1;
        }

        .brand-logo {
            display: flex;
            align-items: center;
        }

        .brand-logo img {
            height: 24px;
            display: block;
        }

        .file-badge {
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-sm);
            padding: 3px 10px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            min-width: 0;
            max-width: 500px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .file-badge i {
            color: var(--accent);
            font-size: 0.72rem;
            flex-shrink: 0;
        }

        .file-badge .fname {
            color: var(--text-link);
            font-weight: 600;
        }

        .unsaved-dot {
            width: 7px;
            height: 7px;
            background: var(--accent-warning);
            border-radius: 50%;
            flex-shrink: 0;
            display: none;
        }

        .unsaved-dot.visible {
            display: inline-block;
        }

        .topbar-right {
            display: flex;
            align-items: center;
            gap: 4px;
            flex-shrink: 0;
        }

        /* ── Toolbar Selects ─────────────────────────────────────── */
        .tb-select {
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            color: var(--text-secondary);
            font-size: 0.75rem;
            padding: 3px 8px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            outline: none;
            transition: border-color 0.15s;
            -webkit-appearance: none;
            appearance: none;
            padding-right: 20px;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2364748b'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 6px center;
        }

        .tb-select:focus,
        .tb-select:hover {
            border-color: var(--accent);
            color: var(--text-primary);
        }

        .tb-select option {
            background: var(--bg-elevated);
            color: var(--text-primary);
        }

        /* ── Toolbar Buttons ─────────────────────────────────────── */
        .tb-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            font-size: 0.75rem;
            font-weight: 500;
            border: 1px solid var(--border-default);
            border-radius: var(--radius-sm);
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .tb-btn i {
            font-size: 0.68rem;
        }

        .tb-btn:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
            border-color: var(--border-default);
        }

        .tb-btn.primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        .tb-btn.primary:hover {
            background: var(--accent-hover);
            border-color: var(--accent-hover);
        }

        .tb-btn.primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .tb-btn.success {
            background: var(--accent-success);
            border-color: var(--accent-success);
            color: #fff;
        }

        .tb-btn.success:hover {
            background: #059669;
            border-color: #059669;
        }

        .tb-btn.success:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .tb-divider {
            width: 1px;
            height: 18px;
            background: var(--border-subtle);
            margin: 0 2px;
        }

        /* ── Second toolbar (sub-bar) ────────────────────────────── */
        #subbar {
            position: fixed;
            top: 46px;
            left: 0;
            right: 0;
            height: 34px;
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            padding: 0 12px;
            gap: 4px;
            z-index: 199;
        }

        /* ── Editor Area ─────────────────────────────────────────── */
        #editor-wrap {
            position: fixed;
            top: 80px;
            bottom: 24px;
            /* status bar */
            left: 0;
            right: 0;
        }

        #editor {
            width: 100%;
            height: 100%;
            font-size: 14px;
        }

        /* ── Status Bar ──────────────────────────────────────────── */
        #statusbar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            height: 24px;
            background: var(--bg-elevated);
            border-top: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 12px;
            font-size: 0.68rem;
            color: var(--text-muted);
            z-index: 200;
            gap: 12px;
        }

        .statusbar-left,
        .statusbar-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .status-item i {
            font-size: 0.6rem;
        }

        #status-saved {
            color: var(--accent-success);
            font-weight: 600;
            display: none;
        }

        #status-cursor {
            color: var(--text-secondary);
        }

        /* ── Save notification toast ─────────────────────────────── */
        #save-toast {
            position: fixed;
            top: 56px;
            right: 16px;
            background: var(--bg-elevated);
            border: 1px solid var(--accent-success);
            border-radius: var(--radius-md);
            color: var(--accent-success);
            padding: 8px 16px;
            font-size: 0.8rem;
            font-weight: 600;
            display: none;
            align-items: center;
            gap: 8px;
            z-index: 9999;
            box-shadow: var(--shadow-lg);
            animation: slideIn 0.2s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-8px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* ── Spinner (initial load) ───────────────────────────────── */
        #spinner-overlay {
            position: fixed;
            inset: 0;
            background: var(--bg-deep);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            gap: 16px;
        }

        .spinner {
            width: 32px;
            height: 32px;
            border: 3px solid var(--border-default);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .spinner-label {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* ── Kbd shortcuts hint ──────────────────────────────────── */
        kbd {
            display: inline-block;
            background: var(--bg-deep);
            border: 1px solid var(--border-default);
            border-radius: 3px;
            padding: 1px 5px;
            font-size: 0.65rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }
        #git-diff-dialog { margin: auto; width: min(1000px, 94vw); max-height: 88vh; background: var(--bg-main); color: var(--text-primary); border: 1px solid var(--border-default); border-radius: 6px; padding: 0; }
        #git-diff-dialog::backdrop { background: #0008; }
        .git-diff-title { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: var(--bg-elevated); }
        #git-diff-close { background: transparent; border: 0; color: var(--text-primary); font-size: 24px; cursor: pointer; }
        #git-diff-output { margin: 0; padding: 12px; max-height: 72vh; overflow: auto; font: 12px/1.6 monospace; white-space: pre; }
        .git-added { background: #33995522; color: var(--text-primary); border-left: 3px solid #43a866; }
        .git-removed { background: #dd445522; color: var(--text-primary); border-left: 3px solid #e06c75; }
        .git-hunk { color: var(--text-link); }
        /* Fit the editor inside narrow internal tabs. */
        body { display: flex; flex-direction: column; overflow: hidden; }
        #topbar { position: static; height: auto; min-height: 36px; flex-shrink: 0; flex-wrap: wrap; justify-content: flex-start; gap: 4px; padding: 4px 8px; }
        #topbar .file-badge { max-width: 160px; flex-shrink: 1; padding: 3px 6px; }
        #topbar .tb-select { max-width: 125px; }
        .topbar-left { flex-basis: 100%; }
        .topbar-right { flex-wrap: wrap; flex-shrink: 1; }

        #subbar { position: static; flex-shrink: 0; overflow: hidden; white-space: nowrap; }
        #subbar > span:first-child { overflow: hidden; text-overflow: ellipsis; }
        #editor-wrap { position: relative; inset: auto; flex: 1; min-height: 0; display: flex; }
        #editor { flex: 1; min-width: 0; width: auto; }
        /* The minimap handles vertical navigation; keep Ace's own bar as a fallback. */
        #editor-wrap { overflow: hidden; }
        #editor .ace_scrollbar-v { visibility: hidden; pointer-events: none; }
        body.minimap-hidden #editor .ace_scrollbar-v { visibility: visible; pointer-events: auto; }
        #editor .ace_scrollbar { scrollbar-width: thin; scrollbar-color: var(--scrollbar-gold) var(--bg-main); }
        #editor .ace_scrollbar::-webkit-scrollbar { width: 10px; height: 10px; }
        #editor .ace_scrollbar::-webkit-scrollbar-track { background: var(--bg-main); }
        #editor .ace_scrollbar::-webkit-scrollbar-thumb { background: var(--scrollbar-gold); border: 2px solid var(--bg-main); border-radius: 5px; }
        #editor .ace_scrollbar::-webkit-scrollbar-thumb:hover { background: var(--scrollbar-gold-hover); }
        #editor .ace_scrollbar::-webkit-scrollbar-corner { background: var(--bg-main); }

        #minimap { position: relative; width: 112px; flex-shrink: 0; overflow: hidden; touch-action: none; cursor: pointer; border-left: 1px solid var(--border-subtle); }
        #minimap[hidden] { display: none; }
        #occurrence-rail { width: 12px; flex-shrink: 0; position: relative; background: var(--bg-main); border-left: 1px solid var(--border-subtle); cursor: pointer; touch-action: none; outline: none; }
        #occurrence-rail:focus-visible { outline: 1px solid var(--accent); outline-offset: -1px; }
        #occurrence-rail canvas { width: 100%; height: 100%; display: block; pointer-events: none; }
        #minimap canvas { display: block; width: 100%; height: 100%; pointer-events: none; }
        #minimap-viewport { position: absolute; left: 0; right: 0; background: #abb2bf20; border: 1px solid #abb2bf40; pointer-events: none; }
        #minimap:hover #minimap-viewport { background: #abb2bf35; }
        #minimapBtn[aria-pressed="true"] { color: var(--text-link); border-color: var(--accent); }
        .minimap-color-probe { position: absolute; visibility: hidden; pointer-events: none; }
        @media (max-width: 600px) { #minimap { width: 70px; } }
        .status-language { appearance: none; -webkit-appearance: none; background: transparent; color: var(--text-primary); border: 0; padding: 2px 8px; font: inherit; cursor: pointer; max-width: 140px; }
        .status-language:hover, .status-language:focus-visible { background: var(--bg-hover); outline: 1px solid var(--accent); }
        .status-language option { background: var(--bg-elevated); color: var(--text-primary); }
        .statusbar-right { min-width: 0; }
        .status-language { flex-shrink: 0; }
        #statusbar { position: static; flex-shrink: 0; overflow: hidden; white-space: nowrap; }
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
    <div id="save-toast">
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

    <!-- ── Status Bar ────────────────────────────────────────────── -->
    <div id="statusbar">
        <div class="statusbar-left">
            <span class="status-item" id="status-cursor">
                <i class="fas fa-location-crosshairs"></i>
                Ln 1, Col 1
            </span>
            <span class="status-item" id="status-selection" style="display:none">
                <i class="fas fa-i-cursor"></i>
                <span id="sel-text"></span>
            </span>
        </div>
        <div class="statusbar-right">
            <select class="status-language" id="fontSize" onchange="changeFontSize(this.value)" title="Font size" aria-label="Font size">
                <option value="12px">12px</option>
                <option value="13px">13px</option>
                <option value="14px" selected>14px</option>
                <option value="15px">15px</option>
                <option value="16px">16px</option>
                <option value="18px">18px</option>
                <option value="20px">20px</option>
            </select>
            <span class="status-item" id="status-saved">
                <i class="fas fa-check-circle"></i> Saved
            </span>
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

    <script>
ace.define("ace/theme/one_dark-css",["require","exports","module"], function(require, exports, module){module.exports = ".ace-one-dark .ace_gutter {\n    background: #282c34;\n    color: #6a6f7a\n}\n\n.ace-one-dark .ace_print-margin {\n    width: 1px;\n    background: #e8e8e8\n}\n\n.ace-one-dark {\n    background-color: #282c34;\n    color: #abb2bf\n}\n\n.ace-one-dark .ace_cursor {\n    color: #528bff\n}\n\n.ace-one-dark .ace_marker-layer .ace_selection {\n    background: #3d4350\n}\n\n.ace-one-dark.ace_multiselect .ace_selection.ace_start {\n    box-shadow: 0 0 3px 0 #282c34;\n    border-radius: 2px\n}\n\n.ace-one-dark .ace_marker-layer .ace_step {\n    background: #c6dbae\n}\n\n.ace-one-dark .ace_marker-layer .ace_bracket {\n    margin: -1px 0 0 -1px;\n    border: 1px solid #747369\n}\n\n.ace-one-dark .ace_marker-layer .ace_active-line {\n    background: rgba(76, 87, 103, .19)\n}\n\n.ace-one-dark .ace_gutter-active-line {\n    background-color: rgba(76, 87, 103, .19)\n}\n\n.ace-one-dark .ace_marker-layer .ace_selected-word {\n    border: 1px solid #3d4350\n}\n\n.ace-one-dark .ace_fold {\n    background-color: #61afef;\n    border-color: #abb2bf\n}\n\n.ace-one-dark .ace_keyword {\n    color: #c678dd\n}\n\n.ace-one-dark .ace_keyword.ace_operator {\n    color: #c678dd\n}\n\n.ace-one-dark .ace_keyword.ace_other.ace_unit {\n    color: #d19a66\n}\n\n.ace-one-dark .ace_constant.ace_language {\n    color: #d19a66\n}\n\n.ace-one-dark .ace_constant.ace_numeric {\n    color: #d19a66\n}\n\n.ace-one-dark .ace_constant.ace_character {\n    color: #56b6c2\n}\n\n.ace-one-dark .ace_constant.ace_other {\n    color: #56b6c2\n}\n\n.ace-one-dark .ace_support.ace_function {\n    color: #61afef\n}\n\n.ace-one-dark .ace_support.ace_constant {\n    color: #d19a66\n}\n\n.ace-one-dark .ace_support.ace_class {\n    color: #e5c07b\n}\n\n.ace-one-dark .ace_support.ace_type {\n    color: #e5c07b\n}\n\n.ace-one-dark .ace_storage {\n    color: #c678dd\n}\n\n.ace-one-dark .ace_storage.ace_type {\n    color: #c678dd\n}\n\n.ace-one-dark .ace_invalid {\n    color: #fff;\n    background-color: #f2777a\n}\n\n.ace-one-dark .ace_invalid.ace_deprecated {\n    color: #272b33;\n    background-color: #d27b53\n}\n\n.ace-one-dark .ace_string {\n    color: #98c379\n}\n\n.ace-one-dark .ace_string.ace_regexp {\n    color: #e06c75\n}\n\n.ace-one-dark .ace_comment {\n    font-style: italic;\n    color: #5c6370\n}\n\n.ace-one-dark .ace_variable {\n    color: #e06c75\n}\n\n.ace-one-dark .ace_variable.ace_parameter {\n    color: #d19a66\n}\n\n.ace-one-dark .ace_meta.ace_tag {\n    color: #e06c75\n}\n\n.ace-one-dark .ace_entity.ace_other.ace_attribute-name {\n    color: #e06c75\n}\n\n.ace-one-dark .ace_entity.ace_name.ace_function {\n    color: #61afef\n}\n\n.ace-one-dark .ace_entity.ace_name.ace_tag {\n    color: #e06c75\n}\n\n.ace-one-dark .ace_markup.ace_heading {\n    color: #98c379\n}\n\n.ace-one-dark .ace_indent-guide {\n    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWPQ09NrYAgMjP4PAAtGAwchHMyAAAAAAElFTkSuQmCC) right repeat-y\n}\n\n.ace-one-dark .ace_indent-guide-active {\n    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQIW2PQ1dX9zzBz5sz/ABCcBFFentLlAAAAAElFTkSuQmCC) right repeat-y;\n}\n";

});

ace.define("ace/theme/one_dark",["require","exports","module","ace/theme/one_dark-css","ace/lib/dom"], function(require, exports, module){exports.isDark = true;
exports.cssClass = "ace-one-dark";
exports.cssText = require("./one_dark-css");
var dom = require("../lib/dom");
dom.importCssString(exports.cssText, exports.cssClass, false);

});                (function() {
                    ace.require(["ace/theme/one_dark"], function(m) {
                        if (typeof module == "object" && typeof exports == "object" && module) {
                            module.exports = m;
                        }
                    });
                })();
            
        // ── Init ──────────────────────────────────────────────────────
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('spinner-overlay').style.display = 'none';
        });

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
        // Theme Mix palette adapted from tal7aouy/theme for Ace's token classes.
        ace.define("ace/theme/theme_mix", ["require", "exports", "module", "ace/lib/dom"], function(require, exports, module) {
            exports.isDark = true;
            exports.cssClass = "ace-theme-mix";
            exports.cssText = "\n.ace-theme-mix { background: #282c34; color: #abb2bf; }\n.ace-theme-mix .ace_gutter { background: #282c34; color: #495162; }\n.ace-theme-mix .ace_gutter-active-line, .ace-theme-mix .ace_marker-layer .ace_active-line { background: #2c313c; }\n.ace-theme-mix .ace_cursor { color: #528bff; }\n.ace-theme-mix .ace_marker-layer .ace_selection { background: #67769660; }\n.ace-theme-mix .ace_marker-layer .ace_selected-word { background: #ffffff10; border: 1px solid #dddddd; }\n.ace-theme-mix .ace_marker-layer .ace_bracket { background: #515a6b; border: 1px solid #515a6b; }\n.ace-theme-mix .ace_print-margin { background: #abb2bf26; }\n.ace-theme-mix .ace_invisible { color: #ffffff1d; }\n.ace-theme-mix .ace_indent-guide { box-shadow: inset -1px 0 #3b4048; background: none; }\n.ace-theme-mix .ace_comment { color: #5c6370; font-style: italic; }\n.ace-theme-mix .ace_keyword, .ace-theme-mix .ace_storage { color: #d55fde; }\n.ace-theme-mix .ace_keyword.ace_operator { color: #2bbac5; }\n.ace-theme-mix .ace_string { color: #89ca78; }\n.ace-theme-mix .ace_constant { color: #d19a66; }\n.ace-theme-mix .ace_constant.ace_language { color: #d55fde; }\n.ace-theme-mix .ace_variable { color: #ef596f; }\n.ace-theme-mix .ace_variable.ace_language, .ace-theme-mix .ace_support.ace_class, .ace-theme-mix .ace_support.ace_type { color: #e5c07b; }\n.ace-theme-mix .ace_identifier { color: #e5c07b; }\n.ace-theme-mix .ace_entity.ace_name.ace_function, .ace-theme-mix .ace_support.ace_function { color: #61afef; }\n.ace-theme-mix .ace_meta.ace_tag, .ace-theme-mix .ace_meta.ace_tag.ace_punctuation { color: #abb2bf; }\n.ace-theme-mix .ace_meta.ace_tag.ace_tag-name, .ace-theme-mix .ace_entity.ace_name.ace_tag { color: #ef596f; }\n.ace-theme-mix .ace_entity.ace_other.ace_attribute-name { color: #d19a66; font-style: italic; }\n.ace-theme-mix .ace_support.ace_type.ace_property-name { color: #abb2bf; }\n.ace-theme-mix .ace_punctuation, .ace-theme-mix .ace_paren { color: #abb2bf; }\n.ace-theme-mix .ace_invalid { color: #fff; background: #c24038; }\n.ace-theme-mix .ace_fold { background: #61afef; border-color: #abb2bf; }\n.ace-theme-mix .ace_markup.ace_heading { color: #ef596f; }\n.ace-theme-mix .ace_markup.ace_list { color: #e5c07b; }\n.ace-theme-mix .ace_markup.ace_bold { color: #d19a66; font-weight: bold; }\n.ace-theme-mix .ace_markup.ace_italic { color: #d55fde; font-style: italic; }\n";
            require("ace/lib/dom").importCssString(exports.cssText, exports.cssClass);
        });
        editor.setTheme("ace/theme/theme_mix");
        editor.session.setMode("ace/mode/<?= $editorMode ?>");
        editor.setOptions({
            enableBasicAutocompletion: true,
            enableSnippets: true,
            enableLiveAutocompletion: true,
            fontSize: "14px",
            wrap: false,
            highlightActiveLine: true,
            highlightSelectedWord: true,
            enableAutoIndent: true,
            enableKeyboardAccessibility: true,
            showPrintMargin: false,
            scrollPastEnd: 0.5,
            tabSize: 4,
            useSoftTabs: true,
        });

        // Remove Ace's default border
        editor.container.style.lineHeight = '1.6';

        var wrapEnabled = false;
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
                document.title = '● ' + editorFilename + ' — Pocket Code Studio';
            }
            notifyWorkspace();
        });

        // ── Cursor / selection status ─────────────────────────────────
        editor.selection.on('changeCursor', updateCursorStatus);
        editor.selection.on('changeSelection', updateCursorStatus);

        function updateCursorStatus() {
            const pos = editor.getCursorPosition();
            document.getElementById('status-cursor').innerHTML =
                `<i class="fas fa-location-crosshairs"></i> Ln ${pos.row + 1}, Col ${pos.column + 1}`;

            const sel = editor.getSelectedText();
            const selEl = document.getElementById('status-selection');
            if (sel.length > 0) {
                document.getElementById('sel-text').textContent = `${sel.length} chars selected`;
                selEl.style.display = 'flex';
            } else {
                selEl.style.display = 'none';
            }
        }

        // ── Theme / Mode / Font ───────────────────────────────────────
        window.applySelectedTheme = function(theme) {
            theme = window.applyWorkspacePalette(theme);
            editor.setTheme("ace/theme/" + theme);
            requestAnimationFrame(() => {
                mapColors.clear();
                scheduleMinimap();
                if (typeof scheduleOccurrenceDraw === "function") scheduleOccurrenceDraw();
            });
        };
        function changeTheme(theme) {
            const host = window.parent !== window ? window.parent : window;
            host.setWorkspaceTheme(theme);
        }

        function changeMode(mode) {
            editor.session.setMode("ace/mode/" + mode);
            document.getElementById('mode').value = mode;
            localStorage.setItem('ke_mode', mode);
        }

        function changeFontSize(size) {
            editor.setOptions({
                fontSize: size
            });
            localStorage.setItem('ke_font', size);
        }

        // ── Restore preferences ───────────────────────────────────────
        (function restorePrefs() {
            const theme = localStorage.getItem('ke_theme') || document.documentElement.dataset.workspaceTheme;
            const font = localStorage.getItem('ke_font');
            if (theme) {
                    changeTheme(theme);
            }
            if (font) {
                document.getElementById('fontSize').value = font;
                changeFontSize(font);
            }
        })();

        // ── Verified save; successful HTTP alone is not proof of a successful write ──
        async function saveFile() {
            if (savingFile) return;
            savingFile = true;
            document.getElementById('status-saved').style.display = 'none';
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
                lastSavedContent = content;
                hasUnsavedChanges = editor.getValue() !== savedEditorValue;
                notifyWorkspace();
                document.title = (hasUnsavedChanges ? '● ' : '') + editorFilename + ' — Pocket Code Studio';
                const toast = document.getElementById('save-toast');
                toast.innerHTML = '<i class="fas fa-check-circle"></i> File saved and verified';
                toast.style.display = 'flex';
                setTimeout(() => { toast.style.display = 'none'; }, 2000);
                const savedEl = document.getElementById('status-saved');
                savedEl.style.display = 'flex';
                setTimeout(() => { savedEl.style.display = 'none'; }, 3000);
            } catch (error) {
                window.workspaceAlert(error.message || 'Save failed. Your edits remain in the tab.', 'Save failed');
            } finally {
                savingFile = false;
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

        // ── Copy all ──────────────────────────────────────────────────
        function copyAll() {
            navigator.clipboard.writeText(editor.getValue()).then(() => {
                const toast = document.getElementById('save-toast');
                toast.innerHTML = '<i class="fas fa-check-circle"></i> Copied to clipboard';
                toast.style.borderColor = 'var(--accent)';
                toast.style.color = 'var(--text-link)';
                toast.style.display = 'flex';
                setTimeout(() => {
                    toast.style.display = 'none';
                    toast.innerHTML = '<i class="fas fa-check-circle"></i> File saved successfully';
                    toast.style.borderColor = 'var(--accent-success)';
                    toast.style.color = 'var(--accent-success)';
                }, 1800);
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
                else data.diff.split('\n').forEach(line => {
                    const row = document.createElement('div');
                    row.textContent = line || ' ';
                    row.className = line.startsWith('+') && !line.startsWith('+++') ? 'git-added' : line.startsWith('-') && !line.startsWith('---') ? 'git-removed' : line.startsWith('@@') ? 'git-hunk' : '';
                    output.append(row);
                });
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
            mapContext.fillRect(0, 0, width, height);
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
            localStorage.setItem('ke_minimap', String(!minimap.hidden));

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
        if (localStorage.getItem('ke_minimap') === 'false') {
            minimap.hidden = true;
            document.body.classList.add('minimap-hidden');

            editor.resize();
        }
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
/* Embedded Material Icon Theme SVGs. Source: https://github.com/material-extensions/vscode-material-icon-theme
Revision: 13025adc5ad10a5cc649528a2c1edec93069f1b9
The MIT License (MIT)
Copyright (c) 2025 Material Extensions

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
$materialIconData = json_decode(<<<'MATERIAL_ICONS_JSON'
{"icons":{"php":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iIzFlODhlNSIgZD0iTTEyIDE4LjA4Yy02LjYzIDAtMTItMi43Mi0xMi02LjA4czUuMzctNi4wOCAxMi02LjA4UzI0IDguNjQgMjQgMTJzLTUuMzcgNi4wOC0xMiA2LjA4bS01LjE5LTcuOTVjLjU0IDAgLjkxLjEgMS4wOS4zMS4xOC4yLjIyLjU2LjEzIDEuMDMtLjEuNTMtLjI5Ljg3LS41OCAxLjA5cS0uNDIuMzMtMS4yOS4zM2gtLjg3bC41My0yLjc2em0tMy41IDUuNTVoMS40NGwuMzQtMS43NWgxLjIzYy41NCAwIC45OC0uMDYgMS4zMy0uMTcuMzUtLjEyLjY3LS4zMS45Ni0uNTguMjQtLjIyLjQzLS40Ni41OC0uNzMuMTUtLjI2LjI2LS41Ni4zMS0uODguMTYtLjc4LjA1LTEuMzktLjMzLTEuODItLjM5LS40NC0uOTktLjY1LTEuODItLjY1SDQuNTl6bTcuMjUtOC4zMy0xLjI4IDYuNThoMS40MmwuNzQtMy43N2gxLjE0Yy4zNiAwIC42LjA2LjcxLjE4cy4xMy4zNC4wNy42NmwtLjU3IDIuOTNoMS40NWwuNTktMy4wN2MuMTMtLjYyLjAzLTEuMDctLjI3LTEuMzYtLjMtLjI3LS44NS0uNC0xLjY1LS40aC0xLjI3TDEyIDcuMzV6TTE4IDEwLjEzYy41NSAwIC45MS4xIDEuMDkuMzEuMTguMi4yMi41Ni4xMyAxLjAzLS4xLjUzLS4yOS44Ny0uNTcgMS4wOS0uMjkuMjItLjcyLjMzLTEuMy4zM2gtLjg1bC41LTIuNzZ6bS0zLjUgNS41NWgxLjQ0bC4zNC0xLjc1aDEuMjJjLjU1IDAgMS0uMDYgMS4zNS0uMTcuMzUtLjEyLjY1LS4zMS45NS0uNTguMjQtLjIyLjQ0LS40Ni41OC0uNzMuMTUtLjI2LjI2LS41Ni4zMi0uODguMTUtLjc4LjA0LTEuMzktLjM0LTEuODItLjM2LS40NC0uOTktLjY1LTEuODItLjY1aC0yLjc1eiIvPjwvc3ZnPg==","android":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjQiIGhlaWdodD0iMTAiIHg9IjIiIHk9IjEyIiBmaWxsPSIjOGJjMzRhIiByeD0iMiIvPjxyZWN0IHdpZHRoPSI0IiBoZWlnaHQ9IjEwIiB4PSIyNiIgeT0iMTIiIGZpbGw9IiM4YmMzNGEiIHJ4PSIyIi8+PHBhdGggZmlsbD0iIzhiYzM0YSIgZD0iTTggMTJoMTZ2MTJIOHptMiAxMmg0djRhMiAyIDAgMCAxLTIgMiAyIDIgMCAwIDEtMi0yem04IDBoNHY0YTIgMiAwIDAgMS0yIDIgMiAyIDAgMCAxLTItMnptMy41NDUtMTkuNzU5IDIuMTItMi4xMkExIDEgMCAwIDAgMjIuMjUxLjcwN2wtMi4zMjYgMi4zMjZhNy45NyA3Ljk3IDAgMCAwLTcuODUgMEw5Ljc1LjcwN2ExIDEgMCAxIDAtMS40MTQgMS40MTRsMi4xMiAyLjEyQTcuOTcgNy45NyAwIDAgMCA4IDEwaDE2YTcuOTcgNy45NyAwIDAgMC0yLjQ1NS01Ljc1OU0xNCA4aC0yVjZoMlptNiAwaC0yVjZoMloiLz48L3N2Zz4=","git":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2U2NGExOSIgZD0iTTEzLjE3MiAyLjgyOCAxMS43OCA0LjIybDEuOTEgMS45MSAyIDJBMi45ODYgMi45ODYgMCAwIDEgMjAgMTAuODFhMy4yNSAzLjI1IDAgMCAxLS4zMSAxLjMxbDIuMDYgMmEyLjY4IDIuNjggMCAwIDEgMy4zNy41NyAyLjg2IDIuODYgMCAwIDEgLjg4IDIuMTE3IDMuMDIgMy4wMiAwIDAgMS0uODU2IDIuMTA5QTIuOSAyLjkgMCAwIDEgMjMgMTkuODFhMi45MyAyLjkzIDAgMCAxLTIuMTMtLjg3IDIuNjk0IDIuNjk0IDAgMCAxLS41Ni0zLjM4bC0yLTIuMDZhMyAzIDAgMCAxLS4zMS4xMlYyMGEzIDMgMCAwIDEgMS40NCAxLjA5IDIuOTIgMi45MiAwIDAgMSAuNTYgMS43MiAyLjg4IDIuODggMCAwIDEtLjg3OCAyLjEyOCAyLjk4IDIuOTggMCAwIDEtMi4wNDguODcxIDIuOTgxIDIuOTgxIDAgMCAxLTIuNTE0LTQuNzE5QTMgMyAwIDAgMSAxNiAyMHYtNi4zOGEyLjk2IDIuOTYgMCAwIDEtMS40NC0xLjA5IDIuOSAyLjkgMCAwIDEtLjU2LTEuNzIgMi45IDIuOSAwIDAgMSAuMzEtMS4zMWwtMy45LTMuOS03LjU3OSA3LjU3MmE0IDQgMCAwIDAtLjAwMSA1LjY1OGwxMC4zNDIgMTAuMzQyYTQgNCAwIDAgMCA1LjY1NiAwbDEwLjM0NC0xMC4zNDRhNCA0IDAgMCAwIDAtNS42NTZMMTguODI4IDIuODI4YTQgNCAwIDAgMC01LjY1NiAwIi8+PC9zdmc+","xml":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iIzhiYzM0YSIgZD0iTTEzIDloNS41TDEzIDMuNXpNNiAyaDhsNiA2djEyYTIgMiAwIDAgMS0yIDJINmEyIDIgMCAwIDEtMi0yVjRjMC0xLjExLjg5LTIgMi0ybS4xMiAxMy41IDMuNzQgMy43NCAxLjQyLTEuNDEtMi4zMy0yLjMzIDIuMzMtMi4zMy0xLjQyLTEuNDF6bTExLjE2IDAtMy43NC0zLjc0LTEuNDIgMS40MSAyLjMzIDIuMzMtMi4zMyAyLjMzIDEuNDIgMS40MXoiLz48L3N2Zz4=","json":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgLTk2MCA5NjAgOTYwIj48cGF0aCBmaWxsPSIjZjlhODI1IiBkPSJNNTYwLTE2MHYtODBoMTIwcTE3IDAgMjguNS0xMS41VDcyMC0yODB2LTgwcTAtMzggMjItNjl0NTgtNDR2LTE0cS0zNi0xMy01OC00NHQtMjItNjl2LTgwcTAtMTctMTEuNS0yOC41VDY4MC03MjBINTYwdi04MGgxMjBxNTAgMCA4NSAzNXQzNSA4NXY4MHEwIDE3IDExLjUgMjguNVQ4NDAtNTYwaDQwdjE2MGgtNDBxLTE3IDAtMjguNSAxMS41VDgwMC0zNjB2ODBxMCA1MC0zNSA4NXQtODUgMzV6bS0yODAgMHEtNTAgMC04NS0zNXQtMzUtODV2LTgwcTAtMTctMTEuNS0yOC41VDEyMC00MDBIODB2LTE2MGg0MHExNyAwIDI4LjUtMTEuNVQxNjAtNjAwdi04MHEwLTUwIDM1LTg1dDg1LTM1aDEyMHY4MEgyODBxLTE3IDAtMjguNSAxMS41VDI0MC02ODB2ODBxMCAzOC0yMiA2OXQtNTggNDR2MTRxMzYgMTMgNTggNDR0MjIgNjl2ODBxMCAxNyAxMS41IDI4LjVUMjgwLTI0MGgxMjB2ODB6Ii8+PC9zdmc+","zip":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI2FmYjQyYiIgZD0iTTE0IDE3aC0ydi0yaC0ydi0yaDJ2MmgybTAtNmgtMnYyaDJ2MmgtMnYtMmgtMlY5aDJWN2gtMlY1aDJ2MmgybTUtNEg1Yy0xLjExIDAtMiAuODktMiAydjE0YTIgMiAwIDAgMCAyIDJoMTRhMiAyIDAgMCAwIDItMlY1YTIgMiAwIDAgMC0yLTIiLz48L3N2Zz4=","favicon":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2ZmZDU0ZiIgZD0ibTE2IDI0IDEwIDYtNC0xMCA4LTgtMTAtLjAzMkwxNiAybC00IDEwSDJsOCA4LTQgMTBaIi8+PC9zdmc+","image":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0iIzI2YTY5YSIgZD0iTTguNSA2aDRsLTQtNHpNMy44NzUgMUg5LjVsNCA0djguNmMwIC43NzMtLjYxNiAxLjQtMS4zNzUgMS40aC04LjI1Yy0uNzYgMC0xLjM3NS0uNjI3LTEuMzc1LTEuNFYyLjRjMC0uNzc3LjYxMi0xLjQgMS4zNzUtMS40TTQgMTMuNmg4VjhsLTIuNjI1IDIuOEw4IDkuNHptMS4yNS03LjdjLS43NiAwLTEuMzc1LjYyNy0xLjM3NSAxLjRzLjYxNiAxLjQgMS4zNzUgMS40Yy43NiAwIDEuMzc1LS42MjcgMS4zNzUtMS40UzYuMDA5IDUuOSA1LjI1IDUuOSIvPjwvc3ZnPg==","document":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGZpbGw9Im5vbmUiIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTAgMGgyNHYyNEgweiIvPjxwYXRoIGZpbGw9IiM0MmE1ZjUiIGQ9Ik04IDE2aDh2Mkg4em0wLTRoOHYySDh6bTYtMTBINmMtMS4xIDAtMiAuOS0yIDJ2MTZjMCAxLjEuODkgMiAxLjk5IDJIMThjMS4xIDAgMi0uOSAyLTJWOHptNCAxOEg2VjRoN3Y1aDV6Ii8+PC9zdmc+","robots":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2ZmNTI1MiIgZD0iTTI4LjU4NiAxOEgyOGE4IDggMCAwIDAtOC04aC0yVjguNDQ1YTQgNCAwIDEgMC00IDBWMTBoLTJhOCA4IDAgMCAwLTggOGgtLjU4NkExLjQxNCAxLjQxNCAwIDAgMCAyIDE5LjQxNHYzLjE3MkExLjQxNCAxLjQxNCAwIDAgMCAzLjQxNCAyNEg0djFhMyAzIDAgMCAwIDMgM2gxOGEzIDMgMCAwIDAgMy0zdi0xaC41ODZBMS40MTQgMS40MTQgMCAwIDAgMzAgMjIuNTg2di0zLjE3MkExLjQxNCAxLjQxNCAwIDAgMCAyOC41ODYgMThNMTEgMjJhMyAzIDAgMSAxIDMtMyAzIDMgMCAwIDEtMyAzbTEwIDBhMyAzIDAgMSAxIDMtMyAzIDMgMCAwIDEtMyAzIi8+PC9zdmc+","html":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2U2NTEwMCIgZD0ibTQgNCAyIDIyIDEwIDIgMTAtMiAyLTIyWm0xOS43MiA3SDExLjI4bC4yOSAzaDExLjg2bC0uODAyIDkuMzM1TDE1Ljk5IDI1bC02LjYzNS0xLjY0Nkw4LjkzIDE5aDMuMDJsLjE5IDIgMy44Ni43NyAzLjg0LS43Ny4yOS00SDguODRMOCA4aDE2WiIvPjwvc3ZnPg==","css":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iIzdlNTdjMiIgZD0iTTIwIDE4aC0ydi0yaC0ydjJjMCAuMTkzIDAgLjcwMyAxLjI1NCAxLjAzM0EzLjM0NSAzLjM0NSAwIDAgMSAyMCAyMmgydjJoMnYtMmMwLS4zODgtLjU2Mi0uODUxLTEuMjU0LTEuMDM0QzIwLjM1NiAyMC4zNCAyMCAxOC44NCAyMCAxOG0tMy4yNTQgMi45NjZDMTQuMzU2IDIwLjM0IDE0IDE4Ljg0IDE0IDE4aC0ydi0yaC0ydjhoMnYtMmg0djJoMnYtMmMwLS4zODgtLjU2Mi0uODUxLTEuMjU0LTEuMDM0Ii8+PHBhdGggZmlsbD0iIzdlNTdjMiIgZD0iTTI0IDRINHYyMGE0IDQgMCAwIDAgNCA0aDE2LjE2QTMuODQgMy44NCAwIDAgMCAyOCAyNC4xNlY4YTQgNCAwIDAgMC00LTRtMiAxNGgtMnYtMmgtMnYyYzAgLjE5MyAwIC43MDMgMS4yNTQgMS4wMzNBMy4zNDUgMy4zNDUgMCAwIDEgMjYgMjJ2MmEyIDIgMCAwIDEtMiAyaC0yYTIgMiAwIDAgMS0yLTIgMiAyIDAgMCAxLTIgMmgtMmEyIDIgMCAwIDEtMi0yIDIgMiAwIDAgMS0yIDJoLTJhMiAyIDAgMCAxLTItMnYtOGEyIDIgMCAwIDEgMi0yaDJhMiAyIDAgMCAxIDIgMiAyIDIgMCAwIDEgMi0yaDJhMiAyIDAgMCAxIDIgMiAyIDIgMCAwIDEgMi0yaDJhMiAyIDAgMCAxIDIgMloiLz48L3N2Zz4=","javascript":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0iI2ZmY2EyOCIgZD0iTTIgMnYxMmgxMlYyem02IDZoMXY0YTEuMDAzIDEuMDAzIDAgMCAxLTEgMUg3YTEuMDAzIDEuMDAzIDAgMCAxLTEtMXYtMWgxdjFoMXptMyAwaDJ2MWgtMnYxaDFhMS4wMDMgMS4wMDMgMCAwIDEgMSAxdjFhMS4wMDMgMS4wMDMgMCAwIDEtMSAxaC0ydi0xaDJ2LTFoLTFhMS4wMDMgMS4wMDMgMCAwIDEtMS0xVjlhMS4wMDMgMS4wMDMgMCAwIDEgMS0xIi8+PC9zdmc+","typescript":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbDpzcGFjZT0icHJlc2VydmUiIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0iIzAyODhkMSIgZD0iTTIgMnYxMmgxMlYyem00IDZoM3YxSDh2NEg3VjlINnptNSAwaDJ2MWgtMnYxaDFhMS4wMDMgMS4wMDMgMCAwIDEgMSAxdjFhMS4wMDMgMS4wMDMgMCAwIDEtMSAxaC0ydi0xaDJ2LTFoLTFhMS4wMDMgMS4wMDMgMCAwIDEtMS0xVjlhMS4wMDMgMS4wMDMgMCAwIDEgMS0xIi8+PC9zdmc+","python":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iIzAyODhkMSIgZD0iTTkuODYgMkEyLjg2IDIuODYgMCAwIDAgNyA0Ljg2djEuNjhoNC4yOWMuMzkgMCAuNzEuNTcuNzEuOTZINC44NkEyLjg2IDIuODYgMCAwIDAgMiAxMC4zNnYzLjc4MWEyLjg2IDIuODYgMCAwIDAgMi44NiAyLjg2aDEuMTh2LTIuNjhhMi44NSAyLjg1IDAgMCAxIDIuODUtMi44Nmg1LjI1YzEuNTggMCAyLjg2LTEuMjcxIDIuODYtMi44NTFWNC44NkEyLjg2IDIuODYgMCAwIDAgMTQuMTQgMnptLS43MiAxLjYxYy40IDAgLjcyLjEyLjcyLjcxcy0uMzIuODkxLS43Mi44OTFjLS4zOSAwLS43MS0uMy0uNzEtLjg5cy4zMi0uNzExLjcxLS43MTEiLz48cGF0aCBmaWxsPSIjZmRkODM1IiBkPSJNMTcuOTU5IDd2Mi42OGEyLjg1IDIuODUgMCAwIDEtMi44NSAyLjg1OUg5Ljg2QTIuODUgMi44NSAwIDAgMCA3IDE1LjM4OXYzLjc1YTIuODYgMi44NiAwIDAgMCAyLjg2IDIuODZoNC4yOEEyLjg2IDIuODYgMCAwIDAgMTcgMTkuMTR2LTEuNjhoLTQuMjkxYy0uMzkgMC0uNzA5LS41Ny0uNzA5LS45Nmg3LjE0QTIuODYgMi44NiAwIDAgMCAyMiAxMy42NFY5Ljg2QTIuODYgMi44NiAwIDAgMCAxOS4xNCA3ek04LjMyIDExLjUxM2wtLjAwNC4wMDQuMDM4LS4wMDR6bTYuNTQgNy4yNzZjLjM5IDAgLjcxLjMuNzEuODlhLjcxLjcxIDAgMCAxLS43MS43MWMtLjQgMC0uNzItLjEyLS43Mi0uNzFzLjMyLS44OS43Mi0uODkiLz48L3N2Zz4=","database":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2ZmY2EyOCIgZD0iTTE2IDI0Yy01LjUyNSAwLTEwLS45LTEwLTJ2NGMwIDEuMSA0LjQ3NSAyIDEwIDJzMTAtLjkgMTAtMnYtNGMwIDEuMS00LjQ3NSAyLTEwIDJtMC04Yy01LjUyNSAwLTEwLS45LTEwLTJ2NGMwIDEuMSA0LjQ3NSAyIDEwIDJzMTAtLjkgMTAtMnYtNGMwIDEuMS00LjQ3NSAyLTEwIDJtMC0xMkMxMC40NzcgNCA2IDQuODk1IDYgNnY0YzAgMS4xIDQuNDc1IDIgMTAgMnMxMC0uOSAxMC0yVjZjMC0xLjEwNS00LjQ3Ny0yLTEwLTIiLz48L3N2Zz4=","console":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZmlsbD0iI2ZmNzA0MyIgZD0iTTIgMmExIDEgMCAwIDAtMSAxdjEwYzAgLjU1NC40NDYgMSAxIDFoMTJjLjU1NCAwIDEtLjQ0NiAxLTFWM2ExIDEgMCAwIDAtMS0xem0wIDNoMTJ2OEgyem0xIDIgMiAyLTIgMiAxIDEgMy0zLTMtM3ptNSAzLjVWMTJoNXYtMS41eiIvPjwvc3ZnPg==","markdown":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iIzQyYTVmNSIgZD0ibTE0IDEwLTQgMy41TDYgMTBINHYxMmg0di02bDIgMiAyLTJ2Nmg0VjEwem0xMiA2di02aC00djZoLTRsNiA4IDYtOHoiLz48L3N2Zz4=","pdf":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI2VmNTM1MCIgZD0iTTEzIDloNS41TDEzIDMuNXpNNiAyaDhsNiA2djEyYTIgMiAwIDAgMS0yIDJINmEyIDIgMCAwIDEtMi0yVjRhMiAyIDAgMCAxIDItMm00LjkzIDEwLjQ0Yy40MS45LjkzIDEuNjQgMS41MyAyLjE1bC40MS4zMmMtLjg3LjE2LTIuMDcuNDQtMy4zNC45M2wtLjExLjA0LjUtMS4wNGMuNDUtLjg3Ljc4LTEuNjYgMS4wMS0yLjRtNi40OCAzLjgxYy4xOC0uMTguMjctLjQxLjI4LS42Ni4wMy0uMi0uMDItLjM5LS4xMi0uNTUtLjI5LS40Ny0xLjA0LS42OS0yLjI4LS42OWwtMS4yOS4wNy0uODctLjU4Yy0uNjMtLjUyLTEuMi0xLjQzLTEuNi0yLjU2bC4wNC0uMTRjLjMzLTEuMzMuNjQtMi45NC0uMDItMy42YS44NS44NSAwIDAgMC0uNjEtLjI0aC0uMjRjLS4zNyAwLS43LjM5LS43OS43Ny0uMzcgMS4zMy0uMTUgMi4wNi4yMiAzLjI3di4wMWMtLjI1Ljg4LS41NyAxLjktMS4wOCAyLjkzbC0uOTYgMS44LS44OS40OWMtMS4yLjc1LTEuNzcgMS41OS0xLjg4IDIuMTItLjA0LjE5LS4wMi4zNi4wNS41NGwuMDMuMDUuNDguMzEuNDQuMTFjLjgxIDAgMS43My0uOTUgMi45Ny0zLjA3bC4xOC0uMDdjMS4wMy0uMzMgMi4zMS0uNTYgNC4wMy0uNzUgMS4wMy41MSAyLjI0Ljc0IDMgLjc0LjQ0IDAgLjc0LS4xMS45MS0uM20tLjQxLS43MS4wOS4xMWMtLjAxLjEtLjA0LjExLS4wOS4xM2gtLjA0bC0uMTkuMDJjLS40NiAwLTEuMTctLjE5LTEuOS0uNTEuMDktLjEuMTMtLjEuMjMtLjEgMS40IDAgMS44LjI1IDEuOS4zNU03LjgzIDE3Yy0uNjUgMS4xOS0xLjI0IDEuODUtMS42OSAyIC4wNS0uMzguNS0xLjA0IDEuMjEtMS42OXptMy4wMi02LjkxYy0uMjMtLjktLjI0LTEuNjMtLjA3LTIuMDVsLjA3LS4xMi4xNS4wNWMuMTcuMjQuMTkuNTYuMDkgMS4xbC0uMDMuMTYtLjE2LjgyeiIvPjwvc3ZnPg==","folder-base":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzhkNmU2MyIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNkN2NjYzgiIGQ9Ik03LjUgMTFjLS4yNzcgMC0uNS4yMjMtLjUuNXYyYzAgLjI3Ny4yMjMuNS41LjVoOGMuMjc3IDAgLjUtLjIyMy41LS41di0yYzAtLjI3Ny0uMjIzLS41LS41LS41WiIvPjwvc3ZnPg==","folder-template":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzhkNmU2MyIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNkN2NjYzgiIGQ9Ik02IDEzaDR2MUg2Wm0wLTJoNHYxSDZabTAtMmg0djFINlptMC0yaDR2MUg2Wm01IDBoNHY3aC00eiIvPjwvc3ZnPg==","folder-upload":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iI2ZmNzA0MyIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNmZmNjYmMiIGQ9Ik0xMCAxMlY5SDhsMy41LTRMMTUgOWgtMnYzem0tMiAydi0xaDd2MXoiLz48L3N2Zz4=","folder-packages":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzFlODhlNSIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNiYmRlZmIiIGQ9Ik0xNS42IDYuNDY3IDE0LjggNS40QTEgMSAwIDAgMCAxNCA1aC00YTEgMSAwIDAgMC0uOC40bC0uOCAxLjA2NmEyIDIgMCAwIDAtLjQgMS4yVjEzYTEgMSAwIDAgMCAxIDFoNmExIDEgMCAwIDAgMS0xVjcuNjY3YTIgMiAwIDAgMC0uNC0xLjJNMTAgNmg0bC43NSAxaC01LjV6bTMgNXYyaC0ydi0ySDlsMy0zIDMgM3oiLz48L3N2Zz4=","folder-config":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzAwYWNjMSIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiM4MGRlZWEiIGQ9Ik0xMS41IDEyLjA3NUExLjYgMS42IDAgMCAxIDkuODgyIDEwLjVhMS42MiAxLjYyIDAgMSAxIDEuNjIgMS41NzVtMy40MzctMS4xMzhhNCA0IDAgMCAwIC4wMzItLjQzOCA0IDQgMCAwIDAtLjAzMi0uNDVsLjk3Ni0uNzMzYS4yMjMuMjIzIDAgMCAwIC4wNTYtLjI4OGwtLjkyNi0xLjU1NmEuMjMuMjMgMCAwIDAtLjI4My0uMWwtMS4xNS40NWEzLjQgMy40IDAgMCAwLS43ODMtLjQ0bC0uMTcxLTEuMTkzQS4yMy4yMyAwIDAgMCAxMi40MjUgNmgtMS44NWEuMjMuMjMgMCAwIDAtLjIzMS4xODlsLS4xNzEgMS4xOTNhMy40IDMuNCAwIDAgMC0uNzgxLjQ0bC0xLjE1Mi0uNDVhLjIzLjIzIDAgMCAwLS4yODIuMWwtLjkyNiAxLjU1NmEuMjIuMjIgMCAwIDAgLjA1Ni4yODhsLjk3NS43MzRhNCA0IDAgMCAwLS4wMzIuNDUgNCA0IDAgMCAwIC4wMzIuNDM3bC0uOTc1Ljc0NmEuMjIuMjIgMCAwIDAtLjA1Ni4yODhsLjkyNSAxLjU1OGEuMjM1LjIzNSAwIDAgMCAuMjgzLjA5OWwxLjE1Mi0uNDU1YTMuMiAzLjIgMCAwIDAgLjc4MS40NDZsLjE3MSAxLjE5MmEuMjMuMjMgMCAwIDAgLjIzMi4xODloMS44NWEuMjMuMjMgMCAwIDAgLjIzMi0uMTg5bC4xNy0xLjE5MmEzLjQgMy40IDAgMCAwIC43ODMtLjQ0NmwxLjE1LjQ1NWEuMjQuMjQgMCAwIDAgLjI4NC0uMWwuOTI0LTEuNTU3YS4yMjMuMjIzIDAgMCAwLS4wNTUtLjI4OFoiLz48L3N2Zz4=","folder-images":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzAwOTY4OCIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNiMmRmZGIiIGQ9Ik0xMiA1SDguNWEuNS41IDAgMCAwLS41LjV2OGEuNS41IDAgMCAwIC41LjVoNmEuNS41IDAgMCAwIC41LS41VjhabS0yIDNhMSAxIDAgMSAxLTEgMSAxLjAwNSAxLjAwNSAwIDAgMSAxLTFtNCA1SDlsMi0yIDEgMSAyLTJ6bS0yLjQxNC00LjU4NlY2TDE0IDguNDE0WiIvPjwvc3ZnPg==","folder-backup":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzhkNmU2MyIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxnIGlkPSJtb3RpdmUiIGZpbGw9IiNkN2NjYzgiPjxwYXRoIGQ9Ik0xMi42ODggMTIuMzkgMTAgMTAuMjRWN2gxdjIuNzZsMi4zMTMgMS44NXoiLz48cGF0aCBkPSJNMTEgMTVhNSA1IDAgMSAxIDUtNSA1LjAwNSA1LjAwNSAwIDAgMS01IDVtMC05YTQgNCAwIDEgMCA0IDQgNC4wMDUgNC4wMDUgMCAwIDAtNC00Ii8+PC9nPjwvc3ZnPg==","folder-public":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzAzOWJlNSIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNiM2U1ZmMiIGQ9Ik0xMSA1YTUgNSAwIDEgMCA1IDUgNSA1IDAgMCAwLTUtNW0zLjQ1OSAzSDEyLjk4YTggOCAwIDAgMC0uNjcxLTEuNzdBNC4wMiA0LjAyIDAgMCAxIDE0LjQ1OSA4TTExIDZhNyA3IDAgMCAxIC45NDUgMmgtMS44OUE3IDcgMCAwIDEgMTEgNm0tMS4zMDkuMjNBOCA4IDAgMCAwIDkuMDIgOEg3LjU0MWE0LjAyIDQuMDIgMCAwIDEgMi4xNS0xLjc3TTcuMTMxIDExYTMuODUgMy44NSAwIDAgMSAwLTJoMS43MDRhNy44IDcuOCAwIDAgMCAwIDJ6bS40MSAxSDkuMDJhOCA4IDAgMCAwIC42NzEgMS43N0E0LjAyIDQuMDIgMCAwIDEgNy41NDEgMTJNMTEgMTRhNyA3IDAgMCAxLS45NDUtMmgxLjg5QTcgNyAwIDAgMSAxMSAxNG0xLjE1NS0zaC0yLjMxYTYuNyA2LjcgMCAwIDEgMC0yaDIuMzFhNi43IDYuNyAwIDAgMSAwIDJtLjE1NCAyLjc3QTggOCAwIDAgMCAxMi45OCAxMmgxLjQ3OWE0LjAyIDQuMDIgMCAwIDEtMi4xNSAxLjc3bTIuNTYtMi43N2gtMS43MDRhNy44IDcuOCAwIDAgMCAwLTJoMS43MDRhMy44NSAzLjg1IDAgMCAxIDAgMiIvPjwvc3ZnPg==","folder-database":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iI2ZmY2EyOCIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNmZmVjYjMiIGQ9Ik0xMiA1YTQgMiAwIDAgMC00IDIgNCAyIDAgMCAwIDQgMiA0IDIgMCAwIDAgNC0yIDQgMiAwIDAgMC00LTJNOCA4djJjMCAxLjEwNSAxLjc5MSAyIDQgMnM0LS44OTUgNC0yVjhjMCAxLjEwNS0xLjc5MSAyLTQgMnMtNC0uODk1LTQtMm0wIDN2MmMwIDEuMTA1IDEuNzkxIDIgNCAyczQtLjg5NSA0LTJ2LTJjMCAxLjEwNS0xLjc5MSAyLTQgMnMtNC0uODk1LTQtMiIvPjwvc3ZnPg==","folder-src":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzRjYWY1MCIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNjOGU2YzkiIGQ9Ik05LjIyNSAxNWEuNS41IDAgMCAxLS4xMi0uMDE0LjU3LjU2OCAwIDAgMS0uNDE0LS42NjFsMS41NDktNy44NzJhLjU2Ni41NjUgMCAwIDEgLjI1NC0uMzcyLjUzLjUzIDAgMCAxIC40LS4wNjcuNTcuNTcgMCAwIDEgLjQxNS42NjJsLTEuNTUyIDcuODcyYS41Ni41NiAwIDAgMS0uMjUzLjM3MS41My41MyAwIDAgMS0uMjguMDgxbTMuMTA1LTFoLS4wMzhhLjU0LjU0IDAgMCAxLS4zODItLjIwNi41ODMuNTgyIDAgMCAxIC4wNTctLjc3NGwyLjY2NC0yLjQ4My0yLjY1My0yLjMxMmEuNTgzLjU4MiAwIDAgMS0uMDgtLjc3Mi41NC41NCAwIDAgMSAuMzc3LS4yMTguNTMuNTMgMCAwIDEgLjQwNi4xMjlsMy4xMjYgMi43MjdhLjU3OS41NzggMCAwIDEgLjAwMi44NjJsLTMuMTE0IDIuOTA0YS41MzYuNTM1IDAgMCAxLS4zNjUuMTQ0em0tNC42NjEgMGEuNTM2LjUzNSAwIDAgMS0uMzY1LS4xNDZMNC4xODYgMTAuOTVhLjU4LjU4IDAgMCAxLS4wMDUtLjg0NmwuMDEtLjAxIDMuMTI4LTIuNzI2YS41MTYuNTE1IDAgMCAxIC40LS4xMy41NC41NCAwIDAgMSAuMzguMjE4LjU4My41ODIgMCAwIDEtLjA4Ljc3M2wtMi42NSAyLjMxIDIuNjYzIDIuNDgyYS41NzkuNTc4IDAgMCAxIC4wNTYuNzc0LjUzNi41MzUgMCAwIDEtLjM4MS4yMDZ6Ii8+PC9zdmc+","folder-test":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggaWQ9ImZvbGRlciIgZmlsbD0iIzAwYmZhNSIgZD0ibTYuOTIyIDMuNzY4LS42NDQtLjUzNkExIDEgMCAwIDAgNS42MzggM0gyYTEgMSAwIDAgMC0xIDF2OGExIDEgMCAwIDAgMSAxaDEyYTEgMSAwIDAgMCAxLTFWNWExIDEgMCAwIDAtMS0xSDcuNTYyYTEgMSAwIDAgMS0uNjQtLjIzMiIvPjxwYXRoIGlkPSJtb3RpdmUiIGZpbGw9IiNhN2ZmZWIiIGQ9Ik04IDZ2MWgxdjZhMiAyIDAgMCAwIDQgMFY3aDFWNlptMi41IDdhLjUuNSAwIDEgMSAuNS0uNS41LjUgMCAwIDEtLjUuNW0xLTJhLjUuNSAwIDEgMSAuNS0uNS41LjUgMCAwIDEtLjUuNW0uNS0yaC0yVjdoMnoiLz48L3N2Zz4="},"names":{".gitignore":"git",".gitattributes":"git",".gitmodules":"git",".htaccess":"xml",".whitesource":"json","composer.json":"json","composer.lock":"json","favicon.ico":"favicon","robots.txt":"robots"},"extensions":{"php":"php","php3":"php","php4":"php","php5":"php","php7":"php","php8":"php","phtml":"php","apk":"android","aab":"android","json":"json","jsonc":"json","json5":"json","zip":"zip","7z":"zip","rar":"zip","gz":"zip","tar":"zip","bz2":"zip","xz":"zip","png":"image","jpg":"image","jpeg":"image","gif":"image","webp":"image","svg":"image","bmp":"image","ico":"image","avif":"image","txt":"document","log":"document","html":"html","htm":"html","css":"css","scss":"css","sass":"css","less":"css","js":"javascript","mjs":"javascript","cjs":"javascript","ts":"typescript","tsx":"typescript","py":"python","pyw":"python","db":"database","sqlite":"database","sqlite3":"database","sql":"database","sh":"console","bash":"console","zsh":"console","bat":"console","cmd":"console","md":"markdown","markdown":"markdown","pdf":"pdf","xml":"xml"},"folders":{"template":"folder-template","templates":"folder-template","views":"folder-template","upload":"folder-upload","uploads":"folder-upload","vendor":"folder-packages","packages":"folder-packages","node_modules":"folder-packages","config":"folder-config","configs":"folder-config",".vscode":"folder-config",".github":"folder-config","images":"folder-images","img":"folder-images","pictures":"folder-images","icons":"folder-images","backup":"folder-backup","backups":"folder-backup","public":"folder-public","www":"folder-public","htdocs":"folder-public","database":"folder-database","databases":"folder-database","src":"folder-src","source":"folder-src","test":"folder-test","tests":"folder-test"}}
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
                "icon" => getFileIcon($fullPath),
            ];

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
    if (empty($timezone) && empty($dateFormat) && empty($fontSize)) {
        return ["status" => "error", "message" => "No changes made"];
    }
    $data = [
        'timezone' => empty($timezone) ? $config["timezone"] : $timezone,
        'date_format' => empty($dateFormat) ? $config["date_format"] : $dateFormat,
        'font_size' => empty($fontSize) ? $config["font_size"] : $fontSize,
    ];
    $file = $config["root_path"] . "/.fm-config";
    if (file_put_contents($file, json_encode($data))) {
        return ["status" => "success", "message" => "Settings updated successfully", "type" => "confirm"];
    } else {
        return ["status" => "error", "message" => "Failed to update settings"];
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
    if (is_dir($path)) {
        $files = array_diff(scandir($path), [".", ".."]);
        foreach ($files as $file) {
            deleteItem($path . DIRECTORY_SEPARATOR . $file);
        }
        if (rmdir($path)) {
            return true;
        } else {
            return false;
        }
    } else {
        if (unlink($path)) {
            return true;
        } else {
            return false;
        }
    }
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
                $sort = isset($_POST["sort"]) ? $_POST["sort"] : (isset($_GET["sort"]) ? $_GET["sort"] : "name");
                $order = isset($_POST["order"]) ? $_POST["order"] : (isset($_GET["order"]) ? $_GET["order"] : "asc");
                $response = [
                    "status" => "success",
                    "data" => getDirectoryContents($currentPath, $sort, $order),
                    "current_path" => str_replace($config["root_path"], "", $currentPath),
                ];
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


function parseSize($size)
{
    $unit = preg_replace('/[^bkmgtpezy]/i', '', $size);
    $size = preg_replace('/[^0-9\.]/', '', $size);
    if ($unit) {
        return round($size * pow(1024, stripos('bkmgtpezy', $unit[0])));
    }
    return round($size);
}


if (isset($_FILES["files"])) {
    header("Content-Type: application/json");
    $currentPath = isset($_POST["path"]) ? $config["root_path"] . $_POST["path"] : $config["root_path"];
    if (!securityCheck($currentPath)) {
        echo json_encode(["status" => "error", "message" => "Security violation"]);
        exit();
    }
    $files = $_FILES["files"];
    $uploaded = 0;
    $failed = 0;
    $failedFiles = [];
    for ($i = 0; $i < count($files["name"]); $i++) {
        $fileName = $files["name"][$i];
        if (!is_string($fileName) || $fileName === "." || $fileName === ".." || strpbrk($fileName, "/\\\0") !== false) { $failed++; continue; }
        $filePath = $currentPath . DIRECTORY_SEPARATOR . $fileName;
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
        if ($files["size"][$i] > $maxFileSize) {
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
        if (move_uploaded_file($files["tmp_name"][$i], $filePath)) {
            $uploaded++;
        } else {
            $failed++;
            $failedFiles[] = $fileName . " (Server error during move)";
        }
    }
    $response = ["status" => $failed == 0 ? "success" : "partial", "message" => "Uploaded $uploaded file(s)" . ($failed > 0 ? ", Failed $failed file(s)" : "")];
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
        @font-face { font-family: 'Embedded Seti'; src: url('data:font/woff;base64,d09GRgABAAAAAJGkAAsAAAAA3RAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAABHU1VCAAABCAAAADsAAABUIIslek9TLzIAAAFEAAAAPgAAAFY2IERRY21hcAAAAYQAAANyAAAKoPxOcOdnbHlmAAAE+AAAhbgAAMUg4PzpTGhlYWQAAIqwAAAALgAAADYtQ9YeaGhlYQAAiuAAAAAcAAAAJAe8BVNobXR4AACK/AAAADAAAAKIfUUAAGxvY2EAAIssAAABRgAAAUZ9S0tUbWF4cAAAjHQAAAAfAAAAIAJ7ChBuYW1lAACMlAAAAR4AAAHm3koZzHBvc3QAAI20AAAD7gAABbLBteCmeJxjYGRgYOBiMGCwY2BycfMJYeDLSSzJY5BiYGGAAJA8MpsxJzM9kYEDxgPKsYBpDiBmg4gCACY7BUgAeJxjYGR+zziBgZWBgekn0x4GBoYeCM34gMGQkQkoysDKzIAVBKS5pjA4PGB8sJL5BZAbBSaBGkEEAFNwDOEAAHic7dWFklRXFEbhNTAwuLu7u7u7u7u7u7u7uyREeKt+kFSR+9+VxwjU16end+91poYGgDpA7cKgQjXU+kFV8YyqL8WrVeXrtWlQvl5ddaJ8T3Ver/z89at4rMpj8XV1+VireG91UaxLDfWoX+w1pBGNaUJTmtGcFrSkFa2LZ81pQ1va0Z4OdKQTnelCV7rRnR70pBe96UNf+tGfAQwsvofBDGEowxjOiPL3SEYxmjGMZRzjmcBEJjGZKUxlGtOZwUxmFY3ZzGEu85jPAhayiMUsKR6XsozlrCjOlaxiNWtYyzrWs4GNbGIzW9jKNrazg53sYjd72Ms+9nOAgxziMEc4yjGOc4KTnOI0ZzjLOc5zgYtc4jJXuMo1rnODm9ziNne4yz3u84CHPOJx8VN4wlOe8ZwXvOQVr3nDW97xng985BOf+cJXvvG9+JHW5f9fjfJQ889/X/3Mp07l57CWyFlb+TxXqpVPZqWO8lmv1BU5a0TOeiJnfZGzgfJ3oNJQ5GykfHeVxiJnE5GzqcjZTORsLnK2EDlbipytRM7WImcblbttVT5vJzJvLzLvIDLvKDLvJDLvLDLvIjLvKjLvJjLvLjLvITLvKTLvJTLvLTLvIzLvKzLvJzLvLzIfIDIfKDIfJDIfLDIfovx7VhkqMh8mMh8uMh8hMh8pMh8lMh+t8vkYlc/HiuyNE9kbL7I3QWRvosjeJJG9ySJ7U0T2porsTRPZmy6yN0Nkb6bI3iyRvdkie3NE9uaK7M0T2Zuv8s9lgUhjoUhjkUhjsUhjiUhjqUhjmUhjuUhjhUhjpUhjlcr3rBbprRHprRXprRPprVf5/g0i7Y0i7U0i7c0i7S0i7a0i7W0i7e0i7R0i7Z0i7V0i7d0i7T0i7b0i7X0i7f0i7QMi7YMi7UMi7cMi7SMi7aMi7WMi7eMi7RMi7ZMi7VMi7dMi7TMi7bMi7XMi7fMi7Qsi7Ysi7Usi7csi7Ssi7asi7Wsi7esi7Rsi7Zsi7Vsi7dsi7Tsi7bsi7Xsi7fsi7Qci7Yci7Uci7cci7Sci7aci7Wci7eci7Rci7Zci7Vci7dcq/494I3LPW5F73onc817kng8i93wUueeTyD2fRe75InLPV5F7vonc813knt9E7vld5J4fIvf8IXLPnyL3/CVyz98i9/wU3/8FdWELtgAAeJyUvQm8XGd1J1jffvel7la39qr7quo9vb3WJz3pPetZsjZbsmzJkjeBwCDwgu3YgdggYrCx2Rw77dgJtFnGjOkJMdiQhkDjmDRpD07shoQloUNCoKFjYgd3w88JwT2umfPdW08yMzDzG9Wrqlt3/ZbznfP/n3O+Tzmag3/EwM/kjFwxtz23L5dDzQXUX0PdKvItRJoW8quo1x0N+512FGavGkoWUbvTnkVB4vayfb7g8OokwToajoadYaedoBfPv+3882/7PfnR2PaarVtfs+3KwbZtA40xnSsc493X9jinCiu+6k9M1/R0y9TzpjPctk0oTCBkCY6Odi95/SW9Hnx00XxzdfdqUmvc1qx+G2NCKSPkphOaRvjb0CoiQnX8rb6rCXpqiBBmwnA5gerhtI6ILOWO5W6A+vFAltRCgs+i5iJuJ03BbcQ7SbPT3nwN+u0dqD/qj9bQaLiKujUU9sJeF+rWzdrAQnBJBflhIH8lSxEJshbgIhn0R8MzrxCenE9sn9nM0DzDLNvC9tTYhA/TUT3b46HjqZwQrmybjp2alg9Nzh3VLEc7ioquFEtqWyUqUSpWgaK7Q7+kGIpjEyyo6ge2YpkEXcX50oJvEZNwrnJKOecCqarjGaWp9nRsM4+VDc3w2udqQsCzuKpxQrne4O28KJghlK1RsS2EvhJXG1WLU0zs0NR0YcSmSgUmOSTbEP930sjp0II9HfXcyI1G7gj/5vUvvXT9ifn5E+h742dRjHaujn+710PXr+Yy2VrA1+VETssNc+fmct6oFyWdRIx6nWgA7QnNOwC5SoVJtlqvGwVpf/hSyKoo8KFBk+Zo0ItGvSAZiKQTfPGi2YvmokvC+s76LUsl34YWVwOvFthxvKXd3BLnDV3RvXynallxr/Xhbd1+d6ab9NDtP/jBjh2XXvGHbUdhmmJwTVEcz/Grdl6ZMrjqc0VTvHroFEWef/+jH/3+Iw9++FOTOszjf8yVc2u5y1L5aUJxFzFIy6AvRWMwGoIIBK4vEtHalAEQpUx2YCi0R8NuKjMB1K7jbx7twyCRRwfyNHmHUPgglQvpRdAeaygdaSF6mSr8RJeQOxxmGrfze9W8IAYhaI7Sgl+llqkyhjS0qHrHDEMEatsuUIyODKhtaJRSlKjWDuhzEDuvTI7VqZtnwuHUsBi1fGrpmKEcp4dnMLI/Y5j0tEAaUcd7XEZ+4qlbV7pNaC9qMnjmxoHfut7VNW1py8p6iBE/cVAwlZkgIGhx/eQRkysKYaX6jiXTWJtTmeaqhXZpVIBvKoK2UoGmTNvTIufnrs+9M/cJaM3REAZaOuhkuwVdkIEA+lrIARZ1/CSImnAkgEYJEhFEwXAdh0EPfknJ8CN5EQxCONwLevI6OLc3GsJAlXqoOxyBzAyGWT8soj4MWjnYk8kJ0Cd8lPVXOmrXUV/eaNiTR3qDHnz6ojlIAp5w/MVtBeq0q8evunCqgSiiDHSQ4ZuCwYgjno5Ao8EGdXWV9vtYYEyD4oHXYRBPTBkVJha8qIehS+eCfMvWcdldXn4d8Xyxf/tSYXWnQvDSws4ddr5pOvmosjqLsdCF0nUdHuaLNQK9RTRGKzbDrxu054Wq1G3oviTOQ0GgKITbGihEzDHxVKRQDptwUR5US9ujDAY83dV78guIIak6seoEFlarMVQeu7ppYAY93Jo6cF7NVZX7l2rmVETEySu0Eqaars4/ETlehKlndcgNTEWcEs1gtjCYqQtzUZHdiiZ9a8F4z6FoFAUqGqBTd9/9/vGz42eJ+f73v/9uqSLuzp2VAytXyk3l5uH8xqg3SjqgGBIRQecHvpT97hrqLyDWbPdB7/r8zAb+6Phf1k+FJ2q1E+Gp3eUvasZ84xOPbetWq93x27xyuVUuo6PFVqs/NYU+9+Di4sLilYvPG00nGTLHrna39ap3l9tl+KtN9eVZOSUb50TLvTn3vtwf5J7OfRN5qIw6ULLUICyiZlvASK2SUS8b1+uoLSVngQzSE1KTkhnHcCiH/sQ0VOHkKBzJXTVpGQejPtxgMJRKRI7wURcsCwidPAWGAhxaQB2wTAsERkIYrCG4Qw0tSV3RS2UX5F3wAC4epPYltbr9oZDGqicfF8H1UJoOPBjslQ8XgLy3O7LZZPNFYS/qhlDWThKmyrWdWFBFkHRpEaEm/fYgTAucFSl99aBSUS+E0dWBLmk3uR92oIqRvGenTRwCNmnLkVnqg2ZyMMEUh+W2AUonFtH2UsUiDif+cj4Oo5Nr1Qqh27Sy4bbhgYgQkDtWMijzPBgmisotoYHxVijVTIXkwV7C/fILFq8EIMKFEBu/68UI5B1MvCLHFVg9Nms2iwVOBMWAJ7DiKNQQuhlYmuWQIwYl81NgQYlNyqFThmGiGDAItDLsOhE264uN+v8WeysMHu+rglBmeFAj7JfASLLu1K6ty0USa56Zt8VUPQ48XzW5IQ425qEY9UN/ZHvIr/gexTpxwCRrcB+pGwyTU2RqBKswPFm1FGuzRc5tD+RDts+gpoOysC5oXbZ08phVMjRiYhVqhZnlME2jjKkqgjMwAmBgQ31Bz+bdImAdGOcEEAB1Odh5gsMoH16uImZwRFWpiQkmG1HJBiQQGTUHboGEAXjA1xxVcfWiinmv5GBES2Az4GSuGqABwAbAttCpdqK50Ggs1b/EQdcIBVMDm0TVsOIZWrKI2Zb6Cug+0CmYQCnB+IRqrBkqVymUUVztlvN+wVuBegisqkyXwyqzoefjx2DUC8APCYypoDEACJEQMOqsLwU96i2ASU3BJihtkEpsovWX7zlxYn19HRUH07VF7aTSP7TQPdbtHnvd8cLHpgfogSuvRMXxe9CxK9enh0l5bs+WFCf2tgw39Qv+aW4utz93EJBHX45a+SCR4g0AGRYOfBgvAG1HUToSNsFfKxHJKBn00ndPpG8wPvKd+KMO7P9ua20+GS0eiHcrjqb5VpgPi/ma2+l6gbWrAg+YXZyt24ZihOjpmtE224t8esFsGTV4T3f5TNdsCbfOa+hn269c8+1WfJCbmAhNS0a1vTXP07T8wYbvOVbdLti1TvXAgWa3eeBA9oXb53XP6Fv8BfyTXAQ/LJTI4S1rGCzANgzRHrQk/kJzT+fX3/3uX+/sbTR3Jjv374ePJiq73rt/9O58/nWF8JIHLgkL8lYsbbN9gPFYTs2FuUruYrgvyOtowETQ8riIRpMmCkW7I0YAVdoT0yqaUJkgBDOZ6hDAR02Jg0DZdKVChGZOaYE8tYPv06LgtvENP0LOBwASf80BVV9tt/R/GTRv/Bomvw2yafIwLg0FZWUQy7YjhyQIO2Mgi9QsbOEKtlYZzuuarzq6y8S56FuNSw46T8/F30rQB2J1PS6UCw2voM88wDrHY2psCI3lzeX2vGaIFYJxDJjJjME8IjDSVb9F+frPapYn7SjAloL58zM2agn/19yW3I7cJVJqk02CsIAkPUitgAStso5ABiY8Ak4gSWozgESkdEFq8lZKOzi0DKjuqlTrUU/eAb3Y6he3NONZIECa7U+fc55yaOb615gFPw61QMOCPHBQ8LUT66ZfL+fr+ZljbxAMbUX5moOF+D4UWZ/RKzdXDcNTLZycBI2qc48YIJYX5R1fjxjidWrqdv1gzYRmwLjtkfH3uEdVJ5/sjYFqhExcddy1PI4RWiHkONGIUhaAPozcGf60hWzJBbnMHjZk57pVae4aqTF0+wSQeqPZ7riAdnsNEEKXtKPzxleG/BxgkTjagx5iHt1Q95Si8e8VE4rqlo8uLzQp/u6GSkob4yvTw5NTvfENcE6xgE6185q84iy+WCULuTr8WEM9aVMzniA4BosG7Z12CLC1fog+hBl+/11WKTAKus31bT/c5s0FT1Uquqd5sfdmim4l4i/+1KOW8BSzZF48/vTFMQueKpetvOp5b2HZcEg/bPwXuRkYDR+Q7NGGodaGTpfWPzXvXVmOKuzttDmoL/gBfZ+0GYAYnrZR2J1QAfhaQDAopKWVLCIBUw1SJPwazngDoJ5MXIZSxDrp6FpOQURUxXI4ZzcZ9Jspf213mvJJUiKxqSgr3qzlhlPlniBgD4oFqGZ5pa2ELVXLl2b80HXDfFwb/zeukuaK7beKn4x4mXj1BEikaoM1nDmwULzZsgJ1eh9I0RQnmpkHG4CtSFeFnw+I5XSEwArhZmxbAVEbW5d2b1i02QKmiIVxoDf7dB3UGLOqMdiiZzAtqtTR8qohFGEqcIZlUtNGYBJdAwxtXFYImqcGUWMXMClJjRdwU+E7FlKNgktgF8YlwyD269XQibW8ZiuaX6k6KkaMIzyVd+bAfnntgtdWi2Wj1rYX+37xsCGEEUh0AJcbOhdn+1JizkHuvNxrJY/NugdePgxfaFHZqJINSPyF0h6A17AtYdkECXWHpIrXcHosPT2Sh0DoBsOqlA35J10HwCAqgH5/2FbKyspiO5hRZeXs9UE1qpSBSs3wiO24rOkoOgxgOGI1KqPugDl/hXZee9t1awhvDLfuXLu6Wv85wJatMQG9p2LWa9qJsE2mEzO7pjHcQyz2ipu94imgLLOnb2lUKRl/f/3qdbTzhg15U4zOGa6sEpW2pMpjRDVZElkx5crTNlHEI+is3faJkrNgxJ2Tew20mGyeCpLMPW0asNdhlDVM1lge0LikuYBSF0jK5KVQZw6kEU/apMlFqjClSMOGpPgiPQgXpI2KntcKlEQlp6Yaunqs0mxWqMbdvAYVc/LWMy2zNbN8eMm1y1o422jlyYF3XLB7bfv0lin13t23tJPZIHQNzFErWb5ocRCv1isgwAhdsL6BfuQtVUXeBLDi14t/GJ6zbz10Q6sORMcgsxGDgUHySxcttacaJVIobzXzF7zj/EZtpHL05DmjkIH5gSLAs8/bVo62CFNjF7yj1d7Uj9/Afwx2uJZpCA66X0hovDiRG1BJEvmJjujgbyByAGDchz/IFea2YqGSW08xwZ7To4XPHn1421H0Vkz2gGH63fsZc5MCY/Tm1zL6fbQ1nPvkRR8aXXTWVidkd86FZy7n1qV3BQF+AnwTjapoDQOccqEj1rBsYguTX3oMRF/SFuZFBK/tvH7gzf1N9b/MXn3qYGKvv3o4umJLePDa1+8o9c6dGl4x7059tviHU8eP7qyY/UPzC+cn+Z2XHSlW9XawMr74Z+f9C9m975bbuy+Vft70a+efuubS7vjU+qnrDoWzV45au/pldOPqVdfOfDX6z2UnXj966b6Z8aO9o5dt5Kfa89d2gugfUWFt/KOzev5aGKevknXqtFPSnrGrXqYAgZpIoQEGlJEv6bxrp0ey5u4M+knmiOHZxRKWLEhyDyN4DU08DgIYELqIKb6iLfqJ19SjuetO37yn7YnAc2oFXXq+kKAqKzDbFLS2wWKmEkDKyOsmW4rl2A+4r/uFyuzRK6NCOfZaxaIOrISFBRhVCRAUeLZRmr1i4VJGX7244tkSXyh6oLmgDBFBqrk3lMxdEYZwpm1mufX2QqfvDeKZclMzPVadrwuKkG7ly0IDMcbojD0ukHzugdxD0h4vIuBsfWiNNTCBC8hGzUFbbkiKNsxwSNoQzZTtdeQZFnBKP8ncoOlxuSslr0BbfS7dL9KurqNukBrYSKq6jM6moEe6aYBIyjPkQ0HdyY1RRn7Tl7RO0n5JEcNjxTYISVROysxVE051QWxKoTFVw6w6Rh6IG9OnQX1hG05Y1wSzCVga6jBhG3CYGRoYkF92E8AqcBPhgMb4ZTfhQOIMmt0EfhD9n+ePBV5zLv1ET/+KK0xgrlxeoXGm6v+353IGZJXBlfBco1r+f3lsehM4U1O49Qs3aYq08FK6ssKbxa2bhYLPs9hzDPxlJbcLevn/F38JkqAn/VeDZDQ4+wOg9I75ZCWlLa6q+2boBUBbnGmgLebuynRrcQ5shWUKM0TDuW4X/r44WF0dbMd09cQO32lLmkIIV/VkCDTFz6t6/lDDz9tWwy5Ytbl7B3MrK3NkbW2wsTHYlNMd5AZgfQAkQepc1nI7ZBE1BHrxf30Y7UP7Hn7pkkvQ8UvIDa961fiOJ55Ab3vV+ML7779/Uv/sWjPnveLqzgi0mAetMOqcucn3Pv3pmXe+89CnPz39jne88lbn3f87M9dci3K/cz98ZeXBf4//S66U6ulfRfFGiVhHiUAb8cET9uGT8bH4OLwPXuYdvjLdOm0fc5BzeuPgzlvh386DG6dPn37i0CHgTBm+0Cc814ZyR+mzgPF6bsNlcPvR5DG/7Ps7uDue/uhHv/PL/oj28jfx3E0zMzODzff09HSOZ3JCGLC1Vm4a7MCB3DEpLSk0jkTmmEph6ERMUvnoyGr2IrBGvVSGeqlShG1LRn92oFXUrWKwGrNoFMAx3AeLgch065b13f3d861GIdQ1XIyK9dYW2HHO29ozeD7WZrV4LiaO/T9DUFmq0GjIgoavXj9jO6YCsmJuiRxd45RqmoXpvrXVNUUZHKwiHPpJ44IN12csObRqaGs7zqG12p2Hu93D+1ymasLwD+wpFWwzquwVTmmqaIvrjxMlX7X1M/Ed6NcXclouD3X3Ab25gDGAFvTTrSH+7od+7yOfef+Bduv0Q+vDS46il97+TvTiRvXy7R8bf/7wWWxYJiW4g2zJXKpJkyaM5MCvIRg9kufJwFc7aSCpQwcuIqW3vVYp6QXrk8YVSvCdn58af1P3lVCch1V1/Dw69uzNOkfX4s5bX6sayjH+J65RDb5zCv0VEKvz0Lh+s+4GqDX+nbPPp2DzWoC0Ls3sXvYCYzXsZTo1BU5niCYAjAh0dZIat+TM2ZI/QGdHaewkPZYag+wAKAvAfovbukZoCJNRren1z2lf8MaLQQOosTm3rWKNfqYzp2r++u/hbnFLwyxoa/sHFx/YsfccncVG4H7pi07dEnz7/sHRiwf7cY9QHascU/s6plAblB4OqQ6/hApqV8VYuQHoqEZ8JnkpMZh+XaAwIpQPXAc/ZXCpXCM6w5p2Nexnyhnc2cbfODOOcqgRNAYyAATfLrzRe9GD46v+4R/kJ+qOv4q+OvzC6Auj8WOjszgf/1WK86+UvH0C7QPpDRUpLGt2lvtnKFbG41OXZ0rlUzvXasLJqQtXDp0BcPoJH5AuUmjNNAIxi3gKxVlIPUJe+5rFqFO/ipCQ5ZmheopbseJu23c8X63NlIr5pluODWv8T+UY6EtEzMABrBs3AaVP1cqlqku+9/eLh9uzQGfXVcwx2A/PA6AAFB4DpS+4YA+tiiBcV4xaBEyIKhGwNU+xVGyUYrBArbLgalhuERqPPyXRi+dWkiaiiKys8BNNT7ZNSurJ6/Hf/hI9dSHI3hskM0qNRvru/JLvlny3E6lMUi8PNC40aBMaeMKneptUNWvdNtt0P4vUGT6JIvM2enI9/bdXfhyYbKE2vNdjJ8x7VlGoYIJn/+Wtb2YgQaLQmV25e+e2fnc6VKc1GP+qQ8YlzTZD275HD8pGVDOYIfJ6/w34O2vamrn2nslb/htwumA7wqt2AlsDFGe6UdUa1hOKa6X+wpKrEArkwCh80IpMM7J2A9Kjih7qKgNOmpzFpjvx/8w1JfKCYZgyxAU5GtNYFE8d/rLiA/lJZoPzytSxwjkz39tqGjQKA8OgbHm4tDq8mLcqZQW/KtAqLNActb2Rn+nUKvlhb23n0jDxnOnWRRGm1fJ5Ex03xl8HjW/JOGogoqDDxAAEcxA999QDDzyF/ac+8IGncPiF47fffvwLBL7I7Zd//ox+/Co5BD08LT16m2F8kcHqTKizQkNfklR9dEAtV6ANamDadZPydnWpfXGnn8w5lpefbl/RAni2d8aJiHjMGeBHSxW3PpWvV1tbDvZnwzwx7Kn5fecc2X9w7zV2Mrc0LqjIqHlOI/cL5dkAa3WmPL+8NBEgHZ4Gg9JoMADYjsg8JIO+xEEyHhSdLfIxxf6VBYa769r6odpixcm368VBZJWrpfK5hxpT1fmplXnnt89U50rF/lWVaczON9CuYW3KN0Rox+XA228Kfu5KY84xgy0l2x6/b7OqmdNhikxBjVlOmYy0MJdTUaMTDVrIRW5DckIUNTruqIFeHH8fr11/2/hL8P3q8U/ffs8994z/4g5Uf9ft45fQD8bfv/c3/886qr38ZbQTWR+959570NK73jX+/u1n7cc8fh7QkpsLcrlRBsiDVJ21CeA/F5Dg45Vtx6PLo9Pri/34L+9cW3tp8Yr3Td03RZ46eeCiWYIuf/zx8bNra2futwPsEYNyu1IDE6/hsc5gFAWtIAKxw78//shHPoJO3jf+/JNPPjn+/O23305MGelD8Q9v+O6tt3738QcOHHjg8GZ/f4xUoPYy0ieVwyAlyJm/RZYRBtICkXo58wwEYS/tf3THDeTG1aBya1zUlUS0PbX0e0CgjG5pxcKMA9wwBibCN6tt9RL0nY3dNdKee3pmNrS2WmtlqjnvRIwrZTtRECbJWs3b6yH8Mbhk4ZX+oEraO3JUITmqyChooSASwXeQevtdJ0+Cif7xXXdhD2l33nHnncg4+cSVsHnXnXed1QfzZIdEf0CZBGCqUWeEXjz57Q+1v/zl9oN/TbY/WXvg21dd9e0Hapu2Db9IjsM4lj72svSpdGSCQMA8qRc9adplQ3jEAwiHd+3ZaIq8GP/sK3+tumT3f2OmruvsB1/5yqXYFPiSjXddoOtf/xf01qbGzfH17yEYWCe5E711/C68xSTGWV/BrxMvd3/uk7n/kHsm983UiyuSYQcAIpeauJ2GI7PGz9z7UQjlmGQzgJkbZL4cMcoQRaeXgorU45p6eqQdqMnkhTUZMZCsMwuQjiQAtVFvBPR9lLpLO2EN9zqvyJAZdtpSVtfRgPEUvIAtjsLhJKiawpehjKHK23OR3Xw21btw+iSmIIs2JDdRrGFtDWsFolRcosVaed4Eum0EKI7WhGpRYC9gPolwKJhUGUSkVBi46Cim7iouIVXL1HFNxu5VTXfKzCyTvKkpjZbFCGKxXaXBQkiVBUCGBlIoRdzcUX1tqHNda+TV2sK8aSg6ZSCXHEy2YJSOb6O+h8lCAx7PZNixVlEUL+TWVRiduiucLfdvu2VW+QKiTAuYShXGNd3Ia9YTHrYFAwkIYjO4fMhMV1WKVWYVtKoFkq0aJebjlcOu2q7YJcsK9dgmYO+hQppQuHSbElXyS8XA1WUbIKdAgdNuUbsXeR63uBqJ5oEKZeVqAfFKaXnWCPtm/tXn1LZiAYBGUTBxqK5YnBTmgxJjlmU7dnk2nNMB93IF8AvgOsdhGGCc8g2MXg2NpUyZWxbEfk6R/MetOU1oTBx1Sk7gFgpnx8vXyR1pHlEDdHgCgM4dtskd45vmG+OryeN4jjjtxvz/8T18ojF/1g/p4mfA5rZye3Pnw5XJBJvVUJCmd6yjNA1NQkSJcTuDRSxYdzjyetLtlu6X/qJ+KuaJSIGKZF1AhPB9pwxCESAo66THdesUeYOlG+r7DdMQiJfnZsf/Nqjp7/HuNlymlJ4pmyoIEXHe72kej08/v52voEfK0ufNAKmpKhd6/UcvNHQuNwGeDK666r65Gjo6/ny1oTqOw+FEYDRaqxvpIFTOfffee6ZdfFLMHQc9lNYIR91AWkU5aCTkt8ACyuB7GnuC2gZRUIVhAz+FjCUMhnJjkNpOGEBQ6czzlXSysQ0HvoMo4cqDCK8wANw6xdzQASyGqgKonXQxWPx2xHDN5XxAiFU0tZYHveya5fKPK5UfgXACFjOYVzb/AAsVvaAqHCD+hxDeShkANczYezlXiqW8Uypq8OvurgzdewGr550AkwHhcE+SxvMUH276Qrn8jyoRCE71ivYfMMWYtEOfbMldncZ4JsNbpocNAXYnWdwjaadV7kzgZ5DBrij15sv0iOU0BtlJZFAyVWndEWCHCbJYw6BM5KlZCGUHggfgOVEQ60HJIpzpVJPESBexR/j+fVBFT7VtgwGpA97FQGcYC1OxY3JSDAuOU7YZIjxWtXqh7Jhqu7W3OUXJrht3X3jB/jeFvu9fvd8wCWiKq+BKZ3G4ZhiKBfCkiSnFpkHyeWBQQIMwMeoNqEapykPe6Ej/UUyQxnihTEFl2RUfmnC7ENiKurt2H91zy0WWHcc3HbzgggM3xUyzDvi2uylHAaGA5zMOK/OogK9iyRhB84ZdqWtB3s8nuqnh3td7WAOVd9Attt98JXf4N9pFPIef4gIp/MMf5go00Z/NX145fh5jH65cLpEF2K//QY4Clolzndxy7nDuZO6m3DtzP0cKCtEA7UGXotegN6JfQ29D70H3og9KLpu2u+wgIUlpxw+7w77MO+mkLJ1PfIVRP80sAWgXdWF3II/BOc3UECTNUX8ddQfSrgyjbhotSLIYHJdpWsAuBm2ZvwUkuSvNN3SWjEOskTAgSSdNqFtPZaYvfaUwMCYZh8MBXDhKA26p02SUGhv5nQZ0ghB0hR9GXZnimiJQKFAi9cdmwmcGXtuLOCsncHHpVBXcS8N+/YwbVJHcnZEDacCipvS4RtIHG/CwOxFJKetNkPR2NOgvEB7AhX44giJ2QFNaWKTOGun0lhXNKNWo3/R7cElGr7qhgA7uS+oaRk1ZJWgrmecz8pv9XhCChujDHqgH3l5MGPWt2cALcBRoO3Vb14Wiv6mct4ViTgOQUUsVYlgG/F1lmCD4PM8wjAMFW5bJAwbAC9M0EcwESVLAqDJBVUyaTAXzADhE4xiVgb0xxEyGPs4pJwzrrmhqoHo8Q6iqJR2/XMWgjWCMLBYoKxQPHlmqKZrXzpsBMYBZ2w5jClOBDctIGaZalTFHpRZVuMk5pWxhfd8qITBYFfqcw72QBMmC5VOWvMeulFTRLky5irDz200ONgFuYWLNMiwbNL6pKzJ7yKImgmEvi6wwmXPADRjTWGVQ/qJsFltvgkX9YNYWKpzHJMq6TiMqZo7BDbD0i3DCx4Bmg+F9rFgo+q4qRN33SoKsqKaZByi2bJmdfJUBA4wXxJpqGJ5hqDXQp4SQvMYooaAHed4E4CAEpaTJVQ2DXmbChEJ3OVNADZgGRlAqDWwLxUaeyKwdhMclwhgzLZ1Wlq3AiPN7PYPCORqYqvXacNagRMRGHBiM+UrJ4kWFaWarDke3jPa2KcEOlY9knBA1H+hNpxQNEio1vwpVMrlU7TErEZUygrFFRMnz65Zu+1DTG9h8OQgxq+Y7pnUCQBIgB0BFiibTNeBnoHLOwdAdcXBWWNVSmICGNkz4IXGKLVOmBMf0LWlLmUTmwmAtbSAPI1CNmK4QbCga1aGpN6A9iM4pxiINh0x8oI/hewBTRLkkd3Hu9bk3gxVtgqJYRV0YCon4JduB8JNWGqvLkGYgB+A6ygJJcEJwxn2W0tFUJ0QTE5Jl7GaAGNSJtMGpJgKlcRkobUQ/TJCC8Q/T7T8nCF6n0szM43L7OqfYpJTq2vT0AmoU52vGJYISQ6PiIYSUyvLBXb1lRVlYuuDcbuLS9+2cm1b0xcL2mf3XKPra7DmKfSXig/q6xaPC1NQAV7GBsUGm5ZdOZoiOiUYuA8sMcgrWulgdFacJTxyFl31hOMpye6cGdmrtvO3rltGMptm/onbS27tWT4S5d+34+hwM7D9ERJBGU7HWi4u645VkE4uJX22cWwcUdjh3Ivf23Htz98mIJ1DyzCUpkThoY9A5QU2qU2hnwF+pWpYOEXk4gyOT7WS5Capy0znUOOMl6kovJ2xK52ckpJOzmQI3meQBin4RpQBuuStTJlth6rUerMGzosy0NDn64mwdEcUEuCUKxZrnW1eA8F4Iqoi+GrA/u5AweoXrerViQdiUS0Gvz9qmZduWeSys1+cbDeAM6fc1QtctXX8ErnhNeilDnJ6Eu12099xrrz137/jTSHN9V0NBNXgsqIZhNcAvq05SArVFDO6YzXotf7/K6DRvUcZoi09Tpt4flupN0xE6gdNqNUctljEu/4l84Hx98qmKHtc03hPq++ASGKHtNhQAWMW04q836/Xmuv9GzdV1V7ODwIY3PHwz7vImwABK7lronc4y2AWwZaPUEvnSk5JGkvyJcE9yV9P9vUQ6QsEMLoeZkxlaPTNfqyjNc0mb+Ox2tn9whsjhW1qWC2rmj8Pt2wsy41Il+ag804n8ktvenmzfvvegravLSs1CgMyKPqgUSpudMFo2F/bUmgG0LLBAROZW56igfcoRnds2BzSL9phAjt851igamsxwtlTL+mbkWCEIuw2jypze2obhJryqERDSEg3rEktRDBvwFWhlndQKpmGGh7uXXHEDKDpa6XQqlG9+C7pjeVtlY/doML3pF7gG+MZ07mDuRsk20qjppI6ZF3jUeIX1T6OnACg2Q81Btlc27+YlzU53mCYsraJWr5vNIEnTnKEJJWbItE56b8A16Icq0WoCCipA+zJ2WdRyfYy+GrYvXKZEV/KC2TYLYXijt1EwAnG3jjlRBXebZVsF0Eiw6YBFI3j3NFiTwy/nD4Kh7hwC2+HZklbS2S2g7A0mmOGMSgiB9BMVeInq1YJqqZcUmrX2XDfZlRR6lWY0Zeqgn0GBIZfqDI8spePmjdBKZdfybM8ruNDTxT0UDBbbmchU0jiIa6YiPE8oQGDbFnN2ImXii5gj5+c2QE9fkTuVzajotCU/k9lRWTZzZ9hOncmpsrBQRuGaKQWSYSyQXJkmCop3BC2Z+pdlQN/r1lB35EnYFLiyC4KEjBI/GJCUI3Y8yR86g0ZAwKYIpvHQKnZDld4Npr/VnyJ3Y0GibsEM6ObBSKF3Q/NO9VvwbQbLluGM62CGPw9nmOTzqkwWtiLyWXL550lkGexZL65a70c3oA9h+hA3l+dNk6qHuUaKrVbREIcZI6Y5u2zDUWFkRy9ik6P8IsENMwiWi9CPHG0Amxw/oYL5p6hW8grsIbRd5jyPn3iIwWga3+R5FxFyxp9KcmQ+97Hcw9CameN94kYFFtQZtCfho36yPHGqSNFMUwbSuU8g23KfZFkjIE0JcCgeZAlQMlkgpVYC9qcANs2VSgMpaUKAhMEyIV1mradyL2NU3SCLmmQRgM3UTzhFImNQ1KKHv0REoJmaZgLkshy/lqZ6GSIvVGJHflQMHI/qINO6DjBPIBYZFpWpFwTkMGLS08FjUR6UYx5zAFvEoI6FMcBPk+lYaIYTx4A2HBeXmWVPEV5eEYVSoeZrto5V1K+qNVMH5AP9ARcCBnzp/ehHiGhCKxY4tUtR1IQHWRwQIifUleJvaoGcOwWI0WNEIboPIMf0KGBThXgxDA4ZBwqYg6wYzmK+R1hgUw8UNqoDotSEXtQMzYiTPFFUZsROodgolk2xAAqMAdAjVIVxqM5pWmAHeYC/phvr5UE++F8mOgn/O/IOYF39ND4IuiOdLyRkTofsubacSdUZhJ5kfP4mcun00+wQOY4GYQescDcjQWl+Yeqry6JdvQgGT3oNvhmsoaMv6AmAl7atEUzNN38S2iysN1fO26HLMAzgck2Qz33OEMcwZ8BuKdeNRUNThGpYykCjlvkgVDg+csH5h1Bdi9WTLiMOIaaq8Xgx1n2DNtAng+PhDysMOHUe4KDpFW6GNmys95xaezsMGaI4nmZr5sDQGVUNh89uWArs9oQQyhm/Jv4R6BIzV841czPQMjnQqDbmyWA76q0B+JTIIQFBl3M2ko6QW5LEzaIh6S8HcNYqaBz0AnlKSlbzTlRB+GlQm813TxHxFCIzCD/5mmvIf9p5KTn/SU6ewvgpgprvefkpjJ6Gd+PdzcWnnsRIhffrx48gBN8bl52NcTxD8rnLc7+ZzSGRDh0ZZQctjzsycpSkGU3S+5u5Z2BwQq8t8xrKcp26oOjEsvxe7o+WpXfLr6Wpd+ksEvkhp2Sm85omkZN0A2QA6CGfBDKB8nF8I4wMyppc6LSIqFnUFYPUuHTiodt2yjkH0FcENwoGSDmR2XJUoeToRq0be61SI8wDxTNcMChEBQvR9IsSuBOZr17TYfQCEtpdo+JKWgC8HpgeBpLgccewLaiJnLGEOQwTinABgU0nVz8AwkJQXhDFEirWNGBdUHr8RednDcRrny3oiqmCrVEcwhlXdKsSWSdVFVAP41wowACB6SnGAlbD3eU8gGZdd1xd4RMe8C5yCkaLkXNgpFRy7Sx23NmEheyVP6JX/kCvxbWXvz9e2rW8vGsJ5bIfu5fgb/yKbfL6P3tdq9fb1+t9489eN9Xr7e31vv7nk42zvsp5/PVcNTfIbQMrl0Ny/k4YJSlw6C/56cy2RM76kzN9pG2SGnLQ7vSi7MwAZGPUArXdC0BG5Td6HBjd8Pjsm4i1Cl0JH+RNhZNRdLLQuk7z9FP7d19HzAUzSJzy6nagS08uvnh68RH89dJ1pQtvP5eEx0Ppj4UvQqbunUrf413ErVgPkrdcRfJ78rVeicxechn+73vJ4wjtJRM7LXNlo1wR2rGeztroQDkTGyB4AujeRkFvHcnciEU0Yp1IRKIVdYi2tkY+QE6fho8zW1c++tz44PbnH330efSHq8+ht/zi0XTr7kdXn3tu9alHtz///PbN2Ax+DGwahn6s5XKtQSTFWbiJC1KfTdl15Uy9bmc46oGBiF+P1Fjl6DLdqm3bvyU85/ITB8492Lcv17Y9/plLkVNIPGf8z0jzDDsytQq6Y1w9uPuCwzs37ec8IWmsK9dKI11CuoYjfO/4qQcfRCsP/uOhQx8+dOgfQOta45++R/7bHOMv4P8dJM/8hZhsZxC99Pjddz+OXvziPfd8EXuPHj59+vCj5NEjp08feXQiIyH+BrTqdG5r7oi02QNpaHnq0JrY1aiZpXZITbAuZ3ANRzwacbDPIvN2ZZM9MjMNpCube5E2TDZzCz/DaclZJ+rwjYPX7AIzVKh4LZlF66kaZa6jDvjW1nBtof8W5gZVDCxi2NLNsVJTeE205mqceNprrlepwT1yYPXWyy38cRNMrbZOAhTNvkGzeaXgxMT2NN21qXZbbXpP4+CB++1ioKpg6Noj+6Q6oyplpZXM8bw4ZFFD9RwzuEbdjElZ+AXo6cXcObn9ucvkSHUbMpFTVqjfnkVNG0tVDVXNkIT0XEZyKkU6TvgoO5hSRLk37GQeMJn40m9KCANcVNKTTpuYL38Vd39cA80EZojRDbD8HsVNhrkO0LbMAWzRRTA5UFiMjlEjBIiMy2CUA802A8f6I0C2hobILEOY4Rde/vF9iOmLuvTh7gaFRPz2nB+djAiV6dSwcStDNuBv9jSDg2TjhOnZpmqYHoAcjldiUIPLEzmo4J8CTzNyHsh5DmW6yA9bMl2s4XZER0Cr9NwG/mDUaCw2GuM/Rt8dr6DP3LD7vTeh7njXdnQb+lodDizW/2B8Gt0ejD912+H77kWPjB9F5U19tES2gKx1c/tyF6W2SGqi2YysVNArEjakTmoPUHOSKpumx0sn+agpJxp0BrAd9FJqPguDf9DZLC2ZZ/ONK7Y2Kt3Lzj8Wcm12dNHWhe6vXbjTk3MBx0/t3bF9954d6/v23JJM4X3b14CppKzlZFxTNa/8+FVRtT5XrWNn357lnZaqrux7fc3rHtt+uO4z7cjOy6FbmkId/00rufXeW5MW3rN9h/w+CTALPY0Jig3tXi+OX67P1uHvFfFw0B9xbim3Q46wNHowSUlP6zzMbChKM4PldJJI0gqwr2GQrXyAZab/AoBCb7Hpxftee3Tvni2zaMuWPXs/IbfGX0nr9Rt7Dq8D9ltIDBGfd8veZHUKNbftkZ+r+O35XUvmcHbzivTao/vHj6FW85bf+o09aM5Tm0t0ZeveW3ajOydXbduzI5nopAWyFfjnO2SfQUmHk4ny8pU0gyzgEWSBkMkB2J3FcKXx5yJJMaDEh5uB3BTjy5h7mqgjQ62AEIcDOQ01nRG9li51IMG6JKWTyKvcReZVBvIMxIRToXEmNA/gIeBtlWquiCy76Ji+UzQwodbAUvJcpTYh9VKxRkPWLjarc7VinhtguynHfKqo5QftFYOT2UMHXKqJAtIV3VTLC4ImKulXhS483pmWXlh06+Kqpzm21+Idv1nUGffAAOozugE4VG00muulUBUArEV8KjYKwrIAWZRkvhkmuj1VW/ZmAbXDQ6ljmMcOeEzRDEkitAo189UpbCsUa3HF2NCYDQREEOpDvTZjcmCDrHRk8tTdn5L2NNN2JEVlOHB7+DG52IS52skn5a0z8/V1b2tjbvl69CmqREZgzexwBHWCzuG4vG0buuQMNvxn/DnAKCtprpWfzsMFMpsmtU9mAPXTNRFkOENkXSsXRYjSCRNZri+66uhUY8Oe0lUvLlvuR/PAb6rVcnLqgnMHcx7P60FYqjjGdHexPbO/Uo99/NgLFyR1xnapdn5LVxNK0I6MqfO7695uAqQ2aOqq4w073VoCnCYn8+5ABneTNwCyHuZ2A1+/Mnd97u/RVrQXXYl+A70bPYAeQ09JrbWaZYUPs5nSEodOEsGyBPxEZgpIJ5JM3RkN+jKGsoibchhKVggmjk8krZ/xUz9qVqSPCa4dgS2TCerZ3cBAhp70EgBEGi7iNGSTPTQ5m+rvB1HGTzcTnaJJLDSYzM+Gv1E3/e5lbqvhaFmmsUNzy3koUXcZOnc5zHBZKw0ddZayB2SsOr3pcpqkIlMgwD5JmrXpF66hbLwNz+Y1bU6LRDwrQvozvUvaYGmuTtRO0ykkcU4T8aUrpJ2N4CzXYpCNRfjz5R1GMlNkBPZOlgVsXocvLUuFNkzrGzXlChWjQUfw9kCyj+GkQ0h3cxGXLIBlo3UMEA6/HYEirQMNArl1sWTj8KKuplEMwiFcFcY+VjgSs4odhrxgcUM1pXVzKgznhUJle2K7xDg1dB/fhu1YEBF6tiEnGXNgIBjGoEHYnbwQCMdpK55vALF3bESKM+doYXFuzohUDMNPrlCAWKw4QMU0MBTiPEpsqhhpkEbd4eYpDhGbm4nApoLlFpZMicTYyWOgEp4RAmcfP2RRpMkUD3iZps2ZauR1KAWiMnbAMAFLjpC2JXLXarZrqQzUADIBISBKWGTrbiP0orzlUyh8INMClzXXuEuVnjCFDmRdFH1OzriWhIQpqpx8DsxHCSpV1SKIqQojwVIiYzAIiJZiLsNZ2IRGZhhxDQlk2MC1Wm9C2OQFpQrPQTi0hUXkhDvzMNyMCun8IdQ2HGsq1tQ6PoF9mWMgghIVAsrPCMsHps4siV8EovBUk+FQYRzpAir+BiIn3eWVAglshucwqXLoQaKYefFvie07iBqvwzoBvIOyrBHE1fEnfLgHF79WsB1NcLV02cxKsgI3FyXFigmxSqrjYqqqrFNWARblbQptNwvlNURQdxv9GY2W4PTzKNSbQOmBWlLDqsusX4IElk/BJcuIvlYOgR7KUBoCwBh5loOxQUHcYKxGuo8KBlE5I17ZULkjgrxMKSGK6piaMl9ZmYpVF+qpOEYZjJETUNlUhEZXq7HnIoxDOZNXok/HpOnsdio9mG5U4Wr+BelXJvlkqhVCoWQP3sl1aPYalGUbFI+WLNj7WTTiKhwHcLh2Gah4KS+YLmAkU9iVkm24CP0rkosWGEE+H+ar9Shwq70d23tiEis5H/9N7i9zf5X7Qe6fcv8j92LuZZmZv6mq0mnUwWa+cdgDXRhaOFN1oJgEsCpQdNmYlWrET8PBckty+lGv0xO9wQhg2GiSCinD2ZMoN3AxoJXyDZvSPR2Cru2K1FWX+QTgCZ1eIN9RKL0SMqI8kEB7AGoVrkoTJMAoDTpybiNgp+VJKtbZZGmpHYfQV4Oo5we+TLBIpKoZQUHWUQRlTQarKIB6tKVyg8vJARiMW4686bKFQrtmFEG4mclhmArheSa2bBtIPrQ+2kbnccHshKBJVGTIQSy7K0sqwmaBT7NuqYrSFSCYosMoUFmjEZDKh1kxbs+4cDLcBoY4Qkqqxghus9KQFZij4RRRyLUKUNROMMgxLoHgXghKBBd1GLOKXEyF0RU4yRBuGY3fnY9mdgPeAe1nG2KKGe4dcXxBTF+NqBPpqq3jb8HdvCmoHiZWUSeyoJRppqwJN9KwMtRU4xcRI68iFcRQqNwN7SKAJ8BIFPCUENxACzPzeM4wXZW51LQVU7MEDGLBTLNIj6rH857r5OUceGKBerMLptAtV7EN0KmD+aVZqctspOZBp9i+ERGmK6ZvWUwnXCH4EqGaAiSYyvVh5EgQcmzagkHT1cefQPhcuCA25fxvLAb3EYVrpIrQN887F+96wDYYsix61teMx0TkRjJDx0uTqtr9FKlAZydZCviZ7IjMPczDdGZzelw6nftJqxnI5VEC4BEDCXXkoiPpjNFsGaiBBD8ykyudi5bepvdcXcbo8EovNkNPJgI4VrUqVYZs/dCM3yAG2BkQcnVshB6hm0eJHxhxdwXkAFQwMAxbD9TE81yxtLAax9ywFW7mtTbsUBy/pedNw9ZZHK+eaLaSRb6oJqrXPDGIuybQ4pbvKML12lre5M5SgawuLKXHA90+yzkQ/mdgc7H0PHl+mrHVX5ATM9krf3Re+ePZxsrGSiP9QO2z2/e9YvebGpOtxuRvY6VeX3m+IT/TvWdy6/DXCJW5rCjweoNe1CODkfSAovjUYnzNg1945OGjMUEPjG958EEUOi+9964z5QZTkuYpA/AbqbihYhf9AOWR8/J3UX78gnzj5g+yr/G30fT4e+Mxbk78NE+QK3J35b6S+xY8F7hlkib7hHLiTBb7OrM2Dui4QR+45CANn1tZtKuzmTcvT8Nw0ppEdWnujJSACaYD3JPCY+npzg5LULRGs8weoK9tCX1SEuv1s7lwcDJwHxA5KVRZ5lwaxksX30kPtzupogukU05633DYW5NBClDPmVoetfFeum+4SFz/0mpMy6Zm7Jyv+IV8GChqRYt1NySAD4TFaMlbLMCQ9jST5dfAsjPBHJUxX0YFbEZUKo2lzjQDFBOYJVB5Grd8IFHQ8qqmETXUZDoNxxZXQYNQrMb14rUmQBvpn42IxVRCsQ7AQUMyLAT2lDFKp6uFbTK1YHU3g6+QHwC7V67+R5RmAm9ITztJ8PHeTtIqJWq1sqDS8vT8TBcMfD7YlbTLUB5TA+sJpRRW5JrMXGYe8y0/OLIVHjBbLp3qx77CY1E8VXJ2OgADW8PGjvMaElvFZsBpOjUbGwCwFBuAniLdtL5OFeZRgB+qGZ07ftIAvWJZQMrUdJE6agqGoF6axomqMbhWO7S/Z8l0ie7ew12iMHu7/ShQyaWvc58Bl3yo7IDRPTbx8U4Brz+Yuz33odynck/kfpLO+QrkanxcelknCyvIST6DdEUvUCcpNJcwfX0zXC1nsIIRTEOxfm+UqZpsnlDUCTfZhkwwlKI7WsOpkprQ7zQdRDrhz4TTQq+dyBnF2XpkMtzQHYz66aOizfwQEUymycr8d5mfOFGCwOLTXEQbNSdLDoK8AnQf7kBdP6ihKu6Gm26vjPXjoUybPCEqQok0/yLfrIKYALCTiB2MDjW2Yqo0/KIIubRIZiA0gzsyqQlOgY9nTVVObjXsSM5UFpo2u1Sc8mwCtNvhJsCpcg1Tj2BRaU0Xy2Ag3ycBpqrG+RJgK5Be+KkbzrxMybJBAIiad1USizwzwQ6CsgUS7+3NL9bk+kXygSoUQggqzDKXOU1yhTnCAN5/SEmU1/YCgjxZMgYoH6Arr5+rEDBkClEaas07uGjAjdn8ctWEvZpqxmCsmTWw3L1ueCQkhiF01wBTnofax0Vep6S0uBDADeXEHWKYVUo1KMQKIHSFibg87bfQpdJuqFF1qzScstkMUs0XBnYRbIyihDUZFCEyXZwEllztSIXhyMev3pB8h0ijTkIVHl4LtfDhWrxYR8SQARUYoSLma86GXbpaJs2cOOOHehaBlILGOg9dCOz5KvRW9C70u+jj6BPoEfTv0RfRH6M/Rc+gv0J/i/4rehb9E/opYMuXU/4CrAFb2ANEG+ECjnEV1/AUbuE2nsVLeIC34XW8C+/DB/HF+Di+FF+GX4VfjV+HX4+vwTfgG/Fb8Nvwafx2/JvAyd6B78Lvxr+F78H34wfwg/hD+CH87/An8afwo/iz+HP4j/Dj+I/xE/hL+D/hJ/HT+Bn8n/FXpTXpppPte8PBNjSA7e4O1Je5PRXU25bGtICd9uTifSM4MqxJHmwjEN0kdRcmw66MK8vF+fzsKp/P4jbs6KXBuKYfwFH424ImG00erqPM1ciThhwd8LshfzeaNvKjXmPzmFx3KJFe4PYZb/AqPBDQxrDjpgs0hoGbLQY4cIcR7IaSuVIDDFw5qIZRDzSHLH+3T4byxnJBwjY8FMDv5lNaAI/d1CXNg0E7u2kE+wbpPjglGWYPlucD8YfbhOltRHKmEu2EhDxw/QQeLi9MZtKzuyGS+7r9SDaovAbuCNAnqshFnMSgIyvYHoFmiIZSX0mlkN4QNAjrwSlyEVKocbM/QEG/HfU6TShX10byfrwpogQNgtAXWVl7oejAscCWqxeJ/rAHCkvGRPmoPwgGHT8YiFG/K4a+SD87fnMkRvIjEvIEuWmjEZyWdJoJQ6NgaSAvWeolPTH5kW534SO9Zbolr92Bln5hn7xJIBIZ4hrYSO7JtkV3OemtI39ZwJPlfJPRMrwHS3AoWEdLAn7Blzx65gvOgjvAZZ3Jjg5Pv7G/PAhGy+kJZ87G6EWcujZSZqB6Aqc+eYSaoDASQhUhVJrmGVQJUeHIHEamp4oDoLb4jTAg2x+n7MmJe2Tywvg5Agxi/JzUE6DFEODQ8YOcJJSg36cYK+MBPGAvlRNO1mWkfzdYabQX1ArdLsDoG3I5Vh1GBzw4djBqAk+WahOK8UEM9/iytM7jYzL/9TNSTY67MpdSrDLpTQCV9FyK2z2VUsTKoKEukxeZktj+5CdAW+n4x5yewukN74Bf/xGtyNuP/4ziP+I3Ags5IC7H6C1AdO+FMxgwoA141JcYhfItrDTGGwd2A4Fmu/cS9Ciunr5ZPg2hDTIHsMM8Pv59KNajmFanMDo/zfvF6G7ZKiGUDrldtFUmuMINpalR0uVmpBY9StC8XG5q/PSxI4fhqosOSsJ0vrx8H4WeIXvg5zlr8vdv3SaXBsrm6yD0Rvkh51oQEuSlrUk7a3IQpecNYWMJ3kPazS6TevzMDRA9iMfPp2w+TUDlX1KxeBBOgeNvOUaafBGnZ2nChgtpTZ5o5HVo6pBJxd8u04kETXxkss6hgHPVFHSxGmnCfrYqk/rxHkL2QouwNZYWBD0JHSLGh7EwdcrR62RyqxDjv4wN2T0edBY6+ACYN/I3bGxJ27zK0rxZusHQ1bJbPy5lQa6URJ+EK+BU9Uuc8C/Lbn6Af1DaWxHK5qCxpMwDqOD4ISGfM357HQROAfh/B8gDCsmDADmlBOEWtMzvwM3+7vpfp/jZ1MtR5mUi022exHQ99dC8CE/84G5MD2MELB7NjOcO7pW5rOMaIYq7TsgMIYZn/xiuDmRSryMvSq+ULkIiVz4Bs5UJwBKXffEbsHUJtB3+YX387WOyY44eOZwKATqwN+2s9BPwEjTb2lNy+z9kXZx+fkReis/KwVkJ+EVZuIanm3QiCLJjf1EWJrGWHv7XnJ3Ox3Mbbk8SBpxOvEn6crWYBQkMK4j0xgf2Yba8b7p/3j7E56ulFi6M/w4lew2ts6PC1YsG+xDax0SlTvBsee8r4lB2riBj6K1mFltLgzS+hbxsxkO/3ZOp/FlaJnp63+l9+9d2XrD31mRq3+lOY2lh19Li6cYiXkgaC8uP7zv9O29P2hjt27F+3+l96C+XNtITmnBs58Ir12GVq24It+dGvRF8dgRav+r2G86/4farPkvMeGyg4a23jv8cvRg/OeGOY1JMZ9u7MqAOl6VLlw1H+K63XP7Z8c/fZIzK3aAdLZJo/OdXfg45aLvaztdjq7HJPT9ADqUzPLk4s2BPczEjfsPOIFvNTKZMZ+lgcjIWcD/0kuE3Tc91FMOqaFDBXrjfs3qARZ2NVseIXMUyd+gMRZcJi2zV7JKRL0SXTM+HnnfOruDat506QUA/q+tBgAt5xVSXL9Ly/Kqjqnp27uM8fiYX5oq5am42jbhsLpTYk0s8pGtOrqJBOrE9ndzekD6yCQ7wpOmWeXEABQLcKzQaBacqFrVRUl4qw9+/+TePLC7OLS6iG8eXXT0YoI93tq2oZW/8tqXlk+gOv4S+1Fis551ktry4slhe/MjTv7/45W9fcw3eOv2T9sr4U37p4CH+SNk7OzfufHw8d0iuV9nJJreEZ/1t6fqx6cIWsknXshXIoqDdP5uNnrro2pNQSGeS9yeveJYwW66/ptm8bqt5zXF2zsSEVxd6HTVRbccIVE2VsxBML2iBReKW7lUbpeTI1kGt5U+Ho6XtVK4hrYUqGKiXTcKQMALQaSK2FYcbLGzFnDebSk2xGNZDTWEY7JFal1GXJLZVhamMmO2ipTpqXvhuuObpJmVMlM72k4BxMpXr5FZze3NvlKxOxjYqMp40SCFe4mZrLab5bm5fcrhG1Am8yVptcq2rbBnbZLJuvVy5BIl0UM3KVSDSm8jeX5WxHgm/4AkDXCH3EcVxb/LC5z7CSWiSb3mKiKlAqHjTTbNAqnu7GWvtPXHpNsZ292LVa6232+v711utdbulmobWkvNkphVdV6ZhA3TSPKjT+wg/QTlfDPM3vvx3QBcoM/U8LpY08uDNN4/n5AJuR/oLF4/M9vnLzf4Ri6OV1jn71qdQe33f2tRbdFedE6ohZnRbnxFAchzK7bPr2TP8WK6dW5MjXFLQLPcrCyllqy5FqeBwIQkxnMImaxGvZytgd8RkLQv009l8seKatlEqO4lua04Qrg7fM1qNYk9zsJ/nkVacXq+M/7pbHw3eOtyajCprehxde10U66XA9/FjTUQpV3V1zrbtqGnHVpJ3sevVzFp+RjpO83y+bOB33bqlEOEwmju9JeGMrowoZ5bnxpM8vmdBX9m5EvR+L13LTMJ2OfaasqeHvZSpy8yOZNDr/KptQMNADkBAupL3t/FJmVg7/rb8RLcHioE0pRAE/4+N3/8cbCBd+YL8MokJ15yfXvPvi63xfboyr+j46A0afBvoyI2T31t0sSDSy+ZVYyK/1+C7cgJqIWehdGAMp+suNQYskYswDXpR+hmKRvY7/cWSoHf6Ww+jm1/+3vTMkYe/dvTIw2Cq2tMzc9NHXxp/ZmYG3/XS3MzLf3nLLQ8/PPfV7g23wL+H5w6fHTObzwxzzdTn+MufyX71I79+9MjHCWr+fz8x0/F/i7+erjcrMwmkY69DIq8zzJa4Fx7YirbpNy5sBtbc5TdePqMG8ULBUxcvvwGfMGYb/WF9izH+ToLaRrM+M1NL7PHfNM/6TrcRkfvt3J9Kj07L7W9mOgAN85M0VcUP19GmOuzWstWzs4UOeqMzod5oc8mWbFpwGjKtyuVB05QXuSinnDucrjwgOWnoT9zV2VTR1DvTlY7GaFPR9rqDBTRojeSyxNmU09QpzaN0tc40JXMoXT1JbxD0wWgMpfcGHh21O/0kNXJtPvHvZM8FGeVpws3mYinSG0TmKS2p6dS5cWAk8j94cBQFYLqisPR/bfD11LPCFaKDMjDl9Dc1tIUbOJqp+wwrjOSLqjBcF4AsgFnVjJlgFmBGQSr9LmBW5sjrZcKmQTVb9bSgaAZ5UG+mpeYNlY6bFE6pNGqOcKV3SKC8rTO7bEnPpVyekzCOPgTPoVgrG6YKCMpTZSgVKZoMiMZmqW4aiqXlBej1l9HHYzMOgN8AxDanhXGvQJIwMExNBv+4XJ4e3nKmvM4dBUyP7oKWUwHK2nE5y7yW4FKT9TGxyvKaBHwqrgD+hYcZnkN4qIqCRmS8OAXl0sUF48cQCruMlFwZOKQaUrEHxV3VsExh0Yn0VwIGpPK/DDGA5Bh0AIUWBq8XBJLr7tQ8aHWkEyVU5KlyqUfBgJ8R9f9q7E3AJTmqM9GKiMyIjNyXysyqulW3tltZd19q7e7bfa/UrZZa6k1Lgxq0IWiQLSxGwoDNaonFWDIgjcVmLIaHYVjGwANsZpCREdYgWx74wPBgPJY8YAw8mAH7MTP6BpC/Lt45kVW3BfbMN7e7ttxiO3GWiHP+44WFKc6Xwyyl09Vg3nVBr9gAvjVGH7YWGvkJriMMg1FGZpD1iDQWX3hL24jOduFFH57c2lxba5L7m2t0dfLW5iZodRtnH3uUqf9/9ej0j5lrzcnt6sr7mmuTcOvira3Dm18cDk/B/17vO8NkWIYXVjFfK72PXQGaz6BwqHBp4brC8wuFcVuJS1wsB2Lvxy5DOgZSB6pU/uTDHTYcrNPusK8WGzuzFrDZlw4wEnRYwX2+QUsMYfr1YjFUmzwwF753IqiZpmVLsxqeCObLvufY9YB+2DLNWnDCb5Q9vzwfnAirprTP/061kx3oZPP5B/nQC2nn2PDQa5732u306ta7bz0ynkvrS29ZOLG6eG504DndlZMdq3LxtbccOPS81eWjZXJm9Lyl1RMLZvnoM5936MAt115csTonV7rPsbrbWXYwm3xlcTvrbnetg5ddeuBVkXd07Xlu/EdXVU1jK63293hoEfjOjdA3Lym8HjF+o9zZENeIh1OnuO40KLCXe06o2Kg4F6h7oFy5zuUSdJxS2x5ZW3WoCqhQofgtdbgDx8a59wcYGcAjUHfRN9v93EUlx/qKev027pUM8niMHFnpCZjklZZMVqnW8XVPDzVD12LQ5S3NBEJmoKHJdB0mSetwqxxxYTJd44L5bKE534APIPksdHpoaib1Ui0Iyia3A5zGeqIdN8OXzS1wziymCRbo1clnCZmroI+HaWhOfD8YTRL4CkOzDmYuqTq2gFLsSKPHM2vFYiu11lIxZlKE0nfKtbDVZst99CkADcnmiaXjVgYaaJaZMEdBcXhMW1yqlSxgSqH9PbvnRFbpIMxzgvMUsWz1G5yYR5yBOmnPkSuq5QjhFwzd9qVmz3ShIuiNr4GxK3TaOWTABhnOghxwE6ircqyo8KvcJwmY9yyzwUxizONOdls5DeGWJQhK3CCauc2p4zyGJyIHH2SKLhRRDMYXcEbxGBg079uAigfo4WiloXRlv5b6GY/MlgkauFapFD2L2iahfnGh2Gh21xLuJcKv1iNbuJ7tqoUamlAaDbvAIDWT4oaQT3Vg0daGxRye6tGhOWBzoQM6qm2DSLmnYZY60UNaRLlrFN1HFKiw3nz+/gWdcxhcxFTXokq6Wgqkx6uD0mJp3pN+6lVGB2vhvr59W3HOb5XtxVMnOoYp7r2vvR2lLjDhUHoOLQsPJAbiiZhQllvzNy8xih5u3uja6vVGdfP08tnm8aU9//c8B8hc4QqFmj5sBsgMMdYWV2qVOpfLVgWZ1VX+vVNk0RyrTu3WpL0E0bVaamsOtwWTDpyMEzw3yD1625JPPhW20n1Uazr7y9kqpYtf1LsIWMmZUwpDn2qpCHklpaxeWVwC1i7rDlgr0BhPuqaeTX5mx5VyeZ7rASP2+S9x+X2d0dtNnSyBsNA2Fhb3H1vykrKgZZQemmkFLkguu1WJ6wI3/1sgo/REYMoljbrvhrF7IaWOZ7XSqU6zTB8vvLXw4cIf5kitasMoncHMTdmC2lFCZjODnJ4abmkyQ6nAG4d5Zg4M1kly83mAi9pTLQJ0YOw72lLKCUYHceUDCoYPalI7eVIQtCmLqYr8bOPhURdKnSkoeGeC8AljFR0BzHxE3qxXkohLE1iCyYEGcUqmCCwXQDcYFN11GHHqBzS9G5Ts8u760IFDa3XXFyq0HUYCJPmhhTZqCBofrewsHSsjzBo6g2nMr6K4BpkuLGBMFMoQphG0VsE0BLEv5hsa1V3vNzkFFqQz3Edlmi610DFMSSU3yZ0N6XCmmVJwU/oMBsJYSCkROqIbMtOCIbfLa5ccu6RmcxEY1vLCXGMgdcSIw9h2GknPBA1rffNSw9YR3cPS9dras0xPJzrXiAmWDR3NgQplB8Ypy9ZFZLi83PBsHgPvMqKsjoaujkf922AwQ4YpBIAlQssN9qu6IaEqcipnAhapKKWLCpcXTqq4UuXzqVDhRRuxOoo4C/oI3IkLE+oHqPNtXDVCjHkYt05vnrhUye893QLh+OjVDzPxk7iyMOJrxw7JR+SBy9bXLzsgH8Gj5U5+9OHPfGbyvaDCvXojApOVPM9LLb1YnfPmJu8uzs11q1UyvOEGcqVt/cTZuvyAvdhuLcrhZUO52Lpw6NLP/CBu1hxzrmU7N3hz1aJupV40N1md68Ij5m64YU+fv4udmmIMFqJm3MR4G8RAfR2dP/9338SoGnLkb/6GnfyLw/CvMM3B47NxoQ7a1L7CxYWbCv+i8OvK/xk4wkCFhOaYpt22CNLeeDSLgmLZhfmCpDyeraqJWRdtYGad3Fu9j1wnnvL9foBzMOJ7s05NsO4/uZ++LPLitJGasliqRKFrGPHa5tpwvrPVfXlC5uZHlbRsmMWw3bzogBfHtTgGYYyhuz+LDDNtJkkQHen2yEJ9uLq5VnTDcM6zLmq2w6JplNPKsF6hN2L8dhxXNIS70OkHLiHJfJp6ZqgfAR5DtPNPsUp1eXNwaP/p/tLkz9u3r2xZmu83mssLrXr1/yrWivC/gfa20L91VA9MP0nq6dFksX/qwKHB5nK1TB1c2p180K3WWwvLzYbva9bWyu0v+rlbZzK1y4qgQZoY19Id6rFDmsPmt77zbXLn5Dfo0ckfkpPkVa+853d+cuZvgmv21iRCdhGMNWLr6jwbI35ZlPAxW6cIuqUCz8Gw6uwQ+vXJl4VFbyM++wumr/9XPShG+nnOXwUqPufklsAjvbPU5OS8oGJyE6gY5NvSAh4wuV0m8jNS0lv0xpRe/jm8XYVfOXulU9zKzvQ3UiDxv/Md4jz22OSzX/rSKx544E//lJw5d25yCxzs7e6S8jZZOkh2tx87uLO9vU2G2w9vY1HG1E8GMVpXCscKpwo3q/jll++tePJW7uR7ITI8ncHjo6+JjuhEymOuHas34On4lmGupnScjMa8i5JQjFsIra+iEtAbBnNLjPFEpu+Frs2+0M8BWyvWGkvPXGzUioFjOZYnTKoF8drOi55/cFCKNK0VhJM3RMXFikV+vbLUKdU6c5VOFCxE1ROdA9udE1Xzazbo6+m51tiyD5/s9U4etp3LTm/Ig3ox8q3K5GP1lTr8fyz/QEAQzw1NxzFD13OiUnmhtdI5sL6/f3R3/87o0NahI9cszW27ptvsTH60uNC8KAxHoyC6qOlHS2tzkb29bUdzJW6YppEsLDY6XXv75LazuJB1g8NXjv6b6bY6zZcn9frq/HySf0wxS/+Afg4orV44ULi28KzCewvvL3y08InCHxc+V3gUxmA/ESD+lAtH2sqjIGaJN9qjbJyHveB26jQjTR7wskOyzqCPmp5y+8nxttIL6676llpSVfkO0GtTJCrJQzx0SX0PShN5B7CgHdrLY6WRC80WKvANn9DJeumeMbi5n1z4MThE4uJwMx6O6BePW0YQBdKsLyjvXrPW3lqYNzUVldn+O11WW+WgxnR/3SQWSBiDCN8t+bQ2qcLltaDcqrq241Gv5PmcGIZGLSrXyd2XomBjrWZw4gQ10EHRX5douCPMh7CJscx1kM9ri44Vl2PLWVzDgFGeCdwBRV8kTSHrTT5ESDUslxcqlS9lYaWyUC5XCf3Eo7rDuaO72622A6a/gP+hE/mt7bs1WU3gwTr3N8bOaawLcYHn2bx9BeGYcCsBIyIIuQ2M0wXT26Kn3dHG5z9PmY2+TVT3cKdG04KNUV0j3iKnidRBYi97dm2OdC7ydBfBZbyLOqRSdfwFUMiEDgaIrWsnvBEht2JVF8pg6KjPCu4JUYMQcmHNqcDuLYRqd6AQ9esEnRQzjyIs+LCrULkDeP3dT8nzyZ88RNlzyU8ffsELHj5zNfyxt3z2+U8R7bkPP/WC177gA9dMrKtn9uQOfXjKk4qFGsr5tN/pj9tj+NS7CoJj3O10BaZjGA3o8W/1vzX5Ibx9DL98rfUaIV7Tuo1eBW+3wQ/y1s1fh38b8LWIJ+6eHi8W9vRtwozCWmEMFuy/wNKUT8AKoiqoyP9+75CK91LOEXtINokCs5phcYHAS5VvwUDZuOghDHppDSbC1F9jL548G2NQymiK1ZX2RuT7u82urK5GHvf8lU+BxkReKPRq3T84qIQWqE8LzeROt+h7puXesZNfCsZrfim99X91KdW6zX1mVi/vLG0azEen8MW2dJjpcMeSlnN7c4F9xvT80KXed7vN/fIXLwUl39XVpXc0LlwK3eWodczz9CfAxzcK+wsngJucg557ZeFu0NTfU/g3hU/nEds/l0CiRpq5SZlnd0XkyeEYYT9gxo9x+nfz79Azwxgz46bF/lYP+2+okKO5UJ6Narlv0B1m7W47weMIFpbUcedi1B0qb0j0kRhkg80Voh4HluyQqyePpyWMc9wL9JPsxkPgI1AalNQfDbp9+o/V/nB4qLs5J11rLgB5SpgDGrPgztwzskMVptHzT6JTUd0wjdqVdRtzPdUN/mO/jN98V9f0T/CER9J1uR69OHVxl7vFEGVFY1qkU1NswHnM3Ocx8wxjGFJqazAqUg91vh90X1xDc+ghTSjjoB6hy5+KMAez9h1zaUma8601p1IcrQ9391X9dlBLy71ep/yMFd8owk1k8rjRxNXFHtHvtzmvcii9/GkMC2HABigLyTVQmwjRBET8LSlZCNZ05JCG5utwKVTlEahphEsiNpNfIbgAyeEI+10WcagqGMT8KlzI8NFuMy4Bm0IjAhETL8KdaiGUOuOqubXBfJD1LwQ99J7Cu0HaPFp4vPCtwvcL/1/hfxR+UvgZ7lLFF6B0FKms0/HMSzB3NMzR76ZRN9PNX+UfraTFFKe928O1JLxlkK9757G8iH5Cc1W1izDkyoBDYxgJsz9VL9QdnZEK4hvv4SImqY4eiMqszCkZHqXPvG3z9XFV0mzJ/ILuAsIQd9XgS9RWJKdaJ5KOGGedMZDyWB3N6Mc5KKlzxYUUMY+96maN8Cwql4s08ef8FrrNESFWquVymIIB16s26ukc6FC02reiJInsctj4lA4qiyOBFJnX0KxhtezYwpWMSdc2wZ7j0dsiWd1XTxK/7JE7QRmEwbbtctOtlIMsnny4V6WUho2yk8SVhq5wavYzQaWWuOWSVxF+XZ6aPEYwwIZr9VIxtlMjbHC28AannBZ7EiNOSHE5Qvd/IUxRBsJ3jh/jZS78l2pGYGBASWefNvlv8Ca+DccdXiL3MP3QoUWqW2bJE2Xb0m2Z7Ry1Hbscb8VAmzY7mnQqwEh9q0iFlvmx1Lv1nll0hCwbTnOh6RgO0CehTq+q2bS2ZTLokIpjWW656OPuY6mX2MeCNOj6gSXeXu0x1qtzx5PBsu+FsqMLSspZbAaGjKpR2WvoMPPqQTX2gXv6ssSTTJp/y62qkxbTUHBXFkU540eDMBDeVlLxwbpmQpcctD8yNKqGKDk/K8CnFa0JtxoMxcHDZvG5h6VT6zsdB9SfGb4BWwP5hmhrC2jZBU3MEoEBtuNc1xbwWqFdtduEjrXiIXrH+XsfX4/iOPrtP3nNi1981+eal7Y3dl64OVhha+fvffLyqB31emtbZK135MiPVhfHyZ5NkYJ+bxdWcZ65F1KTd4KicFXSNFxUpQrVMRgMdxjMIZY29x3JPeNbk48RImPb8OT8nOklMWo5MigGVpO+ubGv1dh3CV543eTi6Vl0CVHXmzVyddMOw0CSvZw79Mug+x/FjAKdfHJPfcrzfapMZQPL9cHe1C4dqjhchQ41lSUggkizpwIlyR4AMrKFIUroGB0T6YNngDXBgKZmgEi8jgwi6ZUcDXQf0A4dxJVlQqW/oTA96kYzrazYkcMTy9YJCFSgfDb5inDaxbJdjJvF7hw/+OxvSW/VP/9hsCzd0vwVp2uUU0OgKwzUq9IMPMvBpzKJD7KARsEu5jVerdZ3/UYsO1EoDLBmMda6vFPLvKLkTJ/j7Lg92Vm8un4h/mBCJ3lUK+a1zbGClOOni3gnajlcIdbkW/YqGmT0c/nS6eqdULWDMP0txDqUweGgdU8ryurAoGtdDGoDrh6F6fzKytYQxMyEeSMQMGV4vf23LpWIXYyrlGD1zIEo8onBnKFds7cay/Pr1YajKZsW6GrIVskN5L3ka+S/kJ9iEkVapDWKeCFx2t+hGPcOIhy0H4EbhjHoRP15hrpAXERpnUeTImRHEc5WyV6wK3pk5KNOMY0cNB7YNyhTPJ6nGAjbbQvex8AXhU8LOpgCps29Y9sqmDv/3lJxYu3WUIXqe2rLJht2Byjt8xxzoDpQDK0CPbV1iKhY1fag3W1lCksM7tsDLRvC4WwAF2De8f4IXctxqXCHjvu4YQmFjrYx2gKRUHHfsw8W0xA0QYxDGw2VIzsmDk77al9zJ8daBn1xl+6QOu338g1Z1W7c1sQtVey6pIfu7zCt8i2SPNy0nYOcqE3X9IBySBgOetsq7fF6vqQ+XbvHxXjsBTVzVNC1CnJbJwg+MHUixrTEmK0bk4/meU/wfnSV6Q86UI5QuzJtVIjrBKo0TNHTVGHgZtixyQX8lxn4bGe29hNNl4t66QzngH6AMT1S4AWMV00UJ7jMHoEEMRA6pwwWm405LIU0tTKz4UI9xBSEFJcWMYZNUwl5KbqjZ7hrCXMq0jAUVXLHxg0c3MlBJCiGLqmYmVezmUV9mTDJMN5ex5BMgUGq8D/RjAsVqksq0POOYH0wcpLSBENETA4X6no5QfWris6Ekmsy0pW/oqa3cFMWhEDEQLOSgtsYx0rAWsR1VdzxwUTiBlcOdg7Cu2LqRWKjdz4c5K6lWxhTAJdFupj863+I5LzrSdODruGIDQ6FGRpoXWpPA9GwTOLpIB2F7awfZpGt+3qV2dFWl5ObbzAZWK26Fdr79qFt+hkOE9sWDjXLdgwiz0pAlHM/Y5PflejxSssOJZLQwzfDr2O2QJhl6L9T7KEcqpW8OUdvnTxh4If1NjOwTOl8ReBJk/5dhG6UYtoX2PSp7yC0CVgjfDWBlTpc5ZrULNB3QbmwmW4ob1LM9W4JamD4KAY5sATXwzkIXtw01knV1GAc4CeYztAZZRDWjsTsOFo5YXweSQL1Thlh76mRuFCbXxgHDYZB0RgDOxs4lc+hLDU46Apqq7SPVFVBw8iMSIJmADdVn04RUAlsXYKIslgfgr6frAyVwu31CLi5RZEslGck/BI3MzPEFCyeiYGz6A0bMBxUoFmPLYFmh60s1n0WGZ617EKhMJA8zMTkG8xIeWiCNrFIwBYmpg0UJpZQM0fyA0695GtSfi+E/lQ5fQn16x1K71/BSBEgMo+pEbIn/x0/LXMO3iwYzncJy/StD+Mpz5rKmx/QDxZuzvMUAy/AfdveWPGbIvAt3LGdrtJMbVhk0W1l07UVb1HWncJJ88gUSa2L6QMxRbsCNFC5P/tJf4u8vhFz9BZ3GPDzMPBiMGtsUfbLwtFtE3pYSN9yq4u6I+xiaODuh6FLv7Ybg0iG7naZ7URc120HpBRQr95v47R6nx5wXcPpDbZtjJ67ti6EE7px2bSEHfnAEmC6CFBdhGm4uuvNGS72oyZDJ5KgQju4M0eoLWvtHmVTXeU7LC08p3Bbno8y30VCrro70zp2Mb/VbIt0PDVK5mdIYghwkW+OTjH8ZtawckkEiabuQVer4fRo/hDaDzvj0LOGC2DG86hqRrZMAoPi/NGW58syFra3dOzmozuizhcqdnGcnVpBxD2i4nQbWyv1hU3DWJhfO/OMjbJ0QGkt29uaRm1nYxHI8I3L84FOfa8dW9AFX7DS1tLqwoquCS1cbppFYdgSsXyoOTdf9vzVZGF5t1WCyQNKQnZRoxQKreQwhSPdtAwvODDXjoEbDStNpxwtOGWzpzCgKwYCRbOr0vkgdV1mNMLIv5DrY1hAJ1sQLE2MYu033TwbrOom6EMMQ0Gx0Uzi6QWjlK3pdHJuKY3Jqzsvf++Jy1/g+pXKS05f/IbbWyL8QhCHAQbef2QVLth2XfJ1NxVLfnjZ1VG9/orTV508flsxKJ3Yr8XNoJRmfqhpe+tX9P2gk84VBgrZB1WIvRWL4ah/YQFylMb58XyRc6gA8dSIkbb6sUcX4zi/X2XKEvR9MDld0Iicfdf1ysw8tt7eKHXnNQ9zyrvzvFf2t/2l/fOMz906d2wnkPbkYyAVomNRs1daagJrMGDqpwvNo+5Vi1bInNcx5uqGxYAn8NcxW9OFLkxgKuIDr+MW5pqHsYLSX4dhVmbIQaS88XW4+KALzVCwM6/DDUVTWnDp3l4F4hv1CruYOQH9tnH+z9M0B7BtIxq8CiP26GzSd9FmAF1q/PQw3Ieke/TmUaNS6l8DhpYZq2jzt0NpZRWfIe5jl5yNyqOzm/zM2ukbT2+sw9s6bZQrpcEzemCrHrlpvBRtdtF9/u0I7+DwMohxce+azt3Lzq1zYq/jTTfA26lZrkD6fbBtkkJDrd5dXDhVOKuy7CLEFwKcIkKcUJHTQ1AKO82ZU7J4+gW6orFhEy5ox/kaXqb/3AUXDu89i7yoklGa9fHtI7a5uGjatDr5EumZtv3G8t6pyWW2ifnV8CxeY0++pu4bALfuEONLcMI+/7ht3nsvXPH9VmWn0mzCW+uqyLR3bPhvRtJ+tTqkTl4FP9VxCRe8ulXexet3y63tXUdG0kngtetcsCXuZk7h92a7K9N1uAsQLsCFFG+vkeQCvgpqh2p7ZLqKj5tOeYSU6oLR0yyN0SzDXg6flJsjCid1pIKCt3Jw45mFt04Qb2YaoMVzcUL+vedqhm0KE9Ub1ASkkK5nBSXL1WnDBclpR3Y9ti3g+FL0hCTC0O3A4GCKCylhhklQkERoxZE1DWXRpNNwXQsqIGyLMLjUMoMg1jmRvKdAvQ2mmaZueoaBd7ehRFC1HtUl5dKRvsMNzzdNz4X7LEOYGrAyWbZNUGRKQiO6YycaFu1VfcMDHU834Lwo46GysHBHgDtzvi1M3zOF78SpBO3QMLgZmcTybQO1ncB0bNBxuY3LCr7UDQO0IYs38CFtRFm5sL4eAH+aL2yhTRgFuByl4viU202Q+1Fi3niURFHu3IB9jj5QuGaFIMnt0fgJZs13yH2g5SyVdcHM+WI8uV39YleZxWYEitdj6BfYCjfuu+zEf+IRP1hZIavqjsUgZG7XNSa3E420Ek+DX4xcZ5dXimBJdlaK+5bDyCqeLTYv2uOpf8yOqzofUavp2SxxiEL3md9bIaPtTCi3dAQPS0cKNaytMhGrQ9sqTg8OkScPBwZzm7hmo620Brf2N5YkqMDFpgFKl1dePW5Kavn3YjKCKFw6JQU1vbdE8Ebu5P5lB6tL/X0LYy8l5fjZ40Yz7RzueSZj3zEsx0VdXJoRsM07uJS+icqYpLO+j9gcyIZTKiPohQiBPYGfS/fengMTuoBMtytzkb9Bpq5rSnJgPMx0P02f2Uj0iXnLk+41Kxu93ivebeqHDr78V26KuIFeSzSNbyy14tUQOCiLFvvlpebOEdsuY0ZdrXM6bRS7xUsXSzXiWvMlo2489+LLJx+Xjh86Fv3BVdsnLvmVK5oweNqnX3bdxVfH7qU+1YSeah+/8VTRN30BA87zGcPlpRedeLbf7Dr7OyZmKNAb4cHdcuqgs2h5tf8v/cj2EmX253w3ZhJ6SCr/zWZhudAvHFQYcbhb3M2Gu0SMR8MNks5ybMT/5AsY32CSM9LtjPt1Mo7IOCWPHj/+/tOUnJ5cCW+/ZCMuu/30d3LRMzfLNL2NxNn5bz1zq0zS2yY/yH6DPro26pG5udX7t+hcZe39Blxu2y+R+Uf+i5y78lk3OpMXkLev9U+fvcmFb29b2yhckH9vBJ3kHEqOC/5q8WyJd8hVmpvZIktPxbsDkxtkStDsUnV8njwtVzYS/QBGf4o2e0GN6A4yMACdMDSjcXdz3iGeDF3paWCDyqTsZ1vlVdulqGGJ4uQhfxlYFQh3+AdGLUjxuLo8CJ0wsMFiYa7pwMA4whWjxUMN9COmNns9B36SbJ8+c0uvYTmU2kagm6A1a6K+deiS+jVbXY2DtkujKJg8UnNxG0JgYgXN1VsH7KsH12x6QgoLTZpVIEIOD7/il1+sJ1boC2vWXxFbhHlxC/qmZXsI+PwCGKJSZqeLi9kuS5SryWAPZW84nT4Yta8yy+TY2CiHcX2/38L4oT7GrqgUNpw5slrN6tmrXnKkm1iWbHdW2/NH9z1weP6vg9gubw4kDzXW3oqkz/0w02IzlD7oL82dEYtw/zMOi4lmM8OYc81kjpkmK2FgHdVcaZpUeNv95WbF3TyY7bSa7W7r8vFormTEMn3LweOS0oamdxiZA2szDAzTJhz0L7+1EBd12WICrE4CuhjYfJb0Q9C9NFxnUIGRmr2ZlGdrn/+ReYUa5tVQKd6Uu2SitElXyc7ROFNOs2kOzubSWbTJaBqcpGgL5edskyFR2cNxPYlm3fUZ9WXT/FVIkDWFY4h9nZETr1s4e2Ulcq2gbOqN0j34K/TsoKJ+fTw61DDNu4NYSEt93adpZqQjzPtvwrfQ0tOih9hf0gr316Gl9/g/d2nI/5lL6XuvKbFup7K7W94a1nrBWfXrop3Kpvp1Zi4F/n2t2cgyfy6Br22MJZUSlMVnwjfhGWB+OyZuoWReJeXk/+RiwaOssDevK6ym8jkCZ0JgPIxpQu+/cTNokls+strunjm5Xkkvrx8md0zupa+vX55W1o6fWWyvn5vce8FeWS5gDqZBNpwqMsksV9Y0OdZQKUADzKqRdedZOoWZUGAtygU5J/vc+3CqcRVzpBZc06sSXKO8YB/iyl0Ov9HfA7dSu5Nqm0rlpc+RWFh3QFZRz7c1Q7MjXB5IQC+y677dc7KkbNe1qsYp5m8UoswzzdeOZlTDFGom2HugWR3ZEr6eKICJTDKmA2cNQzcCE1McvmywzGQmr9sBzSR0QOVK62AXLh+4aFPX3WrRqBpQpM942Yp0eh+ucES6xaXh2FQSPdLBcilLsyXZStKwlxBDShicV926oSdQL5uBOUT07oHlZR6ZsemHMGO43TvmzXujdVa1RdlmG/vMxDMxLmFFA/PdYNygVcl93dd61zH0ozExHoLaegWIwCqHvMrNsubrvOqAvba3v38Ve9nTciGnQXccjINOnA6jdNglb/zqV3/wzfM73yx/9av0H+78WeFOfJHCb/3kVT85/7ev+vGrLuhi19OHQOLtYGxd1I5V3AE6rPS7bdHPmdo2ifKDNQKnUaNRCE1qubc7TQk8bmM0wzhVT8C0LGq6ol0R90Eo4n0qVTbMZ1yp/fHqPUug10itw5+UHabppiw7Px6GjqBZBkQf9tJYY7Qjn6jXv2Evpu/y1jfk7R7ozsd7DHiV7d/ss2zJvMN3dXbxPml6/jny6OLiFzTbO3aHX5MgWiaPXktN37/L90163LTN0rmlx5aunivedvRoq0O1Fx1jgulLHW3YW10l+s1nTNm5kP/TLcSFrHBFvmeRqrAzZOjTyLNxEBfzYI510sbgjqlRkSa9PZs5wYwTU/6Fa9TZiDz5yc4+wTY6zGGT92xsr2cJuVE6zLImv2+b7Dho3daKBSJvabeJyHVCasyv1zuR3bCPgWrDnPU2dyYPZPt1dmCN3Ly4T0y+98nIkeRG2zTtfaeAQWkJkE59I0FHc2Zharp4baVfCml0q2DSeVr7MCLtOO7U/XxQnRoxGMQUrWCqYj7W2WCHquWzodoZdmmee5cqiCRUCybkh16x6E2K8E4W//To+KzXWerUfDMsA3N2DGH5ZikxuOuGYbEz59fmE9OTlg4aw4LHnOmdHj5l8vjm5l/91eOGMIrzaVAqwsQGjghcULOYDg2nsjifzGWOqVuOcISmuWpL/suKQT7I5gscWlYB23mrcLhwFdjON4EO9NLCXYV3FN5f+HTh/yn8oPDfiU5aZESOkGeS55JfJa8lv0M+SD5FHiOPk2+Qv6eCbtGL6c0KI+U++lb6LvqH9EH6efof6eP0G/Tb9Cf0PGgLJVZjLdZlI3aQHWbH2Al2DXsVezN7K3sne4C9l32QfYT9EXuQ/Rn7a/YN9m32lDavtbQl7TLtpPYc7UXaq7W7tN/U3qx9VPuE9m+1P9b+THtC+6b2Xd3S1/VT+hn9rP4v9XfpH9U/oX9e/5L+df1b+nf1H3EGdkyDL/Alfhk/yZ/Fb+S/zF/L7+EP8A/zj/I/5l/k/y//gWCg7riiJlbEBtiXI3GVeKb4FfFi8Vrxm+LN4j7xIfGw+HPxuPim+J/iH42K0TGWjYPGEeNy42rjJuMW4yXGq4zXGe803mv8G+MTxp8Y/8H4svF14z8b3za+b/y98WNjIkFoyrLsyLE8JC+XV8pnyXPyVnm7fKn8DfkGebf8HfmA/AP5GflF+TX5t/J78ofySfmUyXJc2K32UKALUtxuia1RX9kSmcAQu9yTN7cucFlS4S/jdMJM2iqaojscd1WMBv5EpaE9TtIYAYxHqYdg9Oh4J4r9ZJxHtKLe0BsjWrqHIF5gOGIyPKVYoEaStXdpD+uSordFq4uX4z1prsYNcQN3oI6liDY2UnYRJpPgYjDd90Lf4Rrh+TZguwVnRkqF2RwOxqIowDjCfcFWNhAxtqWX4J3j3LZStcB15XyPalRM4l4fLt/Kxlh0DI+iI6wwsJ9MoKWcTp/XbSG2osAbsW7AbDI4iuHPaYwhFO0RnMWKbw762DFCBT4m3VGSL+ZB12FEImqxKWLKTjOmjjJ1z3Dae9BE2k94EUNfMCQg7iLiTxd4Qf4UKBNBIsfpYAzNwtVfj3ahHsOxshlnELuIYrUBdkhbLZ+PhojhW1NqMmL3AntVqNKH8D92tnpHhXJza4zbxPhEeFo6HqDqHCcCcb2Au2LsZEth60wBd9GJG+mkKNoIlIX3jMbdXiza/THqm/DqoqPVCE2fLB1kfVFENIc0g+bgzuAIyssRuxDWCO7fPARH2zwbpaN0C0+BBTxGMF98Vox5NcaDMVQfXgmOGhAwLjPyNMbcj1CtrXG/KJC4VRZSuCltYzKOMfDVMYI8d7fiNtRkCFXpxwJqMqqTNjQCMy0PR91EVW8wHMdt6N+4GCMYAfzG7ylGovWQ+Fx0U2rlnY2Lmbk1D/eP+yNQuKB6/TQTKJAyhO7MUqTNKsFngYoej/vQxu5WUQwH7X4MAwoVG+EEw3K7myDdxhh8gKmVlCtyDp2MYayYlXKUgbyAlosuJsfEaVKErmpnogs9PQBLKVfs+7m6h5M6xg1Y3GZpZRyppwtdpFq6NYDxwh1jNRqxujFud3G4FOWMVbrKLowGGlV9pCsVEJchRaYx0lEXumGshghu7QqEOVbNPEj6UEYKXd+NB101UNjHGN2C+8EwzYcDZWVAq/IuBlIYx1tdnOEIi4wwp71x3OJd7BjQVcd8lIDNDNwong7TKBvnGbxQxRUKUL2bbSG9q7V0IDsgllRtHamYY7AhazhySBa4qaSC1NBswmVq1QXQJpzJ2RBHE4MCxwonRJHpGPOAjEEK46CM+jgPMBQN3QeAMHk7G6aghWC5cDPO1fZ+spNjY2/gk1tAeN0USaSOMAhpETfWR3nzx1u57wJ2y2iY7JAMwaFgCHHk4Klg343a8/QQSdXU3SXQUQPk3si6kEpwMNCtZTjowcTEYlKoklB+HWAydDd31fhm8PhUjQ/OHuUyDYx75g2gGgOdCJMZp8wWpr7pbkLnQlu7YGDAkZai8Dg3IdKReirWMcOE6eiWOewl437O9VpxOkDywnmAF3XRWzOBMVW+KGjS9OH5xRRZAAwBihB8INYlJ5UtmAADlDCILbAF4+tRHLVM9fEWdAFWADH4gQmPcQwU7DlUfrwFhQ7h0TBqPWBFHCeLOjnl10CpQBBDdJWChgInaAtQnkeiNVtoa88QwQ+RrfGoX2yNQewABcXQ0WmriKIKmQIyJaj7ACVYnK9eCIzIjbvtBH/AwMbANsbxlP1mXWjTUJlkyh8e7s9UjjVsIzDR7gAhskaIKq7aVsSaAh9rC2QWMMogdwfod5ph/Gu6mfZbdfTKgHM9gcgpiohFS/HrdhcDLIExjHkywpEfK7W53QXSxBkk4HlFJJy0jbByPZSvwCugjPYo4dAtA6RUkDhKtuTdAswDBjjNsxIUsSuBO2AEVR1FXJb2URKOBcyPGHQNlf8NrFZo5xhGothPxQCGHOHekN2misNC4cBZinhhNu4m0IJWG5HsRkOcd8hqEGlZPXA4gNanog08HhqLPGCcIZ9TGRjURzcF8Qs6Sq/PoUD8AJYFHdsbAnmhdGsjRB0Kmq0RkAjfyL2rYRa0QZbCeAF9qB0rTGGOz4DGZEqdSQXWE6rZBlofb4NdRfvYV2kfOQaOqKKZPma8Aw4ARF1MW4pU+5sqFzimAUfNAtMC95FzQqlqCnf7QHvAJrZAam0pyx+b08JJgXSFDHZzC92XhkAZCJYKZIt0HfNur4/1AaUOA2y2egrdVwzpXYQaViN0HYbLhI5raFzXNb7IuO8T39eo5IiryIjhU40tE40jbrfpKRhw22E67iZgNlhc2r0F/RqeqemWpus3I9zULxGN6tKQjuai3wQx4DYLvT6oIbmCnJIcUac0jJgAY1DD5TfiYBgg0blswxW2j9BfmPqNUoa+GmrvGZ7C1DGDmg6cqFKFFQ/lEtxAoRjm6VISQEkOQk7BJZpFEdGc5YiWFFML4zNUACDciBtCBppmTKNlXF8gQlAaK1cRhTzFMFliakA5hkZqiIylEK5xM19DULEctAyx8GOaJ1TW0XnoHNxKQWHUEB7eImrT6Qrc/ydcGYIyz+DFsDsSFagNp8wcs61LaDGHLsM47AN4Gfyw4EH4AKZA8ThzNxXwFtE1dRS9XnheN3yKqfa6tOkVHLuPTU+yKfwbPkc5KFH1U6Pk36n7dXVaU3V5NyEPkD/ChDmqjWIG0sU0n5B74FLND4Vh71de4+q/etbDZImy34Wvz8ZgTRh5heXFdAuai4hxI0KSAE6oBhaxapp2PSGfI+R3CYX7lDeWykOMjYFSH8aKwdsHSQe7XEGWqdvUGqga5ymQGXYOe4Tmp0iO/PcVsCPJ2yldxKcskrfBsc9OO+pPVJ3h9XqG6BmKRFQnMObCx2Es7QtY9xxBMIc3/6TqJYrUy0jez+jBg8OEkBQcC7qfkDfnzUYqUs9UlA/NOgpfDlHlHKKr6jOdvYPS2eCp9ANqpxJ7FGrxaQIKqELPIArHQ33o0/HE4YUWka/CnV+ZlkbJX2B34MAKEw4gQgnZIPT3CHmHOo9lqh6D2nAyrRzmPFCB/5hoFOGMp1UyVJ+gQ6eJFJB7gaiOQJc5HWHfcZZqPdIgxESnGaZPex8qbWISOi0PjYJqYwQTTngo4T/pEi7if4ZEqCqF3cjY+wj5OCL/E7yQKETmOaFmrJHCd8npH2CHY6W/RL4PjEpBlywqysZxQxr9NLZQKPA4+qBqHBzVoCvvxgxr2GbN0PI24E04uFuEfBlJCJ77W/CzNJ0vGjRK9TiSscJm1HRO/wifJ6QaX0IFTNS3Tp9GSJWQu5DjKRpJkRMqKkFfIt6kOSridKIQQV8GzFxNLWrifozExjBkAeTLJMflI1MUTHj79+gphrAOOtIm+VemmZqOjYNp8+kzmeIorAHD+0vT6UMUFoQa5DL6BqPPHNi5RKH4GYjC6OSzmiETkJ/J+wM9ChEbgYpQEf/HqRp45XkGpZ+c8RNFwRT65CQU9VlM/sByrqnjCKjCmIkezO/MxxkJYVHdT0ioKo3ZBD7HuGYyFxEkGX8CiU0xP0FWlKMbIe/fwwpkzyfMQHJ4CzaWijdgcngULoYvcZQ4sF6hsz/H+kJ/RYRcB/JBx/F+Mcl7iFrkpUTXf1v1cAZVpQsEhBdUq03eCoVICVJI4raWKDFM2KExITV04wR6lyojiR2BVMEMInrMaKtNLKBDW5jy3ehv99vQEk1QU2p6ivnhBfusmqeUODZOMWjT/RIFxZsIaeKseBaGQ6j51lGQnGRZ4SdCtZDw4JZNrCTWHZ6lb6E0o46LfS00sYvjpQvcd4WuZCsMZTXXYziFMRwthnmG0XkSiNLCWa3rNg6NqbMa8WEsXRcki8AejFlEfSxYU0OIVE4jjD5EgVrF+GYCWiXlknEpFHv1WO67qBGPEWGgkMUUHMIFya/NlSgmcqBFTPLgOcDoiZn4NhAD9InMIqiQVm9gAgY/ifFxGbIgTMsCTxFxikQAjZe1QIYeVApmdH8JSFRRArftqIi814pt6au5qElqwjM0xQkEDWqigTPYKVous3EmmMwINC+UMGXhknqlZGtGTu7C8VwtwlQ6OF0FFTa1mecIDdmkxoGKkJCZVH1jIaeH7rWh/2WRADW66BCr4+QlJOedyB8kkjwji0DsWtVNA2RvTFrYPhXKZAjESBK+EmgK6YijpKBcGDB7DPQKRnAl6AvsCI0L5GLExhwqWBsSpG5V00wBY2CGsgNdROdXDbdrYpYcaXqS+y7XGYaMawZCuUhp6gbSkMQCOEk1VMKUuLNAv9BdofMSQ0IEXcqx/aZvBMQ3OpnhAcNYFq5YhMHDjOmCl4GQTI9j0KkLJMdwhgmJGQouyzpwp40uq7SluBvc7HmXgejQ1PznoG62uGdCAw0YX/SihY4v6ZoEdsKRVJlKXaohSB+Gteqm0rTQ+Zk484ja77nmfAuHwcYRQq1NM5EZAWcXQEQexY1szRI2cFTkJlBpE92wmWnEVHMN4QJjhqeipDFQUmrowqs4sVtkU1nkMZiLFAFe0eUbkxxxUGENVWclkHQO7ECHjqQqZZphYdYSzbKIwiLHeSIszi1OmedCVxED979wjkid+R5GiBDicwSToRKOBoHSzTBID+QjEy5GkBhEzCPMOc5w1PCQS+AgCEMTUqemyvtEuCpHaXz43zDhXvRI9kAgM821ObJzWoFeiVzMKgI0zr3YRErSHCBM2zKw+xxToXNBk4qqWQZdgBJ0iX59Fk4qifnIUW/VbBh6FjKPIyI8dgNQqcGVhoiaqI4PgnkFk9LgmnCAJEsWcA/CXNSTMfUyz1l8ztQkDJIdGQEUQK0yDIqDKCEwJgiNpkFlLKMIUg1memSj+xWmBGLKXYGYDpAugSOYs0koUaYYRxH6DhiJruQXIoPpIpeIMJhwJfARpvJJKSmmRoajm4JtK66Sa9U4ygZFX36GfucB/uIIOI2OXsp4wOlvODCowuW5HUERmhoZLJIua1BhQG9SlTQHNWdUOJR3PnpbWCgGDCXdgeNidgB4EHAo0igaVgADXFQKAU4lKTARJqqByvQAVVNYutLnYR7pLK+v0p2R+BRaNnSHxkMF3YIFI8FxbhrARyVaTTjLQRmjhkphZaLcthIPtSUHyAVhoJgNrF3XPMx/o8/NBUA1ujItBKggGpG5EefhrIZ2g5pGfLgYpxQya4GyBnMKMxhOGzGrCcwNdILGiCmQRUTNcq7mNcxAkLOuMIAqgN0LVJqgiroKSlC4djKChqcxlgoH4FEUE4/ZoBU6XJkx6GZFsCHIi6iyEijaRRi8oZImK5tQxx7UFVsnUYhZOgyQ1oYCzAL6hDJdD7gK9ihKSlRwMTka9KsNreKIbqfhHLWJYRseuo4RlBnUoipYXg2Whj2vK4gotJ0E6pu6aSNllgwCzVcQ25oJHEJzUYNF/Ci8lSulSYFh45DpKu4DiVBZh5jgHOFfUZFGmUrUhaDZajYRvqqYSbA7dYQmR1u3ThpooRqokdNcXcsV5Zn5MPuZv1FtamGggm6ZpelFeVonzxA2NBxThOdNc7GzQCNiurLJUHsDAQytA0nFcwMSaY+oBQD1cHRcRPpSaZeUDarED51pzxI1ToUFrWzeX/zb87lYoH9YMNCXmLQD+Ddsxulgz0dUZSfC+Pi28sfIUdnypIxTb6FxX7lo9MYj8v0XnrqV1J80BLeNonFx1lrqvHKxc0yaxYONyPDtyqGLojDbOby0oR1P5HzQAhXu1yaPkJ39+79h+SABmMGiam1lo1ptNzfdoumVktDlXDfC8Vapa1cbnWEDbeRolgv9SdYvbBdOFm4u/Grhbtx/2wOZ8sjUuSuHx5inGBSmvJh6ex6NeyHLfeV/iQEBs7hF7IDiHsDJeJRvlGM2sWm4gMIARI8oOLKRoxPlDoa4tk8ri5k3B1IEiMXm4WJq+DWHIVo9FXPtCjX9sBkgECR1VrKNTvbKZbeSrZwu2364pB/qZLEvFqwwLMZerPPVRDNEIEzg2mYHweteDYSsh9aczmLXl/a1XAcBFZVdy3UNpfXTs1I4pTg1LW4Kr+Lp6C8JempguIksRo4tbcxLrrv2oNvUdHfjzo2r5xehQtcdb0WmVlrdsiPTA5vRjY6vzUtNCDPM6m0TRLA85hlwO5NJK/GKTpCeM20Xm7USWSEHZcABFUyaM9rymFuICvOIAj5zKFU9qaIzWNDfJZuY53lAnjzx2qxLyYndw6dO3NXJKDm5e/H/zc4z9qGz9ImTFx85dfw1Cxl+XvEbCxl5bPKvP8zu2Ee1md/0V9mSytetoEZxWwCXtJ/2GY0QygQXCDP6zv/JiSe0S0CCob65Ap8NCkbGY8CQLwXNYB2m1OIWET/TOfGJ0M7BMQeY9AOY54fcC+IZf71HN6Zt/D1m53m0SdQW3XbTIm3Q08++58zx42fIzY88chc5Av9+Qoqvfe3k4+TK81+hGz+HGycLpUJDxRUHzaCtEl2zfjrG/6KNC9Jt+N7utuGzLfpP0N7ji+vd/VkV/7KNZlV3zOZ/2LexbG7I5StNd5r6Oe1208ljvwJ/D72istN66KGNjbdfuucXs0M/XrALRSi5QLqiPSsP80H04Vu/C2/kA7s7u6cOr+7s7qwePk3MV5886d/gn/5UqV4i+596ivzaE/A3uZv82uTuG2544E1vmvmaEhUr/fP4RGpshuM0ELGeDrsiSGPWicUaAcOkO6yT8VB0x6mg//DUA3fcONk5/8BLbjxD2AfII5PzH3j4gQfKDzzw4Xc/8AA5fu/tZ5fI6vCRo7MvxLz/hc/uwWvyn898+Lrfh9cdZ85cB9XIY16vYDtQg43C5cAhXlm4v/CRwqOFvy08hX6jU9fPGQxuH/kDDP0UTgd9wZBaZv5bequtgC2F8rTv51g5SM5Z2prFmWD2rB2KUaiYqUTtbsR7+Lz9BKh/iDxVVwB/ce6Phu+jaUbzKfpBN+PKXU05JWPpuCitQq0Vz03UNpeCOEg392PmyHmKqZem7v25Y3/+pCIut+8BA49U8iby96DOrCcdzNwgfC0l4yrV72E6Biwy7QWJi2s5plHVWhGwq6GmOaciv4oqIKhupmVU9WY5dGhJggbI4ojHpNe+fL2GckZfKi2e/8t87dCRYQl0VcnKNdn2gyuOkKfcGxJQWIzAXhfjlm9pVg2RbL4nQntZjDuxS0sX+05FNw65KrHnYZCChrLlQIMvbvt2RC6yrJeV+Fq1iEB2MdgjqIeBxDBaX60la7UALcnR3GbJQCsGF8TIPNsBczGoV0HrlqxUNmrtuZNb88ZdleORV9VEA/RsYlielYn1RuxGyhrhL0wd0Cg8Ew5WVVwkNMlNRZ0sB6lnwdP1tld5Dsp1yoeVtUCph8gkdtulpIcxAUQaQnNZ4LtQ6rHQK5PLdc1hISgkurNsGTYwiAg0LZ0lqHiFzqaxPwMmHW7ZZqwbz/DM4qFsp1tCPbY3t16DLuDUs5h1E2E7i2UT1xdpyEHdZem87BC6h1OwfsFvLhrHIo27Q9IJHMI63Yd+Bn9AcVdPPkauIfBGv97+MZn7cfvrJNma/BVtTP5646cXfOfWWLewVXhN4bPoNYwxIBhG03anwBp8hQTzCLGeKGR53NbpYWR7kPZ0JUKLbRCM6EA1jXPGjVuM/caYwxbmFcPwExUVAXdh6juVTAj3sHbYLhngjlCLd4pbw0ABBs8SHSkXvtE0KAWO/S9OqSqNe2zNtb67ApqttWqtRKvlo3Wb2b0ypjesb8ikSuh3EOWTkcmHqrg0hV6wPFIZsuAmFuHuQBksxNCBwe4wNNkwiRerawikSDFCmdCyj8rl4R88+Ek0Rz714L9F/Qy+578/mf9+kNDvAkW+/irT25ejioL1wCeeSgxmYjauoVLBJSMvZKuvsMsY76d0PnPRtHsOc9iNzFfZS84N9URnxaXNMgj16FSEivHZDeb00g1U4/mrCZls74O21SipthBYFZ7SqKpY6Gqmfm8AHc7w3dZYrbBZOFa4F/jjOwq/V3hP4X2YEQNDVVZIjIMncKyCHuLJTjnJDkOYRgSin/lI/uKrM1CQB5hftd0C1tZCj5Z1xc8QJSBWm50KWBxxE3qDHHd4MM75IsX0b/15QuL2MBj2gYj78RC+43YfW9NM70d6olkbpV4ZG80TDj06t2aXQsNoB9ZGuuGw/2H6tPTjM+rv2mvPnPnx5N8Ram1YjQ7zOXAwUo5gTKtoIXPH3DDjyGQRPIlFCJ+NZqHhOmht1TEAqH1z/kcfnVwL2ra/g5NfsnzwUMv/ItyMK1FgZOGQ0m0HWE42jOBfAq/ONvT72YTvYCYgQoeroPlfgvs58Y0sWmxjVTAvTaJHGubVsajfmMcQc0YOD4eT3x8O7x8O7xwO3z4c7sXsfI5+tuAUqoiBT1B1FW2EBWlnpK0CuNS06Kk0uhjbMOolZOO2m559K7uKrV57YN/FjDhXmdHlB7iv0ZtOXv+u5kadNjea9CF6YPzg8w+/6Po0qU4+1Nt/2ALBcGr3mkvTZqNUajb3YtX+kf6o8FLQ7HI/bdSK0RqAyQwfI5VDdxpY0525uKvwTMwhj5+5qpwDFIvcex4192SW/ANj0pQPppK6uV9aroz3RuTXjHy3TVRS7sDABbptpBQsz8hPYAwChYmjIXy5qG+ALeyamBdWYiwyGKilMS4raDFMeTDzjPacEZqeJ01H+kvXHgT7UBi6ZRoHG6ETarrHjCeBz3JbS32dmyGYi15jKwUNulWeL8UOKONxzTBBHAlq6Q3E6jDBZrSKjgFWOXfOXcscAxT2XrXdAqlrhZqFBr1uC1c3dn0N1whVZmsOWvfTcs6eZVXQn2p5jMsKGYVjhPafBhak6KWCeUATmhiO1PYB5XZWFERM6OieQbODW5Rmh1fImylon+YREBei9/xLlq99W2VJa5ZrmTaPOisQ0xYrQYk2SIwQdKWK0tYy4Ah91Nm6Y48oL+d2EIlulAqY981xlB8fSrDG4dw4aO8iI94lLBXkV49nd4zicmet1bvrdPOvy7985XcnX7jyqStrtx1xvgsa3S99kbzzg9rxuz5/AC5ayo7E5+hD128319e/Fl9G3jT5y+vXyY0HWtdf35s8df0oy0bXw8HSc8gPj8fPmbykt/yX2YHJX+7WsOqxqv+NIPOermlewKbfBqv2SOGywvHC6cI1hWsVplWhM0uwMfUNJv2gHf2zLOzCi/1vzgXTV5qhGdhSQbdcBeZ32611mJlb4x4MFjs1KQrDEOSHXBqTnxaL+qFf+Bvu/JO/11OMX6wOazpBkkniw3FynHohiTzqRST8jOT0Gi4lP/9RLumLJ68nz4+V1wy8UuVtQrbUl3R6mByNJw8W3xQulJkJf6y8ELoBIcGKk+K6cur8//yHl/t4nGNgZGBgAOIgy8O98fw2Xxm4mV8ARRieanpcRaaZLzP3AykOBiYQDwAwwgo7AAB4nGNgZGBgfsEABCwbQCTzZQZGBlSwCAA+7wMaeJxjYGBgYH5BPcyygTI9pOjHp5Ylm7r+QreXkDvJCQd6hjnN8CfS3QNSDwD7GZE0AAAAAAByARQBLgGQAjgDJgM8A4QFMgVsBd4GBgaOBxIHVgeQCHYJDgmiCdwKSgraC8wMLgxMDHYMpgzgDWINhA3EDkoOag76D5gP1A/yEDoQrhDkEQwRMhF+EaARuBHyEzgTUhPEFEgU6BUYF2IYFhjqGYoaOBriG9QcXhysHWYdqB4MHkwegh6eHrofPB++H/AgbCDMIY4huiIOJKwmGCamJuYnAicgKFgpsC2CLbAt6i4ELiQucC7GL0Qv2jBCMKQw3jEWMUQymjLuM4A0YDUoNa42tDcsN0Y4CjgkOF44ljlUOn46qDrgO3o8jj4YPk4+lD8mP3pCXkLqQ5ZD3kRgRLxFTEYuRohG7Ed4R+BIeEkSScxJ7krQSvRLfkvuTFpahlrkW7Rb6FwmXERcgFyuXPRebF6SX4ZgYmCiYVJhhmHmYpAAAHicY2BkYGBYxMXCcJ4BBJiAmAsIGRj+g/kMAC1hApYAeJxdkL1OwzAUhU/atEArARISI7IYWJDSn7EP0E4sHTKTpnaaKomjxK3UhZGnYORZeCgmjsOlA76K73c/n1hKANziCwH8ChB2u189XHD65T5pLByyboQHtHfCQ/oH4RGe8SjsEy+8IQivaC7xKtzDNXbCffqjcEh+Ex7gHu/CQ/oP4RFifAqP8YTvVrt8rbNDkTQe/RPrps1tpWbR1I8rXekmcXqrNifVHrO5c0aZxpZqaSuni8KqurF7nbpo51y9mEyM+Ci1JVpoOORYs2c4oECC5mz/eszubQ6LCgozRJieT1fsVZdIOGtsmdjgxL3l12eY0zoYzoYZi5K07G7y6YJlaerubE+T0kf8h/6tGgtMWOZfPmKKN/0ANjRQxwAAeJxtU/Wb3DYQvXfG27s0acrM3CukjCkzpoxXWRrb2pUlRZIXrszMzG36j1a+TfpT9X16MwKPZ948rayuLMdo5f/HIawiQYoMOQqUWMMI69jALhyF3diDo7EXx+BYHIfjcQJOxEk4GafgVJyG03EGzsRZOBvn4Fych/NxAS7ERbgYl+BSbOIyXI4rcCX24SpcjWtwLa7D9bgBN+Im3IxbcCv24zbcjjtwJ+7C3bgH9+I+3I8H8CAewsN4BI/iMTyOA3gCT+IpPI1n8Cyew/N4AS/iJbyMLbwChgocAoQaDVpIjDGBQgcNA4uDcPAI6DHFDHMssI1X8Rpexxt4E2/hbbyDd/Ee3scH+BAf4WN8gk/xGT7HF/gSX+FrfINv8R2+xw/4ET/hZ/yCX/Ebfscf+BN/4W8cwj8rOJAxaxUVzDXCzHTCfJexXkiTVawiFXF7QMnJZpWZkUsqrwq+6VvmLHjK2YTKAbZsa/fylvikMvPNXu+4JMojWykf+3nGleGTIuK4d7TBjaBNrmTHAq3vLDwxx9sRN0rUvZdG59zoWjYJt7bgbuEDU3sO2y3qKhKCRMK9j3O6ynuIVDAXVkVVCKpZr8JuQdYRZyEG2+TG5iJmQG6DhAzGHY5OY5+TknPpdi3NludO2pCQ6jJyzricvJI6lBRactR3Rb2koKjZVMYoZS0dVcxTMTi1med1rIFcWhsdkkaGPM62rwajWLXamKQx+7LGCBOPHBOKBiOVL6Kx7UGVNa7XIW16ZcuW8Yliuklb1qlRG1tGWurGFy3zE1Iq7s8pj5mZSZ+0NE/b0KlCNto4EutSqd4Hx2K9WeS6oVTq2mSREMnTMRMUYcpGAyzLLsakJ1L7bCz1mKVjb3Q27pVk2YS5juUTEyIZhYqq0J5yJQ/2UoyUnNLy+3TocqJ6VnZRGbVUFB03GQSWdWxKOumEKbuYFIvyKDXNNodLiZZdqU2gyphJom23HufW4SpK3etxzyc+MzySkBnBAkutECqxok4tObVmWxOMb41NohhLK21spqbURupGEUJtXCfNyA469m3kLbdO+o4V1pkx8RCXRpkmsX2T2z6SHEY26nRZVG4XoY1E7DQpc8R4KCNGbjpV/ncpBlC9TV1fLSL4MPJMkY8/5pR6FnXqq5B5zhTLl1ovPYUw9DLbySiNMuvymJMLi9zH9HSz5sNCDZWEfPB6X/i+irco91NSgRI/bTI/k3VYC1GrbKgyCVEEIYqrDH6p8TTMZDMKC3ukR9OYQzaVgkw6lTHKtKd0Fp9/MmOhmFFlo+aSWRN9qWPnfDozTiRz5ZN5p9IFczpZdCrZjs9nW9qVlX8BmxzAsAAA') format('woff'); font-weight: normal; font-style: normal; font-display: block; }
        .file-type-icon { font-family: 'Embedded Seti' !important; font-size: 24px; font-style: normal; font-weight: normal; line-height: 1; width: 20px; height: 20px; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; color: var(--file-icon-color, #9da5b4); }
        :root[data-workspace-theme="github"] .file-type-icon, :root[data-workspace-theme="tomorrow"] .file-type-icon, :root[data-workspace-theme="kuroir"] .file-type-icon { color: var(--file-icon-light-color, #57606a); }
        .file-type-icon img { width: 20px; height: 20px; object-fit: contain; display: block; }
        .file-type-icon.folder-type-icon { color: var(--text-secondary); }
        .folder-type-icon svg { width: 16px; height: 16px; }
        .workspace-tab button[role="tab"] { display: inline-flex; align-items: center; gap: 6px; }
    </style>

    <?= $workspaceThemeScript ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pocket Code Studio</title>
    <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTQiIGZpbGw9IiMyMTI1MmIiLz48cGF0aCBkPSJtMjMgMjAtMTIgMTIgMTIgMTJtMTgtMjQgMTIgMTItMTIgMTJtLTYtMjgtNiAzMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNjFhZmVmIiBzdHJva2Utd2lkdGg9IjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==" type="image/svg+xml">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/coolalertjs@latest/dist/coolalert.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"></script>
    <style>
        /* ── Design Tokens ───────────────────────────────────────── */
        :root {
            --bg-deep: #0f1117;
            --bg-main: #1a1d2e;
            --bg-surface: #1e2235;
            --bg-elevated: #242840;
            --bg-hover: rgba(255, 255, 255, 0.04);
            --bg-selected: var(--bg-selected);

            --border-subtle: rgba(255, 255, 255, 0.06);
            --border-default: rgba(255, 255, 255, 0.10);
            --border-accent: #3b82f6;

            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --text-link: #60a5fa;
            --text-link-hover: #93c5fd;

            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
            --accent-warning: #f59e0b;

            --folder-color: #fbbf24;

            --radius-sm: 4px;
            --radius-md: 6px;
            --radius-lg: 8px;

            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);
            --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.5);
            --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);

            --font-size: <?= $config["font_size"] ?>;
            --font-mono: 'Fira Code', 'Cascadia Code', 'Courier New', monospace;
        }

        /* ── Reset & Base ────────────────────────────────────────── */
        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        html,
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: var(--font-size);
            background-color: var(--bg-deep);
            color: var(--text-primary);
            height: 100%;
            margin: 0;
            overflow: hidden;
        }

        ::-webkit-scrollbar {
            width: 5px;
            height: 5px;
        }

        ::-webkit-scrollbar-track {
            background: transparent;
        }

        ::-webkit-scrollbar-thumb {
            background: var(--bg-elevated);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent);
        }

        /* ── Top Header ──────────────────────────────────────────── */
        .top-header {
            background: var(--bg-main);
            border-bottom: 1px solid var(--border-subtle);
            padding: 7px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 46px;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .main-toolbar .brand img {
            display: block;
        }

        .search-container {
            max-width: 280px;
        }

        .search-container .input-group .form-control {
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            color: var(--text-primary);
            font-size: 0.8rem;
            border-radius: var(--radius-sm) 0 0 var(--radius-sm);
        }

        .search-container .input-group .form-control:focus {
            background: var(--bg-elevated);
            border-color: var(--accent);
            color: var(--text-primary);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
        }

        .search-container .input-group .form-control::placeholder {
            color: var(--text-muted);
        }

        .btn-search {
            background: var(--accent);
            border: none;
            color: #fff;
            font-size: 0.8rem;
            padding: 4px 10px;
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            cursor: pointer;
            transition: background 0.15s;
        }

        .btn-search:hover {
            background: var(--accent-hover);
            color: #fff;
        }

        .btn-settings {
            background: transparent;
            border: 1px solid var(--border-default);
            color: var(--text-secondary);
            font-size: 0.8rem;
            padding: 4px 10px;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .btn-settings:hover {
            border-color: var(--accent);
            color: var(--text-link);
            background: var(--bg-selected);
        }

        /* ── Main Toolbar ────────────────────────────────────────── */
        .main-toolbar {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 2px 10px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 2px;
            min-height: 30px;
        }

        .header-btns {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            text-decoration: none;
            font-size: 0.78rem;
            color: var(--text-secondary);
            padding: 4px 8px;
            border-radius: var(--radius-sm);
            transition: all 0.15s;
            white-space: nowrap;
            border: 1px solid transparent;
        }

        .header-btns i {
            font-size: 0.72rem;
        }

        .header-btns:hover {
            color: var(--text-link);
            background: var(--bg-selected);
            border-color: rgba(59, 130, 246, 0.2);
        }

        .header-btns.disabled {
            color: var(--text-muted) !important;
            pointer-events: none;
            opacity: 0.45;
        }

        .toolbar-divider {
            width: 1px;
            height: 18px;
            background: var(--border-subtle);
            margin: 0 4px;
        }

        /* ── Progress Bar ────────────────────────────────────────── */
        .progress {
            height: 18px;
            border-radius: var(--radius-sm);
            display: none;
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            overflow: hidden;
        }

        .progress-bar {
            transition: width 0.3s ease;
            font-size: 0.7rem;
            font-weight: 600;
            line-height: 18px;
            text-align: center;
            color: #fff;
            white-space: nowrap;
            background: linear-gradient(90deg, var(--accent-success), #059669);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        }

        /* ── Layout Shell ────────────────────────────────────────── */
        .fm-layout {
            display: flex;
            height: calc(100vh - 84px);
            /* header + toolbar */
            overflow: hidden;
        }

        /* ── Sidebar ─────────────────────────────────────────────── */
        .sidebar {
            width: var(--sidebar-width, 220px);
            min-width: 0;
            flex-shrink: 0;
            background: var(--bg-main);
            border-right: 1px solid var(--border-subtle);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .sidebar-resizer { width: 5px; flex-shrink: 0; cursor: col-resize; touch-action: none; background: var(--bg-main); outline: none; }
        .sidebar-resizer:hover, .sidebar-resizer:focus-visible, body.resizing-sidebar .sidebar-resizer { background: var(--accent); }
        body.resizing-sidebar { cursor: col-resize; user-select: none; }
        body.resizing-sidebar iframe { pointer-events: none; }
        .sidebar-path-bar {
            padding: 8px 10px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            gap: 4px;
        }

        .sidebar-path-bar .form-control {
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            color: var(--text-primary);
            font-size: 0.75rem;
            padding: 3px 7px;
            border-radius: var(--radius-sm) 0 0 var(--radius-sm);
            min-width: 0;
        }

        .sidebar-path-bar .form-control:focus {
            background: var(--bg-elevated);
            border-color: var(--accent);
            color: var(--text-primary);
            box-shadow: none;
            outline: none;
        }

        .sidebar-path-bar .form-control::placeholder {
            color: var(--text-muted);
        }

        .sidebar-path-bar .btn-icon {
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            color: var(--text-secondary);
            padding: 3px 8px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.15s;
            white-space: nowrap;
        }

        .sidebar-path-bar .btn-icon:first-child {
            border-radius: var(--radius-sm) 0 0 var(--radius-sm);
            border-right: none;
        }

        .sidebar-path-bar .btn-icon:last-child {
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
        }

        .sidebar-path-bar .btn-icon:hover {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        .collapse-all-btn {
            font-size: 0.72rem;
            color: var(--text-muted);
            text-align: center;
            padding: 4px;
            cursor: pointer;
            border-bottom: 1px solid var(--border-subtle);
            transition: color 0.15s;
            letter-spacing: 0.03em;
        }

        .collapse-all-btn:hover {
            color: var(--text-link);
        }

        .tree-scroll {
            overflow-y: auto;
            flex: 1;
            padding: 6px 0;
        }

        /* ── File Tree ───────────────────────────────────────────── */
        .file-tree {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .file-tree li {
            margin: 0;
        }

        .tree-name { overflow: hidden; text-overflow: ellipsis; }
        .tree-loading { display: flex; align-items: center; gap: 6px; padding: 3px 10px; font-size: 0.8rem; line-height: 20px; color: var(--text-muted); }
        .tree-loading-spinner { width: 12px; height: 12px; flex-shrink: 0; border: 2px solid var(--border-default); border-top-color: var(--accent); border-radius: 50%; animation: tree-loading-spin 0.8s linear infinite; }
        @keyframes tree-loading-spin { to { transform: rotate(360deg); } }
        @media (prefers-reduced-motion: reduce) { .tree-loading-spinner { animation: none; } }
        .tree-message { padding: 4px 10px; color: var(--text-muted); font-size: 0.75rem; }
        .tree-file { padding-left: 25px !important; }
        .file-tree .folder-item {
            display: flex;
            width: 100%;
            border: 0;
            background: transparent;
            text-align: left;
            align-items: center;
            gap: 5px;
            padding: 3px 10px;
            font-size: 0.8rem;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 0;
            transition: all 0.12s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .file-tree .folder-item:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .file-tree .folder-item.active {
            background: var(--bg-selected);
            color: var(--text-link);
            border-left: 2px solid var(--accent);
        }

        .file-tree .folder-item .fa-folder {
            color: var(--folder-color);
            font-size: 0.75rem;
        }

        .file-tree .folder-item .caret {
            font-size: 0.6rem;
            color: var(--text-muted);
            transition: transform 0.15s;
            min-width: 10px;
        }

        .file-tree .folder-item .caret.expanded {
            transform: rotate(90deg);
        }

        .file-tree .nested {
            display: none;
            padding-left: 16px;
        }

        .file-tree .nested.active {
            display: block;
        }

        body { display: flex; flex-direction: column; }
        .main-toolbar { flex-shrink: 0; }
        .main-toolbar { flex-wrap: nowrap; }
        .toolbar-actions { display: flex; align-items: center; gap: 2px; flex: 1; min-width: 0; overflow: visible; }
        .toolbar-actions > * { flex-shrink: 0; }
        .toolbar-actions .header-btns { padding: 4px 5px; font-size: 0.74rem; }
        .toolbar-utilities { margin-left: auto; padding-left: 8px; flex-shrink: 0; }
        .toolbar-utilities .search-container { width: 160px; }
        .toolbar-utilities #workspace-theme { height: 25px; padding: 1px 6px; font-size: 0.75rem; }
        .toolbar-utilities .input-group .form-control { height: 25px; min-height: 25px; padding: 1px 7px; font-size: 0.75rem; }
        .toolbar-utilities .btn-search { height: 25px; padding: 1px 8px; font-size: 0.75rem; }
        #workspace-theme { max-width: 130px; background: var(--bg-elevated); color: var(--text-primary); }
        .menu-heading { background: transparent; border: 0; border-radius: 4px; padding: 3px 8px; color: var(--text-primary); font-size: 0.78rem; }
        .menu-heading:hover, .menu-heading[aria-expanded="true"] { background: var(--bg-hover); }
        .menu-shortcut { margin-left: auto; padding-left: 20px; font-size: 0.7rem; color: var(--text-muted); }
        .editor-menu-action:disabled { opacity: 0.45; cursor: default; }
        .toolbar-more .dropdown-divider { border-color: var(--border-subtle); }
        .toolbar-more .dropdown-menu { background: var(--bg-main); border-color: var(--border-default); padding: 5px; min-width: 160px; box-shadow: var(--shadow-md); }
        .toolbar-more .dropdown-menu .header-btns {
            appearance: none; -webkit-appearance: none; display: flex; width: 100%; padding: 7px 10px;
            background: transparent; background-image: none; border: 0; box-shadow: none;
            text-align: left; font: inherit; font-size: 0.78rem; color: var(--text-secondary);
        }
        .toolbar-more .dropdown-menu .header-btns:not(:disabled):not(.disabled):hover,
        .toolbar-more .dropdown-menu .header-btns:not(:disabled):not(.disabled):focus-visible {
            background: var(--bg-hover); color: var(--text-primary);
        }
        .toolbar-more .dropdown-menu .header-btns:disabled,
        .toolbar-more .dropdown-menu .header-btns.disabled { background: transparent; opacity: 0.45; color: var(--text-muted); }
        @media (max-width: 900px) { .toolbar-actions .action-label { display: none; } .toolbar-actions .header-btns { padding: 6px 8px; } }
        @media (max-width: 550px) { .main-toolbar { flex-wrap: wrap; } .toolbar-utilities { padding-left: 0; } .toolbar-utilities .search-container { width: 120px; } }
        #workspace-theme option { background: var(--bg-elevated); color: var(--text-primary); }
        .fm-layout { flex: 1; min-height: 0; height: auto; }
        /* Internal editor tabs */
        .workspace { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        .workspace-tabs { display: flex; flex-shrink: 0; overflow-x: auto; background: var(--bg-main); border-bottom: 1px solid var(--border-subtle); }
        .workspace-tab { display: flex; align-items: center; flex-shrink: 0; border-right: 1px solid var(--border-subtle); border-top: 2px solid transparent; }
        .workspace-tab.active { background: var(--bg-deep); border-top-color: var(--accent); }
        .workspace-tab button { border: 0; background: transparent; color: var(--text-secondary); cursor: pointer; padding: 9px 12px; font-size: 0.8rem; white-space: nowrap; }
        .workspace-tab.active button { color: var(--text-primary); }
        .workspace-tab .tab-close { padding: 5px 8px; margin-right: 4px; border-radius: 4px; }
        .workspace-tab .tab-close:hover { background: var(--bg-elevated); }
        .tab-dirty { color: var(--accent); margin-left: 6px; }
        .workspace-panels { flex: 1; min-height: 0; display: flex; }
        .editor-panel { flex: 1; min-width: 0; border: 0; background: var(--bg-deep); }
        .workspace-panels > [hidden] { display: none !important; }
        /* ── Main Content Area ───────────────────────────────────── */
        .main-content {
            flex: 1;
            background: var(--bg-deep);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* ── Navigation Bar ──────────────────────────────────────── */
        .navigation-bar {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 5px 12px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 2px;
        }

        .nav-links {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            text-decoration: none;
            font-size: 0.78rem;
            color: var(--text-secondary);
            padding: 3px 8px;
            border-radius: var(--radius-sm);
            transition: all 0.15s;
            white-space: nowrap;
        }

        .nav-links i {
            font-size: 0.72rem;
        }

        .nav-links:hover {
            color: var(--text-link);
            background: var(--bg-selected);
        }

        .nav-links.disabled {
            color: var(--text-muted) !important;
            pointer-events: none;
            opacity: 0.45;
        }

        .git-status-badge { margin-left: 8px; font-size: 0.7rem; font-weight: 600; color: var(--text-link); }
        /* Match the editor scrollbar in the file list and explorer. */
        .file-table-wrap, .tree-scroll {
            scrollbar-width: thin;
            scrollbar-color: var(--scrollbar-gold) var(--bg-main);
        }
        .file-table-wrap::-webkit-scrollbar, .tree-scroll::-webkit-scrollbar { width: 10px; height: 10px; }
        .file-table-wrap::-webkit-scrollbar-track, .tree-scroll::-webkit-scrollbar-track { background: var(--bg-main); }
        .file-table-wrap::-webkit-scrollbar-thumb, .tree-scroll::-webkit-scrollbar-thumb {
            background: var(--scrollbar-gold);
            border: 2px solid var(--bg-main);
            border-radius: 5px;
        }
        .file-table-wrap::-webkit-scrollbar-thumb:hover, .tree-scroll::-webkit-scrollbar-thumb:hover { background: var(--scrollbar-gold-hover); }
        .file-table-wrap::-webkit-scrollbar-corner, .tree-scroll::-webkit-scrollbar-corner { background: var(--bg-main); }

        /* ── File Table ──────────────────────────────────────────── */
        .file-table-wrap {
            flex: 1;
            overflow-y: auto;
            padding: 0;
        }

        .file-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
        }

        .file-table thead th {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-default);
            padding: 7px 10px;
            font-weight: 600;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            position: sticky;
            top: 0;
            z-index: 10;
            white-space: nowrap;
        }

        .file-table tbody tr.file-item {
            border-bottom: 1px solid var(--border-subtle);
            transition: background 0.1s;
            cursor: pointer;
        }

        .file-table tbody tr.file-item:hover {
            background: var(--bg-hover);
        }

        .file-table tbody tr.file-item.selected {
            background: var(--bg-selected);
        }

        .file-table td {
            padding: 5px 10px;
            vertical-align: middle;
            color: var(--text-primary);
        }

        .checkbox-col {
            width: 32px;
        }

        .icon-col {
            width: 32px;
            padding-right: 0;
        }

        .file-name {
            color: var(--text-primary);
            text-decoration: none;
            font-weight: 500;
        }

        .file-name:hover {
            color: var(--text-link);
            text-decoration: underline;
        }

        .folder-icon {
            color: var(--folder-color);
        }

        .file-size,
        .file-date,
        .file-type {
            color: var(--text-secondary);
            font-size: 0.75rem;
        }

        .file-type {
            color: var(--text-muted);
            font-size: 0.7rem;
        }

        .permissions {
            font-family: var(--font-mono);
            font-size: 0.68rem;
            color: var(--text-muted);
            letter-spacing: 0.02em;
        }

        .form-check-input {
            background-color: var(--bg-elevated);
            border-color: var(--border-default);
            cursor: pointer;
        }

        .form-check-input:checked {
            background-color: var(--accent);
            border-color: var(--accent);
        }

        .form-check-input:focus {
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
        }

        /* ── Footer bar ──────────────────────────────────────────── */
        .fm-footer {
            background: var(--bg-surface);
            border-top: 1px solid var(--border-subtle);
            padding: 4px 14px;
            font-size: 0.72rem;
            color: var(--text-muted);
            text-align: center;
        }

        .fm-footer a {
            color: var(--text-link);
            text-decoration: none;
        }

        .fm-footer a:hover {
            color: var(--text-link-hover);
            text-decoration: underline;
        }

        /* ── Context Menu ────────────────────────────────────────── */
        .context-menu {
            position: fixed;
            z-index: 9999;
            background: var(--bg-elevated);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            min-width: 170px;
            display: none;
            padding: 4px 0;
            backdrop-filter: blur(8px);
        }

        .context-menu-item {
            padding: 6px 14px;
            cursor: pointer;
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.12s;
        }

        .context-menu-item i {
            font-size: 0.72rem;
            color: var(--text-muted);
            width: 14px;
        }

        .context-menu-item:hover {
            background: var(--bg-selected);
            color: var(--text-primary);
        }

        .context-menu-item:hover i {
            color: var(--text-link);
        }

        .context-menu-item.danger {
            color: #f87171;
        }

        .context-menu-item.danger i {
            color: #f87171;
        }

        .context-menu-item.danger:hover {
            background: rgba(239, 68, 68, 0.1);
        }

        .context-menu-divider {
            border-top: 1px solid var(--border-subtle);
            margin: 3px 0;
        }

        /* ── Drag-over ───────────────────────────────────────────── */
        .drag-over {
            background: rgba(59, 130, 246, 0.05) !important;
            outline: 2px dashed var(--accent) !important;
            outline-offset: -4px;
        }

        /* ── Modals ──────────────────────────────────────────────── */
        .modal-content {
            background: var(--bg-surface);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-lg);
            color: var(--text-primary);
            box-shadow: var(--shadow-lg);
        }

        .modal-header {
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-subtle);
            padding: 10px 16px;
            border-radius: var(--radius-lg) var(--radius-lg) 0 0;
        }

        .modal-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .modal-body {
            padding: 16px;
        }

        .modal-footer {
            background: var(--bg-elevated);
            border-top: 1px solid var(--border-subtle);
            padding: 10px 16px;
            border-radius: 0 0 var(--radius-lg) var(--radius-lg);
        }

        .form-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }

        .form-control,
        .form-select {
            background: var(--bg-deep);
            border: 1px solid var(--border-default);
            color: var(--text-primary);
            font-size: 0.82rem;
            border-radius: var(--radius-sm);
            transition: border-color 0.15s, box-shadow 0.15s;
        }

        .form-control:focus,
        .form-select:focus {
            background: var(--bg-deep);
            border-color: var(--accent);
            color: var(--text-primary);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
        }

        .form-control::placeholder {
            color: var(--text-muted);
        }

        .form-control-sm {
            font-size: 0.78rem;
            padding: 4px 8px;
        }

        .form-text,
        small {
            color: var(--text-muted);
            font-size: 0.72rem;
        }

        /* Buttons */
        .btn {
            border-radius: var(--radius-sm);
            font-size: 0.8rem;
            padding: 5px 12px;
            font-weight: 500;
            transition: all 0.15s;
        }

        .btn-primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        .btn-primary:hover,
        .btn-primary:focus {
            background: var(--accent-hover);
            border-color: var(--accent-hover);
            color: #fff;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
        }

        .btn-danger {
            background: var(--accent-danger);
            border-color: var(--accent-danger);
            color: #fff;
        }

        .btn-danger:hover {
            background: #dc2626;
            border-color: #dc2626;
            color: #fff;
        }

        .btn-outline-secondary {
            border-color: var(--border-default);
            color: var(--text-secondary);
            background: transparent;
        }

        .btn-outline-secondary:hover {
            background: var(--bg-elevated);
            color: var(--text-primary);
            border-color: var(--border-default);
        }

        .btn-outline-light {
            border-color: var(--border-default);
            color: var(--text-secondary);
            background: transparent;
        }

        .btn-outline-light:hover {
            background: var(--bg-elevated);
            color: var(--text-primary);
            border-color: var(--border-default);
        }

        .btn-sm {
            padding: 3px 8px;
            font-size: 0.75rem;
        }

        /* Alert boxes inside modals */
        .alert {
            font-size: 0.8rem;
            border-radius: var(--radius-sm);
            padding: 8px 12px;
        }

        .alert-info {
            background: var(--bg-selected);
            border: 1px solid rgba(59, 130, 246, 0.25);
            color: #93c5fd;
        }

        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #fca5a5;
        }

        /* Radio/Checkbox in modals */
        .form-check-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .form-check {
            margin-bottom: 3px;
        }

        /* Border in permissions boxes */
        .border {
            border-color: var(--border-default) !important;
        }

        .border.p-2 {
            background: var(--bg-deep);
            border-radius: var(--radius-sm);
        }

        /* Code editor textarea */
        .code-editor {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            line-height: 1.6;
            color: #93c5fd;
            background: var(--bg-deep);
            border: 1px solid var(--border-default);
            border-radius: var(--radius-sm);
            padding: 10px;
            resize: vertical;
            width: 100%;
        }

        .code-editor:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
            outline: none;
        }

        /* Table inside modals */
        .table {
            color: var(--text-primary);
            font-size: 0.8rem;
        }

        .table thead th {
            background: var(--bg-elevated);
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-default);
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 7px 10px;
        }

        .table tbody td {
            border-bottom: 1px solid var(--border-subtle);
            padding: 6px 10px;
        }

        .table-hover tbody tr:hover {
            background: var(--bg-hover);
        }

        /* Spinner */
        .spinner-container {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .spinners {
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .my-indicator {
            display: none;
        }

        .htmx-request .my-indicator {
            display: inline;
        }

        .htmx-request.my-indicator {
            display: inline;
        }

        /* CoolAlert override */
        .cool-alert-toast {
            background-color: var(--bg-elevated) !important;
            color: var(--text-primary) !important;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 48px 16px;
            color: var(--text-muted);
        }

        .empty-state i {
            font-size: 2rem;
            margin-bottom: 10px;
            opacity: 0.3;
        }

        .empty-state p {
            font-size: 0.82rem;
        }
    </style>
</head>

<body>

    <!-- ── Main Toolbar ─────────────────────────────────────────── -->
    <div class="main-toolbar">
        <nav class="toolbar-actions" aria-label="Application menus"><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-file" data-bs-toggle="dropdown" aria-expanded="false">File</button><div class="dropdown-menu" aria-labelledby="menu-file"><a href="#" class="header-btns" id="new-file-btn" title="New File" aria-label="New File"><i class="fas fa-file"></i> New File</a><a href="#" class="header-btns" id="new-folder-btn" title="New Folder" aria-label="New Folder"><i class="fas fa-folder-plus"></i> New Folder</a><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="edit-btn" title="Open selected file" aria-label="Open selected file"><i class="fas fa-code"></i> Open selected file</a><button type="button" class="header-btns editor-menu-action" data-editor-command="save" disabled>Save <span class="menu-shortcut">Ctrl / ⌘ S</span></button><div class="dropdown-divider"></div><a href="#" class="header-btns" id="upload-btn" title="Upload" aria-label="Upload"><i class="fas fa-upload"></i> Upload</a><a href="#" class="header-btns disabled" id="download-btn" title="Download" aria-label="Download"><i class="fas fa-download"></i> Download</a><div class="dropdown-divider"></div><button type="button" class="header-btns" data-bs-toggle="modal" data-bs-target="#settingsModal">Settings…</button></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-edit" data-bs-toggle="dropdown" aria-expanded="false">Edit</button><div class="dropdown-menu" aria-labelledby="menu-edit"><button type="button" class="header-btns editor-menu-action" data-editor-command="undo" disabled>Undo</button><button type="button" class="header-btns editor-menu-action" data-editor-command="redo" disabled>Redo</button><button type="button" class="header-btns editor-menu-action" data-editor-command="copyall" disabled>Copy document text</button><button type="button" class="header-btns editor-menu-action" data-editor-command="find" disabled>Find / Replace</button><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="copy-btn" title="Copy" aria-label="Copy"><i class="fas fa-copy"></i> Copy</a><a href="#" class="header-btns disabled" id="move-btn" title="Move" aria-label="Move"><i class="fas fa-arrows-alt"></i> Move</a><a href="#" class="header-btns disabled" id="rename-btn" title="Rename" aria-label="Rename"><i class="fas fa-tag"></i> Rename</a><a href="#" class="header-btns disabled" id="delete-btn" title="Delete" aria-label="Delete"><i class="fas fa-trash"></i> Delete</a><a href="#" class="header-btns disabled" id="restore-btn" title="Restore" aria-label="Restore"><i class="fas fa-undo"></i> Restore</a></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-view" data-bs-toggle="dropdown" aria-expanded="false">View</button><div class="dropdown-menu" aria-labelledby="menu-view"><button type="button" class="header-btns" id="menu-show-files">File list</button><button type="button" class="header-btns editor-menu-action" data-editor-command="map" disabled>Toggle minimap</button><button type="button" class="header-btns editor-menu-action" data-editor-command="wrap" disabled>Toggle word wrap</button><button type="button" class="header-btns editor-menu-action" data-editor-command="fullscreen" disabled>Fullscreen</button></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-tools" data-bs-toggle="dropdown" aria-expanded="false">Tools</button><div class="dropdown-menu" aria-labelledby="menu-tools"><button type="button" class="header-btns editor-menu-action" data-editor-command="gitdiff" disabled>Git: View changes against HEAD</button><div class="dropdown-divider"></div><button type="button" class="header-btns editor-menu-action" data-editor-command="format" disabled>Format document</button><div class="dropdown-divider"></div><a href="#" class="header-btns disabled" id="permissions-btn" title="Permission" aria-label="Permission"><i class="fas fa-shield-alt"></i> Permission</a><a href="#" class="header-btns disabled" id="compress-btn" title="Compress" aria-label="Compress"><i class="fas fa-file-archive"></i> Compress</a><a href="#" class="header-btns disabled" id="extract-btn" title="Extract" aria-label="Extract"><i class="fas fa-box-open"></i> Extract</a></div></div><div class="dropdown toolbar-more"><button class="menu-heading" type="button" id="menu-help" data-bs-toggle="dropdown" aria-expanded="false">Help</button><div class="dropdown-menu" aria-labelledby="menu-help"><button type="button" class="header-btns" data-bs-toggle="modal" data-bs-target="#editorHelpModal">Keyboard shortcuts &amp; help</button></div></div><form method="post" id="logout-form" style="margin-left:8px"><input type="hidden" name="fm_auth_action" value="logout"><button type="submit" class="menu-heading">Sign out</button></form></nav>
        <div class="toolbar-utilities d-flex align-items-center gap-2">
            <select id="workspace-theme" class="btn-settings" title="Workspace theme" aria-label="Workspace theme" onchange="setWorkspaceTheme(this.value)">
                <option value="theme_mix">Theme Mix</option>
                <option value="one_dark">One Dark</option>
                <option value="nord_dark">Nord Dark</option>
                <option value="tomorrow_night_eighties">Tomorrow Night 80s</option>
                <option value="cobalt">Cobalt</option>
                <option value="monokai">Monokai</option>
                <option value="dracula">Dracula</option>
                <option value="tomorrow_night">Tomorrow Night</option>
                <option value="github_dark">GitHub Dark</option>
                <option value="github">GitHub Light</option>
                <option value="tomorrow">Tomorrow</option>
                <option value="kuroir">Kuroir</option>
            </select>
            <div class="search-container">
                <div class="input-group input-group-sm">
                    <input type="text" class="form-control" id="search-input" placeholder="Search files…">
                    <button class="btn-search" id="search-btn"><i class="fas fa-search"></i></button>
                </div>
            </div>
        </div>
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
            <div class="sidebar-path-bar">
                <button class="btn-icon" id="breadcrumb-home-btn" title="Home"><i class="fas fa-home"></i></button>
                <input type="text" class="form-control" id="breadcrumb" placeholder="/path">
                <button class="btn-icon" id="breadcrumb-search-btn">Go</button>
            </div>
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
                        </tr>
                    </thead>
                    <tbody id="files-list">
                        <tr>
                            <td colspan="7" class="text-center" style="padding: 32px; color: var(--text-muted);">
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
                <p><strong>Ctrl / ⌘ S</strong> — Save<br><strong>Ctrl / ⌘ Z</strong> — Undo<br><strong>Ctrl H</strong> — Find / Replace<br><strong>Shift Alt F</strong> — Format<br><strong>F11</strong> — Fullscreen</p>
                <p>Change the theme on the top bar. Use View to toggle the minimap and word wrap. Unsaved tabs show a dot.</p>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
        </div></div>
    </div>

    <!-- ── Context Menu ──────────────────────────────────────────── -->
    <div class="context-menu" id="context-menu">
        <div class="context-menu-item" id="ctx-open"><i class="fas fa-folder-open"></i> Open</div>
        <div class="context-menu-item" id="ctx-download"><i class="fas fa-download"></i> Download</div>
        <div class="context-menu-item" id="ctx-edit"><i class="fas fa-code"></i> Edit</div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" id="ctx-copy"><i class="fas fa-copy"></i> Copy</div>
        <div class="context-menu-item" id="ctx-cut"><i class="fas fa-arrows-alt"></i> Move</div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" id="ctx-rename"><i class="fas fa-tag"></i> Rename</div>
        <div class="context-menu-item" id="ctx-permissions"><i class="fas fa-shield-alt"></i> Permissions</div>
        <div class="context-menu-item" id="ctx-compress"><i class="fas fa-file-archive"></i> Compress</div>
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
                <form hx-post="" hx-trigger="submit" hx-swap="none">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-cog me-2" style="color:var(--accent)"></i>File Manager
                            Settings</h5>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Timezone</label>
                            <input type="text" class="form-control" name="timezone"
                                value="<?= htmlspecialchars($config['timezone']) ?>" placeholder="Africa/Lagos"
                                required>
                            <input type="hidden" name="action" value="settings">
                            <div class="form-text">PHP timezone identifier (e.g. Africa/Lagos, UTC)</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Date Format</label>
                            <input type="text" class="form-control" name="dateformat"
                                value="<?= htmlspecialchars($config['date_format']) ?>" placeholder="M j Y, g:i A"
                                required>
                            <div class="form-text">PHP date() format string</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Font Size</label>
                            <input type="text" class="form-control" name="fontSize"
                                value="<?= htmlspecialchars($config['font_size']) ?>" placeholder="14px" required>
                        </div>
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
                <form method="post" id="change-password-form" class="modal-body" style="border-top:1px solid var(--border-subtle)">
                    <h6>Change password</h6>
                    <input type="hidden" name="fm_auth_action" value="change_password">
                    <label class="form-label" for="current-password">Current password</label><input class="form-control mb-2" type="password" id="current-password" name="current_password" autocomplete="current-password" required>
                    <label class="form-label" for="new-password">New password</label><input class="form-control mb-2" type="password" id="new-password" name="new_password" autocomplete="new-password" minlength="12" maxlength="72" required>
                    <label class="form-label" for="confirm-password">Repeat new password</label><input class="form-control mb-3" type="password" id="confirm-password" name="confirm_password" autocomplete="new-password" minlength="12" maxlength="72" required>
                    <button class="btn btn-primary" type="submit">Change password</button>
                    <p class="form-text" id="password-result" role="status"></p>
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
                            <input type="text" name="destination" class="form-control" id="destinationPath"
                                placeholder="/path/to/destination" required>
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
        var SERVER_ROOT_PATH = "<?php echo $config['root_path']; ?>";
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

            document.getElementById('change-password-form').addEventListener('submit', async event => {
                event.preventDefault();
                const form = event.currentTarget;
                const button = form.querySelector('button');
                const result = document.getElementById('password-result');
                button.disabled = true;
                try {
                    const response = await fetch(location.pathname, {method: 'POST', body: new FormData(form)});
                    const data = await response.json();
                    result.textContent = data.message;
                    if (response.ok && data.status === 'success') form.reset();
                } catch (_) { result.textContent = 'Password change was not confirmed. Please try signing in to verify.'; }
                finally { button.disabled = false; }
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
            let clickedBtn = null;
            let hasResponseError = false;

            // ── File list ─────────────────────────────────────────────
            function loadFileList() {
                refreshGitStatus();
                const tbody = document.getElementById('files-list');
                tbody.innerHTML = `<tr><td colspan="7" style="padding:32px;text-align:center;color:var(--text-muted)">
                <i class="fas fa-spinner fa-spin me-2"></i> Loading files…</td></tr>`;
                selectedItems = [];
                updateButtonStates();

                const fd = new FormData();
                fd.append('action', 'list');
                fd.append('path', currentPath);
                fd.append('sort', currentSort);
                fd.append('order', currentOrder);

                fetch(window.location.pathname, {
                        method: 'POST',
                        body: fd
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            fileList = data.data;
                            updateBreadcrumb(data.current_path);
                            showFiles(fileList);
                            if (data.current_path !== undefined) currentPath = data.current_path;
                        } else {
                            showAlert('Error', data.message);
                        }
                    })
                    .catch(() => showAlert('Error', 'Failed to load file list'));
            }

            function updateBreadcrumb(path) {
                document.getElementById('breadcrumb').value = path;
            }

            function getMimeType(filename) {
                const ext = filename.split('.').pop().toLowerCase();
                const map = {
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
                return map[ext] || 'application/octet-stream';
            }

            let gitStatusRequest = 0;
            async function refreshGitStatus() {
                const request = ++gitStatusRequest;
                try {
                    const body = new FormData(); body.append('action','git_status');
                    const response = await fetch(window.location.pathname,{method:'POST',body});
                    const data = await response.json();
                    if (request !== gitStatusRequest) return;
                    document.querySelectorAll('.git-status-badge').forEach(element => element.remove());
                    if (!response.ok || data.status !== 'success') return;
                    const appendBadge = (element, path) => {
                        const status = data.files[path.replace(/^\/+/, '')];
                        if (!status) return;
                        const badge = document.createElement('span');
                        badge.className = 'git-status-badge'; badge.textContent = status;
                        badge.title = {M:'Modified compared with Git',U:'Untracked file',A:'Added to Git',D:'Deleted'}[status];
                        element.append(badge);
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
                    tbody.innerHTML = `<tr><td colspan="7">
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
                    <td class="permissions">${file.permissions}</td>
                </tr>`).join('');

                document.querySelectorAll('.file-item').forEach(row => {
                    row.addEventListener('dblclick', function() {
                        const name = this.dataset.name;
                        const type = this.dataset.type;
                        if (type === 'dir') {
                            navigateTo(currentPath + '/' + name);
                        } else {
                            openFileEditor(name);
                        }
                    });

                    row.addEventListener('click', function(e) {
                        if (e.target.type === 'checkbox') return;
                        const cb = this.querySelector('.item-check');
                        cb.checked = !cb.checked;
                        cb.dispatchEvent(new Event('change'));
                    });

                    row.addEventListener('contextmenu', function(e) {
                        e.preventDefault();
                        contextTarget = {
                            name: this.dataset.name,
                            type: this.dataset.type
                        };
                        const cb = this.querySelector('.item-check');
                        if (!cb.checked) {
                            cb.checked = true;
                            cb.dispatchEvent(new Event('change'));
                        }
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
                menu.style.visibility = 'hidden';
                menu.style.display = 'block';
                const mw = menu.offsetWidth,
                    mh = menu.offsetHeight;
                const vw = window.innerWidth,
                    vh = window.innerHeight;
                if (x + mw > vw) x = vw - mw - 8;
                if (y + mh > vh) y = Math.max(8, y - mh);
                menu.style.left = x + 'px';
                menu.style.top = y + 'px';
                menu.style.visibility = 'visible';

                document.getElementById('ctx-edit').style.display = type === 'file' ? 'flex' : 'none';
                document.getElementById('ctx-open').style.display = type === 'dir' ? 'flex' : 'none';

                setTimeout(() => {
                    document.addEventListener('click', function close(e) {
                        if (!menu.contains(e.target)) {
                            menu.style.display = 'none';
                            document.removeEventListener('click', close);
                        }
                    });
                }, 0);
            }

            function updateButtonStates() {
                const n = selectedItems.length;
                const inTrash = currentPath === '/.trash';

                const isArchive = n === 1 && (() => {
                    const f = fileList.find(i => i.name === selectedItems[0]);
                    if (!f || f.type !== 'file') return false;
                    return ['zip', 'tar', 'gz', 'gzip', 'bz2', 'bzip2', 'rar', '7z'].includes((f
                        .extension || '').toLowerCase());
                })();
                const isFile = n === 1 && fileList.find(i => i.name === selectedItems[0])?.type === 'file';

                const states = {
                    'permissions-btn': n === 1 && !inTrash,
                    'edit-btn': n === 1 && !inTrash,
                    'rename-btn': n === 1 && !inTrash,
                    'copy-btn': n > 0 && !inTrash,
                    'move-btn': n > 0 && !inTrash,
                    'delete-btn': n > 0 && !inTrash,
                    'compress-btn': n > 0 && !inTrash,
                    'download-btn': isFile && !inTrash,
                    'extract-btn': isArchive && !inTrash,
                    'restore-btn': n > 0 && inTrash,
                    'unselect-all-btn': n > 0,
                };
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
                const fd = new FormData();
                fd.append('action', 'tree');
                fd.append('path', path);
                try {
                    const response = await fetch(window.location.pathname, {method: 'POST', body: fd});
                    const data = await response.json();
                    if (data.status !== 'success') throw new Error(data.message || 'Failed to load folder');
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
                                document.querySelectorAll('#directory-tree .tree-file.active').forEach(el => el.classList.remove('active'));
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
                if (confirm !== null) {
                    CoolAlert.show({
                        title: title,
                        text: message,
                        icon: "success",
                        confirmButtonText: "Ok",
                        showCancelButton: false,
                    }).then((result) => {
                        if (result.isConfirmed) {
                            window.location.reload();
                        }
                    });

                } else {
                    CoolAlert.show({
                        toast: true,
                        icon: title === 'Error' ? 'error' : 'success',
                        title,
                        text: message
                    });
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
            document.getElementById('breadcrumb-home-btn').addEventListener('click', e => {
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

            document.getElementById('rename-btn').addEventListener('click', e => {
                e.preventDefault();
                if (!e.currentTarget.classList.contains('disabled') && selectedItems.length === 1) {
                    document.getElementById('oldName').value = selectedItems[0];
                    document.getElementById('newName').value = selectedItems[0];
                    document.getElementById('renamePath').value = currentPath;
                    new bootstrap.Modal(document.getElementById('renameModal')).show();
                }
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
                if (this.classList.contains('disabled') || selectedItems.length === 0) return;
                document.getElementById('deletePath').value = currentPath;
                document.getElementById('deleteItems').value = selectedItems;
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
                if (selectedItems.length === 0) return;
                document.getElementById('fileOpTitle').textContent = op === 'copy' ? '📋 Copy Items' :
                    '✂️ Move Items';
                document.getElementById('fileOpType').value = op;
                document.getElementById('destinationPath').value = currentPath;
                document.getElementById('copyPath').value = currentPath;
                document.getElementById('copyItems').value = selectedItems;
                document.getElementById('fileOpItems').textContent = `Selected: ${selectedItems.length} item(s)`;
                document.getElementById('currentPathDisplay').textContent = currentPath || '/';
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

            function uploadFiles(files) {
                if (!files.length) return;
                const fd = new FormData();
                fd.append('path', currentPath);
                for (let i = 0; i < files.length; i++) fd.append('files[]', files[i]);

                const bar = document.getElementById('upload-progress');
                const fill = bar.querySelector('.progress-bar');
                bar.style.display = 'block';
                fill.style.width = '0%';
                fill.textContent = 'Preparing…';

                const xhr = new XMLHttpRequest();
                xhr.open('POST', window.location.pathname, true);
                xhr.upload.addEventListener('progress', e => {
                    if (e.lengthComputable) {
                        const pct = Math.round(e.loaded / e.total * 100);
                        fill.style.width = pct + '%';
                        fill.textContent = pct + '%';
                        if (pct >= 100) {
                            fill.classList.remove('progress-bar-animated');
                            fill.textContent = 'Processing…';
                        }
                    }
                });
                xhr.addEventListener('load', () => {
                    setTimeout(() => {
                        bar.style.display = 'none';
                        fill.classList.add('progress-bar-animated');
                    }, 600);
                    if (xhr.status === 200) {
                        try {
                            const resp = JSON.parse(xhr.responseText);
                            if (resp.status === 'success' || resp.status === 'partial') {
                                loadFileList();
                                showAlert('Success', resp.message);
                            } else {
                                showAlert('Error', resp.message || 'Upload failed');
                            }
                        } catch {
                            showAlert('Error', 'Failed to parse server response');
                        }
                    } else {
                        showAlert('Error', 'HTTP ' + xhr.status);
                    }
                });
                xhr.addEventListener('error', () => {
                    bar.style.display = 'none';
                    showAlert('Error', 'Network error during upload');
                });
                xhr.send(fd);
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
            function searchFiles() {
                const q = document.getElementById('search-input').value.trim();
                if (!q) {
                    showAlert('Error', 'Please enter a search query');
                    return;
                }

                const tbody = document.getElementById('search-results');
                tbody.innerHTML =
                    `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted)"><i class="fas fa-spinner fa-spin me-2"></i>Searching…</td></tr>`;

                const fd = new FormData();
                fd.append('action', 'search');
                fd.append('path', currentPath);
                fd.append('query', q);

                fetch(window.location.pathname, {
                        method: 'POST',
                        body: fd
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            if (!data.data.length) {
                                tbody.innerHTML =
                                    `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted)">No results found</td></tr>`;
                            } else {
                                tbody.innerHTML = data.data.map(r => `
                                <tr class="search-result-item" data-path="${r.path}" style="cursor:pointer">
                                    <td>${r.icon} ${r.name}</td>
                                    <td style="font-size:0.75rem;color:var(--text-muted)">${r.path}</td>
                                    <td>${r.type === 'dir' ? 'Folder' : 'File'}</td>
                                    <td>${r.size||''}</td>
                                    <td>${r.last_modified}</td>
                                </tr>`).join('');

                                document.querySelectorAll('.search-result-item').forEach(row => {
                                    row.addEventListener('dblclick', function() {
                                        const p = this.dataset.path;
                                        navigateTo(p.substring(0, p.lastIndexOf('/')));
                                        bootstrap.Modal.getInstance(document.getElementById(
                                            'searchModal')).hide();
                                    });
                                });
                            }
                        } else {
                            tbody.innerHTML =
                                `<tr><td colspan="5" style="color:var(--accent-danger)">Error: ${data.message}</td></tr>`;
                        }
                    });

                new bootstrap.Modal(document.getElementById('searchModal')).show();
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
            function restoreWorkspaceTabs() {
                const cookie = document.cookie.split('; ').find(item => item.startsWith(tabsCookieName + '='));
                if (!cookie) return;
                try {
                    const state = JSON.parse(decodeURIComponent(cookie.substring(tabsCookieName.length + 1)));
                    if (state.v !== 1 || !Array.isArray(state.tabs)) return;
                    restoringTabs = true;
                    for (const item of state.tabs.slice(0, 50)) {
                        if (!Array.isArray(item) || typeof item[0] !== 'string' || !item[0].startsWith('/') || item[0].split('/').some(part => part === '..' || part === '.') || item[0].includes('\0')) continue;
                        const split = item[0].lastIndexOf('/');
                        const name = item[0].substring(split + 1);
                        if (!name) continue;
                        const number = n => Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
                        openFileEditor(name, item[0].substring(0, split), {row: number(item[1]), column: number(item[2]), top: number(item[3]), left: number(item[4])});
                    }
                    const activePath = typeof state.active === 'string' ? workspaceRoot + state.active : null;
                    activateTab(editorTabs.has(activePath) ? activePath : null);
                } catch (_) {
                    // Ignore stale or malformed cookies.
                } finally {
                    restoringTabs = false;
                }
            }
            window.addEventListener('pagehide', saveWorkspaceTabs);


            function activateTab(path) {
                activeEditorPath = path;
                scheduleSaveTabs();
                updateEditorMenu();
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
            function updateEditorMenu() {
                const ready = activeEditorPath !== null && !!editorTabs.get(activeEditorPath)?.frame.contentWindow.editor;
                document.querySelectorAll('.editor-menu-action').forEach(button => { button.disabled = !ready; });
            }
            document.getElementById('menu-show-files').addEventListener('click', () => activateTab(null));
            document.querySelectorAll('.editor-menu-action').forEach(button => {
                button.addEventListener('click', () => {
                    const target = editorTabs.get(activeEditorPath)?.frame.contentWindow;
                    if (!target?.editor) return;
                    const commands = {
                        save: () => target.saveFile(), undo: () => target.editor.undo(), redo: () => target.editor.redo(),
                        copyall: () => target.copyAll(), find: () => target.editor.execCommand('replace'), map: () => target.toggleMinimap(),
                        gitdiff: () => target.showGitDiff(), wrap: () => target.toggleWrap(), fullscreen: () => target.toggleFullscreen(), format: () => target.formatCode()
                    };
                    commands[button.dataset.editorCommand]?.();
                    if (!['map', 'wrap', 'fullscreen'].includes(button.dataset.editorCommand)) target.editor.focus();
                });
            });
            // Move between menu headings with the keyboard or pointer while a menu is open.
            document.querySelectorAll('.menu-heading').forEach(heading => {
                heading.addEventListener('mouseenter', () => {
                    if (document.querySelector('.menu-heading[aria-expanded="true"]') && heading.getAttribute('aria-expanded') !== 'true') {
                        document.querySelectorAll('.menu-heading[aria-expanded="true"]').forEach(open => bootstrap.Dropdown.getOrCreateInstance(open).hide());
                        bootstrap.Dropdown.getOrCreateInstance(heading).show();
                    }
                });
                heading.addEventListener('keydown', event => {
                    if (!['ArrowLeft','ArrowRight'].includes(event.key)) return;
                    event.preventDefault();
                    const headings = [...document.querySelectorAll('.menu-heading')];
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
                    }
                });
            };
            window.addEventListener('beforeunload', event => {
                saveWorkspaceTabs();
                if ([...editorTabs.values()].some(tab => tab.dirty)) {
                    event.preventDefault();
                    event.returnValue = '';
                }
            });

            function openFileEditor(name, directory = currentPath, savedLocation = null) {
                const full = SERVER_ROOT_PATH + (directory.startsWith('/') ? directory : '/' + directory);
                const path = full.replace(/\/+$/, '') + '/' + name;
                if (editorTabs.has(path)) {
                    activateTab(path);
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
                frame.title = 'Editor: ' + name;
                frame.src = window.location.pathname + '?editor=1&filename=' + encodeURIComponent(path);
                frame.setAttribute('allow', 'fullscreen');
                const tab = {element, button, close, frame, dot, dirty: false, loaded: false, savedLocation};
                editorTabs.set(path, tab);
                button.addEventListener('click', () => activateTab(path));
                close.addEventListener('click', async () => {
                    if (tab.dirty && !await window.workspaceConfirm('Discard unsaved changes in ' + name + '?')) return;
                    const keys = [...editorTabs.keys()];
                    const index = keys.indexOf(path);
                    editorTabs.delete(path);
                    element.remove();
                    frame.remove();
                    scheduleSaveTabs();
                    if (activeEditorPath === path) activateTab(keys[index - 1] || keys[index + 1] || null);
                });
                element.append(button, close);
                tabsBar.append(element);
                panels.append(frame);
                frame.addEventListener('load', () => {
                    const source = frame.contentWindow.editor;
                    if (!source) {
                        if (frame.contentDocument.body.textContent.trim() === 'Invalid file specified.') {
                            editorTabs.delete(path);
                            element.remove();
                            frame.remove();
                            if (activeEditorPath === path) activateTab(null);
                            scheduleSaveTabs();
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
                activateTab(path);
                button.scrollIntoView({block: 'nearest', inline: 'nearest'});
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

            // ── Context menu actions ──────────────────────────────────
            document.getElementById('ctx-open').addEventListener('click', () => {
                if (contextTarget?.type === 'dir') navigateTo(currentPath + '/' + contextTarget.name);
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-download').addEventListener('click', () => {
                if (contextTarget) window.location.href =
                    `${window.location.pathname}?action=download&path=${encodeURIComponent(currentPath)}&file=${encodeURIComponent(contextTarget.name)}`;
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-edit').addEventListener('click', () => {
                if (contextTarget?.type === 'file') openFileEditor(contextTarget.name);
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-copy').addEventListener('click', () => {
                if (contextTarget) {
                    selectedItems = [contextTarget.name];
                    performFileOperation('copy');
                }
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-cut').addEventListener('click', () => {
                if (contextTarget) {
                    selectedItems = [contextTarget.name];
                    performFileOperation('move');
                }
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-rename').addEventListener('click', () => {
                if (contextTarget) {
                    document.getElementById('oldName').value = contextTarget.name;
                    document.getElementById('newName').value = contextTarget.name;
                    document.getElementById('renamePath').value = currentPath;
                    new bootstrap.Modal(document.getElementById('renameModal')).show();
                }
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-permissions').addEventListener('click', () => {
                if (contextTarget) {
                    selectedItems = [contextTarget.name];
                    document.getElementById('permissions-btn').click();
                }
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-compress').addEventListener('click', () => {
                if (contextTarget) {
                    selectedItems = [contextTarget.name];
                    document.getElementById('compress-btn').click();
                }
                document.getElementById('context-menu').style.display = 'none';
            });
            document.getElementById('ctx-delete').addEventListener('click', () => {
                if (contextTarget) {
                    selectedItems = [contextTarget.name];
                    document.getElementById('delete-btn').click();
                }
                document.getElementById('context-menu').style.display = 'none';
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
                    CoolAlert.show({
                        icon: 'error',
                        title: data.title || 'Error',
                        text: data.text || data.message || 'Something went wrong!',
                        toast: true
                    });
                } catch {
                    CoolAlert.show({
                        icon: 'error',
                        title: 'Error',
                        text: 'Request failed',
                        toast: true
                    });
                }
            });

            init();
            restoreWorkspaceTabs();
        });
    </script>
</body>

</html>