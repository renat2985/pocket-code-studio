<?php
// Optional Pocket Code Studio module. The direct endpoint serves the token API.
$cdxUI = isset($fmModulePage) && $fmModulePage === __FILE__;
// @workspace-launcher
const CDX_LIMIT = 1048576;
const CDX_HISTORY_LIMIT = 10;
const CDX_BATCH_LIMIT = 50 * CDX_LIMIT;
// JSON escapes can take six bytes per input byte. Reserve room for metadata.
const CDX_JSON_LIMIT = 6 * CDX_BATCH_LIMIT + CDX_LIMIT;
const CDX_PRIVATE_PREFIX = "<?php http_response_code(404); exit; __halt_compiler();\n";

function cdxJSON($code, $data) {
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_THROW_ON_ERROR);
    exit;
}

function cdxAtomic($path, $bytes, $mode = 0600, $owner = null, $group = null, $beforeReplace = null) {
    $temp = @tempnam(dirname($path), '.pcs-');
    if ($temp === false) throw new RuntimeException('Cannot create a temporary file.');
    try {
        if (realpath(dirname($temp)) !== realpath(dirname($path)) ||
            @file_put_contents($temp, $bytes) !== strlen($bytes) ||
            ($owner !== null && fileowner($temp) !== $owner && !@chown($temp, $owner)) ||
            ($group !== null && filegroup($temp) !== $group && !@chgrp($temp, $group)) ||
            !@chmod($temp, $mode)) {
            throw new RuntimeException('Cannot replace the file while preserving its permissions.');
        }
        if ($beforeReplace) $beforeReplace();
        if (!@rename($temp, $path)) throw new RuntimeException('Cannot replace the file.');
    } finally {
        if (is_file($temp)) @unlink($temp);
    }
}

function cdxInside($path, $root) {
    return $path === $root || strpos($path, rtrim($root, '/') . '/') === 0;
}

function cdxFolders($project, $history) {
    $project = realpath($project);
    $history = realpath($history);
    $public = realpath($_SERVER['DOCUMENT_ROOT']);
    if (!$project || $project === '/' || !is_dir($project) || !is_readable($project)) {
        throw new RuntimeException('Choose an existing project folder.');
    }
    if (!$history || !is_dir($history)) throw new RuntimeException('The history folder does not exist. Create it first, then choose it with Browse.');
    if (!is_writable($history)) throw new RuntimeException('PHP cannot write to the selected history folder.');
    if (!$public || cdxInside($history, $public) || cdxInside($history, $project) ||
        cdxInside($public, $history) || cdxInside($project, $history)) {
        throw new RuntimeException('Choose a dedicated writable history folder outside the website and project.');
    }
    return [$project, $history];
}

function cdxProjectHistory($project, $history, $create = false) {
    $folder = $history . '/pcs-' . substr(hash('sha256', __FILE__ . '|' . $project), 0, 24);
    if ($create && !is_dir($folder)) @mkdir($folder, 0700);
    if (is_link($folder) || !is_dir($folder) || !is_readable($folder) || (fileperms($folder) & 0077)) {
        throw new RuntimeException('The private project history folder is unavailable.');
    }
    return $folder;
}

function cdxTarget($project, $relative, $directory = false) {
    if (!is_string($relative) || strlen($relative) > 1000 || preg_match('~[\\\\\x00-\x1f\x7f]~', $relative)) {
        throw new RuntimeException('Invalid project path.');
    }
    foreach (explode('/', $relative) as $part) {
        if ($part === '' || $part[0] === '.') throw new RuntimeException('Use a relative path without hidden folders or files.');
    }
    $path = $project . '/' . $relative;
    clearstatcache(true);
    $resolved = realpath($path);
    if (is_link($path) || realpath(dirname($path)) !== dirname($path) ||
        ($directory ? $resolved !== $path || !is_dir($path) : $resolved !== false && ($resolved !== $path || !is_file($path))) ||
        cdxInside($path, __DIR__) || $path === ($GLOBALS['cdxConfig']['editor'] ?? null)) {
        throw new RuntimeException('This path is unavailable. Parent folders must already exist.');
    }
    return $path;
}

function cdxModified($project, $since, $folder) {
    $scanStart = time();
    if (!is_int($since) || $since < 0 || $since > $scanStart) {
        throw new RuntimeException('Provide a Unix timestamp in seconds for since.');
    }
    $directory = $folder === '' ? $project : cdxTarget($project, $folder, true);
    $visited = 0;
    $tree = new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        function ($entry) use (&$visited) {
            if (++$visited > 15000) throw new RuntimeException('Too many entries. Scan a smaller folder.');
            return $entry->getFilename()[0] !== '.' && !$entry->isLink() &&
                !cdxInside($entry->getPathname(), __DIR__) && $entry->getPathname() !== ($GLOBALS['cdxConfig']['editor'] ?? null);
        }
    );
    $files = [];
    foreach (new RecursiveIteratorIterator($tree) as $entry) {
        if (!$entry->isFile() || $entry->getSize() > CDX_LIMIT || $entry->getMTime() < $since) continue;
        if (count($files) >= 500) throw new RuntimeException('Too many candidates. Choose a more recent timestamp or a smaller folder.');
        $path = substr($entry->getPathname(), strlen($project) + 1);
        if (strlen($path) > 1000 || preg_match('//u', $path) !== 1 || preg_match('~[\\\\\x00-\x1f\x7f]~', $path)) continue;
        $files[] = ['path' => $path, 'modified' => $entry->getMTime(), 'size' => $entry->getSize()];
    }
    return ['checked_at' => $scanStart, 'files' => $files];
}

function cdxIsText($bytes) {
    return strpos($bytes, "\0") === false && preg_match('//u', $bytes) === 1;
}

function cdxBytes($bytes) {
    if (!is_string($bytes) || strlen($bytes) > CDX_LIMIT) {
        throw new RuntimeException('Only files up to 1 MiB are supported.');
    }
    return $bytes;
}

function cdxRead($path) {
    return is_file($path) ? cdxBytes(@file_get_contents($path, false, null, 0, CDX_LIMIT + 1)) : null;
}

function cdxHash($bytes) {
    return $bytes === null ? null : hash('sha256', $bytes);
}

function cdxHistory($folder) {
    $files = glob($folder . '/pcs-update-*.json') ?: [];
    rsort($files, SORT_STRING);
    return array_values(array_filter($files, function ($file) {
        return !is_link($file) && preg_match('/^pcs-update-\d{20}-[a-f0-9]{12}\.json$/D', basename($file));
    }));
}

function cdxSync($project, $history, $relative, $hash, $acknowledge = false) {
    if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/D', $hash)) throw new RuntimeException('Provide a SHA-256 hash.');
    $path = cdxTarget($project, $relative);
    $marker = $history . '/pending-' . hash('sha256', $relative) . '.json';
    $lock = @fopen($history . '/.pcs-sync.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX)) {
        if ($lock) fclose($lock);
        throw new RuntimeException('Cannot lock pending sync.');
    }
    try {
        clearstatcache(true, $path);
        if (!is_file($path) || is_link($path) || @hash_file('sha256', $path) !== $hash) {
            throw new DomainException('File changed on the server: ' . $relative);
        }
        if (!$acknowledge) cdxAtomic($marker, json_encode($relative, JSON_THROW_ON_ERROR));
        elseif (is_file($marker) && !unlink($marker)) throw new RuntimeException('Cannot clear pending sync.');
    } finally {
        fclose($lock);
    }
}

function cdxPending($project, $history) {
    $files = [];
    foreach (glob($history . '/pending-*.json') ?: [] as $marker) {
        if (is_link($marker)) continue;
        $relative = json_decode((string) @file_get_contents($marker, false, null, 0, 8192), true);
        try {
            if (is_file(cdxTarget($project, $relative))) $files[] = $relative;
        } catch (RuntimeException $error) { /* File no longer available. */ }
    }
    return $files;
}

function cdxOutcome($entry) {
    if (isset($entry['failure'])) return 'Upload rejected';
    $count = count($entry['files']);
    $planned = $entry['planned'] ?? $count;
    return $count . ' of ' . $planned . ' uploaded' . (empty($entry['errors']) ? '' : ' · Error');
}

function cdxPlan($project, $files) {
    if (!is_array($files) || !$files || count($files) > 50) throw new RuntimeException('Submit between 1 and 50 files.');
    $plan = [];
    $total = 0;
    foreach ($files as $file) {
        if (!is_array($file) || !array_key_exists('expected', $file)) throw new RuntimeException('Each file requires an expected hash or null.');
        $relative = $file['path'] ?? null;
        $path = cdxTarget($project, $relative);
        if (isset($plan[$path])) throw new RuntimeException('Duplicate path in update.');
        $before = cdxRead($path);
        if ($file['expected'] !== cdxHash($before)) throw new DomainException('File changed on the server: ' . $relative);
        $content = $file['content'] ?? null;
        $encoding = $file['encoding'] ?? 'utf8';
        if (!is_string($content) || !in_array($encoding, ['utf8', 'base64'], true)) {
            throw new RuntimeException('Provide UTF-8 text or base64 content.');
        }
        $after = cdxBytes($encoding === 'base64' ? base64_decode($content, true) : $content);
        if ($encoding === 'utf8' && !cdxIsText($after)) throw new RuntimeException('Use base64 for binary content.');
        if ($before === $after) continue;
        $total += strlen($before ?? '') + strlen($after);
        if ($total > CDX_BATCH_LIMIT) throw new RuntimeException('The update exceeds the 50 MiB history limit.');
        if (($before !== null && !is_writable($path)) || !is_writable(dirname($path))) throw new RuntimeException('Cannot write to the folder for ' . $relative);
        $plan[$path] = ['path' => $relative, 'before' => $before, 'after' => $after];
    }
    return $plan;
}

function cdxDeploy($project, $history, $request) {
    $description = trim(is_string($request['description'] ?? null) ? $request['description'] : '');
    if (!preg_match('/^[^\r\n]{1,100}$/uD', $description)) throw new RuntimeException('Enter a one-line description of up to 100 characters.');
    $lockPath = $history . '/.pcs-deploy.lock';
    if (is_link($lockPath) || !($lock = @fopen($lockPath, 'c')) || !flock($lock, LOCK_EX)) {
        throw new RuntimeException('Cannot lock the update history.');
    }
    try {
        $stamp = (new DateTimeImmutable())->format('YmdHisu');
        $record = $history . '/pcs-update-' . $stamp . '-' . bin2hex(random_bytes(6)) . '.json';
        $entry = ['description' => $description, 'time' => time(), 'files' => []];
        try {
            $plan = cdxPlan($project, $request['files'] ?? null);
        } catch (RuntimeException | DomainException $error) {
            $entry['failure'] = $error->getMessage();
            cdxAtomic($record, json_encode($entry, JSON_THROW_ON_ERROR));
            foreach (array_slice(cdxHistory($history), CDX_HISTORY_LIMIT) as $old) @unlink($old);
            throw $error;
        }
        $entry['planned'] = count($plan);
        $errors = [];
        foreach ($plan as $path => $file) {
            $written = false;
            try {
                cdxTarget($project, $file['path']);
                if (cdxRead($path) !== $file['before']) throw new RuntimeException('The file changed during the update.');
                $exists = $file['before'] !== null;
                $mode = $exists ? fileperms($path) & 0777 : 0644;
                $owner = $exists ? fileowner($path) : null;
                $group = $exists ? filegroup($path) : null;
                $next = $entry;
                $binary = ($file['before'] !== null && !cdxIsText($file['before'])) || !cdxIsText($file['after']);
                $next['files'][] = $binary ? [
                    'path' => $file['path'], 'binary' => true,
                    'before' => $file['before'] === null ? null : strlen($file['before']),
                    'after' => strlen($file['after']), 'after_hash' => cdxHash($file['after'])
                ] : $file;
                // Stage the history first so storage failures leave the site untouched.
                cdxAtomic($record . '.pending', json_encode($next, JSON_THROW_ON_ERROR));
                cdxAtomic($path, $file['after'], $mode, $owner, $group, function () use ($project, $path, $file) {
                    cdxTarget($project, $file['path']);
                    if (cdxRead($path) !== $file['before']) throw new RuntimeException('The file changed during the update.');
                });
                $written = true;
                if (!@rename($record . '.pending', $record)) {
                    throw new RuntimeException('File was written, but history could not be published. A pending record remains.');
                }
                $entry = $next;
            } catch (Throwable $error) {
                if (!$written) @unlink($record . '.pending');
                $errors[] = ['path' => $file['path'], 'written' => $written, 'message' => $error->getMessage()];
                break;
            }
        }
        if ($errors) {
            $entry['errors'] = $errors;
            $entry['skipped'] = array_column(array_slice($plan, count($entry['files']) + 1), 'path');
            try {
                cdxAtomic($record, json_encode($entry, JSON_THROW_ON_ERROR));
            } catch (Throwable $error) {
                $errors[] = ['message' => 'Cannot save the upload result in history.'];
            }
        }
        foreach (array_slice(cdxHistory($history), CDX_HISTORY_LIMIT) as $old) @unlink($old);
        return ['files' => array_column($entry['files'], 'path'), 'errors' => $errors];
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

header('Cache-Control: no-store');
function cdxSites($path, &$showDecorations = null) {
    $showDecorations = false;
    if (is_link($path)) throw new RuntimeException('Invalid settings file.');
    if (!is_file($path)) return [];
    $stored = @file_get_contents($path, false, null, 0, 65537);
    if (!is_string($stored) || strlen($stored) > 65536 || strpos($stored, CDX_PRIVATE_PREFIX) !== 0) {
        throw new RuntimeException('Cannot read Codex settings.');
    }
    $data = json_decode(substr($stored, strlen(CDX_PRIVATE_PREFIX)), true);
    $showDecorations = ($data['show_decorations'] ?? false) === true;
    if (isset($data['sites']) && is_array($data['sites'])) return $data['sites'];
    if (isset($data['project'], $data['history'], $data['token'])) return ['default' => $data];
    throw new RuntimeException('Invalid Codex settings.');
}

$cdxSettings = __DIR__ . '/.codex-settings.php';
$cdxConfig = [];
$cdxSettingsError = '';
try {
    $cdxSites = cdxSites($cdxSettings, $showDecorations);
} catch (Throwable $error) {
    $cdxSites = [];
    $cdxSettingsError = $error->getMessage();
}

if ($cdxUI && ($_GET['launcher'] ?? '') === '1') {
    header('Content-Type: application/javascript; charset=UTF-8');
    header('Cache-Control: no-store');
    echo '(() => { let enabled = ' . json_encode($showDecorations) . ';' . "\n";
    echo <<<'JS'
    const link = document.querySelector('[data-module="codex"]');
    if (!link || !window.bootstrap) return;
    const host = document.createElement('div');
    host.innerHTML = `<div class="modal fade" id="workspace-module-modal" data-workspace-module tabindex="-1" aria-labelledby="workspace-module-title" aria-hidden="true">
        <div class="modal-dialog modal-xl modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="workspace-module-title"><i class="fas fa-puzzle-piece me-2" aria-hidden="true"></i>Codex</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
                <div class="modal-body p-0"><iframe title="Codex" style="display:block;width:100%;height:72dvh;border:0;background:var(--bg-main)"></iframe></div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><i class="fas fa-xmark me-2" aria-hidden="true"></i>Close</button></div>
            </div>
        </div>
    </div>`;
    const modal = host.firstElementChild, frame = modal.querySelector('iframe');
    document.body.append(modal);
    const dialog = bootstrap.Modal.getOrCreateInstance(modal);
    const open = url => {
        url.searchParams.set('embedded', '1');
        frame.src = url.href;
        dialog.show(link);
    };
    link.addEventListener('click', event => {
        event.preventDefault();
        open(new URL(link.href));
    });
    document.addEventListener('workspace-file-saved', async ({detail}) => {
        const url = new URL(link.href);
        url.searchParams.set('pending-sync', '1');
        try {
            const response = await fetch(url.href, {method:'POST', body:new URLSearchParams(detail)});
            if (response.ok) updateDecorations();
            else window.workspaceToast?.('Could not record the file for Codex sync.', 'Codex', 'warning');
        } catch (_) {
            window.workspaceToast?.('Could not record the file for Codex sync.', 'Codex', 'warning');
        }
    });
    let details = {};
    const openEntry = (path, current = false) => {
        const entry = details[path.replace(/^\/+/, '')];
        if (!entry) return;
        const url = new URL(link.href);
        for (const key of ['site', 'update', 'file']) url.searchParams.set(key, entry[key]);
        if (current) url.searchParams.set('compare', 'current');
        open(url);
    };
    const updateDecorations = () => {
        document.dispatchEvent(new CustomEvent('workspace-decoration-source', {detail: enabled ? {
            async load() {
                try {
                    const url = new URL(link.href);
                    url.searchParams.set('decorations', '1');
                    const response = await fetch(url);
                    if (!response.ok) throw new Error();
                    const data = await response.json();
                    details = data.details || {};
                    return data;
                } catch (_) {
                    details = {};
                    return {status:'error'};
                }
            },
            title: 'View changes from the last Codex upload',
            folderTitles: {added: 'Contains files added by the last Codex upload', changed: 'Contains changes from the last Codex upload'},
            open: openEntry,
            openCurrent: path => openEntry(path, true)
        } : null}));
    };
    document.addEventListener('codex-decoration-setting', event => {
        enabled = event.detail;
        updateDecorations();
    });
    document.addEventListener('DOMContentLoaded', updateDecorations);
    modal.addEventListener('hidden.bs.modal', () => { frame.removeAttribute('src'); });
    frame.addEventListener('load', () => {
        frame.contentDocument?.addEventListener('keydown', event => {
            if (event.key === 'Escape') dialog.hide();
        });
    });
})();
JS;
    exit;
}
if ($cdxUI && ($_GET['decoration-setting'] ?? '') === '1') {
    if (!$isPostRequest) cdxJSON(405, ['error' => 'Use POST.']);
    $enabled = $_POST['enabled'] ?? null;
    if ($enabled !== '0' && $enabled !== '1') cdxJSON(400, ['error' => 'Invalid decoration setting.']);
    $lockPath = __DIR__ . '/.codex-settings.lock';
    if (is_link($lockPath) || !($lock = @fopen($lockPath, 'c'))) cdxJSON(500, ['error' => 'Cannot open Codex settings lock.']);
    try {
        if (!flock($lock, LOCK_EX)) throw new RuntimeException('Cannot lock Codex settings.');
        $sites = cdxSites($cdxSettings);
        $serialized = CDX_PRIVATE_PREFIX . json_encode(['sites' => $sites, 'show_decorations' => $enabled === '1'], JSON_THROW_ON_ERROR);
        if (strlen($serialized) > 65536) throw new RuntimeException('Codex settings exceed the size limit.');
        cdxAtomic($cdxSettings, $serialized);
        $error = null;
    } catch (Throwable $failure) {
        $error = $failure->getMessage();
    } finally {
        fclose($lock);
    }
    if ($error !== null) cdxJSON(500, ['error' => $error]);
    cdxJSON(200, ['status' => 'success']);
}

if (!$cdxUI) {
    $https = in_array(strtolower((string) ($_SERVER['HTTPS'] ?? '')), ['on', '1'], true);
    $loopback = PHP_SAPI === 'cli-server' && ($_SERVER['REMOTE_ADDR'] ?? '') === '127.0.0.1';
    $custom = $_SERVER['HTTP_X_PCS_TOKEN'] ?? '';
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $bearer = preg_match('/^Bearer ([a-f0-9]{64})$/D', $authorization, $token) === 1;
    $candidate = $custom !== '' ? $custom : ($bearer ? $token[1] : '');
    $digest = preg_match('/^[a-f0-9]{64}$/D', $candidate) ? hash('sha256', $candidate) : '';
    $proof = $_SERVER['HTTP_X_CDX_DIAGNOSTIC'] ?? '';
    $diagnostic = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' &&
        preg_match('/^(\d{10}):([a-f0-9]{64})$/D', $proof, $parts) &&
        abs(time() - (int) $parts[1]) <= 1800;
    foreach ($cdxSites as $site) {
        $storedHash = $site['token'] ?? '';
        if (!$storedHash) continue;
        if ($diagnostic && hash_equals(hash_hmac('sha256', 'diagnostic:' . $parts[1], $storedHash), $parts[2])) {
            cdxJSON(200, ['https' => $https || $loopback, 'authorization' => $authorization !== '',
                'bearer' => $bearer, 'custom_header' => $custom !== '', 'token_matches' => hash_equals($storedHash, $digest)]);
        }
        if (hash_equals($storedHash, $digest)) $cdxConfig = $site;
    }
    if ((!$https && !$loopback) || !$cdxConfig) cdxJSON(403, ['error' => 'Access denied.']);
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') cdxJSON(405, ['error' => 'Use POST.']);
    try {
        [$project, $history] = cdxFolders($cdxConfig['project'], $cdxConfig['history']);
        $history = cdxProjectHistory($project, $history);
        $body = file_get_contents('php://input', false, null, 0, CDX_JSON_LIMIT + 1);
        if (strlen($body) > CDX_JSON_LIMIT) cdxJSON(413, ['error' => 'Request too large.']);
        $request = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($request)) throw new RuntimeException('Send a JSON object.');
        switch ($request['action'] ?? '') {
            case 'pending':
                cdxJSON(200, ['files' => cdxPending($project, $history)]);
                break;
            case 'ack_sync':
                cdxSync($project, $history, $request['path'] ?? null, $request['hash'] ?? null, true);
                cdxJSON(200, ['status' => 'success']);
                break;
            case 'status':
                cdxJSON(200, ['status' => 'connected', 'checked_at' => time()]);
                break;
            case 'read':
                $bytes = cdxRead(cdxTarget($project, $request['path'] ?? null));
                $result = ['content' => $bytes, 'hash' => cdxHash($bytes)];
                if ($bytes !== null && !cdxIsText($bytes)) {
                    $result['content'] = base64_encode($bytes);
                    $result['encoding'] = 'base64';
                }
                cdxJSON(200, $result);
                break;
            case 'modified':
                cdxJSON(200, cdxModified($project, $request['since'] ?? max(0, time() - 86400), $request['folder'] ?? ''));
                break;
            case 'changes':
                $paths = $request['paths'] ?? null;
                if (!is_array($paths) || count($paths) > 200) throw new RuntimeException('Provide up to 200 paths with expected hashes.');
                $changed = [];
                foreach ($paths as $path => $expected) {
                    $hash = cdxHash(cdxRead(cdxTarget($project, (string) $path)));
                    if ($hash !== $expected) $changed[] = ['path' => $path, 'hash' => $hash];
                }
                cdxJSON(200, ['changed' => $changed]);
                break;
            case 'check':
                $plan = cdxPlan($project, $request['files'] ?? null);
                cdxJSON(200, ['files' => array_column($plan, 'path')]);
                break;
            case 'apply':
                $result = cdxDeploy($project, $history, $request);
                cdxJSON($result['errors'] ? 409 : 200, $result);
                break;
            default:
                cdxJSON(400, ['error' => 'Unknown action.']);
        }
    } catch (DomainException $error) {
        cdxJSON(409, ['error' => $error->getMessage()]);
    } catch (Throwable $error) {
        cdxJSON(400, ['error' => $error->getMessage()]);
    }
}

if (($_GET['pending-sync'] ?? '') === '1') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') cdxJSON(405, ['error' => 'Use POST.']);
    $path = $_POST['path'] ?? null;
    $workspace = realpath($config['root_path']);
    if (!$workspace || !is_string($path) || !cdxInside($path, $workspace) || realpath($path) !== $path) {
        cdxJSON(400, ['error' => 'Invalid workspace file.']);
    }
    try {
        foreach ($cdxSites as $site) {
            [$project, $history] = cdxFolders($site['project'], $site['history']);
            if (!cdxInside($path, $project)) continue;
            $cdxConfig = $site;
            cdxSync($project, cdxProjectHistory($project, $history), substr($path, strlen($project) + 1), $_POST['hash'] ?? null);
        }
        cdxJSON(200, ['status' => 'success']);
    } catch (Throwable $error) {
        cdxJSON(409, ['error' => $error->getMessage()]);
    }
}

if (($_GET['decorations'] ?? '') === '1') {
    $files = $details = $dates = $pending = [];
    $workspace = realpath($config['root_path']);
    foreach ($cdxSites as $siteId => $site) {
        try {
            [$project, $history] = cdxFolders($site['project'], $site['history']);
            $history = cdxProjectHistory($project, $history);
            $cdxConfig = $site;
            foreach (cdxPending($project, $history) as $relative) {
                $path = $project . '/' . $relative;
                if ($workspace && cdxInside($path, $workspace)) $pending[substr($path, strlen(rtrim($workspace, '/')) + 1)] = true;
            }
            foreach (cdxHistory($history) as $record) {
                $entry = json_decode(file_get_contents($record, false, null, 0, CDX_JSON_LIMIT), true, 32, JSON_THROW_ON_ERROR);
                if (empty($entry['files'])) continue;
                $id = basename($record);
                foreach ($entry['files'] as $index => $file) {
                    $path = $project . '/' . $file['path'];
                    $resolved = realpath($path);
                    if (!$workspace || !cdxInside($path, $workspace) || ($resolved && (!cdxInside($resolved, $workspace) || !cdxInside($resolved, $project)))) continue;
                    $key = substr($path, strlen(rtrim($workspace, '/')) + 1);
                    if (($dates[$key] ?? '') >= $id) continue;
                    $dates[$key] = $id;
                    $files[$key] = $file['before'] === null ? 'A' : 'M';
                    $expected = !empty($file['binary']) ? ($file['after_hash'] ?? null) : cdxHash($file['after']);
                    $size = !empty($file['binary']) ? $file['after'] : strlen($file['after']);
                    $changed = $expected !== null && (!$resolved || !is_file($resolved) ||
                        @filesize($resolved) !== $size || @hash_file('sha256', $resolved) !== $expected);
                    $details[$key] = ['site' => $siteId, 'update' => $id, 'file' => $index, 'changed' => $changed];
                }
                break;
            }
        } catch (Throwable $error) {
            continue;
        }
    }
    foreach ($pending as $key => $_) {
        $files[$key] = $files[$key] ?? 'P';
        $details[$key]['pending'] = true;
    }
    cdxJSON(200, ['status' => 'success', 'files' => (object) $files, 'details' => (object) $details]);
}

$cdxEscape = static function ($value) { return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
$cdxEmbedded = ($_GET['embedded'] ?? '') === '1';
$cdxBaseURL = '?module=codex' . ($cdxEmbedded ? '&embedded=1' : '');
$cdxSiteId = $_GET['site'] ?? (array_key_first($cdxSites) ?? 'new');
if (!is_string($cdxSiteId) || ($cdxSiteId !== 'new' && !isset($cdxSites[$cdxSiteId]))) {
    $cdxSiteId = array_key_first($cdxSites) ?? 'new';
}
$cdxConfig = $cdxSites[$cdxSiteId] ?? [];
$cdxToken = '';
$cdxMessage = $cdxSettingsError;
$cdxFailed = $cdxMessage !== '';
$nameInput = $cdxConfig['name'] ?? (isset($cdxConfig['project']) ? basename($cdxConfig['project']) : '');
$projectInput = $cdxConfig['project'] ?? ($cdxSites ? '' : $config['root_path']);
$historyInput = $cdxConfig['history'] ?? ($cdxSites[array_key_first($cdxSites)]['history'] ?? '');
if ($isPostRequest) {
    $lock = null;
    try {
        $lockPath = __DIR__ . '/.codex-settings.lock';
        if (is_link($lockPath) || !($lock = @fopen($lockPath, 'c')) || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('Cannot lock Codex settings.');
        }
        $cdxSites = cdxSites($cdxSettings, $showDecorations);
        $current = $cdxSites[$cdxSiteId] ?? [];
        if (isset($_POST['remove_site'])) {
            if (($_GET['site'] ?? null) !== $cdxSiteId || !$current) {
                throw new RuntimeException('This site is no longer configured.');
            }
            unset($cdxSites[$cdxSiteId]);
            cdxAtomic($cdxSettings, CDX_PRIVATE_PREFIX . json_encode(
                ['sites' => $cdxSites, 'show_decorations' => $showDecorations], JSON_THROW_ON_ERROR
            ));
            header('Location: ' . $cdxBaseURL . '&site-removed=1', true, 303);
            return;
        }
        $project = $_POST['project'] ?? '';
        $history = $_POST['history'] ?? '';
        $name = $_POST['site_name'] ?? $nameInput;
        if (!is_string($project) || !is_string($history) || !is_string($name)) throw new RuntimeException('Invalid site settings.');
        $projectInput = $project;
        $historyInput = $history;
        $nameInput = trim($name);
        if ($nameInput !== '' && !preg_match('/^[^\r\n]{1,80}$/uD', $nameInput)) throw new RuntimeException('Enter a site name of up to 80 characters.');
        [$project, $history] = cdxFolders(trim($project), trim($history));
        if ($cdxSiteId !== 'new' && !$current) throw new RuntimeException('This site is no longer configured.');
        if ($cdxSiteId === 'new' && count($cdxSites) >= 20) throw new RuntimeException('Up to 20 sites can be configured.');
        foreach ($cdxSites as $id => $site) {
            if ($id !== $cdxSiteId && $site['project'] === $project) throw new RuntimeException('This project folder already has a site profile.');
        }
        cdxProjectHistory($project, $history, true);
        if (!$current || isset($_POST['rotate_token']) || $current['project'] !== $project) {
            $cdxToken = bin2hex(random_bytes(32));
        }
        $nextConfig = ['name' => $nameInput ?: basename($project), 'project' => $project, 'history' => $history,
            'editor' => $fmModuleEditor, 'token' => $cdxToken ? hash('sha256', $cdxToken) : $current['token']];
        $nextId = $cdxSiteId === 'new' ? bin2hex(random_bytes(8)) : $cdxSiteId;
        $nextSites = $cdxSites;
        $nextSites[$nextId] = $nextConfig;
        $serialized = CDX_PRIVATE_PREFIX . json_encode(['sites' => $nextSites, 'show_decorations' => $showDecorations], JSON_THROW_ON_ERROR);
        if (strlen($serialized) > 65536) throw new RuntimeException('Codex settings exceed the size limit.');
        cdxAtomic($cdxSettings, $serialized);
        $cdxSites = $nextSites;
        $cdxSiteId = $nextId;
        $cdxConfig = $nextConfig;
        $nameInput = $nextConfig['name'];
        $projectInput = $project;
        $historyInput = $history;
        $cdxMessage = $cdxToken ? 'Settings saved. Copy the connection instructions while the token is visible.' : 'Settings saved. Your current token still works.';
    } catch (Throwable $error) {
        $cdxToken = '';
        $cdxFailed = true;
        $cdxMessage = $error->getMessage();
    } finally {
        if (is_resource($lock)) fclose($lock);
    }
}
$cdxURL = $cdxBaseURL . '&site=' . rawurlencode($cdxSiteId);
$cdxUpdates = [];
$cdxEntry = null;
try {
    if ($cdxConfig) {
        [$cdxProject, $cdxHistoryFolder] = cdxFolders($cdxConfig['project'], $cdxConfig['history']);
        $cdxHistoryFolder = cdxProjectHistory($cdxProject, $cdxHistoryFolder);
        $selection = $_GET['update'] ?? '';
        foreach (cdxHistory($cdxHistoryFolder) as $path) {
            $id = basename($path);
            if ($selection !== '' && $selection !== $id) continue;
            $entry = json_decode(file_get_contents($path, false, null, 0, CDX_JSON_LIMIT), true, 32, JSON_THROW_ON_ERROR);
            if ($selection === $id) {
                $cdxEntry = $entry;
                break;
            }
            $cdxUpdates[$id] = ['description' => $entry['description'], 'time' => $entry['time'], 'outcome' => cdxOutcome($entry)];
        }
    }
} catch (Throwable $error) {
    $cdxMessage = 'Cannot read the update history.';
}
$cdxCurrent = null;
$cdxCurrentIndex = $_GET['file'] ?? null;
if (($_GET['compare'] ?? '') === 'current' && is_string($cdxCurrentIndex) &&
    ctype_digit($cdxCurrentIndex) && isset($cdxEntry['files'][$cdxCurrentIndex])) {
    $file = $cdxEntry['files'][$cdxCurrentIndex];
    if (empty($file['binary'])) {
        try {
            $bytes = cdxRead(cdxTarget($cdxProject, $file['path']));
            if ($bytes !== null && cdxIsText($bytes)) $cdxCurrent = $bytes;
        } catch (RuntimeException $error) { /* Comparison unavailable. */ }
    }
}
$cdxEndpoint = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/modules/codex.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Codex updates</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<?= $workspaceThemeScript ?>
<?php if (!$cdxEmbedded): ?><script defer src="https://cdn.jsdelivr.net/npm/coolalertjs@latest/dist/coolalert.min.js"></script><?php endif; ?>
<style>
body.modal {position:static;display:block;height:auto;overflow:visible;margin:0;background:var(--bg-surface);color:var(--text-primary);}
header,section,aside,article {padding:12px 16px;}
header {background:var(--bg-main);border-bottom:1px solid var(--border-default);}
a {color:var(--text-link);}
h1,h2 {margin:0 0 8px;font-size:inherit;font-weight:600;}
.setup-note {margin:4px 0 10px;}
.setup-error {color:var(--accent-danger);}
.fas {margin-right:.35em;}
h1 .fas {color:var(--accent);}
.connection-settings {padding:10px;border:1px solid var(--border-default);border-radius:6px;background:var(--bg-main);}
.connection-actions {padding-top:10px;border-top:1px solid var(--border-default);}
.connection-fields {display:grid;gap:8px;}
.form-label {display:block;margin:8px 0 4px;color:var(--text-secondary);}
.form-control,.form-select {background:var(--bg-deep);border-color:var(--border-default);color:var(--text-primary);}
.form-control:focus,.form-select:focus {background:var(--bg-deep);border-color:var(--accent);color:var(--text-primary);}
.btn {padding:5px 12px;font-weight:500;}
.input-group {max-width:720px;flex-wrap:nowrap;}
.input-group .btn {white-space:nowrap;}
.connection-value {max-width:720px;}
.layout {display:grid;grid-template-columns:minmax(170px,25%) minmax(0,1fr);border:1px solid var(--border-default);}
aside {background:var(--bg-main);border-right:1px solid var(--border-default);max-height:65vh;overflow:auto;}
.codex-file-choice {display:flex;align-items:center;gap:8px;width:100%;padding:6px 8px;border:1px solid transparent;border-radius:4px;background:transparent;color:var(--text-primary);font:inherit;text-align:left;cursor:pointer;}
.codex-file-choice:hover,.codex-file-choice:focus-visible {background:var(--bg-hover);}
.codex-file-choice[aria-pressed="true"] {background:var(--bg-selected);border-color:var(--accent);}
.codex-file-choice > i {flex-shrink:0;}
.codex-file-choice > span:first-of-type {flex:1;min-width:0;overflow-wrap:anywhere;}
article {min-width:0;}
.update-row {display:block;padding:10px 12px;background:var(--bg-main);border-bottom:1px solid var(--border-default);text-decoration:none;overflow-wrap:anywhere;}
.update-row:hover,.update-row:focus-visible {background:var(--bg-selected);}
.update-row small {display:block;margin-top:4px;color:var(--text-secondary);}
.diff-heading {display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;}
.diff-heading h2 {margin:0;overflow-wrap:anywhere;}
.diff-actions {display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;flex-shrink:0;}
.diff-actions .btn:disabled {opacity:.5;cursor:default;}
#cdx-connection-dialog {width:min(720px,calc(100% - 24px));max-height:calc(100% - 24px);margin:auto;padding:0;}
#cdx-connection-dialog:not([open]) {display:none;}
#cdx-connection-dialog::backdrop {background:#0008;}
#cdx-connection-dialog .modal-body {min-height:0;overflow:auto;}
#cdx-instructions {max-width:none;}
#codex-diff {overflow:auto;max-height:60vh;white-space:pre;font:13px/1.6 monospace;}
@media(max-width:640px) {.layout {grid-template-columns:1fr;}aside {max-height:24vh;border-right:0;border-bottom:1px solid var(--border-default);}}
</style>
</head>
<body class="modal">
<?php if (!$cdxEmbedded): ?><header><a href="<?= $cdxEscape($_SERVER['SCRIPT_NAME']) ?>"><i class="fas fa-arrow-left" aria-hidden="true"></i> Pocket Code Studio</a></header><?php endif; ?>
<section class="pb-1">
<h1><i class="fas fa-code-branch" aria-hidden="true"></i> Codex updates</h1>
<?php if ($cdxSites): ?>
<form method="get" class="<?= $cdxConfig && !$cdxMessage ? 'mb-0' : 'mb-2' ?>">
<input type="hidden" name="module" value="codex">
<?php if ($cdxEmbedded): ?><input type="hidden" name="embedded" value="1"><?php endif; ?>
<?php endif; ?>
<?php if (($_GET['site-removed'] ?? '') === '1'): ?>
<p role="status">Site connection removed.</p>
<?php if ($cdxEmbedded): ?>
<script>
window.parent.document.dispatchEvent(new CustomEvent('codex-decoration-setting', {detail: <?= json_encode($showDecorations) ?>}));
</script>
<?php endif; ?>
<?php endif; ?>
<?php $settingsOpen = !$cdxConfig || $cdxMessage || $cdxToken; ?>
<?php if ($cdxSites): ?>
<div class="d-flex align-items-center gap-2">
<label class="form-label m-0 text-nowrap" for="cdx-site"><i class="fas fa-globe" aria-hidden="true"></i> Site</label>
<div class="input-group flex-nowrap" style="min-width:0">
<select class="form-select" id="cdx-site" style="min-width:0" name="site" onchange="this.form.submit()">
<?php foreach ($cdxSites as $id => $site): ?>
<option value="<?= $cdxEscape($id) ?>"<?= $id === $cdxSiteId ? ' selected' : '' ?>><?= $cdxEscape($site['name'] ?? basename($site['project'])) ?></option>
<?php endforeach; ?>
<?php if ($cdxSiteId === 'new'): ?><option value="new" selected>New site</option><?php endif; ?>
</select>
<?php if ($cdxSiteId !== 'new'): ?>
<button type="button" class="btn btn-secondary text-nowrap" id="cdx-settings-toggle" aria-controls="cdx-settings-panel" aria-expanded="<?= $settingsOpen ? 'true' : 'false' ?>"><i class="fas fa-gear" aria-hidden="true"></i> Settings</button>
<?php endif; ?>
</div>
<?php if ($cdxSiteId !== 'new'): ?>
<a class="btn btn-secondary text-nowrap flex-shrink-0" href="<?= $cdxEscape($cdxBaseURL . '&site=new') ?>"><i class="fas fa-plus" aria-hidden="true"></i> Add site</a>
<?php endif; ?>
</div>
</form>
<?php endif; ?>
<div id="cdx-settings-panel" class="pt-2"<?= $settingsOpen ? '' : ' hidden' ?>>
<script>
document.getElementById('cdx-settings-toggle')?.addEventListener('click', ({currentTarget}) => {
    const panel = document.getElementById('cdx-settings-panel');
    panel.hidden = !panel.hidden;
    currentTarget.setAttribute('aria-expanded', String(!panel.hidden));
});
document.getElementById('cdx-decorations').addEventListener('change', async ({target}) => {
    const enabled = target.checked;
    target.disabled = true;
    try {
        const response = await fetch('?module=codex&decoration-setting=1', {
            method:'POST', body:new URLSearchParams({enabled: enabled ? '1' : '0'})
        });
        if (!response.ok) throw new Error('Could not save Codex display settings.');
        window.parent.document.dispatchEvent(new CustomEvent('codex-decoration-setting', {detail: enabled}));
    } catch (_) {
        target.checked = !enabled;
        window.parent.workspaceToast?.('Could not save Codex display settings.', 'Codex', 'warning');
    } finally {
        target.disabled = false;
    }
});
</script>
<div class="connection-settings" role="region" aria-labelledby="cdx-connection-settings-title">
<h2 id="cdx-connection-settings-title">Connection settings</h2>
<?php if ($cdxMessage): ?><p role="<?= $cdxFailed ? 'alert' : 'status' ?>"<?= $cdxFailed ? ' class="setup-error"' : '' ?>><?= $cdxEscape($cdxMessage) ?></p><?php endif; ?>
<form method="post" action="<?= $cdxEscape($cdxURL) ?>">
<input type="hidden" name="fm_csrf" value="<?= $cdxEscape($fmCSRFToken) ?>">
<div class="connection-fields">
<div>
<label class="form-label" for="cdx-site-name"><i class="fas fa-tag" aria-hidden="true"></i> Site name</label>
<input class="form-control connection-value" id="cdx-site-name" name="site_name" maxlength="80" placeholder="Example: flaer.lv" value="<?= $cdxEscape($nameInput) ?>">
</div>
<div>
<label class="form-label" for="cdx-project"><i class="fas fa-folder" aria-hidden="true"></i> Project folder</label>
<div class="input-group"><input class="form-control" id="cdx-project" name="project" required value="<?= $cdxEscape($projectInput) ?>"><?php if ($cdxEmbedded): ?><button type="button" class="btn btn-secondary" data-browse="cdx-project" aria-label="Browse project folder"><i class="fas fa-folder-open" aria-hidden="true"></i> Browse…</button><?php endif; ?></div>
<p class="form-text setup-note">The site folder Codex can read and update.</p>
</div>
<div>
<label class="form-label" for="cdx-history"><i class="fas fa-box-archive" aria-hidden="true"></i> Private history folder</label>
<div class="input-group"><input class="form-control" id="cdx-history" name="history" required value="<?= $cdxEscape($historyInput) ?>"><?php if ($cdxEmbedded): ?><button type="button" class="btn btn-secondary" data-browse="cdx-history" aria-label="Browse history folder"><i class="fas fa-folder-open" aria-hidden="true"></i> Browse…</button><?php endif; ?></div>
<p class="form-text setup-note">Choose an existing writable folder outside all public site folders and outside the project. The module creates its history subfolder there.</p>
</div>
</div>
<div class="form-check mt-2 mb-3">
<input class="form-check-input" type="checkbox" id="cdx-decorations"<?= $showDecorations ? ' checked' : '' ?>>
<label class="form-check-label" for="cdx-decorations">Show last Codex upload in Files</label>
<p class="form-text mb-0">Replaces Git marks in the file list and tree for all sites visible in this workspace.</p>
</div>
<div class="connection-actions d-flex flex-wrap gap-2">
<button type="submit" class="btn btn-primary"><i class="fas fa-floppy-disk" aria-hidden="true"></i> <?= empty($cdxConfig['token']) ? 'Save and generate token' : 'Save settings' ?></button>
<?php if (!empty($cdxConfig['token'])): ?><button type="submit" class="btn btn-secondary" name="rotate_token" value="1"><i class="fas fa-key" aria-hidden="true"></i> Replace token</button><?php endif; ?>
<?php if ($cdxConfig): ?>
<button type="submit" form="cdx-remove-site" class="btn btn-danger ms-auto"><i class="fas fa-trash" aria-hidden="true"></i> Remove site</button>
<?php endif; ?>
</div>
<?php if (!empty($cdxConfig['token'])): ?><p class="form-text setup-note mb-0">Replacing the token or changing the project invalidates the old token.</p><?php endif; ?>
</form>
<?php if ($cdxConfig): ?>
<form id="cdx-remove-site" method="post" action="<?= $cdxEscape($cdxURL) ?>">
<input type="hidden" name="fm_csrf" value="<?= $cdxEscape($fmCSRFToken) ?>">
<input type="hidden" name="remove_site" value="1">
</form>
<script>
document.getElementById('cdx-remove-site').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = event.submitter;
    const message = 'The site token will stop working. Site files and upload history will stay on disk.';
    button.disabled = true;
    try {
        const alert = window.parent.CoolAlert || window.CoolAlert;
        const confirmed = alert
            ? (await alert.show({title: 'Remove site?', text: message, icon: 'warning',
                showCancelButton: true, confirmButtonText: 'Remove site', cancelButtonText: 'Cancel'})).isConfirmed
            : window.confirm('Remove site? ' + message);
        if (confirmed) form.submit();
    } finally {
        button.disabled = false;
    }
});
</script>
<?php endif; ?>
</div>
</div>
<?php if ($cdxToken): ?>
<dialog id="cdx-connection-dialog" class="modal-content" aria-labelledby="cdx-connection-title">
<div class="modal-header">
<h2 class="modal-title mb-0" id="cdx-connection-title"><i class="fas fa-key me-2" aria-hidden="true"></i>Codex desktop or CLI</h2>
<button type="submit" form="cdx-connection-actions" class="btn-close" aria-label="Close"></button>
</div>
<div class="modal-body">
<p>Click <strong>Copy instructions</strong> and paste the text into your private Codex chat. Codex will save the connection on your computer.</p>
<label class="form-label" for="cdx-instructions">Instructions for the Codex chat</label>
<textarea class="form-control connection-value" id="cdx-instructions" data-endpoint="<?= $cdxEscape($cdxEndpoint) ?>" readonly rows="8">Use Pocket Code Studio at __ENDPOINT__ to work with <?= $cdxEscape($cdxConfig['name'] ?? basename($cdxConfig['project'])) ?>.
API token: <?= $cdxEscape($cdxToken) ?>

Choose a site-specific private file outside the repository. Create it yourself with permissions restricted to my account and store the endpoint and token there as PCS_CODEX_URL and PCS_CODEX_TOKEN. Use the saved file for API calls and tell me its location without repeating the token. Start by calling {"action":"status"} to verify the connection without a test file.
Send JSON via POST with X-PCS-Token: &lt;token&gt; and Content-Type: application/json. Send the raw token, without the Bearer prefix. Use paths relative to the configured project. For binary files, send base64 in content and set encoding to "base64". Decode read results with encoding "base64" before comparing or saving locally.
Between tasks, call {"action":"modified","since":LAST_CHECKED_AT} with the previous server timestamp in seconds. An optional project-relative "folder" limits the scan. Read the candidates and compare hashes. Record checked_at locally after reviewing them. If there is no previous scan timestamp, call {"action":"modified"} to scan the last 24 hours. If the scan exceeds its limits, report that and continue with the files relevant to the task.
Add a short project-local AGENTS.md rule (preserve existing rules, never include the token): when I write “sync”, pull changes from Pocket Code Studio using the saved connection. Call {"action":"pending"}, read each listed file, and integrate the server changes locally. If local edits conflict, show me the conflict and leave that file pending. Once saved locally, call {"action":"ack_sync","path":"relative/file.php","hash":"SHA-256 from read"}. On HTTP 409, reread and reconcile before acknowledging. Summarize the updated files. Never upload as part of “sync”.
Before editing, call {"action":"read","path":"relative/file.php"}. Integrate newer server content locally and retain the returned hash. A missing file returns null for content and hash.
Before uploading, call {"action":"check","files":[{"path":"relative/file.php","expected":"original SHA-256","content":"full new text"}]}. Use null for expected only for a new file.
Show me the planned changes. When I explicitly ask you to deploy, send the same files with action "apply" and a one-line description of up to 100 characters. On conflict or partial write, reread the affected files before retrying.</textarea>
<p id="cdx-copy-status" class="form-text mb-0" role="status"></p>
</div>
<form id="cdx-connection-actions" class="modal-footer" method="dialog">
<button type="button" class="btn btn-primary" data-copy="cdx-instructions" autofocus><i class="fas fa-copy" aria-hidden="true"></i> Copy instructions</button>
<button type="submit" class="btn btn-secondary">Close</button>
</form>
</dialog>
<script>
const connectionDialog = document.getElementById('cdx-connection-dialog');
connectionDialog.addEventListener('keydown', event => {
    if (event.key === 'Escape') event.stopPropagation();
});
connectionDialog.showModal();
const instructions = document.getElementById('cdx-instructions');
instructions.value = instructions.value.replace('__ENDPOINT__', () => new URL(instructions.dataset.endpoint, location.origin).href);
document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    const status = document.getElementById('cdx-copy-status');
    try {
        await navigator.clipboard.writeText(field.value);
        status.textContent = 'Copied.';
    } catch (_) {
        field.focus();
        field.select();
        status.textContent = 'Text selected. Use your device’s Copy command.';
    }
}));
</script>
<?php endif; ?>
<?php if ($cdxEmbedded): ?>
<script>
document.querySelectorAll('[data-browse]').forEach(button => {
    button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.browse);
        window.parent.browseModuleFolder(input, 'Choose ' + input.labels[0].textContent.trim().toLowerCase());
    });
});
</script>
<?php endif; ?>

</section>
<section>
<?php if ($cdxEntry): ?>
<p><a href="<?= $cdxEscape($cdxURL) ?>"><i class="fas fa-arrow-left" aria-hidden="true"></i> All updates</a></p>
<h2><?= $cdxEscape($cdxEntry['description']) ?></h2>
<p><i class="fas fa-clock" aria-hidden="true"></i> <?= $cdxEscape(date('d M Y, H:i:s', $cdxEntry['time'])) ?> · <?= $cdxEscape(cdxOutcome($cdxEntry)) ?></p>
<?php if (isset($cdxEntry['failure'])): ?><p role="alert"><?= $cdxEscape($cdxEntry['failure']) ?></p><?php endif; ?>
<?php foreach ($cdxEntry['errors'] ?? [] as $error): ?>
<p role="alert"><i class="fas fa-triangle-exclamation" aria-hidden="true"></i> <?= $cdxEscape($error['path']) ?> · <?= $cdxEscape($error['message']) ?></p>
<?php endforeach; ?>
<?php if (!empty($cdxEntry['skipped'])): ?>
<p>Not processed</p>
<ul class="list-unstyled"><?php foreach ($cdxEntry['skipped'] as $path): ?><li><i class="fas fa-file-code fa-fw me-2" aria-hidden="true"></i><?= $cdxEscape($path) ?></li><?php endforeach; ?></ul>
<?php endif; ?>
<?php if ($cdxEntry['files']): ?>
<div class="layout">
<aside aria-label="Changed files">
<?php
$cdxWorkspace = realpath($config['root_path']);
foreach ($cdxEntry['files'] as $index => $file):
    $status = $file['before'] === null ? 'A' : 'M';
    $target = realpath($cdxProject . '/' . $file['path']);
    $openPath = $cdxEmbedded && $target && $cdxWorkspace && is_file($target) &&
        cdxInside($target, $cdxProject) && cdxInside($target, $cdxWorkspace)
        ? substr($target, strlen(rtrim($cdxWorkspace, '/'))) : '';
?>
<button type="button" class="codex-file-choice" data-index="<?= $index ?>" data-open-path="<?= $cdxEscape($openPath) ?>" aria-pressed="false"><i class="fas fa-file-code" aria-hidden="true"></i><span><?= $cdxEscape($file['path']) ?></span><span class="git-status-badge" title="<?= $status === 'A' ? 'Added' : 'Modified' ?>"><?= $status ?></span></button>
<?php endforeach; ?>
</aside>
<article><div class="diff-heading"><h2 id="codex-file"></h2><?php if ($cdxEmbedded): ?><div class="diff-actions"><button type="button" class="btn btn-secondary" id="codex-open" disabled><i class="fas fa-file-code" aria-hidden="true"></i> Open file</button><button type="button" class="btn btn-secondary" id="codex-open-changes" disabled><i class="fas fa-code-compare" aria-hidden="true"></i> Open changes</button></div><?php endif; ?></div><div id="codex-diff" tabindex="0">Loading comparison…</div></article>
</div>
<script type="application/json" id="codex-record"><?= json_encode($cdxEntry['files'], JSON_HEX_TAG | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR) ?></script>
<script type="application/json" id="codex-current"><?= json_encode($cdxCurrent, JSON_HEX_TAG | JSON_THROW_ON_ERROR) ?></script>
<script src="https://cdn.jsdelivr.net/npm/diff@5.2.0/dist/diff.min.js"></script>
<script>
const files = JSON.parse(document.getElementById('codex-record').textContent);
const buttons = [...document.querySelectorAll('button[data-index]')];
const openFile = document.getElementById('codex-open');
const openChanges = document.getElementById('codex-open-changes');
let selectedFile, comparingCurrent;
function openInWorkspace(comparison) {
    window.parent.document.dispatchEvent(new CustomEvent('workspace-open-file', {
        detail:{path:openFile.dataset.path, comparison}
    }));
}
openFile?.addEventListener('click', () => openInWorkspace(null));
openChanges?.addEventListener('click', () => openInWorkspace({
    baseline:comparingCurrent ? selectedFile.after : (selectedFile.before ?? ''),
    date:(comparingCurrent ? 'Uploaded' : 'Before Codex update') + ' · <?= $cdxEscape(date('d M Y, H:i:s', $cdxEntry['time'])) ?>'
}));
function showFile(button, compareCurrent = false) {
    comparingCurrent = compareCurrent;
    selectedFile = files[button.dataset.index];
    if (openFile) {
        openFile.dataset.path = button.dataset.openPath;
        openFile.disabled = !openFile.dataset.path;
        openChanges.disabled = openFile.disabled || !!selectedFile.binary;
        openFile.title = openFile.disabled ? 'The current file is unavailable in this workspace.' : 'Open the current file in the editor.';
        openChanges.title = selectedFile.binary ? 'Text comparison is unavailable for binary files.' : openFile.disabled ? openFile.title : compareCurrent ? 'Compare the current editor text with the uploaded version.' : 'Compare the current editor text with the file before this update.';
    }
    const file = files[button.dataset.index], output = document.getElementById('codex-diff');
    document.getElementById('codex-file').textContent = file.path;
    buttons.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    const current = compareCurrent ? JSON.parse(document.getElementById('codex-current').textContent) : null;
    if (compareCurrent && current === null) {
        output.textContent = 'Uploaded → Current is unavailable. The current file must be readable UTF-8 text up to 1 MiB.';
        return;
    }
    if (file.binary) {
        const before = file.before === null ? 'New file' : file.before + ' bytes before';
        output.textContent = 'Binary file · ' + before + ' · ' + file.after + ' bytes after';
        output.scrollTo(0, 0);
        return;
    }
    try {
        const patch = Diff.createTwoFilesPatch(file.path, file.path, compareCurrent ? file.after : (file.before ?? ''), compareCurrent ? current : file.after);
        const view = window.renderGitDiff(patch.split('\n').slice(4).join('\n'));
        const labels = view.querySelectorAll('.git-diff-column-head .git-diff-number');
        labels[0].textContent = compareCurrent ? 'Uploaded' : 'Before';
        labels[1].textContent = compareCurrent ? 'Current' : 'After';
        output.replaceChildren(view);
        output.scrollTo(0, 0);
    } catch (_) {
        output.textContent = 'Comparison unavailable. Reload the page and try again.';
    }
}
buttons.forEach(button => button.addEventListener('click', () => showFile(button)));
const parameters = new URLSearchParams(location.search);
const requested = buttons.find(button => button.dataset.index === parameters.get('file'));
if (buttons.length) showFile(requested || buttons[0], !!requested && parameters.get('compare') === 'current');
</script>
<?php endif; ?>
<?php elseif ($cdxUpdates): ?>
<h2><i class="fas fa-clock-rotate-left" aria-hidden="true"></i> Update history</h2>
<?php foreach ($cdxUpdates as $id => $update): ?>
<a class="update-row" href="<?= $cdxEscape($cdxURL . '&update=' . rawurlencode($id)) ?>">
<strong><i class="fas fa-code-commit" aria-hidden="true"></i> <?= $cdxEscape($update['description']) ?></strong>
<small><?= $cdxEscape(date('d M Y, H:i:s', $update['time'])) ?> · <?= $cdxEscape($update['outcome']) ?></small>
</a>
<?php endforeach; ?>
<?php elseif ($selection ?? ''): ?>
<p>This update is unavailable. <a href="<?= $cdxEscape($cdxURL) ?>">All updates</a></p>
<?php else: ?><p><i class="fas fa-clock-rotate-left" aria-hidden="true"></i> No updates recorded.</p><?php endif; ?>
</section>
</body>
</html>
