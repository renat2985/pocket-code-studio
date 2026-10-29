# Pocket Code Studio

A single-file PHP file manager and code editor with a Visual Studio Code-inspired interface.

[Русский](README.ru.md) · [Issues](https://github.com/Renat2985/pocket-code-studio/issues)

![Pocket Code Studio — workspace tabs](screenshots/screen.png)

## Features

- File tree, resizable sidebar, tabs, and restoration of cursor/scroll positions.
- Syntax highlighting, find/replace, formatting, word wrap, and multi-cursor editing.
- Minimap, occurrence markers, file icons, and themes for the entire interface.
- Create, rename, copy, move, upload/download, trash/restore, permissions, and archives where supported.
- Git status, comparison with HEAD, and selected-file commits and push to GitHub.
- Mobile layout with compact menus and code shortcut buttons.
- Password authentication, CSRF protection, login attempt limits, and verified saves with backups.

- The changed-file list has no 500-file limit. Each commit can select up to 2000 files, 32 MB per file and 128 MB total; content hashes are calculated only for selected files. Push existing commits does not scan working files.

<details>
<summary>Watch editing and Git previews</summary>

![Editing and verified saves](screenshots/edit-and-save.gif)

![Git HEAD comparison](screenshots/git-diff.gif)

</details>

## Requirements

- PHP **7.4+**, sessions, and writable workspace and temporary storage. A maintained PHP version is recommended.
- HTTPS; loopback development is exempt. On Apache/Nginx, PHP must receive `HTTPS=on` for TLS requests.
- Browser internet access: JavaScript/CSS libraries load from CDNs.
- Optional: Git and PHP `proc_open`; appropriate extensions/tools for archives.

No database, Composer, or Node.js build is required.

## Installation

1. Upload **`filemanager.php`** — no other application files are needed.
2. The initial workspace is the web server document root; change it with **File → Settings → Workspace root → Browse…**.
3. Open the file over HTTPS. The initial password is **`admin123`**, with no username.
4. Immediately change it in **File → Settings** before allowing public access to the manager.

For a unique password before deployment, generate a hash locally and paste it into `$authPasswordHash`:

```sh
php -r 'echo password_hash(readline("New password (input is visible): "), PASSWORD_DEFAULT), PHP_EOL;'
```

Keep your personal password hash and settings when replacing the PHP file. Do not publish your configured deployment copy.

## Controls and settings

**Edit → Copy / Move / Rename / Delete** applies to the active editor file, or to selected items in Files. Save unsaved editor changes before using these operations.

- **Ctrl/⌘ S:** save. **Ctrl/⌘ + click:** add cursors. **Escape:** return to one cursor.
- **View → Show Changes Since Save:** highlight unsaved additions and deletions; reset the comparison after a verified save.
- **View → Color theme:** 43 Ace themes; the interface follows the selected theme. Language and editor font size are in the bottom status bar.
- **File → Settings:** timezone, date format, interface font size, and optional password change. Browser timezone detection is available. Default date format: `M j Y, H:i:s`.
- **Browse…** in Copy/Move selects an existing destination folder inside the workspace. The workspace picker can explore other folders permitted by PHP and hosting restrictions. Save open edits before switching roots.
- **Save Settings** saves all changes together; **Cancel** discards them. Leave password fields empty to keep the current password.

Settings are stored in `filemanager.php`; PHP needs permission to replace it. Legacy `.fm-config` values migrate on the next Settings save.

## Authentication

- Password-only login; the initial password is **`admin123`**. Replace it in **File → Settings**. The PHP file stores a password hash, not the plain password.
- Default login throttling: **8 failed attempts per IP** or **64 failures across all IPs** block further logins until the respective **15-minute window** expires. Windows start with the first recorded failure. The shared limit can temporarily block everyone, including the owner.
- **Tools → Login activity:** IP addresses, results, browser details, active blocks and per-IP/global limit resets. Limits are configurable here. After login, a one-time notification appears only if IPs are currently blocked.
- Private server storage: `sys_get_temp_dir()/fm-auth-<installation-id>/`. `attempts.json` holds counters keyed by SHA-256 with the recorded IP; `login-activity.json` keeps up to **7 days / 2,000 entries / 1 MB**, and `login-policy.json` stores custom limits. No passwords are logged. Repeated blocked requests are grouped; statistics use retained entries. Old hash-only counters cannot reveal their original IP.
- Cookies do not reset server counters; hosting cleanup of temporary files may clear counters, history and custom limits. PHP uses `REMOTE_ADDR`; configure trusted proxies at the server layer to preserve the correct client address.
- Sessions expire after **30 minutes of inactivity** or **12 hours total**. Cookies are HttpOnly and SameSite=Strict, with Secure on HTTPS. Changing the password invalidates other sessions. State-changing requests require a CSRF token.
- This limits password guessing; it is **not DDoS protection**. Traffic limits at the hosting/web-server layer are separate.

## Important limits

- Only requests through this manager are password-protected; public website URLs remain public.
- The editor accepts UTF-8 text up to **8 MB**. Binary files, mixed line endings, and hard links are refused. UTF-8 BOM and uniform LF/CRLF/CR endings are preserved.
- Saves check disk revisions and create verified private backups. Temporary backups may be cleared by the host and do not replace permanent backups. External writes can still race with saves; filesystem ACLs/extended attributes may not survive replacement.
- Saving does not validate code syntax. Unsaved document text is not restored after reload.
- Git requires the workspace root to match an existing repository with at least one commit. **Tools → GitHub: Commit & Push** configures the HTTPS GitHub URL, current branch, author and a fine-grained token (Contents: Read and write; workflow changes may also require Workflows permission). Private repositories are supported.
- The token is stored with owner-only permissions in the private temporary authentication directory, separately for each workspace. It is never returned to the browser; clearing temporary storage removes it. Blank keeps the token; changing repositories clears it unless a new token is supplied.
- Select saved files and enter a message, then Commit & Push. After a failed or uncertain push, refresh and use Push existing commits. Staged changes, conflicts, symlinks and Git clean filters require a separate Git client. No automatic pull, force push, branch switching or inline Git change bars.

## Credits and support

Based on [Joseph Chuks’ PHP File Manager](https://github.com/JosephChuks/php-file-manager-with-code-editor) and [CWP Code Editor](https://github.com/JosephChuks/cwp-codeEditor). Powered by Ace. Independent of Microsoft; VS Code extensions are not supported.

[Credits](CREDITS.md) · [License](LICENSE) · [Third-party notices and upstream license details](THIRD_PARTY_NOTICES.md)

Bugs and requests: [GitHub Issues](https://github.com/Renat2985/pocket-code-studio/issues). Installation and custom development: [Renat2985](https://github.com/Renat2985).
