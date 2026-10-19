# Pocket Code Studio

A single-file PHP file manager and code editor with a Visual Studio Code-inspired interface.

[Русский](README.ru.md) · [Issues](https://github.com/Renat2985/pocket-code-studio/issues)

![Pocket Code Studio](screenshots/screen.png)

## Features

- File tree, resizable sidebar, tabs, and restoration of cursor/scroll positions.
- Syntax highlighting, find/replace, formatting, word wrap, and multi-cursor editing.
- Minimap, occurrence markers, file icons, and themes for the entire interface.
- Create, rename, copy, move, upload/download, trash/restore, permissions, and archives where supported.
- Read-only Git status and comparison with HEAD, including unsaved changes.
- Mobile layout with compact menus and code shortcut buttons.
- Password authentication, CSRF protection, login attempt limits, and verified saves with backups.

## Requirements

- PHP **7.4+**, sessions, and writable workspace and temporary storage. A maintained PHP version is recommended.
- HTTPS; loopback development is exempt. On Apache/Nginx, PHP must receive `HTTPS=on` for TLS requests.
- Browser internet access: JavaScript/CSS libraries load from CDNs.
- Optional: Git and PHP `proc_open`; appropriate extensions/tools for archives.

No database, Composer, or Node.js build is required.

## Installation

1. Upload **`filemanager.php`** — no other application files are needed.
2. Check `$config['root_path']`: by default, it is the web server document root.
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
- **View → Color theme:** choose a theme. Language and editor font size are in the bottom status bar.
- **File → Settings:** timezone, date format, interface font size, and optional password change. Browser timezone detection is available. Default date format: `M j Y, H:i:s`.
- **Save Settings** saves all changes together; **Cancel** discards them. Leave password fields empty to keep the current password.

Settings are stored in `filemanager.php`; PHP needs permission to replace it. Legacy `.fm-config` values migrate on the next Settings save.

## Important limits

- Only requests through this manager are password-protected; public website URLs remain public.
- The editor accepts UTF-8 text up to **8 MB**. Binary files, mixed line endings, and hard links are refused. UTF-8 BOM and uniform LF/CRLF/CR endings are preserved.
- Saves check disk revisions and create verified private backups. Temporary backups may be cleared by the host and do not replace permanent backups. External writes can still race with saves; filesystem ACLs/extended attributes may not survive replacement.
- Saving does not validate code syntax. Unsaved document text is not restored after reload.
- Git requires the workspace root to match the repository root. No commits, resets, branch switching, or inline Git change bars are provided.

## Credits and support

Based on [Joseph Chuks’ PHP File Manager](https://github.com/JosephChuks/php-file-manager-with-code-editor) and [CWP Code Editor](https://github.com/JosephChuks/cwp-codeEditor). Powered by Ace. Independent of Microsoft; VS Code extensions are not supported.

[Credits](CREDITS.md) · [License](LICENSE) · [Third-party notices and upstream license details](THIRD_PARTY_NOTICES.md)

Bugs and requests: [GitHub Issues](https://github.com/Renat2985/pocket-code-studio/issues). Installation and custom development: [Renat2985](https://github.com/Renat2985).
