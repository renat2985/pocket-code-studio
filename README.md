# Pocket Code Studio

**Your server files. A familiar coding workspace. One PHP file.**

A self-hosted PHP file manager and browser-based code editor with a Visual Studio Code-inspired interface. Upload `filemanager.php`, sign in and change the initial password, and manage your website through your browser.

[Русская версия](README.ru.md) · [Setup](#quick-start) · [Security](#security-and-file-saving) · [Credits](CREDITS.md) · [Report an issue](https://github.com/Renat2985/pocket-code-studio/issues)

![Pocket Code Studio — file explorer and code editor](screenshots/screen.png)

## Why Pocket Code Studio?

- **One application file:** no database, Composer, Node.js build, or application installation wizard.
- **Familiar workspace:** file tree, internal tabs, compact File / Edit / View / Tools / Help menus, minimap, and status bar.
- **Themes across the interface:** editor, file list, menus, dialogs, and scrollbars follow the selected palette.
- **Careful file saving:** revision checks, verified writes, and a private backup before replacing an edited file.
- **Read-only Git tools:** see changed files and compare editor text with the latest commit.

The application is independent of Microsoft. It uses Ace, not the Visual Studio Code engine, and does not run VS Code extensions.

## Features

| Area | Included |
| --- | --- |
| Workspace | Internal editor tabs; unsaved indicators and discard confirmation; tab/order/active-file restoration with cursor and scroll position in a bounded cookie |
| Explorer | Expandable folders; resizable sidebar with width stored in a cookie; file search, sorting, selection, context menus |
| Editing | Syntax highlighting; language selection in the status bar; font size; undo/redo; find/replace; word wrap; copy document text; formatting for supported languages |
| Navigation | Syntax-colored minimap with click/drag navigation; selected-text occurrence markers; keyboard shortcuts |
| Appearance | Theme Mix, Tokyo Night, Night Owl, Ayu Dark, One Dark, Nord Dark, Tomorrow variants, Cobalt, Monokai, Dracula, GitHub variants, Kuroir; themed menus, popups, and scrollbars |
| Icons | Embedded Material Icon Theme SVGs for common file types and named folders; embedded Seti fallback icons |
| File operations | Create, rename, copy, move, upload, download, trash/restore, permissions, compression/extraction where server capabilities permit |
| Git | `M` modified, `U` untracked, `A` added; comparison against HEAD including unsaved editor text; added/deleted lines highlighted in a dialog |
| Authentication | Password hash in the PHP file; change password through Settings; protected requests; CSRF tokens; session expiry; login attempt limits |
| Mobile | Full-width explorer/editor switching; compact menu; open-file selector; hideable code shortcut row; keyboard-aware viewport |

## Requirements

- PHP **7.4+** with sessions and standard filesystem/hash/JSON functions; a maintained PHP release is recommended.
- Apache, Nginx, or another PHP-capable server. HTTPS is required except for loopback development.
- A writable workspace and private writable PHP temporary/session storage.
- Internet access in the browser for the current CDN-loaded JavaScript/CSS dependencies. **Single-file deployment does not mean fully offline.**
- Optional: Git on the server PATH and enabled PHP `proc_open` for Git status/comparison.
- Optional: archive extensions/tools appropriate to the archive format. Availability depends on the host.

## Quick start

1. Download `filemanager.php` from this repository. It is the **only application file** to upload.
2. The initial password is **`admin123`**. Sign in and immediately change it through **File → Settings → Change password** before making the manager publicly accessible. The file stores a hash, not the plain password. There is no username field.

   For a unique password before deployment, generate a hash locally and replace `$authPasswordHash` near the beginning of the PHP file:

   ```sh
   php -r 'echo password_hash(readline("New password (input is visible): "), PASSWORD_DEFAULT), PHP_EOL;'
   ```

   Do not commit your personal deployment hash to the public repository.

3. Review `$config['root_path']`. By default it uses the web server document root. Restrict it to the directory you intend to administer.
4. Upload the configured PHP file. Grant the web-server account only the filesystem access it needs.
5. Open it over HTTPS and sign in with the password used in step 2.

On Apache/Nginx TLS deployments, PHP must receive the correct `HTTPS=on` server setting. Arbitrary client forwarding headers are not trusted.

Local development example, with the initial password or your own configured password:

```sh
php -S 127.0.0.1:8080
```

Open `http://127.0.0.1:8080/filemanager.php`. Change the password later through **File → Settings → Change password**. This requires the web-server account to be able to replace `filemanager.php`; failure leaves the previous password intact.

## Working with files

Expand folders in the left explorer and click a file to open an internal tab. Resize the sidebar by dragging its boundary. Tabs and cursor positions are restored after reload; **unsaved document contents are not stored in cookies**.

Use **File → Save** or Ctrl/⌘ S to save, **Edit → Find / Replace** to search, and **View** to toggle the minimap or word wrap. Formatting is an explicit **Tools → Format document** action; saving does not automatically format code. Language and font size are selected in the bottom status bar. Choose the interface theme under **View → Color theme**. File search is centered in the top bar; **Sign out** is at the far right.

## Saved settings

The timezone dropdown shows UTC offsets and a live time preview. The browser-detected timezone is offered through **Use browser timezone**, never applied automatically. Confirm the choice with **Save Settings**, or use **Cancel** to discard it.

Settings and the optional password change share one form and the **Cancel / Save Settings** buttons. Leave all password fields empty to keep the current password. If changing it, supply the current password and matching new passwords. All values are validated before a single configuration replacement; an invalid field leaves both settings and password unchanged. Cancel discards the form edits. Saving does not reload the workspace or discard open editor changes.

**File → Settings** stores the timezone, PHP date format, and interface font size directly in `filemanager.php`, alongside the password configuration. Values are held as base64-encoded JSON data, not executable PHP. Font size accepts 10px–32px; timezones and date formats are validated before saving.

Saving settings requires permission to replace the application file. Password and settings updates share a lock and use a verified private backup, checked temporary file, and atomic replacement. If writing fails, the original remains intact. Keep a separate copy of your personal settings and password configuration when upgrading the application.

Existing `.fm-config` files are read for compatibility until settings are saved in the PHP file. The next successful Settings save migrates the effective values into `filemanager.php`; no new `.fm-config` is created. The old file is left untouched and can be removed after confirming the migrated settings.

## Mobile layout

On screens up to 760 px wide, **Files** opens the full-width explorer, **List** opens the file table, and an editor tab fills the available width. The compact **☰** menu contains the existing actions, theme selector, and file search. Open files remain accessible through horizontal tabs and a dropdown; returning to the explorer preserves its scroll position.

Mobile editors default to word wrap and a hidden minimap; the mobile minimap preference is stored separately from the desktop preference. A hideable shortcut row provides Tab, outdent, braces, parentheses, undo, and redo. Use **⌨** to toggle it and **…** in the status bar to show additional editor settings. Viewport resize events adjust the workspace when the on-screen keyboard opens and keep the focused cursor in view. Dialogs and editor search fit the narrow layout. Desktop navigation remains available on wider screens.

## Git comparison

The configured workspace root must also be the Git repository root. File lists show status badges; open a file and choose **Tools → Git: View changes against HEAD** for a unified comparison with the latest commit, including unsaved text. New files are compared with an empty document.

This integration exposes **no stage, commit, checkout, reset, push, or pull actions**. If Git or `proc_open` is unavailable, file browsing still works and the comparison dialog displays an explanation. Parent repositories and inline change bars in the code gutter are not currently supported.

## Security and file saving

All access **through `filemanager.php`** requires authentication: listings, searches, downloads, uploads, editor reads, and writes. This deliberately leaves the ordinary public website public; direct URLs are governed by your web server configuration.

- The PHP file stores a `password_hash()` result. Sessions regenerate on login/password change; changing the password invalidates other sessions.
- Cookies use HttpOnly, SameSite=Strict, and Secure over HTTPS. Sessions expire after 30 minutes idle or 12 hours total.
- Every POST requires a session-bound CSRF token. Mutating requests via GET are refused. Login attempts are limited per address and globally.
- Saves verify the submitted byte count and SHA-256 disk revision. A revision conflict blocks replacement and leaves editor text available.
- Before replacing a changed file, a private backup is verified outside the web root. New bytes are written and verified in a sibling temporary file before rename. Editor saves are serialized.
- UTF-8 BOM and uniform LF/CRLF/CR endings are preserved. Binary/non-UTF-8 text, mixed line endings, hard links, and files above 8 MB are refused by the editor.

Private runtime backups are stored under `sys_get_temp_dir()/fm-editor-<workspace hash>/`; authentication state uses a separate private temporary directory. Hosts may clean temporary storage. These backups are **not a substitute for permanent backups**. External writers that ignore the editor lock can still race with replacement; filesystem-specific ACLs and extended attributes may not survive replacement. Saving does not validate the syntax of your code.

## Dependencies and licensing

Ace, Prettier and its PHP plugin, Bootstrap, Font Awesome, CoolAlert, and HTMX currently load from CDNs. Icons and their associations are embedded. Attribution and license details are in [CREDITS.md](CREDITS.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Pocket Code Studio additions are MIT-licensed; see [LICENSE](LICENSE). The original file-manager README declares MIT but its repository did not contain a separate license file when checked. That provenance limitation is documented in the notices rather than silently inventing an upstream license file.

## Support and contributions

Report reproducible issues and feature requests in [GitHub Issues](https://github.com/Renat2985/pocket-code-studio/issues). Never include passwords, session cookies, private file contents, or a configured deployment copy.

For installation help or custom development, contact [Renat2985](https://github.com/Renat2985). Pull requests are welcome; keep deployment to one PHP file and preserve existing file-saving and authentication protections.
