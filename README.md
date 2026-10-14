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
| Appearance | Theme Mix, One Dark, Nord Dark, Tomorrow variants, Cobalt, Monokai, Dracula, GitHub variants, Kuroir; themed menus, popups, and scrollbars |
| Icons | Embedded Material Icon Theme SVGs for common file types and named folders; embedded Seti fallback icons |
| File operations | Create, rename, copy, move, upload, download, trash/restore, permissions, compression/extraction where server capabilities permit |
| Git | `M` modified, `U` untracked, `A` added; comparison against HEAD including unsaved editor text; added/deleted lines highlighted in a dialog |
| Authentication | Password hash in the PHP file; change password through Settings; protected requests; CSRF tokens; session expiry; login attempt limits |

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

Use **File → Save** or Ctrl/⌘ S to save, **Edit → Find / Replace** to search, and **View** to toggle the minimap or word wrap. Formatting is an explicit **Tools → Format document** action; saving does not automatically format code. Language and font size are selected in the bottom status bar.

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
