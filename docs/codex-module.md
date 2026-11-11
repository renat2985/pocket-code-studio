# Optional Codex module

Copy `modules/codex.php` from the project repository into a `modules` folder beside the editor. Sign in and open **Tools → Codex**. Enter the absolute project folder and an existing writable history folder outside the site's web root and the project. On a hosting account with several sites, use **Add site** for each site and select its own project folder. Use the **Site** dropdown to switch between settings and update histories. Sites can share a private history folder because the module creates a separate subfolder for each project. Existing single-site settings appear as the first profile. All profiles use the same API URL, and each token selects its own project. Put the history folder outside all public site roots.

Save the settings and copy the generated token to your local secret store. Saving the same project keeps the token. **Replace token** or changing the project invalidates the old token. The module stores its hash in the generated `modules/.codex-settings.php` and keeps the latest ten updates per project in a private subfolder of the selected history folder. Keep the settings file out of source control. Use the same history folder and module path to retain access to the history. Open an update by its description to see its changed files and their before/after comparison.

## Connect a local client

Use the HTTPS endpoint provided in **Instructions for the Codex chat**, with the site's scheme and hostname. Send JSON in a POST with the header `X-PCS-Token: <token>` using the raw token. The API also accepts `Authorization: Bearer <token>` on hosts that forward it to PHP. Keep the token in an environment variable or secret store and avoid printing it in chat or logs.

| Action | JSON fields |
| --- | --- |
| `read` | `path`, relative to the configured project. Returns `content` and its SHA-256 `hash`. Both are null for a missing file. |
| `pending` | Lists files saved in the workspace editor and awaiting local sync. |
| `ack_sync` | Send `path` and the SHA-256 `hash` after saving the server version locally. An outdated hash returns a conflict and keeps the mark. |
| `status` | No additional fields. Verifies the token and returns the server time in `checked_at`. |
| `modified` | `since`, a Unix timestamp in seconds (defaults to 24 hours ago), and optional project-relative `folder`. Returns `checked_at` and candidate files with path, modification time and byte size. |
| `changes` | `paths`, an object mapping up to 200 relative paths to previously read hashes or null. Returns paths whose current hashes differ. |
| `check` | `files`, an array of objects with `path`, `expected` (the previous hash or null for a new file), and `content`. Returns the paths that would change. |
| `apply` | Same `files` plus a one-line `description` of up to 100 characters. Rechecks the hashes and returns recorded files and any write errors. |

For example, given `PCS_CODEX_URL` and `PCS_CODEX_TOKEN` in your shell:

```sh
curl --fail-with-body "$PCS_CODEX_URL" \
  -H "X-PCS-Token: $PCS_CODEX_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"action":"read","path":"index.php"}'
```

Before editing, use `read` or `changes` to detect server edits and integrate them locally. Keep the server hashes used as the base, then send `check` before `apply`. If a request reports a conflict or partial write, read the affected files again before retrying. Use `modified` to discover files to check between tasks. Store the returned server `checked_at` locally after reviewing the candidates and use it as the next `since`. The scan includes files with timestamps equal to `since`, so a boundary file may appear twice. Compare hashes with `read` or `changes` to confirm content differences. The scan skips hidden paths, symlinks, and files above 1 MiB. It returns an error if it exceeds 15,000 directory entries or 500 candidates. Narrow the folder or time range if needed. Deletions and changes that preserve older timestamps require checking known paths with `changes`.

Updates support adding and replacing files up to 1 MiB, with up to 50 files and 50 MiB of combined before/after data per batch. Send binary files with `"encoding":"base64"` and base64-encoded `content`. Binary reads return the same encoding marker. Hashes cover the original bytes. History shows binary file names and sizes. Parent directories must exist. Hidden paths, symlinks, and the configured editor and module files are excluded. A conflict during preflight rejects the batch. A write error during deployment stops the batch and reports which earlier files were recorded. Keep a separate backup if you need restoration or history beyond ten deployments.

## Add other modules

A trusted PHP file named with lowercase letters, digits, and hyphens in `modules/` appears in Tools. The editor requires it only when an authenticated user visits `?module=<name>`. A module can provide its own launcher by declaring `@workspace-launcher` in its first 256 bytes and serving JavaScript for the authenticated `?module=<name>&launcher=1` request. Bind the launcher to the menu link with the corresponding `data-module` value. The optional workspace dialog can use `data-workspace-module` for the shared folder picker and file-opening hooks. Module pages can use the editor theme through `$workspaceThemeScript`. POST requests through the editor use the normal CSRF token. A module with a direct endpoint must implement its own authorization, as Codex does. Install only PHP modules you trust to run with the editor's permissions.

## Connect Codex

When you create or replace a token in Tools → Codex, the **Codex desktop or CLI** dialog opens. Click **Copy instructions**, then paste the text into your private Codex chat. The text includes the API URL and token and asks Codex to save them locally outside the repository. For a fresh connection after closing the window, use **Replace token**. It invalidates the previous token.
