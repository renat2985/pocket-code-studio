# Changelog

Each ZIP contains the complete editor release. Entries describe changes from the preceding archived version; the oldest entry summarizes the baseline.

## 1.4.0

Archive: `pocket-code-studio-1.4.0.zip`

- Browse file history from Tools or a file's context menu, compare a saved copy inline, and restore it into the editor for review before saving.
- Compare open files, including unsaved edits, against Git HEAD inline. See Git status colors for changed files and folders in the file list and sidebar.
- Search filenames as you type, use wildcards, or prefix a query with `%` to search file contents and jump to a matching line.
- Remember the current folder and expanded sidebar folders per workspace. On mobile, open the file manager from Files and switch or close files from the tab selector.
- Check GitHub for a newer editor version and download the update when one is available.
- Connect multiple sites through the optional Codex module, each with its own token and deployment history. Copy setup instructions, upload text and binary files, and review changes and upload results.
- Show the latest Codex deployment and later edits in the file list and sidebar. Track editor saves and verified uploads awaiting sync, and pull those changes with the `sync` shortcut.

## 1.3.1

Archive: `pocket-code-studio-1.3.1.zip`

- Keep the sidebar file highlighted when opened from the tree, and clear that highlight when switching tabs.
- Show dates in day–month–year order with a two-digit day, and label recent file changes Today or Yesterday.
- Shorten long file and folder names in the file list while preserving ordinary file extensions and full names on hover.
- Add missing dialog title icons and use the active theme accent throughout.
- Use workspace date and time settings in login activity and show monochrome icons for allowed and blocked IPs.
- Match folder picker navigation icons to the file manager and align folder icons with their names.
- Use the theme accent for primary dialog actions and consistent styling for Cancel buttons.
- Sort the file list by clicking column headers; sort sizes and modification times by their raw values.
- Match Copy, Move, and file creation command icons to their dialog headers.
- Restore the New File icon and use the theme accent in both file and folder creation dialogs.
- Match the folder picker toolbar to the file manager with Home, Up, Reload and a path field, and remove the separate Website folder shortcut.
- Make update and GitHub dialogs easier to scan with shorter text and monochrome icons.
- Add action icons to modal and folder picker footer buttons, and emphasize folder picker actions with semibold labels.
- Use shared modal headers and footers in the folder picker.
- Add a close button to every modal header, including the folder picker.

## 1.3.0

Archive: `pocket-code-studio-1.3.0.zip`

- Show changes between the installed and uploaded versions in the update dialog.
- Keep manual updates available when GitHub release notes cannot be loaded.

## 1.2.0

Archive: `pocket-code-studio-1.2.0.zip`

- Click an M Git status badge in the file list, sidebar or GitHub Push dialog to view changes against HEAD.
- Compare unsaved editor content when the file is open, or saved file content otherwise, without opening another editor tab.

## 1.1.2

Archive: `pocket-code-studio-1.1.2.zip`

- Enable permanent deletion from Trash, with filenames and an explicit confirmation warning.
- Add Restore to the file context menu in Trash and show selected filenames in the restore dialog.

## 1.1.1

Archive: `pocket-code-studio-1.1.1.zip`

- Style file chooser buttons with the current theme, including hover and disabled states, instead of the default white Browse button.

## 1.1.0

Archive: `pocket-code-studio-1.1.0.zip`

- Introduce consistent application versioning in the PHP header and displayed version.
- Derive the release ZIP filename automatically from the application version.
- Make self-update regression tests independent of a fixed release number.

## 1.0.0

Archive: `pocket-code-studio-1.0.0.zip`

- Baseline single-file PHP workspace with file management, tabbed editing, Git integration and Ace themes.
- Includes manual editor updates with upload validation, configuration preservation, private backups and support for renamed installations.
- Includes temporary line bookmarks with clickable overview markers, Emmet for HTML, themed loading indicators and mobile status bar improvements.
