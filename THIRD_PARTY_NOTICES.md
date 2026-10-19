# Third-party notices

## Original file manager

Source: https://github.com/JosephChuks/php-file-manager-with-code-editor

Original author: Joseph Chuks. The upstream README states that the project is MIT-licensed and references `LICENSE`. On 2026-10-14 the repository root and GitHub license endpoint did not supply that file. This repository retains the attribution and records the declared license, but does not claim that its new LICENSE file is an upstream original. Confirm the missing upstream notice with the original author before relying on it for redistribution decisions.

## Original CWP Code Editor

Source: https://github.com/JosephChuks/cwp-codeEditor

MIT License, Copyright (c) 2024 Joseph Chuks. The verified original license is preserved verbatim in [docs/CWP-EDITOR-LICENSE.txt](docs/CWP-EDITOR-LICENSE.txt), and in the application source so single-file deployments retain it.

## Embedded icon assets

Material Icon Theme: MIT, Copyright (c) 2025 Material Extensions. Source revision `13025adc5ad10a5cc649528a2c1edec93069f1b9`. Full license is embedded immediately before `$materialIconData` in `filemanager.php`.

Seti UI: MIT, Copyright (c) 2014 Jesse Weed. Original notice is embedded with the Seti data in `filemanager.php`.

## CDN components

Ace, Prettier, its PHP plugin, Bootstrap, Font Awesome, CoolAlert (`coolalertjs`), and HTMX remain third-party dependencies with their respective upstream licenses. Their inclusion does not transfer ownership to Pocket Code Studio. Font Awesome uses different licenses for icons, fonts, and code. Consult each version's upstream license and notices when redistributing or vendoring CDN assets.

Visual Studio Code and related marks belong to their respective owners. No Microsoft product logos are used for this project's branding.

## Embedded dark theme palettes

- Tokyo Night: MIT, Copyright (c) 2018-present Enkia. Source: https://github.com/enkia/tokyo-night-vscode-theme. Original license: [docs/TOKYO-NIGHT-LICENSE.txt](docs/TOKYO-NIGHT-LICENSE.txt).
- Night Owl: MIT, Copyright (c) 2018 Sarah Drasner. Source: https://github.com/sdras/night-owl-vscode-theme. Original license: [docs/NIGHT-OWL-LICENSE.txt](docs/NIGHT-OWL-LICENSE.txt).
- Ayu Dark: MIT, Copyright (c) 2016 Ike Kurghinyan. Source: https://github.com/ayu-theme/vscode-ayu. Original license: [docs/AYU-DARK-LICENSE.txt](docs/AYU-DARK-LICENSE.txt).

These are embedded Ace/workspace adaptations of upstream palettes. Full notices are also included in `filemanager.php` for single-file deployment.

## QR code generation

Embedded qrcode-generator 1.4.4 by Kazuhiko Arase (MIT). Source: https://github.com/kazuhikoarase/qrcode-generator. License: [docs/QRCODE-GENERATOR-LICENSE.txt](docs/QRCODE-GENERATOR-LICENSE.txt). QR codes are generated locally in the browser.
