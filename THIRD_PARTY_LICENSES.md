# Third-party licenses

This file lists third-party components shipped with or linked by ssh-sync.
Project license: Apache-2.0 (see LICENSE and NOTICE).

## Vendored portal libraries (`web/vendor/`)

| Component | Version | License | Location |
|-----------|---------|---------|----------|
| hash-wasm | 4.12.0 | MIT | `web/vendor/hash-wasm/` |
| @noble/curves | 1.8.1 | MIT | `web/vendor/noble-curves/` |
| @noble/hashes | 1.7.1 | MIT | `web/vendor/noble-hashes/` |

Full license texts are in each package `LICENSE` file. See also `web/vendor/VENDOR.md`.

## Go module dependencies (direct)

| Module | Version | License |
|--------|---------|---------|
| github.com/golang-jwt/jwt/v5 | v5.2.2 | MIT |
| github.com/kardianos/service | v1.2.2 | Zlib |
| github.com/mattn/go-sqlite3 | v1.14.53 | MIT |
| github.com/zalando/go-keyring | v0.2.6 | MIT |
| golang.org/x/crypto | v0.59.0 | BSD-3-Clause |
| golang.org/x/term | v0.48.0 | BSD-3-Clause |

## Go module dependencies (indirect, selected)

| Module | Version | License |
|--------|---------|---------|
| al.essio.dev/pkg/shellescape | v1.5.1 | MIT |
| github.com/danieljoos/wincred | v1.2.2 | MIT |
| github.com/godbus/dbus/v5 | v5.1.0 | BSD-2-Clause |
| golang.org/x/sys | v0.50.0 | BSD-3-Clause |

Exact versions follow `go.mod` / `go.sum`. License classification is based on upstream LICENSE files at the pinned versions.
