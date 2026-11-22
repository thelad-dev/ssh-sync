# Vendored Portal-Krypto

Quellen (offline im Repo, keine Laufzeit-CDN-Abhaengigkeit):

| Paket | Version | Einstieg |
|-------|---------|----------|
| hash-wasm | 4.12.0 | `hash-wasm/index.esm.js` |
| @noble/curves | 1.8.1 | `noble-curves/esm/ed25519.js` |
| @noble/hashes | 1.7.1 | `noble-hashes/esm/*` (Abhaengigkeit von curves) |

Integritaet (SHA-256 der Einstiegsdateien): siehe `SHA256SUMS` in diesem Verzeichnis.

Aktualisieren: `npm pack` der festen Versionen, Dateien ersetzen, `SHA256SUMS` neu erzeugen.
