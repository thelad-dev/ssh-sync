# Release-Signierung

Agent-Updates und Installer vertrauen nur einem **Ed25519**-Public-Key, der im Binary bzw. Install-Skript eingebettet ist. Es gibt keinen Produktionsschluessel im Repository.

## Schluessel erzeugen (Captain, offline)

```bash
# Seed ausserhalb des Repos (0600). Standard: ~/ssh-sync-release.seed
./scripts/gen-release-key.sh ~/ssh-sync-release.seed
```

Das Skript (via `cmd/genreleasekey`) schreibt den privaten Seed, gibt den oeffentlichen Schluessel als 64 Hex-Zeichen aus und druckt eine fertige Zeile fuer `internal/releaseverify/release_ed25519.pub` sowie den Befehl zum Setzen des Secrets.

```bash
# Public Key eintragen (eine Hex-Zeile, Kommentare erlaubt)
# internal/releaseverify/release_ed25519.pub

# Secret fuer GitHub Actions (Inhalt nie loggen)
gh secret set RELEASE_SIGNING_KEY < ~/ssh-sync-release.seed
```

Private Keys niemals committen, nicht in CI-Logs drucken, zweite Kopie offline verwahren. Fingerabdruck (`fingerprint_sha256` aus dem Skript) im Release-Text nennen.

Schritt-fuer-Schritt inklusive Tag und Entwurf: [docs/release.md](release.md).

## Manifest bauen und signieren

Nach dem Build der Agent-Binaries (z. B. in `downloads/` oder CI `dist/`):

```bash
go run ./cmd/signrelease -version 1.2.3 -dir downloads -key ~/ssh-sync-release.seed
go run ./cmd/signrelease -verify -dir downloads
```

Schreibt kanonisches `manifest.json` und `manifest.sig`. `-verify` prueft Signatur und Asset-Hashes gegen den eingebetteten Public Key.

Docker-Build:

```bash
docker build \
  --build-arg AGENT_VERSION=1.2.3 \
  --build-arg RELEASE_PRIVATE_KEY_HEX="$(cat ~/ssh-sync-release.seed)" \
  -t ssh-sync-api .
```

Ohne `RELEASE_PRIVATE_KEY_HEX` entstehen unsignierte Downloads; `ssh-sync update` und die Installer lehnen sie ab.

Der Workflow `.github/workflows/release.yml` signiert bei Tag `v*.*.*` mit dem Secret `RELEASE_SIGNING_KEY` und bricht ab, wenn die Verifikation gegen den eingebetteten Key fehlschlaegt.

## Client-Pruefung

- `ssh-sync update` laedt Manifest + Signatur + Asset, prueft Signatur, Version (muss groesser als lokal sein) und SHA-256; bei Nachpruefungsfehler Rollback auf `.old`.
- `http://` nur gegen Loopback oder mit `--insecure` / `SSH_SYNC_ALLOW_INSECURE=1`.
- Installer: Skript speichern und lesen; openssl prueft die Manifest-Signatur, `sha256sum` den Asset-Hash.

## Migration bestehender Installationen

1. Public Key einbetten und neu bauen.
2. Signiertes Manifest auf dem Portal bereitstellen.
3. Geraete einmalig mit dem neuen Binary versorgen (erster Schritt noch ueber vertrauenswuerdigen Kanal), danach `ssh-sync update`.
4. macOS: LaunchAgent-Label ist jetzt `com.ssh-sync.ssh-sync`. Alte private Labels manuell per `launchctl bootout` entfernen.
