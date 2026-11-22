# Release-Signierung (H3)

Agent-Updates und Installer vertrauen nur einem **Ed25519**-Public-Key, der im Binary bzw. Install-Skript eingebettet ist. Es gibt keinen Produktionsschlüssel im Repository.

## Schlüssel erzeugen (Captain, offline)

```bash
# 32-Byte-Seed als Hex (Private Key Datei, 0600, offline verwahren)
openssl rand -hex 32 > release.ed25519.seed
chmod 600 release.ed25519.seed

# Public Key (64 Hex-Zeichen) ableiten und in
# internal/releaseverify/release_ed25519.pub eintragen (eine Zeile, ohne Kommentarpflicht).
# Dazu z. B. mit Go:
#   pub = ed25519.NewKeyFromSeed(seed)[32:]
```

Private Keys niemals committen, nicht in CI-Logs drucken, idealerweise auf einem getrennten Signatur-Rechner oder in einem HSM/Secrets-Store halten. Fingerabdruck des Public Keys im Release-Text nennen.

## Manifest bauen und signieren

Nach dem Build der Agent-Binaries in `downloads/`:

```bash
go run ./cmd/signrelease -version 1.2.3 -dir downloads -key release.ed25519.priv
```

Schreibt kanonisches `downloads/manifest.json` und `downloads/manifest.sig`.

Docker-Build:

```bash
docker build \
  --build-arg AGENT_VERSION=1.2.3 \
  --build-arg RELEASE_PRIVATE_KEY_HEX="$(cat release.ed25519.seed)" \
  -t ssh-sync-api .
```

Ohne `RELEASE_PRIVATE_KEY_HEX` entstehen unsignierte Downloads; `ssh-sync update` und die Installer lehnen sie ab.

## Client-Prüfung

- `ssh-sync update` lädt Manifest + Signatur + Asset, prüft Signatur, Version (muss größer als lokal sein) und SHA-256; bei Nachprüfungsfehler Rollback auf `.old`.
- `http://` nur gegen Loopback oder mit `--insecure` / `SSH_SYNC_ALLOW_INSECURE=1`.
- Installer: Skript speichern und lesen; openssl prüft die Manifest-Signatur, `sha256sum` den Asset-Hash.

## Migration bestehender Installationen

1. Public Key einbetten und neu bauen.
2. Signiertes Manifest auf dem Portal bereitstellen.
3. Geräte einmalig mit dem neuen Binary versorgen (erster Schritt noch über vertrauenswürdigen Kanal), danach `ssh-sync update`.
4. macOS: LaunchAgent-Label ist jetzt `com.ssh-sync.ssh-sync`. Alte private Labels manuell per `launchctl bootout` entfernen.
