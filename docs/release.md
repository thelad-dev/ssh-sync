# Release-Ablauf

Voraussetzungen: Schreibrecht am Repo, `gh` authentifiziert. Fuer Builds und Signieren: Go laut `go.mod`. Fuer das einmalige Erzeugen des Release-Seeds reicht auch Docker oder OpenSSL 3 (siehe unten).

## 1. Schluessel erzeugen (einmalig, offline)

Auf einem vertrauenswuerdigen Rechner, nicht auf dem Produktivhost:

```bash
./scripts/gen-release-key.sh ~/ssh-sync-release.seed
```

`scripts/gen-release-key.sh` waehlt automatisch:

1. Lokales Go >= Version aus `go.mod` (`go run ./cmd/genreleasekey`)
2. Sonst Docker-Image `golang:<go.mod>` (Repo read-only, Seed-Verzeichnis als eigener Mount, `--user` wie der Aufrufer)
3. Sonst OpenSSL >= 3 (Ed25519 ohne Go, gleiches Seed-Dateiformat)
4. Sonst Fehler mit diesen drei Moeglichkeiten

Aeltere Go-Versionen (z. B. 1.19) sind kein Blocker, solange Docker oder OpenSSL 3 verfuegbar ist.

- Seed-Datei mit Rechten 0600 ausserhalb des Repos; zweite Kopie offline sichern. Bestehende Datei wird nicht ueberschrieben.
- Niemals committen, niemals in Logs drucken.
- Ausgabe `public_key_hex`, `fingerprint_sha256` und `fingerprint_short` (erste 16 Hex-Zeichen) notieren.

## 2. Secret setzen

```bash
gh secret set RELEASE_SIGNING_KEY < ~/ssh-sync-release.seed
```

## 3. Public Key eintragen

Die Hex-Zeile aus dem Skript nach `internal/releaseverify/release_ed25519.pub` schreiben (Kommentare erlaubt). Commit auf `main` (ueber PR), warten bis CI gruen ist.

## 4. Tag setzen

Nur einen Commit taggen, der bereits auf `main` liegt und dessen CI gruen war:

```bash
git checkout main
git pull
git tag -a v0.1.0 -m "ssh-sync v0.1.0"
git push origin v0.1.0
```

Der Workflow `release` baut Linux (amd64, arm64), Windows (amd64), macOS (amd64, arm64) mit `-trimpath` und `CGO_ENABLED=0`, erzeugt `SHA256SUMS`, signiert das Manifest, verifiziert die Signatur und legt einen **Entwurf** eines GitHub-Releases an (nicht veroeffentlicht). Zusaetzlich wird eine Build-Provenance-Attestierung erzeugt.

## 5. Entwurf pruefen

Im GitHub-UI den Draft-Release oeffnen:

- Alle Binaries, `SHA256SUMS`, `manifest.json`, `manifest.sig` vorhanden.
- Fingerabdruck des Public Keys im Release-Text nennen bzw. mit der lokalen Notiz abgleichen.
- Optional lokal: Assets laden und `go run ./cmd/signrelease -verify -dir <ordner>` gegen denselben eingebetteten Key.

## 6. Veroeffentlichen

Erst nach erfolgreicher Pruefung den Draft im UI auf "Publish release" setzen. Kein Force-Push am Tag.

## 7. Update-Test auf einem Client

1. Agent mit aelterer Version und dem neuen Public Key installieren (oder Portal-Downloads nutzen).
2. `ssh-sync update` ausfuehren.
3. Erwartung: Manifest-Signatur und SHA-256 ok, Binary aktualisiert, bei Fehler Rollback.

Details zur Signatur: [release-signing.md](release-signing.md).
