# Release-Ablauf

Voraussetzungen: Schreibrecht am Repo, `gh` authentifiziert, Go laut `go.mod`.

## 1. Schluessel erzeugen (einmalig, offline)

Auf einem vertrauenswuerdigen Rechner, nicht auf dem Produktivhost:

```bash
./scripts/gen-release-key.sh ~/ssh-sync-release.seed
```

- Seed-Datei mit Rechten 0600 ausserhalb des Repos; zweite Kopie offline sichern.
- Niemals committen, niemals in Logs drucken.
- Ausgabe `public_key_hex` / Fingerabdruck notieren.

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

Der Workflow `release` baut Linux (amd64, arm64), Windows (amd64), macOS (amd64, arm64) mit `-trimpath` und `CGO_ENABLED=0`, erzeugt `SHA256SUMS`, signiert das Manifest keyless mit Cosign/Sigstore, verifiziert das Bundle und legt einen **Entwurf** eines GitHub-Releases an (nicht veroeffentlicht). Die Herkunftsattestierung (`actions/attest-build-provenance`) laeuft nur, wenn das Repository oeffentlich ist; bei privaten Benutzer-Repos ueberspringt der Workflow diesen Schritt, weil die Attestations-API dort nicht verfuegbar ist. Cosign-Signatur und Draft-Release bleiben davon unabhaengig.

## 5. Entwurf pruefen

Im GitHub-UI den Draft-Release oeffnen:

- Alle Binaries (fuenf Plattformen plus Windows-Zip), `SHA256SUMS`, `manifest.json`, `manifest.json.sigstore.json` vorhanden.
- Optional lokal: Assets laden und das Sigstore-Bundle mit Cosign gegen die bekannte Workflow-Identitaet pruefen (siehe [release-signing.md](release-signing.md) bzw. `internal/releaseverify`).

## 6. Veroeffentlichen

Erst nach erfolgreicher Pruefung den Draft im UI auf "Publish release" setzen. Kein Force-Push am Tag.

## 7. Update-Test auf einem Client

1. Agent mit aelterer Version und dem neuen Public Key installieren (oder Portal-Downloads nutzen).
2. `ssh-sync update` ausfuehren.
3. Erwartung: Manifest-Signatur und SHA-256 ok, Binary aktualisiert, bei Fehler Rollback.

Details zur Signatur: [release-signing.md](release-signing.md).
