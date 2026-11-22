# Release-Ablauf

Voraussetzungen: Schreibrecht am Repo, `gh` authentifiziert, Go laut `go.mod`. Signierung laeuft keyless ueber Sigstore im Workflow; kein Release-Signing-Secret und kein eingebetteter Ed25519-Release-Key.

## 1. Voraussetzungen auf main

- Aenderungen sind per PR auf `main` gemerged.
- CI auf dem Ziel-Commit ist gruen.
- Vertrauenswuerdige Identitaet und Verifikation: [release-signing.md](release-signing.md) bzw. `internal/releaseverify/identity.go`.

## 2. Tag setzen

Nur einen Commit taggen, der bereits auf `main` liegt und dessen CI gruen war:

```bash
git checkout main
git pull
git tag -a v0.1.0 -m "ssh-sync v0.1.0"
git push origin v0.1.0
```

Der Workflow `release` baut Linux (amd64, arm64), Windows (amd64), macOS (amd64, arm64) mit `-trimpath` und `CGO_ENABLED=0`, erzeugt `SHA256SUMS`, erstellt `manifest.json` (`cmd/mkmanifest`), signiert das Manifest keyless mit Cosign/Sigstore, verifiziert das Bundle und legt einen **Entwurf** eines GitHub-Releases an (nicht veroeffentlicht). Die Herkunftsattestierung (`actions/attest-build-provenance`) laeuft nur, wenn das Repository oeffentlich ist; bei privaten Benutzer-Repos ueberspringt der Workflow diesen Schritt, weil die Attestations-API dort nicht verfuegbar ist. Cosign-Signatur und Draft-Release bleiben davon unabhaengig.

## 3. Entwurf pruefen

Im GitHub-UI den Draft-Release oeffnen:

- Alle Binaries (fuenf Plattformen plus Windows-Zip), `SHA256SUMS`, `manifest.json`, `manifest.json.sigstore.json` vorhanden.
- Lokal: Assets laden und das Sigstore-Bundle mit Cosign gegen die bekannte Workflow-Identitaet pruefen (siehe [release-signing.md](release-signing.md)).

## 4. Veroeffentlichen

Erst nach erfolgreicher Pruefung den Draft im UI auf "Publish release" setzen. Kein Force-Push am Tag.

## 5. Update-Test auf einem Client

1. Agent mit aelterer Version installieren (oder Portal-Downloads bzw. GitHub-Release nutzen).
2. `ssh-sync update` ausfuehren.
3. Erwartung: Sigstore-Verifikation und SHA-256 ok, Binary aktualisiert, bei Fehler Rollback.

Details zur Signatur und zum Bedrohungsmodell: [release-signing.md](release-signing.md).
