# Plan: Sigstore keyless Verifikation (Worker V)

## Annahme
- Manifest-Format bleibt vorerst kompatibel (`version` + `assets`), Bundle-Datei heisst `manifest.json.sigstore.json`.
- Worker W/I liefern Signatur und Installer spaeter; Client muss fail-closed gegen Bundle pruefen.
- `AllowDowngrade` ist die explizite Option fuer Downgrade-Schutz-Ausnahme.

## Zwei Wege
1. Auftrag: sigstore-go Verifier + identity.go Konstanten + Ed25519 entfernen.
2. Alternative: cosign CLI wrapper (nicht im Binary, schlechter Offline).

Gewaehlt: Weg 1. Weg 2 gelassen weil Client eingebettet offline pruefen muss.

## Ablehnung
- Unvollstaendige Identitaetspruefung (nur Issuer ohne Subject-Regex).
- Canonical-JSON-Signing beibehalten obwohl Bundle ueber Rohbytes signiert.
- Public-Key-Reste die API/Installer noch erwarten (Worker I raeumt das; wir entfernen nur unseren Bereich, aber Export-API entfernen wenn nur Ed25519).

## Nachweis
`docker run --rm -v <worktree>:/src -w /src golang:1.26 sh -c 'go vet ./... && go test ./...'`

## Grenze
Nicht anfassen: Workflows, scripts/, Makefile, install_scripts, README/docs Install, web/.
