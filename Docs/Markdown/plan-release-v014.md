# Plan: Release v0.1.4

## Annahme
- PR https://github.com/thelad-dev/ssh-sync/pull/12 ist auf origin/main gemerged; HEAD 05a7ce1 ist der Merge.
- Definition of done (direct-PR) meint hier den Nachweis-/Report-Pfad bzw. ggf. keine Code-Aenderung; das eigentliche Ship ist Tag v0.1.4 + report.md. Wenn nach Tag/Verify nichts commitbar ist, Report ausserhalb und Status klaeren statt leeren PR.

## Zwei Wege
1. Auftrag: Tag auf Kopf von main setzen, nur Tag pushen, Workflow beobachten, Release + Installer verifizieren, report.md schreiben.
2. Alternativ (nicht Auftrag): GitHub Release UI manuell / soft-tag auf anderen Commit — lasse ich, weil Spec Tag auf main-Kopf und OIDC-Release-Workflow verlangt.

Wahl: Weg 1.

## Ablehnung
- Tag auf veraltetem lokalen main statt origin/main.
- Force-push oder Verschieben bestehender Tags bei Workflow-Fehler.
- Anfassen der produktiven Instanz auf Docker-01.
- cosign vorinstalliert im Installer-Test-Container (muss selbst beschaffen).

## Nachweis
- gh-axi: PR12 in main, CI auf main gruen
- docker: go test ./... und go vet (Go laut go.mod 1.26)
- Tag v0.1.4 == origin/main HEAD, nur dieser Tag gepusht
- Release-Workflow success; Artefakte + cosign verify-blob
- Wegwerf-Container: Installer beschafft cosign, prueft, installiert; manipulierte Pruefsumme bricht ab

## Grenze
- Keine Aenderung an produktiver Instanz; v0.1.3-Tag bleibt; kein Force; keine weiteren Tags; Worktree am Ende clean (Report unter data/...).
