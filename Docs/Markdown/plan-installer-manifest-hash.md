# Plan: Installer Manifest-Hash unter mawk

- Annahme: Debian/BusyBox-Installer nutzen mawk; `{64}` in awk-ERE ist dort kein Quantifier, deshalb liefert `hash_from_manifest` leer obwohl das Manifest korrekt ist. PowerShell-Installer ist nicht betroffen.
- Zwei Wege: (A) awk-Regex portabel machen (`[0-9a-fA-F]+` + `length==64`) und Erfolgspfad-Test mit eingeruecktem mkmanifest-Format ergaenzen; (B) Parser auf `sed`/`python` umstellen. Ich nehme A (klein, gleiche Struktur), lasse B (groesserer Umbau).
- Ablehnung: Kollege wuerde ablehnen, wenn nur Golden geaendert wird ohne Test, der unter dem System-awk den Erfolgspfad absichert, oder wenn das bereits veroeffentlichte Tag stillschweigend bewegt wird.
- Nachweis: `go test ./internal/api/ -count=1` in `golang:1.26-bookworm`; Wegwerf-Container `debian:bookworm-slim` mit cosign gegen Release-URL (nach Merge/Tag) bzw. lokal gegen gefixtes Skript + heruntergeladene Artefakte.
- Grenze: Kein Force auf Tags, kein Deploy auf Produktionsinstanz/Geraete, Windows-PS1 unangetastet sofern Regex dort greift, Release-Workflow unangetastet.
