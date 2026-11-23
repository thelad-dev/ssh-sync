# Plan: Release v0.1.6

- Annahme: https://github.com/thelad-dev/ssh-sync/pull/16 (kein Ueberschreiben von Config/Keys) ist auf `origin/main` gemerged; Tag `v0.1.6` fehlt noch; Release-Workflow signiert keyless per OIDC; produktive Instanz bleibt unangetastet; v0.1.4 und v0.1.5 bleiben bestehen.
- Zwei Wege: (A) Tag direkt auf `origin/main` setzen und nur diesen Tag pushen, dann Verifikation, Wegwerf-Container-Test und Report-PR; (B) zusaetzlichen Version-Bump-Commit auf Feature-Branch mergen und erst danach taggen. Ich nehme A, weil die Spec Tag auf Kopf von main verlangt und Merge durch den Worker verboten ist.
- Ablehnung: Tag auf falschem Commit; Force-Push oder Verschieben bestehender Tags bei Workflow-Fehler; Anfassen der produktiven Instanz; Release-Notizen mit Rollenwoertern, Klarnamen oder internen Hostnamen; leerer Report-PR ohne Nachweis.
- Nachweis: lokale Docker-Tests (`go test`/`go vet` mit Go laut go.mod), gruene CI auf main, Release-Workflow gruen, Artefakte + `cosign verify-blob`, Wegwerf-Container Debian/mawk ohne cosign mit `pull --dry-run`/`--apply` und Installer, Report unter `data/...`.
- Grenze: keine Aenderung an der produktiven Instanz; Tags v0.1.4 und v0.1.5 bleiben; kein Force; keine weiteren Tags; Worktree am Ende clean ausser Report-/Plan-Commit auf `fm/ssh-sync-release-v016-20261123`.
