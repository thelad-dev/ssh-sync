# Plan: Release v0.1.5

- Annahme: https://github.com/thelad-dev/ssh-sync/pull/14 (Portal-Importmap unter CSP) ist auf `origin/main` gemerged; Tag `v0.1.5` fehlt noch; Release-Workflow signiert keyless per OIDC; produktive Instanz bleibt unangetastet.
- Zwei Wege: (A) Tag direkt auf `origin/main` setzen und nur diesen Tag pushen, dann Verifikation und Report; (B) zusaetzlichen Version-Bump-Commit auf Feature-Branch mergen und erst danach taggen. Ich nehme A, weil die Spec Tag auf Kopf von main verlangt und Merge durch den Worker verboten ist.
- Ablehnung: Tag auf falschem Commit; Force-Push oder Verschieben bestehender Tags bei Workflow-Fehler; Anfassen der produktiven Instanz; Release-Notizen mit Rollenwoertern, Klarnamen oder internen Hostnamen.
- Nachweis: lokale Docker-Tests (`go test`/`go vet` mit Go laut go.mod), gruene CI auf main, Release-Workflow gruen, Artefakte + `cosign verify-blob`, Browser-Check Portal ohne CSP-Konsolenfehler, Installer-Skript unter Debian mit mawk ohne cosign.
- Grenze: keine Aenderung an der produktiven Instanz; Tag `v0.1.4` bleibt; kein Force; keine weiteren Tags; Worktree am Ende clean (Report unter `data/...`).
