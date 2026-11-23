# Plan: Release v0.1.8

- Annahme: https://github.com/thelad-dev/ssh-sync/pull/20 (verwalteter SSH-Config-Block am Dateiende) ist auf `origin/main` gemerged; Tag `v0.1.8` fehlt noch; Release-Workflow signiert keyless per OIDC; produktive Instanz bleibt unangetastet; v0.1.7 bleibt bestehen.
- Zwei Wege: (A) Tag direkt auf `origin/main` setzen und nur diesen Tag pushen, dann Verifikation, Wegwerf-Container-Test und Report-PR; (B) zusaetzlichen Version-Bump-Commit auf Feature-Branch mergen und erst danach taggen. Ich nehme A, weil die Spec Tag auf Kopf von main verlangt und Merge durch den Worker verboten ist.
- Ablehnung: Tag auf falschem Commit; Force-Push oder Verschieben bestehender Tags bei Workflow-Fehler; Anfassen der produktiven Instanz; Release-Notizen mit Rollenwoertern, Klarnamen oder internen Hostnamen; leerer Report-PR ohne Nachweis.
- Nachweis: lokale Docker-Tests (`go test`/`go vet` mit Go laut go.mod), gruene CI auf main, Release-Workflow gruen, Artefakte + `cosign verify-blob`, Wegwerf-Container Debian/openssh-client ohne cosign mit `pull --apply` und stabilem `ssh -G` fuer lokale Hosts, Report unter `data/...`.
- Grenze: keine Aenderung an der produktiven Instanz; Tag v0.1.7 bleibt; kein Force; keine weiteren Tags; Worktree am Ende clean ausser Report-/Plan-Commit auf `fm/ssh-sync-release-v018-20261123`.
