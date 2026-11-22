# Branch-Schutz und Release-Verifikation (M6)

Für das öffentliche oder geteilte Repo (z. B. `ssh-sync`) vor dem ersten Merge auf `main`:

## GitHub-Einstellungen

1. **Ruleset oder Branch protection** auf `main`:
   - Pull Request erforderlich
   - mind. ein Review
   - Conversation resolution erforderlich
   - signierte Commits erforderlich (empfohlen)
   - kein Force-Push, kein Löschen von `main`
2. **CODEOWNERS** ist unter `.github/CODEOWNERS` hinterlegt; Owner-Review für kritische Pfade erzwingen.
3. **Secret Scanning** und **Push Protection** einschalten.
4. **Dependabot** Alerts + Security Updates.
5. **Private Vulnerability Reporting** einschalten (`SECURITY.md`).
6. Wiki und Discussions aus, wenn nicht benötigt.
7. Actions: Standard `permissions: contents: read`; Actions per Commit-SHA pinnen (siehe `.github/workflows/ci.yml`); kein `pull_request_target`.

## Deploy

- Nicht automatisch von `main`-HEAD auf den Tresor-Host ausrollen.
- Nur signierte Tags oder geprüfte Commits bauen (`docs/release-signing.md`).
- AI-/Agent-Regeldateien in PRs immer manuell prüfen (Prompt-Injection).

## Release-Checkliste

- [ ] `manifest.json` + `manifest.sig` veröffentlicht
- [ ] Public-Key-Fingerabdruck im Release-Text
- [ ] CI grün
- [ ] Keine privaten Hostnamen, Domains oder Pfade in Diff/Docs
