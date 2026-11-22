# Branch-Schutz und Release-Verifikation

Fuer das oeffentliche oder geteilte Repo vor dem ersten Merge auf `main`:

## GitHub-Einstellungen

1. **Ruleset oder Branch protection** auf `main`:
   - Pull Request erforderlich
   - mind. ein Review
   - Conversation resolution erforderlich
   - signierte Commits erforderlich (empfohlen)
   - kein Force-Push, kein Loeschen von `main`
2. **CODEOWNERS** ist unter `.github/CODEOWNERS` hinterlegt; Owner-Review fuer kritische Pfade erzwingen.
3. **Secret Scanning** und **Push Protection** einschalten.
4. **Dependabot** Alerts + Security Updates.
5. **Private Vulnerability Reporting** einschalten (`SECURITY.md`).
6. Wiki und Discussions aus, wenn nicht benoetigt.
7. Actions: Standard `permissions: contents: read`; Actions per Commit-SHA pinnen (siehe `.github/workflows/ci.yml`); kein `pull_request_target`.

## Deploy

- Nicht automatisch von `main`-HEAD auf den Tresor-Host ausrollen.
- Nur signierte Tags oder gepruefte Commits bauen (`docs/release-signing.md`).
- Aenderungen an CI-/Release-Workflows und an eingebetteten Vertrauensregeln in PRs besonders sorgfaeltig reviewen.

## Release-Checkliste

- [ ] `manifest.json` + `manifest.json.sigstore.json` veroeffentlicht
- [ ] Cosign-Verifikation gegen die Workflow-Identitaet erfolgreich
- [ ] CI gruen
- [ ] Keine privaten Hostnamen, Domains oder Pfade in Diff/Docs
