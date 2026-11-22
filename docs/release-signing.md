# Release-Signierung (Sigstore keyless)

Agent-Updates und Installer akzeptieren nur Releases, deren `manifest.json` mit einem **Sigstore-keyless**-Bundle (`manifest.json.sigstore.json`) verifiziert werden kann. Es gibt keinen langlebigen Release-Signing-Key im Repository und kein Secret `RELEASE_SIGNING_KEY`.

## Vertrauenswuerdige Identitaet

Die Signatur entsteht im Workflow `.github/workflows/release.yml` am Tag `v*.*.*` ueber GitHub Actions OIDC und Cosign (`cosign sign-blob`). Clients und Installer erwarten dieselbe Identitaet wie in `internal/releaseverify/identity.go`:

| Pruefpunkt | Wert |
|---|---|
| OIDC-Issuer | `https://token.actions.githubusercontent.com` |
| Certificate SAN (Subject) | `^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$` |
| Quell-Repository | `https://github.com/thelad-dev/ssh-sync` |
| Owner | `https://github.com/thelad-dev` |

Nur ein Bundle, das von genau diesem Workflow an einem Versions-Tag ausgestellt wurde, gilt als gueltig.

## Verifikation mit cosign

Nach dem Download der Release-Artefakte:

```bash
cosign verify-blob \
  --bundle manifest.json.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  manifest.json
```

Danach SHA-256 der Assets gegen die Hashes in `manifest.json` (bzw. `SHA256SUMS`) pruefen. Installer tun dasselbe mit `cosign verify-blob`; der Agent (`ssh-sync update`) nutzt die eingebettete Verifikation in `internal/releaseverify`.

## Vertrauensanker und Rekor

- Der Client bindet die oeffentliche Sigstore Trusted Root (`trusted_root.json` in `internal/releaseverify`) ein und prueft das Bundle dagegen.
- Die Verifikation verlangt einen Eintrag im **Rekor**-Transparenzlog. Rekor speichert die Signatur oeffentlich nachvollziehbar; spaetere Aenderungen am Bundle ohne neuen Log-Eintrag fallen auf.
- Ohne gueltiges Bundle, falsche Identitaet oder fehlgeschlagenen Log-Check lehnen Client und Installer das Release ab (fail-closed).

## Downgrade-Schutz

`ssh-sync update` akzeptiert nur Manifest-Versionen, die strikt neuer als die installierte Version sind (siehe `CheckUpgrade`). Installer und manuelle Cosign-Pruefung ersetzen diesen Check nicht; vor einem manuellen Downgrade die Version bewusst waehlen.

## Kompromittierung von Konto oder Workflow

| Szenario | Wirkung |
|---|---|
| Kompromittiertes GitHub-Konto mit Recht, Tags zu pushen und den Workflow zu aendern | Angreifer koennen ein neues Tag und damit ein neues keyless-signiertes Manifest erzeugen. Clients akzeptieren es, wenn Identitaet und Bundle stimmen. |
| Nur Lesezugriff oder kein Push auf Tags/Workflow | Keine gueltige Release-Signatur moeglich. |
| Aenderung der Workflow-Identitaet (anderer Pfad, anderer Issuer) | Bestehende Clients und Installer mit der festen Identitaet in `identity.go` lehnen die Signatur ab, bis die eingebettete Policy bewusst aktualisiert und neu ausgeliefert wird. |

Schutzmassnahmen: Branch-Schutz und CODEOWNERS (siehe [branch-protection.md](branch-protection.md)), signierte Commits, Review vor Merge, Tags nur auf bereits CI-gruene `main`-Commits (Release-Gate).

## Release pruefen (Kurzablauf)

1. Draft-Release vom Workflow oeffnen: Binaries, `SHA256SUMS`, `manifest.json`, `manifest.json.sigstore.json` vorhanden.
2. `cosign verify-blob` wie oben gegen die bekannte Identitaet.
3. Asset-Hashes mit `manifest.json` / `SHA256SUMS` abgleichen.
4. Optional: `ssh-sync update` auf einem Testgeraet mit aelterer Version; Erwartung: Signatur und Hashes ok, sonst Rollback.

Schritt-fuer-Schritt zum Taggen und Veroeffentlichen: [release.md](release.md).
