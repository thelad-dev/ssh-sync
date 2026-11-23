# Plan: Passphrase-Identity ueberspringen, pull nutzt gespeichertes Master-Passwort

## Annahme

- Die Server-PEM nach Master-Entschluesselung kann selbst OpenSSH-Passphrase tragen (`aes256-ctr`/`bcrypt`); das ist Absicht, nicht ein kaputter Eintrag.
- `golang.org/x/crypto/ssh.PassphraseMissingError` liefert bei OpenSSH-Format den eingebetteten Public Key ohne Entschluesseln; daraus reicht der Fingerabdruck fuer den Vergleich mit einer lokalen Datei.
- Ueberspringen heisst: kein Schreiben der passphrase-geschuetzten PEM, keine Ausweichdatei `.ssh-sync`, vorhandene lokale Datei unberuehrt; Hosts ohne IdentityFile fuer diese Identity, wenn kein passender lokaler Key da ist.
- Stimmt der Fingerabdruck mit dem lokalen Key ueberein, bleibt IdentityFile auf der lokalen Datei (Write=false).
- Andere Parse-Fehler einer einzelnen Identity brechen den Lauf ebenfalls nicht ab, sondern ueberspringen mit Warnung.
- `pull` soll dieselbe Passwortquelle wie der Daemon nutzen (`keyring.GetMasterPassword`); Terminal-Prompt nur als Fallback.

## Zwei Wege

1. **Auftragsweg:** In `planPrivateKey` Passphrase erkennen, Identity ueberspringen bzw. nur vergleichen; in `runPull` zuerst Keyring/`.master-key`, sonst TTY-Prompt.
2. **Alternative (nicht gewaehlt):** Passphrase interaktiv abfragen und die PEM entschluesselt schreiben.

Gewaehlt: Weg 1. Kein Passwort-Prompt fuer Schluessel-Passphrases im Daemon/CLI-Sync; der lokale OpenSSH-Client kann bei Bedarf selbst nachfragen. Weniger Angriffsflaeche, passt zum Nicht-Ueberschreiben.

## Ablehnung

- Ein Kollege koennte verlangen, die passphrase-geschuetzte PEM trotzdem nach `.ssh-sync` zu schreiben (OpenSSH wuerde dann nachfragen). Der Auftrag verbietet Schreiben; Ausweichdatei entfaellt fuer diesen Fall.
- Pull ohne gespeichertes Passwort und ohne TTY endet mit Fehler statt still; das ist gewollt und verweist auf `ssh-sync unlock`.
- Zusammenfassung `N Identity uebersprungen: name (Passphrase)` als Warnung statt eigener Exit-Codes: Exit bleibt 0 bei erfolgreichem Rest-Abgleich.

## Nachweis

- `PATH=/usr/local/go/bin:$PATH go test ./internal/sshconfig/ ./internal/keyring/ ./cmd/agent/ -count=1`
- Test: Bundle mit einer passphrase-geschuetzten und einer normalen Identity; Rest wird geschrieben, lokale Datei der Passphrase-Identity bleibt, Warnung/Zaehlung vorhanden.
- Test: `ResolveMasterPassword` ohne TTY mit gespeichertem Passwort ok; ohne Speicherung klare Meldung mit `ssh-sync unlock`.
- Wegwerf-Container Debian: Modul-Testbinary unter `HOME=/tmp/...`, Ergebnis im Bericht.

## Grenze

- Kein Release, kein Tag, kein Versionsbump auf v0.1.7.
- Keine Aenderungen an Server-Store, Crypto-KDF, Installer.
- Kein Passwort in Logs oder Ausgaben.
- Keine produktiven Geraete oder echte Schluessel anfassen.
