# Plan: ssh-sync darf Config und Private Keys nie ueberschreiben

## Annahme

- Marker-Merge in `~/.ssh/config` reicht; eine Extra-Datei plus `Include` ist nicht noetig, weil die Marker schon existieren und betroffene Geraete den Block kennen.
- Fingerabdruck-Vergleich ueber den eingebetteten Public Key des Private Keys (SHA256) ist ausreichend; bytegleiche Dateien mit gleicher Public-Key-Identitaet gelten als gleich.
- Ein vorhandener, nicht parsebarer Private Key (Passphrase) gilt als Kollision: nicht ueberschreiben, Server-Schluessel nach `<name>.ssh-sync`.
- "Erster Schreibvorgang" = Config ohne managed Marker. Geraete, die schon nur den managed Block haben, gelten als bestaetigt und bekommen weiterhin In-Place-Updates des Blocks.
- Alte `config--bak` bleibt unangetastet; neue Sicherungen heissen `config.ssh-sync-bak-<UTC>`.

## Zwei Wege

1. **Auftragsweg:** managed Block zwischen Markern mergen; abweichende Keys nach `<name>.ssh-sync`; erster Lauf Trockenlauf/`--apply`.
2. **Alternative (nicht gewaehlt):** eigene `~/.ssh/ssh-sync.conf` plus `Include`-Zeile.

Gewaehlt: Weg 1. Die Marker sind schon im Render-Pfad und in der Doku; weniger OpenSSH-Versionsfragen um `Include`, und Migration von schon geschriebenen Bloecken bleibt ein In-Place-Replace.

## Ablehnung

- Ein Kollege koennte verlangen, dass abweichende Keys gar nicht geschrieben werden (nur warnen). Die Ausweichdatei ist absichtlich, damit Sync weiter IdentityFile setzen kann, ohne den lokalen Schluessel zu toeten.
- Daemon-Skip beim Erstlauf kann bedeuten, dass neue Geraete ohne manuelles `pull --apply` nie syncen. Das ist gewollt und wird geloggt.
- Backup-Retention 10 koennte bei haeufigen Syncs alte Staende knapper halten als gewuenscht; Grenze steht im Auftrag.

## Nachweis

- `go test ./internal/sshconfig/ ./internal/agentsync/ ./cmd/agent/ -count=1`
- Wegwerf-Container (Debian): Home mit eigener `config` (Host local) und eigenem `id_ed25519`, Apply einmal ohne und einmal mit Bestaetigung; vorher/nachher Fingerabdruecke und Zeilenzahlen im Bericht.

## Grenze

- Kein Release, kein Tag, keine Version-Bump auf v0.1.6.
- Keine Aenderungen an Server-Store, Crypto, Installer-Skripten ausser noetigen CLI-Flags fuer pull/daemon.
- Keine echten Schluessel im Bericht; nur synthetische Testdaten.
- Keine Wiederherstellung auf produktiven Geraeten.
