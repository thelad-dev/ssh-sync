# ssh-sync

ssh-sync ist ein self-hosted Werkzeug zum Synchronisieren von SSH-Private-Keys und `ssh config` ueber mehrere Rechner (Linux, Windows, macOS). Ein Webportal verwaltet Hosts und Identities; ein Agent auf jedem Geraet holt das verschluesselte Bundle und schreibt die lokalen SSH-Dateien.

## Funktionen

- Clientseitige Verschluesselung der Private Keys (AES-256-GCM, Argon2id)
- Webportal fuer Import, Host-Zuweisung und Geraeteverwaltung
- Agent mit Sync, Self-Update, Backup und Purge
- Installer fuer Linux/macOS und Windows (mit Sigstore-Pruefung)
- Docker-Compose-Schnellstart fuer das Portal

## Installation

```bash
cp .env.example .env
# Pflicht: SSH_SYNC_JWT_SECRET setzen (openssl rand -hex 32), mindestens 32 Zeichen
docker compose up --build -d
```

Portal (Compose bindet nur Loopback): `http://127.0.0.1:8080`. In Produktion nur hinter TLS bzw. Tunnel. Ausfuehrliche Bedienung: [docs/ANLEITUNG.md](docs/ANLEITUNG.md).

Agent-Installer vom Portal laden, lesen, dann ausfuehren (kein `curl | sh`). Fehlt [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) im PATH, beschafft der Installer eine gepinnte Version selbst (siehe [docs/release-signing.md](docs/release-signing.md)).

```bash
curl -fsSL "https://portal.example/install/linux.sh" -o install-linux.sh
less install-linux.sh
sh install-linux.sh
ssh-sync init --server https://portal.example --name laptop-linux
ssh-sync pull
```

## Sicherheitsmodell (Kurz)

1. Private Keys werden nur clientseitig entschluesselt; der Server speichert Ciphertext und einen Auth-Schluessel-Hash, nicht das Master-Passwort und nicht den Enc-Schluessel.
2. Das schuetzt gegen Diebstahl der Server-Datenbank; ein kompromittierter Serverprozess oder MITM auf dem Transport bleibt ein Risiko.
3. Geraete authentifizieren sich per JWT; Sync liefert derzeit alle Hosts an jedes registrierte Geraet.
4. Agent-Updates und Installer pruefen ein Sigstore-signiertes Manifest (keyless ueber GitHub Actions) und SHA-256 der Assets.
5. Details und Meldeweg: [SECURITY.md](SECURITY.md), Signaturmodell: [docs/release-signing.md](docs/release-signing.md).

## Lizenz

Apache License 2.0. Siehe [LICENSE](LICENSE), [NOTICE](NOTICE) und [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Mitwirken

Issues und Pull Requests willkommen. Bitte Sicherheitsluecken nicht oeffentlich melden; siehe [SECURITY.md](SECURITY.md). Branch-Schutz und Release-Hinweise: [docs/branch-protection.md](docs/branch-protection.md).
