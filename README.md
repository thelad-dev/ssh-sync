# ssh-sync

Self-hosted Werkzeug zum Synchronisieren von SSH-Private-Keys und `ssh config` über mehrere Rechner (Linux/Windows/macOS)  -  mit Webportal **ssh-sync**.

## Sicherheitsmodell

- Private Keys werden clientseitig mit AES-256-GCM verschluesselt (Argon2id, danach HKDF in Auth- und Enc-Schluessel).
- Nur der Auth-Schluessel (bzw. sein bcrypt-Hash) liegt auf dem Server. Der Enc-Schluessel und das Master-Passwort bleiben auf dem Client.
- Das schuetzt gegen Diebstahl der Server-Datenbank. Ein kompromittierter Serverprozess oder MITM auf dem Transport bleibt ein Risiko. Details: [SECURITY.md](SECURITY.md).
- Geraete authentifizieren sich per JWT. Sync liefert derzeit **alle Hosts** (und die ihnen zugewiesenen Keys) an **jedes** Geraet; eine Profil-/Geraetetrennung ist noch nicht umgesetzt.
- Agent-Updates und Installer pruefen ein **signiertes Manifest** (Ed25519) und SHA-256. Siehe [docs/release-signing.md](docs/release-signing.md).

## Schnellstart (Docker)

```bash
cp .env.example .env
# Pflicht: SSH_SYNC_JWT_SECRET setzen (openssl rand -hex 32), mindestens 32 Zeichen
# Optional: SSH_SYNC_SETUP_TOKEN und SSH_SYNC_PUBLIC_URL
docker compose up --build -d
```

Portal (Compose bindet nur Loopback): `http://127.0.0.1:8080`  -  in Produktion nur hinter TLS bzw. Tunnel.

Deploy: geprueften Commit oder signierten Tag bauen, nicht blind `main`-HEAD auf dem Tresor-Host ausrollen. Siehe [docs/branch-protection.md](docs/branch-protection.md).

## Lokal entwickeln

Voraussetzungen: Go 1.26+, CGO (für SQLite), gcc

```bash
make build
make run
```

## Bedienung

Ausführliche Anleitung: **[docs/ANLEITUNG.md](docs/ANLEITUNG.md)**

## Workflow

1. **Portal oeffnen** → Ersteinrichtung (Master-Passwort, min. 12 Zeichen; nur Auth-Schluessel geht an den Server; Header `X-Setup-Token` wenn gesetzt)
2. **Import** → `ssh-sync import` oder Portal-Button „Importieren“
3. **Hosts zuweisen** → Identity pro Host setzen; jedes registrierte Geraet bekommt beim Sync alle Hosts
4. **Agent auf jedem Rechner**  -  Installer laden, lesen, Signatur/Hash pruefen, dann ausfuehren (kein `curl | sh`):

```bash
curl -fsSL "https://<portal-url>/install/linux.sh" -o install-linux.sh
less install-linux.sh
sh install-linux.sh
ssh-sync init --server https://<portal-url> --name laptop-linux
ssh-sync pull
```

**Windows** (Details in [ANLEITUNG](docs/ANLEITUNG.md#installation-windows-11)):

```powershell
Invoke-WebRequest -Uri "https://<portal-url>/install/windows.ps1" -OutFile install-windows.ps1
notepad install-windows.ps1
powershell -File install-windows.ps1
```

- Binary: `%LOCALAPPDATA%\Programs\ssh-sync\ssh-sync.exe`
- Config nach `%USERPROFILE%\.config\ssh-sync\config.json`
- `ssh-sync unlock` → `ssh-sync service start`

Der Agent schreibt Keys nach `~/.ssh/` bzw. `%USERPROFILE%\.ssh\` (chmod 600) und einen verwalteten Block in `ssh config` (Markierung `BEGIN/END ssh-sync`).

## Agent-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `ssh-sync export --out DATEI` | Konten-Archiv (Keys bleiben verschluesselt) |
| `ssh-sync import DATEI` | Konten-Archiv importieren (siehe [docs/umzug.md](docs/umzug.md)) |
| `ssh-sync import --server URL` | `~/.ssh` ins Portal importieren |
| `ssh-sync backup export -o DATEI` | Verschlüsseltes Vollbackup (Klartext-Keys unter Passwort) |
| `ssh-sync backup import -i DATEI` | Backup wiederherstellen |
| `ssh-sync init --server URL --name NAME` | Gerät registrieren |
| `ssh-sync unlock` | Master-Passwort im Keyring speichern |
| `ssh-sync daemon` | Hintergrund-Agent |
| `ssh-sync pull` | Manuell synchronisieren |
| `ssh-sync update` | Signiertes Self-Update |
| `ssh-sync status` | Verbindung und Bundle-Größe prüfen |
| `ssh-sync purge` | Gerät abgeben (lokal mit `PURGE`); Fern-Purge nur verwaltete Einträge, `authorized_keys`/`known_hosts` bleiben |

Cloudflare Access (Beispiel): [docs/cloudflare-access.md](docs/cloudflare-access.md)

Config: `~/.config/ssh-sync/config.json`

## Umgebungsvariablen

| Variable | Beschreibung |
|----------|--------------|
| `SSH_SYNC_JWT_SECRET` | JWT-Signatur (in Produktion fest setzen, min. 32 Zeichen) |
| `SSH_SYNC_SETUP_TOKEN` | Optional: Token für `POST /api/setup` (Header `X-Setup-Token`) |
| `SSH_SYNC_PUBLIC_URL` | Feste Basis-URL für Install-Skripte (HTTPS) |
| `SSH_SYNC_ALLOW_INSECURE` | `1` erlaubt http:// im Installer (nur Labor) |

## Architektur

```
web/          → Portal (ssh-sync)
cmd/api/      → API + Static Files
cmd/agent/    → CLI für Clients
cmd/signrelease/ → Manifest signieren
internal/     → crypto, store, api, sshconfig, releaseverify
```

API-Spec: `openapi.yaml`

## Hinweise

- Nur hinter TLS bzw. vertrauenswürdigem Tunnel betreiben.
- Master-Passwort sicher aufbewahren.
- Binaries nur aus diesem Repo bzw. dem eigenen Portal, Signatur prüfen.
- **Gerät abgeben:** Portal-Button **Abgeben** oder lokal `ssh-sync purge` (Bestätigung `PURGE`).

## Lizenz

Lizenz: wird vor der Veroeffentlichung festgelegt.
