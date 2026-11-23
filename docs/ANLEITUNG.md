# ssh-sync  -  Bedienungsanleitung

## 1. Portal öffnen

Hinter TLS: **https://<portal-url>**

Beim ersten Start: **Ersteinrichtung** mit Master-Passwort (min. 12 Zeichen).  
Dieses Passwort brauchst du überall  -  Portal, Agent `pull`/`import`.

---

## 2. Bestehende SSH-Daten importieren

### Variante A: Agent (empfohlen  -  liest direkt `~/.ssh`)

Auf dem Rechner, von dem du importieren willst:

```bash
# Optional: Vorschau ohne Upload
ssh-sync import --server https://<portal-url> --dry-run

# Import (Master-Passwort eingeben)
ssh-sync import --server https://<portal-url>
```

Importiert:

- alle Host-Blöcke aus `~/.ssh/config` (ohne Wildcards und ohne managed Block)
- Private Keys aus `IdentityFile`-Einträgen plus `id_ed25519`, `id_rsa`, `id_ecdsa`

Bereits vorhandene Namen/Aliase werden übersprungen.

### Variante B: Webportal

1. Tab **Identities** → **Importieren**
2. SSH-`config` als Datei oder Text einfügen
3. Private-Key-Dateien auswählen (mehrere möglich)
4. **Vorschau** → **Import starten**

---

## 3. Manuell anlegen (ohne Import)

| Schritt | Tab | Aktion |
|---------|-----|--------|
| Key-Paar | Identities | + Identity  -  Private Key einfuegen (wird clientseitig verschluesselt) |
| Server | Hosts | + Host  -  Alias, HostName, User, Identity |
| Rechner | Geraete | + Geraet  -  oder per Agent `init` |

**Hinweis:** Es gibt derzeit **keine** Profil-/Geraetetrennung. Jedes registrierte Geraet bekommt beim Sync alle Hosts und die ihnen zugewiesenen Keys.

---

## 4. Agent auf jedem Rechner

### Download

Im Portal: Tab **Geräte** → **Installation (Linux / Windows)** (Skript speichern und lesen, kein `curl | sh`). Binaries und Signatur kommen vom **GitHub-Release** (`manifest.json`, `manifest.json.sigstore.json`, `SHA256SUMS`).

Herkunftspruefung: der Installer nutzt `cosign` aus dem PATH oder laedt bei Bedarf eine gepinnte cosign-Version (SHA-256 vor Ausfuehrung, privates Temp, danach geloescht). Details: [release-signing.md](release-signing.md#installer-vertrauensmodell-cosign-bootstrap).

### Installation Linux / macOS

Empfohlen (Binary nach `~/.local/bin`, unter Linux systemd-User-Service best effort):

```bash
curl -fsSL "https://<portal-url>/install/linux.sh" -o install-linux.sh
# lesen, dann:
sh install-linux.sh
```

Das Skript laedt vom GitHub-Release, prueft mit `cosign verify-blob` (PATH oder Bootstrap) und vergleicht die Binary-SHA-256 mit dem signierten Manifest.

Manuelle Pruefung:

```bash
cosign verify-blob \
  --bundle manifest.json.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/thelad-dev/ssh-sync/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  manifest.json
```

Ohne cosign nur mit explizitem Schalter (Warnung: keine Herkunftspruefung, nur SHA-256 gegen `SHA256SUMS`):

```bash
sh install-linux.sh --unsicher-nur-pruefsumme
```

Auf EndeavourOS/Arch ggf. `loginctl enable-linger $USER`, neu anmelden, dann `ssh-sync unlock` und `systemctl --user start ssh-sync`.

Manuell (Artefakte vom GitHub-Release, nach cosign-Pruefung):

```bash
chmod +x ssh-sync-linux-amd64
sudo mv ssh-sync-linux-amd64 /usr/local/bin/ssh-sync

ssh-sync init --server https://<portal-url> --name laptop-linux
ssh-sync pull
```

### Installation Windows 11

Anleitung für Windows 11 Pro/Home (64-bit). Der empfohlene Weg ist das Portal-Installskript  -  kein manuelles Kopieren der `.exe`.

#### 1. Voraussetzungen

- Windows 11 **22H2 oder neuer**, 64-bit
- **PowerShell 5.1** (vorinstalliert) oder **Windows Terminal** mit PowerShell 5.1 / **PowerShell 7**
- Netzwerk zum Portal (LAN/VPN oder `https://<portal-url>` mit Cloudflare Access) und zu GitHub Releases (Release-Artefakte und ggf. cosign-Bootstrap)
- Optional: **cosign** im PATH; sonst laedt der Installer eine gepinnte Version (sonst nur `-UnsicherNurPruefsumme`)

**PowerShell öffnen**

- Normal (Install, `unlock`, `pull`, `status`): Windows-Taste → „Windows Terminal“ oder „PowerShell“
- **Als Administrator** (Dienst installieren/reparieren): Rechtsklick → **Als Administrator ausführen**

# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

#### 2. Einzeiler-Install

Öffentlicher Host (Cloudflare):

```powershell
Invoke-WebRequest -Uri "https://<portal-url>/install/windows.ps1" -OutFile install-windows.ps1
# lesen, dann: powershell -File install-windows.ps1
```

Nur LAN/VPN (Portal-Host direkt):

```powershell
Invoke-WebRequest -Uri "https://<portal-url>/install/windows.ps1" -OutFile install-windows.ps1
# lesen, dann: powershell -File install-windows.ps1
```

Anderes Portal-Basis-URL (optional, wird vom Skript ausgewertet):

```powershell
$env:SSH_SYNC_URL = "https://<portal-url>"
# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)
```

Mit Cloudflare Access **ohne** Bypass für `/install`  -  Header an Invoke-WebRequest (siehe Abschnitt 7 und [cloudflare-access.md](cloudflare-access.md)):

```powershell
$headers = @{
  "CF-Access-Client-Id"     = $env:CF_ACCESS_CLIENT_ID
  "CF-Access-Client-Secret" = $env:CF_ACCESS_CLIENT_SECRET
}
# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)
```

#### 3. Was der Installer tut

Das Skript (Quelle: `/install/windows.ps1` auf dem Portal):

1. lädt `manifest.json`, `manifest.json.sigstore.json`, `SHA256SUMS` und `ssh-sync-windows-amd64.zip` vom GitHub-Release (Basis: `$env:SSH_SYNC_RELEASE_URL` oder `…/releases/latest/download`; Portal-URL nur fuer Hinweise, `$env:SSH_SYNC_URL`)
2. prueft mit `cosign verify-blob` (PATH oder Bootstrap; oder bei `-UnsicherNurPruefsumme` nur SHA-256 gegen `SHA256SUMS`)
3. entpackt nach **`%LOCALAPPDATA%\Programs\ssh-sync\ssh-sync.exe`**
4. hängt diesen Ordner an den **Benutzer-PATH** an
5. entfernt die **Legacy-Geplanten-Aufgabe** `ssh-sync` (falls noch vorhanden)
6. versucht, den Windows-Dienst **`ssh-sync`** zu installieren (nur mit Admin-Rechten)

Am Ende gibt das Skript u. a. aus  -  Punkt 4 unter «Nächste Schritte» hängt davon ab, ob die Dienst-Installation gelungen ist:

**Wenn die Dienst-Installation gelungen ist:**

```
Fertig. Binary: …\AppData\Local\Programs\ssh-sync\ssh-sync.exe
Nächste Schritte:
  1. Portal: <BaseUrl> → Geräte → + Gerät → Config kopieren
  2. Nach C:\Users\<IhrName>\.config\ssh-sync\config.json
  3. ssh-sync.exe unlock
  4. ssh-sync.exe service start   (oder: Dienst ssh-sync in services.msc)

Updates:
# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)
  # oder: ssh-sync.exe update
```

**Wenn die Dienst-Installation nicht gelungen ist** (keine Admin-Rechte, abgebrochen oder fehlgeschlagen):

```
Fertig. Binary: …\AppData\Local\Programs\ssh-sync\ssh-sync.exe
Nächste Schritte:
  1. Portal: <BaseUrl> → Geräte → + Gerät → Config kopieren
  2. Nach C:\Users\<IhrName>\.config\ssh-sync\config.json
  3. ssh-sync.exe unlock
# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)

Updates:
# Skript per Invoke-WebRequest speichern, lesen, dann ausfuehren (kein irm|iex)
  # oder: ssh-sync.exe update
```

**Wichtig:** Nach dem Install ein **neues PowerShell-Fenster** öffnen  -  der PATH-Update gilt sonst nicht in der laufenden Session.

#### 4. Install ohne Administrator-Rechte

Ohne Admin-Rechte überspringt der Installer die Dienst-Installation und meldet:

```
→ Dienst-Installation übersprungen (keine Administrator-Rechte)
  Später: PowerShell als Admin → ssh-sync.exe service install --user DOMAIN\USER
  oder: ssh-sync.exe service install --user DOMAIN\USER
```

Später als **Administrator** nachziehen  -  eine der beiden Varianten:

```powershell
# Variante A: nur Dienst (Binary muss schon existieren)
Invoke-WebRequest -Uri "https://<portal-url>/install/windows-service.ps1" -OutFile install-windows-service.ps1
# lesen, dann ausfuehren

# Variante B: direkt über die CLI (Anmeldedialog für Windows-Passwort)
ssh-sync service install --user DOMAIN\USER
```

Der Anmeldedialog verlangt das **Windows-Kontopasswort** (Dienst-Anmeldung), nicht das ssh-sync-Master-Passwort.

#### 5. Gerät anlegen und entsperren

1. Portal → Tab **Geräte** → **+ Gerät** → Name vergeben
2. **`config.json`** aus dem Dialog kopieren
3. Zielpfad (Ordner ggf. anlegen):

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\ssh-sync"
notepad "$env:USERPROFILE\.config\ssh-sync\config.json"
```

4. Master-Passwort für Hintergrund-Sync speichern:

```powershell
ssh-sync unlock
```

Unter Windows speichert `ssh-sync unlock` das Master-Passwort primär im **Windows-Anmeldeinformationsmanager** (über `go-keyring`, Dienstname `ssh-sync`). Schlägt das fehl, liegt ein Fallback unter `%USERPROFILE%\.config\ssh-sync\.master-key` (Datei mit Rechten nur für den Benutzer).

#### 6. Dienst starten

```powershell
ssh-sync service start
```

In **`services.msc`** heißt der Dienst **`ssh-sync`**. Er läuft unter deinem Windows-Benutzer (gleiches Konto wie bei `unlock`), Starttyp automatisch.

**„Fehlerhafte Anmeldung“ / Dienst startet nicht:** PowerShell **als Administrator**:

```powershell
ssh-sync service repair
```

(Der Installer weist bei fehlgeschlagener Dienst-Installation auf `service repair` hin.)

Der alte Weg über **`Start-ScheduledTask -TaskName ssh-sync`** ist obsolet  -  der Installer entfernt diese Aufgabe.

#### 7. Cloudflare Access

Details und Server-Setup: **[cloudflare-access.md](cloudflare-access.md)**.

Kurz für Windows-Clients:

- Beim Download ohne Bypass: Umgebungsvariablen `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` setzen und als Header übergeben (siehe Abschnitt 2).
- In **`config.json`** dieselben Werte als `access_client_id` und `access_client_secret` (plus `server_url`, z. B. `https://<portal-url>`).
- Fehlen die **CF-Access-Header** beim Download, liefert Cloudflare eine **Login-HTML-Seite** statt des Skripts  -  Header wie in Abschnitt 2 setzen oder Bypass für `/install` (siehe [cloudflare-access.md](cloudflare-access.md)).

#### 8. Prüfen

```powershell
ssh-sync status
ssh-sync pull    # falls der Dienst noch keinen ersten Sync ausgeführt hat
```

- Keys landen in **`%USERPROFILE%\.ssh\`**
- In **`%USERPROFILE%\.ssh\config`** wird nur der Block zwischen `BEGIN/END ssh-sync` überschrieben; eigene Einträge darüber/darunter bleiben

Sync vom Portal: Tab **Geräte** → **Sync**  -  der Dienst führt `pull` im Hintergrund aus.

#### 9. Updates

Gleicher Einzeiler wie bei der Erstinstallation:

```powershell
Invoke-WebRequest -Uri "https://<portal-url>/install/windows.ps1" -OutFile install-windows.ps1
# lesen, dann: powershell -File install-windows.ps1
```

Oder, wenn `ssh-sync` schon im PATH:

```powershell
ssh-sync update
```

#### 10. Windows Terminal (optional)

Wenn du nach dem Sync **OpenSSH** in Windows Terminal nutzt:

- OpenSSH-Client unter **Einstellungen → Apps → Optionale Features** bzw. „Client für OpenSSH“ aktivieren
- In Windows Terminal **Textumbruch** eingeschaltet lassen (lange `ssh`-Zeilen)
- Träge Eingabe oder flackernder Cursor sind meist **GPU/ConPTY/Schrift**  -  nicht ssh-sync; andere Schrift oder Hardware-GPU in den Terminal-Einstellungen testen

#### 11. Häufige Fallen

| Problem | Ursache / Lösung |
|---------|------------------|
| `ssh-sync` unbekannt | Altes PowerShell-Fenster  -  **neues Fenster** nach Install |
| Config „leer“ / falscher Server | `config.json` im **falschen Profil**  -  z. B. Dienst unter LocalSystem liest `C:\Windows\System32\config\systemprofile\…` statt `%USERPROFILE%` |
| Dienst meldet Anmeldefehler | **`service repair`** als Admin; Windows-Passwort eingeben, nicht Master-Passwort |
| Download liefert HTML | Cloudflare-Login-Seite  -  CF-Header setzen oder Bypass für `/install` (siehe cloudflare-access.md) |
| Keine Keys nach Sync | Host ohne Identity-Zuweisung, Daemon/Unlock fehlt, oder Sync noch nicht ausgeloest |

Manuelles Binary (nur Fallback): GitHub-Release `ssh-sync-windows-amd64.exe` nach cosign-/Manifest-Pruefung  -  dann Pfad selbst in PATH legen und Dienst per `ssh-sync service install` einrichten.

### Hintergrund-Agent Linux (empfohlen)

```bash
ssh-sync unlock    # Master-Passwort einmalig in den System-Keyring
ssh-sync daemon    # Pollt alle 30s, führt Portal-Trigger aus
```

Alternativ: Unit-Vorlage `scripts/ssh-sync.service` (der curl-Installer legt `~/.config/systemd/user/ssh-sync.service` an).

Unter **Windows 11** stattdessen Abschnitt [Installation Windows 11](#installation-windows-11): `ssh-sync unlock` → `ssh-sync service start`.

### Sync vom Portal auslösen

1. Tab **Geräte** → **Sync** (oder **Alle synchronisieren**)
2. Daemon auf dem Client führt `pull` aus

Manuell weiterhin möglich:

```bash
ssh-sync pull
```

`pull` / Daemon holen das Sync-Buendel fuer dieses Geraet (alle Hosts) und schreiben:

- Keys nach `~/.ssh/` (chmod 600)
- managed Block in `~/.ssh/config`

Config des Agents: `~/.config/ssh-sync/config.json`

---

## 5. Typischer Ablauf (Neuinstallation)

```
1. Portal: Setup (Master-Passwort lokal; Auth-Schluessel an Server)
2. ssh-sync import  (oder Web-Import)
3. Portal: Hosts mit Identities versehen
4. Auf jedem PC: Agent installieren, Portal-Config nach config.json, ssh-sync unlock
   (Linux-Alternative: ssh-sync init --server … --name …)
5. Hintergrund-Sync: Linux systemd/daemon · Windows 11 ssh-sync service start
6. Ab dann: Aenderung im Portal → Sync auf den Geraeten
```

### Migration von ssh-profile-syncer (ohne Neuanlage)

Bestehende Geraete des Vorgaengers **ssh-profile-syncer** koennen mit einem Binary-/Installer-Update auf den neuen Server umziehen, ohne Geraete im Portal neu anzulegen. Der Client uebernimmt `~/.config/ssh-profile-syncer/config.json` und das Master-Passwort aus Keyring/Datei, erneuert das Geraete-JWT still und belaesst die alte Config als Sicherung. Auth-Upgrade auf `auth_v1` erst **nach** dem Update aller Geraete. Details und Rueckweg: [migration-ssh-profile-syncer.md](migration-ssh-profile-syncer.md).

### Migration bestehender Installationen (Auth/Enc-Split)

Nach dem Update von Server und Clients:

1. Portal oder Agent einmal mit dem bisherigen Master-Passwort anmelden.
2. Der Client leitet Auth- und Enc-Schluessel ab, meldet sich ggf. noch einmal legacy an und ruft `/api/auth/upgrade` auf. Der Server verlangt dabei den Nachweis des bisherigen Geheimnisses: Feld `password` (Legacy-Master-Passwort gegen den alten Pruefwert, mit Ratenbegrenzung) oder Header `X-Setup-Token`, wenn `SSH_SYNC_SETUP_TOKEN` gesetzt ist. Identities werden mit AAD neu verschluesselt.
3. Ab dann geht nur noch der Auth-Schluessel an den Server; Agent-Import braucht kein Klartext-Passwort mehr (Geraete-JWT reicht).
4. Alte Agent-Binaries, die noch `password` im Import-Body senden, funktionieren nur, solange der Server den optionalen Legacy-Check akzeptiert - Agent zeitnah aktualisieren.
5. Konten, die bereits `auth_v1` speichern, sind von diesem Schritt nicht betroffen (`/api/auth/upgrade` ist dann ein No-Op).

---

## 6. Befehlsübersicht Agent

| Befehl | Zweck |
|--------|-------|
| `ssh-sync import` | `~/.ssh` hochladen |
| `ssh-sync init` | Gerät registrieren |
| `ssh-sync pull` | Vom Server synchronisieren |
| `ssh-sync status` | Verbindung prüfen |
| `ssh-sync purge` | Gerät abgeben (lokal; siehe Abschnitt 7) |

---

## 7. Gerät abgeben (Purge)

Wenn ein Rechner das Netz verläßt oder neu aufgesetzt wird:

### Im Portal (Agent muss online sein)

Tab **Geräte** → **Abgeben** beim betroffenen Gerät.  
Löscht auf dem Client vollständig: `~/.ssh`, ssh-sync-Config/Keyring, systemd-/Dienst-Registrierung und das `ssh-sync`-Binary.  
Der Datensatz im Portal wird nach erfolgreichem Ack entfernt (× löscht nur den Portal-Eintrag).

Gerät offline → lokal:

```bash
ssh-sync purge
```

Bestätigung: `PURGE` eingeben (oder `--yes` nur für Tests).

### Nur verwaltete Dateien

```bash
ssh-sync purge --managed-only
```

Entfernt nur den managed Block und zugehörige Keys; andere Dateien in `~/.ssh` bleiben.

---

## 8. Backup & Wiederherstellung

### Export (Webportal)

1. Tab **Backup**
2. Backup-Passwort eingeben (min. 12 Zeichen, kann = Master-Passwort sein)
3. **Backup herunterladen** → Datei `ssh-sync-backup-YYYY-MM-DD.json`

Die Datei enthaelt alle Identities (Keys im Klartext innerhalb der Verschluesselung), Hosts und Geraete-Namen.

### Import auf frischer Installation

1. Neues Portal: **Ersteinrichtung** mit Master-Passwort
2. Einloggen → Tab **Backup**
3. Backup-Datei wählen, Backup-Passwort eingeben
4. **Backup wiederherstellen**
5. Geräte neu per `ssh-sync init` registrieren
6. Hosts und Geraete pruefen
7. `ssh-sync pull` auf allen Rechnern

### Export/Import per Agent

```bash
ssh-sync backup export --server https://<portal-url> -o mein-backup.json
ssh-sync backup import --server https://<portal-url> -i mein-backup.json
```

### Konten-Umzug (Keys bleiben verschluesselt)

Fuer den Wechsel auf einen anderen Server oder ein neues Konto siehe **[umzug.md](umzug.md)**. Kurz:

```bash
ssh-sync export --server https://<quelle> --out konto.json
ssh-sync import konto.json --server https://<ziel> --setup-new --mode replace
```

Im Portal: **Konto exportieren** / **Konto importieren** (Master-Passwort-Bestaetigung lokal).

---

## 9. Häufige Fragen

**Nach Import keine Keys auf dem Rechner?**  
→ Sync ausloesen, Identity dem Host zuweisen, `ssh-sync unlock` und Daemon/Dienst pruefen.

**Gerät einrichten?**  
→ Portal **Geräte** → **+ Gerät** → Dialog mit kopierbarer `config.json` und Befehlen (CF-Token aus Server-`.env`, wenn gesetzt).

**Lokale ssh config-Einträge weg?**  
→ Nur der Block zwischen `BEGIN/END ssh-sync` wird überschrieben. Eigene Einträge darüber/darunter bleiben (bis `ssh-sync purge`).
