# Migration von ssh-profile-syncer

Schritt-fuer-Schritt: bestehende Geraete vom Vorgaenger **ssh-profile-syncer** (Agent-Stand 2026-08-22) auf ssh-sync umziehen, ohne Geraete im Portal neu anzulegen.

## Voraussetzungen

- Neuer Server mit frischem, starkem `SSH_SYNC_JWT_SECRET` (kein bekanntes Platzhalter-Secret, mindestens 32 Zeichen).
- Datenbank vom alten Server uebernommen (Geraetezeilen bleiben).
- Auf jedem Geraet liegt das Master-Passwort schon lokal vor (Keyring-Service `ssh-profile-syncer` oder Datei `~/.config/ssh-profile-syncer/.master-key`), wie nach einem laufenden `unlock`.
- Konto bleibt zunaechst `auth_scheme=legacy`. Auth-Upgrade auf `auth_v1` kommt **erst nach** dem Client-Update aller Geraete.

## Was der neue Client beim ersten Lauf tut

1. Fehlt `~/.config/ssh-sync/config.json`, wird die alte Config aus `~/.config/ssh-profile-syncer/config.json` kopiert (Linux, Windows und macOS nutzen denselben `.config`-Pfad unter dem Home-Verzeichnis). Die alte Datei bleibt als Sicherung erhalten.
2. Master-Passwort wird aus dem neuen Speicher gelesen; fehlt er, aus dem Legacy-Keyring bzw. der Legacy-`.master-key` (Legacy bleibt unangetastet).
3. Schlaegt der Geraete-Ping mit 401 fehl, meldet sich der Client per Legacy-Passwort-Login an (kein stilles Auth-Upgrade) und ruft `POST /api/devices/{id}/rotate` auf.
4. Der Server stellt ein neues JWT mit dem aktuellen Secret aus, speichert `token_hash = sha256(jwt)` und schreibt ein Audit-Log. Rate-Limit schuetzt vor Missbrauch.
5. Die neue Config wird unter `~/.config/ssh-sync/config.json` gespeichert. Danach syncen Ping und Daemon normal.

Windows: Config und `.master-key` liegen unter `%USERPROFILE%\.config\ssh-profile-syncer\` bzw. nach dem Umzug unter `%USERPROFILE%\.config\ssh-sync\`. Keyring-Dienstname bisher `ssh-profile-syncer`, neu `ssh-sync` (Windows-Anmeldeinformationsmanager).

macOS: dieselben `.config`-Pfade unter `$HOME`; Keyring-Service analog.

## Ablauf Server-Umzug

1. Parallelinstanz mit neuem Image/Binary (inkl. Rotate-Endpunkt) und neuem JWT-Secret starten.
2. DB und ggf. Tunnel/Reverse-Proxy so vorbereiten, dass Umschalten moeglich ist, ohne alte Instanz sofort zu loeschen.
3. Tunnel/URL auf die neue Instanz legen.
4. Pro Geraet einmal Installer bzw. Binary-Update ausfuehren (siehe unten).
5. Pruefen: `ssh-sync status` zeigt Ping ok.
6. Erst wenn alle Geraete syncen: einmal Auth-Upgrade auf `auth_v1` (Portal-Login oder Client-Upgrade-Pfad).
7. Alte Instanz danach stoppen.

## Ablauf Geraete-Update

Pro Host:

```bash
# Installer vom Portal oder manuelles Binary-Update
ssh-sync status
```

Wenn Unlock schon bestand, reicht dieser eine Lauf. Fehlt das Master-Passwort lokal:

```bash
ssh-sync unlock
ssh-sync status
```

Kein zweites Enroll im Portal, keine manuelle Config-Kopie.

## Konto-Upgrade (nach allen Geraeten)

1. Sicherstellen, dass jedes Geraet den neuen Client hat und sync.
2. Einmal mit Master-Passwort anmelden; der Client leitet Auth-/Enc-Schluessel ab und ruft `/api/auth/upgrade` auf.
3. Danach geht nur noch der Auth-Schluessel an den Server. Alte Agenten ohne Upgrade-Pfad verlieren Legacy-Login.

Reihenfolge bewusst: **Geraete zuerst, Upgrade zuletzt**. Ein fruehes Upgrade wuerde alte Binaries abschneiden.

## Rueckweg

- Tunnel/URL zurueck auf die alte Instanz (solange sie noch laeuft).
- Bereits rotierte JWTs gelten nur am neuen Secret; Geraete mit neuem Client bleiben auf der neuen Instanz lauffaehig.
- Alte Config unter `~/.config/ssh-profile-syncer/` wurde nicht geloescht und kann bei Bedarf wieder gelesen werden.
- Auth-Upgrade rueckgaengig machen ist nicht vorgesehen; vor dem Upgrade alle Geraete pruefen.

## Sicherheitseigenschaften

- Neues starkes JWT-Secret; kein Legacy-Signing mit dem alten bekannten Secret.
- Sync verlangt Token-Hash-Abgleich (`sha256` der Bearer-JWT-Zeichenkette).
- Rotate nur mit User-Bearer; Geraete-JWT reicht nicht.
- Master-Passwort geht nur ueber den bestehenden Legacy-Login an den Server, nicht im Klartext in Rotate-Requests.
- Rate-Limit und Audit-Log fuer Rotate-Aufrufe.
- Idempotent: gueltiges JWT -> kein erneutes Rotate.
