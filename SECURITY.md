# Security Policy

## Meldeweg

Bitte Sicherheitslücken **nicht** öffentlich in Issues posten.

Nutze GitHub **Private Vulnerability Reporting** für dieses Repository (Settings → Security → Private vulnerability reporting), oder schreibe an den Maintainer über den im GitHub-Profil hinterlegten privaten Kontaktkanal.

Erwarte eine Erstantwort innerhalb weniger Werktage. Kritische Befunde an Update-/Installer-Pfaden und Auth haben Vorrang.

## Scope

In Scope: Server-API, Agent, Portal, Installer, Release-Signierung, Docker-Image.

Ausser Scope: Kompromittierung des Betreiber-Hosts, physischer Zugriff, schwache Master-Passwörter.

## Release-Verifikation

- Agent-Binaries nur mit gültiger Ed25519-Signatur über `downloads/manifest.json` akzeptieren.
- Public-Key-Fingerabdruck aus dem Release-Hinweis mit dem eingebetteten Key vergleichen (`docs/release-signing.md`).
- Keine `curl | sh` / `irm | iex`-Einzeiler aus Drittquellen.

## Bekannte Grenzen (kurz)

- Gemeinsamer Cloudflare-Access-Service-Token für alle Geräte (siehe `docs/cloudflare-access.md`).
- Login sendet nur den abgeleiteten Auth-Schluessel (nicht das Master-Passwort). Enc-Schluessel bleibt clientseitig; ein kompromittierter Serverprozess bleibt ein Risiko.
- Legacy-Upgrade (`POST /api/auth/upgrade`) verlangt das bisherige Master-Passwort oder ein konfiguriertes Setup-Token; siehe Migration in `docs/ANLEITUNG.md`.
- Konten-Umzugsarchiv: Private Keys nur als Ciphertext; Host-Metadaten und optionale Settings im Klartext; genau ein `payload` und HMAC ueber diese Bytes (Portal und CLI); siehe `docs/umzug.md`.
- Fern-Purge und Geräte-Token: siehe Audit-/Issue-Tracker der Maintainer.
