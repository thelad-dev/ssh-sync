# Konten-Umzug (Export / Import)

Schritt-fuer-Schritt-Anleitung, um ein Konto von einem Server oder einer Installation auf eine andere zu uebertragen.

## Was das Archiv enthaelt

- Schema-Version und Zeitstempel
- KDF-Salt und Auth-Schema des Quellkontos
- Identities inkl. **verschluesselter** Private Keys (wie auf dem Server gespeichert, nie Klartext)
- Hosts und Einstellungen (z. B. gespeicherte CF-Bootstrap-Werte)
- Geraetenamen (nur Metadaten)

## Was geschuetzt ist und was nicht

| Inhalt | Schutz |
|--------|--------|
| Private Keys im Archiv | AES-GCM-Ciphertext; ohne Master-Passwort nicht lesbar |
| Integritaet der Payload | HMAC-SHA256 mit aus Master-Passwort abgeleitetem Schluessel |
| Geraete-JWT / TokenHashes | **nicht** enthalten |
| Host-Metadaten (Alias, HostName, …) | im Klartext im Archiv (wie in der DB) |
| CF Access Client Secret in settings | im Klartext im Archiv, wenn gesetzt |

Das Master-Passwort wird **nie** an den Server geschickt (nur `auth_key` beim Login/Setup).

## Voraussetzungen

- Quell- und Zielkonto nutzen dasselbe Master-Passwort und dasselbe KDF-Salt (bei frischem Ziel: Setup mit Salt aus dem Archiv).
- Zielserver erreichbar per HTTPS (Labor: Loopback).
- Kein Live-Deploy ueber diesen Pfad noetig; rein lokal nutzbar.

## Export (CLI)

```bash
ssh-sync export --server https://<portal-url> --out konto.json
```

Master-Passwort zweimal eingeben (Login + Bestaetigung). Datei wird mit Rechten `0600` geschrieben.

## Export (Portal)

1. Anmelden
2. **Konto exportieren** → Master-Passwort bestaetigen → Download

## Import auf frischen Server

```bash
# Zielserver leer, Setup-Token falls konfiguriert:
export SSH_SYNC_SETUP_TOKEN=...   # optional
ssh-sync import konto.json --server https://<neues-portal> --setup-new --mode replace
```

Optional zuerst Trockenlauf:

```bash
ssh-sync import konto.json --server https://<neues-portal> --setup-new --mode replace --dry-run
```

## Import in bestehendes Konto (gleiches Salt)

```bash
ssh-sync import konto.json --server https://<portal-url> --mode merge
# oder
ssh-sync import konto.json --server https://<portal-url> --mode replace
```

## Import (Portal)

1. Am Ziel anmelden (Konto muss bereits existieren, Salt muss zum Archiv passen)
2. **Konto importieren** → Datei waehlen → Modus / Trockenlauf → Ausfuehren

## Nach dem Import

1. Geraete neu registrieren (`ssh-sync init` bzw. Portal **+ Geraet**)
2. `ssh-sync unlock` und Sync pruefen
3. Quellarchiv sicher aufbewahren oder vernichten

## Ablehnung / Grenzen

- Falsches Passwort, manipuliertes Archiv, unbekannte Schema-Version → Abbruch
- Mehr als ein `payload`-Schluessel (auch Unicode-Escape) → Abbruch; HMAC und Import nutzen nur die geprueften Bytes
- Host-Felder mit verbotenen ssh_config-Direktiven (H2-Allowlist) → Abbruch
- Anderes KDF-Salt am Ziel → Abbruch (kein serverseitiges Umschluesseln)
- Kein Zip-Container (eine JSON-Datei, Groessenlimit 64 MiB)
