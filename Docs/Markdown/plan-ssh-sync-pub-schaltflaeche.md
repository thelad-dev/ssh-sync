# Plan: Pub-Schaltflaeche liefert Public Key ohne .pub-Import

## Annahme

- Captain meint die Schaltflaeche `Pub` in der Key-Liste des Portals (`web/app.js` → `renderIdentities`).
- Browser-Import speichert `public_key` nur, wenn eine `.pub`-Datei mitgeliefert wird; Ableitung aus dem Private Key fehlt (anders als `internal/importlocal`).
- Ohne `public_key` wird der Pub-Button gar nicht gerendert; mit `public_key` kopiert der Klick still in die Zwischenablage ohne sichtbares Feedback.
- OpenSSH-PEM (`BEGIN OPENSSH PRIVATE KEY`) enthaelt den Public-Key-Blob im Klartext; daraus laesst sich die authorized_keys-Zeile ohne zusaetzliche Kryptografie ableiten.
- Klassische PKCS#1/PKCS#8-PEM ohne OpenSSH-Header sind seltener; wenn Ableitung scheitert, bleibt eine klare Fehlermeldung.

## Zwei Wege

1. **Auftragsweg:** Pub immer anzeigen; beim Klick Private Key entschluesseln, Public Key ableiten, speichern, sichtbar liefern (Kopie + Dialog/Anzeige). Beim Import ebenfalls ableiten, wenn keine `.pub` da ist.
2. **Alternative (nicht gewaehlt):** Nur Import-Ableitung, Pub-Button unveraendert. Laesst bestehende Identities ohne `public_key` und den stillen Clipboard-Klick unbehoben.

Gewaehlt: Weg 1, weil der Captain explizit den Klick auf Pub und Erzeugung durch das Tool verlangt.

## Ablehnung

- Ein erfahrener Kollege wuerde ablehnen, wenn Pub nur Clipboard ohne sichtbaren Key liefert (wirkt weiter wie „tut nichts“).
- Ablehnung, wenn Ableitung nur bei frischem Import greift und bereits importierte Keys ohne Pub weiter ohne Button bleiben.
- Ablehnung, wenn Master-Passwort oder echte Schluessel des Captains angefasst werden (nur Wegwerf-Keys in Tests).

## Nachweis

- Regression: `node web/openssh_pub_test.mjs` — extrahiert Public Key aus OpenSSH-Private-PEM ohne `.pub`; schlaegt vorher fehl (fehlende API).
- Browser E2E: Portal lokal, Import Private Key ohne `.pub`, Klick auf Pub zeigt/liefert `ssh-…`-Zeile (chrome-devtools-axi).

## Grenze

- Keine Aenderung an Agent-Pull, Host-Config, Auth, Docker-Compose oder Captain-Konten/Schluesseln.
- Kein Import von `.pub`-Dateien als neue Pflicht.
- RSA/ECDSA-Ableitung nur soweit OpenSSH-Klartext-Public-Blob reicht; kein neues Crypto-Vendor-Paket.
