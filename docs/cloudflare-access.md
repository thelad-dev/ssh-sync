# Cloudflare Access vor dem Portal (Beispiel)

Ziel: Portal unter **https://\<portal-url\>** erreichbar, geschützt durch **Cloudflare Access**. Agenten verbinden sich per **Service Token** (ohne Browser-Login).

Ersetze alle Platzhalter (`<portal-url>`, `<account>`, `<tunnel-uuid>`, `<email>`) durch deine Werte. Keine echten Account-IDs, Hostnamen oder Mailadressen in öffentliche Docs oder Commits schreiben.

## Voraussetzungen

- Domain bei Cloudflare
- ssh-sync läuft auf dem App-Host (Docker), Port nur lokal gebunden (z. B. `127.0.0.1:8080`)
- `cloudflared` auf dem App-Host

## Tunnel (Kurzfassung)

```bash
# cloudflared installieren (siehe Cloudflare-Dokumentation)
cloudflared tunnel login
cloudflared tunnel create ssh-sync
cloudflared tunnel route dns ssh-sync <portal-url>
```

Beispiel `config.yml`:

```yaml
tunnel: <tunnel-uuid>
credentials-file: /home/<user>/.cloudflared/<tunnel-uuid>.json

ingress:
  - hostname: <portal-url>
    service: http://127.0.0.1:8080
  - service: http_status:404
```

## Access-Anwendung

1. Zero Trust → Access → Applications → Self-hosted
2. Domain: `<portal-url>`
3. Policy: erlaubte Identitäten (eigene Admin-Mail, keine öffentliche Beispiel-Mail)
4. Optional: Bypass-Pfade für `/install` und `/downloads` nur wenn du die Risiken verstehst (Installer sind signiert, aber trotzdem Prefer Access + Service Token)

## Service Token für Agenten (N14)

Aktuell nutzt das Projekt **einen gemeinsamen** Cloudflare-Access-Service-Token für alle Geräte (über Portal-Bootstrap oder Env).

Folgen:

- Widerruf für ein Gerät sperrt alle
- Das Secret liegt in jeder `config.json` und ist für Admins lesbar

Empfehlung bis per-Gerät-Tokens existieren: Token rotieren bei Geräteverlust, Secret nicht in Tickets/Chats posten, Zugriff auf `/api/client-bootstrap` streng schützen.

Env auf dem App-Host:

```bash
SSH_SYNC_CF_ACCESS_CLIENT_ID=...
SSH_SYNC_CF_ACCESS_CLIENT_SECRET=...
SSH_SYNC_PUBLIC_URL=https://<portal-url>
```

## Client

```bash
ssh-sync init --server https://<portal-url> --name laptop \
  --access-client-id "$CF_ACCESS_CLIENT_ID" \
  --access-client-secret "$CF_ACCESS_CLIENT_SECRET"
```

Oder Werte in `config.json` als `access_client_id` / `access_client_secret`.

## Installer

Skript speichern, lesen, ausführen  -  kein Pipe-zu-Shell:

```bash
curl -fsSL -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  "https://<portal-url>/install/linux.sh" -o install-linux.sh
less install-linux.sh
sh install-linux.sh
```
