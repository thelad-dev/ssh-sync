# Plan: Portal leer wegen CSP vs. Importmap

## Annahme

- Die leere Portal-Seite kommt allein vom blockierten Inline-`<script type="importmap">`, nicht von einem API- oder Rendering-Fehler im Markup.
- Der von Chrome vorgeschlagene Hash `sha256-6MO+MTaSPv15Pf6SkLy7Wq0cEZSDs5/gMWQ5mTYTZRQ=` entspricht dem exakten Textinhalt zwischen den Script-Tags der ausgelieferten `web/index.html`.
- Vendor-Module (`@noble/...` Bare-Imports) bleiben; die Importmap bleibt der Resolver.

## Zwei Wege

1. **Auftragsweg:** SHA-256 der Importmap (bzw. aller Inline-Scripts) aus dem echten HTML berechnen und als `'sha256-...'` in `script-src` aufnehmen; CSP sonst unverändert (kein `unsafe-inline` für Scripts).
2. **Alternativ:** Importmap entfernen und Vendor-Dateien auf relative Imports umbiegen.

**Wahl:** Weg 1. Weniger invasiv, Vendor bleibt unangetastet, Hash kann nicht gegen den Inhalt driften, wenn er zur Laufzeit aus `index.html` berechnet wird. Weg 2 würde gepatchte Vendor-Kopien und künftige Update-Reibung bedeuten.

## Ablehnung

- Ein fest eingetragener Hash-String ohne Ableitung aus der Datei driftet bei Whitespace-Änderungen.
- `unsafe-inline` in `script-src` würde das Symptom lösen, aber die CSP aufweichen.
- Nur die Importmap hardcoden und andere spätere Inline-Scripts vergessen.

## Nachweis

- `go test ./internal/api/ -count=1` inkl. Test: jeder Inline-Script/Style-Hash aus der ausgelieferten HTML steckt in der CSP; Hash im Header passt zum Importmap-Inhalt.
- Browser gegen lokale Instanz: Login/Setup sichtbar, keine CSP-/Modul-Konsolenfehler, Screenshot.
- `git blame`/`git log`: Fehler seit Initial-Commit, alle Tags v0.1.0–v0.1.4 betroffen.

## Grenze

- Kein Release, kein Tag, kein Deploy.
- Keine CSP-Aufweichung (`unsafe-inline` für Scripts bleibt verboten).
- Keine Umbauten an Auth, API oder Vendor-Quellen außer nötiger CSP-/Test-Anpassung.
- `style-src 'unsafe-inline'` bleibt wie bisher (nicht Teil dieses Bugs).
