# Plan: managed Block ans Ende der ssh-Config

- Annahme: OpenSSH nimmt pro Option den ersten Treffer; `IdentityFile` sammelt alle passenden Bloecke in Dateireihenfolge. Ein Block am Anfang schiebt deshalb Ausweichdateien und Server-Keys vor lokale Eintraege. Marker und Ersetzen an bestehender Stelle bleiben wie heute. Kein Release/Tag in dieser Arbeit.
- Zwei Wege:
  1. **Auftragsweg (gewaehlt):** `spliceManagedBlock` haengt den Block beim ersten Einfuegen ans Dateiende; vorhandener Block bleibt an seiner Stelle und wird dort ersetzt. Bei Kollision mit Ausweichdatei `*.ssh-sync` schreibt der managed Host zwei `IdentityFile`-Zeilen: zuerst die lokale Datei gleichen Namens, dann die Ausweichdatei (falls die lokale existiert). So bleibt Sync fuer Hosts nutzbar, die den Server-Key brauchen, ohne die lokale Datei zu bevorzugen.
  2. **Alternative (gelassen):** Ausweichdatei gar nicht in die Config schreiben, wenn die lokale Datei existiert. Das wuerde die Reihenfolge auch schuetzen, laesst den Server-Key aber fuer managed-only Hosts ungenutzt.
- Ablehnung: Ein Kollege koennte verlangen, bestehende Bloecke vom Anfang ans Ende zu verschieben. Das wuerde die Datei umordnen und `ssh -G` fuer schon syncende Geraete aendern; der Auftrag verbietet Verschieben ohne Not.
- Nachweis: `go test ./internal/sshconfig/…` fuer Anfuegen, Ersetzen in der Mitte, IdentityFile-Reihenfolge; zusaetzlich Wegwerf-Container (Debian + openssh-client) mit `ssh -G` gegen eine vm88-aehnliche Beispiel-Config.
- Grenze: kein Release, kein Tag, keine Aenderung an Daemon/`AllowFirstWrite`, kein Anfassen produktiver Hosts oder Installer.
