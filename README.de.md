# Briqwall – Firewall für Windows, die man nicht konfigurieren muss

[English](README.md) · **Deutsch**

Briqwall ist eine anwendungsbasierte Firewall für Windows 10/11 auf Basis der
**Windows Filtering Platform (WFP)**. Sie besteht aus einem Systemdienst
(`briqwall-service.exe`, Rust) und einer modernen Oberfläche (`briqwall.exe`,
Tauri 2 mit Svelte 5 und TypeScript), die über eine abgesicherte Named Pipe
miteinander sprechen. Die Oberfläche gibt es auf Deutsch und Englisch; sie folgt
der Windows-Anzeigesprache und lässt sich in den Einstellungen umschalten.

Screenshots und eine Programmübersicht stehen in der
[englischen README](README.md#a-quick-tour).

## Das Grundproblem – und der Kompromiss

Klassische Firewalls scheitern an einem Dilemma:

* **Ausgehend alles erlauben** (Windows-Standard) ist bequem, schützt aber nicht
  vor Schadsoftware, die nach Hause telefoniert.
* **Bei jeder Verbindung fragen** schützt in der Theorie – in der Praxis klicken
  Menschen nach dem zehnten Pop-up nur noch „Erlauben“. Das ist schlechter als
  gar kein Schutz, weil es Sicherheit vortäuscht.

Briqwall löst das, indem es **nicht über Ports und IP-Adressen, sondern über die
Herkunft eines Programms** entscheidet. Die zentrale Frage lautet:

> *Hätte ein Programm ohne Administratorrechte diese Datei hier ablegen können?*

Software, die nur ein Administrator installieren konnte (Windows, Program Files,
Store-Apps), ist eine bewusste Entscheidung des Besitzers. Eine `.exe`, die in
`Downloads`, `Temp` oder `AppData` aufgetaucht ist, kann dagegen von jedem
Prozess stammen – auch von Schadcode. Genau dort setzt Briqwall an. Ergebnis auf
einem typischen PC: **~90 % aller Programme laufen ohne jede Rückfrage**, und die
wenigen Rückfragen betreffen genau die Programme, bei denen sie sinnvoll sind.

## Was Briqwall anders macht

| Idee | Umsetzung |
|---|---|
| **ACL-basierte Herkunft statt Pfadlisten** | Für jede `.exe` werden Besitzer und DACL der Datei *und* ihres Ordners ausgewertet. Kann ein normaler Benutzer die Datei ändern, ersetzen oder eine DLL daneben legen, gilt sie als „Benutzerordner“. Damit fallen auch bekannte Lücken wie `C:\Windows\Temp` oder `spool\drivers\color` richtig heraus, an denen reine Pfadregeln scheitern. |
| **LOLBin-Härtung** | PowerShell, mshta, certutil, rundll32, bitsadmin & Co. sind echt von Microsoft signiert, werden aber von Angreifern zum Nachladen von Schadcode genutzt. Sie bekommen *nicht* automatisch Netzzugang (außer im Modus „Entspannt“). Das gilt auch für **Kopien**: Ein solches Werkzeug wird am Namen erkannt, mit dem es gebaut wurde, nicht am Dateinamen – und eine Windows-Systemdatei außerhalb eines geschützten Ordners wird in keinem Modus automatisch erlaubt. |
| **Asymmetrische Rechte** | Den Schutz **verschärfen** darf jeder sofort (blockieren, Notfall-Sperre, strengerer Modus). Den Schutz **lockern** braucht einen Nachweis, dass ein Mensch zugestimmt hat: entweder eine **Windows-Hello-Signatur** (Fingerabdruck, Gesicht oder PIN; der Schlüssel liegt im TPM, der Dienst prüft eine Einmal-Nonce plus die exakten Änderungen) oder als Rückfall eine UAC-Abfrage auf dem sicheren Desktop. Mehrere Anfragen lassen sich mit einer Bestätigung erledigen. Schadsoftware im Benutzerkontext kann sich so **nicht selbst freischalten**, auch nicht über die Pipe. |
| **Inbox statt Pop-up-Flut** | Blockierte, unbekannte Apps landen in einer ruhigen „Anfragen“-Liste mit Klartext-Begründung, Risikostufe und letztem Verbindungsziel. Eine dezente Windows-Benachrichtigung informiert, unterbricht aber nicht. Bei hohem Risiko ist „Blockieren“ die hervorgehobene Option (Nudging zur sicheren Wahl); solche Anfragen bleiben bei einem gesammelten „Erlauben“ außen vor. Mehrere neue Anfragen auf einmal kommen als eine Benachrichtigung. Das Aktivitätsprotokoll bleibt 30 Tage erhalten, auch über Neustarts, und nennt bei gelockertem Schutz, wer bestätigt hat (Windows Hello oder Administrator); nachgeschlagene Namen werden nicht gespeichert. |
| **Prozess-Herkunft** | Gemeinsam genutzte Werkzeuge wie `rundll32.exe` oder PowerShell verwenden Windows und Angreifer gleichermaßen. Deshalb zeigt jede Anfrage, **welche Prozessinstanz** den Versuch ausgelöst hat: Kette der Elternprozesse und vollständige **Befehlszeile** (bei rundll32 also DLL und Funktion). Startet ein Office-Programm, PDF-Reader oder Skript-Host das Werkzeug – ein klassisches Makro-Malware-Muster –, warnt Briqwall deutlich und stuft das Risiko hoch. Technisch: WFP-Ereignisse enthalten keine Prozess-ID, das Sicherheitsereignis 5157 schon; ein Cache deckt kurzlebige Prozesse ab. Befehlszeilen bleiben nur im Arbeitsspeicher. |
| **Regeln im Voraus** | Regeln entstehen nicht nur als Antwort auf eine Anfrage: Über *Apps › Programm hinzufügen* lässt sich ein beliebiges Programm aufnehmen und entscheiden, bevor es zum ersten Mal ins Netz will. Im selben Detailbereich wird eine eigene Regel auch wieder entfernt. |
| **Namen statt Adressen** | Der Dienst hört die ETW-Ereignisse des DNS-Clients mit und merkt sich, welcher Name zu welcher Adresse aufgelöst wurde. In einer Anfrage steht dann `telemetry.example.com` neben `45.133.1.20:443`. Der Zwischenspeicher liegt nur im Arbeitsspeicher und wird nie auf Platte geschrieben. |
| **Befristete Freigaben** | „1 Stunde erlauben“ – danach schließt Briqwall die Tür von selbst. Ideal für PowerShell-Sitzungen oder Installer. |
| **Herausgeber lernen** | Wer eine signierte App dauerhaft erlaubt, erlaubt damit auch ihre Updates (die oft in neuen, versionierten Ordnern landen) und andere Apps desselben Herausgebers. Abschaltbar, Liste jederzeit einsehbar. |
| **Manipulationserkennung** | Beim Erlauben merkt sich Briqwall die Identität (Herausgeber bzw. SHA-256). Wird die Datei danach ausgetauscht, wird die Freigabe ausgesetzt und erneut gefragt. |
| **Eine Entscheidung pro Produkt** | „Streng“ fragt bei jedem unsignierten Werkzeug eines installierten Programms nach. *Alles in „Git“* vertraut dem Programmordner als Ganzem – nur bei Ordnern, in die ausschließlich Administratoren schreiben dürfen; die Liste steht in den Einstellungen. |
| **Netzwerk-Kontext** | Eingehende LAN-Dienste (Dateifreigabe, Casting, Gerätesuche) gibt es nur in vertrauenswürdigen Netzwerken. Im Café-WLAN ist der PC unsichtbar. Die Einstufung folgt Windows, kann aber pro Netzwerk mit einem Klick überschrieben werden. Die Freigaben sind im Filter an das Netzwerkprofil von Windows gebunden und schließen sich deshalb von selbst, wenn das Netzwerk wechselt, während der Dienst nicht läuft. |
| **Ausfallsicher (fail-closed)** | Alle Filter sind **persistent** in der WFP gespeichert. Stürzt der Dienst ab oder wird er beendet, bleibt das letzte Regelwerk aktiv – auch über Neustarts hinweg, schon bevor der Dienst startet. Regelwechsel passieren in einer einzigen WFP-Transaktion, es gibt nie einen ungeschützten Moment. |
| **Koexistenz mit der Windows-Firewall** | Briqwall nutzt einen eigenen Sublayer. In WFP gewinnt ein Block in *irgendeinem* Sublayer – Briqwall kann den Schutz der Windows-Firewall also nur ergänzen, nie aushebeln. |

### Die Schutzstufen

| Kategorie | Entspannt | **Ausgewogen** (Standard) | Streng |
|---|---|---|---|
| Windows-Komponenten | ✅ | ✅ | ✅ |
| Installiert + signiert | ✅ | ✅ | ✅ |
| Installiert, unsigniert | ✅ | ✅ | ❓ |
| Benutzerordner, bekannter Herausgeber | ✅ | ✅ (❓ in Downloads, Temp, Desktop, Öffentlich, Wechseldatenträger) | ❓ |
| Benutzerordner, unbekannter Herausgeber | ✅ | ❓ | ❓ |
| Benutzerordner, unsigniert | ❓ | ❓ | ❓ |
| Missbrauchte Windows-Werkzeuge (LOLBins) | ✅ | ❓ | ❓ |
| Eingehend | Windows entscheidet | nur Windows-Dienste aus dem LAN, nur in vertrauenswürdigen Netzen | alles blockiert |

✅ = automatisch erlaubt · ❓ = blockiert, bis Sie entscheiden. Dazu kommen
**Notfall-Sperre** (alles zu außer Loopback/DHCP, ein Klick, auch im Tray-Menü)
und **Aus**.

## Architektur

```
┌────────────────────────── Benutzersitzung ──────────────────────────┐
│ briqwall.exe (unprivilegiert)        briqwall.exe --apply (erhöht)  │
│  WebView2 (Svelte/TS) · Tray · Toasts  eine Änderung, dann Ende     │
└──────────────┬───────────────────────────────────┬──────────────────┘
               │ Named Pipe briqwall-control (JSON, Länge+Payload)        
┌──────────────▼───────────────────────────────────▼──────────────────┐
│ briqwall-service.exe (LocalSystem)                                     │
│  ipc_server ─┐                                                      │
│  procmon ────┼──► core (Actor, ein Thread, besitzt allen Zustand)   │
│  net events ─┘      │  policy  (Vertrauensentscheidung, rein)       │
│                     │  trust   (ACLs, Authenticode, Katalog, SHA-256)│
│                     │  compiler(Policy → WFP-Filter)                │
│                     ▼                                               │
│                wfp.rs ──► BFE / Windows Filtering Platform          │
│                          ALE_AUTH_CONNECT (aus) · ALE_AUTH_RECV_ACCEPT (ein)│
└─────────────────────────────────────────────────────────────────────┘
```

**Filterlayout** im Briqwall-Sublayer (höheres Gewicht gewinnt):

| Gewicht | Inhalt |
|---|---|
| 15 | Loopback, DHCP (immer erlaubt, auch in der Sperre; DHCP nur für den DHCP-Client von Windows und dessen Ports) |
| 14 | Notfall-Sperre: alles blockieren |
| 13 | Notwendiges ICMP (PMTU, IPv6-Nachbarerkennung); Echo-Request bleibt zu |
| 12 | Explizite Blockierregeln pro App |
| 10 | Freigaben pro App (überall oder nur LAN-Bereiche) |
| 0 | Standard-Block – hier landen „wartende“ Apps und erzeugen eine Anfrage |

**Proaktive Bewertung:** Ein Prozessmonitor bewertet jedes neu gestartete
Programm, *bevor* es seine erste Verbindung aufbaut, und setzt bei Bedarf die
Freigabe. Beim ersten Start werden alle laufenden Programme vor dem ersten
Regelaufbau bewertet. Blockierte Versuche kommen über WFP-Net-Events
(`FwpmNetEventSubscribe0`) zurück und werden der verursachenden Regel
zugeordnet. Dafür aktiviert der Dienst die Audit-Unterkategorien „Filtering
Platform Connection/Packet Drop“ (nur Fehler); bei der Deinstallation werden
sie zurückgesetzt.

**Sicherheit der Steuerung:**

* Pipe-DACL: Netzwerk-Logons verweigert, Remote-Clients abgewiesen; normale
  Benutzer dürfen verbinden, aber keine weiteren Pipe-Instanzen anlegen (Schutz
  vor Pipe-Squatting/Man-in-the-Middle). Die erste Instanz wird mit
  `FILE_FLAG_FIRST_PIPE_INSTANCE` erzeugt.
* Clients verbinden mit `SECURITY_IDENTIFICATION`: Der Server darf die
  Identität prüfen, aber nie in ihrem Namen handeln.
* Die Erhöhung wird per `ImpersonateNamedPipeClient` + `CheckTokenMembership`
  geprüft. Gefilterte UAC-Token zählen nicht als Administrator.
* Das Datenverzeichnis `C:\ProgramData\Briqwall` wird direkt mit einer
  geschützten DACL angelegt (SYSTEM/Administratoren schreiben, Benutzer lesen).
  Ein Ordner, der schon da ist und nicht SYSTEM oder den Administratoren
  gehört (oder eine Verknüpfung ist), wird beiseitegeschoben und neu angelegt –
  in ProgramData darf jeder Benutzer Ordner erstellen.
* Eine Regel gilt auch dann als Lockerung, wenn sie heute nichts Neues erlaubt,
  aber länger hält: eine befristete Freigabe verlängern oder eine automatische
  Freigabe als eigene Regel festschreiben braucht eine Bestätigung.
* Der erhöhte Helfer (`briqwall.exe --apply`) zeigt die Änderung im Klartext
  und fragt nach, bevor er sie an den Dienst schickt. Die UAC-Abfrage nennt nur
  „Briqwall“, nicht die Änderung – und jedes Programm kann den Helfer starten.
* Dateirechte zählen nur auf Datenträgern, die die Administratoren dieses PCs
  kontrollieren: dem Windows-Laufwerk und internen Festplatten. Eine
  USB-Platte, Speicherkarte oder ein Datenträgerabbild bringt eigene Besitzer
  und Rechte mit. Dateien auf Netzwerkfreigaben öffnet der Dienst gar nicht
  (als SYSTEM würde er diesen PC an jenem Server anmelden); Programme dort
  fragen immer nach und werden erst gelesen, wenn Sie sie erlaubt haben.
* Ein Programm erscheint nur dann unter der Beschreibung aus seiner Datei, wenn
  jemand dafür einsteht – eine gültige Signatur oder ein Administrator, der es
  installiert hat. Alles andere heißt wie seine Datei; ein unsignierter
  Download kann sich so nicht „Windows Update“ nennen.
* Hostnamen sind als *unbestätigt* gekennzeichnet, solange sie nicht von einem
  Programm gemeldet wurden, das nur Administratoren ändern können (in der Regel
  der DNS-Client von Windows): Jedes Programm kann DNS-Ereignisse schreiben und
  behaupten, einen harmlosen Namen nachgeschlagen zu haben.
* Kommandozeilen blockierter Prozesse bekommt nur das Konto zu sehen, unter dem
  der Prozess lief, sowie Administratoren.
* `briqwall-service install` richtet den Dienst nicht aus einem Ordner ein, in
  den Nicht-Administratoren schreiben dürfen.
* Bekannte Herausgeber werden am ganzen Zertifikatsnamen erkannt (plus
  Rechtsform wie „Inc.“), nicht am Namensanfang.
* Das `briqwall:`-Protokoll (Klick auf eine Benachrichtigung) kann nur das Fenster
  öffnen, nie Aktionen auslösen – jede Webseite könnte es aufrufen.

## Installieren

Den Installer `Briqwall-<version>-setup-x64.exe` von der Release-Seite laden und
ausführen. Er

* installiert für alle Benutzer nach `C:\Program Files\Briqwall` – ein Ort, an
  dem nur Administratoren schreiben dürfen, damit niemand den Dienst austauschen
  kann,
* richtet den Firewall-Dienst ein (automatischer Start, Neustart bei Fehlern),
* aktualisiert eine bestehende Installation, ohne dass der Schutz unterbrochen
  wird (die WFP-Filter bleiben während des Updates aktiv),
* übernimmt Regeln und Einstellungen der Vorgängerversion **xWall**,
* lässt sich still verteilen: `Briqwall-<version>-setup-x64.exe /S`.

Deinstallieren über *Einstellungen › Apps*. Dabei werden Dienst und alle
WFP-Filter entfernt; die Regeln bleiben erhalten, außer man wählt im
Deinstallationsdialog das Löschen der App-Daten.

## Bauen

Voraussetzungen: Rust (stable, MSVC-Toolchain), Node.js 20+, Windows 10/11
mit WebView2 (bei Windows 11 vorinstalliert).

```powershell
.\scripts\build.ps1
```

Das Skript prüft die Typen der Oberfläche, baut das Frontend, den Dienst, führt
alle Tests aus (`-SkipTests` zum Überspringen) und erzeugt mit der Tauri-CLI
Oberfläche und Installer:

| Datei | Inhalt |
|---|---|
| `target\release\bundle\nsis\Briqwall_<version>_x64-setup.exe` | Installer |
| `target\release\briqwall.exe` | Oberfläche (Frontend eingebettet) |
| `target\release\briqwall-service.exe` | Firewall-Dienst |

Die Tests prüfen unter anderem Policy-Matrix, Filter-Compiler und die
Windows-Hello-Signaturprüfung, und sie testen gegen das echte System, dass etwa
`notepad.exe` als geschützt und signiert erkannt wird und eine Datei im
Temp-Ordner als Benutzerordner gilt.

Hinweis: Die Oberfläche bettet beim Kompilieren `ui/dist` und den Dienst
(`crates/briqwall-ui/binaries/`) ein. Ein einzelnes `cargo build` funktioniert
deshalb erst, nachdem `build.ps1` einmal gelaufen ist.

Die Branding-Bilder des Installers erzeugt `design\make-installer-images.ps1`.

### Releases (GitHub Actions)

* **CI** (`.github/workflows/ci.yml`): bei jedem Push auf `main` und bei Pull
  Requests – Typprüfung, Frontend-Build, alle Rust-Tests.
* **Release** (`.github/workflows/release.yml`): ein Tag `v<version>` baut den
  Installer und veröffentlicht ein GitHub-Release mit Installer,
  Binaries-Zip und `SHA256SUMS.txt`. Der Tag muss zur Version in `Cargo.toml`
  passen. Manuell gestartet entstehen nur Build-Artefakte zum Testen.

  ```bash
  git tag v0.11.0
  ```

  ```bash
  git push origin v0.11.0
  ```

* **Festgelegte Actions und Herkunftsnachweis:** Fremde Actions sind auf einen
  Commit festgelegt (Dependabot schlägt Aktualisierungen vor). Bei öffentlichen
  Repositories erhält ein Release zusätzlich einen signierten Herkunftsnachweis;
  ein Download lässt sich mit
  `gh attestation verify <Datei> --repo <Besitzer>/<Repository>` prüfen.
* **Code-Signatur (optional):** Sind die Repository-Secrets
  `WINDOWS_CERTIFICATE` (Base64 einer `.pfx`) und
  `WINDOWS_CERTIFICATE_PASSWORD` gesetzt, signiert die Pipeline Programme und
  Installer. Ohne Signatur zeigt Windows SmartScreen beim ersten Start eine
  Warnung.

### Oberfläche entwickeln

```bash
npm --prefix ui run dev
```

Im normalen Browser (`http://localhost:5173`) läuft die Oberfläche mit
realistischen **Demo-Daten** (`ui/src/lib/mock.ts`), ganz ohne Dienst. In
`briqwall.exe` spricht sie über Tauri-Commands und -Events mit dem Dienst. Der
Rust-Teil fragt den Dienst einmal pro Sekunde ab (bei verstecktem Fenster alle
drei Sekunden) und schickt nur *Änderungen* an die Oberfläche. Die App-Liste –
mit Abstand die größte Antwort – wird nur geholt, solange das Fenster sichtbar
ist: sofort, wenn sich etwas Entscheidungsrelevantes geändert hat, bei bloßen
Zählern höchstens alle fünf Sekunden. Die App-Liste ist virtualisiert, im DOM liegen also nur die
sichtbaren Zeilen. Das Design orientiert sich an Windows 11, die Schrift ist
Segoe UI Variable, und hell/dunkel folgt dem System (umschaltbar). Der
abgestimmte Entwurf liegt in `design/mock.html`.

**Übersetzungen:** `ui/src/lib/i18n/en.ts` ist das Referenz-Wörterbuch,
`de.ts` muss exakt dieselben Schlüssel haben – das prüft TypeScript
(`npm --prefix ui run check`). Der Dienst liefert keine fertigen Sätze, sondern
Codes (Begründung, Ort, Fehler, Ereignis), die erst die Oberfläche übersetzt.
Tray-Menü, Benachrichtigungen und Installer folgen derselben Spracheinstellung.

**Screenshots** für die README erzeugt `node design/screenshots.mjs` (bei
laufendem `npm --prefix ui run dev`) mit Demo-Daten nach `docs/screenshots/`.

### Ohne Installer

Für Entwicklung oder manuelle Verteilung: `scripts\install.ps1` in einer
PowerShell als Administrator kopiert die Programme aus `target\release` (oder
aus dem Binaries-Zip eines Releases) nach `C:\Program Files\Briqwall` und
richtet den Dienst ein. Entfernen mit `scripts\uninstall.ps1` (`-Purge` löscht
auch Regeln und Protokolle).

### Nützliche Befehle

| Befehl | Wirkung |
|---|---|
| `briqwall-service check <pfad.exe>` | Zeigt, wie Briqwall eine Datei einstuft (kein Admin nötig) |
| `briqwall-service reset` | **Notfall:** entfernt sofort alle Briqwall-Filter |
| `briqwall-service console` | Dienst im Vordergrund mit Log-Ausgabe |
| `briqwall-service uninstall [--purge]` | Dienst und alle WFP-Objekte entfernen |

Ohne Administratorrechte läuft `console` im **Anzeige-Modus**: Bewertung,
Netzwerkerkennung und Oberfläche funktionieren, Filter werden aber nicht
gesetzt. Daten liegen dann in `%LOCALAPPDATA%\Briqwall-dev`.

Protokoll: `C:\ProgramData\Briqwall\service.log`.

## Projektstruktur

```
crates/
  briqwall-common/   Datenmodell, IPC-Protokoll, Pipe-Client
  briqwall-service/  Dienst
    wfp.rs        WFP-Wrapper (Provider, Sublayer, Filter, Transaktionen, Net Events)
    compiler.rs   Policy → Filter (mit Tests)
    policy.rs     Vertrauensentscheidung, LOLBins, bekannte Herausgeber (mit Tests)
    trust.rs      ACL-Prüfung, Authenticode inkl. Katalogsignaturen, Versionsinfos
    core.rs       Zustand, Bewertung, inkrementelle Filter-Updates, IPC-Logik
    watchers.rs   Prozessmonitor, Net-Event-Callback, Gerätepfade, Netzwerkliste
    ipc_server.rs Abgesicherte Named Pipe
    store.rs      Persistenz (atomar), geschütztes Datenverzeichnis, Logging
    hello.rs      Prüfung von Windows-Hello-Signaturen (mit Tests)
    procinfo.rs   Befehlszeile und Elternkette blockierter Prozesse
    evaluator.rs  Worker-Threads, die neu gestartete Programme prüfen (mit Tests)
  briqwall-ui/       Tauri-Hülle: Commands, Events, Tray, Toasts, Hello, Elevation
    installer/    NSIS-Hooks (Dienst einrichten/entfernen, Migration) und Branding
ui/               Oberfläche (Svelte 5 + TypeScript + Vite)
  src/lib/        Typen, API-Brücke, Demo-Daten, Zustand, Bausteine
  src/lib/i18n/   Wörterbücher (en.ts = Referenz, de.ts)
  src/pages/      Übersicht, Anfragen, Apps (+ Detail-Panel), Aktivität, Einstellungen
design/           UI-Mock, App-Icon (SVG), Installer-Bilder, Screenshot-Skript
docs/screenshots/ Screenshots für die README
scripts/          build.ps1 / install.ps1 / uninstall.ps1
.github/workflows CI und Release-Pipeline
```

## Bekannte Grenzen & nächste Schritte

* **Erste Verbindung unbekannter Apps:** Ohne Kernel-Callout-Treiber kann eine
  Verbindung nicht „angehalten“ werden, bis der Nutzer entscheidet. Unbekannte
  Apps erhalten beim ersten Versuch einen Fehler und verbinden sich nach der
  Freigabe beim nächsten Versuch. Ein signierter WFP-Callout-Treiber
  (ALE-Pend/Redirect) würde das beheben, braucht aber eine
  Microsoft-Treibersignatur.
* **svchost-Dienste** teilen sich eine App-ID. Eine Unterscheidung pro Dienst
  (`FWPM_CONDITION_ALE_USER_ID` mit Service-SID) wäre eine sinnvolle Erweiterung.
* **Code-Signatur:** Die Release-Pipeline signiert, sobald ein Zertifikat als
  Secret hinterlegt ist. Ohne Zertifikat zeigen SmartScreen und UAC keinen
  verifizierten Herausgeber.
* **Mehrere Windows-Konten:** Jedes Konto richtet einen eigenen Hello-Schlüssel
  ein; Konten ohne Schlüssel bestätigen per UAC. Der Schlüssel selbst verlässt
  das TPM des Rechners nicht, auf dem er entstanden ist.
* **Wege an einer Anwendungs-Firewall vorbei.** Briqwall entscheidet pro
  Programm; ein blockiertes Programm kann deshalb über ein erlaubtes nach außen
  gelangen:
  * *DNS:* Namen löst der DNS-Client von Windows auf, nicht das Programm. Ein
    blockiertes Programm kann Daten in den Namen verstecken, die es nachschlägt.
  * *Systemdienste:* Downloads über BITS oder Seiten in einem Browser oder
    WebView, den das Programm startet, laufen unter dem Namen des Dienstes bzw.
    Browsers. Briqwall vermerkt im Aktivitätsprotokoll (und meldet), wenn ein
    Browser oder ein erlaubtes Werkzeug von einem Programm gestartet wird, das
    selbst nicht ins Netz darf – verhindern kann es das nicht.
  * *WSL 2, Hyper-V, Windows-Sandbox:* Deren Verkehr läuft nicht über die
    Schicht, auf der Windows das Programm kennt; Briqwall sieht ihn nicht.
* **Windows Hello:** Die Abfrage kann nicht anzeigen, was bestätigt wird, und
  jedes Programm des Benutzers kann eine Signatur anfordern. Lehnen Sie eine
  Hello-Abfrage ab, die Sie nicht selbst ausgelöst haben; das
  Aktivitätsprotokoll zeigt jede bestätigte Änderung und wer sie bestätigt hat.
* **Administrator-Sitzungen:** Ist die Benutzerkontensteuerung ausgeschaltet
  oder wurde Briqwall als Administrator gestartet, werden Änderungen ohne
  Nachfrage übernommen – für jedes so gestartete Programm. Die Übersicht weist
  darauf hin.
* **Notfall:** Sollte etwas die Verbindung blockieren, entfernt
  `briqwall-service reset` (als Administrator) sofort alle Filter.

## Lizenz

Lizenziert nach Wahl unter

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT-Lizenz ([LICENSE-MIT](LICENSE-MIT))

Beiträge, die zur Aufnahme in dieses Projekt eingereicht werden, stehen –
sofern nicht ausdrücklich anders angegeben – im Sinne der Apache-2.0-Lizenz
unter denselben beiden Lizenzen, ohne zusätzliche Bedingungen.
