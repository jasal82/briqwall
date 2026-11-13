// Mock backend for browser development, design reviews and README screenshots.
// Uses neutral sample data (no real user names, networks or paths).

import type { Backend } from "./api";
import type { AppInfo, ConnState, Reason, Request, Snapshot, Status, UiPrefs, XEvent } from "./types";

const t = () => Math.floor(Date.now() / 1000);
/** Windows path from forward slashes (keeps backslashes out of the source). */
const win = (p: string) => p.split("/").join(String.fromCharCode(92));
const signed = (publisher: string) => ({ Valid: { publisher, catalog: false } });
const catalog = (publisher: string) => ({ Valid: { publisher, catalog: true } });

function app(p: Partial<AppInfo> & { name: string; path: string }): AppInfo {
  return {
    key: p.path.toLowerCase(),
    signature: "Unsigned",
    category: "Installed",
    protected: true,
    location_hint: null,
    first_seen: t() - 86400 * 3,
    last_seen: t() - 120,
    last_blocked: null,
    blocked_count: 0,
    inbound_blocked_count: 0,
    last_remote: null,
    rule: null,
    auto_out: "Allow",
    auto_in: "Block",
    reason: "Installed",
    effective_out: "Allow",
    effective_in: "Block",
    risk: "Low",
    pending: false,
    snoozed_until: null,
    tampered: false,
    ...p,
  };
}

function installed(name: string, path: string, publisher: string, extra: Partial<AppInfo> = {}): AppInfo {
  const reason: Reason = { InstalledSigned: publisher };
  return app({ name, path: win(path), signature: signed(publisher), location_hint: "ProgramFiles", reason, ...extra });
}

function system(name: string, file: string): AppInfo {
  return app({
    name,
    path: win(`C:/Windows/System32/${file}`),
    category: "System",
    signature: catalog("Microsoft Windows"),
    reason: "System",
    auto_in: "Lan",
    effective_in: "Lan",
  });
}

function sampleApps(): AppInfo[] {
  const ask = { auto_out: "Ask", effective_out: "Ask", pending: true } as const;
  const list: AppInfo[] = [
    app({
      name: "QuickNotes",
      path: win("C:/Users/alex/AppData/Local/Programs/QuickNotes/QuickNotes.exe"),
      category: "UserSpace",
      protected: false,
      location_hint: "AppData",
      risk: "High",
      reason: "Unsigned",
      ...ask,
      blocked_count: 4,
      last_blocked: t() - 180,
      last_remote: "185.199.108.153:443 (HTTPS)",
    }),
    app({
      name: "curl",
      path: win("C:/Program Files/Git/mingw64/bin/curl.exe"),
      category: "Lolbin",
      signature: signed("The Git Development Community"),
      location_hint: "ProgramFiles",
      risk: "Medium",
      reason: "Tool",
      ...ask,
      blocked_count: 2,
      last_blocked: t() - 360,
      last_remote: "104.20.23.154:443 (HTTPS)",
      origins: [
        {
          pid: 6604,
          command_line: "curl -sSL https://example.com/install.sh -o install.sh",
          parents: [
            { pid: 6012, name: "bash.exe", path: win("C:/Program Files/Git/usr/bin/bash.exe") },
            { pid: 4410, name: "WindowsTerminal.exe", path: null },
          ],
          last_seen: t() - 360,
          count: 2,
        },
      ],
    }),
    app({
      name: "Windows host process (Rundll32)",
      path: win("C:/Windows/System32/rundll32.exe"),
      category: "Lolbin",
      signature: catalog("Microsoft Windows"),
      risk: "Medium",
      reason: "Tool",
      ...ask,
      blocked_count: 5,
      last_blocked: t() - 40,
      last_remote: "45.133.1.20:443 (HTTPS)",
      origins: [
        {
          pid: 9412,
          command_line: win("rundll32.exe C:/Users/alex/AppData/Local/Temp/upd4.dll,DllRegisterServer"),
          parents: [
            { pid: 8820, name: "WINWORD.EXE", path: win("C:/Program Files/Microsoft Office/root/Office16/WINWORD.EXE") },
            { pid: 5120, name: "explorer.exe", path: win("C:/Windows/explorer.exe") },
          ],
          last_seen: t() - 40,
          count: 3,
        },
        {
          pid: 7716,
          command_line: win("C:/Windows/system32/rundll32.exe C:/Windows/System32/Windows.Storage.ApplicationData.dll,CleanupTemporaryState"),
          parents: [
            { pid: 1288, name: "svchost.exe", path: win("C:/Windows/System32/svchost.exe") },
            { pid: 940, name: "services.exe", path: win("C:/Windows/System32/services.exe") },
          ],
          last_seen: t() - 1500,
          count: 2,
        },
      ],
    }),
    app({
      name: "CamViewer",
      path: win("C:/Users/alex/AppData/Local/Programs/CamViewer/CamViewer.exe"),
      category: "UserSpace",
      protected: false,
      location_hint: "AppData",
      signature: signed("Contoso Cameras Ltd."),
      risk: "Medium",
      reason: { UnknownPublisher: "Contoso Cameras Ltd." },
      ...ask,
      blocked_count: 12,
      last_blocked: t() - 60,
      last_remote: "192.168.1.40:9000",
    }),
    app({
      name: "Discord",
      path: win("C:/Users/alex/AppData/Local/Discord/app-1.0.9187/Discord.exe"),
      category: "UserSpace",
      protected: false,
      location_hint: "AppData",
      signature: signed("Discord Inc."),
      reason: { KnownPublisher: "Discord Inc." },
      last_seen: t() - 10,
    }),
    app({
      name: "Visual Studio Code",
      path: win("C:/Users/alex/AppData/Local/Programs/Microsoft VS Code/Code.exe"),
      category: "UserSpace",
      protected: false,
      location_hint: "AppData",
      signature: signed("Microsoft Corporation"),
      reason: { KnownPublisher: "Microsoft Corporation" },
      rule: { outbound: "Auto", inbound: "Lan", expires: null, created: t() - 5000 },
      effective_in: "Lan",
      last_seen: t() - 700,
    }),
    app({
      name: "Windows PowerShell",
      path: win("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
      category: "Lolbin",
      signature: catalog("Microsoft Windows"),
      auto_out: "Ask",
      effective_out: "Block",
      risk: "Medium",
      reason: "Tool",
      rule: { outbound: "Block", inbound: "Auto", expires: null, created: t() - 90000 },
      blocked_count: 3,
      last_blocked: t() - 90000,
    }),
    installed("Google Chrome", "C:/Program Files/Google/Chrome/Application/chrome.exe", "Google LLC", { last_seen: t() - 30 }),
    installed("Mozilla Firefox", "C:/Program Files/Mozilla Firefox/firefox.exe", "Mozilla Corporation", { last_seen: t() - 2000 }),
    installed("Steam", "C:/Program Files (x86)/Steam/steam.exe", "Valve Corp.", { last_seen: t() - 5400 }),
    installed("Spotify", "C:/Program Files/WindowsApps/SpotifyAB.SpotifyMusic/Spotify.exe", "Spotify AB", { last_seen: t() - 900 }),
    installed("Node.js JavaScript Runtime", "C:/Program Files/nodejs/node.exe", "OpenJS Foundation"),
    installed("Git for Windows", "C:/Program Files/Git/mingw64/bin/git.exe", "Johannes Schindelin"),
    installed("Microsoft Teams", "C:/Program Files/WindowsApps/MSTeams/ms-teams.exe", "Microsoft Corporation"),
    installed("Zoom Workplace", "C:/Program Files/Zoom/bin/Zoom.exe", "Zoom Communications, Inc."),
    installed("Malwarebytes", "C:/Program Files/Malwarebytes/Anti-Malware/Malwarebytes.exe", "Malwarebytes Inc", { last_seen: t() - 4000 }),
    installed("NVIDIA Container", "C:/Program Files/NVIDIA Corporation/NvContainer/nvcontainer.exe", "NVIDIA Corporation"),
    installed("1Password", "C:/Program Files/1Password/app/8/1Password.exe", "AgileBits Inc."),
    app({
      name: "Windows Kernel (System)",
      path: "System",
      key: "pseudo:system",
      category: "Pseudo",
      reason: "Kernel",
      auto_in: "Lan",
      effective_in: "Lan",
    }),
  ];
  const windows: [string, string][] = [
    ["Host Process for Windows Services", "svchost.exe"],
    ["Windows Explorer", "explorer.exe"],
    ["Desktop Window Manager", "dwm.exe"],
    ["Windows Update", "wuauclt.exe"],
    ["Background Task Host", "backgroundTaskHost.exe"],
    ["Runtime Broker", "RuntimeBroker.exe"],
    ["Search Indexer", "SearchIndexer.exe"],
    ["Windows Defender SmartScreen", "smartscreen.exe"],
    ["Microsoft Edge WebView2", "msedgewebview2.exe"],
    ["Settings", "SystemSettings.exe"],
    ["Task Scheduler Engine", "taskhostw.exe"],
    ["Shell Experience Host", "ShellExperienceHost.exe"],
    ["Windows Security Health Service", "SecurityHealthService.exe"],
    ["Delivery Optimization", "dosvc.exe"],
    ["Windows Time", "w32tm.exe"],
    ["Print Spooler", "spoolsv.exe"],
  ];
  for (const [name, file] of windows) list.push(system(name, file));
  return list;
}

export function createMock(): Backend {
  let apps = sampleApps();
  let seq = 0;
  const events: XEvent[] = [];
  const push = (kind: XEvent["kind"], ago = 0) => events.push({ seq: ++seq, time: t() - ago, kind });
  push({ Started: { version: "0.2.0", mode: "Balanced" } }, 600);
  push({ AutoAllowed: { key: "discord", name: "Discord", reason: { KnownPublisher: "Discord Inc." } } }, 420);
  push({ Blocked: { key: "curl", name: "curl", remote: "104.20.23.154:443 (HTTPS)", direction: "Out", by_rule: false } }, 360);
  push({ NewRequest: { key: "curl", name: "curl", risk: "Medium" } }, 359);
  push({ Blocked: { key: "x", name: "Host Process for Windows Services", remote: "203.0.113.24:3389 (RDP)", direction: "In", by_rule: false } }, 240);
  push({ NewRequest: { key: "quicknotes", name: "QuickNotes", risk: "High" } }, 180);
  push({
    RuleChanged: { key: "code", name: "Visual Studio Code", rule: { outbound: "Auto", inbound: "Lan", expires: null, created: t() - 120 } },
  }, 120);
  push({ Blocked: { key: "camviewer", name: "CamViewer", remote: "192.168.1.40:9000", direction: "Out", by_rule: false } }, 60);

  const status: Status = {
    version: "0.2.0",
    mode: "Balanced",
    engine_ok: true,
    engine_error: null,
    privileged: false,
    networks: [{ id: "{net-1}", name: "Home WiFi", windows_category: "Private", trusted: true, explicit: false }],
    network_trusted: true,
    apps_total: 0,
    apps_allowed: 0,
    apps_blocked: 0,
    pending: 0,
    blocked_session: 27,
    started: t() - 600,
    revision: 1,
    hello_enrolled: false,
    settings: {
      mode: "Balanced",
      previous_mode: "Balanced",
      lan_discovery: true,
      learn_publishers: true,
      learned_publishers: ["Contoso Software GmbH"],
      network_trust: {},
    },
  };
  const recount = () => {
    status.apps_total = apps.length;
    status.apps_allowed = apps.filter((a) => a.effective_out === "Allow" || a.effective_out === "Lan").length;
    status.apps_blocked = apps.length - status.apps_allowed;
    status.pending = apps.filter((a) => a.pending).length;
    status.revision++;
  };
  recount();

  let stateCb: ((s: ConnState) => void) | null = null;
  let appsCb: ((a: AppInfo[]) => void) | null = null;
  const emit = () => {
    recount();
    stateCb?.({ connected: true, error: null, status: structuredClone(status) });
    appsCb?.(structuredClone(apps));
  };

  const apply = (req: Request) => {
    if (typeof req === "string") {
      status.hello_enrolled = false;
      return;
    }
    if ("SetMode" in req) {
      push({ ModeChanged: { from: status.mode, to: req.SetMode } });
      if (req.SetMode === "Lockdown" || req.SetMode === "Off") status.settings.previous_mode = status.mode;
      status.mode = req.SetMode;
      status.settings.mode = req.SetMode;
    } else if ("SetRule" in req) {
      apps = apps.map((a) => {
        if (a.key !== req.SetRule.key) return a;
        const r = req.SetRule.rule;
        const map = (x: string, auto: AppInfo["auto_out"]) => (x === "Auto" ? auto : (x as AppInfo["auto_out"]));
        return {
          ...a,
          rule: r,
          pending: false,
          effective_out: r ? map(r.outbound, a.auto_out) : a.auto_out,
          effective_in: r ? map(r.inbound, a.auto_in) : a.auto_in,
        };
      });
    } else if ("Snooze" in req) {
      apps = apps.map((a) => (a.key === req.Snooze.key ? { ...a, pending: false } : a));
    } else if ("Forget" in req) {
      apps = apps.filter((a) => a.key !== req.Forget.key);
    } else if ("SetNetworkTrust" in req) {
      status.networks = status.networks.map((n) =>
        n.id === req.SetNetworkTrust.id ? { ...n, trusted: !!req.SetNetworkTrust.trusted, explicit: true } : n,
      );
    } else if ("SetOptions" in req) {
      if (req.SetOptions.lan_discovery !== null) status.settings.lan_discovery = req.SetOptions.lan_discovery;
      if (req.SetOptions.learn_publishers !== null) status.settings.learn_publishers = req.SetOptions.learn_publishers;
    } else if ("RemovePublisher" in req) {
      status.settings.learned_publishers = status.settings.learned_publishers.filter((p) => p !== req.RemovePublisher);
    }
  };

  const storedLang = (() => {
    try {
      const l = localStorage.getItem("briqwall.lang");
      return l === "de" || l === "en" ? l : "system";
    } catch {
      return "system";
    }
  })();
  const prefs: UiPrefs = {
    notifications: true,
    autostart: true,
    service_exe_available: false,
    language: storedLang,
    system_language: navigator.language.toLowerCase().startsWith("de") ? "de" : "en",
  };

  return {
    snapshot: async (): Promise<Snapshot> => {
      recount();
      return { connected: true, error: null, status: structuredClone(status), apps: structuredClone(apps), events: [...events] };
    },
    send: async (reqs) => {
      await new Promise((r) => setTimeout(r, 250));
      reqs.forEach(apply);
      emit();
      return { kind: "done" };
    },
    helloSupported: async () => true,
    helloEnroll: async () => {
      await new Promise((r) => setTimeout(r, 400));
      status.hello_enrolled = true;
      push("HelloEnrolled");
      emit();
      return { kind: "done" };
    },
    helloRemove: async () => {
      status.hello_enrolled = false;
      emit();
      return { kind: "done" };
    },
    prefs: async () => ({ ...prefs }),
    setNotifications: async (on) => void (prefs.notifications = on),
    setAutostart: async (on) => void (prefs.autostart = on),
    setLanguage: async (lang) => {
      prefs.language = lang;
      try {
        localStorage.setItem("briqwall.lang", lang);
      } catch {
        /* ignore */
      }
    },
    installService: async () => ({ kind: "done" }),
    onState: (cb) => void (stateCb = cb),
    onApps: (cb) => void (appsCb = cb),
    onEvents: () => {},
    onNavigate: () => {},
  };
}
