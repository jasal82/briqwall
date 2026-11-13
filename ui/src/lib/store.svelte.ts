import { backendPromise, isMock, type Backend } from "./api";
import { i18n, t, type LangPref } from "./i18n/index.svelte";
import type { ActionResult, AddResult, AppInfo, Request, Status, UiPrefs, XEvent } from "./types";

export type Page = "overview" | "inbox" | "apps" | "activity" | "settings";
export type Theme = "system" | "light" | "dark";
type ToastTone = "ok" | "warn" | "danger";

const riskOrder = { High: 2, Medium: 1, Low: 0 } as const;

function loadTheme(): Theme {
  try {
    const t = localStorage.getItem("briqwall.theme");
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* storage unavailable */
  }
  return "system";
}

class Store {
  ready = $state(false);
  connected = $state(false);
  error = $state<string | null>(null);
  status = $state<Status | null>(null);
  apps = $state.raw<AppInfo[]>([]);
  events = $state.raw<XEvent[]>([]);
  prefs = $state<UiPrefs>({
    notifications: true,
    autostart: true,
    service_exe_available: false,
    language: "system",
    system_language: "en",
    user_sid: "",
    user_name: "",
  });

  page = $state<Page>("overview");
  theme = $state<Theme>(loadTheme());
  busy = $state(0);
  helloSupported = $state(false);
  toast = $state<{ id: number; text: string; tone: ToastTone } | null>(null);

  /**
   * Is this Windows account set up for Hello? A key without a sid predates
   * per-account enrollment and belonged to the device as a whole.
   */
  helloEnrolled = $derived((this.status?.hello_users ?? []).some((u) => u.sid === "" || u.sid === this.prefs.user_sid));

  pending = $derived(
    this.apps
      .filter((a) => a.pending)
      .sort((a, b) => riskOrder[b.risk] - riskOrder[a.risk] || (b.last_blocked ?? 0) - (a.last_blocked ?? 0)),
  );

  #backend: Backend | null = null;
  /** Demo/screenshot mode: preselected app in the details panel / inbox selection. */
  #requestedApp: string | null = null;
  #requestedSelection: string[] = [];
  #toastTimer: ReturnType<typeof setTimeout> | undefined;

  async init() {
    const be = await backendPromise;
    this.#backend = be;
    be.onState((s) => {
      this.connected = s.connected;
      this.error = s.error;
      if (s.status) this.status = s.status;
    });
    be.onApps((a) => (this.apps = a));
    be.onEvents((e) => {
      // The service numbers its events from 1 again after a restart. What is
      // left from before would share numbers with the new ones (they key the
      // lists), so the log starts over with the new instance.
      const last = this.events.at(-1);
      const restarted = last !== undefined && e.length > 0 && e[0].seq <= last.seq;
      this.events = [...(restarted ? [] : this.events), ...e].slice(-500);
    });
    be.onNavigate((p) => this.go(p as Page));
    const [snap, prefs] = await Promise.all([be.snapshot(), be.prefs()]);
    this.connected = snap.connected;
    this.error = snap.error;
    this.status = snap.status;
    this.apps = snap.apps;
    this.events = snap.events;
    this.prefs = prefs;
    i18n.system = prefs.system_language;
    i18n.pref = prefs.language;
    if (isMock) this.#applyDemoParams();
    this.ready = true;
    be.helloSupported().then((v) => (this.helloSupported = v));
  }

  /** `?lang=en&theme=dark&page=apps&app=Discord&select=2` – only in demo mode. */
  #applyDemoParams() {
    const p = new URLSearchParams(location.search);
    const lang = p.get("lang");
    if (lang === "de" || lang === "en") i18n.pref = lang;
    const theme = p.get("theme");
    if (theme === "light" || theme === "dark") this.theme = theme;
    const page = p.get("page");
    if (page && ["overview", "inbox", "apps", "activity", "settings"].includes(page)) this.page = page as Page;
    const app = p.get("app");
    if (app) this.#requestedApp = this.apps.find((a) => a.name === app)?.key ?? null;
    const select = Number(p.get("select") ?? 0);
    if (select > 0) this.#requestedSelection = this.pending.slice(0, select).map((a) => a.key);
  }

  takeRequestedApp(): string | null {
    const k = this.#requestedApp;
    this.#requestedApp = null;
    return k;
  }

  takeRequestedSelection(): string[] {
    const s = this.#requestedSelection;
    this.#requestedSelection = [];
    return s;
  }

  async setLanguage(pref: LangPref) {
    i18n.pref = pref;
    this.prefs.language = pref;
    await this.#backend?.setLanguage(pref);
  }

  go(p: Page) {
    this.page = p;
  }

  setTheme(t: Theme) {
    this.theme = t;
    try {
      localStorage.setItem("briqwall.theme", t);
    } catch {
      /* ignore */
    }
  }

  notify(text: string, tone: ToastTone = "ok") {
    clearTimeout(this.#toastTimer);
    this.toast = { id: Date.now(), text, tone };
    this.#toastTimer = setTimeout(() => (this.toast = null), 3800);
  }

  /** Send a change to the service. Loosening changes need one confirmation. */
  act(req: Request, success: string): Promise<boolean> {
    return this.actMany([req], success);
  }

  /** Several changes, confirmed once (Windows Hello or UAC). */
  async actMany(reqs: Request[], success: string): Promise<boolean> {
    if (!this.#backend || reqs.length === 0) return false;
    this.busy++;
    try {
      return this.#report(await this.#backend.send(reqs), success);
    } finally {
      this.busy--;
    }
  }

  /**
   * Let the user pick a program and take it into the list, so a rule can be
   * set before it ever asks. Returns its key, or null if nothing was added.
   */
  async addProgram(): Promise<string | null> {
    if (!this.#backend) return null;
    this.busy++;
    try {
      const r: AddResult = await this.#backend.addProgram();
      if (r.kind === "cancelled") return null;
      if (r.kind === "failed") {
        this.notify(t("toast.failed", { message: r.message }), "danger");
        return null;
      }
      const name = this.apps.find((a) => a.key === r.key)?.name ?? fileName(r.key);
      this.notify(r.existed ? t("toast.alreadyKnown", { name }) : t("toast.added", { name }), "ok");
      return r.key;
    } finally {
      this.busy--;
    }
  }

  async enrollHello() {
    if (!this.#backend) return;
    this.busy++;
    try {
      this.#report(await this.#backend.helloEnroll(), t("toast.helloEnrolled"));
    } finally {
      this.busy--;
    }
  }

  async removeHello() {
    if (!this.#backend) return;
    this.#report(await this.#backend.helloRemove(), t("toast.helloRemoved"));
  }

  #report(r: ActionResult, success: string): boolean {
    if (r.kind === "done") {
      this.notify(success, "ok");
      return true;
    }
    if (r.kind === "cancelled") this.notify(t("toast.cancelled"), "warn");
    else this.notify(t("toast.failed", { message: r.message }), "danger");
    return false;
  }

  async setNotifications(on: boolean) {
    this.prefs.notifications = on;
    await this.#backend?.setNotifications(on);
  }

  async setAutostart(on: boolean) {
    this.prefs.autostart = on;
    await this.#backend?.setAutostart(on);
  }

  async installService() {
    const r = await this.#backend?.installService();
    if (r?.kind === "failed") this.notify(r.message, "danger");
  }
}

/** Last path segment, used before the service has delivered the new entry. */
function fileName(key: string): string {
  return key.split(String.fromCharCode(92)).pop() ?? key;
}

export const store = new Store();
