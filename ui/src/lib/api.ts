// Bridge to the Tauri backend. Outside Tauri (plain browser / `npm run dev`)
// a mock backend with realistic data is used, so the UI can be developed and
// reviewed without the service.

import type { ActionResult, AddResult, AppInfo, ConnState, Request, Snapshot, UiPrefs, XEvent } from "./types";
import { createMock } from "./mock";

export interface Backend {
  snapshot(): Promise<Snapshot>;
  send(reqs: Request[]): Promise<ActionResult>;
  /** Open the file dialog and take the chosen program into the list. */
  addProgram(): Promise<AddResult>;
  helloSupported(): Promise<boolean>;
  helloEnroll(): Promise<ActionResult>;
  helloRemove(): Promise<ActionResult>;
  prefs(): Promise<UiPrefs>;
  setNotifications(on: boolean): Promise<void>;
  setAutostart(on: boolean): Promise<void>;
  setLanguage(lang: "system" | "de" | "en"): Promise<void>;
  installService(): Promise<ActionResult>;
  onState(cb: (s: ConnState) => void): void;
  onApps(cb: (a: AppInfo[]) => void): void;
  onEvents(cb: (e: XEvent[]) => void): void;
  onNavigate(cb: (page: string) => void): void;
}

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function tauriBackend(): Promise<Backend> {
  const { invoke } = await import("@tauri-apps/api/core");
  const { listen } = await import("@tauri-apps/api/event");
  return {
    snapshot: () => invoke<Snapshot>("snapshot"),
    send: (reqs) => invoke<ActionResult>("send_requests", { reqs }),
    addProgram: () => invoke<AddResult>("add_program"),
    helloSupported: () => invoke<boolean>("hello_supported"),
    helloEnroll: () => invoke<ActionResult>("hello_enroll"),
    helloRemove: () => invoke<ActionResult>("hello_remove"),
    prefs: () => invoke<UiPrefs>("ui_prefs"),
    setNotifications: (on) => invoke("set_notifications", { on }),
    setAutostart: (on) => invoke("set_autostart", { on }),
    setLanguage: (lang) => invoke("set_language", { lang }),
    installService: () => invoke<ActionResult>("install_service"),
    onState: (cb) => void listen<ConnState>("briqwall://state", (e) => cb(e.payload)),
    onApps: (cb) => void listen<AppInfo[]>("briqwall://apps", (e) => cb(e.payload)),
    onEvents: (cb) => void listen<XEvent[]>("briqwall://events", (e) => cb(e.payload)),
    onNavigate: (cb) => void listen<string>("briqwall://navigate", (e) => cb(e.payload)),
  };
}

export const backendPromise: Promise<Backend> = inTauri ? tauriBackend() : Promise.resolve(createMock());
export const isMock = !inTauri;
