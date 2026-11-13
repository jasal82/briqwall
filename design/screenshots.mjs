// Captures the README screenshots of the English UI with demo data.
//
//   npm --prefix ui run dev            (in another terminal)
//   node design/screenshots.mjs        (writes docs/screenshots/*.png)
//
// Uses Microsoft Edge in headless mode via the DevTools protocol; no extra
// dependencies (Node 22+ has fetch and WebSocket built in).

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.BRIQWALL_UI ?? "http://localhost:5173";
const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "screenshots");
const EDGE = process.env.EDGE ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const PORT = 9341;
const WIDTH = 1180;
const HEIGHT = 760;
const SCALE = 1.5;

const shots = [
  { file: "overview.png", query: "page=overview" },
  { file: "requests.png", query: "page=inbox&select=2" },
  { file: "apps.png", query: "page=apps&app=Discord" },
  { file: "activity.png", query: "page=activity" },
  { file: "settings.png", query: "page=settings" },
  { file: "overview-dark.png", query: "page=overview&theme=dark", dark: true },
];

const profile = mkdtempSync(join(tmpdir(), "briqwall-shots-"));
const edge = spawn(
  EDGE,
  [
    "--headless=new",
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`,
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--lang=en-US",
    "about:blank",
  ],
  { stdio: "ignore" },
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    await sleep(200);
  }
  throw new Error("Edge did not start");
}

try {
  const ws = new WebSocket(await target());
  let id = 0;
  const pending = new Map();
  const loaded = [];
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) {
      pending.get(d.id)(d);
      pending.delete(d.id);
    } else if (d.method === "Page.loadEventFired") {
      loaded.splice(0).forEach((r) => r());
    }
  };
  await new Promise((r) => (ws.onopen = r));
  const call = (method, params = {}) =>
    new Promise((res, rej) => {
      const i = ++id;
      pending.set(i, (d) => (d.error ? rej(new Error(`${method}: ${d.error.message}`)) : res(d.result)));
      ws.send(JSON.stringify({ id: i, method, params }));
    });

  await call("Page.enable");
  await call("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: SCALE, mobile: false });
  mkdirSync(OUT, { recursive: true });

  for (const s of shots) {
    await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: s.dark ? "dark" : "light" }] });
    const done = new Promise((r) => loaded.push(r));
    await call("Page.navigate", { url: `${BASE}/?lang=en&${s.query}` });
    await done;
    await sleep(900); // data load + entry animations + drawer slide-in
    const { data } = await call("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(OUT, s.file), Buffer.from(data, "base64"));
    console.log("saved", s.file);
  }
  ws.close();
} finally {
  edge.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
