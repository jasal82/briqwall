import type { Access, AppInfo, Category, Location, Mode, NetCategory, Reason, Risk, RuleAccess, Signature } from "./types";
import { i18n, t, type Key } from "./i18n/index.svelte";

export type Tone = "ok" | "warn" | "danger" | "accent" | "muted";

export const modeLabel = (m: Mode) => t(`mode.${m}` as const);
export const modeDescription = (m: "Relaxed" | "Balanced" | "Strict") => t(`mode.${m}.desc` as const);
export const categoryLabel = (c: Category) => t(`category.${c}` as const);
export const riskLabel = (r: Risk) => t(`risk.${r}` as const);
export const accessLabel = (a: Access) => t(`access.${a}` as const);
export const ruleLabel = (r: RuleAccess) => t(`rule.${r}` as const);
export const locationLabel = (l: Location) => t(`location.${l}` as const);
export const netCategoryLabel = (c: NetCategory) => t(`netcat.${c}` as const);

export const riskTone: Record<Risk, Tone> = { Low: "ok", Medium: "warn", High: "danger" };
export const accessTone: Record<Access, Tone> = { Allow: "ok", Lan: "accent", Ask: "warn", Block: "danger" };

/** Sentence explaining the automatic verdict. */
export function reasonText(r: Reason): string {
  if (typeof r === "string") return t(`reason.${r}` as const);
  const [kind, publisher] = Object.entries(r)[0] as [string, string];
  return t(`reason.${kind}` as Key, { publisher });
}

export function publisher(sig: Signature): string | null {
  return typeof sig === "object" && "Valid" in sig ? sig.Valid.publisher : null;
}

export function signatureText(sig: Signature): string {
  if (typeof sig === "object" && "Valid" in sig) return sig.Valid.publisher + (sig.Valid.catalog ? ` (${t("sig.catalog")})` : "");
  if (typeof sig === "object" && "Invalid" in sig)
    return t("sig.invalidCode", { code: `0x${(sig.Invalid.code >>> 0).toString(16).toUpperCase()}` });
  return sig === "Unsigned" ? t("sig.unsigned") : t("sig.unknown");
}

const BACKSLASH = String.fromCharCode(92);

export function folderOf(path: string): string {
  const i = path.lastIndexOf(BACKSLASH);
  return i > 0 ? path.slice(0, i) : path;
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/** "5 min. ago", "vor 2 Std.", "in 45 min." – via Intl in the current language. */
export function ago(ts: number | null | undefined): string {
  if (!ts) return "–";
  const rtf = new Intl.RelativeTimeFormat(i18n.locale, { numeric: "auto", style: "short" });
  const d = ts - now();
  const a = Math.abs(d);
  if (a < 45) return d < 0 ? t("time.justNow") : t("time.soon");
  if (a < 3600) return rtf.format(Math.sign(d) * Math.max(1, Math.round(a / 60)), "minute");
  if (a < 86400) return rtf.format(Math.sign(d) * Math.round(a / 3600), "hour");
  return rtf.format(Math.sign(d) * Math.round(a / 86400), "day");
}

export function clock(ts: number): string {
  return new Intl.DateTimeFormat(i18n.locale, { hour: "2-digit", minute: "2-digit" }).format(new Date(ts * 1000));
}

export function dateTime(ts: number): string {
  return new Intl.DateTimeFormat(i18n.locale, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }).format(
    new Date(ts * 1000),
  );
}

export function dayLabel(ts: number): string {
  const d = new Date(ts * 1000);
  const today = new Date();
  const days = Math.round((new Date(today.toDateString()).getTime() - new Date(d.toDateString()).getTime()) / 86400000);
  if (days === 0 || days === 1) {
    const s = new Intl.RelativeTimeFormat(i18n.locale, { numeric: "auto" }).format(-days, "day");
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  return new Intl.DateTimeFormat(i18n.locale, { weekday: "long", day: "numeric", month: "long" }).format(d);
}

/** Stable, pleasant avatar color per app name. */
export function avatarColor(name: string): string {
  const palette = ["#3a7bd5", "#5b6ee1", "#7c5cd6", "#2b8a5b", "#0f7b6c", "#d9822b", "#c0392b", "#b5487a", "#4a7d9c"];
  let h = 5381;
  for (const c of name) h = ((h * 33) ^ c.charCodeAt(0)) >>> 0;
  return palette[h % palette.length];
}

export function initial(name: string): string {
  const m = name.match(/[\p{L}\p{N}]/u);
  return m ? m[0].toUpperCase() : "?";
}

export function isUserFacing(a: AppInfo): boolean {
  return !(a.category === "System" || a.category === "Pseudo") || a.rule !== null || a.pending;
}

/**
 * "example.com · 93.184.216.34:443 (HTTPS)" – the name first, it says more.
 * A name that only the program itself (or another program of the user)
 * reported is marked: it can claim to have looked up anything.
 */
export function targetText(remote: string, host?: string | null, verified?: boolean): string {
  if (!host) return remote;
  return `${verified ? host : t("host.claimed", { host })} · ${remote}`;
}
