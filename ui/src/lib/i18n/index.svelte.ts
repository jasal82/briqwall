// Minimal, type-safe i18n: English is the reference dictionary (every key is
// a TypeScript type), German must provide exactly the same keys.

import { en } from "./en";
import { de } from "./de";

export type Key = keyof typeof en;
export type Dict = Record<Key, string>;
export type Lang = "de" | "en";
export type LangPref = "system" | Lang;

const dicts: Record<Lang, Dict> = { en, de };

function browserLang(): Lang {
  return typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("de") ? "de" : "en";
}

class I18n {
  /** User preference: follow Windows, or a fixed language. */
  pref = $state<LangPref>("system");
  /** What "system" resolves to (reported by the backend). */
  system = $state<Lang>(browserLang());
  lang = $derived<Lang>(this.pref === "system" ? this.system : this.pref);
  locale = $derived(this.lang === "de" ? "de-DE" : "en-US");
}

export const i18n = new I18n();

/** Translate a key; `{name}` placeholders are filled from `vars`. */
export function t(key: Key, vars?: Record<string, string | number>): string {
  const s = dicts[i18n.lang][key] ?? en[key] ?? key;
  return vars ? s.replace(/\{(\w+)\}/g, (_, k: string) => String(vars[k] ?? `{${k}}`)) : s;
}

type PluralBase = Key extends infer K ? (K extends `${infer B}.one` ? B : never) : never;

/** Plural form: uses `<base>.one` or `<base>.other`, with `{n}` set to `n`. */
export function tn(base: PluralBase, n: number, vars?: Record<string, string | number>): string {
  return t(`${base}.${n === 1 ? "one" : "other"}` as Key, { n, ...vars });
}

/** Typographic quotes for the current language. */
export function q(s: string): string {
  return i18n.lang === "de" ? `„${s}“` : `“${s}”`;
}
