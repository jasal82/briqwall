<script lang="ts" module>
  import type { IconName } from "./Icon.svelte";
  import type { UserRule, XEvent } from "./types";
  import { modeLabel, reasonText, riskLabel, ruleLabel, targetText } from "./format";
  import { q, t } from "./i18n/index.svelte";

  export type Described = { icon: IconName; tone: string; title: string; sub?: string; blocked: boolean; decision: boolean };

  function ruleSummary(r: UserRule | null): string {
    if (!r) return t("event.rule.auto");
    let s = t("event.rule.summary", { out: ruleLabel(r.outbound), in: ruleLabel(r.inbound) });
    if (r.expires) s += ` (${t("event.rule.temporary")})`;
    return s;
  }

  export function describe(e: XEvent): Described {
    const k = e.kind;
    const base = { blocked: false, decision: false };
    if (k === "HelloEnrolled") return { ...base, icon: "fingerprint", tone: "accent", title: t("event.helloEnrolled") };
    if (k === "HelloRemoved") return { ...base, icon: "fingerprint", tone: "accent", title: t("event.helloRemoved") };
    if ("Blocked" in k) {
      const b = k.Blocked;
      const remote = targetText(b.remote, b.host);
      const title =
        b.direction === "Out" ? t("event.blocked.out", { name: b.name, remote }) : t("event.blocked.in", { name: b.name, remote });
      const sub = b.by_rule ? t("event.byRule") : b.direction === "Out" ? t("event.waiting") : t("event.unsolicited");
      return { icon: "block", tone: "danger", title, sub, blocked: true, decision: false };
    }
    if ("NewRequest" in k)
      return { ...base, icon: "bell", tone: "warn", title: t("event.newRequest", { name: k.NewRequest.name }), sub: riskLabel(k.NewRequest.risk) };
    if ("AutoAllowed" in k)
      return {
        ...base,
        icon: "check",
        tone: "ok",
        title: t("event.autoAllowed", { name: k.AutoAllowed.name }),
        sub: reasonText(k.AutoAllowed.reason),
      };
    if ("RuleChanged" in k)
      return {
        ...base,
        decision: true,
        icon: "gear",
        tone: "accent",
        title: t("event.ruleChanged", { name: k.RuleChanged.name }),
        sub: ruleSummary(k.RuleChanged.rule),
      };
    if ("RuleExpired" in k)
      return { ...base, decision: true, icon: "clock", tone: "accent", title: t("event.ruleExpired", { name: k.RuleExpired.name }) };
    if ("Tampered" in k)
      return { ...base, icon: "alert", tone: "danger", title: t("event.tampered", { name: k.Tampered.name }), sub: t("event.tampered.sub") };
    if ("ModeChanged" in k)
      return {
        ...base,
        decision: true,
        icon: "swap",
        tone: "accent",
        title: t("event.modeChanged", { from: modeLabel(k.ModeChanged.from), to: modeLabel(k.ModeChanged.to) }),
      };
    if ("NetworkChanged" in k)
      return {
        ...base,
        icon: "wifi",
        tone: "accent",
        title: t("event.network", { name: k.NetworkChanged.name }),
        sub: k.NetworkChanged.trusted ? t("event.network.home") : t("event.network.public"),
      };
    if ("Started" in k)
      return {
        ...base,
        icon: "shield",
        tone: "accent",
        title: t("event.started", { version: k.Started.version }),
        sub: t("hero.level", { mode: q(modeLabel(k.Started.mode)) }),
      };
    if ("PublisherLearned" in k)
      return {
        ...base,
        decision: true,
        icon: "learn",
        tone: "accent",
        title: t("event.publisherLearned", { publisher: q(k.PublisherLearned.publisher) }),
      };
    return { ...base, icon: "alert", tone: "danger", title: t("event.applyFailed"), sub: k.ApplyFailed.detail };
  }
</script>

<script lang="ts">
  import Icon from "./Icon.svelte";
  import { clock } from "./format";
  let { event, compact = false }: { event: XEvent; compact?: boolean } = $props();
  const d = $derived(describe(event));
</script>

<div class="list-row">
  <div class="ev-icon {d.tone}"><Icon name={d.icon} size={15} /></div>
  <div class="grow">
    <div class="ellipsis" title={d.title}>{d.title}</div>
    {#if d.sub && !compact}<div class="faint ellipsis" title={d.sub}>{d.sub}</div>{/if}
  </div>
  <span class="time">{clock(event.time)}</span>
</div>
