<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import RequestCard from "./RequestCard.svelte";
  import { store } from "../lib/store.svelte";
  import { now } from "../lib/format";
  import { t, tn } from "../lib/i18n/index.svelte";
  import { suspiciousParent } from "../lib/OriginInfo.svelte";
  import type { AppInfo, Request, RuleAccess } from "../lib/types";

  let selected = $state<string[]>(store.takeRequestedSelection());

  // Forget selections for requests that were decided meanwhile.
  $effect(() => {
    const keys = new Set(store.pending.map((a) => a.key));
    if (selected.some((k) => !keys.has(k))) selected = selected.filter((k) => keys.has(k));
  });

  const chosen = $derived(store.pending.filter((a) => selected.includes(a.key)));
  const allSelected = $derived(store.pending.length > 0 && chosen.length === store.pending.length);
  // Where a card puts "Block" first, one click for many must not allow it
  // in passing. Those requests stay selected and are decided one by one.
  const risky = (a: AppInfo) => a.risk === "High" || (a.origins ?? []).some((o) => suspiciousParent(o) !== null);
  const allowable = $derived(chosen.filter((a) => !risky(a)));
  const leftOut = $derived(chosen.length - allowable.length);
  const hello = $derived(store.helloEnrolled);

  function toggle(key: string) {
    selected = selected.includes(key) ? selected.filter((k) => k !== key) : [...selected, key];
  }

  type Outcome = "bulk.allowed" | "bulk.allowedHour" | "bulk.allowedLan" | "bulk.blocked";

  async function decideAll(out: RuleAccess, hours: number | null, outcome: Outcome) {
    const targets = out === "Block" ? chosen : allowable;
    const reqs: Request[] = targets.map((a) => ({
      SetRule: { key: a.key, rule: { outbound: out, inbound: "Auto", expires: hours ? now() + hours * 3600 : null, created: now() } },
    }));
    if (await store.actMany(reqs, tn(outcome, reqs.length))) selected = selected.filter((k) => !targets.some((a) => a.key === k));
  }

  async function snoozeAll() {
    const reqs: Request[] = chosen.map((a) => ({ Snooze: { key: a.key } }));
    if (await store.actMany(reqs, tn("bulk.snoozed", reqs.length))) selected = [];
  }
</script>

<section class="page">
  <div class="page-head">
    <div>
      <h1>{t("nav.inbox")}</h1>
      <p>{t("inbox.intro")}</p>
    </div>
    <span class="sp"></span>
    {#if store.pending.length >= 2}
      <button class="btn ghost" onclick={() => (selected = allSelected ? [] : store.pending.map((a) => a.key))}>
        {allSelected ? t("inbox.selectNone") : t("inbox.selectAll")}
      </button>
    {/if}
  </div>

  {#if store.pending.length > 0 && !hello && !store.status?.privileged && store.helloSupported}
    <div class="hello-tip">
      <span class="ic"><Icon name="fingerprint" size={26} /></span>
      <div class="t">
        <b>{t("hello.tip.title")}</b>
        <span class="muted">{t("hello.tip.text")}</span>
      </div>
      <button class="btn primary" onclick={() => store.enrollHello()}>{t("common.setUp")}</button>
    </div>
  {/if}

  {#if store.pending.length > 0}
    <div class="req-grid">
      {#each store.pending as app (app.key)}
        <RequestCard {app} selected={selected.includes(app.key)} ontoggle={() => toggle(app.key)} />
      {/each}
    </div>
  {:else}
    <div class="card empty">
      <div class="big"><Icon name="check" size={30} /></div>
      <h3 style="margin:0 0 4px;font:600 18px var(--font-display)">{t("inbox.empty.title")}</h3>
      <p class="muted" style="margin:0">{t("inbox.empty.text")}</p>
    </div>
  {/if}

  {#if store.pending.length > 0 && !store.status?.privileged}
    <p class="uac" style="margin-top:16px">
      <Icon name="fingerprint" size={15} />
      {hello ? t("inbox.hint.hello") : t("inbox.hint.uac")}
    </p>
  {/if}

  {#if chosen.length > 0}
    <div class="bulkbar" role="toolbar" aria-label={t("bulk.aria")}>
      <b>{tn("bulk.selected", chosen.length)}</b>
      {#if leftOut > 0}<span class="bulk-note"><Icon name="alert" size={14} />{tn("bulk.riskyLeft", leftOut)}</span>{/if}
      <button class="btn primary" disabled={allowable.length === 0} onclick={() => decideAll("Allow", null, "bulk.allowed")}>{t("common.allow")}</button>
      <button class="btn" disabled={allowable.length === 0} onclick={() => decideAll("Allow", 1, "bulk.allowedHour")}>{t("bulk.hour")}</button>
      <button class="btn" disabled={allowable.length === 0} onclick={() => decideAll("Lan", null, "bulk.allowedLan")}>{t("req.lan")}</button>
      <button class="btn danger" onclick={() => decideAll("Block", null, "bulk.blocked")}>{t("common.block")}</button>
      <button class="btn ghost" onclick={snoozeAll}>{t("common.later")}</button>
    </div>
  {/if}
</section>
