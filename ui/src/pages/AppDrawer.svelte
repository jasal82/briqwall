<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import Avatar from "../lib/Avatar.svelte";
  import Seg from "../lib/Seg.svelte";
  import OriginInfo from "../lib/OriginInfo.svelte";
  import { store } from "../lib/store.svelte";
  import { accessLabel, ago, categoryLabel, dateTime, now, reasonText, riskLabel, riskTone, ruleLabel, signatureText, targetText } from "../lib/format";
  import { q, t } from "../lib/i18n/index.svelte";
  import type { AppInfo, RuleAccess } from "../lib/types";

  let { key, onclose, docked = false }: { key: string | null; onclose: () => void; docked?: boolean } = $props();

  // Keep showing the last app while the panel slides out.
  let last = $state<AppInfo | null>(null);
  const live = $derived(key ? (store.apps.find((a) => a.key === key) ?? null) : null);
  $effect(() => {
    if (live) last = live;
  });
  const app = $derived(live ?? last);
  const open = $derived(live !== null);

  const options = $derived(
    (["Auto", "Allow", "Lan", "Block"] as RuleAccess[]).map((v) => ({
      value: v,
      label: ruleLabel(v),
    })),
  );

  function setRule(a: AppInfo, dir: "outbound" | "inbound", v: RuleAccess) {
    const cur = a.rule ?? { outbound: "Auto" as RuleAccess, inbound: "Auto" as RuleAccess, expires: null, created: now() };
    // The end date belongs to the rule as a whole. A new choice for the
    // internet is a new decision and lasts; changing the inbound side must
    // not quietly turn "allowed for an hour" into "allowed for good".
    const rule = { ...cur, [dir]: v, expires: dir === "outbound" ? null : cur.expires, created: now() };
    const which = dir === "outbound" ? t("drawer.internet.short") : t("drawer.inbound.short");
    store.act({ SetRule: { key: a.key, rule } }, `${a.name}: ${which} ${q(ruleLabel(v))}`);
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape" && open) onclose();
  }
</script>

<svelte:window onkeydown={onKey} />

{#snippet panel()}
  <aside class="drawer" class:open class:docked aria-hidden={!open} aria-label={t("drawer.aria")}>
    {#if app}
      <div class="drawer-head">
        <Avatar name={app.name} />
        <div style="flex:1;min-width:0">
          <h3 class="ellipsis" style="margin:0;font:600 17px var(--font-display)" title={app.name}>{app.name}</h3>
          <div class="faint ellipsis">{signatureText(app.signature)}</div>
        </div>
        <button class="btn ghost sm" onclick={onclose} aria-label={t("common.close")}><Icon name="x" /></button>
      </div>
      <div class="drawer-body">
        {#if app.tampered}
          <div class="tampered"><Icon name="alert" />{t("drawer.tampered")}</div>
        {/if}
        <div class="field">
          <span class="label">{t("drawer.internet")}</span>
          <Seg label={t("drawer.internet")} {options} value={app.rule?.outbound ?? "Auto"} onchange={(v) => setRule(app, "outbound", v)} />
          <span class="faint">{t("drawer.auto", { verdict: accessLabel(app.auto_out).toLowerCase() })} – {reasonText(app.reason)}</span>
          {#if app.rule?.expires}
            <span class="faint" style="color:var(--warn)"><Icon name="clock" size={12} /> {t("drawer.expires", { when: ago(app.rule.expires) })}</span>
          {/if}
        </div>
        <div class="field">
          <span class="label">{t("drawer.inbound")}</span>
          <Seg label={t("drawer.inbound")} {options} value={app.rule?.inbound ?? "Auto"} onchange={(v) => setRule(app, "inbound", v)} />
          <span class="faint">{t("drawer.auto", { verdict: accessLabel(app.auto_in).toLowerCase() })}</span>
          {#if app.rule?.expires && app.rule.inbound !== "Auto"}
            <span class="faint" style="color:var(--warn)"><Icon name="clock" size={12} /> {t("drawer.expires", { when: ago(app.rule.expires) })}</span>
          {/if}
        </div>
        <OriginInfo {app} />
        <dl class="kv">
          <dt>{t("drawer.path")}</dt><dd class="selectable">{app.path}</dd>
          <dt>{t("drawer.origin")}</dt>
          <dd>{categoryLabel(app.category)} – {app.protected ? t("drawer.protected") : t("drawer.unprotected")}</dd>
          <dt>{t("drawer.risk")}</dt><dd><span class="badge {riskTone[app.risk]}">{riskLabel(app.risk)}</span></dd>
          <dt>{t("drawer.firstSeen")}</dt><dd>{dateTime(app.first_seen)}</dd>
          <dt>{t("drawer.lastActive")}</dt><dd>{ago(app.last_seen)}</dd>
          <dt>{t("drawer.blocked")}</dt>
          <dd>
            {#if app.blocked_count + app.inbound_blocked_count === 0}
              {t("drawer.noAttempts")}
            {:else}
              {t("drawer.attempts", { out: app.blocked_count, in: app.inbound_blocked_count })}{app.last_remote
                ? ` · ${t("drawer.lastTarget", { remote: targetText(app.last_remote, app.last_host, app.last_host_verified) })}`
                : ""}
            {/if}
          </dd>
        </dl>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          {#if app.rule}
            <button class="btn sm" onclick={() => store.act({ SetRule: { key: app.key, rule: null } }, t("toast.resetAuto", { name: app.name }))}>
              {t("drawer.reset")}
            </button>
          {/if}
          {#if app.category !== "Pseudo"}
            <button
              class="btn ghost sm"
              onclick={async () => {
                if (await store.act({ Forget: { key: app.key } }, t("toast.forgotten", { name: app.name }))) onclose();
              }}>{t("drawer.forget")}</button>
          {/if}
        </div>
      </div>
    {/if}
  </aside>
{/snippet}

{#if docked}
  {@render panel()}
{:else}
  <div class="drawer-wrap">{@render panel()}</div>
{/if}
