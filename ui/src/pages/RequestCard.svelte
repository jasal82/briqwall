<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import Avatar from "../lib/Avatar.svelte";
  import SplitButton from "../lib/SplitButton.svelte";
  import OriginInfo, { suspiciousParent } from "../lib/OriginInfo.svelte";
  import { store } from "../lib/store.svelte";
  import { ago, categoryLabel, locationLabel, now, publisher, reasonText, riskLabel, riskTone } from "../lib/format";
  import { t, tn } from "../lib/i18n/index.svelte";
  import type { AppInfo, RuleAccess } from "../lib/types";

  let { app, selected = false, ontoggle }: { app: AppInfo; selected?: boolean; ontoggle?: () => void } = $props();

  const pub = $derived(publisher(app.signature));
  const invalidSig = $derived(typeof app.signature === "object" && "Invalid" in app.signature);
  const lanTarget = $derived(isPrivate(app.last_remote));
  // A suspicious parent (Office, script host …) makes any request high risk.
  const suspicious = $derived((app.origins ?? []).some((o) => suspiciousParent(o) !== null));
  const risky = $derived(app.risk === "High" || suspicious);
  const lolbin = $derived(app.category === "Lolbin");
  const hintTone = $derived(
    app.location_hint && ["Downloads", "Temp", "Desktop", "Public", "Removable"].includes(app.location_hint) ? "warn" : "",
  );

  function isPrivate(remote: string | null): boolean {
    if (!remote) return false;
    const ip = remote.replace(/^\[/, "").split(/[\]\s]/)[0].replace(/:\d+$/, "");
    return /^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip);
  }

  function decide(out: RuleAccess, hours: number | null, msg: string) {
    store.act(
      { SetRule: { key: app.key, rule: { outbound: out, inbound: "Auto", expires: hours ? now() + hours * 3600 : null, created: now() } } },
      msg,
    );
  }
  const allowAlways = () => decide("Allow", null, t("toast.allowed", { name: app.name }));
  const allowHour = () => decide("Allow", 1, t("toast.allowedHour", { name: app.name }));
  const allowLan = () => decide("Lan", null, t("toast.allowedLan", { name: app.name }));
  const block = () => decide("Block", null, t("toast.blocked", { name: app.name }));
  const later = () => store.act({ Snooze: { key: app.key } }, t("toast.snoozed", { name: app.name }));

  const items = $derived({
    always: { label: t("req.always"), hint: t("req.always.hint"), run: allowAlways },
    hour: { label: t("req.hour"), hint: t("req.hour.hint"), run: allowHour },
    lan: { label: t("req.lan"), hint: lanTarget ? t("req.lan.hintTarget") : t("req.lan.hint"), run: allowLan },
  });
</script>

<article class="card req" class:risk-high={risky} class:selected>
  <div class="req-head">
    {#if ontoggle}
      <button
        type="button"
        class="check"
        class:on={selected}
        role="checkbox"
        aria-checked={selected}
        aria-label={t("req.select", { name: app.name })}
        onclick={ontoggle}><Icon name="check" size={13} /></button>
    {/if}
    <Avatar name={app.name} />
    <div class="grow">
      <h3 class="ellipsis" title={app.name}>{app.name}</h3>
      <div class="faint ellipsis selectable" title={app.path}>{app.path}</div>
      <div class="req-tags">
        <span class="badge {suspicious ? 'danger' : riskTone[app.risk]}"
          ><Icon name={risky ? "alert" : "info"} size={12} />{riskLabel(suspicious ? "High" : app.risk)}</span>
        {#if pub}
          <span class="badge ok"><Icon name="check" size={12} />{t("req.signedBy", { publisher: pub })}</span>
        {:else if invalidSig}
          <span class="badge danger">{t("req.invalidSig")}</span>
        {:else}
          <span class="badge warn">{t("req.unsigned")}</span>
        {/if}
        <span class="badge">{categoryLabel(app.category)}</span>
        {#if app.location_hint && app.location_hint !== "ProgramFiles"}
          <span class="badge {hintTone}">{locationLabel(app.location_hint)}</span>
        {/if}
        {#if app.tampered}<span class="badge danger"><Icon name="alert" size={12} />{t("req.tampered")}</span>{/if}
      </div>
    </div>
  </div>

  <div class="why">
    <span class="k">{t("req.why")}</span>
    <span>{reasonText(app.reason)}</span>
    {#if app.last_remote}
      <span class="faint">
        {t("req.wanted", { remote: app.last_remote })}{lanTarget ? ` (${t("req.localNet")})` : ""} · {tn("req.attempts", app.blocked_count)} · {ago(app.last_blocked)}
      </span>
    {/if}
  </div>

  <OriginInfo {app} />

  <div class="req-actions">
    {#if risky}
      <button class="btn danger-solid" onclick={block}>{t("common.block")}</button>
      <SplitButton label={t("common.allow")} run={allowAlways} items={[items.hour, items.lan]} />
    {:else if lolbin}
      <SplitButton label={t("req.allowHour")} primary run={allowHour} items={[items.always, items.lan]} />
      <button class="btn danger" onclick={block}>{t("common.block")}</button>
    {:else if lanTarget}
      <SplitButton label={t("req.allowLan")} primary run={allowLan} items={[items.always, items.hour]} />
      <button class="btn danger" onclick={block}>{t("common.block")}</button>
    {:else}
      <SplitButton label={t("common.allow")} primary run={allowAlways} items={[items.hour, items.lan]} />
      <button class="btn danger" onclick={block}>{t("common.block")}</button>
    {/if}
    <span class="sp"></span>
    <button class="btn ghost" title={t("req.later.tip")} onclick={later}>{t("common.later")}</button>
  </div>
</article>
