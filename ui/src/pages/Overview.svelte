<script lang="ts">
  import Icon, { type IconName } from "../lib/Icon.svelte";
  import Seg from "../lib/Seg.svelte";
  import EventRow from "../lib/EventRow.svelte";
  import { store } from "../lib/store.svelte";
  import { modeDescription, modeLabel } from "../lib/format";
  import { q, t, tn } from "../lib/i18n/index.svelte";
  import type { Mode, NetworkInfo } from "../lib/types";

  const s = $derived(store.status!);
  const levels: ("Relaxed" | "Balanced" | "Strict")[] = ["Relaxed", "Balanced", "Strict"];
  const restoreMode = $derived<Mode>(
    s.settings.previous_mode === "Off" || s.settings.previous_mode === "Lockdown" ? "Balanced" : s.settings.previous_mode,
  );

  const netText = $derived(
    s.networks.length === 0
      ? t("net.none")
      : s.networks.map((n) => n.name).join(", ") + " · " + (s.network_trusted ? t("net.home") : t("net.public")),
  );

  type Hero = { tone: "ok" | "warn" | "danger"; icon: IconName; title: string; sub?: string };
  const hero = $derived.by<Hero>(() => {
    if (!s.engine_ok) return { tone: "warn", icon: "shield-alert", title: t("hero.limited"), sub: s.engine_error ?? undefined };
    if (s.mode === "Off") return { tone: "danger", icon: "power", title: t("hero.off"), sub: t("hero.off.sub") };
    if (s.mode === "Lockdown") return { tone: "danger", icon: "lock", title: t("hero.lockdown"), sub: t("hero.lockdown.sub") };
    if (s.pending > 0) return { tone: "warn", icon: "shield-check", title: t("hero.pending") };
    return { tone: "ok", icon: "shield-check", title: t("hero.ok") };
  });

  const pendingNames = $derived(store.pending.slice(0, 3).map((a) => a.name));
  const recent = $derived(store.events.slice(-4).reverse());

  function setTrust(n: NetworkInfo, trusted: boolean) {
    store.act({ SetNetworkTrust: { id: n.id, trusted } }, t(trusted ? "net.nowHome" : "net.nowPublic", { name: n.name }));
  }
</script>

<section class="page">
  <div class="page-head"><div><h1>{t("nav.overview")}</h1></div></div>

  <div class="card hero tone-{hero.tone}">
    <div class="hero-icon"><Icon name={hero.icon} size={34} /></div>
    <div>
      <h3>{hero.title}</h3>
      <div class="meta">
        {#if hero.sub}
          <span>{hero.sub}</span>
        {:else}
          <span><Icon name="shield" size={15} />{t("hero.level", { mode: q(modeLabel(s.mode)) })}</span>
          <span><Icon name="wifi" size={15} />{netText}</span>
        {/if}
      </div>
    </div>
    <div class="actions">
      {#if s.mode === "Lockdown"}
        <button class="btn primary" onclick={() => store.act({ SetMode: restoreMode }, t("toast.lockdownLifted"))}>{t("hero.liftLockdown")}</button>
      {:else if s.mode === "Off"}
        <button class="btn primary" onclick={() => store.act({ SetMode: restoreMode }, t("toast.protectionOn"))}>{t("hero.turnOn")}</button>
      {:else}
        <button class="btn danger" title={t("hero.lockdown.tip")} onclick={() => store.act({ SetMode: "Lockdown" }, t("toast.lockdownOn"))}>
          <Icon name="lock" />{t("mode.Lockdown")}
        </button>
      {/if}
    </div>
  </div>

  {#if s.pending > 0 && s.mode !== "Lockdown"}
    <div class="callout">
      <span class="ic"><Icon name="bell" size={20} /></span>
      <div class="t">
        <b>{tn("callout.waiting", s.pending)}</b>
        <span class="muted">{tn("callout.stopped", s.pending, { names: pendingNames.join(", ") + (s.pending > 3 ? " …" : "") })}</span>
      </div>
      <button class="btn primary" onclick={() => store.go("inbox")}>{t("common.view")}</button>
    </div>
  {/if}

  <div class="card stats">
    <div class="stat"><div class="v">{s.apps_allowed}</div><div class="l">{t("stats.allowed")}</div></div>
    <div class="stat"><div class="v">{s.apps_blocked}</div><div class="l">{t("stats.blocked")}</div></div>
    <div class="stat">
      <div class="v" style:color={s.pending ? "var(--warn)" : undefined}>{s.pending}</div>
      <div class="l">{t("stats.pending")}</div>
    </div>
    <div class="stat"><div class="v">{s.blocked_session}</div><div class="l">{t("stats.attempts")}</div></div>
  </div>

  <h2>{t("overview.level")}</h2>
  <div class="levels">
    {#each levels as m (m)}
      <button
        class="level"
        class:on={s.mode === m}
        aria-pressed={s.mode === m}
        onclick={() => s.mode !== m && store.act({ SetMode: m }, t("toast.modeActive", { mode: q(modeLabel(m)) }))}>
        <div class="top">
          {modeLabel(m)}
          {#if m === "Balanced"}<span class="rec">{t("overview.recommended")}</span>{/if}
          <span class="radio"></span>
        </div>
        <p>{modeDescription(m)}</p>
      </button>
    {/each}
  </div>

  <div class="two" style="margin-top:12px">
    <div class="card">
      <div class="card-head"><b>{t("overview.network")}</b></div>
      {#each s.networks as n (n.id)}
        <div class="list-row">
          <div class="ev-icon accent"><Icon name="wifi" size={16} /></div>
          <div class="grow">
            <div class="ellipsis" style="font-weight:600">{n.name}</div>
            <div class="faint">{n.trusted ? t("net.home.desc") : t("net.public.desc")}</div>
          </div>
          <Seg
            label={t("net.type")}
            options={[
              { value: "public", label: t("net.public") },
              { value: "home", label: t("net.home") },
            ]}
            value={n.trusted ? "home" : "public"}
            onchange={(v) => setTrust(n, v === "home")} />
        </div>
      {:else}
        <div class="list-row"><span class="muted">{t("net.noConnection")}</span></div>
      {/each}
    </div>
    <div class="card">
      <div class="card-head"><b>{t("overview.recent")}</b><button class="link" onclick={() => store.go("activity")}>{t("common.showAll")}</button></div>
      {#each recent as e (e.seq)}
        <EventRow event={e} compact />
      {:else}
        <div class="list-row"><span class="muted">{t("activity.empty")}</span></div>
      {/each}
    </div>
  </div>

  {#if s.mode !== "Off" && s.mode !== "Lockdown"}
    <p class="faint" style="margin-top:18px">
      {tn("overview.known", s.apps_total)}
      <button class="link" onclick={() => store.act({ SetMode: "Off" }, t("toast.turnedOff"))}>{t("overview.turnOff")}</button>
    </p>
  {/if}
</section>
