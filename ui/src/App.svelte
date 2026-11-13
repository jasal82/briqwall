<script lang="ts">
  import Icon, { type IconName } from "./lib/Icon.svelte";
  import Overview from "./pages/Overview.svelte";
  import Inbox from "./pages/Inbox.svelte";
  import Apps from "./pages/Apps.svelte";
  import AppDrawer from "./pages/AppDrawer.svelte";
  import Activity from "./pages/Activity.svelte";
  import Settings from "./pages/Settings.svelte";
  import { store, type Page } from "./lib/store.svelte";
  import { isMock } from "./lib/api";
  import { i18n, t, tn, type Key } from "./lib/i18n/index.svelte";

  let selectedApp = $state<string | null>(null);
  let main: HTMLElement;
  let contentWidth = $state(0);

  /** Wide enough to show the app details next to the list instead of over it. */
  const DOCK_WIDTH = 1120;
  const docked = $derived(contentWidth >= DOCK_WIDTH);

  const nav: { id: Page; icon: IconName; label: Key }[] = [
    { id: "overview", icon: "home", label: "nav.overview" },
    { id: "inbox", icon: "bell", label: "nav.inbox" },
    { id: "apps", icon: "grid", label: "nav.apps" },
    { id: "activity", icon: "pulse", label: "nav.activity" },
    { id: "settings", icon: "gear", label: "nav.settings" },
  ];

  $effect(() => {
    const th = store.theme;
    if (th === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = th;
  });

  $effect(() => {
    document.documentElement.lang = i18n.lang;
  });

  // New page: scroll to top, close the details panel (unless one was requested).
  $effect(() => {
    void store.page;
    selectedApp = store.takeRequestedApp();
    if (main) main.scrollTop = 0;
  });

  const online = $derived(store.connected && store.status !== null);
  const footText = $derived(
    !store.connected ? t("foot.offline") : store.status?.engine_ok === false ? t("foot.displayOnly") : t("foot.active"),
  );
</script>

<div class="app">
  <nav class="nav" aria-label={t("nav.aria")}>
    <div class="brand">
      <div class="brand-mark"><Icon name="shield-check" size={18} /></div>
      <b>Briqwall</b>
    </div>
    {#each nav as n (n.id)}
      <button
        class="nav-item"
        class:active={store.page === n.id}
        aria-current={store.page === n.id ? "page" : undefined}
        onclick={() => store.go(n.id)}
        title={t(n.label)}>
        <Icon name={n.icon} size={18} /><span>{t(n.label)}</span>
        {#if n.id === "inbox" && store.pending.length > 0}
          <span class="count" aria-label={tn("inbox.pendingCount", store.pending.length)}>{store.pending.length}</span>
        {/if}
      </button>
    {/each}
    <div class="nav-foot">
      {#if store.busy > 0}
        <div class="row"><span class="spinner"></span><span class="txt">{t("foot.applying")}</span></div>
      {/if}
      <div class="row" title={footText}>
        <span
          class="dot"
          style:background={store.connected ? undefined : "var(--danger)"}
          style:box-shadow={store.connected ? undefined : "0 0 0 3px var(--danger-soft)"}></span>
        <span class="txt">{footText}{isMock ? ` (${t("foot.demo")})` : ""}</span>
      </div>
    </div>
  </nav>

  <div class="content" bind:clientWidth={contentWidth}>
    <main class="main" class:no-scroll={store.page === "apps" && online} bind:this={main}>
      {#if !store.ready}
        <!-- first paint: nothing, avoids flashing an offline message -->
      {:else if !online}
        <div class="offline">
          <div class="big"><Icon name="shield-alert" size={30} /></div>
          <h1>{t("offline.title")}</h1>
          <p class="muted">{t("offline.text")}</p>
          {#if store.error}<p class="faint">{store.error}</p>{/if}
          <div class="actions">
            {#if store.prefs.service_exe_available}
              <button class="btn primary" onclick={() => store.installService()}>{t("offline.install")}</button>
            {/if}
          </div>
          <p class="faint" style="margin-top:18px">{t("offline.manualPrefix")} <code>briqwall-service.exe install</code> {t("offline.manualSuffix")}</p>
        </div>
      {:else if store.page === "overview"}
        <Overview />
      {:else if store.page === "inbox"}
        <Inbox />
      {:else if store.page === "apps"}
        <Apps bind:selected={selectedApp} {docked} />
      {:else if store.page === "activity"}
        <Activity />
      {:else}
        <Settings />
      {/if}
    </main>
    {#if online && store.page === "apps" && !docked}
      <AppDrawer key={selectedApp} onclose={() => (selectedApp = null)} />
    {/if}
  </div>
</div>

{#if store.toast}
  {#key store.toast.id}
    <div class="toast {store.toast.tone}" role="status">
      <span class="ti"><Icon name={store.toast.tone === "ok" ? "check" : "info"} size={14} /></span>{store.toast.text}
    </div>
  {/key}
{/if}
