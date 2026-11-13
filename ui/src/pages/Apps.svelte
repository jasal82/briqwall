<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import Avatar from "../lib/Avatar.svelte";
  import Switch from "../lib/Switch.svelte";
  import AppDrawer from "./AppDrawer.svelte";
  import { store } from "../lib/store.svelte";
  import { accessLabel, accessTone, ago, categoryLabel, folderOf, isUserFacing } from "../lib/format";
  import { i18n, t, type Key } from "../lib/i18n/index.svelte";
  import type { AppInfo } from "../lib/types";

  type Filter = "all" | "allowed" | "blocked" | "custom";
  let { selected = $bindable(), docked = false }: { selected: string | null; docked?: boolean } = $props();

  let query = $state("");
  let filter = $state<Filter>("all");
  let showSystem = $state(false);

  const ROW = 56;
  let scrollTop = $state(0);
  let viewport = $state(400);
  let list: HTMLDivElement;

  const rows = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const locale = i18n.locale;
    return store.apps
      .filter((a) => showSystem || isUserFacing(a))
      .filter((a) => {
        switch (filter) {
          case "allowed":
            return a.effective_out === "Allow" || a.effective_out === "Lan";
          case "blocked":
            return a.effective_out === "Block" || a.effective_out === "Ask";
          case "custom":
            return a.rule !== null;
          default:
            return true;
        }
      })
      .filter((a) => !q || a.name.toLowerCase().includes(q) || a.key.includes(q))
      .sort(
        (a, b) => Number(b.pending) - Number(a.pending) || a.name.localeCompare(b.name, locale, { numeric: true, sensitivity: "base" }),
      );
  });

  const hiddenSystem = $derived(showSystem ? 0 : store.apps.filter((a) => !isUserFacing(a)).length);
  const first = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 6));
  const last = $derived(Math.min(rows.length, Math.ceil((scrollTop + viewport) / ROW) + 6));
  const visible = $derived(rows.slice(first, last));

  $effect(() => {
    const ro = new ResizeObserver(() => (viewport = list.clientHeight));
    ro.observe(list);
    return () => ro.disconnect();
  });

  // Reset scroll position when the result set changes shape.
  $effect(() => {
    void filter;
    void query;
    void showSystem;
    if (list) list.scrollTop = 0;
  });

  function publisher(a: AppInfo): string {
    return typeof a.signature === "object" && "Valid" in a.signature ? a.signature.Valid.publisher : "—";
  }

  function inbound(a: AppInfo): { label: string; tone: string } {
    const explicit = a.rule !== null && a.rule.inbound !== "Auto";
    if (store.status?.mode === "Relaxed" && !explicit) return { label: t("apps.inbound.windows"), tone: "muted" };
    if (a.effective_in === "Block" || a.effective_in === "Ask") return { label: accessLabel("Block"), tone: "muted" };
    return { label: accessLabel(a.effective_in), tone: accessTone[a.effective_in] };
  }

  const filters: { id: Filter; label: Key }[] = [
    { id: "all", label: "apps.filter.all" },
    { id: "allowed", label: "apps.filter.allowed" },
    { id: "blocked", label: "apps.filter.blocked" },
    { id: "custom", label: "apps.filter.custom" },
  ];
</script>

<section class="page fill">
  <div class="page-head">
    <div><h1>{t("nav.apps")}</h1><p>{t("apps.intro")}</p></div>
  </div>
  <div class="toolbar">
    <label class="search">
      <Icon name="search" />
      <input class="input" placeholder={t("apps.search")} bind:value={query} spellcheck="false" />
    </label>
    {#each filters as f (f.id)}
      <button class="chip" class:on={filter === f.id} onclick={() => (filter = f.id)}>{t(f.label)}</button>
    {/each}
    <span class="sp"></span>
    <span class="faint" style="display:inline-flex;align-items:center;gap:8px">
      {t("apps.system")}{hiddenSystem ? ` (${hiddenSystem})` : ""}
      <Switch on={showSystem} label={t("apps.system.show")} onchange={(v) => (showSystem = v)} />
    </span>
  </div>

  <div class="apps-split" class:docked={docked && selected !== null}>
    <div class="card table">
      <div class="thead">
        <span>{t("apps.col.app")}</span><span class="col-pub">{t("apps.col.publisher")}</span><span>{t("apps.col.origin")}</span><span>{t("apps.col.internet")}</span><span
          >{t("apps.col.inbound")}</span><span>{t("apps.col.last")}</span>
      </div>
      <div class="vlist" bind:this={list} onscroll={() => (scrollTop = list.scrollTop)}>
        {#if rows.length === 0}
          <div class="table-empty">{t("apps.none")}</div>
        {/if}
        <div class="spacer" style:height="{rows.length * ROW}px">
          {#each visible as a, i (a.key)}
            {@const inn = inbound(a)}
            <div
              class="trow"
              class:sel={selected === a.key}
              style:top="{(first + i) * ROW}px"
              role="button"
              tabindex="0"
              onclick={() => (selected = a.key)}
              onkeydown={(e) => (e.key === "Enter" || e.key === " ") && (selected = a.key)}>
              <div class="appcell">
                <Avatar name={a.name} small />
                <div class="t">
                  <b class="ellipsis" title={a.name}>{a.name}</b>
                  <div class="faint ellipsis" title={a.path}>{folderOf(a.path)}</div>
                </div>
              </div>
              <span class="col-pub ellipsis" title={publisher(a)}>{publisher(a)}</span>
              <span><span class="badge">{categoryLabel(a.category)}</span></span>
              {#if a.effective_out === "Ask" && !a.pending}
                <span class="state muted" title={t("apps.asks.tip")}><i></i>{t("apps.asks")}</span>
              {:else}
                <span class="state {accessTone[a.effective_out]}"><i></i>{accessLabel(a.effective_out)}{a.rule?.expires ? " ⏱" : ""}</span>
              {/if}
              <span class="state {inn.tone}"><i></i>{inn.label}</span>
              <span class="time">{ago(a.last_blocked && a.last_blocked > a.last_seen ? a.last_blocked : a.last_seen)}</span>
            </div>
          {/each}
        </div>
      </div>
    </div>
    {#if docked && selected !== null}
      <AppDrawer key={selected} docked onclose={() => (selected = null)} />
    {/if}
  </div>
</section>
