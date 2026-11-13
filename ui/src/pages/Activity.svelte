<script lang="ts">
  import EventRow, { describe } from "../lib/EventRow.svelte";
  import { store } from "../lib/store.svelte";
  import { dayLabel } from "../lib/format";
  import { i18n, t } from "../lib/i18n/index.svelte";
  import type { XEvent } from "../lib/types";

  type Filter = "all" | "blocked" | "decisions";
  let filter = $state<Filter>("all");

  const groups = $derived.by(() => {
    const out: { day: string; items: XEvent[] }[] = [];
    for (const e of [...store.events].reverse()) {
      const d = describe(e);
      if (filter === "blocked" && !d.blocked) continue;
      if (filter === "decisions" && !d.decision) continue;
      const day = dayLabel(e.time);
      if (out.at(-1)?.day !== day) out.push({ day, items: [] });
      out.at(-1)!.items.push(e);
    }
    return out;
  });

  /** Today at a glance (shown beside the log on wide windows). */
  const today = $derived.by(() => {
    const start = new Date(new Date().toDateString()).getTime() / 1000;
    let blocked = 0;
    let requests = 0;
    let decisions = 0;
    const perApp = new Map<string, number>();
    for (const e of store.events) {
      if (e.time < start) continue;
      const k = e.kind;
      if (typeof k === "object" && "Blocked" in k) {
        blocked++;
        perApp.set(k.Blocked.name, (perApp.get(k.Blocked.name) ?? 0) + 1);
      } else if (typeof k === "object" && "NewRequest" in k) requests++;
      else if (describe(e).decision) decisions++;
    }
    const top = [...perApp]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], i18n.locale))
      .slice(0, 5)
      .map(([name, n]) => ({ name, n }));
    return { blocked, requests, decisions, top, max: top[0]?.n ?? 1 };
  });
</script>

<section class="page">
  <div class="page-head">
    <div><h1>{t("nav.activity")}</h1><p>{t("activity.intro")}</p></div>
  </div>
  <div class="toolbar">
    <button class="chip" class:on={filter === "all"} onclick={() => (filter = "all")}>{t("activity.filter.all")}</button>
    <button class="chip" class:on={filter === "blocked"} onclick={() => (filter = "blocked")}>{t("activity.filter.blocked")}</button>
    <button class="chip" class:on={filter === "decisions"} onclick={() => (filter = "decisions")}>{t("activity.filter.decisions")}</button>
  </div>
  <div class="act">
    <div class="act-log">
      {#each groups as g (g.day)}
        <div class="day">{g.day}</div>
        <div class="card">
          {#each g.items as e (e.seq)}<EventRow event={e} />{/each}
        </div>
      {:else}
        <div class="card empty"><p class="muted" style="margin:0">{t("activity.emptyFiltered")}</p></div>
      {/each}
    </div>
    <aside class="act-side">
      <div class="card">
        <div class="card-head"><b>{t("activity.today")}</b></div>
        <div class="kpi">
          <div><b>{today.blocked}</b><span>{t("activity.kpi.blocked")}</span></div>
          <div><b>{today.requests}</b><span>{t("activity.kpi.requests")}</span></div>
          <div><b>{today.decisions}</b><span>{t("activity.kpi.decisions")}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><b>{t("activity.top")}</b></div>
        <div class="top-list">
          {#each today.top as a (a.name)}
            <div>
              <div class="row"><span class="ellipsis">{a.name}</span><span class="faint">{a.n}</span></div>
              <div class="meter"><i style:width="{(a.n / today.max) * 100}%"></i></div>
            </div>
          {:else}
            <span class="muted">{t("activity.top.empty")}</span>
          {/each}
        </div>
      </div>
    </aside>
  </div>
</section>
