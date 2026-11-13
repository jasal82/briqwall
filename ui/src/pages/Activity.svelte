<script lang="ts">
  import EventRow, { describe } from "../lib/EventRow.svelte";
  import { store } from "../lib/store.svelte";
  import { dayLabel } from "../lib/format";
  import { t } from "../lib/i18n/index.svelte";
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
  {#each groups as g (g.day)}
    <div class="day">{g.day}</div>
    <div class="card">
      {#each g.items as e (e.seq)}<EventRow event={e} />{/each}
    </div>
  {:else}
    <div class="card empty"><p class="muted" style="margin:0">{t("activity.emptyFiltered")}</p></div>
  {/each}
</section>
