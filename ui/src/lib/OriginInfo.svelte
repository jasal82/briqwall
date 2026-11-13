<script lang="ts" module>
  /** Programs that should not normally start command-line tools or unknown programs. */
  const SUSPICIOUS = new Set([
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "onenote.exe",
    "visio.exe",
    "acrord32.exe",
    "acrobat.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "hh.exe",
  ]);

  export function suspiciousParent(o: { parents: { name: string }[] }): string | null {
    return o.parents.find((p) => SUSPICIOUS.has(p.name.toLowerCase()))?.name ?? null;
  }
</script>

<script lang="ts">
  import Icon from "./Icon.svelte";
  import { ago } from "./format";
  import { t, tn } from "./i18n/index.svelte";
  import type { AppInfo, ProcessOrigin } from "./types";

  let { app, compact = false }: { app: AppInfo; compact?: boolean } = $props();

  const origins = $derived(app.origins ?? []);
  const exe = $derived(app.path.split(String.fromCharCode(92)).pop() ?? app.name);
  const warn = $derived(origins.map(suspiciousParent).find((p) => p !== null) ?? null);
  const shared = $derived(app.category === "Lolbin");
  let showAll = $state(false);
  const shown = $derived(showAll ? origins : origins.slice(0, 1));

  /** Grandparent › parent › app */
  function chain(o: ProcessOrigin): string[] {
    return [...o.parents.map((p) => p.name).reverse(), exe];
  }
</script>

{#if origins.length > 0}
  <div class="origin" class:compact>
    <span class="k">{t("origin.title")}</span>
    {#each shown as o, i (i)}
      <div class="origin-item">
        <div class="chain">
          {#each chain(o) as name, j (j)}
            {#if j > 0}<span class="sep">›</span>{/if}
            <span class="proc" class:me={j === chain(o).length - 1} class:bad={suspiciousParent({ parents: [{ name }] }) !== null}
              >{name}</span>
          {/each}
          <span class="faint">· PID {o.pid} · {tn("origin.count", o.count)} · {ago(o.last_seen)}</span>
        </div>
        {#if o.command_line}
          <code class="cmd selectable" title={o.command_line}>{o.command_line}</code>
        {:else}
          <span class="faint">{t("origin.noCmdline")}</span>
        {/if}
      </div>
    {/each}
    {#if origins.length > 1}
      <button class="link" onclick={() => (showAll = !showAll)}>
        {showAll ? t("origin.less") : tn("origin.more", origins.length - 1)}
      </button>
    {/if}
    {#if warn}
      <div class="origin-warn"><Icon name="alert" size={14} />{t("origin.suspicious", { parent: warn })}</div>
    {/if}
    {#if shared}
      <div class="faint">{t("origin.scope", { name: exe })}</div>
    {/if}
  </div>
{/if}
