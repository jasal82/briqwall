<script lang="ts">
  import Icon from "./Icon.svelte";
  import { t } from "./i18n/index.svelte";

  type Item = { label: string; hint: string; run: () => void };
  let {
    label,
    primary = false,
    run,
    items,
    disabled = false,
  }: { label: string; primary?: boolean; run: () => void; items: Item[]; disabled?: boolean } = $props();

  let open = $state(false);
  let root: HTMLElement;

  function onWindowClick(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) open = false;
  }
  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape") open = false;
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKey} />

<span class="split" bind:this={root}>
  <button type="button" class="btn split-main" class:primary {disabled} onclick={run}>{label}</button>
  <button
    type="button"
    class="btn split-toggle"
    class:primary
    {disabled}
    aria-label={t("common.moreOptions")}
    aria-expanded={open}
    onclick={() => (open = !open)}><Icon name="chev" size={14} /></button>
  <div class="menu" class:open style="top:38px;left:0" role="menu">
    {#each items as it (it.label)}
      <button
        type="button"
        role="menuitem"
        onclick={() => {
          open = false;
          it.run();
        }}><span>{it.label}</span><small>{it.hint}</small></button>
    {/each}
  </div>
</span>
