<script lang="ts" generics="T extends string">
  let {
    options,
    value,
    onchange,
    label,
  }: { options: { value: T; label: string }[]; value: T; onchange: (v: T) => void; label?: string } = $props();
</script>

<div class="seg" role="radiogroup" aria-label={label}>
  {#each options as o (o.value)}
    <button
      type="button"
      role="radio"
      aria-checked={o.value === value}
      class:on={o.value === value}
      onclick={() => o.value !== value && onchange(o.value)}>{o.label}</button>
  {/each}
</div>
