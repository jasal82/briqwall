<script lang="ts">
  import { avatarColor, initial } from "./format";
  let { name, small = false }: { name: string; small?: boolean } = $props();
</script>

<div class="avatar" class:sm={small} style:background={avatarColor(name)} aria-hidden="true">{initial(name)}</div>
