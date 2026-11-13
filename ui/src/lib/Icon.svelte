<script lang="ts" module>
  const S = 'fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"';
  export const ICONS = {
    shield: `<path ${S} d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z"/>`,
    "shield-check": `<path ${S} d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z"/><path ${S} stroke-width="1.9" d="m8.7 12 2.3 2.3 4.4-4.6"/>`,
    "shield-alert": `<path ${S} d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z"/><path ${S} stroke-width="1.9" d="M12 8.5v4M12 15.6v.1"/>`,
    home: `<path ${S} d="M4 10.5 12 4l8 6.5V19a1 1 0 0 1-1 1h-4.5v-5.5h-5V20H5a1 1 0 0 1-1-1v-8.5Z"/>`,
    bell: `<path ${S} d="M6 16.5V11a6 6 0 1 1 12 0v5.5l1.5 1.5h-15L6 16.5Z"/><path ${S} d="M10 20.5a2.2 2.2 0 0 0 4 0"/>`,
    grid: `<rect ${S} x="4" y="4" width="7" height="7" rx="1.6"/><rect ${S} x="13" y="4" width="7" height="7" rx="1.6"/><rect ${S} x="4" y="13" width="7" height="7" rx="1.6"/><rect ${S} x="13" y="13" width="7" height="7" rx="1.6"/>`,
    pulse: `<path ${S} d="M3 12h4l2.5-6 5 12 2.5-6H21"/>`,
    gear: `<circle ${S} cx="12" cy="12" r="3"/><path ${S} d="M12 2.8 14 5l3-.4.9 2.9 2.6 1.5-.8 2.9.8 2.9-2.6 1.5-.9 2.9-3-.4-2 2.2-2-2.2-3 .4-.9-2.9-2.6-1.5.8-2.9-.8-2.9 2.6-1.5L7 4.6l3 .4 2-2.2Z"/>`,
    check: `<path ${S} stroke-width="2" d="m5 12.5 4.5 4.5L19 7.5"/>`,
    block: `<circle ${S} cx="12" cy="12" r="8.2"/><path ${S} d="m6.4 17.6 11.2-11.2"/>`,
    alert: `<path ${S} d="M10.3 4.5 2.9 17.6A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-2.9L13.7 4.5a2 2 0 0 0-3.4 0Z"/><path ${S} stroke-width="1.9" d="M12 9.5v4.2M12 16.9v.1"/>`,
    info: `<circle ${S} cx="12" cy="12" r="8.2"/><path ${S} stroke-width="1.9" d="M12 11v5.2M12 7.9v.1"/>`,
    wifi: `<path ${S} d="M3.5 9.5a12.5 12.5 0 0 1 17 0M6.5 12.8a8 8 0 0 1 11 0M9.5 16a3.6 3.6 0 0 1 5 0"/><circle cx="12" cy="19" r="1.1" fill="currentColor"/>`,
    lock: `<rect ${S} x="5" y="10.5" width="14" height="9.5" rx="2"/><path ${S} d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>`,
    unlock: `<rect ${S} x="5" y="10.5" width="14" height="9.5" rx="2"/><path ${S} d="M8 10.5V8a4 4 0 0 1 7.6-1.7"/>`,
    search: `<circle ${S} cx="11" cy="11" r="6.5"/><path ${S} d="m16 16 4 4"/>`,
    chev: `<path ${S} stroke-width="1.9" d="m7 10 5 5 5-5"/>`,
    x: `<path ${S} stroke-width="1.8" d="m6.5 6.5 11 11m0-11-11 11"/>`,
    clock: `<circle ${S} cx="12" cy="12" r="8.2"/><path ${S} d="M12 7.5V12l3 2"/>`,
    globe: `<circle ${S} cx="12" cy="12" r="8.2"/><path ${S} stroke-width="1.5" d="M3.8 12h16.4M12 3.8c2.4 2.4 3.4 5.2 3.4 8.2s-1 5.8-3.4 8.2c-2.4-2.4-3.4-5.2-3.4-8.2s1-5.8 3.4-8.2Z"/>`,
    fingerprint: `<path ${S} stroke-width="1.6" d="M6.5 8.5a6.5 6.5 0 0 1 11.6 1.8M5.5 13c0-1 .1-1.9.4-2.7M18.5 12.6c0 2.4-.4 4.6-1.2 6.4M9 19.5c.7-2 1.1-4.3 1.1-6.6a1.9 1.9 0 0 1 3.8 0c0 1 0 2-.1 3M8.1 12.6c0 1.9-.3 3.6-.8 5.1M15.4 17.8c-.2.8-.5 1.6-.8 2.3"/>`,
    power: `<path ${S} d="M12 3.5V12M7.2 6.5a7.5 7.5 0 1 0 9.6 0"/>`,
    swap: `<path ${S} d="M4 8h13l-3.5-3.5M20 16H7l3.5 3.5"/>`,
    moon: `<path ${S} d="M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10Z"/>`,
    refresh: `<path ${S} d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4"/>`,
    plus: `<path ${S} stroke-width="1.9" d="M12 5.5v13M5.5 12h13"/>`,
    learn: `<path ${S} d="M12 5 3 9.5 12 14l9-4.5L12 5Z"/><path ${S} d="M7 11.8v4.2c1.5 1.3 3.2 2 5 2s3.5-.7 5-2v-4.2"/>`,
  } as const;
  export type IconName = keyof typeof ICONS;
</script>

<script lang="ts">
  let { name, size = 16 }: { name: IconName; size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">{@html ICONS[name]}</svg>
