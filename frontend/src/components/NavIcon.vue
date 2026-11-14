<script setup>
defineProps({ name: String })
const paths = {
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  machines: 'M3 4h18v12H3z M8 21h8 M12 16v5',
  groups: 'M3 5h7v6H3z M14 5h7v6h-7z M8 16h8v5H8z M6 11v3h12v-3 M12 14v2',
  policies: 'M3 6h7l2 2h9v12H3z M3 6V4h7l2 2 M8 13h8 M8 16h5',
  certificates: 'M6 3h12v12l-6 6-6-6z M9 7h6 M9 10h6 M10 14h4',
  licensing: 'M12 3l8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6z M8 12l3 3 5-6',
  hostnames: 'M8 8H6a4 4 0 000 8h3 M16 8h2a4 4 0 010 8h-3 M8 12h8',
  events: 'M4 3h16v18H4z M8 7h8 M8 12h8 M8 17h5',
  settings: 'M4 7h16 M4 17h16 M8 4v6 M16 14v6',
  menu: 'M3 6h18 M3 12h18 M3 18h18'
}
</script>
<template><svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] || paths.overview" /></svg></template>
