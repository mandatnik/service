<script setup>
defineProps({ value: String })
</script>
<template><span class="badge" :class="value === 'present' ? 'badge-ok' : 'badge-neutral'">{{ value === 'present' ? 'Есть' : value === 'absent' ? 'Нет' : 'Не определено' }}</span></template>
