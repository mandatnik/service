<script setup>
defineProps({ title: { type: String, default: 'Нет данных' }, text: { type: String, default: 'Измените фильтры или дождитесь следующего сбора.' } })
</script>
<template>
  <div class="state empty-state">
    <div class="state-icon muted-icon">∅</div>
    <div><strong>{{ title }}</strong><p>{{ text }}</p></div>
  </div>
</template>
