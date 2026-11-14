<script setup>
defineProps({ message: { type: String, default: 'Не удалось загрузить данные' }, retry: { type: Boolean, default: true } })
defineEmits(['retry'])
</script>
<template>
  <div class="state error-state" role="alert">
    <div class="state-icon">!</div>
    <div>
      <strong>Ошибка загрузки</strong>
      <p>{{ message }}</p>
    </div>
    <button v-if="retry" class="btn" @click="$emit('retry')">Повторить</button>
  </div>
</template>
