<script setup>
import { computed } from 'vue'
const props = defineProps({ page: { type: Number, default: 1 }, pageSize: { type: Number, default: 25 }, total: { type: Number, default: 0 } })
const emit = defineEmits(['change'])
const pages = computed(() => Math.max(1, Math.ceil(props.total / Math.max(1, props.pageSize))))
function go(next) {
  if (next < 1 || next > pages.value || next === props.page) return
  emit('change', next)
}
</script>
<template>
  <div class="pager" v-if="total > 0">
    <span class="muted">{{ total }} записей · страница {{ page }} из {{ pages }}</span>
    <div class="pager-actions">
      <button class="btn btn-quiet" :disabled="page <= 1" @click="go(page - 1)">Назад</button>
      <button class="btn btn-quiet" :disabled="page >= pages" @click="go(page + 1)">Вперёд</button>
    </div>
  </div>
</template>
