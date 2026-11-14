<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
const query = ref('')
const severity = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 30 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.events({ query: query.value, severity: severity.value, page: page.value, page_size: 30 }) } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Ошибки сбора, DNS-предупреждения, конфликты и административные действия.</p></div><button class="btn" @click="load">Обновить</button></div>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input aria-label="Поиск событий" v-model="query" placeholder="Тип или текст" /><select aria-label="Уровень события" v-model="severity" @change="apply"><option value="">Все уровни</option><option value="info">info</option><option value="warning">warning</option><option value="error">error</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading && !data.items.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Событий нет" text="Измените фильтры или дождитесь активности агентов." />
      <div v-else class="event-list">
        <div v-for="e in data.items" :key="e.event_id" class="event-row"><div><span class="badge" :class="e.severity === 'error' ? 'badge-error' : (e.severity === 'warning' ? 'badge-warning' : 'badge-neutral')">{{ e.severity }}</span> <strong>{{ e.kind }}</strong><div>{{ e.message }}</div><div v-if="e.machine_id" class="small muted">machine {{ e.machine_id }}</div><details v-if="e.details_json"><summary class="small muted">Детали</summary><pre class="details-json">{{ e.details_json }}</pre></details></div><span class="muted small">{{ formatTime(e.created_at) }}</span></div>
      </div>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="p => { page = p; load() }" />
    </div>
  </section>
</template>
