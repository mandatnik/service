<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel, stateLabel, timeAgo } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
const emit = defineEmits(['open-machine'])
const query = ref('')
const status = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api.machines({ query: query.value, status: status.value, page: page.value, page_size: 25 })
  } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
function changePage(next) { page.value = next; load() }
onMounted(load)
</script>
<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Зарегистрированные агенты, профили, лицензии и полнота сбора.</p></div>
      <button class="btn" @click="load">Обновить</button>
    </div>
    <div class="toolbar">
      <form class="search-form" @submit.prevent="apply">
        <input v-model="query" placeholder="Имя, hostname или UUID" />
        <select v-model="status" @change="apply">
          <option value="">Все состояния</option>
          <option value="active">Доступные</option>
          <option value="offline">Нет связи</option>
          <option value="conflict">Конфликт hostname</option>
        </select>
        <button class="btn">Найти</button>
      </form>
      <span class="muted">Опрос агента — каждые 10 минут</span>
    </div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Машины не найдены" text="Проверьте фильтры или зарегистрируйте агент." />
      <table v-else class="data-table">
        <thead><tr><th>Машина</th><th>Hostname / UUID</th><th>Связь</th><th>CSP</th><th>Лицензия</th><th>Сбор</th><th>Данные</th></tr></thead>
        <tbody>
          <tr v-for="m in data.items" :key="m.machine_id" class="clickable" @click="emit('open-machine', m.machine_id)">
            <td><strong>{{ m.display_name }}</strong><div v-if="m.hostname_conflict" class="badge badge-warning">hostname конфликт</div></td>
            <td><div>{{ m.hostname || '—' }}</div><code class="small">{{ m.uuid || 'нет регистрации' }}</code></td>
            <td><span class="badge" :class="m.offline ? 'badge-error' : 'badge-ok'">{{ m.offline ? 'offline' : 'online' }}</span><div class="small muted">{{ m.last_seen_at ? timeAgo(m.last_seen_at) : 'нет связи' }}<br />{{ m.source_ip }}</div></td>
            <td><div>product <code>{{ m.product_version || '—' }}</code></div><div class="small muted">core <code>{{ m.core_version || '—' }}</code></div></td>
            <td><span class="badge badge-license">{{ licenseKindLabel(m.license_kind, m.license_kind_raw) }}</span><div class="small muted">{{ stateLabel(m.license_state) }}<span v-if="m.is_trial"> · trial={{ m.is_trial }}</span></div></td>
            <td><span class="badge" :class="m.last_report_status === 'complete' ? 'badge-ok' : (m.last_report_status ? 'badge-warning' : 'badge-neutral')">{{ stateLabel(m.last_report_status) }}</span><div class="small muted">{{ formatTime(m.last_report_at) }}</div></td>
            <td><div>{{ m.users }} польз. · {{ m.active_certificates }} серт.</div><div class="small muted">источников: {{ m.applied_sources }}</div></td>
          </tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
  </section>
</template>
