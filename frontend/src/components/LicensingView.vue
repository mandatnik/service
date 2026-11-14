<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel, stateLabel, trialLabel, licenseExpiry } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
const expanded = ref('')
const query = ref('')
const kind = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.licensing({ query: query.value, kind: kind.value, page: page.value, page_size: 25 }) } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Лицензии КриптоПро на рабочих машинах. Технические сведения доступны по нажатию на строку.</p></div><button class="btn" @click="load">Обновить</button></div>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input aria-label="Поиск лицензий" v-model="query" placeholder="Машина или версия" /><select aria-label="Тип лицензии" v-model="kind" @change="apply"><option value="">Все типы</option><option value="client">Клиентская</option><option value="server">Серверная</option><option value="unknown">Неизвестно</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading && !data.items.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Лицензии не найдены" text="Проверьте фильтры или дождитесь сбора CSP." />
      <table v-else class="data-table"><thead><tr><th>Машина</th><th>КриптоПро CSP</th><th>Тип лицензии</th><th>Состояние</th><th>Действует до</th><th>Вариант</th></tr></thead>
        <tbody v-for="l in data.items" :key="l.machine_id">
          <tr class="clickable" tabindex="0" :aria-expanded="expanded === l.machine_id" @click="expanded = expanded === l.machine_id ? '' : l.machine_id" @keydown.enter="expanded = expanded === l.machine_id ? '' : l.machine_id">
            <td><strong>{{ l.display_name }}</strong></td>
            <td>{{ l.product_version || 'Не установлен' }}<div v-if="l.core_version" class="small muted">Ядро {{ l.core_version }}</div></td>
            <td><span class="badge badge-license">{{ licenseKindLabel(l.license_kind) }}</span></td>
            <td><span class="badge" :class="['valid', 'active'].includes(l.license_state) ? 'badge-ok' : ['expired', 'invalid'].includes(l.license_state) ? 'badge-error' : 'badge-neutral'">{{ stateLabel(l.license_state) }}</span><div v-if="!l.complete" class="small muted">Сбор неполный</div><div v-if="l.error || l.last_attempt_error" class="small error-text">Ошибка сбора · подробнее в строке</div></td>
            <td>{{ licenseExpiry(l) }}</td>
            <td>{{ trialLabel(l.is_trial) }}</td>
          </tr>
          <tr v-if="expanded === l.machine_id" class="row-details"><td colspan="6"><dl class="facts"><dt>Проверено</dt><dd>{{ formatTime(l.collected_at) }}</dd><dt>Источник типа</dt><dd>{{ l.license_kind_source || '—' }} ({{ l.license_kind_raw ?? '—' }})</dd><dt>Источник данных</dt><dd>{{ l.source || '—' }}</dd><dt>Исходный срок</dt><dd>{{ l.valid_to_raw || '—' }} · {{ l.time_basis || '—' }}</dd><dt v-if="l.error || l.last_attempt_error">Ошибка</dt><dd v-if="l.error || l.last_attempt_error" class="error-text">{{ l.error || l.last_attempt_error }}</dd></dl></td></tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="p => { page = p; load() }" />
    </div>
  </section>
</template>
