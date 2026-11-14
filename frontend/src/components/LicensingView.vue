<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel, stateLabel } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
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
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Версия продукта, тип лицензии, срок и пробность показаны раздельно, без вывода типа из версии.</p></div><button class="btn" @click="load">Обновить</button></div>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input v-model="query" placeholder="Машина или версия" /><select v-model="kind" @change="apply"><option value="">Все типы</option><option value="client">Клиентская</option><option value="server">Серверная</option><option value="unknown">Неизвестно</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Лицензии не найдены" text="Проверьте фильтры или дождитесь сбора CSP." />
      <table v-else class="data-table"><thead><tr><th>Машина</th><th>Продукт / ядро</th><th>Тип</th><th>Состояние</th><th>Срок</th><th>Пробность</th><th>Источник</th></tr></thead>
        <tbody><tr v-for="l in data.items" :key="l.machine_id">
          <td><strong>{{ l.display_name }}</strong><div class="small muted">{{ l.machine_id }}</div></td>
          <td>product <code>{{ l.product_version || '—' }}</code><div class="small muted">core <code>{{ l.core_version || '—' }}</code></div></td>
          <td><span class="badge badge-license">{{ licenseKindLabel(l.license_kind, l.license_kind_raw) }}</span><div class="small muted">{{ l.kind_source || '—' }}</div></td>
          <td>{{ stateLabel(l.state) }}<div class="small muted">{{ l.complete ? 'полный сбор' : 'частичный сбор' }}</div></td>
          <td>{{ l.valid_to_utc ? formatTime(l.valid_to_utc) : (l.valid_to_raw || '—') }}<div class="small muted">{{ l.term_kind || '—' }} · {{ l.time_basis || '—' }}</div></td>
          <td>{{ l.is_trial || 'unknown' }}</td>
          <td>{{ l.source || '—' }}<div v-if="l.error || l.last_attempt_error" class="small error-text">{{ l.error || l.last_attempt_error }}</div></td>
        </tr></tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="p => { page = p; load() }" />
    </div>
  </section>
</template>
