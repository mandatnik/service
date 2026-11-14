<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatDate } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
import CertificateOwner from './CertificateOwner.vue'
import EmbeddedLicenseBadge from './EmbeddedLicenseBadge.vue'
const emit = defineEmits(['open-certificate'])
const query = ref('')
const status = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.certificates({ query: query.value, status: status.value, page: page.value, page_size: 25 }) } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
function changePage(next) { page.value = next; load() }
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Владельцы, сроки действия и места обнаружения сертификатов. Подробности — в карточке.</p></div><button class="btn" @click="load">Обновить</button></div>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input aria-label="Поиск сертификатов" v-model="query" placeholder="Владелец, организация, номер или издатель" /><select aria-label="Фильтр по состоянию" v-model="status" @change="apply"><option value="">Все</option><option value="valid">Действительные</option><option value="expired">Истёкшие</option><option value="future">Ещё не действуют</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading && !data.items.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Сертификаты не найдены" text="Проверьте фильтры или дождитесь сбора с машин." />
      <table v-else class="data-table"><thead><tr><th>Владелец</th><th>Сертификат</th><th>Срок</th><th>Найден на машинах</th><th>Встроенная лицензия</th></tr></thead>
        <tbody><tr v-for="c in data.items" :key="c.sha256" class="clickable" tabindex="0" @keydown.enter.self="emit('open-certificate', c.sha256)" @click="emit('open-certificate', c.sha256)">
          <td><CertificateOwner :certificate="c" /></td>
          <td><div class="certificate-serial">{{ c.serial_hex || c.serial_number || '—' }}</div><div class="small muted">{{ c.issuer_cn || 'Издатель не указан' }}</div></td>
          <td>{{ formatDate(c.not_before) }}<br /><span class="muted">— {{ formatDate(c.not_after) }}</span></td>
          <td><span class="badge" :class="c.active ? 'badge-ok' : 'badge-neutral'">{{ c.active ? c.machines : 'Не обнаружен' }}</span><div class="small muted">{{ c.observations }} мест обнаружения</div></td>
          <td><EmbeddedLicenseBadge :value="c.embedded_license" /></td>
        </tr></tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
  </section>
</template>
