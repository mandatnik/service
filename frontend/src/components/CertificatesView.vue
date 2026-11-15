<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { badgeClass } from '../format'
import { certificateLocations, certificateValidity } from '../certificates'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
import CertificateParty from './CertificateParty.vue'

const emit = defineEmits(['open-certificate'])
const query = ref('')
const status = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const rows = computed(() => data.value.items.map(c => ({ ...c, locations: certificateLocations(c), validity: certificateValidity(c) })))
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
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input aria-label="Поиск сертификатов" v-model="query" placeholder="Владелец, организация, номер или издатель" /><select aria-label="Фильтр по состоянию" v-model="status" @change="apply"><option value="">Все</option><option value="valid">Действующие</option><option value="expired">Истёкшие</option><option value="future">Не вступили в силу</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading && !data.items.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Сертификаты не найдены" text="Проверьте фильтры или дождитесь сбора с машин." />
      <table v-else class="data-table certificates-table"><thead><tr><th>Владелец</th><th>УЦ</th><th>АРМ</th><th>Встроенная лицензия</th><th>Срок</th><th>Статус</th></tr></thead>
        <tbody><tr v-for="c in rows" :key="c.sha256" class="clickable" tabindex="0" @keydown.enter.self="emit('open-certificate', c.sha256)" @click="emit('open-certificate', c.sha256)">
          <td><CertificateParty :certificate="c" /></td>
          <td><CertificateParty :certificate="c" issuer /></td>
          <td><div class="certificate-sources">Реестр: {{ c.locations.registry }}, Файл: {{ c.locations.files }}</div><div class="small muted">{{ c.locations.total }}</div></td>
          <td><span class="badge" :class="c.embedded_license === 'present' ? 'badge-ok' : 'badge-neutral'" :title="c.embedded_license !== 'present' && c.embedded_license !== 'absent' ? 'Наличие встроенной лицензии не определено' : undefined">{{ c.embedded_license === 'present' ? 'Да' : c.embedded_license === 'absent' ? 'Нет' : 'Не определено' }}</span></td>
          <td><div class="certificate-period">{{ c.validity.period }}</div><div class="small muted">{{ c.validity.remaining }}</div></td>
          <td><span class="badge" :class="badgeClass(c.validity.tone)" :title="c.validity.label === 'Отозван' ? undefined : 'Статус по сроку действия. Проверка отзыва не выполнялась.'">{{ c.validity.label }}</span></td>
        </tr></tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
  </section>
</template>
