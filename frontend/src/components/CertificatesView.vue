<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatDate } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
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
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Уникальные сертификаты и места их обнаружения. Subject показывается отдельно от идентификаторов пользователя.</p></div><button class="btn" @click="load">Обновить</button></div>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><input v-model="query" placeholder="Subject, issuer, serial или SHA-256" /><select v-model="status" @change="apply"><option value="">Все</option><option value="valid">Действительные</option><option value="expired">Истёкшие</option><option value="future">Ещё не действуют</option></select><button class="btn">Найти</button></form></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Сертификаты не найдены" text="Проверьте фильтры или дождитесь сбора с машин." />
      <table v-else class="data-table"><thead><tr><th>Subject</th><th>Идентификаторы</th><th>Срок</th><th>Наблюдения</th><th>Источник лицензии</th></tr></thead>
        <tbody><tr v-for="c in data.items" :key="c.sha256" class="clickable" @click="emit('open-certificate', c.sha256)">
          <td><strong>{{ c.subject || '—' }}</strong><div class="small muted">serial {{ c.serial_hex || c.serial_number || '—' }}</div><code class="small">{{ c.sha256.slice(0, 20) }}…</code></td>
          <td><div>CN: {{ c.owner_cn || '—' }}</div><div class="small muted">ИНН: {{ c.inn || '—' }}<br />СНИЛС: {{ c.snils || '—' }}</div></td>
          <td>{{ formatDate(c.not_before) }}<br /><span class="muted">— {{ formatDate(c.not_after) }}</span></td>
          <td><span class="badge" :class="c.active ? 'badge-ok' : 'badge-neutral'">{{ c.active ? 'активен' : 'не наблюдается' }}</span><div class="small muted">{{ c.machines }} машин · {{ c.observations }} мест</div></td>
          <td>{{ c.embedded_license || '—' }}</td>
        </tr></tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
  </section>
</template>
