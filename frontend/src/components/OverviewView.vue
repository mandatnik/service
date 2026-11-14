<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import ErrorState from './ErrorState.vue'
const emit = defineEmits(['navigate'])
const data = ref(null)
const error = ref('')
const loading = ref(true)
async function load() {
  loading.value = true
  error.value = ''
  try { data.value = await api.overview() } catch (e) { error.value = e.message } finally { loading.value = false }
}
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Сводка по машинам, сертификатам и каналам связи.</p></div>
      <button class="btn" :disabled="loading" @click="load">{{ loading ? 'Обновление…' : 'Обновить' }}</button>
    </div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else-if="loading && !data" class="state">Загрузка…</div>
    <template v-else-if="data">
      <div class="card-grid">
        <button class="metric-card" @click="emit('navigate', 'machines')"><span>Машины</span><strong>{{ data.machines }}</strong><small>{{ data.active_registrations }} активных регистраций</small></button>
        <button class="metric-card" @click="emit('navigate', 'machines')"><span>Пользователи</span><strong>{{ data.users }}</strong><small>присутствующие профили</small></button>
        <button class="metric-card" @click="emit('navigate', 'certificates')"><span>Сертификаты</span><strong>{{ data.certificates }}</strong><small>{{ data.active_observations }} активных наблюдений</small></button>
        <button class="metric-card" @click="emit('navigate', 'tasks')"><span>Задания</span><strong>{{ data.pending_jobs }}</strong><small>ожидают доставки или выполнения</small></button>
      </div>
      <div class="panel two-column">
        <div>
          <h3>Состояние системы</h3>
          <dl class="facts">
            <dt>SQL Server</dt><dd><span class="badge" :class="data.db_ok ? 'badge-ok' : 'badge-error'">{{ data.db_ok ? 'доступен' : 'недоступен' }}</span></dd>
            <dt>Последний отчёт</dt><dd>{{ formatTime(data.last_report_at) }}</dd>
            <dt>Отчётов за сутки</dt><dd>{{ data.reports_24h }}</dd>
            <dt>Событий за сутки</dt><dd>{{ data.events_24h }}</dd>
            <dt>Конфигурация</dt><dd>версия {{ data.config_version }} · <code>{{ data.config_hash?.slice(0, 16) }}…</code></dd>
          </dl>
          <button class="btn btn-quiet" @click="emit('navigate', 'events')">Открыть события</button>
        </div>
        <div class="callout">
          <strong>Что проверять</strong>
          <p>Строка «offline» появляется, когда с последнего выхода агента на связь прошло 3 минуты и более. Частичный отчёт не скрывается: он отмечается в источниках и остаётся в истории.</p>
          <p>Тип лицензии показывается ровно тем, что вернул источник; пробность и срок не выводятся из версии CSP.</p>
        </div>
      </div>
    </template>
  </section>
</template>
