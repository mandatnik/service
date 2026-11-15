<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { pluralRu } from '../format'
import ErrorState from './ErrorState.vue'
const emit = defineEmits(['navigate', 'monitor'])
const data = ref(null)
const error = ref('')
const loading = ref(true)
async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.overview() } catch (e) { error.value = e.message } finally { loading.value = false }
}
function monitor(key) { emit('monitor', key, data.value.monitoring.as_of) }
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Машины, лицензии и сертификаты, требующие внимания.</p><span v-if="data" class="badge" :class="data.db_ok ? 'badge-ok' : 'badge-error'">SQL Server {{ data.db_ok ? 'доступен' : 'недоступен' }}</span></div>
      <button class="btn" :disabled="loading" @click="load">{{ loading ? 'Обновление…' : 'Обновить' }}</button>
    </div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else-if="loading && !data" class="state">Загрузка…</div>
    <template v-else-if="data">
      <div class="card-grid">
        <div class="metric-card machine-total-card"><button class="metric-main" @click="emit('navigate', 'machines')"><span>Машины</span><strong>{{ data.machines }}</strong></button><button class="metric-sub" @click="monitor('online')">{{ data.monitoring.online_machines }} {{ pluralRu(data.monitoring.online_machines, ['машина', 'машины', 'машин']) }} онлайн →</button></div>
        <button class="metric-card" @click="emit('navigate', 'machines')"><span>Пользователи</span><strong>{{ data.users }}</strong><small>присутствующие профили</small></button>
        <button class="metric-card" @click="emit('navigate', 'certificates')"><span>Сертификаты</span><strong>{{ data.certificates }}</strong><small>{{ data.active_observations }} активных наблюдений</small></button>
        <button class="metric-card" @click="emit('navigate', 'tasks')"><span>Задания</span><strong>{{ data.pending_jobs }}</strong><small>ожидают доставки или выполнения</small></button>
      </div>
      <h2 class="monitoring-title">Мониторинг</h2>
      <div class="card-grid monitoring-cards">
        <button class="metric-card" :class="{ 'metric-warning': data.monitoring.expired_certificates > 0 }" @click="monitor('expired_certificates')"><span>Сертификаты без замены</span><strong>{{ data.monitoring.expired_certificates }}</strong><small>{{ pluralRu(data.monitoring.expired_certificates, ['сертификат истёк', 'сертификата истекли', 'сертификатов истекли']) }} за последний месяц</small><small>На {{ data.monitoring.expired_certificate_machines }} АРМ · действующей замены по ИНН нет</small></button>
        <button class="metric-card" @click="monitor('active_license')"><span>Машины с активной лицензией</span><strong>{{ data.monitoring.active_license_machines }}</strong><small>из них {{ data.monitoring.active_license_trial_machines }} с пробной</small></button>
        <button class="metric-card" :class="{ 'metric-warning': data.monitoring.needs_license_machines > 0 }" @click="monitor('needs_license')"><span>Машины нуждаются в лицензии</span><strong>{{ data.monitoring.needs_license_machines }}</strong><small>из них {{ data.monitoring.needs_license_trial_machines }} с пробной</small></button>
        <button class="metric-card" :class="{ 'metric-danger': data.monitoring.missing_csp_machines > 0 }" @click="monitor('csp_missing')"><span>Машины без КриптоПро</span><strong>{{ data.monitoring.missing_csp_machines }}</strong><small>КриптоПро CSP не обнаружен</small></button>
      </div>
    </template>
  </section>
</template>
