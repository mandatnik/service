<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { formatDate, formatTime, licenseKindLabel, stateLabel, trialLabel } from '../format'
import ErrorState from './ErrorState.vue'
import InstallationReview from './InstallationReview.vue'
import MachineRenameDialog from './MachineRenameDialog.vue'
const props = defineProps({ machineId: { type: String, required: true } })
const emit = defineEmits(['back', 'open-machine'])
const data = ref(null)
const error = ref('')
const loading = ref(false)
const message = ref('')
const actionError = ref('')
const rebindID = ref('')
const publicKey = ref('')
const manualBusy = ref(false)
const rebindBusy = ref(false)
const reviewing = ref(null)
const archiveReason = ref('')
const archiveBusy = ref(false)
const renameOpen = ref(false)
const activeRegs = computed(() => (data.value?.registrations || []).filter(r => r.state === 'active'))
const pendingInstallations = computed(() => data.value?.pending_installations || [])
async function load() {
  loading.value = true
  error.value = ''
  try {
    data.value = await api.machine(props.machineId)
    if (!rebindID.value && activeRegs.value.length) rebindID.value = String(activeRegs.value[0].registration_id)
  } catch (e) { error.value = e.message } finally { loading.value = false }
}
async function scan() {
  actionError.value = ''
  message.value = ''
  manualBusy.value = true
  try {
    const result = await api.createJob(props.machineId)
    message.value = `Задание ${result.job_id} создано. Оно будет доставлено на следующем опросе агента.`
    await load()
  } catch (e) { actionError.value = e.message } finally { manualBusy.value = false }
}
async function rebind() {
  actionError.value = ''
  message.value = ''
  if (!rebindID.value || !publicKey.value.trim()) { actionError.value = 'Выберите регистрацию и вставьте PUBLIC KEY в PEM.'; return }
  if (!window.confirm('Заменить публичный ключ активной регистрации? Старый ключ перестанет авторизовывать агент.')) return
  rebindBusy.value = true
  try {
    const result = await api.rebind(Number(rebindID.value), props.machineId, publicKey.value)
    message.value = `Ключ заменён: ${result.key_fingerprint}`
    publicKey.value = ''
    await load()
  } catch (e) { actionError.value = e.message } finally { rebindBusy.value = false }
}
async function revoke(registrationID) {
  actionError.value = ''
  message.value = ''
  if (!window.confirm(`Отозвать регистрацию ${registrationID}? Старый ключ перестанет авторизовывать агент; история останется.`)) return
  try {
    await api.revokeRegistration(registrationID)
    message.value = `Регистрация ${registrationID} отозвана.`
    await load()
  } catch (e) { actionError.value = e.message }
}
async function installationResolved(payload) {
  const action = payload?.action
  reviewing.value = null
  message.value = action === 'replace'
    ? `Установка заменена. Карточка ${payload.result.machine_id} и история сохранены.`
    : action === 'separate'
      ? `Создана отдельная машина ${payload.result.machine_id}.`
      : 'Заявка на установку отклонена.'
  await load()
}
async function machineRenamed(result) {
  renameOpen.value = false
  message.value = `Имя АРМ изменено: «${result.display_name}». Hostname и machine_id не изменялись.`
  await load()
}
async function archive() {
  actionError.value = ''
  message.value = ''
  if (!archiveReason.value.trim()) { actionError.value = 'Укажите причину архивирования.'; return }
  archiveBusy.value = true
  try {
    await api.archiveMachine(props.machineId, archiveReason.value.trim())
    message.value = 'Карточка архивирована; история сохранена и доступна через фильтр «Архивные».'
    archiveReason.value = ''
    await load()
  } catch (e) { actionError.value = e.message } finally { archiveBusy.value = false }
}
async function assign(hostname, registrationID) {
  actionError.value = ''
  message.value = ''
  if (!window.confirm(`Назначить владельцем hostname «${hostname}» регистрацию ${registrationID}?`)) return
  try {
    await api.assignHostname(hostname, registrationID)
    message.value = `Hostname ${hostname} переназначен.`
    await load()
  } catch (e) { actionError.value = e.message }
}
onMounted(load)
useAutoRefresh(load, () => loading.value || manualBusy.value || rebindBusy.value || archiveBusy.value || !!publicKey.value.trim() || !!reviewing.value || renameOpen.value)
</script>
<template>
  <section>
    <button class="btn btn-quiet back" @click="emit('back')">← К машинам</button>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else-if="loading && !data" class="state">Загрузка…</div>
    <template v-else-if="data">
      <div class="page-heading">
        <div>
          <h2>{{ data.machine.display_name }} <span v-if="data.machine.archived" class="badge badge-neutral">Архивная запись</span></h2>
          <p class="muted">{{ data.machine.hostname || 'hostname не собран' }} · <code>{{ data.machine.machine_id }}</code></p>
        </div>
        <div class="heading-actions">
          <button class="btn" @click="renameOpen = true">Переименовать</button>
          <button class="btn btn-primary" :disabled="manualBusy" @click="scan">{{ manualBusy ? 'Создание…' : 'Ручное сканирование' }}</button>
          <button class="btn" @click="load">Обновить</button>
        </div>
      </div>
      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="actionError" class="alert alert-error">{{ actionError }}</div>
      <div class="card-grid compact">
        <div class="metric-card static"><span>Связь</span><strong>{{ data.machine.offline ? 'offline' : 'online' }}</strong><small>{{ formatTime(data.machine.last_seen_at) }} · {{ data.machine.source_ip || 'IP неизвестен' }}</small></div>
        <div class="metric-card static"><span>Пользователи</span><strong>{{ data.users.length }}</strong><small>{{ data.users.filter(u => u.present).length }} присутствуют</small></div>
        <div class="metric-card static"><span>Сертификаты</span><strong>{{ data.machine.active_certificates }}</strong><small>активных наблюдений</small></div>
        <div class="metric-card static"><span>DNS</span><strong>{{ data.machine.dns_verified ? 'Проверен' : 'Не подтверждён' }}</strong><small>{{ data.machine.dns_verified ? 'взаимное соответствие hostname ↔ IP' : 'сигнал, не блокировка' }}</small></div>
      </div>

      <div class="panel">
        <div class="panel-heading"><h3>Лицензия и версии CSP</h3><span class="badge" :class="data.csp?.complete ? 'badge-ok' : 'badge-warning'">{{ data.csp?.complete ? 'источник полный' : 'данные частичные' }}</span></div>
        <div class="two-column">
          <dl class="facts">
            <dt>Версия продукта</dt><dd><code>{{ data.csp?.product_version || '—' }}</code></dd>
            <dt>Версия ядра</dt><dd><code>{{ data.csp?.core_version || '—' }}</code></dd>
            <dt>Тип лицензии</dt><dd>{{ licenseKindLabel(data.csp?.license_kind, data.csp?.license_kind_raw) }}</dd>
            <dt>Источник типа</dt><dd><code>{{ data.csp?.license_kind_source || '—' }}</code></dd>
            <dt>Состояние</dt><dd>{{ stateLabel(data.csp?.license_state) }}</dd>
            <dt>Срок</dt><dd>{{ data.csp?.valid_to_utc ? formatTime(data.csp.valid_to_utc) : (data.csp?.valid_to_raw || '—') }}</dd>
          </dl>
          <dl class="facts">
            <dt>Пробность</dt><dd>{{ trialLabel(data.csp?.is_trial) }}</dd>
            <dt>Тип срока</dt><dd>{{ data.csp?.term_kind || '—' }}</dd>
            <dt>Основа времени</dt><dd>{{ data.csp?.time_basis || '—' }}</dd>
            <dt>Источник</dt><dd>{{ data.csp?.source || '—' }}</dd>
            <dt>Последняя ошибка</dt><dd class="error-text">{{ data.csp?.error || data.csp?.last_attempt_error || '—' }}</dd>
            <dt>Сканирование</dt><dd>{{ formatTime(data.csp?.collected_at) }}</dd>
          </dl>
        </div>
      </div>

      <div class="panel">
        <h3>Регистрации и идентичность</h3>
        <table class="data-table">
          <thead><tr><th>ID</th><th>UUID</th><th>Hostname</th><th>Состояние</th><th>Ключ</th><th>Последняя связь</th></tr></thead>
          <tbody><tr v-for="r in data.registrations" :key="r.registration_id">
            <td>{{ r.registration_id }}<div v-if="r.previous_registration_id" class="small muted">ранее {{ r.previous_registration_id }}</div><div v-if="r.replaced_by_registration_id" class="small muted">заменена {{ r.replaced_by_registration_id }}</div></td>
            <td><code class="small">{{ r.uuid }}</code></td><td>{{ r.hostname }}</td><td><span class="badge" :class="r.state === 'active' ? 'badge-ok' : 'badge-neutral'">{{ stateLabel(r.state) }}</span></td>
            <td><code class="small">{{ r.key_fingerprint?.slice(0, 20) }}…</code></td><td>{{ formatTime(r.last_seen_at) }}<div class="small muted">{{ r.source_ip }} · DNS (прямая): {{ r.dns_status || 'unknown' }}</div><button v-if="r.state === 'active'" class="btn btn-danger btn-small" @click="revoke(r.registration_id)">Отозвать</button></td>
          </tr></tbody>
        </table>
        <details class="advanced">
          <summary>Перепривязать публичный ключ</summary>
          <p class="muted">Это не замена установки: операция меняет ключ текущей регистрации. Новую установку с новым UUID подтверждайте через очередь «Ожидают подтверждения» и действие «Заменить установку агента».</p>
          <div class="form-row">
            <label class="field"><span>Активная регистрация</span><select v-model="rebindID"><option v-for="r in activeRegs" :key="r.registration_id" :value="String(r.registration_id)">{{ r.registration_id }} · {{ r.hostname }}</option></select></label>
          </div>
          <label class="field"><span>PUBLIC KEY (PEM)</span><textarea v-model="publicKey" rows="7" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></label>
          <button class="btn btn-danger" :disabled="rebindBusy || !activeRegs.length" @click="rebind">{{ rebindBusy ? 'Сохранение…' : 'Заменить ключ' }}</button>
        </details>
      </div>

      <div class="panel">
        <div class="panel-heading">
          <div><h3>Ожидающие установки</h3><p class="muted">Все ожидающие установки. Для этой карточки можно вручную подтвердить замену, в том числе при отличающемся имени; <code>machine_id</code> и история сохранятся.</p></div>
          <span v-if="pendingInstallations.length" class="badge badge-warning">{{ pendingInstallations.length }}</span>
        </div>
        <div v-if="!pendingInstallations.length" class="muted">Нет заявок, ожидающих решения.</div>
        <div v-for="request in pendingInstallations" :key="request.request_id" class="installation-request">
          <div>
            <strong>{{ request.hostname }}</strong>
            <code class="small muted">{{ request.uuid }}</code>
            <div class="small muted">Ключ {{ request.key_fingerprint.slice(0, 20) }}… · {{ request.source_ip || 'IP неизвестен' }} · {{ formatTime(request.last_seen_at) }}</div>
          </div>
          <button type="button" class="btn btn-primary" @click="reviewing = request">Заменить установку агента</button>
        </div>
        <InstallationReview v-if="reviewing" :request="reviewing" :preset-machine-id="machineId" @resolved="installationResolved" @cancel="reviewing = null" />
      </div>

      <div class="panel">
        <h3>Архив карточки</h3>
        <div v-if="data.machine.archived" class="alert alert-info">
          Карточка архивирована {{ formatTime(data.machine.archived_at) }} · {{ data.machine.archived_by || 'администратор' }}.
          Причина: {{ data.machine.archive_reason || 'не указана' }}. История, отчёты и события сохранены.
        </div>
        <template v-else-if="!activeRegs.length">
          <p class="muted">Историческая карточка без активной регистрации. Архивирование убирает её из списка действующих АРМ, не удаляя историю.</p>
          <label class="field"><span>Причина архивирования</span><input v-model="archiveReason" maxlength="1024" placeholder="Например: устаревшая запись после переустановки" /></label>
          <button type="button" class="btn btn-danger" :disabled="archiveBusy || !archiveReason.trim()" @click="archive">{{ archiveBusy ? 'Архивирование…' : 'Архивировать карточку' }}</button>
        </template>
        <p v-else class="muted">Сначала отзовите или замените активную регистрацию: карточку с действующей установкой архивировать нельзя.</p>
      </div>

      <div class="panel">
        <h3>Hostname и конфликты</h3>
        <div v-if="!data.hostnames.length" class="muted">Резервирований hostname нет.</div>
        <div v-for="h in data.hostnames" :key="h.hostname_norm" class="hostname-row" :class="{ conflict: h.competing.length > 0 }">
          <div><strong>{{ h.hostname_norm }}</strong><div class="small muted">владелец: {{ h.owner_display_name || 'не назначен' }}{{ h.owner_machine_id ? ' · ' + h.owner_machine_id : '' }}</div></div>
          <div v-if="h.competing.length" class="competing">
            <span class="badge badge-warning">Конфликт</span>
            <div v-for="c in h.competing" :key="c.registration_id" class="small">Претендует {{ c.display_name }} ({{ c.machine_id }}, reg {{ c.registration_id }}) <button class="link-button" @click="assign(h.hostname_norm, c.registration_id)">назначить</button></div>
          </div>
          <span v-else class="badge badge-ok">Конфликтов нет</span>
          <button v-if="activeRegs.length && h.owner_registration_id !== activeRegs[0].registration_id" class="btn btn-small" @click="assign(h.hostname_norm, activeRegs[0].registration_id)">Назначить этой машине</button>
        </div>
      </div>

      <div class="panel">
        <h3>Пользователи</h3>
        <table class="data-table"><thead><tr><th>Пользователь</th><th>SID</th><th>Профиль</th><th>Состояние</th><th>Последний раз</th></tr></thead>
          <tbody><tr v-for="u in data.users" :key="u.machine_user_id"><td><strong>{{ u.name }}</strong></td><td><code class="small">{{ u.sid }}</code></td><td class="small">{{ u.profile_path || '—' }}</td><td><span class="badge" :class="u.present ? (u.loaded ? 'badge-ok' : 'badge-neutral') : 'badge-warning'">{{ u.present ? (u.loaded ? 'загружен' : 'выгружен') : 'отсутствует' }}</span></td><td>{{ formatTime(u.last_seen_at) }}</td></tr></tbody>
        </table>
      </div>

      <div class="panel">
        <h3>Источники и полнота</h3>
        <table class="data-table"><thead><tr><th>Тип</th><th>Ключ</th><th>Scan seq</th><th>Полнота</th><th>Собрано</th></tr></thead>
          <tbody><tr v-for="s in data.sources" :key="s.source_type + s.source_key"><td>{{ s.source_type }}</td><td class="small">{{ s.source_key }}</td><td>{{ s.last_scan_seq }}</td><td><span class="badge" :class="s.stale ? 'badge-neutral' : (s.last_complete ? 'badge-ok' : 'badge-warning')">{{ s.stale ? 'устарел' : (s.last_complete ? 'полный' : 'частичный') }}</span></td><td>{{ formatTime(s.last_collected_at) }}</td></tr></tbody>
        </table>
      </div>

      <div class="two-column panels-row">
        <div class="panel">
          <h3>Последние отчёты</h3>
          <div v-if="!data.reports.length" class="muted">Отчётов ещё нет.</div>
          <div v-for="r in data.reports" :key="r.report_id" class="list-row"><span><code class="small">{{ r.report_id.slice(0, 12) }}…</code><br /><span class="muted small">{{ formatTime(r.collected_at) }}</span></span><span><span class="badge" :class="r.status === 'complete' ? 'badge-ok' : 'badge-warning'">{{ stateLabel(r.status) }}</span><span class="small muted"> seq {{ r.scan_seq }} · {{ r.applied ? 'применён' : 'не применён' }}</span></span></div>
        </div>
        <div class="panel">
          <h3>Задания</h3>
          <div v-if="!data.jobs.length" class="muted">Заданий нет.</div>
          <div v-for="j in data.jobs" :key="j.job_id" class="list-row"><span><code class="small">{{ j.job_id.slice(0, 12) }}…</code><br /><span class="muted small">{{ formatTime(j.created_at) }}</span></span><span><span class="badge" :class="j.state === 'completed' ? 'badge-ok' : 'badge-warning'">{{ stateLabel(j.state) }}</span><span class="small muted"> {{ j.report_id ? 'отчёт ' + j.report_id.slice(0, 8) : '' }}</span></span></div>
        </div>
      </div>

      <div class="panel">
        <h3>События машины</h3>
        <div v-if="!data.events.length" class="muted">Событий нет.</div>
        <div v-for="e in data.events" :key="e.event_id" class="event-row"><div><span class="badge" :class="e.severity === 'error' ? 'badge-error' : (e.severity === 'warning' ? 'badge-warning' : 'badge-neutral')">{{ e.severity }}</span> <strong>{{ e.kind }}</strong><div>{{ e.message }}</div><details v-if="e.details_json"><summary class="small muted">Детали</summary><pre class="details-json">{{ e.details_json }}</pre></details></div><span class="muted small">{{ formatTime(e.created_at) }}</span></div>
      </div>
    </template>
    <MachineRenameDialog v-if="renameOpen && data" :machine="data.machine" @saved="machineRenamed" @close="renameOpen = false" />
  </section>
</template>
