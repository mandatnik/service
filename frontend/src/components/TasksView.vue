<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'

const kind = ref('')
const state = ref('')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const detail = ref(null)
const events = ref([])
const eventsFor = ref('')
const error = ref('')
const message = ref('')
const loading = ref(false)
const busy = ref(false)
const scanMachines = ref([])
const machineCatalog = ref([])
const scanBusy = ref(false)
const activationVisible = ref(false)

const taskState = value => ({
  queued: 'Ожидает', running: 'Выполняется', requires_attention: 'Нужно внимание',
  completed: 'Завершена', cancelled: 'Отменена', expired: 'Истекла',
  partially_failed: 'Частичный результат', failed: 'Ошибка'
})[value] || value || '—'
const itemState = value => ({
  queued: 'Ожидает', delivered: 'Доставлено', running: 'Выполняется', retry_wait: 'Повтор',
  succeeded: 'Успех', skipped: 'Пропущено', failed: 'Ошибка', outcome_unknown: 'Результат неизвестен',
  cancelled: 'Отменено', expired: 'Истекло'
})[value] || value || '—'
const kindLabel = value => value === 'install_license' ? 'Установка лицензии' : value === 'scan' ? 'Сбор (scan)' : value
const reasonLabel = value => ({
  preview_stale: 'Снимок устарел — повторите предпросмотр',
  license_deficit: 'Недостаточно свободных ключей',
  machine_not_eligible: 'Машина не подходит для установки',
  license_state_unknown: 'Состояние лицензии неизвестно',
  trial_replacement_not_confirmed: 'Замена триала не подтверждена',
  already_licensed: 'Действует приобретённая лицензия',
  report_evicted: 'Отчёт вытеснен до приёма',
  journal_corrupted: 'Локальный журнал повреждён — только согласование',
  outcome_unknown: 'Результат неизвестен, ключ удерживается',
  task_expired: 'Срок задачи истёк',
  write_failed: 'Ошибка записи',
  verification_failed: 'Проверка после записи не прошла',
  restore_verified: 'Исходное значение восстановлено',
  write_not_started: 'Запись не начиналась',
  external_change: 'Значение изменено извне',
  assignment_mismatch: 'Назначение не совпадает с журналом',
  parameters_invalid: 'Параметры задания недействительны',
  agent_update_required: 'Нужно обновить агента',
  report_required: 'Нет принятого отчёта scan',
  attempts_exhausted: 'Исчерпаны три попытки'
})[value] || value || '—'

async function loadCatalog() { try { const result = await api.inventorySettings(); machineCatalog.value = result.machines || [] } catch (e) { /* catalog is optional */ } }
function activationCreated(task) { message.value = `Задача активации создана: ${task.task.id}.`; scanMachines.value = []; activationVisible.value = false; load() }
async function createScanTask() {
  if (!scanMachines.value.length) { error.value = 'Выберите хотя бы одну машину для scan.'; return }
  scanBusy.value = true; error.value = ''
  try { const task = await api.createTask({ kind: 'scan', machine_ids: scanMachines.value, group_ids: [], idempotency_key: crypto.randomUUID() }); message.value = `Задача scan создана: ${task.task.id}.`; scanMachines.value = []; await load() } catch (e) { error.value = e.message } finally { scanBusy.value = false }
}

async function load() {
  loading.value = true; error.value = ''
  try { data.value = await api.tasks({ kind: kind.value, state: state.value, page: page.value, page_size: 25 }) } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
function changePage(next) { page.value = next; load() }

async function openTask(id) {
  busy.value = true; error.value = ''; events.value = []; eventsFor.value = ''
  try { detail.value = await api.task(id) } catch (e) { error.value = e.message } finally { busy.value = false }
}
async function refreshDetail() { if (detail.value) await openTask(detail.value.task.id) }
async function showEvents(item) {
  busy.value = true; error.value = ''
  try { const result = await api.taskEvents(item.id); events.value = result.items || []; eventsFor.value = item.id } catch (e) { error.value = e.message } finally { busy.value = false }
}
async function cancelTask() {
  if (!detail.value || !confirm('Запросить отмену задачи? Уже начатая запись реестра не откатывается мгновенно.')) return
  busy.value = true; error.value = ''
  try { detail.value = await api.cancelTask(detail.value.task.id); message.value = 'Запрошена отмена задачи.'; await load() } catch (e) { error.value = e.message } finally { busy.value = false }
}
async function cancelItem(item) {
  if (!confirm('Запросить отмену этой машины?')) return
  busy.value = true; error.value = ''
  try { detail.value = await api.cancelTaskItem(item.id); message.value = 'Запрошена отмена выполнения.'; await load() } catch (e) { error.value = e.message } finally { busy.value = false }
}
async function reconcile(item) {
  busy.value = true; error.value = ''
  try { detail.value = await api.reconcileTaskItem(item.id); message.value = 'Запрошена read-only сверка; запись не выполняется.'; await load() } catch (e) { error.value = e.message } finally { busy.value = false }
}

onMounted(() => { load(); loadCatalog() })
</script>

<template>
  <section>
    <div class="page-heading"><div><p class="muted">Единая задача содержит отдельные выполнения на машинах. Счётчики и состояния вычисляются по выполнениям.</p></div><button class="btn" :disabled="loading" @click="load">Обновить</button></div>
    <form class="panel settings-form" @submit.prevent="createScanTask"><h3>Новый scan</h3><p class="muted small">Запуск из раздела задач; выбор машин фиксируется в снимке получателей.</p><label class="field"><span>Машины</span><select v-model="scanMachines" multiple size="4" aria-label="Машины для scan"><option v-for="m in machineCatalog" :key="m.id" :value="m.id">{{ m.name }}</option></select></label><div class="heading-actions"><button class="btn btn-primary" :disabled="scanBusy || !scanMachines.length">Создать scan</button><button class="btn" type="button" :disabled="!scanMachines.length" @click="activationVisible = true">Активировать лицензию</button></div></form>
    <div class="toolbar"><form class="search-form" @submit.prevent="apply"><select v-model="kind" @change="apply"><option value="">Все виды</option><option value="scan">scan</option><option value="install_license">Установка лицензии</option></select><select v-model="state" @change="apply"><option value="">Все состояния</option><option value="queued">Ожидает</option><option value="running">Выполняется</option><option value="requires_attention">Нужно внимание</option><option value="completed">Завершена</option><option value="partially_failed">Частичный результат</option><option value="failed">Ошибка</option><option value="cancelled">Отменена</option><option value="expired">Истекла</option></select><button class="btn">Найти</button></form></div>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div v-if="message" class="alert alert-info">{{ message }}</div>
    <div class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Задач нет" text="Создайте scan или активацию из выбора машин." />
      <table v-else class="data-table">
        <thead><tr><th>Задача</th><th>Вид</th><th>Состояние</th><th>Прогресс</th><th>Автор</th><th>Срок</th></tr></thead>
        <tbody>
          <tr v-for="task in data.items" :key="task.id" class="clickable" @click="openTask(task.id)">
            <td><code class="small">{{ task.id }}</code><div v-if="task.legacy_job_id" class="small muted">legacy job {{ task.legacy_job_id }}</div></td>
            <td>{{ kindLabel(task.kind) }}</td>
            <td><span class="badge" :class="['completed'].includes(task.state) ? 'badge-ok' : ['requires_attention','partially_failed','failed'].includes(task.state) ? 'badge-error' : 'badge-neutral'">{{ taskState(task.state) }}</span><div v-if="task.unknown_items" class="small error-text">неизвестно: {{ task.unknown_items }}</div></td>
            <td class="small">{{ task.counts.finished }} / {{ task.counts.total }}<div class="muted">успех {{ task.counts.succeeded }}, пропуск {{ task.counts.skipped }}, ошибка {{ task.counts.failed }}, ожидание {{ task.counts.queued + task.counts.delivered }}</div></td>
            <td>{{ task.created_by || '—' }}</td>
            <td class="small">{{ formatTime(task.expires_at) }}</td>
          </tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>

    <div v-if="detail" class="panel table-panel">
      <div class="heading-actions"><h3>Детали задачи</h3><div class="heading-actions"><button class="btn" @click="refreshDetail">Обновить</button><button class="btn btn-danger" :disabled="busy || detail.task.cancel_requested_at" @click="cancelTask">Отменить задачу</button><button class="btn" @click="detail = null; events = []">Закрыть</button></div></div>
      <div class="settings-meta"><span>ID: <code>{{ detail.task.id }}</code></span><span>Состояние: <strong>{{ taskState(detail.task.state) }}</strong></span><span>Истекает: {{ formatTime(detail.task.expires_at) }}</span></div>
      <table class="data-table">
        <thead><tr><th>Машина</th><th>Состояние</th><th>Причина</th><th>Попытки</th><th>Лицензия</th><th>Скан</th><th></th></tr></thead>
        <tbody>
          <tr v-for="item in detail.items" :key="item.id">
            <td><strong>{{ item.machine_name }}</strong><div class="small muted">{{ item.hostname }}</div><code class="small">{{ item.id }}</code></td>
            <td><span class="badge" :class="item.state === 'succeeded' ? 'badge-ok' : ['failed','outcome_unknown'].includes(item.state) ? 'badge-error' : 'badge-neutral'">{{ itemState(item.state) }}</span></td>
            <td class="small">{{ reasonLabel(item.reason_code) }}<div v-if="item.cancel_requested" class="muted">запрошена отмена</div><div v-if="item.reconcile_requested" class="muted">запрошена сверка</div></td>
            <td>{{ item.attempt_count }} / 3<div v-if="item.next_attempt_at" class="small muted">{{ formatTime(item.next_attempt_at) }}</div></td>
            <td><code v-if="item.license_mask">{{ item.license_mask }}</code><div v-if="item.license_id" class="small muted">{{ item.license_id }}</div><span v-else>—</span></td>
            <td><code v-if="item.scan_report_id" class="small">{{ item.scan_report_id }}</code><span v-else>—</span></td>
            <td><div class="heading-actions"><button class="btn" type="button" :disabled="busy" @click="showEvents(item)">Журнал</button><button v-if="!['succeeded','skipped','cancelled','expired'].includes(item.state)" class="btn" type="button" :disabled="busy" @click="cancelItem(item)">Отменить</button><button v-if="['outcome_unknown','failed'].includes(item.state)" class="btn" type="button" :disabled="busy" @click="reconcile(item)">Сверить</button></div></td>
          </tr>
        </tbody>
      </table>
      <div v-if="eventsFor" class="panel settings-form">
        <h3>Журнал выполнения <code class="small">{{ eventsFor }}</code></h3>
        <div v-if="!events.length" class="state">Событий пока нет.</div>
        <div v-for="event in events" :key="event.sequence" class="event-row"><span class="small muted">#{{ event.sequence }} · {{ formatTime(event.created_at) }} · попытка {{ event.attempt_no }}</span><strong>{{ event.event_type }}</strong><pre v-if="event.details" class="details-json">{{ JSON.stringify(event.details, null, 2) }}</pre></div>
      </div>
    </div>
    <ActivationModal :visible="activationVisible" :machine-ids="scanMachines" :group-ids="[]" @close="activationVisible = false" @created="activationCreated" />
  </section>
</template>
