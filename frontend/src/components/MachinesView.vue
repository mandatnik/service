<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { api } from '../api'
import { emptyMachineFilters, normalizeMachineFilters, monitoringLabels } from '../machineFilters'
import { badgeClass, formatTime, machineRowView, pluralRu } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
import RefreshControl from './RefreshControl.vue'
import InstallationReview from './InstallationReview.vue'
import MachineRenameDialog from './MachineRenameDialog.vue'

const props = defineProps({ filters: { type: Object, default: () => ({}) } })
const emit = defineEmits(['open-machine', 'open-group', 'filters-change'])
const columnFilters = reactive(normalizeMachineFilters(props.filters))
const selected = ref([]), catalog = ref({ groups: [] }), targetGroup = ref(''), newGroup = ref(''), adding = ref(false), message = ref('')
const groupNotice = ref(null)
const pollSeconds = ref(60)
const scanBusy = ref(false)
const pollText = computed(() => `Опрос агента — раз в ${pollSeconds.value} ${pluralRu(pollSeconds.value, ['секунду', 'секунды', 'секунд'])}`)
const pendingInstallations = ref([])
const reviewing = ref(null)
const renameTarget = ref(null)
const actionMenu = ref(null)
const selectableRows = computed(() => data.value.items.filter(m => !m.archived))
const allSelected = computed(() => selectableRows.value.length > 0 && selectableRows.value.every(m => selected.value.includes(m.machine_id)))
const rows = computed(() => data.value.items.map(machine => ({ machine, view: machineRowView(machine) })))
function selectPage(checked) {
  const ids = selectableRows.value.map(m => m.machine_id)
  selected.value = checked ? [...new Set([...selected.value, ...ids])] : selected.value.filter(id => !ids.includes(id))
}
async function addToGroup() {
  adding.value = true; error.value = ''; message.value = ''; groupNotice.value = null
  const count = selected.value.length
  const target = targetGroup.value
  try {
    let groupID = target
    let groupName = catalog.value.groups.find(group => group.id === target)?.name || ''
    if (target === 'new') {
      const created = await api.saveGroup({ name: newGroup.value, machine_ids: selected.value })
      groupID = created.id
      groupName = newGroup.value.trim()
    } else {
      await api.addGroupMembers(target, selected.value)
    }
    selected.value = []; newGroup.value = ''; targetGroup.value = ''
    await load()
    if (target === 'new') groupName = catalog.value.groups.find(group => group.id === groupID)?.name || groupName
    groupNotice.value = { title: 'Успешно!', text: `В группу «${groupName}» добавлено ${count} АРМ` }
  } catch (e) { error.value = e.message } finally { adding.value = false }
}
async function startScan() {
  scanBusy.value = true; error.value = ''; message.value = ''; groupNotice.value = null
  try {
    const task = await api.createTask({ kind: 'scan', machine_ids: selected.value, group_ids: [], idempotency_key: crypto.randomUUID() })
    message.value = `Задача scan создана: ${task.task.id}.`
  } catch (e) { error.value = e.message } finally { scanBusy.value = false }
}
const query = ref(columnFilters.query)
const status = ref(columnFilters.status)
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true
  error.value = ''
  try {
    const results = await Promise.all([api.machines({ ...columnFilters, query: query.value, status: status.value, page: page.value, page_size: 25 }), api.inventorySettings(), api.installations({ status: 'pending' })]); data.value = results[0]; catalog.value = results[1]; pendingInstallations.value = results[2]?.items || []
  } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { emit('filters-change', { ...columnFilters, query: query.value, status: status.value }) }
function clearFilters() { emit('filters-change', emptyMachineFilters()) }
function clearMonitor() { emit('filters-change', { ...columnFilters, query: query.value, status: status.value, monitor: '', as_of: '' }) }
watch(() => props.filters, value => {
 Object.assign(columnFilters, normalizeMachineFilters(value)); query.value = columnFilters.query; status.value = columnFilters.status
 page.value = 1; selected.value = []; load()
}, { deep: true })
function changePage(next) { page.value = next; load() }
function reviewInstallation(request) { reviewing.value = request; message.value = '' }
function toggleRowActions(machine, event) {
  event.stopPropagation()
  if (actionMenu.value?.machine.machine_id === machine.machine_id) {
    actionMenu.value = null
    return
  }
  const rect = event.currentTarget.getBoundingClientRect()
  actionMenu.value = {
    machine,
    top: Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - 120)),
    left: Math.max(8, Math.min(rect.right - 200, window.innerWidth - 208))
  }
}
function closeRowActions() { actionMenu.value = null }
function startRename(machine) { actionMenu.value = null; renameTarget.value = machine; message.value = ''; groupNotice.value = null }
function openFromMenu(machine) { actionMenu.value = null; emit('open-machine', machine.machine_id) }
async function machineRenamed(result) { renameTarget.value = null; message.value = `Имя АРМ изменено: «${result.display_name}». Hostname и machine_id не изменялись.`; await load() }
async function installationResolved(payload) {
  const action = payload?.action
  reviewing.value = null
  message.value = action === 'replace'
    ? `Установка заменена. Машина ${payload.result.machine_id} сохранила карточку и историю.`
    : action === 'separate'
      ? `Создана отдельная машина ${payload.result.machine_id} с тем же именем.`
      : 'Заявка на установку отклонена.'
  await load()
}
async function loadPollInterval() {
  try {
    const result = await api.config()
    const value = Number(result?.config?.poll_interval_seconds)
    if (Number.isFinite(value) && value > 0) pollSeconds.value = value
  } catch {}
}
onMounted(() => {
  load(); loadPollInterval()
  document.addEventListener('click', closeRowActions)
  window.addEventListener('resize', closeRowActions)
})
onUnmounted(() => {
  document.removeEventListener('click', closeRowActions)
  window.removeEventListener('resize', closeRowActions)
})
useAutoRefresh(load, () => loading.value || adding.value || scanBusy.value || !!reviewing.value || !!renameTarget.value || !!actionMenu.value)
</script>
<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Рабочие станции (РС): агенты, лицензии, сертификаты и состояние.</p></div>
      <div class="heading-actions"><button class="btn" @click="load">Обновить</button><RefreshControl /></div>
    </div>
    <div class="toolbar">
      <form class="search-form" @submit.prevent="apply">
        <input aria-label="Поиск АРМ" v-model="query" placeholder="Имя АРМ, hostname или UUID" />
        <select aria-label="Фильтр по состоянию" v-model="status" @change="apply">
          <option value="">Все</option>
          <option value="active">Текущие</option>
          <option value="offline">Нет связи</option>
          <option value="conflict">Конфликт hostname</option>
          <option value="archived">Архивные</option>
        </select>
        <button class="btn">Найти</button>
      </form>
      <span class="muted">{{ pollText }}</span>
    </div>
    <div v-if="columnFilters.monitor" class="alert alert-info monitoring-filter" role="status"><div><strong>{{ monitoringLabels[columnFilters.monitor] }}</strong><div class="small">Показаны только АРМ из выбранного показателя. Фильтры столбцов дополнительно сужают список.</div></div><button class="btn btn-small" @click="clearMonitor">Снять фильтр мониторинга</button></div>
    <div class="machine-filter-summary"><span class="small muted">Найдено АРМ: {{ data.total }}</span><button class="btn btn-small btn-quiet" @click="clearFilters">Сбросить фильтры</button></div>
    <form v-if="selected.length" class="panel selection-toolbar" @submit.prevent="addToGroup"><strong>Выбрано: {{ selected.length }}</strong><select v-model="targetGroup" aria-label="Группа для выбранных машин" required><option disabled value="">Добавить в группу…</option><option v-for="group in catalog.groups" :key="group.id" :value="group.id">{{ group.name }}</option><option value="new">+ Создать группу</option></select><input v-if="targetGroup === 'new'" v-model="newGroup" required maxlength="200" placeholder="Название новой группы" aria-label="Название новой группы" /><button class="btn btn-primary" :disabled="adding || !targetGroup">Добавить</button><button class="btn" type="button" :disabled="scanBusy" @click="startScan">Запросить информацию</button><button class="btn" type="button" :disabled="adding" @click="selected = []">Снять выбор</button></form>
    <div v-if="groupNotice" class="alert alert-success" role="status"><strong>{{ groupNotice.title }}</strong><div>{{ groupNotice.text }}</div></div>
    <div v-if="message" class="alert alert-success" role="status">{{ message }}</div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-if="pendingInstallations.length && !reviewing" class="panel installation-queue">
      <div class="panel-heading">
        <div><h3>Ожидают подтверждения <span class="badge badge-warning">{{ pendingInstallations.length }}</span></h3><p class="muted">Новые установки с именем существующей машины. Автоматического объединения нет.</p></div>
      </div>
      <div v-for="request in pendingInstallations" :key="request.request_id" class="installation-request">
        <div>
          <strong>{{ request.hostname }}</strong>
          <code class="small muted">{{ request.uuid }}</code>
          <div class="small muted">Ключ {{ request.key_fingerprint.slice(0, 20) }}… · {{ request.source_ip || 'IP неизвестен' }} · {{ formatTime(request.last_seen_at) }}</div>
          <div class="small">
            Связанные карточки:
            <template v-if="request.candidates.length">
              <span v-for="candidate in request.candidates" :key="candidate.machine_id" class="badge badge-neutral">{{ candidate.display_name }}</span>
            </template>
            <span v-else class="muted">нет</span>
          </div>
        </div>
        <button type="button" class="btn" @click="reviewInstallation(request)">Рассмотреть</button>
      </div>
    </div>
    <InstallationReview v-if="reviewing" :request="reviewing" @resolved="installationResolved" @cancel="reviewing = null" />
    <MachineRenameDialog v-if="renameTarget" :machine="renameTarget" @saved="machineRenamed" @close="renameTarget = null" />
    <Teleport to="body">
      <div v-if="actionMenu" class="row-actions-menu" role="menu" :style="{ top: actionMenu.top + 'px', left: actionMenu.left + 'px' }" @click.stop>
        <button type="button" role="menuitem" @click="startRename(actionMenu.machine)">Переименовать АРМ</button>
        <button type="button" role="menuitem" @click="openFromMenu(actionMenu.machine)">Открыть карточку</button>
      </div>
    </Teleport>
    <div v-if="!reviewing" class="panel table-panel">
      <div v-if="loading && !data.items.length" class="state">Загрузка…</div>
      <table v-else class="data-table machines-table">
        <thead>
          <tr>
            <th class="selection-cell"><input type="checkbox" :checked="allSelected" :indeterminate="!allSelected && data.items.some(m => selected.includes(m.machine_id))" aria-label="Выбрать все машины на странице" @change="selectPage($event.target.checked)" /></th>
            <th>Название АРМ</th>
            <th>Хост</th>
            <th>Онлайн</th>
            <th>CSP</th>
            <th>Группы</th>
            <th>Лицензия</th>
            <th>Сертификаты</th>
            <th>Статус</th>
            <th class="actions-cell"><span class="sr-only">Действия</span></th>
          </tr>
          <tr class="column-filters">
            <th></th>
            <th><input v-model="columnFilters.name" aria-label="Фильтр по названию АРМ" placeholder="Название" maxlength="512" @change="apply" @keydown.enter.prevent="apply" /></th>
            <th><input v-model="columnFilters.hostname" aria-label="Фильтр по hostname" placeholder="Hostname" maxlength="512" @change="apply" @keydown.enter.prevent="apply" /><input v-model="columnFilters.source_ip" aria-label="Фильтр по IP" placeholder="Точный IP" @change="apply" @keydown.enter.prevent="apply" /></th>
            <th><select v-model="columnFilters.connection" aria-label="Фильтр по связи" @change="apply"><option value="">Любая связь</option><option value="online">В сети</option><option value="offline">Не в сети</option></select></th>
            <th><select v-model="columnFilters.csp" aria-label="Фильтр по CSP" @change="apply"><option value="">Любой CSP</option><option value="present">Установлен</option><option value="missing">Не найден</option></select></th>
            <th><select v-model="columnFilters.group_id" aria-label="Фильтр по группе" @change="apply"><option value="">Все группы</option><option v-for="group in catalog.groups" :key="group.id" :value="group.id">{{ group.name }}</option></select></th>
            <th><select v-model="columnFilters.license" aria-label="Фильтр по лицензии" @change="apply"><option value="">Любая лицензия</option><option value="active">Активная</option><option value="needs">Требуется лицензия</option><option value="trial">Пробная</option><option value="expired">Истекла</option><option value="perpetual">Бессрочная</option><option value="unknown">Не определена</option></select></th>
            <th><select v-model="columnFilters.certificate" aria-label="Фильтр по сертификатам" @change="apply"><option value="">Все сертификаты</option><option value="present">Есть</option><option value="missing">Нет</option><option value="expired_recent">Истекли без замены</option></select></th>
            <th><select v-model="columnFilters.machine_status" aria-label="Фильтр по статусу АРМ" @change="apply"><option value="">Все статусы</option><option value="ok">Работает</option><option value="trial">Пробная версия</option><option value="license_required">Требуется лицензия</option><option value="csp_missing">CSP не установлен</option></select></th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!data.items.length"><td colspan="10"><EmptyState title="АРМ не найдены" text="Измените фильтры столбцов или сбросьте их." /></td></tr>
          <tr v-for="row in rows" :key="row.machine.machine_id" class="clickable" tabindex="0" @keydown.enter.self="emit('open-machine', row.machine.machine_id)" @click="emit('open-machine', row.machine.machine_id)">
            <td class="selection-cell" @click.stop><input v-model="selected" type="checkbox" :value="row.machine.machine_id" :disabled="row.machine.archived" :aria-label="`Выбрать ${row.view.name}`" /></td>
            <td>
              <strong>{{ row.view.name }}</strong>
              <span v-if="row.machine.archived" class="badge badge-neutral archive-badge" :title="row.machine.archive_reason">Архивирована</span>
              <span v-else-if="row.machine.registration_state !== 'active'" class="badge badge-neutral archive-badge">Историческая запись</span>
              <div v-if="row.machine.archived" class="small muted">Причина: {{ row.machine.archive_reason || 'не указана' }} · {{ formatTime(row.machine.archived_at) }}</div>
              <code class="small muted machine-uuid">{{ row.view.uuid }}</code>
            </td>
            <td>
              <div>{{ row.view.hostname }} <span v-if="row.machine.hostname_conflict" class="badge badge-warning">конфликт</span></div>
              <div class="small muted">{{ row.view.ip }}</div>
            </td>
            <td>
              <span class="badge" :class="badgeClass(row.view.online.tone)">{{ row.view.online.label }}</span>
              <div class="small muted">{{ row.view.online.subtext }}</div>
            </td>
            <td>
              <span v-if="!row.machine.csp_present" class="badge badge-error">Не найден</span>
              <strong v-else>{{ row.view.csp.label }}</strong>
              <div class="small" :class="row.view.csp.server ? 'csp-server-note' : 'muted'">{{ row.view.csp.subtext }}</div>
            </td>
            <td>
              <div class="machine-groups">
                <button v-for="group in row.view.groups.visible" :key="group.id" type="button" class="badge badge-neutral group-badge" :title="group.name" :aria-label="`Открыть группу ${group.name}`" @click.stop="emit('open-group', group.id)">{{ group.name }}</button>
                <span v-if="row.view.groups.overflow" class="badge badge-neutral group-overflow" :title="row.view.groups.tooltip">+{{ row.view.groups.overflow }}</span>
                <span v-if="!row.view.groups.visible.length" class="small muted">—</span>
              </div>
            </td>
            <td>
              <span class="badge" :class="badgeClass(row.view.license.tone)">{{ row.view.license.label }}</span>
              <div v-if="row.view.license.lines.length" class="small muted license-terms">
                <div v-for="(line, index) in row.view.license.lines" :key="index">{{ line }}</div>
              </div>
            </td>
            <td>
              <div>{{ row.view.certificates.primary }}</div>
              <div class="small muted">{{ row.view.certificates.secondary }}</div>
            </td>
            <td><span class="badge" :class="badgeClass(row.view.status.tone)">{{ row.view.status.label }}</span></td>
            <td class="actions-cell" @click.stop>
              <button type="button" class="row-actions-trigger" :aria-expanded="actionMenu?.machine.machine_id === row.machine.machine_id" aria-haspopup="menu" :aria-label="`Действия с АРМ ${row.view.name}`" @click="toggleRowActions(row.machine, $event)">…</button>
            </td>
          </tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>

  </section>
</template>
