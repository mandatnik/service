<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { badgeClass, machineRowView } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
import ActivationModal from './ActivationModal.vue'

const emit = defineEmits(['open-machine', 'open-group'])
const selected = ref([]), catalog = ref({ groups: [] }), targetGroup = ref(''), newGroup = ref(''), adding = ref(false), message = ref('')
const activationVisible = ref(false), scanBusy = ref(false)
const allSelected = computed(() => data.value.items.length > 0 && data.value.items.every(m => selected.value.includes(m.machine_id)))
const rows = computed(() => data.value.items.map(machine => ({ machine, view: machineRowView(machine) })))
function selectPage(checked) {
  const ids = data.value.items.map(m => m.machine_id)
  selected.value = checked ? [...new Set([...selected.value, ...ids])] : selected.value.filter(id => !ids.includes(id))
}
async function addToGroup() {
  adding.value = true; error.value = ''; message.value = ''
  try {
    if (targetGroup.value === 'new') await api.saveGroup({ name: newGroup.value, machine_ids: selected.value })
    else await api.addGroupMembers(targetGroup.value, selected.value)
    message.value = `Машины добавлены в группу: ${selected.value.length}.`; selected.value = []; newGroup.value = ''; targetGroup.value = ''; catalog.value = await api.inventorySettings()
  } catch (e) { error.value = e.message } finally { adding.value = false }
}
function activationCreated(task) { message.value = `Задача активации создана: ${task.task.id}.`; selected.value = []; load() }
async function startScan() {
  scanBusy.value = true; error.value = ''; message.value = ''
  try {
    const task = await api.createTask({ kind: 'scan', machine_ids: selected.value, group_ids: [], idempotency_key: crypto.randomUUID() })
    message.value = `Задача scan создана: ${task.task.id}.`
  } catch (e) { error.value = e.message } finally { scanBusy.value = false }
}
const query = ref('')
const status = ref('active')
const page = ref(1)
const data = ref({ items: [], total: 0, page: 1, page_size: 25 })
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true
  error.value = ''
  try {
    const results = await Promise.all([api.machines({ query: query.value, status: status.value, page: page.value, page_size: 25 }), api.inventorySettings()]); data.value = results[0]; catalog.value = results[1]
  } catch (e) { error.value = e.message } finally { loading.value = false }
}
function apply() { page.value = 1; load() }
function changePage(next) { page.value = next; load() }
onMounted(load)
</script>
<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Рабочие станции (РС): агенты, лицензии, сертификаты и состояние.</p></div>
      <button class="btn" @click="load">Обновить</button>
    </div>
    <div class="toolbar">
      <form class="search-form" @submit.prevent="apply">
        <input aria-label="Поиск машин" v-model="query" placeholder="Имя АРМ, hostname или UUID" />
        <select aria-label="Фильтр по состоянию" v-model="status" @change="apply">
          <option value="">Все</option>
          <option value="active">Текущие</option>
          <option value="offline">Нет связи</option>
          <option value="conflict">Конфликт hostname</option>
        </select>
        <button class="btn">Найти</button>
      </form>
      <span class="muted">Опрос агента — настраивается сервером (по умолчанию 60 с)</span>
    </div>
    <form v-if="selected.length" class="panel selection-toolbar" @submit.prevent="addToGroup"><strong>Выбрано: {{ selected.length }}</strong><select v-model="targetGroup" aria-label="Группа для выбранных машин" required><option disabled value="">Добавить в группу…</option><option v-for="group in catalog.groups" :key="group.id" :value="group.id">{{ group.name }}</option><option value="new">+ Создать группу</option></select><input v-if="targetGroup === 'new'" v-model="newGroup" required maxlength="200" placeholder="Название новой группы" aria-label="Название новой группы" /><button class="btn btn-primary" :disabled="adding || !targetGroup">Добавить</button><button class="btn" type="button" :disabled="scanBusy" @click="startScan">Scan</button><button class="btn btn-primary" type="button" @click="activationVisible = true">Активировать лицензию</button><button class="btn" type="button" :disabled="adding" @click="selected = []">Снять выбор</button></form>
    <div v-if="message" class="alert alert-success">{{ message }}</div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Машины не найдены" text="Проверьте фильтры или зарегистрируйте агент." />
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
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.machine.machine_id" class="clickable" tabindex="0" @keydown.enter.self="emit('open-machine', row.machine.machine_id)" @click="emit('open-machine', row.machine.machine_id)">
            <td class="selection-cell" @click.stop><input v-model="selected" type="checkbox" :value="row.machine.machine_id" :aria-label="`Выбрать ${row.view.name}`" /></td>
            <td>
              <strong>{{ row.view.name }}</strong>
              <span v-if="row.machine.registration_state !== 'active'" class="badge badge-neutral archive-badge">Архивная запись</span>
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
            <td :class="{ 'cell-danger': row.view.csp.tone === 'danger' }">
              <span v-if="!row.machine.csp_present" class="badge badge-error">Не найден</span>
              <strong v-else>{{ row.view.csp.label }}</strong>
              <div class="small muted">{{ row.view.csp.subtext }}</div>
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
          </tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
    <ActivationModal :visible="activationVisible" :machine-ids="selected" :group-ids="[]" @close="activationVisible = false" @created="activationCreated" />
  </section>
</template>
