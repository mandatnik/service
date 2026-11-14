<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel, stateLabel, timeAgo } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'
const emit = defineEmits(['open-machine'])
const selected = ref([]), catalog = ref({ groups: [] }), targetGroup = ref(''), newGroup = ref(''), adding = ref(false), message = ref('')
const allSelected = computed(() => data.value.items.length > 0 && data.value.items.every(m => selected.value.includes(m.machine_id)))
function selectPage(checked) { const ids = data.value.items.map(m => m.machine_id); selected.value = checked ? [...new Set([...selected.value, ...ids])] : selected.value.filter(id => !ids.includes(id)) }
async function addToGroup() {
  adding.value = true; error.value = ''; message.value = ''
  try {
    if (targetGroup.value === 'new') await api.saveGroup({ name: newGroup.value, machine_ids: selected.value })
    else await api.addGroupMembers(targetGroup.value, selected.value)
    message.value = `Машины добавлены в группу: ${selected.value.length}.`; selected.value = []; newGroup.value = ''; targetGroup.value = ''; catalog.value = await api.inventorySettings()
  } catch (e) { error.value = e.message } finally { adding.value = false }
}
const groupsFor = id => catalog.value.groups.filter(g => g.machine_ids.includes(id))
const query = ref('')
const status = ref('')
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
      <div><p class="muted">Зарегистрированные агенты, профили, лицензии и полнота сбора.</p></div>
      <button class="btn" @click="load">Обновить</button>
    </div>
    <div class="toolbar">
      <form class="search-form" @submit.prevent="apply">
        <input aria-label="Поиск машин" v-model="query" placeholder="Имя, hostname или UUID" />
        <select aria-label="Фильтр по состоянию" v-model="status" @change="apply">
          <option value="">Все состояния</option>
          <option value="active">Доступные</option>
          <option value="offline">Нет связи</option>
          <option value="conflict">Конфликт hostname</option>
        </select>
        <button class="btn">Найти</button>
      </form>
      <span class="muted">Опрос агента — каждые 10 минут</span>
    </div>
    <form v-if="selected.length" class="panel selection-toolbar" @submit.prevent="addToGroup"><strong>Выбрано: {{ selected.length }}</strong><select v-model="targetGroup" aria-label="Группа для выбранных машин" required><option disabled value="">Добавить в группу…</option><option v-for="group in catalog.groups" :key="group.id" :value="group.id">{{ group.name }}</option><option value="new">+ Создать группу</option></select><input v-if="targetGroup === 'new'" v-model="newGroup" required maxlength="200" placeholder="Название новой группы" aria-label="Название новой группы" /><button class="btn btn-primary" :disabled="adding || !targetGroup">Добавить</button><button class="btn" type="button" :disabled="adding" @click="selected = []">Снять выбор</button></form>
    <div v-if="message" class="alert alert-success">{{ message }}</div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.items.length" title="Машины не найдены" text="Проверьте фильтры или зарегистрируйте агент." />
      <table v-else class="data-table">
        <thead><tr><th class="selection-cell"><input type="checkbox" :checked="allSelected" :indeterminate="!allSelected && data.items.some(m => selected.includes(m.machine_id))" aria-label="Выбрать все машины на странице" @change="selectPage($event.target.checked)" /></th><th>Машина</th><th>Hostname / UUID</th><th>Связь</th><th>CSP</th><th>Лицензия</th><th>Сбор</th><th>Данные</th></tr></thead>
        <tbody>
          <tr v-for="m in data.items" :key="m.machine_id" class="clickable" tabindex="0" @keydown.enter.self="emit('open-machine', m.machine_id)" @click="emit('open-machine', m.machine_id)">
            <td class="selection-cell" @click.stop><input v-model="selected" type="checkbox" :value="m.machine_id" :aria-label="`Выбрать ${m.display_name}`" /></td>
            <td><strong>{{ m.display_name }}</strong><div class="machine-groups"><span v-for="group in groupsFor(m.machine_id)" :key="group.id" class="badge badge-neutral">{{ group.name }}</span></div><div v-if="m.hostname_conflict" class="badge badge-warning">hostname конфликт</div></td>
            <td><div>{{ m.hostname || '—' }}</div><code class="small">{{ m.uuid || 'нет регистрации' }}</code></td>
            <td><span class="badge" :class="m.offline ? 'badge-error' : 'badge-ok'">{{ m.offline ? 'Нет связи' : 'На связи' }}</span><div class="small muted">{{ m.last_seen_at ? timeAgo(m.last_seen_at) : 'нет связи' }}<br />{{ m.source_ip }}</div></td>
            <td><div>Версия <code>{{ m.product_version || '—' }}</code></div><div class="small muted">Ядро <code>{{ m.core_version || '—' }}</code></div></td>
            <td><span class="badge badge-license">{{ licenseKindLabel(m.license_kind, m.license_kind_raw) }}</span><div class="small muted">{{ stateLabel(m.license_state) }}</div></td>
            <td><span class="badge" :class="m.last_report_status === 'complete' ? 'badge-ok' : (m.last_report_status ? 'badge-warning' : 'badge-neutral')">{{ stateLabel(m.last_report_status) }}</span><div class="small muted">{{ formatTime(m.last_report_at) }}</div></td>
            <td><div>{{ m.users }} польз. · {{ m.active_certificates }} серт.</div><div class="small muted">источников: {{ m.applied_sources }}</div></td>
          </tr>
        </tbody>
      </table>
      <Pager :page="data.page" :page-size="data.page_size" :total="data.total" @change="changePage" />
    </div>
  </section>
</template>
