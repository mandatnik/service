<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel } from '../format'
import EmptyState from './EmptyState.vue'
import Pager from './Pager.vue'

const pools = ref([])
const selectedId = ref('')
const licenses = ref({ items: [], total: 0, page: 1, page_size: 50 })
const history = ref([])
const error = ref('')
const message = ref('')
const busy = ref(false)
const importing = ref(false)
const importText = ref('')
const importResult = ref(null)
const blocking = ref('')
const blockReason = ref('')
const renaming = ref('')
const renameName = ref('')
const page = ref(1)
const poolForm = reactive({ name: '', csp_major_version: 5, license_kind: 'client', term: 'perpetual' })
const selected = computed(() => pools.value.find(p => p.id === selectedId.value) || null)
const termLabel = term => ({ one_year: '1 год', two_years: '2 года', perpetual: 'Бессрочно' })[term] || term
const licenseState = value => ({ available: 'Свободен', reserved: 'Зарезервирован', used: 'Использован', outcome_unknown: 'Результат неизвестен', blocked: 'Заблокирован' })[value] || value

async function load() {
  busy.value = true; error.value = ''
  try {
    const result = await api.licensePools()
    pools.value = result.items || []
    if (!selectedId.value && pools.value.length) selectedId.value = pools.value[0].id
    if (selectedId.value) await loadLicenses()
  } catch (e) { error.value = e.message } finally { busy.value = false }
}

let licenseRequest = 0
async function loadLicenses() {
  if (!selectedId.value) return
  const request = ++licenseRequest
  const id = selectedId.value
  try {
    const [result, events] = await Promise.all([
      api.poolLicenses(id, { page: page.value, page_size: 50 }),
      api.licenseHistory(id, { limit: 100 })
    ])
    if (request !== licenseRequest) return
    licenses.value = result
    history.value = events.items || []
  } catch (e) { if (request === licenseRequest) error.value = e.message }
}

async function selectPool(id) {
  if (importing.value) return
  selectedId.value = id; page.value = 1; importResult.value = null; message.value = ''; error.value = ''
  importText.value = ''; blocking.value = ''; blockReason.value = ''; renaming.value = ''
  licenses.value = { items: [], total: 0, page: 1, page_size: 50 }; history.value = []
  await loadLicenses()
}

async function createPool() {
  busy.value = true; error.value = ''; message.value = ''
  try {
    const pool = await api.createLicensePool({ ...poolForm, name: poolForm.name.trim() })
    poolForm.name = ''
    await load()
    selectedId.value = pool.id
    await loadLicenses()
    message.value = 'Пул создан.'
  } catch (e) { error.value = e.message } finally { busy.value = false }
}

function startRename(pool) { renaming.value = pool.id; renameName.value = pool.name }
async function renamePool(pool) {
  if (!renameName.value.trim()) { error.value = 'Название не может быть пустым.'; return }
  busy.value = true; error.value = ''
  try { await api.updateLicensePool(pool.id, { name: renameName.value.trim() }); renaming.value = ''; await load(); message.value = 'Пул переименован.' } catch (e) { error.value = e.message } finally { busy.value = false }
}

async function archive(pool, archived) {
  if (!confirm(archived ? `Архивировать пул «${pool.name}»? Новые задачи по нему будут недоступны.` : `Вернуть пул «${pool.name}» из архива?`)) return
  busy.value = true; error.value = ''
  try { await api.archiveLicensePool(pool.id, archived); await load(); message.value = archived ? 'Пул архивирован.' : 'Пул возвращён из архива.' } catch (e) { error.value = e.message } finally { busy.value = false }
}

async function importSerials() {
  const lines = importText.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean)
  if (!lines.length) { error.value = 'Вставьте хотя бы один номер.'; return }
  if (lines.length > 2000) { error.value = 'За один раз можно импортировать не более 2000 строк.'; return }
  importing.value = true; error.value = ''; message.value = ''; importResult.value = null
  try {
    const result = await api.importLicenses(selectedId.value, lines)
    importResult.value = result
    if (result.accepted) {
      importText.value = ''
      message.value = `Импортировано ключей: ${result.imported}.`
      await load()
    } else {
      message.value = 'Импорт отклонён целиком. Удалите ошибочные строки и подтвердите исправленный список.'
    }
  } catch (e) {
    error.value = e.message
    importResult.value = e.body || null
  } finally { importing.value = false }
}

async function block(item) {
  if (!blockReason.value.trim()) { error.value = 'Укажите причину блокировки.'; return }
  busy.value = true; error.value = ''
  try { await api.blockLicense(item.id, blockReason.value.trim()); blocking.value = ''; blockReason.value = ''; await load(); message.value = 'Ключ заблокирован.' } catch (e) { error.value = e.message } finally { busy.value = false }
}

function changePage(next) { page.value = next; loadLicenses() }
onMounted(load)
</script>

<template>
  <section>
    <div class="page-heading">
      <div><p class="muted">Пулы описывают заявленные свойства ключей. После добавления ключей версия, тип и срок пула не меняются.</p></div>
      <button class="btn" :disabled="busy || importing" @click="load">Обновить</button>
    </div>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div v-if="message" class="alert alert-info">{{ message }}</div>

    <form class="panel settings-form" @submit.prevent="createPool">
      <h3>Новый пул</h3>
      <div class="form-grid">
        <label class="field"><span>Название</span><input v-model="poolForm.name" maxlength="200" required placeholder="Например, CSP 5 · клиентские · бессрочные" /></label>
        <label class="field"><span>CSP</span><select v-model.number="poolForm.csp_major_version"><option :value="4">CSP 4</option><option :value="5">CSP 5</option></select></label>
        <label class="field"><span>Тип</span><select v-model="poolForm.license_kind"><option value="client">Клиентская</option><option value="server">Серверная</option></select></label>
        <label class="field"><span>Заявленный срок</span><select v-model="poolForm.term"><option value="one_year">1 год</option><option value="two_years">2 года</option><option value="perpetual">Бессрочно</option></select></label>
      </div>
      <div class="heading-actions"><button class="btn btn-primary" :disabled="busy || importing">Создать пул</button></div>
    </form>

    <div class="panel table-panel">
      <div v-if="busy && !pools.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!pools.length" title="Пулов пока нет" text="Создайте пул, затем добавьте номера лицензий." />
      <table v-else class="data-table">
        <thead><tr><th>Пул</th><th>CSP</th><th>Тип</th><th>Срок</th><th>Свободно</th><th>Состояния</th><th></th></tr></thead>
        <tbody>
          <tr v-for="p in pools" :key="p.id" class="clickable" tabindex="0" @keydown.enter.self="selectPool(p.id)" @click="selectPool(p.id)">
            <td><strong>{{ p.name }}</strong><div v-if="p.archived_at" class="badge badge-neutral">Архив</div></td>
            <td>{{ p.csp_major_version }}</td>
            <td>{{ licenseKindLabel(p.license_kind) }}</td>
            <td>{{ termLabel(p.term) }}</td>
            <td><span class="badge badge-ok">{{ p.counts.available }}</span></td>
            <td class="small">Всего {{ p.counts.total }} · резерв {{ p.counts.reserved }} · использовано {{ p.counts.used }}<span v-if="p.counts.outcome_unknown"> · неизвестно {{ p.counts.outcome_unknown }}</span><span v-if="p.counts.blocked"> · блок {{ p.counts.blocked }}</span></td>
            <td><div class="heading-actions"><button class="btn" type="button" :disabled="busy || importing" @click.stop="startRename(p)">Переименовать</button><button class="btn" type="button" :disabled="busy || importing" @click.stop="archive(p, !p.archived_at)">{{ p.archived_at ? 'Вернуть' : 'Архивировать' }}</button></div></td>
          </tr>
        </tbody>
      </table>
    </div>

    <form v-if="renaming && selected" class="panel settings-form" @submit.prevent="renamePool(pools.find(p => p.id === renaming))"><h3>Переименование пула</h3><label class="field"><span>Новое название</span><input v-model="renameName" maxlength="200" required /></label><div class="heading-actions"><button class="btn btn-primary" :disabled="busy || importing">Сохранить</button><button class="btn" type="button" @click="renaming = ''">Отмена</button></div></form>

    <template v-if="selected">
      <div class="panel settings-form">
        <h3>Импорт номеров в «{{ selected.name }}»</h3>
        <p class="muted small">По одному номеру на строку. Импорт атомарен: при любой ошибке не добавляется ни один номер. Полные номера не возвращаются сервером, в таблице видны только маски.</p>
        <textarea :disabled="importing" v-model="importText" rows="6" class="import-area" placeholder="00000-00000-00000-00000-00000&#10;…" aria-label="Номера лицензий для импорта"></textarea>
        <div class="heading-actions"><button class="btn btn-primary" type="button" :disabled="importing || selected.archived_at" @click="importSerials">{{ importing ? 'Проверка…' : 'Проверить и импортировать' }}</button></div>
        <div v-if="importResult?.lines?.length" class="import-results">
          <div v-for="line in importResult.lines" :key="line.line" class="small" :class="line.status === 'accepted' ? 'ok-text' : 'error-text'">
            Строка {{ line.line }}: {{ line.status === 'accepted' ? 'принята' : line.status === 'duplicate' ? 'дубликат' : 'неверный формат' }}<span v-if="line.mask"> · {{ line.mask }}</span>
          </div>
        </div>
      </div>

      <div class="panel table-panel">
        <h3>Ключи пула</h3>
        <div v-if="!licenses.items.length" class="state">Ключей пока нет.</div>
        <table v-else class="data-table">
          <thead><tr><th>Маска</th><th>Состояние</th><th>Машина</th><th>Задача</th><th>Резерв / использование</th><th>Причина</th><th></th></tr></thead>
          <tbody>
            <tr v-for="l in licenses.items" :key="l.id">
              <td><code>{{ l.mask }}</code><div class="small muted">{{ l.id }}</div></td>
              <td><span class="badge" :class="l.state === 'available' ? 'badge-ok' : l.state === 'blocked' ? 'badge-error' : 'badge-neutral'">{{ licenseState(l.state) }}</span></td>
              <td>{{ l.machine_name || '—' }}</td>
              <td><code class="small">{{ l.assigned_task_id || '—' }}</code></td>
              <td class="small">{{ formatTime(l.reserved_at) }}<div>{{ formatTime(l.used_at) }}</div></td>
              <td class="small error-text">{{ l.last_error_code || '' }}</td>
              <td><button v-if="l.state === 'available'" class="btn" type="button" @click="blocking = l.id">Заблокировать</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="blocking" class="panel settings-form">
          <h3>Блокировка ключа</h3>
          <label class="field"><span>Причина</span><input v-model="blockReason" maxlength="512" required /></label>
          <div class="heading-actions"><button class="btn btn-danger" type="button" :disabled="busy || importing" @click="block(licenses.items.find(i => i.id === blocking))">Заблокировать</button><button class="btn" type="button" @click="blocking = ''">Отмена</button></div>
        </div>
        <Pager v-if="licenses.total > licenses.page_size" :page="licenses.page" :page-size="licenses.page_size" :total="licenses.total" @change="changePage" />
      </div>

      <div class="panel table-panel">
        <h3>История закреплений и событий</h3>
        <p class="muted small">Журнал не удаляется при освобождении ключа; полные номера в нём отсутствуют.</p>
        <div v-if="!history.length" class="state">История пока пуста.</div>
        <table v-else class="data-table">
          <thead><tr><th>Время</th><th>Событие</th><th>Ключ</th><th>Машина</th><th>Причина</th></tr></thead>
          <tbody><tr v-for="h in history" :key="h.created_at + h.kind + h.license_id + h.task_item_id"><td class="small">{{ formatTime(h.created_at) }}</td><td>{{ h.kind }}</td><td><code v-if="h.mask">{{ h.mask }}</code><span v-else>—</span></td><td>{{ h.machine_name || h.machine_id || '—' }}</td><td class="small error-text">{{ h.reason || '' }}</td></tr></tbody>
        </table>
      </div>
    </template>
  </section>
</template>
