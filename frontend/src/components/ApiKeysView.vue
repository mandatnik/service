<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import EmptyState from './EmptyState.vue'
import ErrorState from './ErrorState.vue'

const keys = ref([])
const loading = ref(true)
const busy = ref(false)
const error = ref('')
const message = ref('')
const createdToken = ref('')
const form = reactive({ id: '', name: '', allowed: '' })

function resetForm() {
  form.id = ''
  form.name = ''
  form.allowed = ''
  createdToken.value = ''
}

function startEdit(key) {
  form.id = key.key_id
  form.name = key.name
  form.allowed = (key.allowed_ips || []).join('\n')
  createdToken.value = ''
  message.value = ''
  error.value = ''
}

function parseAllowed() {
  return form.allowed
    .split(/[\n,;]+/)
    .map((value) => value.trim())
    .filter(Boolean)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const result = await api.apiKeys()
    keys.value = result.items || []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function save() {
  error.value = ''
  message.value = ''
  createdToken.value = ''
  const allowed = parseAllowed()
  if (!form.name.trim()) {
    error.value = 'Укажите название ключа.'
    return
  }
  if (!form.id && allowed.length === 0) {
    error.value = 'Для нового ключа нужен хотя бы один IP или CIDR.'
    return
  }
  busy.value = true
  try {
    if (form.id) {
      await api.updateApiKey(form.id, { name: form.name.trim(), allowed_ips: allowed })
      message.value = allowed.length
        ? 'Ключ обновлён.'
        : 'Ключ обновлён, список IP пуст — ключ отключён до добавления IP.'
      resetForm()
    } else {
      const result = await api.createApiKey(form.name.trim(), allowed)
      createdToken.value = result.token
      message.value = 'Ключ создан. Скопируйте токен сейчас: он больше не будет показан.'
      form.name = ''
      form.allowed = ''
    }
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function revoke(key) {
  if (!window.confirm(`Отозвать ключ «${key.name}»? После отзыва запросы с ним будут получать 401.`)) return
  error.value = ''
  message.value = ''
  try {
    await api.revokeApiKey(key.key_id)
    message.value = `Ключ «${key.name}» отозван.`
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function copyToken() {
  if (!createdToken.value) return
  try {
    await navigator.clipboard.writeText(createdToken.value)
    message.value = 'Токен скопирован в буфер обмена.'
  } catch {
    message.value = 'Не удалось скопировать автоматически; выделите токен вручную.'
  }
}

onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>

<template>
  <section>
    <div class="page-heading">
      <div>
        <p class="muted">
          Ключи для интеграционного REST API на порту 8446. Каждый ключ имеет полный доступ
          ко всем ручкам и ограничивается только списком IP/CIDR. Токен показывается один раз.
        </p>
      </div>
      <button class="btn" @click="load">Обновить</button>
    </div>

    <ErrorState v-if="error && !keys.length" :message="error" @retry="load" />
    <div v-else class="panel">
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="createdToken" class="alert alert-info">
        <strong>Новый API-ключ:</strong>
        <div class="token-reveal"><code>{{ createdToken }}</code><button class="btn btn-small" @click="copyToken">Копировать</button></div>
        <div class="small muted">Сохраните токен в защищённом месте. В базе хранится только его SHA-256.</div>
      </div>

      <form class="settings-form" @submit.prevent="save">
        <div class="form-grid">
          <label class="field">
            <span>{{ form.id ? 'Название ключа' : 'Название нового ключа' }}</span>
            <input v-model="form.name" maxlength="200" required placeholder="Например, интеграция с 1С" />
          </label>
          <label class="field field-wide">
            <span>Разрешённые IP/CIDR</span>
            <textarea v-model="form.allowed" rows="3" placeholder="192.168.189.0/24&#10;10.10.26.10"></textarea>
            <small class="muted">
              По одному адресу в строке или через запятую. Пустой список при редактировании
              отключает ключ (403); для нового ключа нужен хотя бы один адрес.
            </small>
          </label>
        </div>
        <div class="heading-actions">
          <button class="btn btn-primary" :disabled="busy">{{ busy ? 'Сохранение…' : (form.id ? 'Сохранить изменения' : 'Создать ключ') }}</button>
          <button v-if="form.id" type="button" class="btn" @click="resetForm">Отмена</button>
        </div>
      </form>
    </div>

    <div class="panel table-panel">
      <div v-if="loading" class="state">Загрузка…</div>
      <EmptyState v-else-if="!keys.length" title="API-ключей нет" text="Создайте ключ, чтобы разрешить интеграционным системам доступ к API." />
      <table v-else class="data-table">
        <thead>
          <tr>
            <th>Название</th>
            <th>Префикс</th>
            <th>IP/CIDR</th>
            <th>Статус</th>
            <th>Последнее использование</th>
            <th>Создан</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="key in keys" :key="key.key_id" :class="{ 'row-warning': key.status !== 'active' }">
            <td>
              <strong>{{ key.name }}</strong>
              <div class="small muted">{{ key.key_id }}</div>
            </td>
            <td><code>{{ key.token_prefix }}…</code></td>
            <td>
              <span v-if="!key.allowed_ips?.length" class="badge badge-warning">запрещено всё</span>
              <template v-else>
                <div v-for="ip in key.allowed_ips" :key="ip" class="small"><code>{{ ip }}</code></div>
              </template>
            </td>
            <td>
              <span class="badge" :class="key.status === 'active' ? 'badge-ok' : 'badge-error'">
                {{ key.status === 'active' ? 'активен' : 'отозван' }}
              </span>
              <div v-if="key.revoked_at" class="small muted">{{ formatTime(key.revoked_at) }}</div>
            </td>
            <td>
              <div>{{ formatTime(key.last_used_at) }}</div>
              <div v-if="key.last_used_ip" class="small muted">{{ key.last_used_ip }}</div>
            </td>
            <td>
              <div>{{ formatTime(key.created_at) }}</div>
              <div class="small muted">{{ key.created_by }}</div>
            </td>
            <td class="actions-cell">
              <button v-if="key.status === 'active'" class="btn btn-small" @click="startEdit(key)">Изменить</button>
              <button v-if="key.status === 'active'" class="btn btn-small btn-danger" @click="revoke(key)">Отозвать</button>
              <span v-else class="muted small">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.field-wide { grid-column: span 2; }
.token-reveal { display: flex; align-items: center; gap: 10px; margin: 8px 0; flex-wrap: wrap; }
.token-reveal code { overflow-wrap: anywhere; padding: 6px 8px; }
.actions-cell { white-space: nowrap; }
.actions-cell .btn { margin-right: 6px; }
</style>
