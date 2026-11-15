<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { validateAdminForm } from '../adminForm'
import { formatTime } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'

const props = defineProps({ role: { type: String, default: '' } })
const isSuperAdmin = computed(() => props.role === 'superadmin')
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const message = ref('')
const items = ref([])
const editing = ref(null)
const formError = ref('')

const creating = computed(() => editing.value?.id === 0)

async function load() {
  if (!isSuperAdmin.value) return
  loading.value = true
  error.value = ''
  try {
    const result = await api.admins()
    items.value = result.items || []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function startCreate() {
  error.value = ''
  message.value = ''
  formError.value = ''
  editing.value = { id: 0, email: '', display_name: '', password: '' }
}

function startEdit(record) {
  error.value = ''
  message.value = ''
  formError.value = ''
  editing.value = { id: record.id, email: record.email, display_name: record.display_name, password: '' }
}

function cancelEdit() {
  editing.value = null
  formError.value = ''
}

async function save() {
  if (!editing.value) return
  const problem = validateAdminForm(editing.value, creating.value)
  if (problem) {
    formError.value = problem
    return
  }
  busy.value = true
  formError.value = ''
  error.value = ''
  message.value = ''
  try {
    const body = {
      email: editing.value.email.trim(),
      display_name: editing.value.display_name.trim(),
      password: editing.value.password
    }
    if (creating.value) {
      await api.createAdmin(body)
      message.value = 'Администратор создан. Роль всегда остаётся обычным администратором.'
    } else {
      await api.updateAdmin(editing.value.id, body)
      message.value = 'Учётная запись обновлена. При смене email или пароля её старые сессии завершены.'
    }
    editing.value = null
    await load()
  } catch (e) {
    formError.value = e.message
  } finally {
    busy.value = false
  }
}

async function freeze(record) {
  if (!confirm(`Заморозить администратора «${record.display_name}»? Все его сессии завершатся немедленно.`)) return
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await api.freezeAdmin(record.id)
    message.value = `Администратор «${record.display_name}» заморожен, сессии завершены.`
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function unfreeze(record) {
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await api.unfreezeAdmin(record.id)
    message.value = `Администратор «${record.display_name}» разморожен. Старые сессии не восстанавливаются.`
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function remove(record) {
  if (!confirm(`Удалить администратора «${record.display_name}»? Учётная запись и все её сессии будут удалены; авторство прежних действий сохранится в журнале.`)) return
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await api.deleteAdmin(record.id)
    message.value = `Администратор «${record.display_name}» удалён.`
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <section>
    <div v-if="!isSuperAdmin" class="panel">
      <h2>Доступ ограничен</h2>
      <p class="muted">Управление администраторами доступно только суперадминистратору. Сервер также отклоняет запросы обычного администратора.</p>
    </div>
    <template v-else>
      <div class="page-heading">
        <div><p class="muted">Суперадмин управляет только обычными администраторами. Суперадминские учётные записи защищены от изменения через этот раздел.</p></div>
        <div class="heading-actions"><button class="btn" :disabled="loading" @click="load">Обновить</button><button class="btn btn-primary" :disabled="busy" @click="startCreate">Добавить администратора</button></div>
      </div>
      <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
      <div v-if="message" class="alert alert-success" role="status">{{ message }}</div>
      <form v-if="editing" class="panel settings-form" @submit.prevent="save">
        <h3>{{ creating ? 'Новый администратор' : 'Изменить администратора' }}</h3>
        <div v-if="formError" class="alert alert-error" role="alert">{{ formError }}</div>
        <div class="form-row">
          <label class="field"><span>Email</span><input v-model="editing.email" type="email" maxlength="320" autocomplete="off" required /></label>
          <label class="field"><span>ФИО</span><input v-model="editing.display_name" maxlength="255" autocomplete="off" required /></label>
        </div>
        <label class="field"><span>{{ creating ? 'Пароль' : 'Новый пароль (оставьте пустым, чтобы не менять)' }}</span><input v-model="editing.password" type="password" minlength="12" :required="creating" autocomplete="new-password" /><small class="muted">Не менее 12 символов. Пароль не сохраняется в открытом виде и не возвращается API.</small></label>
        <div class="heading-actions"><button class="btn btn-primary" :disabled="busy">{{ busy ? 'Сохранение…' : 'Сохранить' }}</button><button type="button" class="btn" :disabled="busy" @click="cancelEdit">Отмена</button></div>
      </form>
      <ErrorState v-if="error && !items.length" :message="error" @retry="load" />
      <div v-else class="panel table-panel">
        <div v-if="loading && !items.length" class="state">Загрузка…</div>
        <EmptyState v-else-if="!items.length" title="Администраторы не найдены" text="Создайте первую учётную запись обычного администратора." />
        <table v-else class="data-table admins-table">
          <thead><tr><th>Email</th><th>ФИО</th><th>Роль</th><th>Состояние</th><th>Создан</th><th class="admin-actions-cell"><span class="sr-only">Действия</span></th></tr></thead>
          <tbody>
            <tr v-for="record in items" :key="record.id">
              <td><strong>{{ record.email }}</strong></td>
              <td>{{ record.display_name }}</td>
              <td><span class="badge" :class="record.role === 'superadmin' ? 'badge-license' : 'badge-neutral'">{{ record.role === 'superadmin' ? 'Суперадмин' : 'Администратор' }}</span></td>
              <td><span class="badge" :class="record.disabled ? 'badge-warning' : 'badge-ok'">{{ record.disabled ? 'Заморожен' : 'Активен' }}</span></td>
              <td class="small muted">{{ formatTime(record.created_at) }}</td>
              <td class="admin-actions-cell">
                <span v-if="record.role === 'superadmin'" class="small muted" title="Учётная запись защищена от изменения через этот раздел">Защищён</span>
                <div v-else class="heading-actions">
                  <button class="btn btn-small" :disabled="busy" @click="startEdit(record)">Изменить</button>
                  <button v-if="!record.disabled" class="btn btn-small" :disabled="busy" @click="freeze(record)">Заморозить</button>
                  <button v-else class="btn btn-small" :disabled="busy" @click="unfreeze(record)">Разморозить</button>
                  <button class="btn btn-small btn-danger" :disabled="busy" @click="remove(record)">Удалить</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>
