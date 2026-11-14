<script setup>
import { nextTick, onMounted, ref } from 'vue'
import { api } from '../api'

const props = defineProps({
  machine: { type: Object, required: true }
})
const emit = defineEmits(['saved', 'close'])
const dialog = ref(null)
const input = ref(null)
const displayName = ref(props.machine.display_name || '')
const error = ref('')
const busy = ref(false)

onMounted(async () => {
  dialog.value?.showModal()
  await nextTick()
  input.value?.focus()
  input.value?.select()
})

function close() {
  dialog.value?.close()
}

function cancel() {
  if (!busy.value) close()
}

function backdrop(event) {
  if (event.target === dialog.value && !busy.value) close()
}

async function save() {
  error.value = ''
  const name = displayName.value.trim()
  if (!name) {
    error.value = 'Введите имя АРМ.'
    return
  }
  busy.value = true
  try {
    const result = await api.renameMachine(props.machine.machine_id, name)
    emit('saved', result)
    close()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <dialog ref="dialog" class="rename-dialog" aria-labelledby="rename-machine-heading" @cancel.prevent="cancel" @close="emit('close')" @click="backdrop">
    <header class="authors-dialog-heading">
      <div>
        <h2 id="rename-machine-heading">Переименовать АРМ</h2>
        <p class="muted">Меняется только отображаемое имя в админке. Hostname, UUID и <code>machine_id</code> остаются прежними.</p>
      </div>
      <button type="button" class="dialog-close" aria-label="Закрыть окно переименования" :disabled="busy" @click="cancel">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
      </button>
    </header>
    <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
    <dl class="facts rename-facts">
      <dt>Текущее имя</dt><dd>{{ machine.display_name || '—' }}</dd>
      <dt>Hostname агента</dt><dd><code>{{ machine.hostname || 'не собран' }}</code></dd>
      <dt>machine_id</dt><dd><code class="small">{{ machine.machine_id }}</code></dd>
    </dl>
    <label class="field">
      <span>Новое имя АРМ</span>
      <input ref="input" v-model="displayName" maxlength="253" required placeholder="Например: Бухгалтерия-01" @keydown.enter.prevent="save" />
    </label>
    <p class="muted small">Пользовательское имя сохранится при последующей замене установки и смене hostname агентом.</p>
    <div class="modal-actions">
      <button type="button" class="btn" :disabled="busy" @click="cancel">Отмена</button>
      <button type="button" class="btn btn-primary" :disabled="busy || !displayName.trim()" @click="save">{{ busy ? 'Сохранение…' : 'Сохранить имя' }}</button>
    </div>
  </dialog>
</template>
