<script setup>
import { nextTick, onMounted, ref } from 'vue'
import { api } from '../api'

const props = defineProps({
  machine: { type: Object, required: true }
})
const emit = defineEmits(['saved', 'close'])
const dialog = ref(null)
const reasonInput = ref(null)
const reason = ref('Деактивирована администратором')
const error = ref('')
const busy = ref(false)

onMounted(async () => {
  dialog.value?.showModal()
  await nextTick()
  reasonInput.value?.focus()
  reasonInput.value?.select()
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

async function deactivate() {
  error.value = ''
  const text = reason.value.trim()
  if (!text) {
    error.value = 'Укажите причину деактивации.'
    return
  }
  busy.value = true
  try {
    await api.deactivateMachine(props.machine.machine_id, text)
    emit('saved', props.machine)
    close()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <dialog ref="dialog" class="rename-dialog" aria-labelledby="deactivate-machine-heading" @cancel.prevent="cancel" @close="emit('close')" @click="backdrop">
    <header class="authors-dialog-heading">
      <div>
        <h2 id="deactivate-machine-heading">Деактивировать АРМ</h2>
        <p class="muted">Карточка, отчёты, сертификаты, задания и история сохранятся. Машина исчезнет из действующего списка и будет доступна в фильтре «Архивные».</p>
      </div>
      <button type="button" class="dialog-close" aria-label="Закрыть окно деактивации" :disabled="busy" @click="cancel">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg>
      </button>
    </header>
    <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
    <dl class="facts rename-facts">
      <dt>Имя АРМ</dt><dd>{{ machine.display_name || '—' }}</dd>
      <dt>Hostname агента</dt><dd><code>{{ machine.hostname || 'не собран' }}</code></dd>
      <dt>machine_id</dt><dd><code class="small">{{ machine.machine_id }}</code></dd>
    </dl>
    <div class="alert alert-warning" role="note">Активная регистрация агента будет отозвана, а незавершённые задания доставки отменены. Вернуть машину в действующий список через этот раздел нельзя.</div>
    <label class="field">
      <span>Причина деактивации</span>
      <input ref="reasonInput" v-model="reason" maxlength="1024" required @keydown.enter.prevent="deactivate" />
    </label>
    <div class="modal-actions">
      <button type="button" class="btn" :disabled="busy" @click="cancel">Отмена</button>
      <button type="button" class="btn btn-danger" :disabled="busy || !reason.trim()" @click="deactivate">{{ busy ? 'Деактивация…' : 'Деактивировать' }}</button>
    </div>
  </dialog>
</template>
