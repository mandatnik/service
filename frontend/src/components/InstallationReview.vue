<script setup>
import { computed, ref, watch } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'

const props = defineProps({
  request: { type: Object, required: true },
  presetMachineId: { type: String, default: '' }
})
const emit = defineEmits(['resolved', 'cancel'])

const selectedMachineId = ref('')
const confirmed = ref(false)
const reason = ref('')
const busy = ref('')
const error = ref('')

const candidates = computed(() => props.request?.candidates || [])
const selected = computed(() => candidates.value.find(c => c.machine_id === selectedMachineId.value) || null)
const activeRegistration = computed(() => selected.value?.active_registration || null)
const lastRegistration = computed(() => activeRegistration.value || selected.value?.last_registration || null)
const oldSeenRecently = computed(() => {
  const seen = lastRegistration.value?.last_seen_at
  return !!seen && (Date.now() - new Date(seen).getTime()) < 20 * 60 * 1000
})
const hasRegisteredConflict = computed(() => !!props.request?.registered_machine_id)
const canReplace = computed(() => !!selected.value && !selected.value.archived && !hasRegisteredConflict.value)

watch(() => props.request?.request_id, () => {
  const preset = props.presetMachineId && candidates.value.some(c => c.machine_id === props.presetMachineId)
    ? props.presetMachineId
    : (candidates.value.find(c => !c.archived)?.machine_id || candidates.value[0]?.machine_id || '')
  selectedMachineId.value = preset
  confirmed.value = false
  reason.value = ''
  error.value = ''
  busy.value = ''
}, { immediate: true })

function decisionBase() {
  return {
    request_version: props.request.request_version,
    key_fingerprint: props.request.key_fingerprint,
    reason: reason.value.trim()
  }
}

async function replace() {
  error.value = ''
  if (!canReplace.value) { error.value = 'Выберите действующую карточку машины, не находящуюся в архиве.'; return }
  if (!confirmed.value) { error.value = 'Подтвердите выбранную пару «машина — новая установка».'; return }
  busy.value = 'replace'
  try {
    const result = await api.replaceInstallation(props.request.request_id, {
      ...decisionBase(),
      machine_id: selected.value.machine_id,
      old_registration_id: activeRegistration.value?.registration_id || 0
    })
    emit('resolved', { action: 'replace', result })
  } catch (e) { error.value = e.message } finally { busy.value = '' }
}

async function separate() {
  error.value = ''
  if (!confirmed.value) { error.value = 'Подтвердите создание отдельной машины с совпадающим именем.'; return }
  busy.value = 'separate'
  try {
    const result = await api.separateInstallation(props.request.request_id, {
      ...decisionBase(),
      confirm_name_conflict: true
    })
    emit('resolved', { action: 'separate', result })
  } catch (e) { error.value = e.message } finally { busy.value = '' }
}

async function reject() {
  error.value = ''
  if (!confirmed.value) { error.value = 'Подтвердите отклонение заявки.'; return }
  busy.value = 'reject'
  try {
    const result = await api.rejectInstallation(props.request.request_id, decisionBase())
    emit('resolved', { action: 'reject', result })
  } catch (e) { error.value = e.message } finally { busy.value = '' }
}
</script>

<template>
  <div class="panel installation-review">
    <div class="panel-heading">
      <div>
        <h3>Замена установки агента</h3>
        <p class="muted">Новая установка использует имя существующей машины. Решение принимает администратор; автоматического объединения нет.</p>
      </div>
      <button type="button" class="btn btn-quiet" @click="emit('cancel')">Закрыть</button>
    </div>

    <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
    <div v-if="hasRegisteredConflict" class="alert alert-error">
      UUID новой установки уже зарегистрирован в карточке «{{ request.registered_machine_name || request.registered_machine_id }}»
      ({{ request.registered_machine_id }}). Частичное слияние данных не выполняется: замена и отдельная регистрация недоступны.
    </div>

    <div class="two-column">
      <div>
        <h4>Новая установка</h4>
        <dl class="facts">
          <dt>Hostname</dt><dd><strong>{{ request.hostname }}</strong></dd>
          <dt>UUID</dt><dd><code class="small">{{ request.uuid }}</code></dd>
          <dt>Заявка</dt><dd><code class="small">{{ request.request_id }}</code> · версия {{ request.request_version }}</dd>
          <dt>Отпечаток ключа</dt><dd><code class="small fingerprint">{{ request.key_fingerprint }}</code></dd>
          <dt>Адрес подключения</dt><dd>{{ request.source_ip || 'неизвестен' }} · DNS {{ request.dns_status || 'unknown' }}</dd>
          <dt>Первое обращение</dt><dd>{{ formatTime(request.first_seen_at) }}</dd>
          <dt>Последнее обращение</dt><dd>{{ formatTime(request.last_seen_at) }}</dd>
          <dt>Агент</dt><dd>{{ request.agent_version || '—' }} · {{ request.os_version || 'ОС неизвестна' }} · {{ request.architecture || '—' }}</dd>
        </dl>
      </div>
      <div>
        <h4>Существующая машина</h4>
        <label class="field">
          <span>Карточка машины</span>
          <select v-model="selectedMachineId" aria-label="Существующая машина для замены установки">
            <option v-for="candidate in candidates" :key="candidate.machine_id" :value="candidate.machine_id">
              {{ candidate.display_name || candidate.machine_id }}{{ candidate.archived ? ' (архив)' : '' }}
            </option>
          </select>
        </label>
        <div v-if="!candidates.length" class="alert alert-info">Связанных карточек не найдено. Можно создать отдельную машину или отклонить заявку.</div>
        <template v-if="selected">
          <dl class="facts">
            <dt>machine_id</dt><dd><code class="small">{{ selected.machine_id }}</code></dd>
            <dt>Название</dt><dd>{{ selected.display_name || '—' }}</dd>
            <dt>Состояние карточки</dt><dd>{{ selected.archived ? 'Архивная запись' : 'Действующая' }}<span v-if="selected.archive_reason" class="muted"> · {{ selected.archive_reason }}</span></dd>
            <dt>Старая регистрация</dt>
            <dd v-if="lastRegistration">
              {{ lastRegistration.registration_id }} · <span class="badge" :class="lastRegistration.state === 'active' ? 'badge-ok' : 'badge-neutral'">{{ lastRegistration.state }}</span>
              <div class="small muted">{{ lastRegistration.hostname }} · {{ lastRegistration.uuid }}</div>
            </dd>
            <dd v-else>нет регистраций</dd>
            <dt>Последнее обращение</dt><dd>{{ formatTime(lastRegistration?.last_seen_at) }}</dd>
            <dt>Состояние связи</dt>
            <dd><span class="badge" :class="selected.online ? 'badge-ok' : 'badge-neutral'">{{ selected.online ? 'В сети' : 'Не в сети' }}</span></dd>
          </dl>
          <div v-if="oldSeenRecently" class="alert alert-warning">
            Старая установка выходила на связь менее 20 минут назад. После подтверждения она потеряет доступ к агентским API.
          </div>
          <div v-if="!selected.name_match" class="alert alert-warning">
            Имя новой установки не совпадает с именем этой карточки. Связь выполняется вручную; проверьте выбранную пару и старую регистрацию перед подтверждением.
          </div>
          <div v-if="selected.archived" class="alert alert-warning">
            Архивированную карточку нельзя использовать как цель замены. Выберите действующую карточку или создайте отдельную машину.
          </div>
        </template>
      </div>
    </div>

    <label class="field">
      <span>Причина решения (необязательно)</span>
      <textarea v-model="reason" rows="2" maxlength="1024" placeholder="Например: переустановка Windows, плановая замена системного блока"></textarea>
    </label>

    <label class="confirm-row">
      <input v-model="confirmed" type="checkbox" />
      <span>
        Подтверждаю, что проверил пару
        <strong>«{{ selected?.display_name || selected?.machine_id || 'машина не выбрана' }} — {{ request.hostname }} / {{ request.uuid }}»</strong>.
        Замена сохранит <code>machine_id</code> и историю, но отключит старую установку;
        отдельная машина не переносит историю; отклонение не создаёт машину.
      </span>
    </label>

    <div class="heading-actions">
      <button type="button" class="btn btn-primary" :disabled="!!busy || !canReplace" @click="replace">{{ busy === 'replace' ? 'Замена…' : 'Заменить установку агента' }}</button>
      <button type="button" class="btn" :disabled="!!busy || hasRegisteredConflict" @click="separate">{{ busy === 'separate' ? 'Создание…' : 'Создать отдельную машину' }}</button>
      <button type="button" class="btn btn-danger" :disabled="!!busy" @click="reject">{{ busy === 'reject' ? 'Отклонение…' : 'Отклонить заявку' }}</button>
    </div>
  </div>
</template>
