<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { api } from '../api'
import { formatTime, licenseKindLabel, stateLabel } from '../format'

const props = defineProps({
  visible: { type: Boolean, default: false },
  machineIds: { type: Array, default: () => [] },
  groupIds: { type: Array, default: () => [] }
})
const emit = defineEmits(['close', 'created'])

const dialog = ref(null)
let initializing = false
let previewRequest = 0
watch(() => props.visible, async visible => {
  if (visible) {
    await nextTick()
    if (props.visible && !dialog.value.open) dialog.value.showModal()
  } else {
    previewRequest++
    if (dialog.value?.open) dialog.value.close()
  }
}, { flush: 'post' })
function closeOnBackdrop(event) {
  if (event.target !== dialog.value) return
  const rect = dialog.value.getBoundingClientRect()
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) emit('close')
}
const pools = ref([])
const poolId = ref('')
const preview = ref(null)
const selected = ref(new Set())
const busy = ref(false)
const error = ref('')
const message = ref('')
const checking = ref(false)

const pool = computed(() => pools.value.find(p => p.id === poolId.value) || null)
const required = computed(() => selected.value.size)
const available = computed(() => preview.value?.available_keys ?? pool.value?.counts?.available ?? 0)
const deficit = computed(() => required.value > available.value)
const activation = computed(() => preview.value?.preview?.activation || [])
const optional = computed(() => preview.value?.preview?.optional || [])
const activated = computed(() => preview.value?.preview?.already_activated || [])
const needsCheck = computed(() => preview.value?.preview?.needs_check || [])
const incompatible = computed(() => preview.value?.preview?.incompatible || [])
const optionalSelectable = computed(() => optional.value.filter(m => m.selectable).map(m => m.machine_id))
const optionalAll = computed(() => optionalSelectable.value.length > 0 && optionalSelectable.value.every(id => selected.value.has(id)))
const optionalIndeterminate = computed(() => optionalSelectable.value.some(id => selected.value.has(id)) && !optionalAll.value)
const scanIds = computed(() => needsCheck.value.map(m => m.machine_id))

function idempotencyKey() {
  if (globalThis.crypto?.randomUUID) return crypto.randomUUID()
  return 'idem-' + Date.now() + '-' + Math.random().toString(16).slice(2)
}

async function loadPools() {
  error.value = ''
  try {
    const result = await api.licensePools()
    pools.value = (result.items || []).filter(p => !p.archived_at)
    if (!poolId.value && pools.value.length) poolId.value = pools.value[0].id
  } catch (e) { error.value = e.message }
}

async function loadPreview() {
  if (!poolId.value) return
  if (!props.machineIds.length && !props.groupIds.length) { error.value = 'Не выбрано ни одной машины.'; return }
  const request = ++previewRequest
  busy.value = true; error.value = ''; message.value = ''; preview.value = null
  try {
    const response = await api.activationPreview({ pool_id: poolId.value, machine_ids: props.machineIds, group_ids: props.groupIds })
    if (request !== previewRequest || !props.visible) return
    preview.value = response
    const defaults = new Set(preview.value.preview?.default_selected || [])
    selected.value = defaults
  } catch (e) { if (request === previewRequest) error.value = e.message } finally { if (request === previewRequest) busy.value = false }
}

watch(() => props.visible, async visible => {
  if (!visible) return
  preview.value = null; selected.value = new Set(); error.value = ''; message.value = ''
  initializing = true
  await loadPools()
  initializing = false
  if (props.visible) await loadPreview()
}, { immediate: false })

watch(poolId, () => { if (props.visible && !initializing) loadPreview() })

function toggle(id, enabled) {
  if (!enabled) return
  const next = new Set(selected.value)
  if (next.has(id)) next.delete(id); else next.add(id)
  selected.value = next
}

function toggleOptional(checked) {
  const next = new Set(selected.value)
  for (const id of optionalSelectable.value) {
    if (checked) next.add(id); else next.delete(id)
  }
  selected.value = next
}

function isSelected(id) { return selected.value.has(id) }

async function submit() {
  if (!preview.value || deficit.value || !selected.value.size) return
  busy.value = true; error.value = ''; message.value = ''
  try {
    const task = await api.createTask({
      kind: 'install_license',
      pool_id: poolId.value,
      preview_id: preview.value.preview_id,
      machine_ids: [...selected.value],
      idempotency_key: idempotencyKey()
    })
    emit('created', task)
    emit('close')
  } catch (e) {
    error.value = e.message
    if (e.body?.error?.details) {
      const d = e.body.error.details
      message.value = `Нужно ${d.needed}, свободно ${d.available}. Снимите лишние отметки.`
    }
  } finally { busy.value = false }
}

async function createScanForUnknown() {
  if (!scanIds.value.length) return
  checking.value = true; error.value = ''; message.value = ''
  try {
    const task = await api.createTask({
      kind: 'scan', machine_ids: scanIds.value, group_ids: [], idempotency_key: idempotencyKey()
    })
    message.value = `Задача проверки создана: ${task.task.id}. После сбора обновите предпросмотр.`
  } catch (e) { error.value = e.message } finally { checking.value = false }
}

function reasonText(m) {
  if (m.reason_text) return m.reason_text
  return stateLabel(m.reason_code || '')
}
</script>

<template>
  <dialog ref="dialog" class="modal activation-dialog" aria-labelledby="activation-title" @cancel.prevent="emit('close')" @click="closeOnBackdrop">
    <div class="modal-content">
      <div class="modal-head">
        <div><span class="eyebrow">Удалённая активация</span><h2 id="activation-title">Активировать лицензию</h2><p class="muted">Один пул и один снимок получателей. Несовместимые машины исключены.</p></div>
        <button class="btn" type="button" @click="emit('close')">Закрыть</button>
      </div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="message" class="alert alert-info">{{ message }}</div>
      <div v-if="!pools.length" class="alert alert-info">Нет доступных пулов лицензий. Создайте пул в разделе «Пулы лицензий».</div>
      <div v-else class="toolbar">
        <label class="field"><span>Пул</span>
          <select :disabled="busy" v-model="poolId" aria-label="Пул лицензий">
            <option v-for="p in pools" :key="p.id" :value="p.id">{{ p.name }} · CSP {{ p.csp_major_version }} · {{ licenseKindLabel(p.license_kind) }} · {{ ({ one_year: '1 год', two_years: '2 года', perpetual: 'Бессрочно' })[p.term] || p.term }}</option>
          </select>
        </label>
        <button class="btn" type="button" :disabled="busy" @click="loadPreview">Пересчитать предпросмотр</button>
        <span v-if="pool" class="muted">Свободно: <strong>{{ pool.counts.available }}</strong> · зарезервировано: {{ pool.counts.reserved }} · использовано: {{ pool.counts.used }}</span>
      </div>
      <div v-if="busy && !preview" class="state">Проверка сертификатов и лицензий…</div>
      <template v-if="preview">
        <div class="modal-summary">
          <div class="muted">Требуется ключей: <strong>{{ required }}</strong> · свободно: <strong>{{ available }}</strong></div>
          <div v-if="deficit" class="badge badge-error">Дефицит: нужно {{ required }}, свободно {{ available }}. Снимите лишние отметки.</div>
          <div v-else class="badge badge-ok">Ключей достаточно</div>
        </div>

        <section class="modal-section">
          <h3><span>1. Нужна активация</span><span class="badge-count">{{ activation.length }}</span></h3>
          <p class="muted small">Без действующей лицензии отметка включена. Подтверждённый триал отмечен, но по умолчанию выключен.</p>
          <div class="modal-list">
            <label v-for="m in activation" :key="m.machine_id" class="modal-row" :class="{ disabled: !m.selectable }">
              <input type="checkbox" :checked="isSelected(m.machine_id)" :disabled="busy || !m.selectable" @change="toggle(m.machine_id, m.selectable)" />
              <span><strong>{{ m.display_name }}</strong><div class="small muted">{{ m.hostname }}</div></span>
              <span><span class="badge" :class="m.subtype === 'activation_trial' ? 'badge-warning' : 'badge-neutral'">{{ m.subtype === 'activation_trial' ? 'Триал' : 'Нет лицензии' }}</span></span>
              <span class="small">{{ reasonText(m) }}<div class="muted">CSP {{ m.product_version || '—' }} · сертификат {{ m.suitable_certificate ? 'подходит' : 'нет' }}</div></span>
            </label>
            <div v-if="!activation.length" class="state">Нет машин в этой категории.</div>
          </div>
        </section>

        <section class="modal-section">
          <h3><label><input type="checkbox" :disabled="busy" :checked="optionalAll" :indeterminate="optionalIndeterminate" @change="toggleOptional($event.target.checked)" /> 2. Можно не активировать</label><span class="badge-count">{{ optional.length }}</span></h3>
          <p class="muted small">Администратор может включить машину вручную, если считает активацию необходимой.</p>
          <div class="modal-list">
            <label v-for="m in optional" :key="m.machine_id" class="modal-row" :class="{ disabled: !m.selectable }">
              <input type="checkbox" :checked="isSelected(m.machine_id)" :disabled="busy || !m.selectable" @change="toggle(m.machine_id, m.selectable)" />
              <span><strong>{{ m.display_name }}</strong><div class="small muted">{{ m.hostname }}</div></span>
              <span><span class="badge badge-neutral">Без лицензии</span></span>
              <span class="small">{{ reasonText(m) }}</span>
            </label>
            <div v-if="!optional.length" class="state">Нет машин в этой категории.</div>
          </div>
        </section>

        <section class="modal-section">
          <h3><span>3. Уже активирована</span><span class="badge-count">{{ activated.length }}</span></h3>
          <div class="modal-list">
            <div v-for="m in activated" :key="m.machine_id" class="modal-row disabled">
              <input type="checkbox" disabled />
              <span><strong>{{ m.display_name }}</strong><div class="small muted">{{ m.hostname }}</div></span>
              <span class="badge badge-ok">{{ licenseKindLabel(m.license_kind) }}</span>
              <span class="small">{{ reasonText(m) }}<div class="muted">Действует до: {{ m.valid_to_raw || 'бессрочно' }}</div></span>
            </div>
            <div v-if="!activated.length" class="state">Нет машин в этой категории.</div>
          </div>
        </section>

        <section class="modal-section">
          <h3><span>4. Нужна проверка</span><span class="badge-count">{{ needsCheck.length }}</span></h3>
          <p class="muted small">Для неизвестного состояния создаётся отдельный scan. Активация для этих машин недоступна до нового подтверждения.</p>
          <div class="modal-list">
            <div v-for="m in needsCheck" :key="m.machine_id" class="modal-row disabled">
              <input type="checkbox" disabled />
              <span><strong>{{ m.display_name }}</strong><div class="small muted">{{ m.hostname }}</div></span>
              <span class="badge badge-warning">Проверка</span>
              <span class="small">{{ reasonText(m) }}<div class="muted">Собрано: {{ formatTime(m.collected_at) }}</div></span>
            </div>
            <div v-if="!needsCheck.length" class="state">Нет машин в этой категории.</div>
          </div>
          <div class="modal-actions"><button class="btn" type="button" :disabled="checking || !scanIds.length" @click="createScanForUnknown">Проверить выбранные (scan)</button></div>
        </section>

        <section v-if="incompatible.length" class="modal-section">
          <h3><span>Исключены: несовместимы с пулом</span><span class="badge-count">{{ incompatible.length }}</span></h3>
          <div class="modal-list">
            <div v-for="m in incompatible" :key="m.machine_id" class="modal-row disabled">
              <input type="checkbox" disabled />
              <span><strong>{{ m.display_name }}</strong><div class="small muted">{{ m.hostname }}</div></span>
              <span class="badge badge-error">{{ m.reason_code }}</span>
              <span class="small">{{ reasonText(m) }}</span>
            </div>
          </div>
        </section>

        <div class="modal-actions">
          <span v-if="deficit" class="muted">Сервер не выбирает получателей автоматически.</span>
          <button class="btn" type="button" :disabled="busy" @click="emit('close')">Отмена</button>
          <button class="btn btn-primary" type="button" :disabled="busy || !selected.size || deficit" @click="submit">Подтвердить активацию ({{ required }})</button>
        </div>
      </template>
    </div>
  </dialog>
</template>
