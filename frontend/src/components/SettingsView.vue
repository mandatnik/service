<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import ErrorState from './ErrorState.vue'
const config = reactive({ scan_interval_days: 1, poll_interval_seconds: 60, inventory_freshness_seconds: 86400, task_ttl_seconds: 604800, recursive: true, max_files: 2000, max_file_bytes: 10485760 })
const version = ref(0)
const hash = ref('')
const savedHash = ref('')
const loading = ref(true)
const busy = ref(false)
const error = ref('')
const message = ref('')
const dirty = ref(false)
async function load() {
  loading.value = true; error.value = ''
  try {
    const result = await api.config()
    const c = result.config
    version.value = c.version
    config.scan_interval_days = c.scan_interval_days
    config.poll_interval_seconds = c.poll_interval_seconds || 60
    config.inventory_freshness_seconds = c.inventory_freshness_seconds || 86400
    config.task_ttl_seconds = c.task_ttl_seconds || 604800
    config.recursive = c.recursive
    config.max_files = c.max_files
    config.max_file_bytes = c.max_file_bytes
    hash.value = result.config_hash
    savedHash.value = result.config_hash
    dirty.value = false
  } catch (e) { error.value = e.message } finally { loading.value = false }
}
function touch() { dirty.value = true; message.value = '' }
async function save() {
  error.value = ''; message.value = ''
  const payload = {
    version: version.value,
    scan_interval_days: Number(config.scan_interval_days),
    poll_interval_seconds: Number(config.poll_interval_seconds),
    inventory_freshness_seconds: Number(config.inventory_freshness_seconds),
    task_ttl_seconds: Number(config.task_ttl_seconds),
    cert_directories: [],
    recursive: Boolean(config.recursive),
    max_files: Number(config.max_files),
    max_file_bytes: Number(config.max_file_bytes)
  }
  busy.value = true
  try {
    const result = await api.saveConfig(payload)
    version.value = result.config.version
    hash.value = result.config_hash
    savedHash.value = result.config_hash
    dirty.value = false
    message.value = `Конфигурация сохранена, версия ${result.config.version}. Агенты получат её на следующем опросе (интервал настраивается).`
  } catch (e) { error.value = e.message } finally { busy.value = false }
}
onMounted(load)
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Период и ограничения сбора для всех агентов. Папки настраиваются отдельно в разделе «Политики папок».</p></div><button class="btn" @click="load">Обновить</button></div>
    <ErrorState v-if="error && !hash" :message="error" @retry="load" />
    <div v-else-if="loading" class="state">Загрузка…</div>
    <form v-else class="panel settings-form" @submit.prevent="save">
      <div class="alert alert-info">После сохранения агент получит новый хеш конфигурации при следующем опросе. Ручные задания доставляются независимо от изменения конфигурации.</div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div class="form-grid">
        <label class="field"><span>Период сканирования, дней</span><input v-model.number="config.scan_interval_days" type="number" min="1" max="365" required @input="touch" /><small class="muted">Плановый суточный/периодический сбор остаётся отдельной настройкой.</small></label>
        <label class="field"><span>Интервал опроса, секунд</span><input v-model.number="config.poll_interval_seconds" type="number" min="10" max="3600" required @input="touch" /><small class="muted">60 по умолчанию; применяется новыми агентами без рестарта.</small></label>
        <label class="field"><span>Свежесть инвентаризации, секунд</span><input v-model.number="config.inventory_freshness_seconds" type="number" min="60" max="2592000" required @input="touch" /><small class="muted">86400 по умолчанию; устаревшие данные требуют проверки.</small></label>
        <label class="field"><span>Срок задачи, секунд</span><input v-model.number="config.task_ttl_seconds" type="number" min="60" max="2592000" required @input="touch" /><small class="muted">604800 по умолчанию; неизвестные установки ключ не освобождают.</small></label>
        <label class="field"><span>Максимум файлов</span><input v-model.number="config.max_files" type="number" min="1" max="10000" required @input="touch" /></label>
        <label class="field"><span>Максимум байт на файл</span><input v-model.number="config.max_file_bytes" type="number" min="1" required @input="touch" /></label>
      </div>
      <div class="settings-meta"><span>Версия: <strong>{{ version }}</strong></span><span>Хеш: <code>{{ hash }}</code></span></div>
      <div class="heading-actions"><button class="btn btn-primary" :disabled="busy || !dirty">{{ busy ? 'Сохранение…' : 'Сохранить' }}</button><span v-if="dirty" class="muted">Есть несохранённые изменения</span></div>
    </form>
  </section>
</template>
