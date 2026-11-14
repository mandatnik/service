<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatDate, formatTime } from '../format'
import ErrorState from './ErrorState.vue'
import CertificateOwner from './CertificateOwner.vue'
import EmbeddedLicenseBadge from './EmbeddedLicenseBadge.vue'
const props = defineProps({ sha256: { type: String, required: true } })
const emit = defineEmits(['back', 'open-machine'])
const data = ref(null)
const error = ref('')
async function load() {
  error.value = ''
  try { data.value = await api.certificate(props.sha256) } catch (e) { error.value = e.message }
}
onMounted(load)
</script>
<template>
  <section>
    <button class="btn btn-quiet back" @click="emit('back')">← К сертификатам</button>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else-if="!data" class="state">Загрузка…</div>
    <template v-else>
      <div class="page-heading"><div><p class="muted"><code>{{ data.certificate.sha256 }}</code></p></div><button class="btn" @click="load">Обновить</button></div>
      <div class="panel">
        <CertificateOwner :certificate="data.certificate" />
        <details class="certificate-technical"><summary>Реквизиты сертификата</summary>
        <div class="two-column">
          <dl class="facts">
            <dt>Полное имя владельца</dt><dd>{{ data.certificate.subject || '—' }}</dd>
            <dt>Издатель</dt><dd>{{ data.certificate.issuer || '—' }}</dd>
            <dt>Номер</dt><dd><code>{{ data.certificate.serial_hex || data.certificate.serial_number || '—' }}</code></dd>
            <dt>Действует с</dt><dd>{{ formatDate(data.certificate.not_before) }}</dd>
            <dt>Действует до</dt><dd>{{ formatDate(data.certificate.not_after) }}</dd>
          </dl>
          <dl class="facts">
            <dt>Владелец CN</dt><dd>{{ data.certificate.owner_cn || '—' }}</dd>
            <dt>ИНН</dt><dd>{{ data.certificate.inn || '—' }}</dd>
            <dt>СНИЛС</dt><dd>{{ data.certificate.snils || '—' }}</dd>
            <dt>Встроенная лицензия</dt><dd><EmbeddedLicenseBadge :value="data.certificate.embedded_license" /></dd>
            <dt>Обновлён</dt><dd>{{ formatTime(data.certificate.updated_at) }}</dd>
          </dl>
        </div>
        </details>
      </div>
      <div class="panel">
        <h3>Места обнаружения</h3>
        <div v-if="!data.observations.length" class="muted">Наблюдений нет.</div>
        <table v-else class="data-table"><thead><tr><th>Машина</th><th>Пользователь</th><th>Источник</th><th>Файл</th><th>Состояние</th><th>Последний раз</th></tr></thead>
          <tbody><tr v-for="o in data.observations" :key="o.observation_id">
            <td><button class="link-button" @click="emit('open-machine', o.machine_id)">{{ o.machine_name }}</button><div class="small muted">{{ o.machine_id }}</div></td>
            <td>{{ o.user_name || 'системный/файловый' }}<div class="small muted"><code>{{ o.user_sid || '' }}</code></div></td>
            <td>{{ o.source_type }}<div class="small muted">{{ o.source_key }}</div></td>
            <td class="small">{{ o.file_path || '—' }}</td>
            <td><span class="badge" :class="o.active ? 'badge-ok' : 'badge-neutral'">{{ o.active ? 'активно' : 'удалено' }}</span></td>
            <td>{{ formatTime(o.last_seen_at) }}</td>
          </tr></tbody>
        </table>
      </div>
    </template>
  </section>
</template>
