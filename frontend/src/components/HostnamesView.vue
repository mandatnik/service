<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { formatTime } from '../format'
import ErrorState from './ErrorState.vue'
import EmptyState from './EmptyState.vue'
const emit = defineEmits(['open-machine'])
const data = ref([])
const error = ref('')
const loading = ref(false)
async function load() {
  loading.value = true; error.value = ''
  try { const result = await api.hostnames(); data.value = result.items || [] } catch (e) { error.value = e.message } finally { loading.value = false }
}
onMounted(load)
useAutoRefresh(load, () => loading.value)
</script>
<template>
  <section>
    <div class="page-heading"><div><p class="muted">Резервирование имён машин. Перепривязка выполняется из карточки машины и фиксируется событием.</p></div><button class="btn" @click="load">Обновить</button></div>
    <ErrorState v-if="error" :message="error" @retry="load" />
    <div v-else class="panel table-panel">
      <div v-if="loading && !data.length" class="state">Загрузка…</div>
      <EmptyState v-else-if="!data.length" title="Hostname не зарезервированы" text="Имена появятся после регистрации агентов." />
      <table v-else class="data-table"><thead><tr><th>Hostname</th><th>Владелец</th><th>Конкурирующие регистрации</th></tr></thead>
        <tbody><tr v-for="h in data" :key="h.hostname_norm" :class="{ 'row-warning': h.competing.length }">
          <td><strong>{{ h.hostname_norm }}</strong><div class="small muted">{{ h.display_name }}</div></td>
          <td><button v-if="h.owner_machine_id" class="link-button" @click="emit('open-machine', h.owner_machine_id)">{{ h.owner_display_name || h.owner_machine_id }}</button><span v-else class="muted">не назначен</span><div class="small muted">reg {{ h.owner_registration_id || '—' }}</div></td>
          <td><span v-if="!h.competing.length" class="badge badge-ok">нет</span><div v-for="c in h.competing" :key="c.registration_id" class="small"><span class="badge badge-warning">конфликт</span> <button class="link-button" @click="emit('open-machine', c.machine_id)">{{ c.display_name }}</button> · reg {{ c.registration_id }}</div></td>
        </tr></tbody>
      </table>
    </div>
  </section>
</template>
