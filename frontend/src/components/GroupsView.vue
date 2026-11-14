<script setup>
import { useAutoRefresh } from '../autoRefresh'
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { api } from '../api'
import AssignmentsEditor from './AssignmentsEditor.vue'
const props = defineProps({ focusGroupId: { type: String, default: '' } })
const emit = defineEmits(['clear-focus'])
const data = ref({ groups: [], machines: [], policies: [] })
const editing = ref(null), error = ref(''), busy = ref(false), message = ref('')
const scanBusy = ref(false)
const focusedGroup = computed(() => data.value.groups.find(group => group.id === props.focusGroupId))
function scrollToFocus() {
  if (!props.focusGroupId) return
  document.getElementById(`group-${props.focusGroupId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}
async function load() { try { data.value = await api.inventorySettings(); await nextTick(); scrollToFocus() } catch (e) { error.value = e.message } }
watch(() => props.focusGroupId, scrollToFocus)
async function startScan(group) {
  scanBusy.value = true; error.value = ''; message.value = ''
  try { const task = await api.createTask({ kind: 'scan', machine_ids: [], group_ids: [group.id], idempotency_key: crypto.randomUUID() }); message.value = `Задача scan создана: ${task.task.id}.` } catch (e) { error.value = e.message } finally { scanBusy.value = false }
}
function edit(group) { error.value = ''; message.value = ''; editing.value = group ? { ...group, machine_ids: [...group.machine_ids] } : { name: '', machine_ids: [] } }
async function save() { busy.value = true; error.value = ''; try { await api.saveGroup(editing.value); editing.value = null; await load(); message.value = 'Группа сохранена. Политики получат все её машины.' } catch (e) { error.value = e.message } finally { busy.value = false } }
async function remove(group) { if (!confirm(`Удалить группу «${group.name}»? Машины останутся в системе, назначения политик этой группе будут удалены.`)) return; busy.value = true; error.value = ''; try { await api.deleteGroup(group.id); await load() } catch (e) { error.value = e.message } finally { busy.value = false } }
const names = group => data.value.machines.filter(m => group.machine_ids.includes(m.id)).map(m => m.name).join(', ')
onMounted(load)
useAutoRefresh(load, () => busy.value || scanBusy.value || !!editing.value)
</script>
<template><section>
  <div class="page-heading"><p class="muted">Машина может состоять в нескольких группах. Политики группы применяются ко всем её участникам.</p><button class="btn btn-primary" :disabled="busy" @click="edit()">Создать группу</button></div>
  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div><div v-if="message" class="alert alert-success">{{ message }}</div>
  <div v-if="focusedGroup" class="alert alert-info">Открыта группа «{{ focusedGroup.name }}». <button class="link-button" type="button" @click="emit('clear-focus')">Показать все группы</button></div>
  <form v-if="editing" class="panel settings-form" @submit.prevent="save"><h3>{{ editing.id ? 'Редактирование группы' : 'Новая группа' }}</h3><label class="field"><span>Название</span><input v-model="editing.name" maxlength="200" required /></label><AssignmentsEditor v-model="editing.machine_ids" :items="data.machines" label="Рабочие машины" /><div class="heading-actions"><button class="btn btn-primary" :disabled="busy">Сохранить</button><button type="button" class="btn" :disabled="busy" @click="editing = null">Отмена</button></div></form>
  <div class="panel table-panel"><div v-if="!data.groups.length" class="state">Групп пока нет. Создайте группу здесь или добавьте выбранные машины в группу из таблицы машин.</div><table v-else class="data-table"><thead><tr><th>Группа</th><th>Машины</th><th>Политики</th><th></th></tr></thead><tbody><tr v-for="group in data.groups" :key="group.id" :id="`group-${group.id}`" :class="{ 'row-focus': focusGroupId === group.id }"><td><strong>{{ group.name }}</strong></td><td>{{ group.machine_ids.length }}<div class="small muted group-members-preview">{{ names(group) }}</div></td><td>{{ data.policies.filter(p => p.group_ids.includes(group.id)).map(p => p.name).join(', ') || 'Не назначены' }}</td><td><div class="heading-actions"><button class="btn" :disabled="scanBusy || !group.machine_ids.length" @click="startScan(group)">Scan</button><button class="btn" :disabled="busy" @click="edit(group)">Изменить</button><button class="btn btn-danger" :disabled="busy" @click="remove(group)">Удалить</button></div></td></tr></tbody></table></div>

</section></template>
