<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api'
import AssignmentsEditor from './AssignmentsEditor.vue'
const data = ref({ groups: [], machines: [], policies: [] })
const editing = ref(null), error = ref(''), busy = ref(false), message = ref('')
async function load() { try { data.value = await api.inventorySettings() } catch (e) { error.value = e.message } }
function edit(policy) { error.value = ''; message.value = ''; editing.value = policy ? { ...policy, machine_ids: [...policy.machine_ids], group_ids: [...policy.group_ids] } : { name: '', rules: '', machine_ids: [], group_ids: [] } }
async function save() { busy.value = true; error.value = ''; try { await api.savePolicy(editing.value); editing.value = null; await load(); message.value = 'Политика сохранена. Агенты получат изменения при следующем опросе, в течение 10 минут.' } catch (e) { error.value = e.message } finally { busy.value = false } }
async function remove(policy) { if (!confirm(`Удалить политику «${policy.name}» и её назначения?`)) return; busy.value = true; error.value = ''; try { await api.deletePolicy(policy.id); await load() } catch (e) { error.value = e.message } finally { busy.value = false } }
const targetNames = (ids, items) => items.filter(item => ids.includes(item.id)).map(item => item.name).join(', ')
onMounted(load)
</script>
<template><section>
  <div class="page-heading"><p class="muted">Каждая политика — список шаблонов папок для назначенных машин и групп. Сканируются только файлы .cer.</p><button class="btn btn-primary" :disabled="busy" @click="edit()">Создать политику</button></div>
  <details class="panel policy-help"><summary>Как работают правила и приоритеты</summary><p>Путь включает папку и её содержимое. Звёздочка * заменяет часть имени, ** — несколько уровней папок, ? — один символ, [abc] — один из символов. Строка с ! исключает папку. Внутри политики действует последнее подходящее правило. Пустые строки и комментарии с # пропускаются. Используйте абсолютные пути.</p><pre>C:/Users/*/AppData/testDir/
!C:/Users/*/AppData/testDir/trashFolder
C:/ProgramData/</pre><p>Результаты политик одного уровня объединяются независимо: исключение в одной не отменяет включение в другой. Исключения политик, назначенных машине напрямую, дополнительно отсекают файлы групповых политик. Без назначенных политик папки не сканируются; личные хранилища продолжают обследоваться.</p></details>
  <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div><div v-if="message" class="alert alert-success">{{ message }}</div>
  <form v-if="editing" class="panel settings-form" @submit.prevent="save"><h3>{{ editing.id ? 'Редактирование политики' : 'Новая политика' }}</h3><label class="field"><span>Название</span><input v-model="editing.name" maxlength="200" required /></label><label class="field"><span>Правила папок</span><textarea v-model="editing.rules" class="policy-rules" rows="8" maxlength="65536" required spellcheck="false" placeholder="C:/Certificates/&#10;!C:/Certificates/archive/" /></label><div class="two-column"><AssignmentsEditor v-model="editing.machine_ids" :items="data.machines" label="Машины — прямое назначение" /><AssignmentsEditor v-model="editing.group_ids" :items="data.groups" label="Группы машин" /></div><div class="heading-actions"><button class="btn btn-primary" :disabled="busy">Сохранить</button><button type="button" class="btn" :disabled="busy" @click="editing = null">Отмена</button></div></form>
  <div v-if="!data.policies.length" class="panel state">Политик пока нет. Папки на машинах не сканируются.</div>
  <article v-for="policy in data.policies" :key="policy.id" class="panel policy-card"><div class="page-heading"><h3>{{ policy.name }}</h3><div class="heading-actions"><button class="btn" :disabled="busy" @click="edit(policy)">Изменить</button><button class="btn btn-danger" :disabled="busy" @click="remove(policy)">Удалить</button></div></div><pre class="policy-rules-preview">{{ policy.rules }}</pre><div class="small"><strong>Машины: </strong>{{ targetNames(policy.machine_ids, data.machines) || 'Не назначены' }}</div><div class="small"><strong>Группы: </strong>{{ targetNames(policy.group_ids, data.groups) || 'Не назначены' }}</div><div v-if="!policy.machine_ids.length && !policy.group_ids.length" class="small muted">Политика сохранена без назначений и пока не применяется.</div></article>
</section></template>
