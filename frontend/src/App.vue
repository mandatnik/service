<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api, setCSRF } from './api'
import { adminDisplayName, adminInitial, adminRoleLabel } from './identity'
import AppFooter from './components/AppFooter.vue'
import BrandLogo from './components/BrandLogo.vue'
import ThemePicker from './components/ThemePicker.vue'
import NavIcon from './components/NavIcon.vue'
import Login from './components/Login.vue'
import OverviewView from './components/OverviewView.vue'
import MachinesView from './components/MachinesView.vue'
import MachineDetail from './components/MachineDetail.vue'
import CertificatesView from './components/CertificatesView.vue'
import CertificateDetail from './components/CertificateDetail.vue'
import LicensingView from './components/LicensingView.vue'
import LicensePoolsView from './components/LicensePoolsView.vue'
import TasksView from './components/TasksView.vue'
import HostnamesView from './components/HostnamesView.vue'
import EventsView from './components/EventsView.vue'
import SettingsView from './components/SettingsView.vue'
import GroupsView from './components/GroupsView.vue'
import PoliciesView from './components/PoliciesView.vue'
import ApiKeysView from './components/ApiKeysView.vue'

const session = ref(null)
const checking = ref(true)
const bootError = ref('')
const sessionNotice = ref('')
const view = ref('overview')
const menuOpen = ref(false)
const machineId = ref('')
const certificateSha = ref('')
const groupFocusId = ref('')
let expiryTimer = null

const nav = [
  { id: 'overview', label: 'Обзор', hint: 'Сводка' },
  { id: 'machines', label: 'Машины', hint: 'Агенты и профили' },
  { id: 'groups', label: 'Группы машин', hint: 'Состав групп' },
  { id: 'policies', label: 'Политики папок', hint: 'Правила и назначения' },
  { id: 'certificates', label: 'Сертификаты', hint: 'Наблюдения' },
  { id: 'licensing', label: 'Лицензии', hint: 'КриптоПро CSP' },
  { id: 'license-pools', label: 'Пулы лицензий', hint: 'Ключи и резервы' },
  { id: 'tasks', label: 'Задачи', hint: 'Сбор и установка' },
  { id: 'hostnames', label: 'Имена машин', hint: 'Конфликты' },
  { id: 'events', label: 'События', hint: 'Диагностика' },
  { id: 'api-keys', label: 'API-ключи', hint: 'Интеграции' },
  { id: 'settings', label: 'Настройки', hint: 'Сбор' }
]
const titles = {
  groups: 'Группы машин', policies: 'Политики папок',
  overview: 'Обзор', machines: 'Рабочие машины', machine: 'Карточка машины',
  certificates: 'Сертификаты', certificate: 'Карточка сертификата', licensing: 'Лицензирование',
  'license-pools': 'Пулы лицензий', tasks: 'Задачи',
  hostnames: 'Hostname и конфликты', events: 'События', 'api-keys': 'API-ключи интеграций',
  settings: 'Настройки сбора'
}
const title = computed(() => titles[view.value] || 'Админка')
const adminName = computed(() => adminDisplayName(session.value))
const adminLetter = computed(() => adminInitial(session.value))
const adminRole = computed(() => adminRoleLabel(session.value?.role))

async function checkSession() {
  checking.value = true
  bootError.value = ''
  const hadSession = !!session.value
  try {
    const result = await api.session()
    setCSRF(result.csrf_token)
    session.value = result
    armExpiry(result)
  } catch (e) {
    if (e.status === 401) {
      session.value = null
      if (hadSession) sessionNotice.value = 'Сеанс истёк. Войдите снова.'
    } else {
      bootError.value = e.message
    }
  } finally {
    checking.value = false
  }
}
function armExpiry(result) {
  if (expiryTimer) clearTimeout(expiryTimer)
  const remaining = new Date(result.expires_at).getTime() - Date.now()
  if (remaining > 0) expiryTimer = setTimeout(() => unauthorized(), Math.min(remaining + 250, 2147480000))
}
function loggedIn(result) {
  session.value = result
  sessionNotice.value = ''
  view.value = 'overview'
  machineId.value = ''
  certificateSha.value = ''
  groupFocusId.value = ''
  armExpiry(result)
}
async function logout() {
  try { await api.logout() } catch (e) { /* session may already be gone */ }
  if (expiryTimer) clearTimeout(expiryTimer)
  session.value = null
  sessionNotice.value = 'Вы вышли из админки.'
  view.value = 'overview'
  groupFocusId.value = ''
}
function navigate(next) {
  menuOpen.value = false
  view.value = next
  machineId.value = ''
  certificateSha.value = ''
  groupFocusId.value = ''
}
function openMachine(id) { machineId.value = id; view.value = 'machine' }
function openCertificate(sha) { certificateSha.value = sha; view.value = 'certificate' }
function openGroup(id) { groupFocusId.value = id; machineId.value = ''; certificateSha.value = ''; view.value = 'groups' }
function unauthorized() {
  if (session.value) {
    if (expiryTimer) clearTimeout(expiryTimer)
    session.value = null
    sessionNotice.value = 'Сеанс истёк. Войдите снова.'
  }
}
onMounted(() => {
  window.addEventListener('telehack:unauthorized', unauthorized)
  checkSession()
})
onUnmounted(() => {
  window.removeEventListener('telehack:unauthorized', unauthorized)
  if (expiryTimer) clearTimeout(expiryTimer)
})
</script>

<template>
  <a v-if="session" class="skip-link" href="#main-content">К содержимому</a>
  <div v-if="checking" class="boot-screen"><div class="spinner"></div><p>Проверка сеанса…</p></div>
  <div v-else-if="bootError" class="boot-screen">
    <div class="boot-error"><strong>Backend недоступен</strong><p>{{ bootError }}</p><button class="btn btn-primary" @click="checkSession">Повторить</button></div>
  </div>
  <Login v-else-if="!session" :notice="sessionNotice" @logged-in="loggedIn" />
  <div v-else class="app-shell">
    <aside id="main-navigation" class="sidebar" :class="{ 'is-open': menuOpen }">
      <div class="sidebar-brand"><BrandLogo /><div><div class="brand-name">Мандатник</div><div class="sidebar-subtitle">Инвентаризация сертификатов</div></div></div>
      <div class="nav-caption">Рабочее пространство</div>
      <nav class="nav" aria-label="Основная навигация">
        <button v-for="item in nav" :key="item.id" class="nav-item" :class="{ active: view === item.id || (item.id === 'machines' && view === 'machine') || (item.id === 'certificates' && view === 'certificate') }" :aria-current="(view === item.id || (item.id === 'machines' && view === 'machine') || (item.id === 'certificates' && view === 'certificate')) ? 'page' : undefined" @click="navigate(item.id)">
          <NavIcon :name="item.id" /><span>{{ item.label }}</span>
        </button>
      </nav>
      <div class="sidebar-footer">
        <div class="user-chip"><span class="avatar">{{ adminLetter }}</span><div><strong>{{ adminName }}</strong><small>{{ adminRole }}</small></div></div>
        <button class="btn btn-quiet btn-wide" @click="logout">Выйти</button>
      </div>
    </aside>
    <main id="main-content" class="content" tabindex="-1">
      <header class="topbar">
        <div class="topbar-title"><button class="btn menu-toggle" aria-controls="main-navigation" :aria-expanded="menuOpen" @click="menuOpen = !menuOpen"><NavIcon name="menu" /> Меню</button><div><span class="eyebrow">Инвентаризация / {{ title }}</span><h1>{{ title }}</h1></div></div>
        <ThemePicker />
      </header>
      <div class="content-body">
        <OverviewView v-if="view === 'overview'" @navigate="navigate" />
        <MachinesView v-else-if="view === 'machines'" @open-machine="openMachine" @open-group="openGroup" />
        <MachineDetail v-else-if="view === 'machine'" :machine-id="machineId" @back="navigate('machines')" @open-machine="openMachine" />
        <CertificatesView v-else-if="view === 'certificates'" @open-certificate="openCertificate" />
        <CertificateDetail v-else-if="view === 'certificate'" :sha256="certificateSha" @back="navigate('certificates')" @open-machine="openMachine" />
        <LicensingView v-else-if="view === 'licensing'" />
        <LicensePoolsView v-else-if="view === 'license-pools'" />
        <TasksView v-else-if="view === 'tasks'" />
        <HostnamesView v-else-if="view === 'hostnames'" @open-machine="openMachine" />
        <EventsView v-else-if="view === 'events'" />
        <GroupsView v-else-if="view === 'groups'" :focus-group-id="groupFocusId" @clear-focus="groupFocusId = ''" />
        <PoliciesView v-else-if="view === 'policies'" />
        <ApiKeysView v-else-if="view === 'api-keys'" />
        <SettingsView v-else-if="view === 'settings'" />
      </div>
      <AppFooter />
    </main>
  </div>
</template>
