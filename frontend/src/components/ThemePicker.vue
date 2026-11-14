<script setup>
import { ref, watch, onUnmounted } from 'vue'
const system = window.matchMedia('(prefers-color-scheme: dark)')
const preference = ref('system')
try { const stored = localStorage.getItem('admin-theme'); if (['light', 'dark'].includes(stored)) preference.value = stored } catch {}
function apply() { document.documentElement.dataset.theme = preference.value === 'system' ? (system.matches ? 'dark' : 'light') : preference.value }
watch(preference, () => {
  try { localStorage.setItem('admin-theme', preference.value) } catch {}
  apply()
})
system.addEventListener('change', apply)
function sync(event) {
  if (event.key === 'admin-theme' || event.key === null) {
    preference.value = ['light', 'dark'].includes(event.newValue) ? event.newValue : 'system'
    apply()
  }
}
window.addEventListener('storage', sync)
onUnmounted(() => { system.removeEventListener('change', apply); window.removeEventListener('storage', sync) })
apply()
</script>
<template>
  <label class="theme-picker"><span>Тема</span><select v-model="preference" aria-label="Цветовая тема"><option value="system">Системная</option><option value="light">Светлая</option><option value="dark">Тёмная</option></select></label>
</template>
