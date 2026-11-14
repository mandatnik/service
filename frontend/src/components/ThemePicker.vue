<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import {
  THEME_DARK,
  THEME_STORAGE_KEY,
  applyTheme,
  browserStorage,
  initialTheme,
  oppositeTheme,
  readStoredTheme,
  storeTheme
} from '../theme'

const media = window.matchMedia('(prefers-color-scheme: dark)')
const theme = ref(initialTheme(browserStorage(), () => media))
const isDark = computed(() => theme.value === THEME_DARK)
const actionLabel = computed(() => isDark.value ? 'Включить светлую тему' : 'Включить тёмную тему')

function syncFromPreference() {
  theme.value = initialTheme(browserStorage(), () => media)
  applyTheme(theme.value, document.documentElement)
}

function toggle() {
  theme.value = oppositeTheme(theme.value)
  applyTheme(theme.value, document.documentElement)
  storeTheme(theme.value, browserStorage())
}

function onSystemChange() {
  if (!readStoredTheme(browserStorage())) syncFromPreference()
}

function onStorage(event) {
  if (event.key !== null && event.key !== THEME_STORAGE_KEY) return
  syncFromPreference()
}

onMounted(() => {
  syncFromPreference()
  media.addEventListener('change', onSystemChange)
  window.addEventListener('storage', onStorage)
})

onUnmounted(() => {
  media.removeEventListener('change', onSystemChange)
  window.removeEventListener('storage', onStorage)
})
</script>

<template>
  <button
    type="button"
    class="theme-toggle"
    :class="{ 'is-dark': isDark }"
    :aria-label="actionLabel"
    :aria-pressed="isDark"
    :title="actionLabel"
    @click="toggle"
  >
    <svg v-if="isDark" class="theme-icon theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
    </svg>
    <svg v-else class="theme-icon theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  </button>
</template>
