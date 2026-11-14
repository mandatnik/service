<script setup>
import { ref } from 'vue'
import { api, setCSRF } from '../api'
const props = defineProps({ notice: { type: String, default: '' } })
const emit = defineEmits(['logged-in'])
const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')
async function submit() {
  error.value = ''
  busy.value = true
  try {
    const result = await api.login(username.value, password.value)
    setCSRF(result.csrf_token)
    emit('logged-in', result)
  } catch (e) {
    error.value = e.message || 'Не удалось войти'
  } finally {
    busy.value = false
  }
}
</script>
<template>
  <div class="login-screen">
    <div class="login-brand">
      <div class="brand-mark">TH</div>
      <div>
        <div class="brand-name">Telehack 2026</div>
        <div class="muted">Инвентаризация сертификатов</div>
      </div>
    </div>
    <form class="login-card" @submit.prevent="submit">
      <h1>Вход администратора</h1>
      <p class="muted">Локальная учётная запись. Соединение защищено HTTPS.</p>
      <div v-if="notice" class="alert alert-info">{{ notice }}</div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <label class="field">
        <span>Логин</span>
        <input v-model="username" autocomplete="username" required autofocus />
      </label>
      <label class="field">
        <span>Пароль</span>
        <input v-model="password" type="password" autocomplete="current-password" required />
      </label>
      <button class="btn btn-primary btn-wide" :disabled="busy">{{ busy ? 'Проверка…' : 'Войти' }}</button>
      <p class="login-help muted">Учётные записи создаются администратором напрямую в базе данных.</p>
    </form>
  </div>
</template>
