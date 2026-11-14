<script setup>
import { ref } from 'vue'
import BrandLogo from './BrandLogo.vue'
import ThemePicker from './ThemePicker.vue'
import { api, setCSRF } from '../api'
defineProps({ notice: { type: String, default: '' } })
const emit = defineEmits(['logged-in'])
const email = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')
async function submit() {
  error.value = ''
  busy.value = true
  try {
    const result = await api.login(email.value, password.value)
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
    <div class="login-theme"><ThemePicker /></div>
    <div class="login-brand">
      <BrandLogo />
      <div>
        <div class="brand-name">Мандатник</div>
        <div class="muted">Инвентаризация сертификатов</div>
      </div>
    </div>
    <form class="login-card" @submit.prevent="submit">
      <h1>Вход администратора</h1>
      <p class="muted">Войдите, чтобы управлять машинами, сертификатами и лицензиями.</p>
      <div v-if="notice" class="alert alert-info">{{ notice }}</div>
      <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
      <label class="field">
        <span>Электронная почта</span>
        <input v-model="email" type="email" autocomplete="username" required autofocus />
      </label>
      <label class="field">
        <span>Пароль</span>
        <input v-model="password" type="password" autocomplete="current-password" required />
      </label>
      <button class="btn btn-primary btn-wide" :disabled="busy">{{ busy ? 'Проверка…' : 'Войти' }}</button>
      <p class="login-help muted">Нет доступа? Обратитесь к администратору системы.</p>
    </form>
  </div>
</template>
