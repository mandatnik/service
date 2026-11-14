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
    <main class="login-layout">
    <section class="login-brand" aria-labelledby="login-brand-name">
      <BrandLogo />
      <div>
        <h1 id="login-brand-name" class="brand-name">Мандатник</h1>
        <p class="login-description muted">Инвентаризация сертификатов</p>
      </div>
    </section>
    <section class="login-form-panel" aria-labelledby="login-title">
    <form class="login-card" aria-labelledby="login-title" @submit.prevent="submit">
      <h2 id="login-title">Вход</h2>
      <p class="muted">Войдите в рабочее пространство администратора.</p>
      <div v-if="notice" class="alert alert-info">{{ notice }}</div>
      <div v-if="error" class="alert alert-error" role="alert">{{ error }}</div>
      <label class="field">
        <span>Электронная почта</span>
        <input v-model="email" type="email" autocomplete="username" placeholder="name@example.ru" required autofocus />
      </label>
      <label class="field">
        <span>Пароль</span>
        <input v-model="password" type="password" autocomplete="current-password" placeholder="Введите пароль" required />
      </label>
      <button class="btn btn-primary btn-wide" :disabled="busy">{{ busy ? 'Проверка…' : 'Войти' }}</button>
      <p class="login-help muted">Нет доступа? Обратитесь к администратору системы.</p>
    </form>
    </section>
    </main>
  </div>
</template>
