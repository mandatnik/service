const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// Mirrors the server-side rules closely enough to catch mistakes before a
// request. The server remains authoritative for email/display-name limits.
export function validateAdminForm(form, creating) {
  const email = String(form?.email || '').trim()
  const displayName = String(form?.display_name || '').trim()
  const password = String(form?.password || '')
  if (!email) return 'Укажите email администратора.'
  if (!emailPattern.test(email)) return 'Укажите корректный email администратора.'
  if (!displayName) return 'Укажите ФИО администратора.'
  if (creating && !password) return 'Укажите пароль администратора.'
  if (password && password.length < 12) return 'Пароль должен содержать не менее 12 символов.'
  return ''
}
