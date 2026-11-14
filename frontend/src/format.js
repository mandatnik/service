export function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' })
}

export function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleDateString('ru-RU')
}

export function timeAgo(value) {
  if (!value) return 'нет связи'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000))
  if (seconds < 60) return 'только что'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин назад`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} ч назад`
  return `${Math.floor(seconds / 86400)} дн назад`
}

export function licenseKindLabel(kind, raw) {
  if (kind === 'client') return 'Клиентская'
  if (kind === 'server') return 'Серверная'
  if (kind === 'unknown') return 'Не определено'
  return 'Не собрано'
}

export function stateLabel(value) {
  const map = {
    active: 'активна', expired: 'истекла', not_yet_valid: 'ещё не действует',
    unknown: 'неизвестно', valid: 'действительна', invalid: 'недействительна',
    complete: 'полный', partial: 'частичный', empty: 'пустой',
    pending: 'ожидает', delivered: 'доставлено', completed: 'выполнено',
    not_installed: 'Не установлен', missing: 'Отсутствует', perpetual: 'Бессрочная',
    failed: 'ошибка', revoked: 'отозвана', replaced: 'заменена'
  }
  return map[value] || value || '—'
}

export function trialLabel(value) {
  return ({ yes: 'Пробная', no: 'Обычная', true: 'Пробная', false: 'Обычная', unknown: 'Не определено' })[value] || 'Не определено'
}
export function licenseExpiry(license) {
  if (license.term_kind === 'perpetual' || license.term_kind === 'unlimited') return 'Бессрочно'
  if (license.valid_to_utc) return formatDate(license.valid_to_utc)
  if (license.valid_to_raw) return formatDate(license.valid_to_raw)
  return 'Не определён'
}
