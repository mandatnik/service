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

export function pluralRu(count, forms) {
  const value = Math.abs(Math.trunc(count))
  const tail = value % 100
  if (tail > 10 && tail < 20) return forms[2]
  const last = tail % 10
  if (last === 1) return forms[0]
  if (last >= 2 && last <= 4) return forms[1]
  return forms[2]
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

export function timeAgoDetailed(value, now = Date.now()) {
  if (!value) return 'нет данных'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  const seconds = Math.max(0, Math.floor((now - date.getTime()) / 1000))
  if (seconds < 60) return 'только что'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} ${pluralRu(minutes, ['минуту', 'минуты', 'минут'])} назад`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} ${pluralRu(hours, ['час', 'часа', 'часов'])} назад`
  const days = Math.floor(hours / 24)
  return `${days} ${pluralRu(days, ['день', 'дня', 'дней'])} назад`
}

export function licenseKindLabel(kind, raw) {
  if (kind === 'client') return 'Клиентская'
  if (kind === 'server') return 'Серверная'
  if (kind === 'unknown') return 'Не определено'
  return 'Не собрано'
}

export function cspKindLabel(kind) {
  if (kind === 'client') return 'Клиентский'
  if (kind === 'server') return 'Серверный'
  return 'Тип не определён'
}

export function stateLabel(value) {
  const map = {
    active: 'активна', expired: 'истекла', not_yet_valid: 'ещё не действует',
    unknown: 'неизвестно', valid: 'действительна', invalid: 'недействительна',
    complete: 'полный', partial: 'частичный', empty: 'пустой',
    pending: 'ожидает', delivered: 'доставлено', completed: 'выполнено',
    not_installed: 'Не установлен', missing: 'Отсутствует', perpetual: 'Бессрочная',
    failed: 'ошибка', revoked: 'отозвана', replaced: 'заменена', renamed: 'переименована'
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

export function badgeClass(tone) {
  return ({ ok: 'badge-ok', warning: 'badge-warning', danger: 'badge-error', neutral: 'badge-neutral' })[tone] || 'badge-neutral'
}

export function machineDisplayName(machine) {
  const name = String(machine?.display_name || '').trim()
  if (name) return name
  return machine?.uuid || machine?.machine_id || '—'
}

export function onlineView(machine, now = Date.now()) {
  const subtext = timeAgoDetailed(machine?.last_seen_at, now)
  if (machine?.offline) return { label: 'Не в сети', tone: 'neutral', subtext }
  return { label: 'В сети', tone: 'ok', subtext }
}

export function cspView(machine) {
  if (!machine?.csp_present) {
    return { label: 'Не найден', subtext: 'КриптоПро CSP не обнаружен', tone: 'danger', server: false }
  }
  const version = machine.product_version || machine.core_version || ''
  const subtext = [cspKindLabel(machine.license_kind), version].filter(Boolean).join(' · ')
  return {
    label: 'КриптоПро CSP',
    subtext: subtext || 'Версия не собрана',
    tone: machine.license_kind === 'server' ? 'danger' : 'ok',
    server: machine.license_kind === 'server'
  }
}

function licenseDate(machine) {
  return machine?.license_valid_to || ''
}

function trialFlag(value) {
  const normalized = String(value || '').toLowerCase()
  return normalized === 'true' || normalized === 'yes'
}

function daysRemaining(value, now) {
  const time = new Date(value).getTime()
  if (Number.isNaN(time)) return null
  return Math.max(0, Math.ceil((time - now) / 86400000))
}

export function licenseView(machine, now = Date.now()) {
  const state = machine?.license_state || ''
  const validTo = licenseDate(machine)
  const date = validTo ? formatDate(validTo) : ''
  if (state === 'active') {
    if (trialFlag(machine?.is_trial)) {
      return { label: 'Пробная', tone: 'warning', lines: activeLicenseLines(machine, validTo, date, now) }
    }
    return { label: 'Активная', tone: 'ok', lines: activeLicenseLines(machine, validTo, date, now) }
  }
  if (state === 'expired') {
    return { label: 'Истекла', tone: 'danger', lines: [date || 'Срок не определён'] }
  }
  if (state === 'not_yet_valid') {
    return { label: 'Ещё не действует', tone: 'warning', lines: date ? [`до ${date}`] : [] }
  }
  return { label: 'Не найдена', tone: 'neutral', lines: [] }
}

function activeLicenseLines(machine, validTo, date, now) {
  if (machine?.term_kind === 'perpetual' || machine?.term_kind === 'unlimited') return ['Бессрочная']
  if (!validTo || !date) return ['Срок не определён']
  const days = daysRemaining(validTo, now)
  if (days === null) return [`до ${date}`]
  return [`до ${date}`, `Осталось ${days} ${pluralRu(days, ['день', 'дня', 'дней'])}`]
}

export function certificatesView(machine) {
  const registry = Number(machine?.registry_certificates || 0)
  const files = Number(machine?.file_certificates || 0)
  const licensed = Number(machine?.licensed_certificates || 0)
  return {
    primary: `${registry} реестр, ${files} файлы`,
    secondary: `с лицензией: ${licensed}`
  }
}

export function groupBadges(groups, limit = 2) {
  const list = Array.isArray(groups) ? groups.filter(group => group && group.name) : []
  const visible = list.slice(0, Math.max(0, limit))
  const hidden = list.slice(visible.length)
  return {
    visible,
    hidden,
    overflow: hidden.length,
    tooltip: list.map(group => group.name).join(', ')
  }
}

export function machineStatusView(status, offline = false) {
  if (status === 'ok' && offline) return { label: 'В норме', tone: 'neutral' }
  const labels = {
    csp_missing: { label: 'CSP не установлен', tone: 'danger' },
    trial: { label: 'Пробная версия', tone: 'warning' },
    license_required: { label: 'Требуется лицензия', tone: 'danger' },
    ok: { label: 'Работает', tone: 'ok' }
  }
  return labels[status] || { label: '—', tone: 'neutral' }
}

export function machineRowView(machine, now = Date.now()) {
  return {
    name: machineDisplayName(machine),
    uuid: machine?.uuid || machine?.machine_id || '—',
    hostname: machine?.hostname || '—',
    ip: machine?.source_ip || 'IP не собран',
    online: onlineView(machine, now),
    csp: cspView(machine),
    groups: groupBadges(machine?.groups || []),
    license: licenseView(machine, now),
    certificates: certificatesView(machine),
    status: machineStatusView(machine?.status, machine?.offline)
  }
}
