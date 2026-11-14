import test from 'node:test'
import assert from 'node:assert/strict'
import {
  badgeClass,
  certificatesView,
  cspView,
  formatDate,
  groupBadges,
  licenseView,
  machineDisplayName,
  machineRowView,
  machineStatusView,
  onlineView,
  pluralRu,
  timeAgoDetailed
} from './format.js'

const NOW = Date.parse('2026-11-14T12:00:00.000Z')
const isoMinutesAgo = minutes => new Date(NOW - minutes * 60000).toISOString()
const isoDaysAhead = days => new Date(NOW + days * 86400000).toISOString()

test('pluralRu selects Russian plural forms', () => {
  const forms = ['день', 'дня', 'дней']
  assert.equal(pluralRu(1, forms), 'день')
  assert.equal(pluralRu(2, forms), 'дня')
  assert.equal(pluralRu(5, forms), 'дней')
  assert.equal(pluralRu(11, forms), 'дней')
  assert.equal(pluralRu(21, forms), 'день')
  assert.equal(pluralRu(24, forms), 'дня')
})

test('timeAgoDetailed describes online and offline ages', () => {
  assert.equal(timeAgoDetailed(isoMinutesAgo(5), NOW), '5 минут назад')
  assert.equal(timeAgoDetailed(isoMinutesAgo(1), NOW), '1 минуту назад')
  assert.equal(timeAgoDetailed(isoMinutesAgo(120), NOW), '2 часа назад')
  assert.equal(timeAgoDetailed(isoMinutesAgo(60 * 24 * 3), NOW), '3 дня назад')
  assert.equal(timeAgoDetailed(isoMinutesAgo(60 * 24 * 21), NOW), '21 день назад')
  assert.equal(timeAgoDetailed(isoMinutesAgo(60 * 24 * 11), NOW), '11 дней назад')
  assert.equal(timeAgoDetailed(null, NOW), 'нет данных')
})

test('machineDisplayName falls back to UUID when the name is empty', () => {
  assert.equal(machineDisplayName({ display_name: 'WORKSTATION-1', uuid: 'uuid-1', machine_id: 'machine-1' }), 'WORKSTATION-1')
  assert.equal(machineDisplayName({ display_name: '  ', uuid: 'uuid-1', machine_id: 'machine-1' }), 'uuid-1')
  assert.equal(machineDisplayName({ display_name: '', uuid: '', machine_id: 'machine-1' }), 'machine-1')
})

test('onlineView renders connection labels and age', () => {
  const online = onlineView({ offline: false, last_seen_at: isoMinutesAgo(5) }, NOW)
  assert.deepEqual(online, { label: 'В сети', tone: 'ok', subtext: '5 минут назад' })
  const offline = onlineView({ offline: true, last_seen_at: isoMinutesAgo(60 * 25) }, NOW)
  assert.deepEqual(offline, { label: 'Не в сети', tone: 'neutral', subtext: '1 день назад' })
})

test('cspView highlights missing and server-side CryptoPro', () => {
  assert.deepEqual(cspView({ csp_present: false }), {
    label: 'Не найден',
    subtext: 'КриптоПро CSP не обнаружен',
    tone: 'danger',
    server: false
  })
  assert.deepEqual(cspView({ csp_present: true, license_kind: 'client', product_version: '5.0.13003' }), {
    label: 'КриптоПро CSP',
    subtext: 'Клиентский · 5.0.13003',
    tone: 'ok',
    server: false
  })
  assert.deepEqual(cspView({ csp_present: true, license_kind: 'server', product_version: '4.0.9963' }), {
    label: 'КриптоПро CSP',
    subtext: 'Серверный · 4.0.9963',
    tone: 'danger',
    server: true
  })
})

test('licenseView renders active, trial, expired and perpetual states', () => {
  assert.deepEqual(licenseView({ license_state: 'active', term_kind: 'perpetual' }, NOW), {
    label: 'Активная',
    tone: 'ok',
    lines: ['Бессрочная']
  })
  const trial = licenseView({
    license_state: 'active',
    is_trial: 'yes',
    term_kind: 'time_limited',
    license_valid_to: isoDaysAhead(30)
  }, NOW)
  assert.equal(trial.label, 'Пробная')
  assert.equal(trial.tone, 'warning')
  assert.deepEqual(trial.lines, [`до ${formatDate(isoDaysAhead(30))}`, 'Осталось 30 дней'])
  const expiredDate = isoMinutesAgo(60 * 24 * 30)
  assert.deepEqual(licenseView({ license_state: 'expired', license_valid_to: expiredDate }, NOW), {
    label: 'Истекла',
    tone: 'danger',
    lines: [formatDate(expiredDate)]
  })
  assert.deepEqual(licenseView({ license_state: 'not_installed' }, NOW), {
    label: 'Не найдена',
    tone: 'neutral',
    lines: []
  })
})

test('certificatesView renders registry, file and licensed counters', () => {
  assert.deepEqual(certificatesView({
    registry_certificates: 4,
    file_certificates: 2,
    licensed_certificates: 3
  }), {
    primary: '4 реестр, 2 файлы',
    secondary: 'с лицензией: 3'
  })
})

test('groupBadges limits visible groups and reports the hidden count', () => {
  const groups = ['Первая', 'Вторая', 'Третья', 'Четвёртая', 'Пятая'].map((name, index) => ({ id: `g${index}`, name }))
  const badges = groupBadges(groups, 2)
  assert.deepEqual(badges.visible.map(group => group.name), ['Первая', 'Вторая'])
  assert.equal(badges.overflow, 3)
  assert.equal(badges.tooltip, 'Первая, Вторая, Третья, Четвёртая, Пятая')
  assert.equal(groupBadges(groups.slice(0, 2), 2).overflow, 0)
  assert.equal(groupBadges([], 2).overflow, 0)
})

test('machineStatusView maps every status to the required label and colour', () => {
  assert.deepEqual(machineStatusView('csp_missing'), { label: 'CSP не установлен', tone: 'danger' })
  assert.deepEqual(machineStatusView('trial'), { label: 'Пробная версия', tone: 'warning' })
  assert.deepEqual(machineStatusView('license_required'), { label: 'Требуется лицензия', tone: 'danger' })
  assert.deepEqual(machineStatusView('ok'), { label: 'Работает', tone: 'ok' })
  assert.deepEqual(machineStatusView('ok', true), { label: 'В норме', tone: 'neutral' })
  assert.deepEqual(machineStatusView('csp_missing', true), { label: 'CSP не установлен', tone: 'danger' })
  assert.deepEqual(machineStatusView('trial', true), { label: 'Пробная версия', tone: 'warning' })
  assert.equal(badgeClass('danger'), 'badge-error')
})

test('machineRowView composes the whole table row', () => {
  const row = machineRowView({
    display_name: '',
    uuid: 'uuid-1',
    machine_id: 'machine-1',
    hostname: 'WORKSTATION-1',
    source_ip: '192.168.1.10',
    offline: false,
    last_seen_at: isoMinutesAgo(2),
    csp_present: true,
    license_kind: 'client',
    product_version: '5.0.13003',
    license_state: 'active',
    term_kind: 'perpetual',
    registry_certificates: 2,
    file_certificates: 1,
    licensed_certificates: 1,
    status: 'ok',
    groups: [{ id: 'g1', name: 'Бухгалтерия' }]
  }, NOW)
  assert.equal(row.name, 'uuid-1')
  assert.equal(row.uuid, 'uuid-1')
  assert.equal(row.online.label, 'В сети')
  assert.equal(row.csp.subtext, 'Клиентский · 5.0.13003')
  assert.equal(row.license.label, 'Активная')
  assert.equal(row.certificates.primary, '2 реестр, 1 файлы')
  assert.equal(row.status.label, 'Работает')
  assert.equal(row.groups.visible[0].name, 'Бухгалтерия')
})

test('machineRowView shows a gray normal status for an offline healthy machine', () => {
  const row = machineRowView({
    display_name: 'WORKSTATION-2',
    machine_id: 'machine-2',
    offline: true,
    last_seen_at: isoMinutesAgo(120),
    status: 'ok'
  }, NOW)
  assert.equal(row.online.label, 'Не в сети')
  assert.deepEqual(row.status, { label: 'В норме', tone: 'neutral' })
})
