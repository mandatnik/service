import { formatDate, pluralRu } from './format.js'

// Normalize only all-uppercase personal names. Company spelling is preserved.
export function personalName(value) {
  const name = String(value || '').trim()
  if (!name || name !== name.toLocaleUpperCase('ru-RU') || name === name.toLocaleLowerCase('ru-RU')) return name
  return name.toLocaleLowerCase('ru-RU').replace(/(^|[^\p{L}\p{M}])(\p{L})/gu, (_, prefix, letter) => prefix + letter.toLocaleUpperCase('ru-RU'))
}

export function certificateParty(certificate, issuer = false) {
  const details = issuer ? certificate.issuer_details || {} : certificate.owner_details || {}
  const cn = details.common_name || (issuer ? certificate.issuer_cn : certificate.owner_cn) || ''
  const organization = details.organization || (!issuer ? certificate.organization : '') || ''
  const legal = details.legal_entity === true
  const title = details.title || ''
  const person = personalName(details.person_name || '')
  const primary = (issuer || legal ? cn : personalName(cn)) || organization || (issuer ? 'УЦ не указан' : 'Владелец не указан')
  // A legal entity's CN already names the company; the subtitle names its representative.
  const subtitle = legal && !issuer && person && person !== primary
    ? `${title || 'Представитель'}: ${person}`
    : [title, organization && organization !== cn ? organization : ''].filter(Boolean).join(', ')
  const inn = details.inn || (!issuer ? certificate.inn : '')
  const badges = [
    ['ИННЮЛ', details.inn_legal],
    [legal || details.inn_legal ? 'ИННФЛ' : 'ИНН', inn],
    ['СНИЛС', details.snils || (!issuer ? certificate.snils : '')],
    ['ОГРН', details.ogrn], ['ОГРНИП', details.ogrnip], ['КПП', details.kpp],
    ['Почта', details.email]
  ].filter(([, value]) => value).map(([label, value]) => ({ label, value, href: label === 'Почта' ? `mailto:${encodeURIComponent(value)}` : '' }))
  return { primary, subtitle, badges }
}

export function certificateValidity(certificate, now = Date.now()) {
  const before = certificate.not_before ? new Date(certificate.not_before).getTime() : NaN
  const after = certificate.not_after ? new Date(certificate.not_after).getTime() : NaN
  const period = `С ${formatDate(certificate.not_before)} по ${formatDate(certificate.not_after)}`
  let status = { label: 'Не определён', tone: 'neutral' }
  if (certificate.revocation_status === 'revoked') status = { label: 'Отозван', tone: 'danger' }
  else if (Number.isFinite(after) && after < now) status = { label: 'Истёк', tone: 'danger' }
  else if (Number.isFinite(before) && before > now) status = { label: 'Не вступил', tone: 'neutral' }
  else if (Number.isFinite(before) && Number.isFinite(after)) status = { label: 'Действующий', tone: 'ok' }
  let remaining = 'Срок не указан'
  if (Number.isFinite(after)) {
    const days = Math.max(0, Math.ceil((after - now) / 86400000))
    remaining = after < now ? 'Истёк' : `Осталось: ${days} ${pluralRu(days, ['день', 'дня', 'дней'])}`
  }
  return { period, remaining, ...status }
}

export function certificateLocations(certificate) {
  const machines = Number(certificate.machines || 0)
  return {
    registry: Number(certificate.registry_machines || 0),
    files: Number(certificate.file_machines || 0),
    total: `${machines} ${pluralRu(machines, ['место обнаружения', 'места обнаружения', 'мест обнаружения'])}`
  }
}
