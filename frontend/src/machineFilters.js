export const monitoringLabels = {
  online: 'Машины онлайн',
  active_license: 'С активной лицензией',
  needs_license: 'Нуждаются в лицензии',
  csp_missing: 'Без КриптоПро',
  expired_certificates: 'Сертификаты истекли за последний месяц, замена по ИНН не найдена'
}
export const emptyMachineFilters = () => ({ query: '', status: 'active', monitor: '', as_of: '', name: '', hostname: '', source_ip: '', connection: '', csp: '', group_id: '', license: '', certificate: '', machine_status: '' })
export function normalizeMachineFilters(source = {}) {
  const filters = emptyMachineFilters()
  for (const key of Object.keys(filters)) if (typeof source[key] === 'string') filters[key] = source[key]
  if (filters.monitor && !monitoringLabels[filters.monitor]) filters.monitor = ''
  return filters
}
export function readMachineFilters(search = '') {
  return normalizeMachineFilters(Object.fromEntries(new URLSearchParams(search)))
}
export function machineFilterSearch(source = {}) {
  const filters = normalizeMachineFilters(source)
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    // Empty status explicitly means all cards; omitted status means current.
    if (key === 'status') { if (value !== 'active') params.set(key, value) }
    else if (value) params.set(key, value)
  }
  return params.size ? `?${params}` : ''
}
