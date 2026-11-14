export function adminDisplayName(session) {
  const displayName = typeof session?.display_name === 'string' ? session.display_name.trim() : ''
  if (displayName) return displayName
  const email = typeof session?.email === 'string' ? session.email.trim() : ''
  return email || 'Администратор'
}

export function adminInitial(session) {
  const name = adminDisplayName(session)
  return Array.from(name)[0]?.toUpperCase() || 'А'
}

export function adminRoleLabel(role) {
  return role === 'superadmin' ? 'Суперадмин' : 'Администратор'
}
