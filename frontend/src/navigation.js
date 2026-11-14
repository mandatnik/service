const sections = new Set(['overview', 'machines', 'groups', 'policies', 'certificates', 'licensing', 'tasks', 'hostnames', 'events', 'api-keys', 'settings'])
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const sha256 = /^[0-9a-f]{64}$/i

export function parseRoute(path) {
  const fallback = { view: 'overview', id: '' }
  if (path === '/') return fallback
  const match = /^\/([^/?#]+)(?:\/([^/?#]+))?\/?$/.exec(path)
  if (!match) return fallback
  const [, rawSection, id] = match
  const section = rawSection === 'arm' ? 'machines' : rawSection
  if (!sections.has(section)) return fallback
  if (!id) return { view: section, id: '' }
  if (section === 'machines' && uuid.test(id)) return { view: 'machine', id: id.toLowerCase() }
  if (section === 'certificates' && sha256.test(id)) return { view: 'certificate', id: id.toLowerCase() }
  if (section === 'groups' && uuid.test(id)) return { view: 'groups', id: id.toLowerCase() }
  return fallback
}

export function routePath(view, id = '') {
  const section = view === 'machine' || view === 'machines' ? 'arm' : view === 'certificate' ? 'certificates' : view
  const route = parseRoute(`/${section}${id ? `/${id}` : ''}`)
  if (route.view === 'overview') return '/'
  const canonical = route.view === 'machine' || route.view === 'machines' ? 'arm' : route.view === 'certificate' ? 'certificates' : route.view
  return `/${canonical}${route.id ? `/${route.id}` : ''}`
}
