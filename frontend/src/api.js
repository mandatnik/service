const BASE = '/api/admin/v1'

let csrfToken = ''

function cookie(name) {
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim()
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length))
  }
  return ''
}

export function setCSRF(token) {
  csrfToken = token || cookie('telehack_csrf')
}

export function currentCSRF() {
  return csrfToken || cookie('telehack_csrf')
}

async function request(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const headers = { Accept: 'application/json', ...(options.headers || {}) }
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD') {
    const token = currentCSRF()
    if (token) headers['X-CSRF-Token'] = token
  }
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      ...options,
      method,
      headers,
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body)
    })
  } catch (error) {
    throw new Error('Нет связи с backend: ' + error.message)
  }
  const text = await response.text()
  let body = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { error: { message: text.slice(0, 300) } }
    }
  }
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent('telehack:unauthorized', { detail: body }))
  }
  if (!response.ok) {
    const message = body?.error?.message || `HTTP ${response.status}`
    const error = new Error(message)
    error.status = response.status
    error.body = body
    throw error
  }
  return body
}

function query(params) {
  const q = new URLSearchParams()
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== '') q.set(key, value)
  }
  const text = q.toString()
  return text ? `?${text}` : ''
}

export const api = {
  inventorySettings: () => request('/inventory-settings'),
  saveGroup: (group) => request(group.id ? `/groups/${encodeURIComponent(group.id)}` : '/groups', { method: group.id ? 'PUT' : 'POST', body: group }),
  addGroupMembers: (id, machine_ids) => request(`/groups/${encodeURIComponent(id)}/members`, { method: 'POST', body: { machine_ids } }),
  deleteGroup: (id) => request(`/groups/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  savePolicy: (policy) => request(policy.id ? `/folder-policies/${encodeURIComponent(policy.id)}` : '/folder-policies', { method: policy.id ? 'PUT' : 'POST', body: policy }),
  deletePolicy: (id) => request(`/folder-policies/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  login: (email, password) => request('/login', { method: 'POST', body: { email, password } }),
  session: () => request('/session'),
  logout: () => request('/logout', { method: 'POST', body: {} }),
  overview: () => request('/overview'),
  machines: (params) => request(`/machines${query(params)}`),
  machine: (id) => request(`/machines/${encodeURIComponent(id)}`),
  createJob: (id) => request(`/machines/${encodeURIComponent(id)}/jobs`, { method: 'POST', body: {} }),
  certificates: (params) => request(`/certificates${query(params)}`),
  certificate: (sha) => request(`/certificates/${encodeURIComponent(sha)}`),
  licensing: (params) => request(`/licensing${query(params)}`),
  createTask: (body) => request('/tasks', { method: 'POST', body }),
  tasks: (params) => request(`/tasks${query(params)}`),
  task: (id) => request(`/tasks/${encodeURIComponent(id)}`),
  taskItems: (id) => request(`/tasks/${encodeURIComponent(id)}/items`),
  taskEvents: (id) => request(`/task-items/${encodeURIComponent(id)}/events`),
  cancelTask: (id) => request(`/tasks/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} }),
  cancelTaskItem: (id) => request(`/task-items/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {} }),
  reconcileTaskItem: (id) => request(`/task-items/${encodeURIComponent(id)}/reconcile`, { method: 'POST', body: {} }),
  events: (params) => request(`/events${query(params)}`),
  jobs: (params) => request(`/jobs${query(params)}`),
  config: () => request('/config'),
  saveConfig: (config) => request('/config', { method: 'PUT', body: config }),
  hostnames: () => request('/hostnames'),
  apiKeys: () => request('/api-keys'),
  createApiKey: (name, allowed_ips) => request('/api-keys', { method: 'POST', body: { name, allowed_ips } }),
  updateApiKey: (id, body) => request(`/api-keys/${encodeURIComponent(id)}`, { method: 'PUT', body }),
  revokeApiKey: (id) => request(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  assignHostname: (hostname, registrationID) => request(`/hostnames/${encodeURIComponent(hostname)}/assign`, { method: 'POST', body: { registration_id: registrationID } }),
  rebind: (registrationID, machineID, publicKeyPEM) => request(`/registrations/${registrationID}/rebind`, { method: 'POST', body: { machine_id: machineID, public_key_pem: publicKeyPEM } }),
  revokeRegistration: (registrationID) => request(`/registrations/${registrationID}/revoke`, { method: 'POST', body: {} })
}
