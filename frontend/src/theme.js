export const THEME_STORAGE_KEY = 'admin-theme'
export const THEME_LIGHT = 'light'
export const THEME_DARK = 'dark'

export function normalizeTheme(value) {
  return value === THEME_LIGHT || value === THEME_DARK ? value : ''
}

export function resolveTheme(preference, prefersDark) {
  return normalizeTheme(preference) || (prefersDark ? THEME_DARK : THEME_LIGHT)
}

export function oppositeTheme(theme) {
  return theme === THEME_DARK ? THEME_LIGHT : THEME_DARK
}

export function readStoredTheme(storage) {
  try {
    return normalizeTheme(storage?.getItem(THEME_STORAGE_KEY))
  } catch {
    return ''
  }
}

export function storeTheme(theme, storage) {
  const normalized = normalizeTheme(theme)
  if (!normalized) return
  try {
    storage?.setItem(THEME_STORAGE_KEY, normalized)
  } catch {
    /* storage can be unavailable in restricted browser contexts */
  }
}

export function systemPrefersDark(matchMedia) {
  try {
    return !!matchMedia?.('(prefers-color-scheme: dark)')?.matches
  } catch {
    return false
  }
}

export function initialTheme(storage, matchMedia) {
  return resolveTheme(readStoredTheme(storage), systemPrefersDark(matchMedia))
}

export function applyTheme(theme, root) {
  const normalized = normalizeTheme(theme)
  if (root && normalized) root.dataset.theme = normalized
  return normalized
}

export function initTheme(doc = globalThis.document, storage = browserStorage(), matchMedia = globalThis.matchMedia) {
  const theme = initialTheme(storage, matchMedia)
  applyTheme(theme, doc?.documentElement)
  return theme
}

export function browserStorage() {
  try {
    return globalThis.localStorage
  } catch {
    return undefined
  }
}
