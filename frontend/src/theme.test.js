import test from 'node:test'
import assert from 'node:assert/strict'
import {
  THEME_DARK,
  THEME_LIGHT,
  initialTheme,
  normalizeTheme,
  oppositeTheme,
  readStoredTheme,
  resolveTheme,
  storeTheme,
  systemPrefersDark
} from './theme.js'

function fakeStorage(initial = {}) {
  const values = { ...initial }
  return {
    getItem: (key) => (key in values ? values[key] : null),
    setItem: (key, value) => { values[key] = String(value) },
    values
  }
}

function fakeMatchMedia(prefersDark) {
  return () => ({ matches: prefersDark })
}

test('normalizeTheme accepts only light and dark', () => {
  assert.equal(normalizeTheme('light'), THEME_LIGHT)
  assert.equal(normalizeTheme('dark'), THEME_DARK)
  assert.equal(normalizeTheme('system'), '')
  assert.equal(normalizeTheme(undefined), '')
})

test('resolveTheme falls back to the system preference', () => {
  assert.equal(resolveTheme('light', true), THEME_LIGHT)
  assert.equal(resolveTheme('dark', false), THEME_DARK)
  assert.equal(resolveTheme('', true), THEME_DARK)
  assert.equal(resolveTheme('', false), THEME_LIGHT)
  assert.equal(resolveTheme('unknown', true), THEME_DARK)
})

test('oppositeTheme toggles between both themes', () => {
  assert.equal(oppositeTheme(THEME_LIGHT), THEME_DARK)
  assert.equal(oppositeTheme(THEME_DARK), THEME_LIGHT)
})

test('stored preference wins over the system preference', () => {
  const storage = fakeStorage({ 'admin-theme': 'light' })
  assert.equal(readStoredTheme(storage), THEME_LIGHT)
  assert.equal(initialTheme(storage, fakeMatchMedia(true)), THEME_LIGHT)
  assert.equal(initialTheme(fakeStorage(), fakeMatchMedia(true)), THEME_DARK)
  assert.equal(initialTheme(fakeStorage(), fakeMatchMedia(false)), THEME_LIGHT)
})

test('storeTheme persists only supported values', () => {
  const storage = fakeStorage()
  storeTheme('dark', storage)
  assert.equal(storage.values['admin-theme'], 'dark')
  storeTheme('system', storage)
  assert.equal(storage.values['admin-theme'], 'dark')
})

test('systemPrefersDark tolerates missing media queries', () => {
  assert.equal(systemPrefersDark(fakeMatchMedia(true)), true)
  assert.equal(systemPrefersDark(fakeMatchMedia(false)), false)
  assert.equal(systemPrefersDark(undefined), false)
  assert.equal(systemPrefersDark(() => { throw new Error('denied') }), false)
})
