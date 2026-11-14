import test from 'node:test'
import assert from 'node:assert/strict'
import { adminDisplayName, adminInitial, adminRoleLabel } from './identity.js'

test('adminDisplayName prefers the display name', () => {
  assert.equal(adminDisplayName({ display_name: 'Малыгин А. Е.', email: 'malygin@example.com' }), 'Малыгин А. Е.')
  assert.equal(adminDisplayName({ display_name: '  Малыгин А. Е.  ' }), 'Малыгин А. Е.')
})

test('adminDisplayName falls back to email and then a generic label', () => {
  assert.equal(adminDisplayName({ email: 'admin@example.com' }), 'admin@example.com')
  assert.equal(adminDisplayName({ display_name: '   ', email: ' admin@example.com ' }), 'admin@example.com')
  assert.equal(adminDisplayName(null), 'Администратор')
  assert.equal(adminDisplayName({}), 'Администратор')
})

test('adminInitial uses the first letter of the display name', () => {
  assert.equal(adminInitial({ display_name: 'Малыгин А. Е.', email: 'malygin@example.com' }), 'М')
  assert.equal(adminInitial({ display_name: '  малыгин  ' }), 'М')
  assert.equal(adminInitial({ email: 'admin@example.com' }), 'A')
  assert.equal(adminInitial({}), 'А')
})

test('adminRoleLabel exposes both administrator roles', () => {
  assert.equal(adminRoleLabel('superadmin'), 'суперадминистратор')
  assert.equal(adminRoleLabel('admin'), 'администратор')
  assert.equal(adminRoleLabel(undefined), 'администратор')
})
