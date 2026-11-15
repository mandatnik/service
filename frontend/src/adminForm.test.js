import test from 'node:test'
import assert from 'node:assert/strict'
import { validateAdminForm } from './adminForm.js'

test('administrator form requires email, display name and a strong password on create', () => {
  assert.equal(validateAdminForm({ email: '', display_name: 'Иванов И. И.', password: 'long-enough-password' }, true), 'Укажите email администратора.')
  assert.equal(validateAdminForm({ email: 'bad', display_name: 'Иванов И. И.', password: 'long-enough-password' }, true), 'Укажите корректный email администратора.')
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: '', password: 'long-enough-password' }, true), 'Укажите ФИО администратора.')
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: 'Иванов И. И.', password: '' }, true), 'Укажите пароль администратора.')
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: 'Иванов И. И.', password: 'short' }, true), 'Пароль должен содержать не менее 12 символов.')
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: 'Иванов И. И.', password: 'long-enough-password' }, true), '')
})

test('administrator edit allows an empty password but validates a replacement', () => {
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: 'Иванов И. И.', password: '' }, false), '')
  assert.equal(validateAdminForm({ email: 'a@b.test', display_name: 'Иванов И. И.', password: 'short' }, false), 'Пароль должен содержать не менее 12 символов.')
})
