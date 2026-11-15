import test from 'node:test'
import assert from 'node:assert/strict'
import { selectedRecipientIDs, selectableMachineIDs } from './recipients.js'

const machines = [
  { id: 'm1', archived: false, active_registration: true },
  { id: 'm2', archived: false, active_registration: true },
  { id: 'm3', archived: true, active_registration: true },
  { id: 'm4', archived: false, active_registration: false }
]
const groups = [
  { id: 'g1', machine_ids: ['m1', 'm2', 'm3'] },
  { id: 'g2', machine_ids: ['m2', 'm4'] }
]

test('direct selection and overlapping groups produce one recipient', () => {
  const selectable = selectableMachineIDs(machines)
  assert.deepEqual(selectedRecipientIDs(['m1'], ['g1', 'g2'], groups, selectable), ['m1', 'm2'])
})

test('archived and inactive machines never become selectable through a group', () => {
  const selectable = selectableMachineIDs(machines)
  assert.deepEqual(selectedRecipientIDs([], ['g1', 'g2'], groups, selectable), ['m1', 'm2'])
  assert.deepEqual(selectedRecipientIDs(['m3', 'm4'], [], groups, selectable), [])
})

test('unknown group ids do not crash the counter', () => {
  const selectable = selectableMachineIDs(machines)
  assert.deepEqual(selectedRecipientIDs(['m1'], ['missing'], groups, selectable), ['m1'])
})
