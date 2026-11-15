import test from 'node:test'
import assert from 'node:assert/strict'
import { emptyMachineFilters, readMachineFilters, machineFilterSearch } from './machineFilters.js'

test('monitoring filters, timestamp and columns survive URL round trips', () => {
  const filters = { ...emptyMachineFilters(), monitor: 'needs_license', as_of: '2026-11-15T10:00:00Z', license: 'trial', hostname: 'АРМ 1', group_id: 'a-group' }
  assert.deepEqual(readMachineFilters(machineFilterSearch(filters)), filters)
})
test('all cards is different from the default current-machine scope', () => {
  assert.equal(readMachineFilters('').status, 'active')
  assert.equal(readMachineFilters('?status=').status, '')
  assert.equal(machineFilterSearch({ status: '' }), '?status=')
})
test('unrecognized monitoring names and query keys cannot become filters', () => {
  const filters = readMachineFilters('?monitor=invalid&sql=DROP&name=test')
  assert.equal(filters.monitor, '')
  assert.equal(filters.name, 'test')
  assert.equal('sql' in filters, false)
})
