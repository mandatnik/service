import test from 'node:test'
import assert from 'node:assert/strict'
import { parseRoute, routePath } from './navigation.js'
const id = '5297a534-08b3-418c-823c-be2e8ec01160'
test('sections and object links survive URL round trips', () => {
  for (const [view, objectId] of [['overview', ''], ['settings', ''], ['machine', id], ['groups', id], ['certificate', 'ab'.repeat(32)]]) {
    assert.deepEqual(parseRoute(routePath(view, objectId)), { view, id: objectId })
  }
})
test('invalid paths and identifiers fall back without requesting arbitrary objects', () => {
  for (const path of ['', '#main-content', '/missing', '/machines/not-a-uuid', '/certificates/abc', '/settings/extra', '/groups/%ZZ']) {
    assert.deepEqual(parseRoute(path), { view: 'overview', id: '' })
  }
})
test('object identifiers are canonicalized', () => {
  assert.equal(routePath('machine', id.toUpperCase()), `/arm/${id}`)
})

test('clean paths and legacy machine paths use the canonical ARM path', () => {
  assert.equal(routePath('overview'), '/')
  assert.equal(routePath('machines'), '/arm')
  assert.deepEqual(parseRoute(`/machines/${id}`), { view: 'machine', id })
})

test('removed hostname section redirects predictably to ARM', () => {
  assert.deepEqual(parseRoute('/hostnames'), { view: 'machines', id: '' })
  assert.deepEqual(parseRoute('/hostnames/old-value'), { view: 'machines', id: '' })
  assert.equal(routePath('hostnames'), '/arm')
})

test('administrator section is a first-class route', () => {
  assert.deepEqual(parseRoute('/admins'), { view: 'admins', id: '' })
  assert.equal(routePath('admins'), '/admins')
})
