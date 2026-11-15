import test from 'node:test'
import assert from 'node:assert/strict'
import { personalName, certificateParty, certificateValidity, certificateLocations } from './certificates.js'

const now = Date.parse('2026-11-15T10:00:00Z')
test('only all-uppercase personal names get title case, including hyphens and Ё', () => {
  assert.equal(personalName('МИНИНА ЕЛЕНА АЛЕКСАНДРОВНА'), 'Минина Елена Александровна')
  assert.equal(personalName('СЕМЁНОВА-ИВАНОВА АННА'), 'Семёнова-Иванова Анна')
  assert.equal(personalName('Анна де Витт'), 'Анна де Витт')
})
test('individual owner shows title, organization and separate identity badges', () => {
  const party = certificateParty({ owner_cn: 'МИНИНА ЕЛЕНА АЛЕКСАНДРОВНА', owner_details: {
    title: 'Директор', organization: 'Федеральное Государственное Бюджетное Учреждение', inn: '665906883158', snils: '02171883637', email: 'iv2nov@urtisi.ru'
  } })
  assert.equal(party.primary, 'Минина Елена Александровна')
  assert.equal(party.subtitle, 'Директор, Федеральное Государственное Бюджетное Учреждение')
  assert.deepEqual(party.badges.map(b => b.label), ['ИНН', 'СНИЛС', 'Почта'])
  assert.equal(party.badges[2].href, 'mailto:iv2nov%40urtisi.ru')
})
test('legal entity spelling stays intact and representative is taken from personal attributes', () => {
  const party = certificateParty({ owner_details: {
    common_name: 'ООО «КОНСУЛЬТАНТПЛЮССЕРВИС»', legal_entity: true, title: 'Директор', person_name: 'ПЕСТОВО ВЕРА БОРИСОВНА', inn_legal: '6658372383', inn: '665907737544', snils: '02271358019'
  } })
  assert.equal(party.primary, 'ООО «КОНСУЛЬТАНТПЛЮССЕРВИС»')
  assert.equal(party.subtitle, 'Директор: Пестово Вера Борисовна')
  assert.deepEqual(party.badges.map(b => b.label), ['ИННЮЛ', 'ИННФЛ', 'СНИЛС'])
})
test('issuer badges never fall back to owner identity fields', () => {
  const party = certificateParty({ inn: 'owner-inn', snils: 'owner-snils', issuer_details: { common_name: 'УЦ «ТЕСТ»', inn_legal: 'issuer-inn', email: 'ca@example.test' } }, true)
  assert.equal(party.primary, 'УЦ «ТЕСТ»')
  assert.deepEqual(party.badges.map(b => b.value), ['issuer-inn', 'ca@example.test'])
})
test('registry and files do not sum to the number of detection places', () => {
  assert.deepEqual(certificateLocations({ machines: 1, registry_machines: 1, file_machines: 1, observations: 6 }), { registry: 1, files: 1, total: '1 место обнаружения' })
})
test('validity dates, exact boundaries and explicit revocation determine status', () => {
  const cert = { not_before: '2026-11-14T10:00:00Z', not_after: '2026-11-17T10:00:00Z' }
  assert.equal(certificateValidity(cert, now).label, 'Действующий')
  assert.equal(certificateValidity(cert, now).remaining, 'Осталось: 2 дня')
  assert.equal(certificateValidity(cert, Date.parse(cert.not_after)).label, 'Действующий')
  assert.equal(certificateValidity(cert, Date.parse(cert.not_after) + 1).label, 'Истёк')
  assert.equal(certificateValidity(cert, Date.parse(cert.not_before) - 1).label, 'Не вступил')
  assert.equal(certificateValidity({ ...cert, revocation_status: 'revoked' }, now).label, 'Отозван')
  assert.equal(certificateValidity({}, now).label, 'Не определён')
})
