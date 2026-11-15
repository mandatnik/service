#!/usr/bin/env python3
"""Authorized live API acceptance. Password stays in its file, never in evidence.
Prepare assigns temporary policies to the two CURRENT stand registrations.
After prepare, request scans normally (or restart services to expedite polling).
Check verifies reports. Cleanup revokes only this test's policy/group IDs.
"""
import argparse, http.cookiejar, json, ssl, urllib.request
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('phase', choices=['prepare', 'check', 'reinclusion', 'revoke', 'cleanup'])
p.add_argument('--url', default='https://192.168.189.138:8444')
p.add_argument('--ca', default='.secrets/stand-tls/ca.crt')
p.add_argument('--password-file', default='.secrets/p08-admin-password.txt')
p.add_argument('--state', default='.deploy/folder-policy-acceptance.json')
a = p.parse_args()
jar = http.cookiejar.CookieJar()
http = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=a.ca)), urllib.request.HTTPCookieProcessor(jar))
csrf = ''
def call(path, method='GET', body=None):
    headers = {'Content-Type': 'application/json'}
    if csrf: headers['X-CSRF-Token'] = csrf
    req = urllib.request.Request(a.url + '/api/admin/v1' + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    with http.open(req, timeout=30) as response: return json.load(response)
login = call('/login', 'POST', {'username': 'admin', 'password': Path(a.password_file).read_text().strip()})
csrf = login['csrf_token']
state_file = Path(a.state)
if a.phase == 'prepare':
    machines = call('/machines?page_size=100')['items']
    current = {m['source_ip'].split('.')[-1]: m['machine_id'] for m in machines if m.get('uuid') and m.get('source_ip') in ['192.168.189.136', '192.168.189.137']}
    assert set(current) == {'136', '137'}, current
    state = {'machines': current, 'policies': [], 'groups': []}
    def save(): state_file.parent.mkdir(parents=True, exist_ok=True); state_file.write_text(json.dumps(state, indent=2))
    save()
    group = call('/groups', 'POST', {'name': 'Проверка политик 0.4.0', 'machine_ids': list(current.values())})['id']; state['groups'].append(group); save()
    # Bulk-add is idempotent and never replaces other memberships.
    call('/groups/' + group + '/members', 'POST', {'machine_ids': list(current.values())})
    root = 'C:/ProgramData/Mandatnik/policy-acceptance'
    entries = [
      {'name': 'Проверка: групповые папки', 'rules': root + '/*/\n!' + root + '/trash/', 'group_ids': [group], 'machine_ids': []},
      {'name': 'Проверка: независимое групповое включение', 'rules': root + '/trash/', 'group_ids': [group], 'machine_ids': []},
      {'name': 'Проверка: прямое исключение', 'rules': '!' + root + '/trash/', 'machine_ids': [current['136']], 'group_ids': []}]
    for policy in entries:
        ident = call('/folder-policies', 'POST', policy)['id']; state['policies'].append(ident); save()
    for ident in current.values(): call('/machines/' + ident + '/jobs', 'POST', {})
    print('PREPARED: two group policies; direct exclusion only on .136; scans queued')
else:
    state = json.loads(state_file.read_text())
    if a.phase == 'reinclusion':
        policy = {'name': 'Проверка: независимое прямое включение', 'rules': 'C:/ProgramData/Mandatnik/policy-acceptance/trash/', 'machine_ids': [state['machines']['136']], 'group_ids': []}
        state['policies'].append(call('/folder-policies', 'POST', policy)['id']); state['reinclusion'] = True; state_file.write_text(json.dumps(state, indent=2))
        for ident in state['machines'].values(): call('/machines/' + ident + '/jobs', 'POST', {})
        print('REINCLUSION queued')
    elif a.phase == 'check':
        certificates = call('/certificates?page_size=100')['items']
        all_observations = [o for cert in certificates for o in call('/certificates/' + cert['sha256'])['observations']]
        for ip, ident in state['machines'].items():
            observations = [o for o in all_observations if o['machine_id'] == ident and o['active'] and o['source_type'] == 'folder' and o['source_key'] == 'folder-policies']
            paths = sorted(o.get('file_path', '').replace('\\', '/') for o in observations)
            expected = 0 if state.get('revoked') else 3 if ip == '137' or state.get('reinclusion') else 2
            assert len(paths) == expected, (ip, expected, paths)
            assert all(path.lower().endswith('.cer') for path in paths), paths
            assert any('/trash/' in path for path in paths) == (expected == 3), paths
            print(ip, 'PASS', paths)
    elif a.phase == 'revoke':
        for ident in state['policies']: call('/folder-policies/' + ident, 'DELETE')
        state['policies'] = []; state['revoked'] = True; state_file.write_text(json.dumps(state, indent=2))
        for ident in state['machines'].values(): call('/machines/' + ident + '/jobs', 'POST', {})
        print('REVOKED: rescan must retire test folder observations')
    else:
        for ident in state['policies']: call('/folder-policies/' + ident, 'DELETE')
        for ident in state['groups']: call('/groups/' + ident, 'DELETE')
        print('CLEANED temporary assignments and groups')
