"""One-attempt CSP5 license application in an actual LocalSystem service.
Requires an authenticated SSH control socket; never accepts license keys.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

root = Path(__file__).resolve().parents[2]
suffix = sys.argv[1]
if suffix != '136':
    raise SystemExit('Only WORKSTATION-1 (136) is authorized')
socket = sys.argv[2]
host = f'agent@192.168.189.{suffix}'
remote = 'C:\\ProgramData\\MandatnikActivationProbe-' + uuid.uuid4().hex[:12]
service = 'MandatnikResearchProbe'
candidate_file = root / '.secrets/csp5-workstation1-license.txt'
attempt_file = root / '.secrets/csp5-workstation1-license-attempt.json'
if not candidate_file.is_file():
    raise SystemExit('Protected input file is missing')
if attempt_file.exists():
    raise SystemExit('A prior attempt is recorded; automatic retries are prohibited')

def ps(script):
    encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + script).encode('utf-16le')).decode()
    r = subprocess.run(['ssh', '-S', socket, '-o', 'BatchMode=yes', host, 'powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], capture_output=True, text=True, timeout=45)
    if r.returncode:
        raise RuntimeError(f'Remote command failed (exit={r.returncode}); raw diagnostics withheld')
    return r.stdout.strip().lstrip('\ufeff')

ps(f"if(Get-Service {service} -ErrorAction SilentlyContinue){{throw 'Research service already exists'}};New-Item -ItemType Directory '{remote}'|Out-Null;& icacls.exe '{remote}' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null;if($LASTEXITCODE -ne 0){{throw 'ACL failed'}}")
created = False
try:
    files = [('ServiceProbe.cs', 'ServiceProbe.cs'), ('license_apply_once.ps1', 'probe.ps1')]
    files += [(name, name) for name in ('license_apply_snapshot.ps1', 'license_registry_rollback.ps1')]
    for source, name in files:
        target = remote.replace('\\', '/') + '/' + name
        subprocess.run(['scp', '-o', f'ControlPath={socket}', '-o', 'BatchMode=yes', str(root / 'tools/research' / source), f'{host}:{target}'], capture_output=True, check=True, timeout=30)
    ps(f"& 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe' /nologo /target:exe /platform:x64 /reference:System.ServiceProcess.dll /out:'{remote}\\ServiceProbe.exe' '{remote}\\ServiceProbe.cs';if($LASTEXITCODE -ne 0){{throw 'Compile failed'}};New-Service -Name {service} -BinaryPathName '\"{remote}\\ServiceProbe.exe\" \"{remote}\"' -StartupType Manual|Out-Null")
    created = True
    target = remote.replace('\\', '/') + '/candidate.txt'
    subprocess.run(['scp', '-o', f'ControlPath={socket}', '-o', 'BatchMode=yes', str(candidate_file), f'{host}:{target}'], capture_output=True, check=True, timeout=30)
    attempt_file.write_text(json.dumps({'host': host, 'directory': remote, 'status': 'service_start_requested_no_retry'}, indent=2) + '\n')
    attempt_file.chmod(0o600)
    ps(f'Start-Service {service}')
    for _ in range(20):
        if ps(f"Test-Path '{remote}\\runner.exit.txt'") == 'True':
            break
        time.sleep(1)
    else:
        raise RuntimeError('Service probe timeout')
    if ps(f"Get-Content '{remote}\\runner.exit.txt'") != '0':
        raise RuntimeError('Probe failed; inspect protected remote diagnostics')
    report = json.loads(ps(f"Get-Content -Raw -Encoding UTF8 '{remote}\\report.json'"))
    destination = root / 'research/2026-11-14/activation-valid-key-136.json'
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + chr(10))
    # A second fresh process only reads the candidate and runtime state.
    report['IndependentVerification'] = json.loads(ps(f"& '{remote}\\license_apply_snapshot.ps1' -Directory '{remote}'"))
    subprocess.run(['scp', '-o', f'ControlPath={socket}', '-o', 'BatchMode=yes', f"{host}:{remote.replace(chr(92), '/')}/rollback.xml", str(root / '.secrets/csp5-workstation1-before.xml')], capture_output=True, check=True, timeout=30)
    (root / '.secrets/csp5-workstation1-before.xml').chmod(0o600)
    attempt_file.write_text(json.dumps({'host': host, 'status': 'applied' if report.get('AppliedSuccessfully') else 'failed_restored', 'writes': report.get('RegistryWriteAttempts')}, indent=2) + '\n')
finally:
    if created:
        ps(f"$s=Get-Service {service};if($s.Status -ne 'Stopped'){{Stop-Service {service}}};& sc.exe delete {service}|Out-Null;if($LASTEXITCODE -ne 0){{throw 'Service cleanup failed'}}")
    ps(f"if((Test-Path '{remote}\\rollback.xml') -and -not (Test-Path '{remote}\\rollback-ok.txt') -and -not (Test-Path '{remote}\\activation-commit.txt')){{throw 'Rollback not confirmed; retaining protected recovery files'}};Remove-Item -LiteralPath '{remote}' -Recurse -Force; if((Test-Path '{remote}') -or (Get-Service {service} -ErrorAction SilentlyContinue)){{throw 'Cleanup incomplete'}}")
report['Cleanup'] = {'ServiceDeleted': True, 'DirectoryDeleted': True}
destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False, indent=2))
