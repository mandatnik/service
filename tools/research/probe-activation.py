"""Read-only license API probe in an actual LocalSystem service.
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
if suffix not in ('136', '137'):
    raise SystemExit('Only authorized workstation suffixes 136/137 are accepted')
socket = sys.argv[2]
host = f'agent@192.168.189.{suffix}'
remote = 'C:\\ProgramData\\MandatnikActivationProbe-' + uuid.uuid4().hex[:12]
service = 'MandatnikResearchProbe'

def ps(script):
    encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + script).encode('utf-16le')).decode()
    r = subprocess.run(['ssh', '-S', socket, '-o', 'BatchMode=yes', host, 'powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], capture_output=True, text=True, timeout=45)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    return r.stdout.strip().lstrip('\ufeff')

ps(f"if(Get-Service {service} -ErrorAction SilentlyContinue){{throw 'Research service already exists'}};New-Item -ItemType Directory '{remote}'|Out-Null;& icacls.exe '{remote}' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null;if($LASTEXITCODE -ne 0){{throw 'ACL failed'}}")
created = False
try:
    for source, name in [('ServiceProbe.cs', 'ServiceProbe.cs'), ('license_activation_probe.ps1', 'probe.ps1')]:
        target = remote.replace('\\', '/') + '/' + name
        subprocess.run(['scp', '-o', f'ControlPath={socket}', '-o', 'BatchMode=yes', str(root / 'tools/research' / source), f'{host}:{target}'], capture_output=True, check=True, timeout=30)
    ps(f"& 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe' /nologo /target:exe /platform:x64 /reference:System.ServiceProcess.dll /out:'{remote}\\ServiceProbe.exe' '{remote}\\ServiceProbe.cs';if($LASTEXITCODE -ne 0){{throw 'Compile failed'}};New-Service -Name {service} -BinaryPathName '\"{remote}\\ServiceProbe.exe\" \"{remote}\"' -StartupType Manual|Out-Null")
    created = True
    ps(f'Start-Service {service}')
    for _ in range(20):
        if ps(f"Test-Path '{remote}\\runner.exit.txt'") == 'True':
            break
        time.sleep(1)
    else:
        raise RuntimeError('Service probe timeout')
    if ps(f"Get-Content '{remote}\\runner.exit.txt'") != '0':
        raise RuntimeError(ps(f"Get-Content -Raw '{remote}\\runner.stderr.txt'"))
    report = json.loads(ps(f"Get-Content -Raw -Encoding UTF8 '{remote}\\report.json'"))
    destination = root / 'research/2026-11-14' / f'activation-api-{suffix}.json'
finally:
    if created:
        ps(f"$s=Get-Service {service};if($s.Status -ne 'Stopped'){{Stop-Service {service}}};& sc.exe delete {service}|Out-Null;if($LASTEXITCODE -ne 0){{throw 'Service cleanup failed'}}")
    ps(f"Remove-Item -LiteralPath '{remote}' -Recurse -Force; if((Test-Path '{remote}') -or (Get-Service {service} -ErrorAction SilentlyContinue)){{throw 'Cleanup incomplete'}}")
report['Cleanup'] = {'ServiceDeleted': True, 'DirectoryDeleted': True}
destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False, indent=2))
