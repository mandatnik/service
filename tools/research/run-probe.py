"""Run a temporary LocalSystem SCM service on an authorized research workstation.

Uses an existing SSH control connection; does not store passwords.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

PROJECT = Path(__file__).resolve().parents[2]
suffix = sys.argv[1]
host = f"agent@192.168.189.{suffix}"
socket = f"/tmp/telehack-admin-{suffix}.sock"
collect_only = len(sys.argv) > 2 and sys.argv[2] == "--collect"
run_id = "TelehackResearch-" + uuid.uuid4().hex[:12]
remote = "C:\\ProgramData\\" + run_id
destination = PROJECT / "research" / "2026-11-14" / suffix
destination.mkdir(parents=True, exist_ok=True)
if collect_only or (len(sys.argv) > 2 and sys.argv[2] == "--rerun"):
    remote = json.loads((destination / "run.json").read_text())["directory"]
else:
    (destination / "run.json").write_text(json.dumps({"host": host, "directory": remote, "service": "TelehackResearchProbe"}, indent=2))


def powershell(script, timeout=60):
    script = "$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ProgressPreference='SilentlyContinue';" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    result = subprocess.run(["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
                             "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout.strip().lstrip("\ufeff")


if not collect_only:
    powershell(f"""
    $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
    if((Get-Service TelehackResearchProbe -ErrorAction SilentlyContinue).Status -eq 'Running'){{throw 'Research service already running'}}
    New-Item -ItemType Directory -Path '{remote}\\fixtures' -Force|Out-Null
    & icacls.exe '{remote}' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
    if($LASTEXITCODE -ne 0){{throw 'ACL setup failed'}}
    """)
    files = [PROJECT / "tools/research/ServiceProbe.cs", PROJECT / "tools/research/probe.ps1"]
    fixtures = PROJECT / "test-data/certificates-2026-11-14/certificates"
    files += [fixtures / n for n in ("01-individual-valid.cer", "02-individual-expired.cer", "03-individual-future.cer")]
    for file in files:
        subdir = "/fixtures" if file.suffix == ".cer" else ""
        target = remote.replace("\\", "/") + subdir + "/" + file.name
        subprocess.run(["scp", "-o", f"ControlPath={socket}", "-o", "BatchMode=yes", str(file), f"{host}:{target}"], check=True, capture_output=True, timeout=30)
    print(f"{suffix}: staged protected research directory", flush=True)
    powershell(f"""
    $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
    & 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe' /nologo /target:exe /platform:x64 /reference:System.ServiceProcess.dll /out:'{remote}\\ServiceProbe.exe' '{remote}\\ServiceProbe.cs'
    if($LASTEXITCODE -ne 0){{throw 'Compilation failed'}}
    $bin='"{remote}\\ServiceProbe.exe" "{remote}"'
    if(-not (Get-Service TelehackResearchProbe -ErrorAction SilentlyContinue)){{New-Service -Name TelehackResearchProbe -BinaryPathName $bin -StartupType Manual|Out-Null}}
    Get-ChildItem '{remote}\\runner.*.txt','{remote}\\report.json' -ErrorAction SilentlyContinue|Remove-Item -Force
    Start-Service TelehackResearchProbe
    """)
    print(f"{suffix}: actual LocalSystem service started", flush=True)
for _ in range(30):
    status = powershell(f"""
$ProgressPreference='SilentlyContinue'
if(Test-Path '{remote}\\runner.exit.txt'){{'DONE'}}elseif(Test-Path '{remote}\\runner.failure.txt'){{'FAILED'}}else{{(Get-Service TelehackResearchProbe).Status.ToString()}}
""")
    if status in ("DONE", "FAILED"):
        break
    time.sleep(2)
else:
    raise RuntimeError("Probe timeout; keep directory/service for investigation")
for name in ("report.json", "runner.exit.txt", "runner.stderr.txt", "runner.failure.txt"):
    data = powershell(f"if(Test-Path '{remote}\\{name}'){{Get-Content -Raw -Encoding UTF8 '{remote}\\{name}'}}")
    if data:
        (destination / name).write_text(data + "\n")
    else:
        (destination / name).unlink(missing_ok=True)
report = json.loads((destination / "report.json").read_text())
print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
print(f"Report saved: {destination}", flush=True)
# Always remove temporary service. Keep evidence directory on failure for cleanup investigation.
powershell("""
$ErrorActionPreference='Stop'
$service=Get-Service TelehackResearchProbe -ErrorAction SilentlyContinue
if($service -and $service.Status -ne 'Stopped'){Stop-Service TelehackResearchProbe}
& sc.exe delete TelehackResearchProbe
if($LASTEXITCODE -ne 0){throw 'Service deletion failed'}
""")
offline = report.get("OfflineTest", {})
clean = offline.get("FixtureCleaned") and offline.get("Unmounted") and not report.get("RemainingResearchMounts")
if clean:
    powershell(f"Remove-Item -LiteralPath '{remote}' -Recurse -Force -ErrorAction Stop")
    (destination / "cleanup.json").write_text(json.dumps({"service_deleted": True, "directory_deleted": True, "fixtures_removed": True, "hive_unloaded": True}, indent=2))
    print(f"{suffix}: temporary service, fixtures, mount and directory cleaned", flush=True)
else:
    print(f"{suffix}: service removed; directory retained for investigation: {remote}", flush=True)
if report.get("Errors"):
    raise SystemExit(1)
