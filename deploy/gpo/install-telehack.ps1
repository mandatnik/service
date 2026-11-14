# GPO computer startup script for the Telehack 2026 agent.
# The share and configuration are deployment inputs; no secrets are embedded.
$ErrorActionPreference = 'Stop'
$share = '\\SERVER-WINDOWS\TelehackDeploy'
$root = 'C:\ProgramData\Telehack2026'
$log = Join-Path $root 'gpo-install.log'

New-Item -ItemType Directory -Force -Path $root | Out-Null
function Write-Log([string]$message) {
    Add-Content -Path $log -Value ('{0} {1}' -f (Get-Date).ToString('o'), $message)
}

Write-Log 'GPO startup: begin'
try {
    Copy-Item (Join-Path $share 'agent-config.json') (Join-Path $root 'agent-config.json') -Force
    Write-Log 'GPO startup: config copied'

    $exe = 'C:\Program Files\Telehack2026\Agent\telehack-agent.exe'
    if (-not (Test-Path $exe)) {
        $msi = Join-Path $share 'TelehackAgent.msi'
        $arguments = '/i "{0}" /qn /norestart /l*v C:\Windows\Temp\telehack-gpo-msi.log' -f $msi
        $process = Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList $arguments -Wait -PassThru
        Write-Log ('GPO startup: msiexec exit=' + $process.ExitCode)
        if ($process.ExitCode -ne 0) { exit $process.ExitCode }
    } else {
        Write-Log 'GPO startup: agent already installed'
    }

    Start-Service TelehackAgent -ErrorAction SilentlyContinue
    Write-Log 'GPO startup: service start requested'
    exit 0
} catch {
    Write-Log ('GPO startup: error ' + $_.Exception.Message)
    exit 1
}
