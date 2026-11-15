#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Prepares a Windows 10 x64 development/test workstation for Mandatnik.
.DESCRIPTION
Installs build tools, creates staging directories, optionally starts SQL/SSMS
installers and builds a supplied source checkout. Does not configure the backend,
create SQL databases/users, certificates, firewall rules or application secrets.
Chocolatey packages execute their installation scripts with administrator rights.
.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\prepare-windows.ps1
.EXAMPLE
.\prepare-windows.ps1 -InstallSqlExpress -InstallSSMS -Build
#>
[CmdletBinding()]
param(
    [string] $WorkRoot = 'C:\MandatnikDev',
    [string] $SourcePath = (Split-Path -Parent $PSScriptRoot),
    [string] $GoVersion = '1.26.3',
    [string] $NodeVersion = '22.22.3',
    [string] $MakeVersion = '4.4.1',
    [string] $WixDir = 'C:\Tools\wix314',
    [switch] $InstallSqlExpress,
    [switch] $InstallSSMS,
    [switch] $Build
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'Use 64-bit Windows and 64-bit Windows PowerShell.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This script requires Windows.'
}
foreach ($versionValue in @($GoVersion, $NodeVersion, $MakeVersion)) {
    if ($versionValue -notmatch '^\d+\.\d+(\.\d+)?$') { throw 'Invalid tool version.' }
}
if (-not [IO.Path]::IsPathRooted($WorkRoot) -or -not [IO.Path]::IsPathRooted($WixDir)) {
    throw 'WorkRoot and WixDir must be absolute paths.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$downloads = Join-Path $WorkRoot 'downloads'
$logs = Join-Path $WorkRoot 'logs'
foreach ($directory in @($WorkRoot, $downloads, $logs, (Join-Path $WorkRoot 'src'), (Join-Path $WorkRoot 'server'), (Join-Path $WorkRoot 'deploy'))) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
# This staging tree is only for local administrators/SYSTEM. The setup wizard
# must grant the actual backend service account access to its final directories.
& icacls.exe $WorkRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the working directory.' }
$script:rebootRequired = $false
$transcript = Join-Path $logs ('prepare-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
Start-Transcript -Path $transcript | Out-Null

function Get-Download([string] $Url, [string] $Destination) {
    $partial = $Destination + '.partial'
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $partial -TimeoutSec 180
        if ((Get-Item $partial).Length -eq 0) { throw "Empty download: $Url" }
        Move-Item -Force -Path $partial -Destination $Destination
        $hash = (Get-FileHash -Algorithm SHA256 $Destination).Hash
        Write-Host "Downloaded: $Destination (SHA256 $hash)"
    } finally {
        if (Test-Path $partial) { Remove-Item $partial -Force }
    }
}
function Assert-MicrosoftSignature([string] $Path) {
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Microsoft installer signature is not valid: $Path"
    }
}
function Invoke-Installer([string] $Path, [string[]] $InstallerArguments = @()) {
    $start = @{ FilePath = $Path; Wait = $true; PassThru = $true }
    if ($InstallerArguments.Count -gt 0) { $start.ArgumentList = $InstallerArguments }
    $process = Start-Process @start
    if ($process.ExitCode -in @(1641, 3010)) {
        $script:rebootRequired = $true
    } elseif ($process.ExitCode -ne 0) {
        throw "Installer failed with exit code $($process.ExitCode): $Path"
    }
}
function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    foreach ($candidate in @('C:\ProgramData\chocolatey\bin', "$env:ProgramFiles\Go\bin", "$env:ProgramFiles\nodejs", "$env:ProgramFiles\Git\cmd", "$env:ProgramFiles\Git\usr\bin", $WixDir)) {
        if (Test-Path $candidate) { $env:Path = $candidate + ';' + $env:Path }
    }
}
function Save-BuildEnvironment {
    # Do not use setx: it can truncate a long PATH or expand existing references.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = @($machinePath -split ';' | Where-Object { $_ })
    foreach ($candidate in @('C:\ProgramData\chocolatey\bin', "$env:ProgramFiles\Go\bin", "$env:ProgramFiles\nodejs", "$env:ProgramFiles\Git\cmd", "$env:ProgramFiles\Git\usr\bin", $WixDir)) {
        if ((Test-Path $candidate) -and -not ($entries | Where-Object { $_.TrimEnd('\') -ieq $candidate.TrimEnd('\') })) {
            $entries += $candidate
        }
    }
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'Machine')
    [Environment]::SetEnvironmentVariable('WIX_DIR', $WixDir, 'Machine')
    $env:WIX_DIR = $WixDir
    Update-SessionPath
    # Notify Explorer; already-open consoles keep their old environment.
    if (-not ('Mandatnik.EnvironmentNotification' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Mandatnik {
    public static class EnvironmentNotification {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(IntPtr window, uint message,
            UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
    }
}
'@
    }
    $result = [UIntPtr]::Zero
    [void][Mandatnik.EnvironmentNotification]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}
function Invoke-Checked([string] $Command, [string[]] $CommandArguments) {
    & $Command @CommandArguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command $CommandArguments" }
}
function Install-Package([string] $Name, [string] $Version = '') {
    $packageArguments = @('install', $Name, '-y', '--no-progress', '--limit-output')
    if ($Version) { $packageArguments += "--version=$Version" }
    & choco.exe @packageArguments
    if ($LASTEXITCODE -in @(1641, 3010)) { $script:rebootRequired = $true }
    elseif ($LASTEXITCODE -ne 0) { throw "Chocolatey failed ($LASTEXITCODE): $Name" }
    Update-SessionPath
}

try {
    Write-Host '1/5: .NET Framework 4.8 Runtime'
    $netRelease = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
    if ($null -eq $netRelease -or $netRelease.Release -lt 528040) {
        $netInstaller = Join-Path $downloads 'NDP48-x86-x64-AllOS-ENU.exe'
        Get-Download 'https://go.microsoft.com/fwlink/?linkid=2088631' $netInstaller
        Assert-MicrosoftSignature $netInstaller
        Invoke-Installer $netInstaller @('/q', '/norestart')
    } else { Write-Host '.NET Framework 4.8 or later is already installed.' }

    Write-Host '2/5: Chocolatey and build tools'
    Update-SessionPath
    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        $chocoInstaller = Join-Path $downloads 'install-chocolatey.ps1'
        Get-Download 'https://community.chocolatey.org/install.ps1' $chocoInstaller
        # Run the official bootstrap in a child process; do not persist an
        # execution-policy change or disable certificate/checksum validation.
        Invoke-Checked "$PSHOME\powershell.exe" @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $chocoInstaller)
        Update-SessionPath
    }
    Install-Package 'git.install'
    Install-Package 'golang' $GoVersion
    Install-Package 'nodejs' $NodeVersion
    Install-Package 'make' $MakeVersion

    Write-Host '3/5: WiX Toolset 3.14.1'
    $wixMarker = Join-Path $WixDir '.mandatnik-wix-version'
    if (-not (Test-Path $WixDir)) {
        $wixZip = Join-Path $downloads 'wix314-binaries.zip'
        Get-Download 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' $wixZip
        New-Item -ItemType Directory -Force $WixDir | Out-Null
        Expand-Archive -Path $wixZip -DestinationPath $WixDir
        Set-Content -Encoding ascii -Path $wixMarker -Value '3.14.1'
    } elseif (-not (Test-Path $wixMarker)) {
        Write-Host 'Using existing WiX directory; checking its tools without overwriting it.'
    }
    foreach ($tool in @('candle.exe', 'light.exe', 'WixUtilExtension.dll')) {
        if (-not (Test-Path (Join-Path $WixDir $tool))) { throw "Incomplete WiX directory: $tool. Use a new -WixDir or repair it manually." }
    }
    $wixVersion = (Get-Item (Join-Path $WixDir 'candle.exe')).VersionInfo.ProductVersion
    if ($wixVersion -notlike '3.14*') { throw "Expected WiX 3.14.x, found $wixVersion" }
    Save-BuildEnvironment

    Write-Host '4/5: Optional SQL and SSMS installers'
    if ($InstallSqlExpress) {
        if (Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue) {
            throw 'SQL services already exist. Configure the existing SQL instance manually instead of installing another one.'
        }
        $sqlInstaller = Join-Path $downloads 'SQL2019-SSEI-Expr.exe'
        Get-Download 'https://go.microsoft.com/fwlink/?linkid=866658' $sqlInstaller
        Assert-MicrosoftSignature $sqlInstaller
        Write-Host 'SQL installer opens now. Select Custom, Database Engine, SQLEXPRESS and Mixed Mode. Do not close/cancel it as a successful installation.'
        Invoke-Installer $sqlInstaller @()
        if (-not (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue)) {
            throw 'SQLEXPRESS service was not found. Complete SQL installation and then follow install.md.'
        }
    }
    if ($InstallSSMS) {
        $ssmsInstaller = Join-Path $downloads 'vs_SSMS.exe'
        Get-Download 'https://aka.ms/ssms/22/release/vs_SSMS.exe' $ssmsInstaller
        Assert-MicrosoftSignature $ssmsInstaller
        Invoke-Installer $ssmsInstaller @('--wait', '--passive', '--norestart')
    }

    # A repository unpacked by an elevated console under C:\ must remain
    # writable by the same developer in a normal (non-elevated) console.
    if (Test-Path (Join-Path $SourcePath 'go.mod')) {
        $developerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $SourcePath /grant "*${developerSid}:(OI)(CI)M" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant the current developer write access to SourcePath.' }
    }

    Write-Host '5/5: Verify tools and optionally build'
    Invoke-Checked 'git.exe' @('--version')
    $goOutput = & go.exe version
    if ($LASTEXITCODE -ne 0 -or $goOutput -notmatch "go$([regex]::Escape($GoVersion))(\s|$)") { throw "Unexpected Go version: $goOutput" }
    Write-Host $goOutput
    $nodeOutput = & node.exe --version
    if ($LASTEXITCODE -ne 0 -or $nodeOutput -ne "v$NodeVersion") { throw "Unexpected Node version: $nodeOutput" }
    Write-Host $nodeOutput
    Invoke-Checked 'npm.cmd' @('--version')
    Invoke-Checked 'make.exe' @('--version')
    Invoke-Checked 'openssl.exe' @('version')
    $manifest = [ordered]@{
        prepared_at = (Get-Date).ToUniversalTime().ToString('o')
        work_root = $WorkRoot; source_path = $SourcePath; wix_dir = $WixDir
        go = $goOutput; node = $nodeOutput; wix = $wixVersion
        reboot_required = $script:rebootRequired
        backend_configured = $false
    }
    $manifest | ConvertTo-Json | Set-Content -Encoding ascii (Join-Path $WorkRoot 'environment.json')
    if ($Build) {
        if ($script:rebootRequired) { throw 'Restart Windows, then repeat this command with -Build.' }
        if (-not (Test-Path (Join-Path $SourcePath 'go.mod'))) { throw 'SourcePath must point to the project directory containing go.mod.' }
        Push-Location $SourcePath
        try {
            Invoke-Checked 'go.exe' @('mod', 'download')
            Invoke-Checked 'go.exe' @('mod', 'verify')
            Invoke-Checked 'make.exe' @('check')
            Invoke-Checked 'make.exe' @('package', "WIX_DIR=$WixDir")
        } finally { Pop-Location }
    }
    Write-Host "Tools are ready. Staging: $WorkRoot. Log: $transcript"
    Write-Host 'Machine PATH and WIX_DIR were saved. Open a NEW console; if it still has the old environment, sign out or restart Windows. Then cd to the project and run make build.'
    Write-Host 'Next: configure SQL TCP, create an empty database and application login, then follow install.md. Backend setup is NOT performed by this script.'
    if ($script:rebootRequired) { Write-Warning 'Restart Windows before using the tools. No automatic restart was performed.' }
} finally {
    Stop-Transcript | Out-Null
}
