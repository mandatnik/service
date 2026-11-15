[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AgentExe,
    [Parameter(Mandatory = $true)] [string] $ProductVersion,
    [Parameter(Mandatory = $true)] [string] $ProductCode,
    [string] $UpgradeCode = '{B1DDABDF-2151-4A9D-9E0C-6BC30E9E9BDB}',
    [string] $WixDir = 'C:\ProgramData\Mandatnik\build-tools\wix314',
    [string] $Output = '',
    [string] $ExampleConfig = ''
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ExampleConfig) { $ExampleConfig = Join-Path $here 'agent-config.example.json' }
if (-not $Output) { $Output = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'artifacts\MandatnikAgent.msi' }
if (-not (Test-Path $AgentExe)) { throw "agent EXE not found: $AgentExe" }
if (-not (Test-Path (Join-Path $WixDir 'candle.exe'))) { throw "WiX 3.14 not found at $WixDir" }
if ($ProductVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'ProductVersion must be numeric x.y.z' }
if ($ProductCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { throw 'ProductCode must be a GUID in braces' }

$obj = Join-Path $here 'obj'
$outDir = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $obj, $outDir | Out-Null
$wixobj = Join-Path $obj 'MandatnikAgent.wixobj'
$ext = Join-Path $WixDir 'WixUtilExtension.dll'

& (Join-Path $WixDir 'candle.exe') -nologo -arch x64 -ext $ext `
    "-dAgentExe=$((Resolve-Path $AgentExe).Path)" `
    "-dExampleConfig=$((Resolve-Path $ExampleConfig).Path)" `
    "-dProductVersion=$ProductVersion" `
    "-dProductCode=$ProductCode" `
    "-dUpgradeCode=$UpgradeCode" `
    -out $wixobj (Join-Path $here 'MandatnikAgent.wxs')
if ($LASTEXITCODE -ne 0) { throw "candle failed with exit code $LASTEXITCODE" }

& (Join-Path $WixDir 'light.exe') -nologo -ext $ext -out $Output $wixobj
if ($LASTEXITCODE -ne 0) { throw "light failed with exit code $LASTEXITCODE" }

$hash = (Get-FileHash -Algorithm SHA256 $Output).Hash.ToLowerInvariant()
Write-Host "MSI: $Output"
Write-Host "SHA256: $hash"
