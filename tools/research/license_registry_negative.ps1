# Brief invalid-key control followed by exact restoration, with scheduled fallback.
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Actual SYSTEM service required'}
$guid=if($env:COMPUTERNAME -eq 'WORKSTATION-1'){'{50F91F80-D397-437C-B0C8-62128DE3B55E}'}elseif($env:COMPUTERNAME -eq 'WORKSTATION-2'){'{407E5BA7-6406-40BF-A4DC-3654B8F584C1}'}else{throw 'Unexpected host'}
$packed=if($env:COMPUTERNAME -eq 'WORKSTATION-1'){'08F19F05793DC7340B8C2621D83E5BE5'}else{'7AB5E7046046FB044ACD63458B5F481C'}
$path='SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\'+$packed+'\InstallProperties'
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true)
try {
 $original=$key.GetValue('ProductID');$kind=$key.GetValueKind('ProductID').ToString()
 if([string]::IsNullOrEmpty($original) -or $original -eq '0000000000000000000000000'){throw 'No baseline license'}
 [pscustomobject]@{Path=$path;Value=$original;Kind=$kind;GUID=$guid}|Export-Clixml (Join-Path $Directory 'rollback.xml')
}finally{$key.Close()}
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$task='TelehackLicenseRollback-'+[Guid]::NewGuid().ToString('N').Substring(0,12)
$r=[ordered]@{Host=$env:COMPUTERNAME;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Session=[Diagnostics.Process]::GetCurrentProcess().SessionId;Method='Registry64 ProductID + fresh-process CryptoAPI/COM';LicenseKeySavedInEvidence=$false;RegistryPath=$path;NewValidLicenseTested=$false;InvalidControlWritten=$false;RestoredExact=$false}
function Snapshot {
 $raw=& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Directory 'license_registry_snapshot.ps1') -Directory $Directory
 if($LASTEXITCODE -ne 0){throw 'State read failed'}
 $raw|ConvertFrom-Json
}
try {
 $r.Before=Snapshot
 $action=New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $Directory 'license_registry_rollback.ps1')+'" -Directory "'+$Directory+'"')
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
 Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest|Out-Null
 $r.RollbackTaskRegistered=$true
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true)
 try {$key.SetValue('ProductID','0000000000000000000000000',[Microsoft.Win32.RegistryValueKind]::String);$key.Flush();$r.InvalidControlWritten=$true}finally{$key.Close()}
 $r.WithInvalidControl=Snapshot
} catch {$r.ErrorType=$_.Exception.GetType().FullName;$r.ErrorHRESULT=('0x{0:X8}' -f $_.Exception.HResult)}
finally {
 & (Join-Path $Directory 'license_registry_rollback.ps1') -Directory $Directory
 $r.RestoredExact=Test-Path (Join-Path $Directory 'rollback-ok.txt')
 if($r.RestoredExact) {
  Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  $r.RollbackTaskDeleted=(-not [bool](Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue))
  $r.After=Snapshot
 }
 $r.CollectedUTC=[DateTime]::UtcNow.ToString('o')
 $r|ConvertTo-Json -Depth 8|Set-Content -Encoding UTF8 (Join-Path $Directory 'report.json')
}
