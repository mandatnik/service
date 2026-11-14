# Read-only capability probe; never reads or writes serial numbers.
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ActivationExports {
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr LoadLibrary(string path);
 [DllImport("kernel32",CharSet=CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("kernel32")] public static extern bool FreeLibrary(IntPtr module);
}
'@
$obj=New-Object -ComObject 'CPCSPLicense.CPCSPLicense'
$members=@($obj | Get-Member | Select-Object Name,Definition)
$products=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | Where-Object PSChildName -in @('{407E5BA7-6406-40BF-A4DC-3654B8F584C1}','{50F91F80-D397-437C-B0C8-62128DE3B55E}') | ForEach-Object {
 [pscustomobject]@{GUID=$_.PSChildName;Version=(Get-ItemProperty $_.PSPath).DisplayVersion;Type=$obj.GetType($_.PSChildName);Expires=$obj.GetExpireDate($_.PSChildName).ToString('o')}
})
$exports=@(foreach($path in @('C:\Program Files\Common Files\Crypto Pro\Shared\cplicmgmt.dll','C:\Program Files\Crypto Pro\CSP\cpcsp.dll','C:\Program Files\Crypto Pro\CSP\cpconfig.cpl')) {
 $h=[ActivationExports]::LoadLibrary($path)
 try { [pscustomobject]@{Path=$path;Loaded=($h -ne [IntPtr]::Zero);Exports=@(foreach($name in @('license_get','license_check','license_set','SetLicense','SetSerialNumber')){if($h -ne [IntPtr]::Zero -and [ActivationExports]::GetProcAddress($h,$name) -ne [IntPtr]::Zero){$name}})} }
 finally {if($h -ne [IntPtr]::Zero){[void][ActivationExports]::FreeLibrary($h)}}
})
[pscustomobject]@{Host=$env:COMPUTERNAME;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Session=[Diagnostics.Process]::GetCurrentProcess().SessionId;Products=$products;COMMembers=$members;NativeExports=$exports;LicenseWriteAttempted=$false;CollectedUTC=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $Directory 'report.json')
