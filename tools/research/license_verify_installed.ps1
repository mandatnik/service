# Emits only state and equality flags, never serial numbers.
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class LicenseRuntimeRead {
 [DllImport("advapi32",EntryPoint="CryptAcquireContextW",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Acquire(out IntPtr h,string container,string name,uint type,uint flags);
 [DllImport("advapi32",EntryPoint="CryptGetProvParam",SetLastError=true)] static extern bool Get(IntPtr h,uint param,byte[] buffer,ref uint size,uint flags);
 [DllImport("advapi32",EntryPoint="CryptReleaseContext")] static extern bool Release(IntPtr h,uint flags);
 public static uint AcquireCode,ReadCode;
 public static string Read() {
  IntPtr h; if(!Acquire(out h,null,"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",80,0xF0000040)){AcquireCode=(uint)Marshal.GetLastWin32Error();return null;}
  try {uint n=0;if(!Get(h,158,null,ref n,0)){ReadCode=(uint)Marshal.GetLastWin32Error();return null;}byte[] b=new byte[n];try{if(!Get(h,158,b,ref n,0)){ReadCode=(uint)Marshal.GetLastWin32Error();return null;}return (b.Length>1&&b[1]==0?Encoding.Unicode:Encoding.ASCII).GetString(b).TrimEnd('\0');}finally{Array.Clear(b,0,b.Length);}}
  finally{Release(h,0);}
 }
}
'@
$backup=[pscustomobject]@{Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\08F19F05793DC7340B8C2621D83E5BE5\InstallProperties';GUID='{50F91F80-D397-437C-B0C8-62128DE3B55E}';Value=''}
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backup.Path,$false)
try {$current=[string]$key.GetValue('ProductID')}finally{$key.Close()}
$r=[ordered]@{Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Session=[Diagnostics.Process]::GetCurrentProcess().SessionId;RegistryEqualsOriginal=($current -ceq $backup.Value);RegistryEqualsInvalidControl=($current -ceq '0000000000000000000000000')}
$runtime=[LicenseRuntimeRead]::Read()
$r.AcquireCode=('0x{0:X8}' -f [LicenseRuntimeRead]::AcquireCode)
$r.ReadLicenseCode=('0x{0:X8}' -f [LicenseRuntimeRead]::ReadCode)
$r.RuntimeEqualsRegistry=($null -ne $runtime -and ($runtime -replace '-','') -ceq ($current -replace '-',''))
$r.RuntimeEqualsOriginal=($null -ne $runtime -and ($runtime -replace '-','') -ceq ($backup.Value -replace '-',''))
$r.RuntimeEqualsInvalidControl=($null -ne $runtime -and $runtime -eq '0000000000000000000000000')
try {
 $obj=New-Object -ComObject CPCSPLicense.CPCSPLicense
 $r.COMType=$obj.GetType($backup.GUID);$r.COMExpire=$obj.GetExpireDate($backup.GUID).ToString('o');$r.COMCode='0x00000000'
} catch {
 $e=$_.Exception;while($e.InnerException){$e=$e.InnerException};$r.COMCode=('0x{0:X8}' -f $e.HResult)
}
$r.Host=$env:COMPUTERNAME
$l=New-Object -ComObject CAdESCOM.CPLicense
$r.CAdESIsValid=$l.IsValid()
$r.CAdESType=$l.Type()
$r.CAdESValidTo=$l.ValidTo()
$r.CAdESSerialEqualsRegistry=(($l.SerialNumber() -replace '-','') -ceq ($current -replace '-',''))
$r.CollectedUTC=[DateTime]::UtcNow.ToString('o')
$r.LicenseWriteAttempted=$false
$r.Remove('RegistryEqualsOriginal');$r.Remove('RegistryEqualsInvalidControl');$r.Remove('RuntimeEqualsOriginal');$r.Remove('RuntimeEqualsInvalidControl')
$r|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 (Join-Path $Directory 'report.json')
