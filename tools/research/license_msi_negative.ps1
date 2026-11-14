# Only the cached MSI immediate ValidatePID action. No installation sequence.
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class MSIValidationProbe {
 public delegate int UIHandler(IntPtr context,uint type,[MarshalAs(UnmanagedType.LPWStr)] string message);
 [DllImport("msi.dll")] public static extern uint MsiSetInternalUI(uint level,IntPtr window);
 [DllImport("msi.dll",CharSet=CharSet.Unicode)] public static extern IntPtr MsiSetExternalUI(UIHandler handler,uint filter,IntPtr context);
 [DllImport("msi.dll",CharSet=CharSet.Unicode)] public static extern uint MsiOpenPackageEx(string path,uint options,out uint handle);
 [DllImport("msi.dll",CharSet=CharSet.Unicode)] public static extern uint MsiSetProperty(uint handle,string name,string value);
 [DllImport("msi.dll",CharSet=CharSet.Unicode)] public static extern uint MsiGetProperty(uint handle,string name,StringBuilder buffer,ref uint size);
 [DllImport("msi.dll",CharSet=CharSet.Unicode)] public static extern uint MsiDoAction(uint handle,string name);
 [DllImport("msi.dll")] public static extern uint MsiCloseHandle(uint handle);
 public static string Get(uint h,string name) {uint n=4096;var b=new StringBuilder(4096);uint e=MsiGetProperty(h,name,b,ref n);if(e!=0)throw new Exception("MsiGetProperty error "+e);return b.ToString();}
 public static readonly List<string> LicenseMessages=new List<string>();
 public static readonly UIHandler Handler=OnMessage;
 static int OnMessage(IntPtr context,uint type,string message) {
   if(message!=null && System.Text.RegularExpressions.Regex.IsMatch(message,"serial|license|серийн|лиценз|невер",System.Text.RegularExpressions.RegexOptions.IgnoreCase)) {
     LicenseMessages.Add(System.Text.RegularExpressions.Regex.Replace(message,"[A-Za-z0-9]{5}(?:-?[A-Za-z0-9]{5}){4}","[REDACTED]"));
   }
   return 0;
 }
}
'@
$guid=if($env:COMPUTERNAME -eq 'WORKSTATION-1'){'{50F91F80-D397-437C-B0C8-62128DE3B55E}'}elseif($env:COMPUTERNAME -eq 'WORKSTATION-2'){'{407E5BA7-6406-40BF-A4DC-3654B8F584C1}'}else{throw 'Unexpected host'}
$packed=if($env:COMPUTERNAME -eq 'WORKSTATION-1'){'08F19F05793DC7340B8C2621D83E5BE5'}else{'7AB5E7046046FB044ACD63458B5F481C'}
$path='SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\'+$packed+'\InstallProperties'
$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
$key=$base.OpenSubKey($path,$false);$original=$key.GetValue('ProductID');$key.Close()
$result=[ordered]@{Host=$env:COMPUTERNAME;Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Session=[Diagnostics.Process]::GetCurrentProcess().SessionId;Method='MsiDoActionW(ValidatePID)';LicenseKeySaved=$false;InstallExecuteSequenceRun=$false;UILevel=2}
[uint32]$h=0
try {
 $i=New-Object -ComObject WindowsInstaller.Installer
 $local=$i.ProductInfo($guid,'LocalPackage');$result.CachedMSI=$local
 [void][MSIValidationProbe]::MsiSetInternalUI(2,[IntPtr]::Zero)
 [void][MSIValidationProbe]::MsiSetExternalUI([MSIValidationProbe]::Handler,14,[IntPtr]::Zero)
 $result.OpenPackageCode=[MSIValidationProbe]::MsiOpenPackageEx($local,1,[ref]$h)
 if($result.OpenPackageCode -ne 0){throw 'OpenPackage failed'}
 if([MSIValidationProbe]::MsiSetProperty($h,'ProductID','') -ne 0){throw 'SetProperty failed'}
 if([MSIValidationProbe]::MsiSetProperty($h,'PIDKEY','0000000000000000000000000') -ne 0){throw 'SetProperty failed'}
 $result.ActionCode=[MSIValidationProbe]::MsiDoAction($h,'ValidatePID')
 $result.ProductIDPresentAfterValidation=(-not [string]::IsNullOrEmpty([MSIValidationProbe]::Get($h,'ProductID')))
 $result.ProductIDEqualsInvalidInput=([MSIValidationProbe]::Get($h,'ProductID') -eq '0000000000000000000000000')
 $result.LicenseMessages=@([MSIValidationProbe]::LicenseMessages)
 $result.LicenseErrorTemplate=[MSIValidationProbe]::Get($h,'LICENSEERROR_EN')
} catch {$result.ErrorType=$_.Exception.GetType().FullName;$result.ErrorHRESULT=('0x{0:X8}' -f $_.Exception.HResult)}
finally {
 if($h -ne 0){[void][MSIValidationProbe]::MsiCloseHandle($h)}
 [void][MSIValidationProbe]::MsiSetExternalUI($null,0,[IntPtr]::Zero)
 $key=$base.OpenSubKey($path,$false);$result.RegistryUnchanged=($key.GetValue('ProductID') -ceq $original);$key.Close();$base.Close()
 $obj=New-Object -ComObject CPCSPLicense.CPCSPLicense
 $result.AfterType=$obj.GetType($guid);$result.AfterExpires=$obj.GetExpireDate($guid).ToString('o')
 $result.CollectedUTC=[DateTime]::UtcNow.ToString('o')
 $result|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 (Join-Path $Directory 'report.json')
}
