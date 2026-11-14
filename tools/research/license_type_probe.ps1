# Internal helper: stdout includes sensitive license bytes. Use only through
# check-license-type.py, which consumes them in memory and emits a redacted result.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LicenseReadOnlyProbe {
    [DllImport("advapi32.dll", EntryPoint="CryptAcquireContextW", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool Acquire(out IntPtr provider, string container, string name, uint type, uint flags);
    [DllImport("advapi32.dll", EntryPoint="CryptGetProvParam", SetLastError=true)]
    static extern bool Get(IntPtr provider, uint parameter, byte[] data, ref uint size, uint flags);
    [DllImport("advapi32.dll", EntryPoint="CryptReleaseContext", SetLastError=true)]
    static extern bool Release(IntPtr provider, uint flags);
    public static byte[] Read() {
        IntPtr provider;
        if(!Acquire(out provider,null,"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",80,0xF0000040))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"CryptAcquireContext(VERIFYCONTEXT|SILENT)");
        try {
            uint size=0;
            if(!Get(provider,158,null,ref size,0))throw new Win32Exception(Marshal.GetLastWin32Error(),"PP_LICENSE size");
            byte[] data=new byte[size];
            if(!Get(provider,158,data,ref size,0))throw new Win32Exception(Marshal.GetLastWin32Error(),"PP_LICENSE read");
            return data;
        }finally{Release(provider,0);}
    }
}
'@
$product=Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'|Where-Object PSChildName -in @('{407E5BA7-6406-40BF-A4DC-3654B8F584C1}','{50F91F80-D397-437C-B0C8-62128DE3B55E}')|Select-Object -First 1
if(-not $product){throw 'Installed CSP product not found'}
$obj=New-Object -ComObject 'CPCSPLicense.CPCSPLicense'
$secret=[LicenseReadOnlyProbe]::Read()
try {
    [pscustomobject]@{
        Host=$env:COMPUTERNAME
        Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        ProductVersion=(Get-ItemProperty $product.PSPath).DisplayVersion
        COMType=$obj.GetType($product.PSChildName)
        COMExpire=$obj.GetExpireDate($product.PSChildName).ToString('o')
        LicenseBytesBase64=[Convert]::ToBase64String($secret)
    }|ConvertTo-Json -Compress
}finally{[Array]::Clear($secret,0,$secret.Length)}
