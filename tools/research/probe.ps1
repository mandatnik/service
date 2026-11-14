param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
[void][Reflection.Assembly]::LoadFrom((Join-Path $Directory 'ServiceProbe.exe'))
$report=[ordered]@{ Host=$env:COMPUTERNAME; StartedUTC=[DateTime]::UtcNow.ToString('o'); Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; SessionID=[Diagnostics.Process]::GetCurrentProcess().SessionId; Errors=@() }
$suffix='Software\Microsoft\SystemCertificates\My'
function Mount-Hive($Name,$Hive) {
    $text=& reg.exe load "HKU\$Name" $Hive 2>&1
    if($LASTEXITCODE -ne 0){throw "reg load failed: $text"}
}
function Unmount-Hive($Name) {
    [GC]::Collect();[GC]::WaitForPendingFinalizers()
    $text=& reg.exe unload "HKU\$Name" 2>&1
    if($LASTEXITCODE -ne 0){throw "reg unload failed: $text"}
}
try {
    if($report.SID -ne 'S-1-5-18'){throw 'Probe must run as LocalSystem'}
    [NativeProbe]::Enable('SeBackupPrivilege');[NativeProbe]::Enable('SeRestorePrivilege')
    $report.PrivilegesEnabled=@('SeBackupPrivilege','SeRestorePrivilege')
    $report.Timezone=(Get-TimeZone).Id
    $report.LocalTime=[DateTime]::Now.ToString('o')
    $report.OS=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'|Select-Object ProductName,CurrentBuild,UBR
    $products=@(foreach($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){Get-ChildItem $base|ForEach-Object {$v=Get-ItemProperty $_.PSPath;if(@('{407E5BA7-6406-40BF-A4DC-3654B8F584C1}','{50F91F80-D397-437C-B0C8-62128DE3B55E}') -contains $_.PSChildName){[pscustomobject]@{Name=$v.DisplayName;Version=$v.DisplayVersion;Product=$_.PSChildName}}}})
    $report.Products=$products
    $obj=New-Object -ComObject 'CPCSPLicense.CPCSPLicense'
    $report.Licenses=@(foreach($product in $products){try{$install=$obj.GetInstallDate($product.Product);$expire=$obj.GetExpireDate($product.Product);[pscustomobject]@{Product=$product.Product;TypeCode=$obj.GetType($product.Product);InstallRaw=$install.ToString('o');ExpireRaw=$expire.ToString('o');DateTimeKind=$expire.Kind.ToString();ExpireInterpretedUTC=[TimeZoneInfo]::ConvertTimeToUtc([DateTime]::SpecifyKind($expire,[DateTimeKind]::Unspecified),[TimeZoneInfo]::Local).ToString('o');ExpiredByLocalClock=($expire -lt [DateTime]::Now)}}catch{[pscustomobject]@{Product=$product.Product;Error=$_.Exception.Message}}})
    $report.CurrentSystemMy=@([NativeProbe]::ReadOwnMy())
    $profiles=@(Get-CimInstance Win32_UserProfile |Where-Object {-not $_.Special -and $_.SID -like 'S-1-5-21-*'})
    $report.ProfilesBefore=$profiles|Select-Object SID,LocalPath,Loaded
    $report.LoadedProfileReads=@(foreach($p in $profiles|Where-Object Loaded){try{[pscustomobject]@{SID=$p.SID;Path=$p.LocalPath;Result=[NativeProbe]::Read(($p.SID+'\'+$suffix))}}catch{[pscustomobject]@{SID=$p.SID;Error=$_.Exception.Message}}})
    $target=@($profiles|Where-Object { -not $_.Loaded -and $_.LocalPath -match '\\user[12]$'})
    if($target.Count -ne 1){throw 'Need exactly one unloaded user1/user2 target'}
    $p=$target[0];$mount='TelehackResearch_'+[guid]::NewGuid().ToString('N');$hive=Join-Path $p.LocalPath 'NTUSER.DAT'
    $state=[ordered]@{SID=$p.SID;Path=$p.LocalPath;LoadedBefore=$p.Loaded;Mount=$mount;Seeded=$false;ReadSucceeded=$false;FixtureCleaned=$false;Unmounted=$false}
    $report.OfflineTest=$state
    $files=@(Get-ChildItem (Join-Path $Directory 'fixtures') -Filter '*.cer'|Sort-Object Name|ForEach-Object FullName)
    if($files.Count -ne 3){throw 'Exactly 3 public fixtures required'}
    $expected=@(foreach($f in $files){$c=[Security.Cryptography.X509Certificates.X509Certificate2]::new($f);try{[pscustomobject]@{File=[IO.Path]::GetFileName($f);Thumbprint=$c.Thumbprint;SHA256=(Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant()}}finally{$c.Dispose()}})
    $state.Expected=$expected
    $mounted=$false;$seeded=$false;$baseline=$null
    try {
        if((Get-CimInstance Win32_UserProfile|Where-Object SID -eq $p.SID).Loaded){throw 'Target became loaded; aborting'}
        Mount-Hive $mount $hive;$mounted=$true
        $baseline=[NativeProbe]::Read(($mount+'\'+$suffix));$state.Baseline=$baseline
        foreach($e in $expected){if($baseline.Certificates.Thumbprint -contains $e.Thumbprint){throw 'Fixture already present; aborting'}}
        $state.ParentExisted=Test-Path ('Registry::HKEY_USERS\'+$mount+'\Software\Microsoft\SystemCertificates')
        [NativeProbe]::Seed(($mount+'\'+$suffix),[string[]]$files);$seeded=$true;$state.Seeded=$true
        Unmount-Hive $mount;$mounted=$false;$state.UnmountedAfterSeed=$true
        $state.LoadedBetween=(Get-CimInstance Win32_UserProfile|Where-Object SID -eq $p.SID).Loaded
        if($state.LoadedBetween){throw 'Target logged in between stages'}
        Mount-Hive $mount $hive;$mounted=$true
        $read=[NativeProbe]::Read(($mount+'\'+$suffix));$state.Collected=$read
        $found=@($read.Certificates|Where-Object {$expected.SHA256 -contains $_.SHA256})
        $state.MatchedFixtures=$found.Count
        if($found.Count -ne 3){throw 'Not all offline fixture certificates collected'}
        $state.ReadSucceeded=$true
    } finally {
        if($seeded){
            if(-not $mounted){Mount-Hive $mount $hive;$mounted=$true}
            foreach($e in $expected){$key=[Microsoft.Win32.Registry]::Users.OpenSubKey(($mount+'\'+$suffix+'\Certificates'),$true);if($key){try{$key.DeleteSubKeyTree($e.Thumbprint,$false)}finally{$key.Dispose()}}}
            if(-not $baseline.Exists){$key=[Microsoft.Win32.Registry]::Users.OpenSubKey(($mount+'\Software\Microsoft\SystemCertificates'),$true);if($key){try{$key.DeleteSubKeyTree('My',$false)}finally{$key.Dispose()}}}
            if(-not $state.ParentExisted){$key=[Microsoft.Win32.Registry]::Users.OpenSubKey(($mount+'\Software\Microsoft'),$true);try{$parent=$key.OpenSubKey('SystemCertificates');if($parent){$empty=($parent.SubKeyCount -eq 0 -and $parent.ValueCount -eq 0);$parent.Dispose();if($empty){$key.DeleteSubKey('SystemCertificates',$false)}}}finally{if($key){$key.Dispose()}}}
            $clean=[NativeProbe]::Read(($mount+'\'+$suffix));$state.AfterCleanup=$clean
            $state.FixtureCleaned=(@($clean.Certificates|Where-Object {$expected.Thumbprint -contains $_.Thumbprint}).Count -eq 0 -and $clean.Certificates.Count -eq $baseline.Certificates.Count -and $clean.Exists -eq $baseline.Exists)
        }
        if($mounted){Unmount-Hive $mount;$mounted=$false;$state.Unmounted=$true}
    }
    $report.ProfilesAfter=Get-CimInstance Win32_UserProfile|Where-Object SID -eq $p.SID|Select-Object SID,LocalPath,Loaded
    $report.RemainingResearchMounts=@(Get-ChildItem Registry::HKEY_USERS|Where-Object PSChildName -like 'TelehackResearch_*'|ForEach-Object PSChildName)
} catch {$report.Errors+=($_.Exception.ToString())}
finally {
    $report.FinishedUTC=[DateTime]::UtcNow.ToString('o')
    $report|ConvertTo-Json -Depth 12|Set-Content -Encoding UTF8 (Join-Path $Directory 'report.json')
}
if($report.Errors.Count -gt 0){exit 1}
