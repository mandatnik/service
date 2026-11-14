param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$b=Import-Clixml (Join-Path $Directory 'rollback.xml')
$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($b.Path,$true)
try {
 $k.SetValue('ProductID',$b.Value,[Microsoft.Win32.RegistryValueKind]::$($b.Kind));$k.Flush()
 if($k.GetValue('ProductID') -cne $b.Value -or $k.GetValueKind('ProductID').ToString() -ne $b.Kind){throw 'Exact rollback failed'}
 [IO.File]::WriteAllText((Join-Path $Directory 'rollback-ok.txt'),'restored')
}finally{$k.Close()}
