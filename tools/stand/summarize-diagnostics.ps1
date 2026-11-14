param(
    [Parameter(Mandatory=$true)][string]$DiagnosticsPath,
    [Parameter(Mandatory=$true)][string]$ManifestPath,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$manifest = [IO.File]::ReadAllText($ManifestPath, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
$fixtureHashes = @{}
foreach ($cert in $manifest.certificates) { $fixtureHashes[$cert.sha256_der] = $cert }
$diagnostic = [IO.File]::ReadAllText($DiagnosticsPath, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json

$profiles = @()
foreach ($profile in $diagnostic.collection.profiles) {
    $profiles += [ordered]@{
        sid = $profile.sid
        name = $profile.name
        profile_path = $profile.profile_path
        loaded = [bool]$profile.loaded
        store_present = [bool]$profile.store_present
        complete = [bool]$profile.complete
        error = $profile.error
    }
}
$sources = @()
foreach ($source in $diagnostic.collection.sources) {
    $fixtureCerts = @()
    $otherCount = 0
    foreach ($cert in $source.certificates) {
        if ($fixtureHashes.ContainsKey($cert.sha256)) {
            $expected = $fixtureHashes[$cert.sha256]
            $fixtureCerts += [ordered]@{
                sha256 = $cert.sha256
                serial_hex = $cert.serial_hex
                subject = $cert.subject
                not_before = $cert.not_before
                not_after = $cert.not_after
                expected_sha256 = $expected.sha256_der
                matches_manifest = ($cert.sha256 -eq $expected.sha256_der -and $cert.serial_hex -eq $expected.serial_hex)
            }
        } else {
            $otherCount++
        }
    }
    $sources += [ordered]@{
        source_type = $source.source_type
        source_key = $source.source_key
        complete = [bool]$source.complete
        error = $source.error
        certificate_count = $source.certificates.Count
        file_count = $source.files.Count
        fixture_certificates = $fixtureCerts
        non_fixture_certificate_count = $otherCount
    }
}
$mounts = @()
Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'Telehack' } | ForEach-Object { $mounts += $_.Name }
$service = Get-Service -Name TelehackAgent -ErrorAction SilentlyContinue
$summary = [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    host = $env:COMPUTERNAME
    diagnostic_file = $DiagnosticsPath
    identity = $diagnostic.identity
    service = if ($service) { [ordered]@{ name=$service.Name; status=$service.Status.ToString() } } else { $null }
    profiles = $profiles
    sources = $sources
    csp = [ordered]@{
        product_version = $diagnostic.collection.csp.product_version
        core_version = $diagnostic.collection.csp.core_version
        present = [bool]$diagnostic.collection.csp.present
        complete = [bool]$diagnostic.collection.csp.complete
        error = $diagnostic.collection.csp.error
        license = [ordered]@{
            kind = $diagnostic.collection.csp.license.kind
            kind_raw = $diagnostic.collection.csp.license.kind_raw
            kind_source = $diagnostic.collection.csp.license.kind_source
            state = $diagnostic.collection.csp.license.state
            valid_to_raw = $diagnostic.collection.csp.license.valid_to_raw
            valid_to_utc = $diagnostic.collection.csp.license.valid_to_utc
            time_basis = $diagnostic.collection.csp.license.time_basis
            term_kind = $diagnostic.collection.csp.license.term_kind
            is_trial = $diagnostic.collection.csp.license.is_trial
        }
    }
    leftover_telehack_mounts = $mounts
}
$directory = Split-Path -Parent $OutputPath
if ($directory) { New-Item -ItemType Directory -Force $directory | Out-Null }
[IO.File]::WriteAllText($OutputPath, ($summary | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Write-Output $OutputPath
