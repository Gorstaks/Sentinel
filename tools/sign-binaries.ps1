<#
.SYNOPSIS
    Authenticode-signs Sentinel's own binaries (Sentinel*.dll / Sentinel*.exe / SentinelSetup-*.exe).

.DESCRIPTION
    Called by installer\build.ps1 for the publish folder and again for the produced installer.
    Third-party files (Microsoft.*, System.*, NuGet dependencies) are never touched.

    An unsigned security product is the single biggest cause of VirusTotal heuristic verdicts.
    This script never invents a certificate. Configure ONE signing source via environment:

      Certificate in the Windows store (hardware token / cloud HSM CSP included):
        SENTINEL_SIGN_CERT_THUMBPRINT   SHA-1 thumbprint (CurrentUser\My or LocalMachine\My)

      PFX file (only for test certificates; public CAs no longer issue exportable keys):
        SENTINEL_SIGN_PFX               path to .pfx
        SENTINEL_SIGN_PFX_PASSWORD      its password

      Microsoft Trusted/Artifact Signing (signtool dlib):
        SENTINEL_SIGN_DLIB              path to Azure.CodeSigning.Dlib.dll
        SENTINEL_SIGN_METADATA          path to metadata.json (endpoint, account, profile)

      Optional:
        SENTINEL_SIGN_TIMESTAMP_URL     RFC 3161 timestamp server (default http://timestamp.digicert.com)
        SENTINEL_REQUIRE_SIGNING=1      same as -Required

    Without a configured source the script prints a prominent warning and exits 0, so local
    builds still work, unless -Required is set (release builds), in which case it exits 1.
#>
param(
    [Parameter(Mandatory = $true)][string]$TargetDirectory,
    [switch]$Required
)

$ErrorActionPreference = 'Stop'
if ($env:SENTINEL_REQUIRE_SIGNING -eq '1') { $Required = $true }

function Fail-OrWarn([string]$message) {
    if ($Required) {
        Write-Host "SIGNING FAILED: $message" -ForegroundColor Red
        exit 1
    }
    Write-Host ''
    Write-Host '!!! ============================================================ !!!' -ForegroundColor Red
    Write-Host "!!!  UNSIGNED BUILD: $message" -ForegroundColor Red
    Write-Host '!!!  VirusTotal / SmartScreen will flag unsigned Sentinel binaries.' -ForegroundColor Red
    Write-Host '!!!  See tools\sign-binaries.ps1 header for signing configuration.' -ForegroundColor Red
    Write-Host '!!! ============================================================ !!!' -ForegroundColor Red
    Write-Host ''
    exit 0
}

if (-not (Test-Path -LiteralPath $TargetDirectory)) { Fail-OrWarn "target directory not found: $TargetDirectory" }

# Locate signtool.exe (newest Windows SDK first, x64 preferred).
function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin")
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $found = Get-ChildItem -LiteralPath $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object { $_.Directory.Parent.Name } -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

$signTool = Find-SignTool
if (-not $signTool) { Fail-OrWarn 'signtool.exe not found (install the Windows 10/11 SDK signing tools)' }

$timestamp = if ($env:SENTINEL_SIGN_TIMESTAMP_URL) { $env:SENTINEL_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

# Build the certificate-selection arguments from exactly one configured source.
$certArgs = $null
if ($env:SENTINEL_SIGN_CERT_THUMBPRINT) {
    $thumb = ($env:SENTINEL_SIGN_CERT_THUMBPRINT -replace '\s', '').ToUpperInvariant()
    if ($thumb -notmatch '^[0-9A-F]{40}$') { Fail-OrWarn 'SENTINEL_SIGN_CERT_THUMBPRINT is not a 40-hex SHA-1 thumbprint' }
    $inMachine = Test-Path -LiteralPath "Cert:\LocalMachine\My\$thumb"
    $inUser = Test-Path -LiteralPath "Cert:\CurrentUser\My\$thumb"
    if (-not ($inMachine -or $inUser)) { Fail-OrWarn "certificate $thumb not found in CurrentUser\My or LocalMachine\My" }
    $certArgs = @('/sha1', $thumb)
    if ($inMachine -and -not $inUser) { $certArgs += '/sm' }
}
elseif ($env:SENTINEL_SIGN_PFX) {
    if (-not (Test-Path -LiteralPath $env:SENTINEL_SIGN_PFX)) { Fail-OrWarn 'SENTINEL_SIGN_PFX file not found' }
    $certArgs = @('/f', $env:SENTINEL_SIGN_PFX)
    if ($env:SENTINEL_SIGN_PFX_PASSWORD) { $certArgs += @('/p', $env:SENTINEL_SIGN_PFX_PASSWORD) }
}
elseif ($env:SENTINEL_SIGN_DLIB -and $env:SENTINEL_SIGN_METADATA) {
    foreach ($f in @($env:SENTINEL_SIGN_DLIB, $env:SENTINEL_SIGN_METADATA)) {
        if (-not (Test-Path -LiteralPath $f)) { Fail-OrWarn "signing dlib/metadata file not found: $f" }
    }
    $certArgs = @('/dlib', $env:SENTINEL_SIGN_DLIB, '/dmdf', $env:SENTINEL_SIGN_METADATA)
}
else {
    Fail-OrWarn 'no signing certificate configured'
}

# Only Sentinel's own binaries. Never re-sign or sign third-party dependencies.
$targets = Get-ChildItem -LiteralPath $TargetDirectory -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.dll', '.exe' -and $_.Name -like 'Sentinel*' }
if (-not $targets) {
    Write-Host "No Sentinel binaries to sign under $TargetDirectory" -ForegroundColor Yellow
    exit 0
}

$failed = @()
foreach ($file in $targets) {
    $existing = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($existing.Status -eq 'Valid') {
        Write-Host "Already signed: $($file.Name)" -ForegroundColor DarkGray
        continue
    }
    Write-Host "Signing $($file.FullName)" -ForegroundColor Yellow
    $signArgs = @('sign', '/fd', 'SHA256', '/tr', $timestamp, '/td', 'SHA256', '/d', 'Sentinel') + $certArgs + @($file.FullName)
    & $signTool @signArgs
    if ($LASTEXITCODE -ne 0) { $failed += $file.Name; continue }
    & $signTool verify /pa /q $file.FullName
    if ($LASTEXITCODE -ne 0) { $failed += $file.Name }
}

if ($failed.Count -gt 0) {
    $msg = "signing or verification failed for: $($failed -join ', ')"
    if ($Required) { Write-Host "SIGNING FAILED: $msg" -ForegroundColor Red; exit 1 }
    Write-Warning $msg
    exit 0
}
Write-Host "Signed and verified $($targets.Count) Sentinel binaries." -ForegroundColor Green
exit 0
