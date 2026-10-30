[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$ReferenceDirectory,
    [Parameter(Mandatory)][string]$PublishedDirectory
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid release version' }
# Use fixed expected names, never paths supplied by a downloaded manifest.
$names = @("SentinelSetup-$Version.exe", "SentinelWorker-$Version.js", "SentinelDiagnostics-$Version.zip")
$referenceManifest = Join-Path $ReferenceDirectory 'SHA256SUMS.txt'
$publishedManifest = Join-Path $PublishedDirectory 'SHA256SUMS.txt'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $referenceManifest).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $publishedManifest).Hash) {
    throw 'Published checksum manifest differs from the tested build manifest'
}
$lines = @(Get-Content -LiteralPath $publishedManifest | Where-Object { $_.Trim().Length -gt 0 })
if ($lines.Count -ne $names.Count) { throw 'Checksum manifest must list exactly the three shipping artifacts' }
foreach ($name in $names) {
    $expectedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ReferenceDirectory $name)).Hash.ToLowerInvariant()
    if (@($lines | Where-Object { $_ -ceq "$expectedHash  $name" }).Count -ne 1) { throw "Stale or missing checksum for $name" }
    $publishedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PublishedDirectory $name)).Hash.ToLowerInvariant()
    if ($publishedHash -ne $expectedHash) { throw "Published artifact bytes differ from the tested build: $name" }
    Write-Host "Verified published SHA256: $name"
}
