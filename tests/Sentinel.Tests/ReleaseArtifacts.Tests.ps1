$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('SentinelArtifacts-' + [Guid]::NewGuid().ToString('N'))
$reference = Join-Path $root 'reference'
$published = Join-Path $root 'published'
$verify = Join-Path $PSScriptRoot '../../tools/validation/VerifyReleaseArtifacts.ps1'
try {
    New-Item -ItemType Directory -Path $reference,$published | Out-Null
    $names = @('SentinelSetup-3.4.6.exe', 'SentinelWorker-3.4.6.js', 'SentinelDiagnostics-3.4.6.zip')
    $manifest = foreach ($name in $names) {
        Set-Content -LiteralPath (Join-Path $reference $name) -Value ('inert fixture ' + $name)
        Copy-Item -LiteralPath (Join-Path $reference $name) -Destination $published
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $reference $name)).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    $manifest | Set-Content -LiteralPath (Join-Path $reference 'SHA256SUMS.txt') -Encoding ascii
    Copy-Item -LiteralPath (Join-Path $reference 'SHA256SUMS.txt') -Destination $published
    & $verify -Version 3.4.6 -ReferenceDirectory $reference -PublishedDirectory $published
    Set-Content -LiteralPath (Join-Path $published $names[0]) -Value 'different installer with stale checksum'
    $rejected = $false
    try { & $verify -Version 3.4.6 -ReferenceDirectory $reference -PublishedDirectory $published } catch { $rejected = $true }
    if (-not $rejected) { throw 'Changed published bytes were accepted' }
    Copy-Item -LiteralPath (Join-Path $reference $names[0]) -Destination $published -Force
    Add-Content -LiteralPath (Join-Path $published 'SHA256SUMS.txt') -Value 'unexpected manifest replacement'
    $rejected = $false
    try { & $verify -Version 3.4.6 -ReferenceDirectory $reference -PublishedDirectory $published } catch { $rejected = $true }
    if (-not $rejected) { throw 'Changed published manifest was accepted' }
    Write-Host 'Passed 3 release artifact integrity checks'
} finally { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
