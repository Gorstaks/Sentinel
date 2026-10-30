[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$InputPaths,
    [string]$OutputDirectory = 'TestResults/Defender'
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Actual Windows Defender is required; this check cannot be skipped or simulated.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $OutputDirectory).Path
$reportPath = Join-Path $outputRoot 'defender-scan.json'
$report = [ordered]@{ StartedUtc=[DateTime]::UtcNow.ToString('O'); Status='NotPassed'; Engine=$null; Signature=$null; SignatureUpdated=$null; Files=@(); ExitCode=$null; Error=$null }
# Keep scan targets outside the workspace and user-controlled TEMP/exclusion roots.
$scanRoot = Join-Path ($env:SystemDrive + '\') ('SentinelDefenderValidation-' + [Guid]::NewGuid().ToString('N'))
try {
    Import-Module Defender -ErrorAction Stop
    $status = Get-MpComputerStatus -ErrorAction Stop
    if ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
        (-not $status.AMServiceEnabled -or -not $status.RealTimeProtectionEnabled)) {
        # Enable protection only on the disposable runner. Never disable it or add exclusions.
        Start-Service WinDefend -ErrorAction Stop
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        $status = Get-MpComputerStatus -ErrorAction Stop
    }
    for ($attempt=0; $attempt -lt 15; $attempt++) {
        if ($status.AMServiceEnabled -and $status.AntivirusEnabled -and $status.RealTimeProtectionEnabled -and $status.AMRunningMode -eq 'Normal') { break }
        Start-Sleep -Seconds 2
        $status = Get-MpComputerStatus -ErrorAction Stop
    }
    $report['Availability'] = $status | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode
    if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled -or $status.AMRunningMode -ne 'Normal') {
        throw ('Defender unavailable: AMServiceEnabled={0}; AntivirusEnabled={1}; RealTimeProtectionEnabled={2}; AMRunningMode={3}. Unavailable is NOT a pass.' -f $status.AMServiceEnabled,$status.AntivirusEnabled,$status.RealTimeProtectionEnabled,$status.AMRunningMode)
    }
    Update-MpSignature -ErrorAction Stop
    $status = Get-MpComputerStatus -ErrorAction Stop
    $report.Engine = $status.AMEngineVersion
    $report.Signature = $status.AntivirusSignatureVersion
    $report.SignatureUpdated = $status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('O')
    if (([DateTime]::UtcNow - $status.AntivirusSignatureLastUpdated.ToUniversalTime()) -gt [TimeSpan]::FromDays(2)) { throw 'Defender signatures are stale; release blocked.' }
    $platform = Join-Path $env:ProgramData 'Microsoft/Windows Defender/Platform'
    $command = Get-ChildItem -LiteralPath $platform -Directory -ErrorAction Stop | Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $command) { throw 'Supported Defender MpCmdRun.exe was not found.' }
    $preference = Get-MpPreference -ErrorAction Stop
    if ([int]$preference.MAPSReporting -eq 0) {
        if ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') {
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
        } else { throw 'Defender cloud protection must be enabled for compatibility validation.' }
    }
    $cloudExit = -1
    for ($attempt=0; $attempt -lt 3; $attempt++) {
        & $command -ValidateMapsConnection 2>&1 | Out-File -LiteralPath (Join-Path $outputRoot 'cloud-connection.txt') -Append -Encoding utf8
        $cloudExit = $LASTEXITCODE
        if ($cloudExit -eq 0) { break }
        if ($attempt -lt 2) { Start-Sleep -Seconds 5 }
    }
    $report['CloudValidationExitCode'] = $cloudExit
    if ($cloudExit -ne 0) {
        $detail = (Get-Content -LiteralPath (Join-Path $outputRoot 'cloud-connection.txt') -Tail 30) -join ' '
        if ($detail.Length -gt 1800) { $detail = $detail.Substring(0,1800) }
        throw ('Defender cloud connection validation failed (exit ' + $cloudExit + '); verdict coverage is unverified. ' + $detail)
    }

    New-Item -ItemType Directory -Path $scanRoot | Out-Null
    $index = 0
    foreach ($inputPath in $InputPaths) {
        $source = Get-Item -LiteralPath $inputPath -ErrorAction Stop
        if (($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Scan inputs must not be reparse points.' }
        $destination = Join-Path $scanRoot ([string]$index)
        New-Item -ItemType Directory -Path $destination | Out-Null
        Copy-Item -LiteralPath $source.FullName -Destination $destination -Recurse -Force -ErrorAction Stop
        $index++
    }
    $files = @(Get-ChildItem -LiteralPath $scanRoot -File -Recurse)
    if (-not ($files | Where-Object Name -eq 'Sentinel.Core.dll')) { throw 'The actual Sentinel.Core.dll payload must be scanned.' }
    $report.Files = @($files | ForEach-Object { [ordered]@{ Path=$_.FullName.Substring($scanRoot.Length); SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
    # This custom-scan option reports detections without silently treating successful
    # remediation as a clean scan. It does NOT turn off Defender or its real-time protection.
    $process = Start-Process -FilePath $command -ArgumentList @('-Scan','-ScanType','3','-File',$scanRoot,'-DisableRemediation') -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $outputRoot 'scan-stdout.txt') -RedirectStandardError (Join-Path $outputRoot 'scan-stderr.txt')
    if (-not $process.WaitForExit(600000)) { $process.Kill(); throw 'Defender scan timed out; release blocked.' }
    $process.WaitForExit()
    $report.ExitCode = $process.ExitCode
    if ($process.ExitCode -ne 0) {
        $detail = (Get-Content -LiteralPath (Join-Path $outputRoot 'scan-stdout.txt') -Tail 30) -join ' '
        if ($detail.Length -gt 1800) { $detail = $detail.Substring(0,1800) }
        throw ('Defender custom scan did not pass. Exit code: ' + $process.ExitCode + '. ' + $detail)
    }
    foreach ($file in $report.Files) {
        $path = $scanRoot + $file.Path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.SHA256) {
            throw ('A scanned payload was removed or changed (including possible real-time quarantine): ' + $file.Path)
        }
    }
    $after = Get-MpComputerStatus -ErrorAction Stop
    if (-not $after.AntivirusEnabled -or -not $after.RealTimeProtectionEnabled -or $after.AMRunningMode -ne 'Normal') { throw 'Defender ceased to be active during validation.' }
    $report.Status = 'Passed'
    Write-Host 'Actual Defender scan passed; engine, signatures and exact file hashes recorded.'
} catch {
    $report.Error = $_.Exception.Message
    try {
        $report['Detections'] = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -Last 20 | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,Resources)
        $report['ThreatNames'] = @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatID,ThreatName,IsActive)
    } catch { $report['DetectionEvidenceError'] = $_.Exception.GetType().Name }
    Write-Host ('::error title=Defender release gate::' + $report.Error.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A'))
    throw
} finally {
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding utf8
    if (Test-Path -LiteralPath $scanRoot) { Remove-Item -LiteralPath $scanRoot -Recurse -Force -ErrorAction Continue }
}
