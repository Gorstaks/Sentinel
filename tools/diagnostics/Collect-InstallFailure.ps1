# Read-only diagnostics. Does not load Sentinel.Core, change policy, restore quarantine or reboot.
[CmdletBinding()]
param([string]$OutputPath = (Join-Path $env:TEMP ('Sentinel-install-diagnostics-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.json')))
$ErrorActionPreference = 'Stop'
$report = [ordered]@{ CollectedUtc=[DateTime]::UtcNow.ToString('O'); Errors=@() }
function Read-Section($name, [scriptblock]$reader) {
    try { $report[$name] = & $reader }
    catch { $report.Errors += ($name + ': ' + $_.Exception.Message) }
}
Read-Section 'DefenderStatus' { Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMEngineVersion,AntivirusSignatureVersion,AntivirusSignatureLastUpdated }
Read-Section 'DefenderThreats' { @(Get-MpThreat | Select-Object ThreatID,ThreatName,IsActive) }
Read-Section 'DefenderDetections' { @(Get-MpThreatDetection | Select-Object -Last 25 | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,Resources) }
Read-Section 'Services' { @(Get-Service Sentinel,SentinelGuard,MpsSvc,BFE,AppXSvc,StateRepository -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType) }
Read-Section 'ApplicationFailures' {
    @(Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001,1002; StartTime=[DateTime]::Now.AddHours(-6)} -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Message -match 'SystemSettings|Sentinel|FileLoadException' } | Select-Object -First 30 TimeCreated,Id,ProviderName,Message)
}
Read-Section 'FirewallJournal' {
    $path = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Sentinel/FirewallPolicy/rollback.json'
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path
        [ordered]@{Exists=$true;Length=$item.Length;LastWriteUtc=$item.LastWriteTimeUtc;ReparsePoint=(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)}
    } else { [ordered]@{Exists=$false} }
}
Read-Section 'FirewallProfiles' { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
Read-Section 'RelevantPendingFileOperations' {
    $value = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $matches = @()
    for ($i=0; $i -lt $value.Count; $i+=2) {
        if ($value[$i] -match 'Sentinel|FileSyncShell64\.dll') {
            $matches += [ordered]@{Source=$value[$i];Destination=$(if ($i+1 -lt $value.Count) {$value[$i+1]} else {$null})}
        }
    }
    $matches
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "Read-only report saved: $OutputPath"
Write-Host 'Review before sharing; the report contains local paths and relevant Windows error messages. No data was uploaded.'
