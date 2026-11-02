$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot '../../src/Sentinel.Core/HardeningResources/GSecurity.inf'
$text = Get-Content -LiteralPath $path -Raw
if ($text -match '(?im)^\s*\[Privilege Rights\]\s*$') { throw 'Shipping policy must not replace global Windows privilege/logon-right assignments.' }
$section = ''; $seen = @{}; $audit = @{}
foreach ($raw in ($text -split '\r?\n')) {
    $line = $raw.Trim()
    if (-not $line -or $line.StartsWith(';')) { continue }
    if ($line -match '^\[([^\]]+)\]$') { $section = $Matches[1]; continue }
    if ($line -match '^([^=]+)=(.*)$') {
        $key = $Matches[1].Trim(); $value = $Matches[2].Trim()
        $identity = $section + ':' + $key
        if ($seen.ContainsKey($identity)) { throw "Duplicate security policy assignment: $identity" }
        $seen[$identity] = $true
        if ($section -eq 'Event Audit') { $audit[$key] = $value }
        if ($section -eq 'System Access' -and
            $key -in @('MinimumPasswordLength','PasswordComplexity','PasswordHistorySize') -and $value -eq '0') {
            throw "Shipping policy must not weaken existing password requirements: $key"
        }
        if ($section -eq 'Registry Values' -and
            $key -eq 'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled' -and $value -eq '4,0') {
            throw 'Shipping policy must not force FIPS policy off.'
        }
    }
}
foreach ($key in @('AuditSystemEvents','AuditLogonEvents','AuditObjectAccess','AuditPrivilegeUse','AuditPolicyChange','AuditAccountManage','AuditProcessTracking','AuditDSAccess','AuditAccountLogon')) {
    if ($audit[$key] -ne '3') { throw "Expected success/failure declaration restored for $key" }
}
Write-Host 'Passed security-template checks: no global user-right overrides, no duplicate assignments, declared audit policy restored.'
