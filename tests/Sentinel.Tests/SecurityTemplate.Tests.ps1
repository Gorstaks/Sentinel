$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot '../../src/Sentinel.Core/HardeningResources/GSecurity.inf'
$text = Get-Content -LiteralPath $path -Raw
# 3.6.1 restored a deliberately restrictive [Privilege Rights] section (see CHANGELOG 3.6.1 and
# V220SecurityHardeningTests). The template may assign user rights, but it must never GRANT the
# dangerous privileges to anyone, and must never grant any privilege to Everyone/Users-wide groups
# beyond the Windows defaults asserted below. (The 3.5.3 "no [Privilege Rights]" rule is superseded.)
$neverGranted = @('SeDebugPrivilege','SeTcbPrivilege','SeCreateTokenPrivilege','SeLoadDriverPrivilege',
                  'SeEnableDelegationPrivilege','SeTrustedCredManAccessPrivilege','SeCreatePermanentPrivilege')
$broadPrincipals = @('*S-1-1-0','*S-1-5-11','*S-1-5-32-545','*S-1-5-7')   # Everyone, Authenticated Users, Users, Anonymous
$broadAllowed = @('SeChangeNotifyPrivilege','SeShutdownPrivilege','SeUndockPrivilege','SeIncreaseWorkingSetPrivilege',
                  'SeTimeZonePrivilege','SeInteractiveLogonRight',
                  'SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyInteractiveLogonRight')
$section = ''; $seen = @{}; $audit = @{}; $rights = @{}
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
        if ($section -eq 'Privilege Rights') { $rights[$key] = $value }
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
foreach ($privilege in $neverGranted) {
    if ($rights.ContainsKey($privilege) -and $rights[$privilege] -ne '') { throw "Shipping policy must grant $privilege to no one (found '$($rights[$privilege])')." }
}
if ($rights.ContainsKey('SeDebugPrivilege') -eq $false) { throw 'Shipping policy must explicitly revoke SeDebugPrivilege.' }
if ($rights['SeBackupPrivilege'] -ne '*S-1-5-32-544,*S-1-5-32-551') { throw 'SeBackupPrivilege must be limited to Administrators and Backup Operators.' }
foreach ($entry in $rights.GetEnumerator()) {
    if ($broadAllowed -contains $entry.Key) { continue }
    foreach ($principal in ($entry.Value -split ',')) {
        if ($broadPrincipals -contains $principal.Trim()) { throw "Shipping policy must not grant $($entry.Key) to broad principal $principal." }
    }
}
Write-Host 'Passed security-template checks: dangerous privileges granted to no one, no broad-group grants, no duplicate assignments, declared audit policy restored.'
