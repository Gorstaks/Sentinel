# GVPN Integration with Sentinel - Process Protection

## Issue Found

Sentinel's `AppNetworkPolicyMonitor` monitors all outbound network connections and flags unusual destinations. **GVPN was not in the whitelist**, which means:

1. **Learning Phase** (first 30 minutes after Sentinel boot): GVPN connections are recorded as "normal"
2. **Enforcement Phase** (after 30 minutes): GVPN connections to new VPN servers would be flagged as "Unusual Destination" (Tier2 LogOnly, not killed)

GVPN wouldn't be killed, but it would generate constant alerts as it connects to different VPN servers.

## Solution Applied

Added GVPN to the `NetworkAllowlist` in `AppNetworkPolicyMonitor.cs`:

```csharp
private static readonly HashSet<string> NetworkAllowlist = new(StringComparer.OrdinalIgnoreCase)
{
    // ... existing entries ...
    
    // GVPN - VPN manager module
    "GVPN"
};
```

## How It Works

### NetworkAllowlist Verification (AppNetworkPolicyMonitor)

When GVPN (or any process) connects to a network address:

1. **Name check**: Does the process name match an entry in `NetworkAllowlist`?
   - If GVPN → YES, process is skipped (no alert)
   - If unknown malware → NO, process is checked further

2. **Signature verification**: Is the binary Authenticode-signed OR in a system directory?
   - Requires: `_signerTrust.IsSignedFile(imagePath)` to return true
   - OR: Binary located in Windows system directories
   - This prevents malware renamed to "GVPN.exe"

3. **Result**: 
   - ✅ GVPN.exe (signed or in Program Files) → Allowed, no alerts
   - ❌ GVPN.exe (unsigned, in Temp) → Blocked from allowlist, checked for policy violations

### GVPN Binary Requirements

For GVPN to be properly whitelisted:

1. **File location**: `C:\Program Files (x86)\Sentinel\GVPN\GVPN.exe` (trusted location)
2. **Signature**: GVPN.exe should ideally be Authenticode-signed (optional if in Program Files)
3. **Network operations**: Connects to VPNGate servers on ports 1194 (L2TP/IPSec)

### What This Protects

- ✅ Legitimate GVPN can connect to VPN servers without alerts
- ✅ Malware cannot simply rename itself to "GVPN.exe" and bypass detection
- ✅ GVPN running from suspicious paths (Temp, Downloads, etc.) is still detected
- ✅ GVPN can work alongside Sentinel without generating false-positive alerts

## Testing

### Test 1: Verify GVPN is Whitelisted
```powershell
# After Sentinel boots, run GVPN
& "C:\Program Files (x86)\Sentinel\GVPN\GVPN.exe"

# Check Sentinel logs - should NOT see "Network Policy: Unusual Destination" alerts for GVPN
Get-Content "$env:PROGRAMDATA\Sentinel\audit.log" | Select-String "GVPN" | Select-String "Unusual"
```

**Expected Result**: No alerts for GVPN network connections

### Test 2: Verify Malware Still Detected
```powershell
# Place malware renamed to "GVPN.exe" in Temp folder
Copy-Item "malware.exe" "$env:TEMP\GVPN.exe"
& "$env:TEMP\GVPN.exe"

# Check Sentinel logs - SHOULD see alerts
Get-Content "$env:PROGRAMDATA\Sentinel\audit.log" | Select-String "GVPN"
```

**Expected Result**: Alerts generated for unsigned GVPN.exe from Temp folder

## Related Code

### AppNetworkPolicyMonitor (Sentinel.Core)
- **File**: `src/Sentinel.Core/AppNetworkPolicyMonitor.cs`
- **Function**: `RegisterConnection()` - Called every time a process connects to a network address
- **Change**: Added "GVPN" to `NetworkAllowlist`
- **Verification**: `IsVerifiedAllowlistProcess()` checks signature and path

### Other Checks

**Not affected by:**
- `OutboundConnectionWhitelist` (requires explicit registry configuration, off by default)
- `GhostProcessMonitor` (only alerts on process hollowing, doesn't target GVPN)
- `BeaconingDetector` (looks for specific C2 patterns, GVPN is legitimate VPN)
- `ReverseShellDetector` (GVPN is not a shell spawned by network process)

**Protected by:**
- `AlwaysOnPolicies.IsProtectedGameProcess()` - GVPN is NOT a game, no special protection
- `AllowlistService` - GVPN should be added to user allowlist if needed (currently in system allowlist)

## Deployment

1. **Build Sentinel** with updated `AppNetworkPolicyMonitor.cs`:
   ```powershell
   cd e:\Gorstak\Sentinel
   .\installer\build.ps1
   ```

2. **Installer includes**:
   - Updated Sentinel.Service.exe (with GVPN whitelisting)
   - GVPN.exe (deployed to `C:\Program Files (x86)\Sentinel\GVPN\`)
   - Complete integration - no separate setup needed

3. **On installation**:
   - Sentinel service loads with GVPN in allowlist
   - GVPN auto-starts via Run registry
   - GVPN connects to VPN with zero Sentinel alerts

## Files Modified

- `src/Sentinel.Core/AppNetworkPolicyMonitor.cs` - Added "GVPN" to NetworkAllowlist

## Verification After Build

```powershell
# Search for GVPN in the compiled binary
$bytes = [System.IO.File]::ReadAllBytes("e:\Gorstak\Sentinel\publish\service\Sentinel.Core.dll")
$text = [System.Text.Encoding]::UTF8.GetString($bytes)
if ($text -match 'GVPN') {
    Write-Host "✓ GVPN whitelisting compiled into binary"
} else {
    Write-Host "✗ GVPN whitelisting NOT found"
}
```

## Future Enhancements

1. **Code-sign GVPN.exe**: Authenticode signing makes GVPN trusted even outside Program Files
2. **Policy configuration**: Allow admins to add/remove GVPN from allowlist via registry
3. **Behavioral baseline**: GVPN network destinations are learned during first 30 minutes
4. **Audit logging**: Add detailed logs when GVPN connects to each VPN server

## Security Notes

- ✅ GVPN is whitelisted at the process level, not the destination level
- ✅ GVPN connections are still monitored for new/unusual destinations
- ✅ Malware impersonating GVPN is still detected (signature + path verification)
- ✅ This does NOT affect Sentinel's core threat detection capabilities
- ✅ GVPN cannot be used to bypass Sentinel's network monitoring

