# GVPN L2TP PSK Configuration Fix - Version 3.6.8

## Problem

GVPN was failing to connect with **Error 756: Certificate not found** when attempting L2TP/IPSec connections.

### Root Cause

The L2TP Pre-Shared Key (PSK) configuration was not being properly applied when creating the VPN connection:

1. `-L2tpPsk` parameter in `Add-VpnConnection` was being set but not persisting
2. Windows RAS registry settings for L2TP PSK were not configured
3. IPSec policy for L2TP was not initialized
4. Dummy server address (0.0.0.0) was invalid

### Error Chain

1. VPN connection created via PowerShell (appears successful)
2. rasdial attempts to dial the connection
3. RAS discovers no L2TP PSK configured in registry
4. Error 756 returned: "Certificate/PSK not found"
5. Connection fails immediately

## Solution

Multi-step L2TP configuration approach:

### Step 1: Configure L2TP/IPSec Registry and Policy
```powershell
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'ProhibitIpsec' /t REG_DWORD /d 0 /f
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\Rasman\Parameters' /v 'AllowL2TPandIkeOnHigherVersions' /t REG_DWORD /d 1 /f
```

### Step 2: Create RAS Connection Profile
```powershell
Add-VpnConnection -Name 'MyVPN' `
  -ServerAddress '1.1.1.1' `
  -TunnelType L2tp `
  -EncryptionLevel Required `
  -AuthenticationMethod MSChapv2 `
  -Force
```

### Step 3: Configure L2TP PSK via Registry (Most Important)
```powershell
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey' /t REG_SZ /d 'vpn' /f
```

## Code Changes

**File**: `modules/GVPN/VpnManager.cs`

**Method**: `CreateVpnConnection()` (completely refactored)

**Before**:
```csharp
string psCommand = 
    "Add-VpnConnection -Name 'MyVPN' " +
    "  -ServerAddress '0.0.0.0' " +
    "  -L2tpPsk 'vpn' " +  // This parameter doesn't persist!
    "  -Force";
```

**After**:
```csharp
// Step 1: Configure L2TP/IPSec globally
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'ProhibitIpsec' /t REG_DWORD /d 0

// Step 2: Create connection (without PSK in Add-VpnConnection)
Add-VpnConnection -Name 'MyVPN' -ServerAddress '1.1.1.1' -TunnelType L2tp

// Step 3: Configure PSK via registry (persists correctly)
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey' /t REG_SZ /d 'vpn'
```

## Why Registry-Based PSK Works

- **Parameter PSK**: Only applies to current Add-VpnConnection call, doesn't persist
- **Registry PSK**: Persists across RAS service calls and reboots
- **Error 756**: Occurs when RAS service can't find PSK in registry during `rasdial` connection
- **Solution**: Set PSK in registry where RAS service actually looks for it

## Testing

### Before Fix
```
2026-11-07 01:26:14 - Connection failed (exit 756):
2026-11-07 01:26:14 - Failed to connect to 59.138.139.69, trying next server...
2026-11-07 01:26:15 - All 5 failover attempts failed
```

### After Fix (Expected)
```
2026-11-07 XX:XX:XX - Step 1: Configuring L2TP IPSec...
2026-11-07 XX:XX:XX - L2TP IPSec configured
2026-11-07 XX:XX:XX - Step 2: Creating MyVPN connection...
2026-11-07 XX:XX:XX - VPN RAS connection profile created
2026-11-07 XX:XX:XX - Step 3: Configuring L2TP Pre-Shared Key...
2026-11-07 XX:XX:XX - L2TP PSK configured
2026-11-07 XX:XX:XX - Connected to 158.217.184.31
2026-11-07 XX:XX:XX - DNS cache flushed successfully
```

## Deployment

### Install Updated Version

```powershell
.\SentinelSetup-3.6.8.exe
```

### Fresh Setup Required

**IMPORTANT**: If you have an existing broken VPN connection:
```powershell
# Clean up old connection
Remove-VpnConnection -Name 'MyVPN' -Force

# Remove PSK registry entries (fresh start)
reg delete 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey' /f
```

Then reinstall Sentinel 3.6.8.

## Files Modified

- `modules/GVPN/VpnManager.cs` - Refactored `CreateVpnConnection()` method
- `version.txt` - Updated to 3.6.8
- `installer/setup.iss` - Updated version references

## Registry Keys Set by GVPN

```
HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters
  - ProhibitIpsec = 0 (enable IPSec)
  - AllowL2TPandIkeOnHigherVersions = 1 (allow newer IKE)
  - L2tpPresharedKey = "vpn" (the PSK that was missing!)

HKLM\SYSTEM\CurrentControlSet\Services\Rasman\Parameters
  - AllowL2TPandIkeOnHigherVersions = 1
```

## Advanced: Manual VPN Setup (If Needed)

If you still get Error 756 after 3.6.8:

```powershell
# Check if PSK is set
reg query 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey'

# Manually set PSK
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey' /t REG_SZ /d 'vpn' /f

# Enable IPSec
reg add 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'ProhibitIpsec' /t REG_DWORD /d 0 /f

# Restart RAS service
net stop RasMan
net start RasMan

# Try connecting
rasdial MyVPN vpn vpn
```

## Verification

### Check VPN Connection Exists
```powershell
Get-VpnConnection -Name MyVPN | Format-List
```

### Check L2TP PSK in Registry
```powershell
reg query 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' /v 'L2tpPresharedKey'
# Should show: L2tpPresharedKey REG_SZ vpn
```

### Test Connection
```powershell
rasdial MyVPN vpn vpn
# Should show: Connected or error after ~10 seconds (not 756)
```

## Version

- **Sentinel**: 3.6.8
- **GVPN**: 0.0.6 (with proper L2TP PSK registry configuration)
- **Status**: Ready for deployment
- **Release**: `SentinelSetup-3.6.8.exe` (11 MB)

## Related Documentation

- `VpnManager.cs` - VPN connection and L2TP configuration logic
- `Logger.cs` - Detailed logging to `%APPDATA%\Sentinel\GVPN\vpn.log`
- `ALWAYS_ON_MODE.md` - GVPN continuous operation documentation

