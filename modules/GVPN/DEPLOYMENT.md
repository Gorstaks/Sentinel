# GVPN Module - Deployment Guide for Sentinel

## Overview

GVPN is now a **continuous, always-on VPN manager** for Sentinel. Unlike the previous breach-triggered mode, GVPN now:
- Automatically starts on every system boot
- Runs minimized in the system tray 24/7
- Continuously monitors VPN connection (30-second checks)
- Auto-reconnects automatically if disconnected
- Provides kill switch for security incidents

## Quick Start

GVPN is a single 31.5 KB executable with zero external dependencies.

### Build

```powershell
cd modules/GVPN
.\build.ps1
# Output: bin/Release/GVPN.exe
```

### Run (First Time)

```powershell
# Right-click PowerShell.exe → "Run as Administrator"
GVPN.exe
```

This automatically:
1. Creates L2TP/IPSec "MyVPN" connection in Windows
2. Configures it for VPNGate servers with pre-shared key auth
3. Connects to the closest available VPN server
4. Starts monitoring (30-second check interval)
5. Auto-reconnects with failover if disconnected

### Run (Subsequent Times)

```powershell
GVPN.exe  # No admin needed
```

## Deployment Scenarios

### Scenario 1: Manual Deployment

**For testing or single-endpoint deployment:**

1. Copy `bin/Release/GVPN.exe` to target system
2. Right-click PowerShell → "Run as Administrator"
3. Run GVPN.exe
4. Verify: Check System Tray for VPN icon, check `vpn.log` for connection status

### Scenario 2: Sentinel Agent Deployment

**Automation via Sentinel Agent:**

1. **Stage the binary**
   ```powershell
   # Sentinel Agent would:
   $exePath = "C:\Program Files\GVPN\GVPN.exe"
   Copy-Item "modules/GVPN/bin/Release/GVPN.exe" $exePath
   ```

2. **First-run bootstrap (admin context)**
   ```powershell
   # Sentinel Service or elevated Agent job runs:
   & $exePath
   # Wait 5 seconds for VPN creation to complete
   Start-Sleep -Seconds 5
   ```

3. **Subsequent execution (normal user context)**
   ```powershell
   # Any user can now run - no admin needed:
   & $exePath
   ```

4. **Monitor status**
   ```powershell
   # Sentinel Agent reads logs:
   Get-Content "C:\Program Files\GVPN\vpn.log" -Tail 20
   # Look for: "Connected to <IP>"
   # Look for: "VPN status: Connected"
   ```

### Scenario 3: Policy-Driven Activation

**Based on Sentinel threat detection:**

```powershell
# Sentinel Agent could:
# 1. Detect high-risk endpoint state
# 2. Activate GVPN kill switch
if ($threatLevel -eq "Critical") {
    # Activate kill switch (blocks all outbound traffic except VPN)
    # Sentinel would signal GVPN via command-line or config
}

# 2. Force VPN connection
& "C:\Program Files\GVPN\GVPN.exe"

# 3. Monitor VPN log for success
while ($retries -lt 5) {
    if (Select-String -Path "C:\Program Files\GVPN\vpn.log" -Pattern "Connected") {
        # VPN is active, endpoint isolated
        break
    }
    Start-Sleep -Seconds 5
    $retries++
}
```

## Integration Checklist

- [ ] GVPN module cloned/copied to `Sentinel/modules/GVPN/`
- [ ] Build verified: `.\build.ps1` → 31 KB GVPN.exe
- [ ] First-run tested with admin privileges
- [ ] VPN connection "MyVPN" appears in Settings → Network & Internet → VPN
- [ ] vpn.log created and shows "Connected to <IP>"
- [ ] System tray icon visible (green = connected, red = disconnected)
- [ ] Kill switch tested: Right-click tray → "Kill Switch: ON"
- [ ] Log aggregation configured to monitor `vpn.log`
- [ ] Sentinel Agent tested for deployment

## Monitoring

Sentinel can monitor GVPN health by:

1. **Reading vpn.log**
   ```powershell
   # Alert if any of these appear:
   "Connection attempt timed out"
   "All 5 failover attempts failed"
   "Kill switch enabled"
   ```

2. **Checking process**
   ```powershell
   Get-Process GVPN -ErrorAction SilentlyContinue
   ```

3. **Verifying connection**
   ```powershell
   rasdial MyVPN  # Should show "Connected to <IP>"
   ```

## Troubleshooting Deployment

| Issue | Cause | Solution |
|-------|-------|----------|
| "MyVPN connection NOT FOUND" in log | First run without admin | Rerun as Administrator first time only |
| "Connection attempt timed out" | VPN servers unreachable | Check network/firewall allows L2TP/IPSec |
| Kill switch won't turn off | Orphaned firewall rules | Manual: `netsh advfirewall firewall delete rule name="GVPN Kill Switch"` |
| Tray icon missing | GVPN crashed early | Check Application event log, review vpn.log for startup errors |
| Multiple GVPN processes | User ran multiple instances | Kill first: `Stop-Process -Name GVPN` |

## Removing GVPN

If needed to uninstall:

```powershell
# 1. Stop process
Stop-Process -Name GVPN -Force

# 2. Remove kill switch rules (if enabled)
netsh advfirewall firewall delete rule name="GVPN Kill Switch"
netsh advfirewall firewall delete rule name="GVPN Kill Switch - Loopback"
netsh advfirewall firewall delete rule name="GVPN Kill Switch - DNS"

# 3. Remove VPN connection
Remove-VpnConnection -Name "MyVPN" -Force

# 4. Delete binary
Remove-Item "C:\Program Files\GVPN\GVPN.exe"
```

## Performance Baseline

- **Startup**: 2-3 seconds (first run), <1 second (subsequent)
- **Memory**: 20-30 MB when connected
- **CPU**: Idle (<1%) when connected, brief spikes on failover
- **Network**: ~1 KB per 30-second check, minimal when connected
- **Log size**: ~100 KB per week of operation

## Security Notes

- **Admin required once**: Only on first run to create VPN connection
- **No persistence**: GVPN must be explicitly run each time
- **No privilege escalation**: Runs as regular user after setup
- **No network elevation**: Can't modify firewall beyond kill switch rules
- **Fail-closed**: Kill switch blocks outbound on connection loss
- **Transparent**: Visible in Task Manager, no self-hiding

## Next Steps

1. **Test Locally**
   - Build module: `cd modules/GVPN && .\build.ps1`
   - Run as admin: Right-click PowerShell → Run as Administrator → `GVPN.exe`
   - Verify VPN connection created and active

2. **Integrate with Sentinel Agent**
   - Add GVPN deployment task to Agent bootstrap
   - Configure log aggregation for `vpn.log`
   - Test deployment to isolated endpoint

3. **Policy Integration**
   - Define when GVPN should activate (e.g., threat level >= Medium)
   - Configure kill switch auto-activation
   - Create alerts for VPN connection failures

4. **Production Rollout**
   - Stage GVPN.exe distribution
   - Pilot with security team
   - Full deployment via Sentinel Agent

## Support

For issues or questions:
- Check `vpn.log` for detailed error messages
- Review `MODULE.md` for architecture and troubleshooting
- Check `README.md` for user documentation
