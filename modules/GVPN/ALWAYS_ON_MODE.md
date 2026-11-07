# GVPN Always-On Mode

## Change Summary

GVPN has been updated from **breach-triggered** mode to **always-on continuous** mode:

| Aspect | Before | Now |
|--------|--------|-----|
| Activation | Only on network breach | Always running |
| Startup | Manual or Sentinel signal | Automatic at boot |
| Visibility | Tray icon hidden until needed | Always minimized in tray |
| Monitoring | On-demand checks | Continuous 30-second checks |
| Reconnection | Manual or auto on breach | Automatic continuous |
| Kill Switch | Activated on breach | Available for threat response |

## How It Works

### On System Boot
1. Windows Run registry key triggers GVPN.exe
2. GVPN starts minimized (no visible window)
3. Automatically creates MyVPN connection (if first run)
4. Attempts to connect to VPNGate servers
5. Sits in system tray monitoring connection

### Continuous Operation
- Every 30 seconds: Check if VPN connection is active
- If connected: All good, continue monitoring
- If disconnected: Automatically reconnect using failover (try up to 5 servers)
- If all failover fails: Log to vpn.log, notify Sentinel if configured

### User Interaction
- **Right-click tray icon** → Connect Now, Disconnect, Kill Switch, View Logs, Exit
- **Double-click tray icon** → Show status balloon
- **Icon color** → Green (connected), Red (disconnected)

## Registry Integration

GVPN adds itself to Windows Run on first execution:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  GVPN → C:\path\to\GVPN.exe
```

**To disable auto-start:**
- Open Regedit
- Navigate to: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- Delete the `GVPN` entry
- Or: Run `reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v GVPN /f`

## Logs

`vpn.log` now shows continuous operation:

```
2026-11-07 09:00:15 - Application started (auto-start from boot)
2026-11-07 09:00:17 - Checking if MyVPN connection exists...
2026-11-07 09:00:17 - MyVPN connection is ready
2026-11-07 09:00:18 - Fetched 96 VPN servers
2026-11-07 09:00:19 - Starting failover - trying up to 5 servers
2026-11-07 09:00:19 - Connecting to VPN: 158.217.184.31
2026-11-07 09:00:25 - Connected to 158.217.184.31
2026-11-07 09:00:25 - Flushing DNS cache...
2026-11-07 09:00:26 - DNS cache flushed successfully
2026-11-07 09:00:26 - === VPN DIAGNOSTICS ===
2026-11-07 09:00:26 - VPN status: Connected (verified via rasdial)
2026-11-07 09:00:26 - === END DIAGNOSTICS ===
[30 second gap]
2026-11-07 09:00:56 - VPN status: Connected (rasdial shows active connection)
[30 second gap]
2026-11-07 09:01:26 - VPN status: Connected
... (continues every 30 seconds)
```

## Sentinel Integration

### Automated Deployment
Sentinel Agent can:
1. Deploy GVPN.exe to `C:\Program Files\GVPN\GVPN.exe`
2. Trigger first-run setup (admin context)
3. GVPN automatically adds itself to Run registry
4. System reboots → GVPN auto-starts

### Continuous Monitoring
Sentinel can read `vpn.log` to:
- Verify VPN is always connected
- Alert if connection fails repeatedly
- Monitor kill switch usage
- Track auto-reconnection patterns

### Threat Response Integration
On threat detection, Sentinel can:
```powershell
# 1. Force VPN connection
& "C:\Program Files\GVPN\GVPN.exe"

# 2. Activate kill switch (blocks all outbound except VPN)
# Sentinel sends signal to GVPN to enable kill switch
# User sees tray icon change, kill switch menu option shows "ON"

# 3. Monitor connection
Get-Content "C:\Program Files\GVPN\vpn.log" -Tail 20 | Select-String "Connected"

# 4. Alert if VPN fails
if (!(Select-String -Path "C:\Program Files\GVPN\vpn.log" -Pattern "Connected")) {
    # Trigger incident response
}
```

## Performance Impact

**Minimal overhead:**
- Memory: 20-30 MB (typical .NET WinForms app)
- CPU: <1% idle, brief spikes on reconnect
- Network: ~1 KB per 30-second check
- Disk: ~100 KB per week of logs

## System Tray Behavior

**Icon states:**
- **Green circle** = Connected to VPN
- **Red circle** = Not connected (attempting failover)

**Right-click menu:**
- Status: Shows current connection (Connected/Disconnected + optional kill switch state)
- Connect Now: Opens VPN server list for manual selection
- Disconnect: Disconnects VPN (can reconnect manually or wait for auto-reconnect)
- Kill Switch: Toggle ON/OFF (blocks all outbound if ON and VPN disconnects)
- View Logs: Opens vpn.log in default text editor
- Exit: Closes GVPN (will restart on next boot if configured)

## Version 0.0.4 - Enhanced Kill Switch for C2 Prevention

The kill switch now provides **active C2/reverse shell prevention** by blocking all outbound traffic except:
- **Loopback**: 127.0.0.1 (local inter-process communication)
- **DNS**: UDP:53 (required for domain resolution)
- **Sentinel processes**: Allow all executables in Sentinel directory
- **Windows services**: svchost.exe on ports 80/443 (Windows updates, essential services)

This prevents compromised processes from exfiltrating data via C2 channels or reverse shells while maintaining VPN and system functionality.

**Firewall Rules Applied When Kill Switch Activates:**
```powershell
# Block all outbound
netsh advfirewall firewall add rule name="GVPN Kill Switch" dir=out action=block

# Allow loopback
netsh advfirewall firewall add rule name="GVPN Allow Loopback" dir=out action=allow remoteip=127.0.0.1

# Allow DNS
netsh advfirewall firewall add rule name="GVPN Allow DNS" dir=out action=allow protocol=udp remoteport=53

# Allow Sentinel
netsh advfirewall firewall add rule name="GVPN Allow Sentinel" dir=out action=allow program="%ProgramFiles%\Sentinel\*"

# Allow Windows services
netsh advfirewall firewall add rule name="GVPN Allow Windows" dir=out action=allow program="C:\Windows\System32\svchost.exe" remoteport=80,443
```

## Disabling/Modifying

### Temporarily Disable
- Right-click → Exit (will restart on next boot)
- Or: Stop-Process -Name GVPN

### Permanently Disable
- Delete Run registry entry (see above)
- Or: Uninstall via Control Panel (if MSI installed)

### Change VPN Server
- Edit `VpnManager.cs` constant:
  ```csharp
  private const string VpnName = "MyVPN";  // or custom name
  ```
- Rebuild and redeploy

### Change Monitoring Interval
- Edit `VpnTrayApplication.cs` in monitoring loop:
  ```csharp
  Thread.Sleep(30000);  // 30 seconds (change to desired interval)
  ```

## Troubleshooting Always-On Mode

| Issue | Cause | Solution |
|-------|-------|----------|
| GVPN not starting on boot | Registry entry missing | Manually run GVPN.exe once (admin) to re-register |
| Multiple GVPN windows | Launched manually + auto-start | Close one window, only one needed |
| High CPU usage | Continuous reconnect loop | Check VPN servers are reachable, verify ISP allows L2TP |
| Kill switch stuck ON | Previous kill switch not cleaned | Manually disable: `netsh advfirewall firewall delete rule name="GVPN Kill Switch"` |
| Tray icon not visible | Hidden icon settings | Show hidden icons in taskbar settings |

## Security Notes

- **Always transparent** - Visible in Task Manager, can't hide
- **No privilege escalation** - Runs as regular user (admin only for boot setup)
- **Network isolation** - Kill switch can immediately block all outbound
- **Audit trail** - Complete vpn.log for compliance/incident response
- **Fail-safe** - If GVPN crashes, kill switch can remain active (manual cleanup needed)

## Next Steps for Sentinel Integration

1. **Test Always-On Behavior**
   - Build: `modules/GVPN/build.ps1`
   - Run: `GVPN.exe` (will auto-register for startup)
   - Reboot system: Verify GVPN auto-starts
   - Check `vpn.log` for continuous monitoring

2. **Deploy via Sentinel Agent**
   - Package GVPN.exe in agent bootstrap
   - First-run with admin privileges
   - GVPN auto-adds to Run registry
   - Verify on subsequent boots

3. **Log Aggregation**
   - Forward `vpn.log` to Sentinel central logging
   - Alert on "All 5 failover attempts failed"
   - Alert on kill switch activation

4. **Policy Integration**
   - Define auto-start policy (enabled by default)
   - Define kill switch activation triggers
   - Create remediation workflow

## References

- `MODULE.md` - Architecture and Sentinel integration
- `DEPLOYMENT.md` - Deployment procedures
- `README.md` - User documentation
