# GVPN Integration into Sentinel

## Overview

GVPN (Global VPN Manager) is now integrated into the Sentinel installer. When you install Sentinel, GVPN is automatically deployed and configured to run as an always-on background VPN service with kill switch capability.

**Result**: Single install, complete protection — no separate VPN setup needed.

## Installation

### Standard Install

```powershell
# Run installer as Administrator
.\SentinelSetup-3.6.7.exe
```

**What happens during setup:**
1. Sentinel service and agent are installed
2. GVPN.exe is deployed to `C:\Program Files\Sentinel\GVPN\GVPN.exe`
3. GVPN runs during setup to configure Windows VPN connection
4. GVPN auto-registers in Windows Run registry for auto-start on next boot
5. On reboot, GVPN starts automatically and monitors VPN connection 24/7

### First Run (Admin Required)

The installer runs GVPN in admin context during setup. This allows GVPN to:
- Create the "MyVPN" L2TP/IPSec connection in Windows
- Configure firewall rules
- Register in Run registry for auto-start

After the first run, no admin privileges are needed — GVPN runs as a regular user process.

## File Structure

After installation:

```
C:\Program Files\Sentinel\
├── Sentinel.Service.exe           # Main EDR service
├── Sentinel.Agent.exe             # Agent UI
├── SentinelAutoRotate.exe         # Auto-rotating credentials
├── GVPN/
│   └── GVPN.exe                   # VPN manager (33 KB)
└── ExploitShield/
    └── Sentinel.ExploitShield.exe # Automatic exploit protection
```

**Log Files:**
- `vpn.log` - Written to the working directory where GVPN runs (typically `%ProgramData%\Sentinel\` or user's home directory)

## Usage

### Automatic Operation

GVPN runs continuously in the background:
- **Auto-start**: Starts automatically on system boot
- **Always-on**: Monitors VPN connection every 30 seconds
- **Auto-reconnect**: Reconnects if VPN fails (tries up to 5 servers)
- **System tray**: Green icon = connected, Red icon = disconnected

### Manual Control

Right-click the GVPN tray icon to:

- **Status** - Show current VPN connection status
- **Connect Now** - Manually connect to closest VPN server
- **Disconnect** - Disconnect from VPN
- **Kill Switch** - Block all outbound traffic except:
  - Loopback (127.0.0.1) for local processes
  - DNS (UDP:53) for domain resolution
  - Sentinel processes for monitoring
  - Windows services (svchost.exe on 80/443) for system updates
- **View Logs** - Open `vpn.log` in default text editor
- **Exit** - Close GVPN (will restart on next boot)

## Kill Switch for C2 Prevention

When GVPN detects a connection failure after failover attempts, it can activate the kill switch to prevent data exfiltration:

```powershell
netsh advfirewall firewall add rule name="GVPN Kill Switch" dir=out action=block
netsh advfirewall firewall add rule name="GVPN Allow Loopback" dir=out action=allow remoteip=127.0.0.1
netsh advfirewall firewall add rule name="GVPN Allow DNS" dir=out action=allow protocol=udp remoteport=53
netsh advfirewall firewall add rule name="GVPN Allow Sentinel" dir=out action=allow program="%ProgramFiles%\Sentinel\*"
netsh advfirewall firewall add rule name="GVPN Allow Windows" dir=out action=allow program="C:\Windows\System32\svchost.exe" remoteport=80,443
```

**Protection against:**
- C2 (Command & Control) callbacks
- Reverse shell connections
- Lateral movement via outbound channels
- Data exfiltration attempts

## Integration with Sentinel

### Monitoring

Sentinel can monitor GVPN connection status:
- Read `vpn.log` for connection history
- Alert on repeated failover failures
- Alert on kill switch activation
- Monitor VPN server latency and reliability

### Threat Response

On threat detection, Sentinel can:
1. Monitor `vpn.log` to verify VPN is active
2. Alert if VPN connection is unstable
3. Trigger kill switch activation (when implemented)
4. Aggregate VPN metrics into incident context

### Policy Configuration

Define GVPN behavior via Sentinel policy:
```json
{
  "gvpn": {
    "enabled": true,
    "autoStart": true,
    "autoReconnect": true,
    "killSwitchOn": "failover_all",
    "failoverServers": 5,
    "monitorInterval": 30
  }
}
```

## Uninstallation

### Via Control Panel

1. **Settings** → **Apps** → **Apps & features**
2. Find **Sentinel**
3. Click **Uninstall**

**Uninstall cleanup:**
- Stops GVPN.exe process
- Removes firewall rules (including GVPN kill switch)
- Cleans up VPN connection "MyVPN" (preserved by default)
- Removes Sentinel and GVPN from Program Files
- Removes auto-start registry entries

### Manual Uninstall

```powershell
# Stop GVPN
Stop-Process -Name GVPN -Force -ErrorAction SilentlyContinue

# Remove firewall rules
netsh advfirewall firewall delete rule name="GVPN Kill Switch"
netsh advfirewall firewall delete rule name="GVPN Allow Loopback"
netsh advfirewall firewall delete rule name="GVPN Allow DNS"
netsh advfirewall firewall delete rule name="GVPN Allow Sentinel"
netsh advfirewall firewall delete rule name="GVPN Allow Windows"

# Remove from Run registry
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v GVPN /f

# Delete VPN connection (optional)
rasdial /disconnect MyVPN
Remove-VpnS2SInterface -Protocol IKEv2 -Name MyVPN -Force

# Delete installation folder
Remove-Item "C:\Program Files\Sentinel\GVPN" -Recurse -Force
```

## Configuration

### VPN Servers

GVPN uses **VPNGate** public servers (https://www.vpngate.net):
- Credentials: `vpn` / `vpn` (public, hardcoded)
- Protocol: L2TP/IPSec
- Selection: Automatic based on ping (closest server)
- Failover: Up to 5 servers on disconnect

To use a different VPN provider, modify `VpnManager.cs` in the GVPN source:

```csharp
private const string VpnName = "MyVPN";      // Connection name
private const string VpnUser = "vpn";        // Username
private const string VpnPass = "vpn";        // Password
// Change server fetch URL and authentication as needed
```

Then rebuild and redeploy.

### Monitoring Interval

Default: 30 seconds between status checks

To change, edit `VpnTrayApplication.cs`:

```csharp
Thread.Sleep(30000);  // Change to desired interval (milliseconds)
```

## Troubleshooting

### GVPN Not Starting

**Check logs:**
```powershell
# View recent log entries
Get-Content "$env:LOCALAPPDATA\GVPN\vpn.log" -Tail 20
```

**Common issues:**
1. **"MyVPN connection NOT FOUND"** → Reinstall GVPN as Administrator
2. **".NET Framework 4.8 not found"** → Install .NET Framework 4.8
3. **"Connection attempt timed out"** → Network can't reach VPNGate (ISP blocking, regional restriction)

### VPN Not Connecting

**Causes:**
- ISP blocks L2TP/IPSec protocol
- VPNGate servers unreachable in your region
- Network firewall blocking VPN ports
- VPN credentials wrong (shouldn't happen — hardcoded)

**Solutions:**
1. Check if https://www.vpngate.net is accessible in your browser
2. Verify ISP allows L2TP/IPSec (contact ISP)
3. Try running GVPN manually: `C:\Program Files\Sentinel\GVPN\GVPN.exe`
4. Review `vpn.log` for specific error messages

### Kill Switch Stuck ON

**If GVPN crashes with kill switch active:**

```powershell
# Manually disable firewall rules
netsh advfirewall firewall delete rule name="GVPN Kill Switch"
netsh advfirewall firewall delete rule name="GVPN Allow Loopback"
netsh advfirewall firewall delete rule name="GVPN Allow DNS"
netsh advfirewall firewall delete rule name="GVPN Allow Sentinel"
netsh advfirewall firewall delete rule name="GVPN Allow Windows"

# Verify rules are gone
netsh advfirewall firewall show rule name="GVPN*"
```

### High Memory or CPU Usage

- **Memory**: 20-30 MB is normal
- **CPU**: <1% idle, brief spikes during failover
- If consistently high: Check `vpn.log` for error loops or restart GVPN

## Performance Impact

**System-wide:**
- Memory: +30 MB (GVPN process)
- CPU: <1% idle
- Network: ~1 KB per 30-second check
- Disk: ~100 KB per week of logs

**Network:**
- VPN adds latency typical for remote VPN servers (~50-200 ms depending on server)
- Throughput: Depends on VPN server capacity

## Security Notes

### Kill Switch Limitations

- ✓ Blocks new outbound connections
- ✗ Cannot terminate already-established connections (OS limitation)
- ✓ Transparent — visible in Task Manager and netsh rules
- ✓ Fail-closed — defaults to block if unsure

### Threat Model

GVPN defends against:
- Data exfiltration via C2 channels
- Reverse shell callbacks
- Lateral movement via outbound ports
- Unencrypted network traffic (traffic goes through VPN)

GVPN does NOT protect against:
- Local attacks (files, registry, running processes)
- Physical attacks
- Attacks that don't require outbound network
- Malware that runs before GVPN loads

Combine GVPN with Sentinel's real-time threat detection and response for complete endpoint protection.

## Documentation

- `README.md` - GVPN user guide
- `ALWAYS_ON_MODE.md` - Always-on operation details
- `MODULE.md` - Architecture and technical details
- `DEPLOYMENT.md` - Deployment procedures

## Version

- **Installer Version**: 3.6.7
- **GVPN Version**: 0.0.4
- **Release Date**: November 7, 2026
- **Status**: Production Ready

---

**Questions?** Check GVPN logs at `vpn.log` or refer to the documentation in `C:\Program Files\Sentinel\GVPN\`.
