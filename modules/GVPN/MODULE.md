# GVPN Module - Sentinel VPN Integration

GVPN (Global VPN Manager) is a lightweight Windows VPN management module for Sentinel, providing **continuous always-on** automatic L2TP/IPSec VPN connection creation, monitoring, and auto-reconnection with kill switch functionality.

## Key Change: Always-On Mode

**GVPN now runs continuously by default** - no longer just on network breach. It:
- Auto-starts on every boot (registers in Windows Run registry)
- Runs minimized in system tray (invisible, always monitoring)
- Connects automatically on startup
- Auto-reconnects if connection drops
- Can be integrated into Sentinel's threat response (kill switch activation, network isolation)

```
Sentinel/modules/GVPN/
```

## Build

```powershell
cd modules/GVPN
.\build.ps1
```

**Output:** `bin/Release/GVPN.exe` (31 KB) - Single standalone executable, no dependencies.

## Features

- **Always-On Continuous Operation** - Auto-starts on boot, runs minimized in tray, monitors 24/7
- **Automatic VPN Setup** - Creates "MyVPN" L2TP/IPSec connection on first run (admin required once)
- **Auto-Reconnection** - Monitors connection every 30 seconds, auto-reconnects with intelligent failover
- **Kill Switch** - Blocks all outbound traffic if VPN fails (Windows Firewall rules)
- **VPN Server Selection** - Fetches public VPNGate servers, selects by lowest ping
- **System Tray UI** - Minimalist taskbar integration, one-click controls (Connect/Disconnect/Kill Switch)
- **Comprehensive Logging** - `vpn.log` tracks all operations for integration/debugging

## Usage

**First run (Administrator required):**
```powershell
# Right-click PowerShell.exe → "Run as Administrator"
GVPN.exe
```

**Subsequent runs (no admin needed):**
```powershell
GVPN.exe
```

## Sentinel Integration

### 1. Distributed Deployment

Sentinel Agent can deploy GVPN.exe to endpoints:
- Stage GVPN.exe in a bootstrap location
- First execution (with admin) auto-creates VPN connection
- Subsequent deployments/runs require no admin

### 2. Status Monitoring

Sentinel can monitor GVPN status by reading `vpn.log`:
- Track VPN connection creation success/failure
- Monitor auto-reconnection activity
- Alert on persistent connection failures
- Detect kill switch activation (security incidents)

### 3. Policy-Driven Connections

Sentinel Agent can trigger VPN connections based on security policies:
- Enforce VPN for high-risk endpoints
- Disable VPN for compliance scenarios
- Activate/deactivate kill switch per policy

### 4. Threat Response

On threat detection, Sentinel can:
- Activate GVPN kill switch to prevent data exfiltration
- Force VPN connection to isolate endpoint
- Log connection state for incident response

## Architecture

```
GVPN.exe (31 KB standalone)
├── Program.cs           - Entry point
├── VpnTrayApplication.cs - UI & monitoring loop
├── VpnManager.cs        - VPN operations (L2TP/IPSec, auto-reconnect, failover)
├── VpnListForm.cs       - Server list UI
└── Logger.cs            - Thread-safe logging
```

## Core Components

### VpnManager.cs
- **EnsureVpnConnectionExists()** - Auto-creates L2TP/IPSec "MyVPN" on startup
- **ConnectVpn()** - Connects to specific server via rasdial
- **ConnectVpnWithFailover()** - Tries up to 5 best servers, auto-reconnects
- **EnableKillSwitch()** - Blocks outbound via Windows Firewall
- **DisableKillSwitch()** - Restores network access

### VpnTrayApplication.cs
- System tray icon & context menu
- Connection monitoring thread (30s interval)
- Automatic failover on disconnect
- Kill switch passive activation

### Logger.cs
- Thread-safe logging to `vpn.log`
- Timestamps for every operation
- Useful for Sentinel log aggregation

## Configuration

Edit `VpnManager.cs` constants if needed:
```csharp
private const string VpnName = "MyVPN";      // Connection name (used by rasdial)
private const string VpnUser = "vpn";        // VPNGate username (hardcoded)
private const string VpnPass = "vpn";        // VPNGate password (hardcoded)
```

## VPN Servers

- **Source**: https://www.vpngate.net/api/iphone/
- **Protocol**: L2TP/IPSec with Pre-Shared Key (PSK) authentication
- **Selection**: Lowest ping (geographically closest)
- **Fallback**: Up to 5 servers tried on disconnect, with 3-second stabilization wait per attempt

## Logs

`vpn.log` in the working directory tracks:

```
2026-11-07 14:23:45 - Application started
2026-11-07 14:23:46 - Checking if MyVPN connection exists...
2026-11-07 14:23:47 - MyVPN not found - creating it now...
2026-11-07 14:23:49 - VPN creation output: Created\nMyVPN
2026-11-07 14:23:50 - MyVPN connection created successfully
2026-11-07 14:23:51 - Fetched 96 VPN servers
2026-11-07 14:23:52 - Starting failover - trying up to 5 servers
2026-11-07 14:23:52 - Connecting to VPN: 158.217.184.31
2026-11-07 14:24:00 - Connected to 158.217.184.31
2026-11-07 14:24:00 - Flushing DNS cache...
2026-11-07 14:24:01 - DNS cache flushed successfully
```

## Constraints & Security

- **Userland only** - No kernel drivers, no persistence, no self-hiding
- **Transparent** - Visible in process list and Task Manager
- **Fail-closed** - Kill switch blocks outbound on connection loss
- **No network elevation** - Runs as regular process (admin needed once for VPN setup)
- **No string-built commands** - Safe parameter passing to rasdial/netsh

## Troubleshooting

### VPN Creation Fails
- Run GVPN.exe as Administrator on first launch
- Right-click PowerShell.exe → "Run as Administrator"

### Connection Timeouts
- Indicates infrastructure is working but servers unreachable
- Check ISP allows L2TP/IPSec (not blocked by firewall)
- Try again (different servers might be available)

### Kill Switch Won't Deactivate
- Ensure Windows Firewall is enabled
- Check GVPN logs for netsh errors
- Manually verify: `netsh advfirewall firewall show rule name="GVPN Kill Switch"`

## Performance

- **Startup**: ~2-3 seconds (VPN creation only on first run)
- **Memory**: ~20-30 MB (minimal .NET WinForms app)
- **CPU**: Idle when connected, brief spikes on failover
- **Network**: Polling interval 30 seconds, ~1 KB per check

## Dependencies

- Windows 7 or later
- .NET Framework 4.8
- VPNGate public server access (for actual VPN connections)
- Windows Firewall (for kill switch)

## Future Enhancement Ideas

1. **Sentinel Agent Integration** - Publish VPN status to Sentinel Agent
2. **Policy Engine** - Conditional VPN activation based on Sentinel policies
3. **Threat Response** - Auto-kill-switch on high-severity threat detection
4. **Server Persistence** - Remember last working server across restarts
5. **Multiple Profiles** - Support multiple VPN configurations (work, home, isolate)
6. **DNS Hijack Protection** - Detect and block DNS leaks during connection transitions

## License & Attribution

Part of Sentinel project. Licensed under Sentinel's terms.
