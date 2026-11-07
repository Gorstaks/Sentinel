# GVPN Module for Sentinel

GVPN (Global VPN) is a lightweight VPN manager module for Sentinel that provides automatic VPN connection management with system tray monitoring, auto-reconnection, and kill switch functionality.

## Location

```
E:\Gorstak\Sentinel\modules\GVPN\
```

## Build

```powershell
cd E:\Gorstak\Sentinel\modules\GVPN
.\build.ps1
```

Output: `bin\Release\GVPN.exe` (31 KB)

## Features

- **Automatic VPN Setup** - Creates L2TP/IPSec "MyVPN" connection on first run
- **Auto-Reconnection** - Monitors connection every 30 seconds, auto-reconnects with failover
- **Kill Switch** - Blocks all outbound traffic if VPN disconnects
- **VPN Server Management** - Fetches public VPNGate servers, selects by lowest ping
- **System Tray Integration** - Minimalist UI in taskbar with one-click controls
- **Detailed Logging** - `vpn.log` tracks all operations for debugging

## Usage

Run as Administrator on first launch:

```powershell
# Right-click PowerShell → Run as Administrator
GVPN.exe
```

After setup, no admin needed for subsequent runs.

## Architecture

- **Program.cs** - Entry point, creates main form
- **VpnTrayApplication.cs** - Tray icon UI and connection monitoring
- **VpnManager.cs** - VPN operations (create connection, connect, disconnect, failover)
- **VpnListForm.cs** - Server list UI with ping/speed/session info
- **Logger.cs** - Thread-safe logging utility

## Integration with Sentinel

This module can be integrated into Sentinel's monitoring and management infrastructure:

1. **As a standalone module** - Users run GVPN.exe independently
2. **Via Sentinel Agent** - Sentinel Agent can:
   - Deploy GVPN.exe to endpoints
   - Monitor GVPN status via `vpn.log`
   - Trigger VPN connections based on security policies
   - Alert on connection failures or kill switch activation

## Dependencies

- Windows 7 or later
- .NET Framework 4.8
- Administrator privileges (first run only)
- VPNGate public server access (for actual VPN connections)

## Logs

`vpn.log` in the working directory contains:
- VPN connection creation status
- Server selection and connection attempts
- Auto-reconnection activity
- Kill switch activation/deactivation
- DNS cache flush operations

## Troubleshooting

**"Connection attempt timed out"**
- VPN connection infrastructure is working
- But can't reach selected VPN servers
- Try again (different servers might be available)
- Check if ISP blocks L2TP protocol

**MyVPN not found**
- Ensure first run as Administrator

See `README.md` for full user documentation.
