# GVPN - VPN Manager with Tray Icon

A minimal C# 4.8 / .NET Framework Windows Forms application that provides VPN management with a system tray icon and kill switch functionality.

## Features

- **System Tray Icon** - Minimalist UI that lives in the taskbar
- **Auto-setup** - Automatically creates VPN connection on first run
- **Auto-reconnect** - Automatically fetches the closest VPN server and maintains connection
- **Kill Switch** - Blocks ALL traffic if VPN disconnects (firewall-based)
- **Status Monitoring** - Real-time VPN status indicator (green = connected, red = disconnected)
- **Manual Connect/Disconnect** - One-click VPN operations
- **Logging** - Detailed logs saved to `vpn.log`
- **Lightweight** - Single 30 KB executable with no external dependencies

## Requirements

- Windows 7 or later
- .NET Framework 4.8

## Installation & Usage

**Just run GVPN.exe - that's it!**

```powershell
GVPN.exe
```

**First run:**
- Right-click PowerShell.exe → "Run as Administrator"
- Run GVPN.exe from the admin shell
- GVPN automatically creates the "MyVPN" L2TP/IPSec VPN connection
- Takes ~2-3 seconds on first launch
- After that, no admin needed

**After setup:**
- GVPN minimizes to system tray
- Automatically connects to the closest VPN Gate server
- Monitors connection every 30 seconds
- Auto-reconnects to a different server if disconnected

## Usage

### Tray Icon Menu

Right-click the tray icon to access:

- **Status** - Shows current connection status
- **Connect Now** - Manually connect to the closest VPN
- **Disconnect** - Disconnect from VPN
- **Kill Switch** - Blocks ALL outbound traffic using Windows Firewall (prevents data leaks if VPN drops)
- **View Logs** - Open `vpn.log` in default editor
- **Exit** - Close application gracefully

### Double-Click Tray Icon

Shows a popup with current connection status.

## Configuration

Edit these constants in `VpnManager.cs` if needed:

```csharp
private const string VpnName = "MyVPN";      // Name of VPN connection
private const string VpnUser = "vpn";        // VPN username (hardcoded for VPNGate)
private const string VpnPass = "vpn";        // VPN password (hardcoded for VPNGate)
```

## VPN Servers

The application fetches public VPN servers from:
- **Source**: https://www.vpngate.net/api/iphone/
- **Selection**: Automatically selects the server with the lowest ping (closest to you)
- **Credentials**: Always vpn / vpn (VPNGate public credentials)

## Logs

Application logs are saved to `vpn.log` in the working directory with entries like:

```
2026-11-07 14:23:45 - Application started
2026-11-07 14:23:46 - Checking if MyVPN connection exists...
2026-11-07 14:23:47 - MyVPN connection created successfully
2026-11-07 14:23:50 - Selected VPN: 158.217.184.31 (JP, ping: 1ms)
2026-11-07 14:23:52 - Connected to 158.217.184.31
```

## Architecture

- **Program.cs** - Entry point, creates main form
- **VpnTrayApplication.cs** - Main form with tray icon UI and monitoring loop
- **VpnManager.cs** - Handles all VPN operations (create, connect, disconnect, status, fetch servers)
- **Logger.cs** - Thread-safe logging utility

## Build

```powershell
cd E:\Gorstak\GVPN
.\build.ps1
```

Or compile manually with csc:

```powershell
csc /target:winexe /out:bin\Release\GVPN.exe `
  /reference:System.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
  Program.cs VpnTrayApplication.cs VpnManager.cs Logger.cs
```

## Compilation Details

- **Language**: C# 5.0
- **Framework**: .NET Framework 4.8
- **Output Type**: Windows Executable (WinExe)
- **References**: System, System.Core, System.Windows.Forms, System.Drawing
- **Compiler**: csc.exe (C# Compiler from Visual Studio)

## Known Limitations

- Windows only (uses `rasdial.exe` for VPN operations)
- Kill switch blocks outbound traffic when failover fails; doesn't create persistent blocks
- VPN credentials hardcoded (VPNGate always uses vpn/vpn)
- Requires first run as Administrator (to create VPN connection)

## Legal Disclaimer

**IMPORTANT - READ BEFORE USE**

GVPN is provided as-is for educational and personal use only. By using this software, you agree to the following:

### Usage Restrictions
- Use GVPN **only on systems you own or have explicit permission to use**
- Do **NOT** use GVPN to circumvent security measures, firewalls, or access controls that you are not authorized to bypass
- Do **NOT** use GVPN for any illegal activities, including but not limited to:
  - Unauthorized access to computer systems
  - Copyright infringement or piracy
  - Fraud, hacking, or cybercrime
  - Evading law enforcement
  - Harassment or attacks on others
  - Any activity that violates local, state, or international laws

### No Warranty
- This software is provided **without any warranty, express or implied**
- The author is **not responsible** for:
  - Data loss or corruption
  - Network issues or connection problems
  - VPN disconnections or reconnection failures
  - Any damage caused by use or misuse of this software
  - Any liability arising from your use of this software

### Liability
- **You are solely responsible** for your use of GVPN
- The author **assumes no liability** for:
  - Any loss of privacy or exposure of data
  - Regulatory violations or legal consequences
  - System damage or downtime
  - Third-party claims

### VPN & Privacy
- Using a VPN does **not guarantee anonymity or privacy**
- VPN providers may log your activity (check their privacy policy)
- Your ISP may still see that you're using a VPN
- Kill switch can fail; never rely on it as your only protection
- **No tool can provide 100% privacy** - use responsibly and legally

### Age Restriction
- You must be **at least 18 years old** (or the legal age of majority in your jurisdiction) to use this software

### Compliance
- **You are responsible for complying** with:
  - All local, state, and national laws
  - Your ISP's terms of service
  - Your employer's or organization's policies
  - The laws of countries whose services you access
  - VPN provider's terms of service

### No Support for Illegal Activity
- The author **does not condone, endorse, or support** any illegal use
- Misuse of this software may result in:
  - Criminal prosecution
  - Civil liability
  - Permanent bans from services
  - Legal consequences

**By downloading and using GVPN, you acknowledge that you have read, understood, and agree to these terms.**

If you do not agree with any of these terms, **do not use this software**.

## Troubleshooting

### "Connection attempt timed out" in logs
This means:
- GVPN created MyVPN correctly ✓
- It's trying to connect to a VPNGate server
- But the connection timed out after 10 seconds

**Causes:**
- Network can't reach VPNGate servers (firewall, ISP, region blocking)
- ISP blocks L2TP protocol
- All 5 selected servers are unreachable or rejecting connections
- VPNGate service is down in your region

**Solutions:**
- Try running GVPN again (different servers might be available)
- Check if you can access https://www.vpngate.net in your browser
- Check with your ISP if they allow L2TP/IPSec VPN protocols
- If blocked, you may need a different VPN protocol or service
- Try disabling any antivirus/firewall temporarily

### "MyVPN connection NOT FOUND" in logs
- Make sure you ran GVPN.exe as Administrator on first launch
- Right-click PowerShell.exe → "Run as Administrator"
- Then run GVPN.exe again

### Application won't start
- Verify .NET Framework 4.8 is installed
- Try running from Command Prompt to see error messages
- Check Windows Event Viewer for errors

### VPN server fetch fails
- Verify internet connection (GVPN needs internet to fetch server list)
- Try accessing https://www.vpngate.net in your browser
- VPN Gate may be blocked in your region

### Kill switch not working
- Ensure you have administrator privileges
- Check Windows Firewall is enabled
- Review `vpn.log` for netsh errors

## License

Public Domain - Use freely
