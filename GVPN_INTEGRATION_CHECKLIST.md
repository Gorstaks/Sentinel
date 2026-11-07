# GVPN Integration Checklist

## ✅ Status: Ready to Build

GVPN is now integrated into Sentinel. The installer will automatically deploy and configure GVPN when Sentinel is installed.

## Changes Made

### 1. ✅ GVPN Binary Deployment
- Created: `publish/gvpn/` folder
- Deployed: `GVPN.exe` (33.3 KB, v0.0.4)
- Status: Ready for installer to include

### 2. ✅ Installer Integration
- **File**: `installer/setup.iss`
- **Changes**:
  - Added `[Files]` section: GVPN files deploy to `{app}\GVPN\`
  - Added `[Run]` section: GVPN.exe runs during post-install setup
  - Updated `KillSentinelImagesOnce()`: Added GVPN.exe to process kill list
  - Updated `UninstallFallbackCleanup()`: Added GVPN kill switch rule cleanup
  - Updated uninstall: Removes GVPN firewall rules on uninstall

### 3. ✅ Documentation Created
- **File**: `docs/GVPN_INTEGRATION.md`
- **Content**:
  - Installation instructions
  - File structure
  - Usage and manual control
  - Kill switch explanation
  - Sentinel integration details
  - Troubleshooting guide
  - Performance impact
  - Security notes

### 4. ✅ Firewall Rule Cleanup
- Added "GVPN Kill Switch" to uninstall rule cleanup
- Ensures clean removal on uninstall

## What Happens During Installation

### Step 1: Pre-Install
- Sentinel service/agent stopped
- Old binaries renamed aside
- ACLs reset for write access

### Step 2: File Copy
- Sentinel binaries → `C:\Program Files\Sentinel\`
- Agent → `C:\Program Files\Sentinel\`
- AutoRotate → `C:\Program Files\Sentinel\`
- ExploitShield → `C:\Program Files\Sentinel\ExploitShield\`
- **GVPN → `C:\Program Files\Sentinel\GVPN\`** ← NEW

### Step 3: Post-Install Setup
- Sentinel.Service.exe --install
- **GVPN.exe runs in admin context** ← NEW
  - Creates "MyVPN" VPN connection
  - Registers in Windows Run registry
  - Configures firewall rules
  - Auto-starts on next boot
- ExploitShield --install
- SentinelAutoRotate --install (if selected)

### Step 4: Cleanup
- Old binaries (*.old) deleted
- Setup completes

### Step 5: First Reboot
- Windows auto-starts GVPN via Run registry ← NEW
- GVPN monitors VPN connection 24/7

## Next Steps

### 1. Build Sentinel Installer
```powershell
cd E:\Gorstak\Sentinel\installer
.\build.ps1
```

This will:
- Compile Inno Setup script (setup.iss)
- Create `SentinelSetup-3.6.7.exe` with GVPN embedded

### 2. Test Installation
```powershell
# Run installer
.\SentinelSetup-3.6.7.exe

# Verify GVPN installed
Test-Path "C:\Program Files\Sentinel\GVPN\GVPN.exe"

# Check VPN connection created
rasdial | Select-String MyVPN

# Verify GVPN tray icon appears
Get-Process GVPN
```

### 3. Test VPN Connection (Optional)
- Right-click GVPN tray icon → Connect Now
- Watch vpn.log for connection attempts
- Verify firewall rules created: `netsh advfirewall firewall show rule name="GVPN*"`

### 4. Release
```powershell
# Follow release procedure in Sentinel/.agents/rules/workflow.md
cd E:\Gorstak\Sentinel
& D:\Gorstak\push.ps1 -ProjectFilter sentinel
```

## File Checklist

### Installer Script
- [x] `installer/setup.iss` - Updated with GVPN integration
- [x] GVPN executable copied to publish/

### Documentation
- [x] `docs/GVPN_INTEGRATION.md` - Integration guide
- [x] `GVPN_INTEGRATION_CHECKLIST.md` - This file

### GVPN Module (Already Complete)
- [x] `modules/GVPN/` - Source code
- [x] `modules/GVPN/README.md` - User guide
- [x] `modules/GVPN/MODULE.md` - Architecture
- [x] `modules/GVPN/ALWAYS_ON_MODE.md` - Always-on behavior
- [x] `releases/modules/0.0.4/` - v0.0.4 release

## Installer Changes Summary

### Files Section (NEW)
```iss
Source: "..\publish\gvpn\*"; DestDir: "{app}\GVPN"; Flags: ignoreversion recursesubdirs createallsubdirs uninsrestartdelete
```

### Run Section (NEW)
```iss
Filename: "{app}\GVPN\GVPN.exe"; Flags: runhidden waituntilterminated; StatusMsg: "Setting up VPN..."
```

### Kill Functions (UPDATED)
- Added GVPN.exe to `KillSentinelImagesOnce()`

### Uninstall Cleanup (UPDATED)
- Added "GVPN Kill Switch" to firewall rule deletion
- Array size increased from 11 to 12 rules

## User Experience

### Before Integration
1. Install Sentinel
2. Download and install separate VPN solution
3. Configure VPN manually
4. Enable auto-start manually
5. Result: Two separate tools to manage

### After Integration
1. Install Sentinel
2. Done ✓
3. VPN automatically deployed and running
4. Kill switch ready for threat response
5. Result: Single install, complete protection

## Verification Commands

```powershell
# Check GVPN is deployed
Get-Item "C:\Program Files\Sentinel\GVPN\GVPN.exe"

# Verify VPN connection
rasdial | Select-String MyVPN

# Check Run registry
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object GVPN

# Verify firewall rules exist
netsh advfirewall firewall show rule name="GVPN*"

# Monitor GVPN process
Get-Process GVPN

# Watch VPN logs
Get-Content "vpn.log" -Tail 20 -Wait
```

## Rollback (If Needed)

If GVPN integration needs to be removed from installer:

```powershell
# Remove from setup.iss:
# 1. Delete the Source line for GVPN files
# 2. Delete the Filename line for GVPN.exe from [Run]
# 3. Remove GVPN.exe from KillSentinelImagesOnce()
# 4. Remove "GVPN Kill Switch" from firewall rule cleanup
# 5. Delete publish/gvpn/ folder
```

Then rebuild installer.

## Version Information

- **Sentinel**: 3.6.7
- **GVPN**: 0.0.4
- **Installer**: SentinelSetup-3.6.7.exe (will include GVPN)
- **Integration Date**: November 7, 2026
- **Status**: Ready to Build

## Notes

- GVPN runs as regular user process (no extra privileges after setup)
- First run during setup requires admin context for VPN creation
- GVPN auto-starts on every subsequent boot
- Kill switch rules are managed by GVPN, cleaned up on uninstall
- No changes needed to Sentinel.Service.exe or Sentinel.Agent.exe
- GVPN operates independently; fails gracefully if VPN unavailable

---

**Build the integrated installer:**
```powershell
cd E:\Gorstak\Sentinel\installer
.\build.ps1
```

Result: `SentinelSetup-3.6.7.exe` with embedded GVPN
