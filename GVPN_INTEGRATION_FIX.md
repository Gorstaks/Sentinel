# GVPN Integration Fix - Installation Hang Issue

## Problem

The installer was hanging during the "Setting up VPN..." phase when trying to run GVPN.exe during installation. This occurred because:

1. GVPN.exe was being executed during the installer's [Run] phase with `waituntilterminated` flag
2. GVPN was trying to:
   - Create a Windows VPN connection (needs network access)
   - Fetch VPN servers from VPNGate API (requires internet)
   - Perform initial setup with full admin context
3. The installer waited indefinitely for GVPN to complete

## Solution

Changed GVPN initialization strategy:

### Before (Broken)
```iss
[Run]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; ...
Filename: "{app}\GVPN\GVPN.exe"; Flags: runhidden waituntilterminated; StatusMsg: "Setting up VPN..."
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ..."
```

### After (Fixed)
```iss
[Run]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; ...
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ..."

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // ... other post-install tasks ...
    
    // Schedule GVPN to run on next boot (do not block installation)
    if FileExists(ExpandConstant('{app}\GVPN\GVPN.exe')) then
    begin
      RegWriteStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'GVPN', ExpandConstant('{app}\GVPN\GVPN.exe'));
    end;
  end;
end;
```

## What Changed

1. **Removed blocking GVPN.exe call** from [Run] section
2. **Added non-blocking registration** in post-install code section
3. **GVPN now auto-starts on next system boot** (not during installation)
4. **Installation completes immediately** without waiting for VPN setup

## Installation Flow (Updated)

### During Setup
1. Sentinel service/agent deployed
2. ExploitShield scheduled
3. SentinelAutoRotate scheduled (if selected)
4. **GVPN registered for auto-start** (registry entry, no blocking)
5. Setup completes ✓

### After Reboot
1. Windows runs GVPN from Run registry
2. GVPN creates VPN connection (if first run)
3. GVPN auto-connects to VPN
4. GVPN minimizes to tray
5. Continuous monitoring starts

## Benefits

- ✅ Installation completes in seconds (no hang)
- ✅ GVPN still auto-starts on boot
- ✅ VPN setup happens when user is logged in (better context)
- ✅ User can see GVPN tray icon (visual feedback)
- ✅ Seamless experience on first reboot

## Testing

**To test the updated installer:**

```powershell
# Run installer
.\SentinelSetup-3.6.7.exe

# Should complete WITHOUT hanging
# Check: GVPN registry entry created
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object GVPN

# Reboot system
Restart-Computer

# After reboot: GVPN should auto-start in tray
Get-Process GVPN
```

## Files Modified

- `installer/setup.iss` - Removed blocking GVPN call, added registry registration
- `installer/build.ps1` - Added GVPN to build output (publish/gvpn/)

## Version

- **Sentinel**: 3.6.7
- **GVPN**: 0.0.4
- **Installer**: SentinelSetup-3.6.7.exe (11 MB)
- **Status**: Ready for deployment
