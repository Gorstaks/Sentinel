[Setup]
AppName=Sentinel
AppVersion=3.6.0
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
AppCopyright=Copyright (C) 2026 Gorstak
VersionInfoVersion=3.6.0.0
VersionInfoCompany=Gorstak
VersionInfoDescription=Sentinel Endpoint Detection and Response Setup
VersionInfoCopyright=Copyright (C) 2026 Gorstak
VersionInfoProductName=Sentinel EDR
VersionInfoProductVersion=3.6.0.0
VersionInfoOriginalFileName=SentinelSetup-3.6.0.exe
SourceDir=.
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
SetupIconFile=assets\Sentinel.ico
LicenseFile=assets\disclaimer.txt
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma/max
SolidCompression=no
OutputDir=.
OutputBaseFilename=SentinelSetup-3.6.0
PrivilegesRequired=admin
SetupMutex=Global\SentinelSetupMutex
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\disclaimer.txt"; DestDir: "{app}"; DestName: "DISCLAIMER.txt"; Flags: ignoreversion
; uninsrestartdelete: if a file is still locked at uninstall, Windows removes it at the next restart
; instead of leaving the executable behind.
Source: "..\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsrestartdelete
Source: "..\publish\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsrestartdelete
Source: "..\publish\autorotate\SentinelAutoRotate.exe"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete
Source: "..\publish\exploitshield\*"; DestDir: "{app}\ExploitShield"; Flags: ignoreversion recursesubdirs createallsubdirs

; Migrate the previous companion without deleting recovery data.
Source: "retire-nanoav.ps1"; Flags: dontcopy
Source: "set-malwarebazaar-key.ps1"; DestDir: "{app}\Tools"; Flags: ignoreversion
Source: "..\tools\diagnostics\Collect-InstallFailure.ps1"; DestDir: "{app}\Tools"; Flags: ignoreversion

[InstallDelete]
; Legacy runtime migration is performed before service upgrade.
; Keep its configuration, database, logs, backups and quarantine intact.


[Tasks]
Name: "autorotate"; Description: "Enable SentinelAutoRotate for the account running this setup. Its password is set to blank at every boot and to a random value every 10 minutes while the account is signed in, so the password is unknown to everyone. Saved browser logins, Credential Manager entries and encrypted files can become unreadable, a locked session may only unlock after a restart, and services or tasks that use this account's password stop working. Leave unchecked unless you specifically want this."; Flags: unchecked

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Run]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "Starting Sentinel..."
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"" 2>nul & exit /b 0"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonpf32}\Sentinel"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ResultCode := -1;
    if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      RaiseException('Could not start automatic exploit protection configuration.');
    if ResultCode <> 0 then
      RaiseException('Automatic exploit protection could not be scheduled. Check the ExploitShield audit log.');

    if WizardIsTaskSelected('autorotate') then
    begin
      ResultCode := -1;
      if (not Exec(ExpandConstant('{app}\SentinelAutoRotate.exe'), '--install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
        MsgBox('SentinelAutoRotate was not enabled. See ProgramData\Sentinel\AutoRotate\events.log. If the log says the password was blanked, set a password with Windows tools. Sentinel itself is installed.', mbError, MB_OK);
    end;
  end;
end;

function IsDotNet48OrHigher(): Boolean;
var
  Release: Cardinal;
begin
  Result := False;
  if IsWin64 then
  begin
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    begin
      Result := Release >= 528040;
      Exit;
    end;
  end;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Release >= 528040;
end;

function OfferDotNet48Download(): Boolean;
var
  ErrCode: Integer;
begin
  Result := False;
  if MsgBox(
    'Sentinel requires .NET Framework 4.8.' + #13#10#13#10 +
    'Yes = open the Microsoft download page' + #13#10 +
    'No  = cancel Setup',
    mbConfirmation, MB_YESNO) = IDYES then
  begin
    ShellExec('open',
      'https://dotnet.microsoft.com/download/dotnet-framework/net48',
      '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    MsgBox('After installing .NET Framework 4.8, run SentinelSetup again.', mbInformation, MB_OK);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsDotNet48OrHigher() then
    Result := OfferDotNet48Download();
end;

function SysNative(const FileName: String): String;
begin
  Result := ExpandConstant('{sysnative}\') + FileName;
  if not FileExists(Result) then
    Result := ExpandConstant('{sys}\') + FileName;
end;

// Restore v2.3.7 upgrade unlock. Hardened installs add a Users Deny-Write on
// {app}; admin accounts are in Users, so Inno cannot overwrite unins000.exe
// (Access is denied). Window is admin Setup only; the service re-locks on start.
procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
  Icacls, Takeown: String;
begin
  if not DirExists(DirPath) then
    Exit;

  Icacls := SysNative('icacls.exe');
  Takeown := SysNative('takeown.exe');

  if FileExists(DirPath + '\unins000.exe') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if FileExists(DirPath + '\unins000.dat') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.dat"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  Exec(Icacls, '"' + DirPath + '" /grant Administrators:(OI)(CI)F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Icacls, '"' + DirPath + '" /remove:d *S-1-5-32-545 /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Rename every loaded PE (EXE + DLL) in the install dir to *.old before the copy.
// A DLL mapped by the running Service/Agent cannot be overwritten or deleted
// (DeleteFile fails with "code 5, Access is denied"), but it CAN be renamed -
// Windows lets you rename a mapped image, and Inno then writes the new file in
// its place. The [Run] "del *.old" step cleans the renamed originals afterward.
procedure RenameLockedBinariesAside(const DirPath: String);
var
  FindRec: TFindRec;
  Name, Lower, Full: String;
begin
  if not DirExists(DirPath) then
    Exit;
  if FindFirst(DirPath + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
        begin
          Name := FindRec.Name;
          Lower := Lowercase(Name);
          // Only relocate PE images we ship and overwrite; leave *.old alone.
          if ((Copy(Lower, Length(Lower) - 3, 4) = '.dll') or
              (Copy(Lower, Length(Lower) - 3, 4) = '.exe')) then
          begin
            Full := DirPath + '\' + Name;
            RenameFile(Full, Full + '.old');
          end;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

// One pass: force-kills the Sentinel service and agent images. Returns True when a process
// was found and killed, False when taskkill reports no matching process (exit 128).
function KillSentinelImagesOnce(): Boolean;
var
  ResultCode: Integer;
  Taskkill: String;
begin
  Result := False;
  Taskkill := SysNative('taskkill.exe');
  Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 128 then Result := True;
  Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 128 then Result := True;
  Exec(Taskkill, '/F /IM "SentinelAutoRotate.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 128 then Result := True;
end;

// Stops every Sentinel service and agent process before files are copied. The service can
// restart the agent while it shuts down, so this repeats until a pass finds nothing. Users
// upgrading should never have to end processes by hand, so if the processes cannot be
// stopped, setup stops with a message instead of failing on a locked file.
procedure WaitForSentinelExit();
var
  Attempt: Integer;
begin
  for Attempt := 1 to 30 do
  begin
    if not KillSentinelImagesOnce() then
    begin
      Log('Sentinel: no service or agent process remains before upgrade.');
      Exit;
    end;
    Sleep(1000);
  end;
  RaiseException('Sentinel could not be stopped for the upgrade. Restart the computer and run setup again. If it still fails, collect the setup log and report it.');
end;

procedure StopExistingService();
var
  ResultCode: Integer;
  Svc, Sc: String;
begin
  if FileExists(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe')) then
  begin
    ResultCode := -1;
    if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      RaiseException('Could not stop automatic exploit protection before upgrade.');
    if ResultCode <> 0 then
      RaiseException('Could not remove the old exploit protection schedule before upgrade.');
  end;
  Svc := ExpandConstant('{app}\Sentinel.Service.exe');
  if FileExists(Svc) then
  begin
    Exec(Svc, '--prepare-upgrade', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(800);
  end;

  // Stop the watchdog FIRST via the SCM, otherwise SentinelGuard restarts
  // Sentinel.Service mid-upgrade and re-locks the DLLs (the regression that
  // brought back "DeleteFile code 5"). Then stop the main service. Give the
  // SCM time to actually transition to STOPPED before we taskkill/rename.
  Sc := SysNative('sc.exe');
  Exec(Sc, 'stop SentinelGuard', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sc, 'stop Sentinel', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);

  WaitForSentinelExit();

  ResetInstallDirAcls(ExpandConstant('{app}'));
  ResetInstallDirAcls(ExpandConstant('{commonpf}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{commonpf32}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{autopf}\Sentinel'));

  // Rename every loaded EXE/DLL aside so Inno can write the new payload even if
  // a handle is still mapped. Covers Sentinel.Core.dll and the
  // Microsoft.Extensions.*.dll set that tripped the failed upgrade.
  RenameLockedBinariesAside(ExpandConstant('{app}'));
end;

procedure RetireNanoAV();
var
  ScriptPath, PowerShellPath, Params: String;
  ExitCode: Integer;
begin
  ExtractTemporaryFile('retire-nanoav.ps1');
  ScriptPath := ExpandConstant('{tmp}\retire-nanoav.ps1');
  PowerShellPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(PowerShellPath) then
    PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Params := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath + '" -SentinelDirectory "' + ExpandConstant('{app}') + '"';
  ExitCode := -1;
  // Retiring the legacy NanoAV companion is best-effort cleanup of a previous product.
  // The script fails closed and always preserves recovery data and never imports poisoned
  // state regardless of its exit code, so a failure here (a locked/absent legacy runtime
  // file, an un-unloadable old companion, a transcript/policy hiccup) must NOT abort a fresh
  // Sentinel install. Record the outcome in the setup log and continue; the new Sentinel
  // installs cleanly and the old companion's leftovers remain reviewable.
  if not Exec(PowerShellPath, Params, '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Log('NanoAV retirement could not be launched; continuing install. Review ProgramData\Sentinel\Logs\nanoav-retirement.log.')
  else if ExitCode <> 0 then
    Log('NanoAV retirement exited ' + IntToStr(ExitCode) + '; recovery data preserved and no poisoned state imported. Continuing install. See ProgramData\Sentinel\Logs\nanoav-retirement.log.')
  else
    Log('NanoAV retirement completed.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;

  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Sentinel') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\Sentinel')) then
  begin
    RetireNanoAV();
    StopExistingService();
  end;
end;

// Force-kills every Sentinel process and waits until none is left. taskkill exits with 128
// when no matching process exists, so a pass with only 128 results means all are gone.
// Repeats because a process can come back between passes. Anything still running after the
// retries is removed at the next restart by the uninsrestartdelete file flag.
procedure KillSentinelProcesses();
var
  ResultCode, Attempt: Integer;
  Taskkill: String;
  AnyRunning: Boolean;
begin
  Taskkill := SysNative('taskkill.exe');
  for Attempt := 1 to 10 do
  begin
    AnyRunning := False;
    Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 128 then AnyRunning := True;
    Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 128 then AnyRunning := True;
    Exec(Taskkill, '/F /IM "SentinelAutoRotate.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode <> 128 then AnyRunning := True;
    if not AnyRunning then
    begin
      Log('Sentinel: all Sentinel processes have exited.');
      Exit;
    end;
    Sleep(500);
  end;
  Log('Sentinel: some Sentinel processes did not exit; locked files are removed at restart.');
end;

// Native, DLL-independent equivalent of InstallBootstrap.RunUninstallCleanup().
//
// The managed --uninstall-cleanup path lives in Sentinel.Core.dll. When an AV
// engine quarantines that DLL (recurring Wacatac.B!ml false positive on
// Sentinel.Core.dll), Sentinel.Service.exe cannot load its core assembly and
// --uninstall-cleanup exits non-zero WITHOUT doing any cleanup. This fallback
// reproduces the same teardown using only native Windows tools so a quarantined
// core DLL can never strand the install: stop watchdog+service, restore the
// firewall rollback journal, delete Sentinel's own self-isolation rules in both
// policy stores, delete the service registrations, and remove the Run + SafeBoot
// keys. Every step is best-effort - a missing journal means the firewall was
// never modified, and absent services/keys are simply skipped.
procedure UninstallFallbackCleanup();
var
  ResultCode: Integer;
  Sc, Netsh, PowerShellPath, Journal, PsRestore: String;
  Rules: array of String;
  i: Integer;
begin
  Log('Sentinel: running native uninstall fallback cleanup (managed --uninstall-cleanup unavailable or failed).');

  Sc := SysNative('sc.exe');
  Netsh := SysNative('netsh.exe');

  // 1. Stop the watchdog first (it restarts the service), then the service.
  Exec(Sc, 'stop SentinelGuard', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sc, 'stop Sentinel', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);

  // 2. Delete the SCM registrations before killing anything. A killed registered service
  // counts as a crash, and ApplyCrashRestart configures SCM to restart it after 2 s. The
  // restarted service would relaunch the Agent and lock the files Setup must remove.
  Exec(Sc, 'delete SentinelGuard', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sc, 'delete Sentinel', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 3. Force-kill survivors and wait until they exit so handles release before file removal.
  KillSentinelProcesses();

  // 4. Restore the firewall policy from Sentinel's own rollback journal. The
  // journal records only rules/profiles Sentinel changed, so this touches
  // nothing else. If the journal is absent, the firewall was never modified.
  Journal := ExpandConstant('{commonappdata}\Sentinel\FirewallPolicy\rollback.json');
  if FileExists(Journal) then
  begin
    PowerShellPath := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
    if not FileExists(PowerShellPath) then
      PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
    // Single -Command string: reload the journal and re-apply each Changed rule's
    // original enabled state and each Changed profile's original inbound action /
    // enabled state, exactly as the managed Restore operation would.
    PsRestore :=
      '$ErrorActionPreference=''SilentlyContinue'';' +
      '$s=Get-Content -LiteralPath ''' + Journal + ''' -Raw | ConvertFrom-Json;' +
      'foreach($r in $s.Rules){ if($r.Changed){' +
      '$e= if($r.OriginalEnabled){''True''}else{''False''};' +
      'Get-NetFirewallRule -Name $r.Name -PolicyStore $r.Store -EA SilentlyContinue | Set-NetFirewallRule -Enabled $e -EA SilentlyContinue } };' +
      'foreach($p in $s.Profiles){ if($p.Changed){ $a=@{Name=$p.Name;PolicyStore=$p.Store};' +
      'if($p.ChangedEnabled -and $p.OriginalEnabled -ne ''NotConfigured''){$a.Enabled=$p.OriginalEnabled};' +
      'if($p.ChangedInbound -and $p.OriginalInboundAction -ne ''NotConfigured''){$a.DefaultInboundAction=$p.OriginalInboundAction};' +
      'Set-NetFirewallProfile @a -EA SilentlyContinue } }';
    if not Exec(PowerShellPath,
      '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + PsRestore + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Log('Sentinel: firewall journal restore could not be launched; continuing teardown.')
    else if ResultCode <> 0 then
      Log('Sentinel: firewall journal restore exited ' + IntToStr(ResultCode) + '; continuing teardown.')
    else
      Log('Sentinel: firewall policy restored from rollback journal.');
  end
  else
    Log('Sentinel: no firewall rollback journal present; firewall was never modified.');

  // 5. Remove Sentinel's own self-isolation rules (both PersistentStore and
  // localhost) plus the named RPC block rule. These match SelfNetworkIsolation.
  SetArrayLength(Rules, 11);
  Rules[0]  := 'Sentinel-Offline-Sentinel.Service.exe-IN';
  Rules[1]  := 'Sentinel-Offline-Sentinel.Agent.exe-IN';
  Rules[2]  := 'Sentinel-Offline-Sentinel.Service.exe-OUT';
  Rules[3]  := 'Sentinel-Offline-Sentinel.Agent.exe-OUT';
  Rules[4]  := 'Sentinel-Offline-Sentinel.Service.exe-OUT-Repair';
  Rules[5]  := 'Sentinel-Offline-Sentinel.Agent.exe-OUT-Repair';
  Rules[6]  := 'Sentinel-Offline-SentinelAutoRotate.exe-OUT';
  Rules[7]  := 'Sentinel-Offline-SentinelAutoRotate.exe-OUT-Repair';
  Rules[8]  := 'Sentinel-Offline-SentinelAutoRotate.exe-IN';
  Rules[9]  := 'Sentinel-Offline-SentinelAutoRotate.exe-IN-Repair';
  Rules[10] := 'Sentinel-Block-Remote-RPC-Ephemeral';
  for i := 0 to GetArrayLength(Rules) - 1 do
    Exec(Netsh, 'advfirewall firewall delete rule name="' + Rules[i] + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // 6. Remove the agent autorun value and the SafeBoot keys.
  RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');
  RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel');
  RegDeleteKeyIncludingSubkeys(HKLM, 'SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel');

  Log('Sentinel: native uninstall fallback cleanup complete.');
end;

// True when any SentinelAutoRotate task (current or from the earlier release) is still registered.
function AutoRotateTaskExists(): Boolean;
var
  ResultCode: Integer;
  Schtasks: String;
begin
  Result := False;
  Schtasks := SysNative('schtasks.exe');
  if Exec(Schtasks, '/Query /TN "SentinelAutoRotate-Logon"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then Result := True;
  if Exec(Schtasks, '/Query /TN "SentinelAutoRotate-Boot"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then Result := True;
  if Exec(Schtasks, '/Query /TN "SentinelAutoRotate"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then Result := True;
  if Exec(Schtasks, '/Query /TN "SentinelAutoRotateStartup"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Svc: String;
  CleanupOk: Boolean;
begin
  if CurUninstallStep = usUninstall then
  begin
    if FileExists(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe')) then
    begin
      ResultCode := -1;
      if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        RaiseException('Could not stop Sentinel ExploitShield; uninstall cancelled.');
      if ResultCode <> 0 then
        RaiseException('Could not remove Sentinel ExploitShield schedule; uninstall cancelled.');
    end;
    // SentinelAutoRotate blanks the account password before its tasks are removed. Fail closed:
    // if the blank cannot be restored, cancel the uninstall so the account is not left on an
    // unknown password. The exe is still present at this point, so it can run its own cleanup.
    if FileExists(ExpandConstant('{app}\SentinelAutoRotate.exe')) then
    begin
      ResultCode := -1;
      if (not Exec(ExpandConstant('{app}\SentinelAutoRotate.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
        RaiseException('SentinelAutoRotate could not restore a blank password, so uninstall was cancelled. See ProgramData\Sentinel\AutoRotate\events.log, fix the cause, then uninstall again.');
    end
    else if AutoRotateTaskExists() then
      RaiseException('SentinelAutoRotate is still scheduled but its program file is missing, so the account password cannot be restored. Uninstall was cancelled. Reinstall Sentinel or remove the SentinelAutoRotate tasks, then uninstall again.');

    // Stop and kill service + agent before files are removed.
    // Without this the processes stay running and file deletion fails silently,
    // leaving both binaries on disk and the service registered.
    //
    // The managed --uninstall-cleanup lives in Sentinel.Core.dll. If an AV engine
    // has quarantined that DLL, Sentinel.Service.exe cannot load it and this call
    // fails WITHOUT doing any cleanup. Previously that raised an exception and
    // aborted the whole uninstall, stranding every file on disk with no way out.
    // Now a launch failure or non-zero exit falls back to native cleanup
    // (UninstallFallbackCleanup) so the uninstall always completes.
    Svc := ExpandConstant('{app}\Sentinel.Service.exe');
    CleanupOk := False;
    if FileExists(Svc) then
    begin
      ResultCode := -1;
      if Exec(Svc, '--uninstall-cleanup', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
      begin
        CleanupOk := True;
        Sleep(800);
      end
      else if ResultCode = -1 then
        Log('Sentinel: --uninstall-cleanup could not be launched (core DLL likely quarantined); using native fallback.')
      else
        Log('Sentinel: --uninstall-cleanup exited ' + IntToStr(ResultCode) + '; using native fallback.');
    end;

    if not CleanupOk then
      UninstallFallbackCleanup();

    KillSentinelProcesses();

    // Legacy GSecurity IPsec policies may belong to the owner; a name is not ownership.
    // Remove only Sentinel's separately named firewall rule.
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Sentinel-Block-Remote-RPC-Ephemeral"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove agent autorun key
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');
  end;
end;
