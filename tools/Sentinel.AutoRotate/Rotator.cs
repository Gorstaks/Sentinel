// Operations for each mode. The model follows PasswordRotator.ps1:
//   --install   verify the target account, blank its password, register tasks, start the session worker
//   --boot      (SYSTEM, at startup) blank the password once per boot
//   --session   (target user, logon) rotate to a random password every ten minutes while the desktop is signed in
//   --uninstall blank the password again, then remove the tasks
//
// Every mode that changes a password holds a machine-wide mutex, so boot, session and uninstall never overlap.
// Passwords are never written to logs or to disk. Strings holding them cannot be wiped in .NET, so they are
// kept in local variables only.
//
// Known consequence (documented to the owner): setting a password without the old one is an administrative
// reset. Windows cannot decrypt DPAPI-protected data protected under the previous password, so saved
// browser logins, Credential Manager entries and EFS files can become unreadable.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Runtime.Serialization.Json;
using System.Threading;
using Microsoft.Win32;

namespace Sentinel.AutoRotate;

internal static class Rotator
{
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string LegacyAutologonSecret = "DefaultPassword";
    private static readonly object LogLock = new object();

    public static readonly string StateDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "AutoRotate");

    private static readonly string StatePath = Path.Combine(StateDirectory, "state.json");
    private static readonly string LogPath = Path.Combine(StateDirectory, "events.log");

    // ---- logging -----------------------------------------------------------------

    public static void Log(string message)
    {
        // Logging is best effort. A failed log write must not change the outcome of a password operation,
        // which is reported through the exit code and the caller's own messages.
        try
        {
            lock (LogLock)
            {
                Directory.CreateDirectory(StateDirectory);
                File.AppendAllText(LogPath, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + message + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    // ---- state -------------------------------------------------------------------

    public static RotatorState? LoadState()
    {
        if (!File.Exists(StatePath)) return null;
        using (FileStream stream = File.OpenRead(StatePath))
        {
            var serializer = new DataContractJsonSerializer(typeof(RotatorState));
            return serializer.ReadObject(stream) as RotatorState;
        }
    }

    public static void SaveState(RotatorState state)
    {
        string temporary = StatePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (FileStream stream = File.Create(temporary))
        {
            var serializer = new DataContractJsonSerializer(typeof(RotatorState));
            serializer.WriteObject(stream, state);
        }
        if (File.Exists(StatePath))
            File.Replace(temporary, StatePath, null);
        else
            File.Move(temporary, StatePath);
    }

    public static void EnsureStateDirectory()
    {
        if (Directory.Exists(StateDirectory))
        {
            if ((new DirectoryInfo(StateDirectory).Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The AutoRotate state directory must not be a reparse point.");
        }
        else
        {
            Directory.CreateDirectory(StateDirectory);
        }

        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (string sid in new[] { "S-1-5-18", "S-1-5-32-544" })
        {
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        new DirectoryInfo(StateDirectory).SetAccessControl(acl);
    }

    // ---- lock --------------------------------------------------------------------

    /// <summary>Runs an action while holding the machine-wide rotation mutex for the target account.</summary>
    public static T Locked<T>(string sid, Func<T> action)
    {
        var security = new MutexSecurity();
        foreach (string allowed in new[] { "S-1-5-18", "S-1-5-32-544" })
        {
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(allowed), MutexRights.FullControl, AccessControlType.Allow));
        }

        bool created;
        using (var mutex = new Mutex(false, "Global\\SentinelAutoRotate." + sid, out created, security))
        {
            bool owned = false;
            try
            {
                try
                {
                    owned = mutex.WaitOne(TimeSpan.FromSeconds(60));
                }
                catch (AbandonedMutexException)
                {
                    // The previous owner exited without releasing. The protected state is re-read under the lock.
                    owned = true;
                }

                if (!owned) throw new TimeoutException("Timed out waiting for the AutoRotate lock.");
                return action();
            }
            finally
            {
                if (owned) mutex.ReleaseMutex();
            }
        }
    }

    // ---- session and boot identity -------------------------------------------------

    /// <summary>SID of the account that owns the current process session, or empty when it cannot be determined.</summary>
    public static string CurrentSessionSid()
    {
        try
        {
            uint session = (uint)Process.GetCurrentProcess().SessionId;
            string user = WtsString(session, NativeMethods.WTSUserName);
            if (user.Length == 0) return string.Empty;
            string domain = WtsString(session, NativeMethods.WTSDomainName);
            return new NTAccount(domain, user).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception ex) when (ex is Win32Exception || ex is IdentityNotMappedException || ex is SystemException)
        {
            // Fail closed: an unknown session never matches the target, so rotation stops.
            Log("Session identity unavailable; rotation stopped: " + ex.Message);
            return string.Empty;
        }
    }

    public static string ConsoleUserName()
    {
        uint session = NativeMethods.WTSGetActiveConsoleSessionId();
        if (session == NativeMethods.NoActiveConsoleSession) return string.Empty;
        return WtsString(session, NativeMethods.WTSUserName);
    }

    private static string WtsString(uint session, int infoClass)
    {
        IntPtr buffer;
        uint bytes;
        if (!NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out buffer, out bytes))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            NativeMethods.WTSFreeMemory(buffer);
        }
    }

    /// <summary>Boot instant in UTC, derived from the uptime counter.</summary>
    public static DateTime CurrentBootUtc()
    {
        return DateTime.UtcNow.AddMilliseconds(-(double)NativeMethods.GetTickCount64());
    }

    // ---- account and policy checks -----------------------------------------------------

    public static void RequireLocalEnabledAccount(string account)
    {
        IntPtr buffer;
        uint rc = NativeMethods.NetUserGetInfo(null, account, 1, out buffer);
        if (rc != NativeMethods.NERR_Success)
            throw new InvalidOperationException("Only a standalone local account is supported (NetUserGetInfo error " + rc + ").");
        try
        {
            var info = Marshal.PtrToStructure<NativeMethods.USER_INFO_1>(buffer);
            if ((info.usri1_flags & NativeMethods.UF_ACCOUNTDISABLE) != 0)
                throw new InvalidOperationException("The local account is disabled.");
        }
        finally
        {
            NativeMethods.NetApiBufferFree(buffer);
        }
    }

    public static void RequireBlankPolicy()
    {
        IntPtr buffer;
        uint rc = NativeMethods.NetUserModalsGet(null, 0, out buffer);
        if (rc != NativeMethods.NERR_Success)
            throw new InvalidOperationException("Could not read the local password policy (NetUserModalsGet error " + rc + "). Policy may be enforced by Group Policy; check with your administrator.");
        try
        {
            var modals = Marshal.PtrToStructure<NativeMethods.USER_MODALS_INFO_0>(buffer);
            if (modals.usrmod0_min_passwd_len > 0)
                throw new InvalidOperationException("The effective local password policy requires a minimum length of " + modals.usrmod0_min_passwd_len + " characters for any password. Windows does not permit blank passwords when this policy is active. " +
                    "To use SentinelAutoRotate, your administrator must temporarily lower the minimum password length to 0 (via Local Security Policy > Account Policies > Password Policy > Minimum Password Length), " +
                    "or you can disable AutoRotate in the Sentinel installer and run it manually later after adjusting the policy. " +
                    "Sentinel itself (Service and Agent) are still installed and working.");
        }
        finally
        {
            NativeMethods.NetApiBufferFree(buffer);
        }
    }

    /// <summary>Effective local minimum password length.</summary>
    public static uint ReadMinPasswordLength()
    {
        IntPtr buffer;
        uint rc = NativeMethods.NetUserModalsGet(null, 0, out buffer);
        if (rc != NativeMethods.NERR_Success)
            throw new InvalidOperationException("Could not read the local password policy (NetUserModalsGet error " + rc + ").");
        try
        {
            return Marshal.PtrToStructure<NativeMethods.USER_MODALS_INFO_0>(buffer).usrmod0_min_passwd_len;
        }
        finally
        {
            NativeMethods.NetApiBufferFree(buffer);
        }
    }

    public static void WriteMinPasswordLength(uint length)
    {
        var info = new NativeMethods.USER_MODALS_INFO_1001 { usrmod1001_min_passwd_len = length };
        uint parameterError;
        uint rc = NativeMethods.NetUserModalsSet(null, 1001, ref info, out parameterError);
        if (rc != NativeMethods.NERR_Success)
            throw new InvalidOperationException("Could not change the local minimum password length (NetUserModalsSet error " + rc + ", parameter " + parameterError + ").");
    }

    /// <summary>
    /// 3.7.1: lower the local minimum password length to 0 for this opted-in install only, recording
    /// the original so uninstall can restore it. Domain or Group Policy can re-apply its own value;
    /// the boot reset then fails closed and is logged, as before.
    /// </summary>
    private static void AllowBlankPassword(RotatorState state)
    {
        uint current = ReadMinPasswordLength();
        if (current == 0) return;
        WriteMinPasswordLength(0);
        state.PolicyAdjusted = true;
        state.OriginalMinPasswordLength = current;
        SaveState(state);
        Log("Lowered the local minimum password length from " + current + " to 0 for SentinelAutoRotate; uninstall restores it.");
    }

    /// <summary>Restore the recorded minimum length, unless an administrator has changed it since.</summary>
    private static void RestorePasswordPolicy(RotatorState state)
    {
        if (!state.PolicyAdjusted) return;
        try
        {
            uint current = ReadMinPasswordLength();
            if (current == 0)
            {
                WriteMinPasswordLength(state.OriginalMinPasswordLength);
                Log("Restored the local minimum password length to " + state.OriginalMinPasswordLength + ".");
            }
            else
            {
                Log("Minimum password length was changed to " + current + " since install; left as is.");
            }
            state.PolicyAdjusted = false;
            SaveState(state);
        }
        catch (InvalidOperationException ex)
        {
            Log("Could not restore the local minimum password length: " + ex.Message);
        }
    }

    // ---- password writes (administrative set; no old password is known) --------------

    private static void SetPassword(string account, string password)
    {
        var info = new NativeMethods.USER_INFO_1003 { usri1003_password = password };
        uint parameterError;
        uint rc = NativeMethods.NetUserSetInfo(null, account, 1003, ref info, out parameterError);
        if (rc != NativeMethods.NERR_Success)
            throw new InvalidOperationException("Windows rejected the password change (error " + rc + ", parameter " + parameterError + ").");
    }

    // ---- modes -----------------------------------------------------------------------

    /// <summary>--boot: blank the password once per boot. Returns 0 on success or when already done for this boot.</summary>
    public static int BootReset()
    {
        RotatorState? snapshot = LoadState();
        if (snapshot is null || !snapshot.Installed) return 0;

        return Locked(snapshot.Sid, () =>
        {
            RotatorState? state = LoadState();
            if (state is null || !state.Installed) return 0;

            DateTime boot = CurrentBootUtc();
            if (state.ResetSucceeded && RotationPolicy.IsSameBoot(state.BootUtc, boot)) return 0;

            state.ResetSucceeded = false;
            state.BootUtc = boot.ToString("o", CultureInfo.InvariantCulture);
            SaveState(state);

            try
            {
                SetPassword(state.Account, string.Empty);
            }
            catch (InvalidOperationException ex)
            {
                Log("Boot blank reset failed; rotation blocked: " + ex.Message);
                return 1;
            }

            state.ResetSucceeded = true;
            state.ResetUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            SaveState(state);
            Log("Boot blank reset succeeded.");
            return 0;
        });
    }

    /// <summary>--session: rotate every ten minutes while the target desktop is signed in.</summary>
    public static int RunSession()
    {
        RotatorState? first = LoadState();
        if (first is null || !first.Installed) return 0;
        string sid = first.Sid;

        string? timerToken = null;
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var waiting = System.Diagnostics.Stopwatch.StartNew();

        using (var idle = new ManualResetEventSlim(false))
        {
            while (true)
            {
                try
                {
                    string mySid = CurrentSessionSid();
                    string? token = timerToken;
                    TimeSpan elapsed = timer.Elapsed;

                    RotationAction action = Locked(sid, () =>
                    {
                        RotatorState? state = LoadState();
                        bool match = mySid.Length > 0 && state != null &&
                            string.Equals(mySid, state.Sid, StringComparison.OrdinalIgnoreCase);
                        RotationAction decided = RotationPolicy.Decide(state, match, CurrentBootUtc(), token, elapsed);
                        if (decided == RotationAction.Rotate)
                        {
                            SetPassword(state!.Account, RotationPolicy.NewRandomPassword());
                            Log("Password rotated; password not retained.");
                        }
                        return decided;
                    });

                    switch (action)
                    {
                        case RotationAction.Stop:
                            return 0;
                        case RotationAction.WaitingForReset:
                            if (waiting.Elapsed > TimeSpan.FromMinutes(3))
                            {
                                Log("Boot reset has not succeeded; rotation was not started.");
                                return 1;
                            }
                            break;
                        case RotationAction.StartTimer:
                            timerToken = Locked(sid, () => LoadState()?.ResetUtc);
                            timer.Restart();
                            waiting.Restart();
                            Log("Session rotation timer started; first rotation in ten minutes.");
                            break;
                        case RotationAction.Rotate:
                            timer.Restart();
                            break;
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException)
                {
                    Log("Session worker stopped: " + ex.Message);
                    return 1;
                }

                idle.Wait(TimeSpan.FromSeconds(5));
            }
        }
    }

    /// <summary>--install: run from the target account's desktop as administrator.</summary>
    public static int Install(bool skipPolicyCheck = false)
    {
        if (!IsAdministrator())
        {
            Rotator.Log("Install refused: administrator rights are required.");
            return 1;
        }

        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        string fullName = identity.Name;
        string account = fullName.Substring(fullName.LastIndexOf('\\') + 1);
        string sid = identity.User?.Value ?? throw new InvalidOperationException("Could not read the account SID.");

        if (!string.Equals(ConsoleUserName(), account, StringComparison.OrdinalIgnoreCase))
        {
            Rotator.Log("Install refused: run setup from the desktop of the account to protect, not from another account.");
            return 1;
        }

        RequireLocalEnabledAccount(account);
        EnsureStateDirectory();

        // Clear any earlier installation first (idempotent reinstall, or migration from an older release).
        int previous = Uninstall();
        if (previous != 0) return previous;

        string exePath = Process.GetCurrentProcess().MainModule.FileName;
        var state = new RotatorState { Installed = true, RotationEnabled = false, Account = account, Sid = sid };
        SaveState(state);

        try
        {
            // 3.7.1: the blank-password allowance is applied here, for the opted-in install only.
            AllowBlankPassword(state);
            if (!skipPolicyCheck)
                RequireBlankPolicy();

            // The first blank reset also verifies that the password policy accepts an empty password.
            if (BootReset() != 0) throw new InvalidOperationException("The blank password reset failed; see events.log.");

            Scheduler.Register(sid, exePath);

            RotatorState current = LoadState() ?? state;
            current.RotationEnabled = true;
            SaveState(current);

            Scheduler.Run(Scheduler.LogonTask);
        }
        catch (Exception ex) when (ex is InvalidOperationException || ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException || ex is Win32Exception)
        {
            Log("Install failed: " + ex.Message + ". Tasks were removed. If the password was already blanked it stays blank; set it with Windows tools.");
            Scheduler.DeleteAll();
            RotatorState failed = LoadState() ?? state;
            failed.Installed = false;
            failed.RotationEnabled = false;
            SaveState(failed);
            RestorePasswordPolicy(failed);
            return 1;
        }

        Log("Installed for " + account + ". Password is blank now; rotation begins in ten minutes while signed in.");
        return 0;
    }

    /// <summary>--uninstall: blank the password, then remove the tasks. Returns nonzero if the password could not be blanked.</summary>
    public static int Uninstall()
    {
        RotatorState? state = LoadState();
        bool legacy = Scheduler.LegacyPresent();

        if (state is null || !state.Installed)
        {
            Scheduler.DeleteAll();
            RemoveLegacyAutologon(state?.Account, legacy);
            if (state != null) RestorePasswordPolicy(state);
            Log("Uninstall: no active installation.");
            return 0;
        }

        // Stop new work first: end the session worker and keep the boot task from running again.
        Scheduler.End(Scheduler.LogonTask);
        Scheduler.Disable(Scheduler.LogonTask);
        Scheduler.Disable(Scheduler.BootTask);

        try
        {
            Locked(state.Sid, () =>
            {
                RotatorState current = LoadState() ?? state;
                current.RotationEnabled = false;
                SaveState(current);

                SetPassword(current.Account, string.Empty);

                current.Installed = false;
                current.ResetSucceeded = false;
                SaveState(current);
                return 0;
            });
        }
        catch (Exception ex) when (ex is InvalidOperationException || ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException)
        {
            // The password was not changed. Keep the boot task so the next boot retries the blank reset.
            Log("Uninstall could not restore a blank password; tasks retained for recovery: " + ex.Message);
            try { Scheduler.Enable(Scheduler.BootTask); }
            catch (InvalidOperationException enableFailure) { Log("Could not re-enable the boot task: " + enableFailure.Message); }
            return 1;
        }

        RemoveLegacyAutologon(state.Account, legacy);
        Scheduler.DeleteAll();
        // The blank password set above stays valid; the restored minimum applies to later changes.
        RotatorState finalState = LoadState() ?? state;
        RestorePasswordPolicy(finalState);
        Log("Uninstalled. The account password is blank.");
        return 0;
    }

    // ---- legacy autologon cleanup -------------------------------------------------------

    /// <summary>
    /// Removes the autologon configuration that the earlier release created. It runs only for the account this
    /// tool manages, or when that release's tasks are still present, so an unrelated autologon is never changed.
    /// </summary>
    private static void RemoveLegacyAutologon(string? account, bool legacyTasksPresent)
    {
        using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true))
        {
            if (key is null) return;
            string? defaultUser = key.GetValue("DefaultUserName") as string;
            bool autologonOn = string.Equals(key.GetValue("AutoAdminLogon")?.ToString(), "1", StringComparison.Ordinal);
            bool ours = account != null && string.Equals(defaultUser, account, StringComparison.OrdinalIgnoreCase);
            if (!autologonOn || !(ours || legacyTasksPresent)) return;

            key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
        }

        DeleteLsaSecret(LegacyAutologonSecret);
        Log("Removed autologon configured by an earlier SentinelAutoRotate release.");
    }

    private static void DeleteLsaSecret(string name)
    {
        var attributes = new NativeMethods.LSA_OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<NativeMethods.LSA_OBJECT_ATTRIBUTES>(),
        };

        uint status = NativeMethods.LsaOpenPolicy(IntPtr.Zero, ref attributes, NativeMethods.POLICY_CREATE_SECRET, out IntPtr policy);
        if (status != 0)
            throw new InvalidOperationException("LsaOpenPolicy failed (NTSTATUS 0x" + status.ToString("X8", CultureInfo.InvariantCulture) + ").");

        try
        {
            var key = new NativeMethods.LSA_UNICODE_STRING
            {
                Buffer = Marshal.StringToHGlobalUni(name),
                Length = (ushort)(name.Length * sizeof(char)),
                MaximumLength = (ushort)((name.Length + 1) * sizeof(char)),
            };
            try
            {
                // A null private data pointer deletes the secret.
                status = NativeMethods.LsaStorePrivateData(policy, ref key, IntPtr.Zero);
                if (status != 0 && status != NativeMethods.STATUS_OBJECT_NAME_NOT_FOUND)
                    throw new InvalidOperationException("LsaStorePrivateData failed (NTSTATUS 0x" + status.ToString("X8", CultureInfo.InvariantCulture) + ").");
            }
            finally
            {
                Marshal.FreeHGlobal(key.Buffer);
            }
        }
        finally
        {
            NativeMethods.LsaClose(policy);
        }
    }

    private static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
