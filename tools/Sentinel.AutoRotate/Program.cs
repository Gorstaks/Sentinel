// =============================================================================
// Sentinel.AutoRotate (SentinelAutoRotate.exe)
//
// WHAT THIS TOOL DOES
//   Keeps one local Windows account's password unknown to any person. It blanks the password at boot,
//   sets a random 48-character password every 10 minutes while the account's desktop is signed in,
//   and restores a blank password on uninstall. No password is stored. There is no autologon.
//
// KNOWN CONSEQUENCES (read before enabling)
//   - Each password change is an administrative set, not a password change, because the old password is
//     not known. DPAPI-protected data encrypted under the previous password becomes unreadable: saved
//     browser logins, Credential Manager entries, EFS files and certificate private keys.
//   - Sign-in after a session lock needs the blank password, which is only valid after the next boot.
//     A locked session may therefore be impossible to unlock until the machine restarts.
//   - Services, scheduled tasks and network shares that store this account's password stop working
//     at the next rotation.
//   - A physical attacker or any process running as SYSTEM or administrator can set the password.
//
// MODES
//   --install     administrator, run from the target account's desktop. Blanks the password,
//                 registers the boot and logon tasks, and starts the session worker.
//   --boot        SYSTEM at startup. Blanks the password once per boot.
//   --session     target account, at logon. Rotates every ten minutes while the desktop is signed in.
//   --uninstall   blanks the password, then removes the tasks and the earlier release's autologon.
// =============================================================================

using System;

namespace Sentinel.AutoRotate;

internal static class Program
{
    private const string Usage =
        "SentinelAutoRotate - keeps a local account password unknown by rotating it every 10 minutes.\n" +
        "Usage:\n" +
        "  SentinelAutoRotate.exe --install     Blank the account password and start rotation (administrator, target desktop).\n" +
        "  SentinelAutoRotate.exe --install --force  Skip password-policy validation (owner override; policy will be re-checked at each password change).\n" +
        "  SentinelAutoRotate.exe --boot        Blank the password once per boot (SYSTEM, scheduled task).\n" +
        "  SentinelAutoRotate.exe --session     Rotate every ten minutes while the desktop is signed in (scheduled task).\n" +
        "  SentinelAutoRotate.exe --uninstall   Blank the password, remove tasks and earlier autologon.";

    private static int Main(string[] args)
    {
        string mode = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : string.Empty;
        bool forceFlag = args.Any(a => a.Equals("--force", StringComparison.OrdinalIgnoreCase));
        try
        {
            switch (mode)
            {
                case "--install":
                    return Rotator.Install(forceFlag);
                case "--boot":
                    return Rotator.BootReset();
                case "--session":
                    return Rotator.RunSession();
                case "--uninstall":
                    return Rotator.Uninstall();
                default:
                    Console.Error.WriteLine(Usage);
                    return 2;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException || ex is System.IO.IOException || ex is UnauthorizedAccessException || ex is System.ComponentModel.Win32Exception || ex is TimeoutException)
        {
            Rotator.Log("ERROR (" + mode + "): " + ex.Message);
            return 1;
        }
    }
}
