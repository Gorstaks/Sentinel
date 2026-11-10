using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - %ProgramData%\Sentinel is created by whichever process runs first. A standard user
    /// who creates it before the service owns it and keeps WRITE_DAC, so SYSTEM must not trust it
    /// as found. This guard takes ownership for Administrators, rewrites a protected ACL, and then
    /// verifies the result. A failure is returned or thrown, never swallowed.
    /// </summary>
    public static class ProgramDataGuard
    {
        public static string SentinelRoot => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        /// <summary>
        /// Creates the directory if needed and enforces: owner Administrators, protected DACL with
        /// SYSTEM and Administrators full control, and optionally interactive read/execute.
        /// Throws if the verified result is not protected.
        /// </summary>
        public static void EnsureProtectedDirectory(string dirPath, bool interactiveReadExecute)
        {
            if (!Directory.Exists(dirPath)) Directory.CreateDirectory(dirPath);

            var info = new DirectoryInfo(dirPath);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Refusing reparse point at protected directory: " + dirPath);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);

            var security = info.GetAccessControl();
            security.SetOwner(admins);
            security.SetAccessRuleProtection(true, false);
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                security.RemoveAccessRuleAll(rule);
            const InheritanceFlags both = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, both, PropagationFlags.None, AccessControlType.Allow));
            if (interactiveReadExecute)
                security.AddAccessRule(new FileSystemAccessRule(interactive, FileSystemRights.ReadAndExecute, both, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);

            var verdict = InstallDirectoryPolicy.EvaluateSecurity(dirPath, info.GetAccessControl(), false);
            if (!verdict.Ok)
                throw new UnauthorizedAccessException("Protected directory verification failed for " + dirPath + ": " + verdict.Reason);
        }

        /// <summary>True when the file exists, is owned by SYSTEM/Administrators and grants no write to anyone else.</summary>
        public static bool IsTrustedFile(string path)
        {
            try
            {
                if (!File.Exists(path)) return false;
                var info = new FileInfo(path);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return false;
                return InstallDirectoryPolicy.EvaluateSecurity(path, info.GetAccessControl(), false).Ok;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("[ProgramDataGuard] Could not verify '" + path + "': " + ex.Message);
                return false;
            }
        }
    }
}
