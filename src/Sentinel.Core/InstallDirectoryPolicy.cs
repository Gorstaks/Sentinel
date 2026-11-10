using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - The Sentinel service runs as LocalSystem from its install directory, so anyone who
    /// can write there owns the machine. The directory must be a protected location: under
    /// Program Files, or (for a custom path) owned by a trusted principal with no write access
    /// granted to anyone else and no reparse points. Installer and service both enforce this.
    /// </summary>
    public static class InstallDirectoryPolicy
    {
        private const FileSystemRights WriteLike =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.CreateFiles |
            FileSystemRights.CreateDirectories | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

        public readonly struct Result
        {
            public Result(bool ok, string reason) { Ok = ok; Reason = reason; }
            public bool Ok { get; }
            public string Reason { get; }
        }

        public static Result Evaluate(string? directory)
        {
            if (string.IsNullOrWhiteSpace(directory)) return new Result(false, "Install directory is empty.");
            string full;
            try { full = Path.GetFullPath(directory!).TrimEnd('\\'); }
            catch (Exception ex) { return new Result(false, "Install directory is not a valid path: " + ex.Message); }

            try
            {
                if (HasReparsePoint(full))
                    return new Result(false, "Install directory or an ancestor is a reparse point.");

                DirectorySecurity security = new DirectoryInfo(full).GetAccessControl();
                return EvaluateSecurity(full, security, IsUnderProgramFiles(full));
            }
            catch (Exception ex)
            {
                // Fail closed: if the ACL cannot be read, the directory is not proven protected.
                return new Result(false, "Install directory ACL could not be verified: " + ex.Message);
            }
        }

        /// <summary>Pure ACL rule so the policy is unit-testable on a constructed descriptor.</summary>
        public static Result EvaluateSecurity(string directory, FileSystemSecurity security, bool underProgramFiles)
        {
            // Under Program Files only an administrator can have created the directory, so the owner
            // (which may be the elevated user's own SID depending on policy) is not the signal there.
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!underProgramFiles && (owner == null || !IsTrusted(owner)))
                return new Result(false, "Install directory is not owned by SYSTEM, Administrators or TrustedInstaller.");

            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.FileSystemRights & WriteLike) == 0) continue;
                var sid = (SecurityIdentifier)rule.IdentityReference;
                if (IsTrusted(sid)) continue;
                if (sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid) && underProgramFiles) continue;
                return new Result(false, "Install directory grants write access to " + sid.Value + ".");
            }
            return new Result(true, "Protected.");
        }

        public static bool IsUnderProgramFiles(string fullPath)
        {
            foreach (var root in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            })
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (fullPath.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static bool IsTrusted(SecurityIdentifier sid)
            => sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
               sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
               string.Equals(sid.Value, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", StringComparison.Ordinal); // NT SERVICE\TrustedInstaller

        private static bool HasReparsePoint(string fullPath)
        {
            var current = fullPath;
            while (!string.IsNullOrEmpty(current))
            {
                var info = new DirectoryInfo(current);
                if (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0) return true;
                var parent = Path.GetDirectoryName(current);
                if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
                current = parent!;
            }
            return false;
        }
    }
}
