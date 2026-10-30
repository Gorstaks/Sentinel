using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core
{
    public partial class QuarantineManager
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
        private static extern SafeFileHandle OpenKnownHashFile(string path, uint access, FileShare share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
        private static extern uint KnownHashFinalPath(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out KnownHashFileInfo info);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref byte delete, uint size);
        [StructLayout(LayoutKind.Sequential)]
        private struct KnownHashFileInfo
        {
            internal uint Attributes; internal System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        private static void ValidateVaultDirectory(string path)
        {
            string productRoot = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel"));
            bool production = IsProductionQuarantinePath(path);
            for (var directory = new DirectoryInfo(path); directory != null; directory = directory.Parent)
            {
                if (!directory.Exists) continue;
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Quarantine directory must not traverse a reparse point");
                if (production && (directory.FullName.Equals(productRoot, StringComparison.OrdinalIgnoreCase) ||
                    directory.FullName.StartsWith(productRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
                {
                    var owner = (SecurityIdentifier)directory.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier));
                    if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                        throw new UnauthorizedAccessException("Quarantine hierarchy must have a privileged owner");
                }
            }
        }
        private void PrepareKnownHashVault()
        {
            ValidateVaultDirectory(_quarantineDir);
            Directory.CreateDirectory(_quarantineDir);
            ValidateVaultDirectory(_quarantineDir);
            if (!IsProductionQuarantinePath(_quarantineDir)) return;
            var info = new DirectoryInfo(_quarantineDir);
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(InteractiveBrowseRule());
            info.SetAccessControl(acl); // Fresh DACL: do not retain an explicit Everyone/User write ACE.
        }

        // Separate compiled FILE policy, not a Tier2 detection response and never process kill.
        // The same file-object handle is hashed, vaulted and marked for deletion. A renamed
        // path/replacement can never redirect deletion to a different file object.
        internal async Task<ResponseEffect> ContainKnownHashAsync(string path, string expectedHash,
            JsonlEventLogger audit, CancellationToken ct)
        {
            var effect = new ResponseEffect { Action = "KnownMalwareFileContainment", Target = path,
                Status = ResponseExecutionStatus.Refused };
            if (!OnlineHashReputation.ValidHash(expectedHash) || SelfPathGuard.IsSentinelSelfBinary(path) ||
                SecurityValidation.IsOsCriticalPath(path))
            { effect.Detail = "Invalid hash or protected product/OS path."; return effect; }
            ct.ThrowIfCancellationRequested();
            for (var ancestor = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(path))!); ancestor != null; ancestor = ancestor.Parent)
                if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0)
                { effect.Detail = "Redirected parent path; no action."; return effect; }
            using var handle = OpenKnownHashFile(path, 0x80000000 | 0x10000,
                FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var final = new StringBuilder(32768);
            uint length = KnownHashFinalPath(handle, final, (uint)final.Capacity, 0);
            if (length == 0 || length >= final.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());
            string resolved = final.ToString();
            if (resolved.StartsWith(@"\\?\", StringComparison.Ordinal)) resolved = resolved.Substring(4);
            if (SecurityValidation.IsOsCriticalPath(resolved) || SelfPathGuard.IsSentinelSelfBinary(resolved))
            { effect.Detail = "Resolved protected product/OS object; no action."; return effect; }
            if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & (0x400u | 0x10u)) != 0 || info.Links != 1 || info.SizeHigh != 0 ||
                info.SizeLow == 0 || info.SizeLow > 16 * 1024 * 1024)
            { effect.Detail = "Reparse point, directory, multiple links, empty or oversized file; no action."; return effect; }
            using var stream = new FileStream(handle, FileAccess.Read, 1, false); // No retained read buffer on the pre-disposition rehash.
            stream.Lock(0, stream.Length); // Fails closed if ordinary concurrent writers hold the bytes.
            try
            {
                var bytes = new byte[stream.Length]; int offset = 0;
                while (offset < bytes.Length)
                {
                    int count = await stream.ReadAsync(bytes, offset, bytes.Length - offset, ct).ConfigureAwait(false);
                    if (count == 0) throw new EndOfStreamException();
                    offset += count;
                }
                using var sha = SHA256.Create();
                string hash = ConvertHex.ToHexString(sha.ComputeHash(bytes));
                if (!string.Equals(hash, expectedHash, StringComparison.OrdinalIgnoreCase))
                { effect.Detail = "Content changed since reputation lookup; no action."; return effect; }
                string id = Guid.NewGuid().ToString("N");
                if (!await audit.TryLogPolicyMutationAsync(new { AuditType = "PRE_FILE_POLICY", Id = id,
                    Timestamp = DateTime.UtcNow, Policy = "ExactCurrentMalwareHash", Path = path, SHA256 = hash }, ct).ConfigureAwait(false))
                { effect.Detail = "Durable audit unavailable; no action."; return effect; }
                PrepareKnownHashVault();
                string vault = Path.Combine(_quarantineDir, "q_" + id + "_" + Regex.Replace(Path.GetFileName(path), @"[^a-zA-Z0-9_\-\.]", "_") + ".senq");
                var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine);
                using (var output = new FileStream(vault, FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
                {
                    output.Write(VaultMagic, 0, VaultMagic.Length); output.Write(encrypted, 0, encrypted.Length); output.Flush(true);
                }
                var metadata = ProtectedData.Protect(Encoding.UTF8.GetBytes(path), null, DataProtectionScope.LocalMachine);
                using (var output = new FileStream(vault + ".meta", FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
                { output.Write(metadata, 0, metadata.Length); output.Flush(true); }
                ct.ThrowIfCancellationRequested();
                // Recheck the pinned object immediately before disposition. Never File.Delete(path),
                // kill holders, seize ACLs, or schedule deletion of an unverified future replacement.
                stream.Position = 0;
                if (!string.Equals(ConvertHex.ToHexString(sha.ComputeHash(stream)), hash, StringComparison.OrdinalIgnoreCase))
                { effect.Detail = "Pinned content changed; vault retained, source not removed."; return effect; }
                byte delete = 1;
                if (!SetFileInformationByHandle(handle, 4, ref delete, 1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Vault saved; file disposition refused");
                effect.Status = ResponseExecutionStatus.PartiallyCompleted;
                effect.Detail = "Encrypted recovery copy saved; original file object marked delete-pending. Other open handles may defer removal. No process was terminated.";
                await audit.TryLogPolicyMutationAsync(new { AuditType = "FILE_POLICY_OUTCOME", Id = id,
                    Timestamp = DateTime.UtcNow, Status = effect.Status.ToString(), effect.Detail, Vault = vault }, ct).ConfigureAwait(false);
                return effect;
            }
            finally { stream.Unlock(0, stream.Length); }
        }
    }
}
