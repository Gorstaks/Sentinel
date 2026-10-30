using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;
namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class Release345WindowsTests
    {
        [EndpointWindowsAdminFact]
        public async Task ExactHashContainmentPreservesRecoverableBytesAndMismatchCannotDelete()
        {
            string root = Path.Combine(Path.GetTempPath(), "Sentinel345_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                var plant = ModuleIdentity.Evaluate(@"D:\InstalledTools\host.exe", @"D:\InstalledTools\version.dll", _ => false);
                Assert.False(plant.Allowed);
                Assert.False(DllUnloadEngine.IsReviewOnlyIdentity(plant));
                string path = Path.Combine(root, "inert.bin");
                var bytes = Encoding.UTF8.GetBytes("Inert native containment fixture " + Guid.NewGuid());
                File.WriteAllBytes(path, bytes);
                var manager = new QuarantineManager(Path.Combine(root, "vault"));
                var audit = new JsonlEventLogger(Path.Combine(root, "events.jsonl"));
                try
                {
                    var mismatch = await manager.ContainKnownHashAsync(path, new string('a', 64), audit, CancellationToken.None);
                    Assert.Equal(ResponseExecutionStatus.Refused, mismatch.Status);
                    Assert.True(File.Exists(path));
                    Assert.Empty(Directory.GetFiles(manager.QuarantineDirectory));
                    using var sha = SHA256.Create();
                    string hash = ConvertHex.ToHexString(sha.ComputeHash(bytes));
                    var outcome = await manager.ContainKnownHashAsync(path, hash, audit, CancellationToken.None);
                    Assert.Equal(ResponseExecutionStatus.PartiallyCompleted, outcome.Status);
                    Assert.False(File.Exists(path));
                    string vault = Assert.Single(Directory.GetFiles(manager.QuarantineDirectory, "*.senq"));
                    Assert.True(File.Exists(vault + ".meta"));
                    string recovered = Path.Combine(root, "recovered.bin");
                    await manager.RestoreAsync(vault, recovered);
                    Assert.Equal(bytes, File.ReadAllBytes(recovered));

                    // Close the logger BEFORE reading the audit file. The logger holds the daily
                    // audit-*.jsonl open for the process lifetime; disposing flushes the buffered
                    // PRE_FILE_POLICY record and releases the handle so this test can read it (and
                    // so the directory delete in the outer finally does not race an open handle).
                    await audit.DisposeAsync();
                    Assert.Contains("PRE_FILE_POLICY", string.Join("\n", Directory.GetFiles(root, "audit-*.jsonl").Select(File.ReadAllText)));
                }
                finally
                {
                    await audit.DisposeAsync();
                }
            }
            finally { Directory.Delete(root, true); }
        }
        [EndpointWindowsAdminFact]
        public async Task UnavailableAuditCannotMutateOrVaultSource()
        {
            string root = Path.Combine(Path.GetTempPath(), "Sentinel345_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                string path = Path.Combine(root, "inert.bin"); File.WriteAllText(path, "inert");
                using var sha = SHA256.Create();
                string hash = ConvertHex.ToHexString(sha.ComputeHash(File.ReadAllBytes(path)));
                var manager = new QuarantineManager(Path.Combine(root, "vault"));
                var audit = new JsonlEventLogger(Path.Combine(root, "events.jsonl"));
                await audit.DisposeAsync();
                var outcome = await manager.ContainKnownHashAsync(path, hash, audit, CancellationToken.None);
                Assert.Equal(ResponseExecutionStatus.Refused, outcome.Status);
                Assert.True(File.Exists(path));
                Assert.Empty(Directory.GetFiles(manager.QuarantineDirectory));
            }
            finally { Directory.Delete(root, true); }
        }
        [EndpointWindowsAdminFact]
        public void NativePolicyFingerprintTracksTypedPolicyChangesWithoutExposingContents()
        {
            string root = @"Software\Sentinel345_" + Guid.NewGuid().ToString("N");
            try
            {
                using var user = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser,
                    Microsoft.Win32.RegistryView.Default);
                using (var key = user.CreateSubKey(root))
                { key!.SetValue("ActivePolicy", "inert-private-assignment"); key.SetValue("ipsecData", new byte[] { 1, 2, 3 }); }
                string first = NetworkPolicyInventoryMonitor.Fingerprint(user, root, CancellationToken.None);
                Assert.Equal(first, NetworkPolicyInventoryMonitor.Fingerprint(user, root, CancellationToken.None));
                using (var key = user.OpenSubKey(root, true)) key!.SetValue("ipsecData", new byte[] { 1, 2, 4 });
                string second = NetworkPolicyInventoryMonitor.Fingerprint(user, root, CancellationToken.None);
                Assert.NotEqual(first, second); Assert.Equal(64, second.Length);
            }
            finally { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(root, false); }
        }
        [EndpointWindowsAdminFact]
        public async Task DirectTerminalResponseRefusesStaleEvidenceThenVerifiesOwnedProcessExitWithoutComposite()
        {
            string root = Path.Combine(Path.GetTempPath(), "Sentinel345_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
                Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Start-Sleep -Seconds 120")),
                UseShellExecute = false, CreateNoWindow = true
            })!;
            try
            {
                await using var audit = new JsonlEventLogger(Path.Combine(root, "events.jsonl"));
                var engine = new AdvancedResponseEngine(new SentinelConfig { ActiveResponse = true, MaxKillsPerMinute = 1 },
                    new SentinelMetrics(), audit, new QuarantineManager(Path.Combine(root, "vault")));
                long birth = WindowsProcessTreeOperations.GetCreationTime(child.Id);
                DetectionEvent Signal(DateTime time, System.Diagnostics.Process process, long creation) => new() { RuleName = "Reverse Shell: Raw Socket I/O Redirect",
                    ProcessId = process.Id, ProcessName = process.ProcessName, Timestamp = time,
                    SignalType = SignalType.ReverseShell, Family = TerminalFamily.ReverseShell, Confidence = .95,
                    Tier = DetectionTier.Tier1Behavioral, AuthorizedResponse = ResponseAction.KillProcessTree,
                    Metadata = new System.Collections.Generic.Dictionary<string, string> {
                        ["BehavioralProof"] = "SocketCommandLoop", ["ProcessCreationTime"] = creation.ToString() } };
                var refused = await engine.HandleAsync(Signal(DateTime.UtcNow.AddSeconds(-31), child, birth));
                Assert.False(refused.HasVerifiedProcessExit(child.Id)); child.Refresh(); Assert.False(child.HasExited);
                var result = await engine.HandleAsync(Signal(DateTime.UtcNow, child, birth));
                Assert.True(result.HasVerifiedProcessExit(child.Id), result.Reason + " | " + string.Join("; ", result.Effects.Select(e => e.Detail)));
                Assert.True(child.WaitForExit(5000));
                Assert.Empty(Directory.GetFiles(Path.Combine(root, "vault")));
                using var second = System.Diagnostics.Process.Start(child.StartInfo)!;
                try
                {
                    // Decisive second lifetime: a direct socket-shell kill must succeed even though
                    // the global one-kill budget is already exhausted (the socket-shell branch
                    // bypasses TryConsumeKillBudget by design).
                    long secondBirth = WindowsProcessTreeOperations.GetCreationTime(second.Id);
                    var next = await engine.HandleAsync(Signal(FreshAfter(secondBirth), second, secondBirth));
                    Assert.True(next.HasVerifiedProcessExit(second.Id), "Decisive socket-shell lifetime must be killed via the budget-bypassing direct path: " + string.Join("; ", next.Effects.Select(e => e.Detail)));
                }
                finally { if (!second.HasExited) { second.Kill(); second.WaitForExit(5000); } }
            }
            finally
            {
                if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); }
                Directory.Delete(root, true);
            }
        }

        // A socket-shell detection timestamp must be >= the target's creation time for
        // SocketShellLifetime.TryResolve to accept it (it rejects a creation FILETIME that is
        // newer than the detection timestamp). DateTime.UtcNow has ~15 ms resolution, so for a
        // just-started process it can quantize to an instant slightly BEFORE the process's
        // high-resolution creation FILETIME, spuriously failing the pin. Anchor the timestamp to
        // the creation instant itself (never earlier), while staying inside the 30 s freshness
        // window because the process was created moments ago.
        private static DateTime FreshAfter(long creationFileTimeUtc)
        {
            var created = DateTime.FromFileTimeUtc(creationFileTimeUtc);
            var now = DateTime.UtcNow;
            return now >= created ? now : created;
        }
    }
}
