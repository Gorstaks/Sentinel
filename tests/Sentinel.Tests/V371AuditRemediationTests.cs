using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// 3.7.1 red/blue audit remediations. Each test pins one closed attack path.
    /// </summary>
    public class V371AuditRemediationTests
    {
        //  Dashboard: no token in unauthenticated responses, Host/Origin pinned 

        private static string RepoFile(params string[] parts)
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Sentinel.sln"))) dir = dir.Parent;
            Assert.NotNull(dir);
            var all = new List<string> { dir!.FullName };
            all.AddRange(parts);
            return File.ReadAllText(Path.Combine(all.ToArray()));
        }

        [Fact]
        public void DashboardSource_NeverEmbedsTheBearerToken()
        {
            var html = RepoFile("src", "Sentinel.Agent", "DashboardHtml.cs");
            Assert.DoesNotContain("var EMBEDDED_TOKEN", html);
            Assert.Contains("public static string GetHtml()", html);

            var service = RepoFile("src", "Sentinel.Agent", "WebDashboardService.cs");
            Assert.DoesNotContain("GetHtml(_bearerToken)", service);
            Assert.Contains("ServeBootstrap", service);
        }

        [Fact]
        public void BootstrapPage_CarriesNoSecretAndOnlyReentersWithSessionToken()
        {
            Assert.DoesNotContain("Bearer", DashboardRequestGuard.BootstrapHtml);
            Assert.Contains("sessionStorage.getItem('sentinel_token')", DashboardRequestGuard.BootstrapHtml);
        }

        [Theory]
        [InlineData("localhost:19845", true)]
        [InlineData("127.0.0.1:19845", true)]
        [InlineData("[::1]:19845", true)]
        [InlineData("evil.example:19845", false)]
        [InlineData("localhost.evil.example:19845", false)]
        [InlineData("localhost", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void HostHeader_IsPinnedToLoopbackDashboard(string? host, bool expected)
            => Assert.Equal(expected, DashboardRequestGuard.IsAllowedHost(host));

        [Theory]
        [InlineData(null, true)]
        [InlineData("http://localhost:19845", true)]
        [InlineData("http://127.0.0.1:19845", true)]
        [InlineData("https://evil.example", false)]
        [InlineData("http://localhost:19845.evil.example", false)]
        [InlineData("null", false)]
        public void OriginHeader_MustBeTheDashboardWhenPresent(string? origin, bool expected)
            => Assert.Equal(expected, DashboardRequestGuard.IsAllowedOrigin(origin));

        [Fact]
        public void Csp_ForbidsExternalScriptsFramesAndForms()
        {
            Assert.Contains("default-src 'none'", DashboardRequestGuard.ContentSecurityPolicy);
            Assert.Contains("frame-ancestors 'none'", DashboardRequestGuard.ContentSecurityPolicy);
            Assert.Contains("form-action 'none'", DashboardRequestGuard.ContentSecurityPolicy);
        }

        //  Install directory: SYSTEM must not run from a user-writable folder 

        private static DirectorySecurity Descriptor(params (WellKnownSidType Sid, FileSystemRights Rights)[] allows)
        {
            var security = new DirectorySecurity();
            security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            security.SetAccessRuleProtection(true, false);
            foreach (var (sid, rights) in allows)
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), rights, AccessControlType.Allow));
            return security;
        }

        [Fact]
        public void InstallPolicy_AcceptsAdminOnlyWriteWithUserReadExecute()
        {
            var security = Descriptor(
                (WellKnownSidType.LocalSystemSid, FileSystemRights.FullControl),
                (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl),
                (WellKnownSidType.BuiltinUsersSid, FileSystemRights.ReadAndExecute));
            Assert.True(InstallDirectoryPolicy.EvaluateSecurity(@"C:\Sentinel", security, underProgramFiles: false).Ok);
        }

        [Theory]
        [InlineData(WellKnownSidType.AuthenticatedUserSid)]
        [InlineData(WellKnownSidType.BuiltinUsersSid)]
        [InlineData(WellKnownSidType.WorldSid)]
        public void InstallPolicy_RejectsAnyNonAdminWriter(WellKnownSidType writer)
        {
            var security = Descriptor(
                (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl),
                (writer, FileSystemRights.Modify));
            Assert.False(InstallDirectoryPolicy.EvaluateSecurity(@"C:\Sentinel", security, underProgramFiles: false).Ok);
        }

        [Fact]
        public void InstallPolicy_RejectsUntrustedOwnerOutsideProgramFiles()
        {
            var security = Descriptor((WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl));
            security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
            Assert.False(InstallDirectoryPolicy.EvaluateSecurity(@"C:\Sentinel", security, underProgramFiles: false).Ok);
        }

        [Fact]
        public void InstallPolicy_RejectsAWritableTempDirectory()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel_install_policy_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                // The current user can write here, so it must never qualify as a SYSTEM install root.
                Assert.False(InstallDirectoryPolicy.Evaluate(dir).Ok);
            }
            finally { Directory.Delete(dir, true); }
        }

        //  Registry removal: exact roots, observed-target binding 

        [Theory]
        [InlineData("HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", "Updater", true)]
        [InlineData("HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "x", true)]
        [InlineData("HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallForcelist", "1", true)]
        [InlineData("HKLM", @"System\CurrentControlSet\Services\WinDefend", "Start", false)]
        [InlineData("HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunServices", "x", false)]
        [InlineData("HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", "SentinelAgent", false)]
        [InlineData("HKCR", @"Software\Microsoft\Windows\CurrentVersion\Run", "x", false)]
        public void RegistryValueRemoval_OnlyAtAllowedRoots(string hive, string key, string value, bool expected)
            => Assert.Equal(expected, RegistryRemovalPolicy.ValueRemovalAllowed(hive, key, value, out _));

        [Fact]
        public void ServiceRemoval_RefusesProtectedServicesDriversAndChangedTargets()
        {
            const string root = RegistryRemovalPolicy.ServicesRoot;
            const string userPath = @"C:\Users\a\AppData\Local\Temp\svc.exe";
            Assert.True(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "EvilSvc", userPath, 0x10, userPath, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "WinDefend", userPath, 0x10, userPath, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "Sentinel", userPath, 0x10, userPath, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "EvilDrv", userPath, 0x01, userPath, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "EvilSvc", @"C:\Program Files\Vendor\svc.exe", 0x10, null, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, "EvilSvc", userPath, 0x10, @"C:\Users\a\other.exe", out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(@"System\CurrentControlSet\Control", "EvilSvc", userPath, 0x10, userPath, out _));
            Assert.False(RegistryRemovalPolicy.ServiceRemovalAllowed(root, @"..\Control", userPath, 0x10, userPath, out _));
        }

        [Fact]
        public void ClsidRemoval_RequiresExactKeyAndUserWritableServer()
        {
            const string clsid = "{11111111-2222-3333-4444-555555555555}";
            var key = @"CLSID\" + clsid + @"\InprocServer32";
            const string dll = @"C:\Users\a\AppData\Roaming\x.dll";
            Assert.True(RegistryRemovalPolicy.ClsidRemovalAllowed(key, clsid, dll, dll, out _));
            Assert.False(RegistryRemovalPolicy.ClsidRemovalAllowed(key, clsid, @"C:\Windows\System32\shell32.dll", null, out _));
            Assert.False(RegistryRemovalPolicy.ClsidRemovalAllowed(@"CLSID\" + clsid, clsid, dll, dll, out _));
            Assert.False(RegistryRemovalPolicy.ClsidRemovalAllowed(key, "not-a-guid", dll, dll, out _));
        }

        //  Ancestor kill: a spoofed parent PID is not a target 

        [Fact]
        public void AncestorKill_RefusesSignedProtectedRootSecurityProductsAndUnresolved()
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            Func<string, bool> unsigned = _ => false;
            Assert.True(ChainTracer.IsAncestorKillRefused(10, 99, "app", Path.Combine(pf, "Vendor", "app.exe"), unsigned, out _));
            Assert.True(ChainTracer.IsAncestorKillRefused(10, 99, "app", @"C:\Users\a\Desktop\app.exe", _ => true, out _));
            Assert.True(ChainTracer.IsAncestorKillRefused(10, 99, "GVPN", Path.Combine(pf, "GVPN", "GVPN.exe"), unsigned, out _));
            Assert.True(ChainTracer.IsAncestorKillRefused(10, 99, "app", null, unsigned, out _));
            Assert.True(ChainTracer.IsAncestorKillRefused(10, 99, "app", @"C:\Users\a\x.exe", _ => throw new IOException(), out _));
        }

        [Fact]
        public void AncestorKill_StillContainsUnsignedUserWritableAncestorAndTheDetectedProcess()
        {
            Assert.False(ChainTracer.IsAncestorKillRefused(10, 99, "loader", @"C:\Users\a\AppData\Local\Temp\loader.exe", _ => false, out _));
            var winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "drop.exe");
            Assert.False(ChainTracer.IsAncestorKillRefused(10, 99, "drop", winTemp, _ => false, out _));
            // The detected process itself is never refused by the ancestor rule.
            Assert.False(ChainTracer.IsAncestorKillRefused(99, 99, "app", null, _ => true, out _));
        }

        [Theory]
        [InlineData("MSMPENG")]
        [InlineData("Explorer")]
        [InlineData("spoolsv")]
        public void CriticalProcessNames_AreCaseInsensitive(string name)
        {
            var sys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name + ".exe").ToUpperInvariant();
            Assert.False(HardeningModule.CanTerminateProcess(12345, name, sys));
        }

        //  Installer/redist noise: anchored, not substring 

        [Fact]
        public void SystemDirectoryCheck_RejectsLookalikeFolders()
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            Assert.True(ResponsePolicy.IsFileInRealSystemDirectory(Path.Combine(sys, "d3dx9_43.dll")));
            Assert.False(ResponsePolicy.IsFileInRealSystemDirectory(@"C:\Users\x\AppData\Local\Temp\System32\d3d\a.exe"));
            Assert.False(ResponsePolicy.IsFileInRealSystemDirectory(null));
        }

        [Fact]
        public void RedistNoise_DoesNotDemoteAFakeSystem32Drop()
        {
            var detection = new DetectionEvent
            {
                RuleName = "File: Unauthorized Write",
                ProcessName = "payload",
                ProcessId = 0,
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                Metadata = new Dictionary<string, string> { ["FilePath"] = @"C:\Users\x\AppData\Local\Temp\System32\d3d\a.exe" }
            };
            Assert.False(ResponsePolicy.IsBenignInstallerNoise(detection));
        }

        [Fact]
        public void RedistNoise_StillDemotesARealSystem32RedistWrite()
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var detection = new DetectionEvent
            {
                RuleName = "File: Unauthorized Write",
                ProcessName = "unknown",
                ProcessId = 0,
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                Metadata = new Dictionary<string, string> { ["FilePath"] = Path.Combine(sys, "d3dx9_43.dll") }
            };
            Assert.True(ResponsePolicy.IsBenignInstallerNoise(detection));
        }

        //  Microsoft signer: exact identity, not a substring 

        [Theory]
        [InlineData("Microsoft Corporation", true)]
        [InlineData("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", true)]
        [InlineData("Microsoft Windows Publisher", true)]
        [InlineData("Windows Optimizer Ltd", false)]
        [InlineData("Microsoft Tools LLC", false)]
        [InlineData("CN=Evil Ltd, O=Microsoft Corporation", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void MicrosoftPublisher_MatchesExactCommonNamesOnly(string? value, bool expected)
            => Assert.Equal(expected, MicrosoftPublisher.IsMicrosoftCommonName(value));

        [Fact]
        public void SignatureCacheFingerprint_ChangesWhenContentChangesEvenIfTimestampIsReset()
        {
            var path = Path.Combine(Path.GetTempPath(), "sentinel_fp_" + Guid.NewGuid().ToString("N") + ".bin");
            try
            {
                File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4 });
                var when = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                File.SetLastWriteTimeUtc(path, when);
                var before = SignerTrustService.FileFingerprint(path);
                File.WriteAllBytes(path, new byte[] { 9, 9, 9, 9 });
                File.SetLastWriteTimeUtc(path, when);
                Assert.NotEqual(before, SignerTrustService.FileFingerprint(path));
            }
            finally { File.Delete(path); }
        }

        //  File mutation link guards 

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);

        [Fact]
        public void FileObjectSafety_AcceptsPlainFileAndRefusesHardLinks()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel_links_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "a.bin");
                File.WriteAllBytes(file, new byte[] { 1 });
                Assert.Null(FileObjectSafety.RefusalReason(file));

                var link = Path.Combine(dir, "b.bin");
                Assert.True(CreateHardLink(link, file, IntPtr.Zero), "CreateHardLink failed");
                Assert.NotNull(FileObjectSafety.RefusalReason(file));
            }
            finally { Directory.Delete(dir, true); }
        }

        //  Network mutation targets 

        [Theory]
        [InlineData("224.0.0.251")]
        [InlineData("239.255.255.250")]
        [InlineData("169.254.10.20")]
        [InlineData("ff02::1")]
        [InlineData("fe80::1")]
        public void CastGuard_NeverBlocksMulticastOrLinkLocal(string ip)
            => Assert.True(CastDeviceGuard.IsProtectedInfrastructureAddress(IPAddress.Parse(ip)));

        [Fact]
        public void CastGuard_MutationGateDeniesWithoutPosture()
        {
            // The MitM suite is always-on by product design (v2.9.4); the gate the firewall block now
            // shares with the kill still fails closed when no posture/config is available.
            Assert.False(ProductPosture.AllowsMitmDefenseMutations(null));
            Assert.False(ProductPosture.AllowsMitmDefenseMutations(new SentinelConfig { MitmDefense = null! }));
        }

        //  ETW session enumeration layout 

        [Fact]
        public void EtwTraceLayout_MatchesNativeEventTraceProperties()
        {
            if (IntPtr.Size == 8)
            {
                Assert.Equal(112, EtwTraceLayout.LogFileNameOffsetField);
                Assert.Equal(116, EtwTraceLayout.LoggerNameOffsetField);
                Assert.Equal(120, EtwTraceLayout.StructSize);
            }
            else
            {
                Assert.Equal(108, EtwTraceLayout.LogFileNameOffsetField);
                Assert.Equal(112, EtwTraceLayout.LoggerNameOffsetField);
                Assert.Equal(116, EtwTraceLayout.StructSize);
            }
            Assert.True(EtwTraceLayout.BufferSize > EtwTraceLayout.StructSize);
        }

        [Fact]
        public void EtwTraceLayout_InitializesSizesAndNameOffsets()
        {
            var buffer = Marshal.AllocHGlobal(EtwTraceLayout.BufferSize);
            try
            {
                EtwTraceLayout.Initialize(buffer);
                Assert.Equal(EtwTraceLayout.BufferSize, Marshal.ReadInt32(buffer, 0));
                Assert.Equal(EtwTraceLayout.StructSize, Marshal.ReadInt32(buffer, EtwTraceLayout.LogFileNameOffsetField));
                Assert.True(Marshal.ReadInt32(buffer, EtwTraceLayout.LoggerNameOffsetField) >= EtwTraceLayout.StructSize);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        [Fact]
        public void PrologueComparison_DetectsRetPatchAndIgnoresIdenticalBytes()
        {
            var reference = new byte[] { 0x4C, 0x8B, 0xD1, 0xB8, 0x5E, 0x00, 0x00, 0x00 };
            Assert.False(EtwProviderTamperMonitor.LooksPatched(reference, (byte[])reference.Clone(), 8));
            Assert.True(EtwProviderTamperMonitor.LooksPatched(reference, new byte[] { 0xC3, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0 }, 8));
            Assert.True(EtwProviderTamperMonitor.LooksPatched(reference, new byte[] { 0x48, 0x33, 0xC0, 0xB8, 0x5E, 0, 0, 0 }, 8));
        }

        //  Mass-deletion false positive (dotnet test / build cleanup) 

        private static FusedTelemetryContext Delete(int pid, string path) => new FusedTelemetryContext
        {
            ProcessId = pid,
            ProcessName = "renamed-tool",
            TriggeringEvent = new FileActivityTelemetry { ProcessId = pid, ProcessName = "renamed-tool", FilePath = path, OperationType = "DELETE" }
        };

        [Fact]
        public void MassDeletion_StillFiresTier1OnUserDataDeletion()
        {
            var rule = new SlidingWindowMassDeletionRule();
            DetectionEvent? result = null;
            for (int i = 0; i < 100 && result == null; i++)
                result = rule.Evaluate(Delete(31001, $@"C:\Users\a\Documents\file{i}.docx"));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\sentinel_test_{0}\x.bin")]
        [InlineData(@"\Device\HarddiskVolume3\Users\a\AppData\Local\Temp\build_{0}.obj")]
        [InlineData(@"C:\Windows\Temp\setup_{0}.tmp")]
        public void MassDeletion_IgnoresTempScratchCleanup(string pattern)
        {
            var rule = new SlidingWindowMassDeletionRule();
            for (int i = 0; i < 400; i++)
                Assert.Null(rule.Evaluate(Delete(31002, string.Format(pattern, i))));
        }

        [Fact]
        public void MassDeletion_TempCleanupDoesNotMaskUserDataDeletion()
        {
            var rule = new SlidingWindowMassDeletionRule();
            DetectionEvent? result = null;
            for (int i = 0; i < 300; i++)
                rule.Evaluate(Delete(31003, $@"C:\Users\a\AppData\Local\Temp\t{i}.tmp"));
            for (int i = 0; i < 100 && result == null; i++)
                result = rule.Evaluate(Delete(31003, $@"D:\Photos\img{i}.jpg"));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        }

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\..\..\Documents\x.docx", false)]
        [InlineData(@"C:\Users\a\Documents\Temp\x.docx", false)]
        [InlineData(@"C:\Users\a\AppData\Local\TempData\x.docx", false)]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\x.docx", true)]
        public void TempScratchPath_IsExact(string path, bool expected)
            => Assert.Equal(expected, SlidingWindowMassDeletionRule.IsTempScratchPath(path));

        //  Self-protection and the Tier2 log-only contract 

        [Theory]
        [InlineData("\"C:\\Program Files\\Sentinel\\Sentinel.Service.exe\"", true)]
        [InlineData("\"C:\\Program Files\\Sentinel\\Sentinel.Service.exe\" --watchdog", true)]
        [InlineData("C:\\Users\\a\\evil.exe", false)]
        [InlineData("\"C:\\Program Files\\Sentinel\\evil.exe\"", false)]
        public void ServiceImagePath_MustNameTheRunningExecutable(string imagePath, bool expected)
            => Assert.Equal(expected, AntiTamperGuard.ServiceImagePathMatches(imagePath, @"C:\Program Files\Sentinel\Sentinel.Service.exe"));

        [Theory]
        [InlineData("Anti-Tamper: Sentinel Companion Binary Changed")]
        [InlineData("Anti-Tamper: Service ImagePath Changed")]
        [InlineData("Anti-Tamper: NtTraceEvent Modified in Critical Process")]
        [InlineData("SUBST Drive Creator Candidate (observe-only)")]
        [InlineData("SUBST Drive Persistence Candidate (observe-only)")]
        public void NewObservations_StayTier2LogOnlyWithActiveResponseOn(string rule)
        {
            Assert.True(new SentinelConfig().ActiveResponse);
            var detection = new DetectionEvent
            {
                RuleName = rule,
                ProcessName = "payload",
                ProcessId = 4242,
                Confidence = 0.99,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
            };
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
            Assert.False(detection.KillAuthorized);
        }

        [Fact]
        public void PipeServerIdentity_AcceptsSessionZeroServiceEvenWhenProcessCannotBeOpened()
        {
            // A standard user cannot open the SYSTEM service process: the image is unreadable.
            Assert.True(PipeServerIdentity.IsAcceptable(0, () => null));
            Assert.True(PipeServerIdentity.IsAcceptable(0, () => Path.Combine(AppContext.BaseDirectory, "Sentinel.Service.exe")));
            // A user-session squatter, or a session-0 server running a different image, is refused.
            Assert.False(PipeServerIdentity.IsAcceptable(1, () => null));
            Assert.False(PipeServerIdentity.IsAcceptable(0, () => @"C:\Users\a\AppData\Local\Temp\evil.exe"));
        }

        [Fact]
        public void PipeServerIdentity_RequiresTheInstalledServiceImage()
        {
            Assert.True(PipeServerIdentity.IsExpectedServiceImage(Path.Combine(AppContext.BaseDirectory, "Sentinel.Service.exe")));
            Assert.False(PipeServerIdentity.IsExpectedServiceImage(@"C:\Users\a\AppData\Local\Temp\Sentinel.Service.exe"));
        }
    }
}
