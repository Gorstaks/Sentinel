using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class Release343RegressionTests
    {
        [Theory]
        [InlineData("Reverse Shell Detected")]
        [InlineData("IdsCommandLineRule")]
        [InlineData("DangerousBrowserFlagRule")]
        public void EvidenceContainingSystemPathsIsNeverAnInstallerPath(string rule)
        {
            var observation = new DetectionEvent
            {
                RuleName = rule, ProcessId = 56789, ProcessName = "arbitrary",
                Evidence = "Observed: \"C:\\Windows\\System32\\cmd.exe\"\nargument=d3dcompiler.exe | payload",
                Tier = DetectionTier.Tier2Indicator, Confidence = 0.5,
                AuthorizedResponse = ResponseAction.LogOnly
            };
            Assert.False(ResponsePolicy.IsBenignInstallerNoise(observation));
            ResponsePolicy.ApplyTierLaw(observation);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.NotEqual("BenignInstallerNoise", observation.Metadata!["TierLaw"]);
        }

        [Theory]
        [InlineData("C:\\Windows\\System32\\vcredist.exe\" | payload")]
        [InlineData("C:\\Windows\\System32\\vcredist.exe\nargument")]
        [InlineData("C:\\Windows\\System32\\vcredist.exe\0")]
        [InlineData("C:\\Windows\\System32\\vc<redist.exe")]
        [InlineData("C:\\Windows\\System32\\vcredist.exe:stream")]
        public void MalformedMetadataCannotCrashOrGrantInstallerExemption(string path)
        {
            Assert.False(InstallerHeuristics.IsDirectXOrRuntimeRedist("arbitrary", path));
            Assert.False(InstallerHeuristics.LooksLikeInstallerName(null, path));
            Assert.False(InstallerHeuristics.IsInstallerExtractor(null, path));
            Assert.False(InstallerHeuristics.IsPortableDownloadOrArchiveTool(null, path));
            var observation = new DetectionEvent
            {
                RuleName = "Reverse Shell Detected", SignalType = SignalType.ReverseShell,
                ProcessId = 56789, ProcessName = "arbitrary", Confidence = 0.95,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["ImagePath"] = path, ["FilePath"] = path }
            };
            ResponsePolicy.ApplyTierLaw(observation);
            Assert.Equal(DetectionTier.Tier1Behavioral, observation.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, observation.AuthorizedResponse);
        }

        [Fact]
        public void ValidRedistMetadataStillWorksWithoutEvidenceParsing()
            => Assert.True(InstallerHeuristics.IsDirectXOrRuntimeRedist("dxsetup", @"C:\Temp\dxsetup.exe"));

        [Fact]
        public void TokenCapabilityCannotBecomeCredentialDumpOrCompositeAuthority()
        {
            var observation = new DetectionEvent
            {
                RuleName = "Suspicious Token Privileges Detected", ProcessId = 56789,
                SignalType = SignalType.CredentialTheft, Family = TerminalFamily.CredentialDump,
                Confidence = 1, Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Metadata = new Dictionary<string, string> { [ResponsePolicy.ChainConfirmedKey] = "true" }
            };
            ResponsePolicy.EnforceDispatchPolicy(observation);
            Assert.Equal(DetectionTier.Tier2Indicator, observation.Tier);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(observation));
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(observation));
        }

        [Fact]
        public void NativeAndManagedFiltersAgreeForEveryRegisteredProvider()
        {
            var providers = typeof(UnifiedEtwSession.Providers).GetFields()
                .Select(f => (Guid)f.GetValue(null)!);
            foreach (Guid provider in providers)
            {
                var ids = EtwCollectionPolicy.EventIds(provider);
                for (int id = 0; id <= ushort.MaxValue; id++)
                    Assert.Equal(ids.Length == 0 || ids.Contains((ushort)id), EtwCollectionPolicy.Consumes(provider, (ushort)id));
            }
            Assert.True(EtwCollectionPolicy.Consumes(Guid.NewGuid(), 65535));
        }

        [Fact]
        public void FullFileLaneCannotDropOrBlockProcessImageOrDnsEvents()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            using var completed = new CountdownEvent(2);
            using var dispatcher = new PartitionedEtwDispatcher(_ => { }, laneCapacity: 1, laneByteLimit: 1);
            try
            {
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelFile },
                    _ => { entered.Set(); release.Wait(TimeSpan.FromSeconds(10)); }));
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                Assert.False(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelFile }, _ => { }));
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelProcess }, _ => completed.Signal()));
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.DnsClient }, _ => completed.Signal()));
                Assert.True(completed.Wait(TimeSpan.FromSeconds(5)));
                Assert.Equal(1, dispatcher.DropSnapshot()["File"]);
                Assert.Equal(0, dispatcher.DropSnapshot()["ProcessImage"]);
            }
            finally { release.Set(); }
        }

        [Fact]
        public void FileLaneRetainsNameReadOrder()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            using var completed = new CountdownEvent(2); var order = new List<ushort>();
            using var dispatcher = new PartitionedEtwDispatcher(_ => { }, laneCapacity: 2, laneByteLimit: 2);
            try
            {
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelFile, EventId = 10 },
                    evt => { entered.Set(); release.Wait(TimeSpan.FromSeconds(10)); order.Add(evt.EventId); completed.Signal(); }));
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelFile, EventId = 15 },
                    evt => { order.Add(evt.EventId); completed.Signal(); }));
                release.Set(); Assert.True(completed.Wait(TimeSpan.FromSeconds(5)));
                Assert.Equal(new ushort[] { 10, 15 }, order);
            }
            finally { release.Set(); }
        }

        [Fact]
        public void LosingOneReasonDoesNotFloodAlertsWhileAnotherGapRemains()
        {
            var alerts = new EtwCoverageAlertState(); var now = DateTimeOffset.UtcNow;
            Assert.True(alerts.Observe("provider denied; loss", now));
            Assert.False(alerts.Observe("provider denied", now.AddSeconds(3)));
            Assert.False(alerts.Observe("provider denied", now.AddSeconds(6)));
            for (int i = 3; i < 60; i++)
                Assert.False(alerts.Observe(i % 2 == 0 ? "provider denied" : "provider denied; loss", now.AddSeconds(i * 3)));
            Assert.True(alerts.IsDegraded);
            Assert.True(alerts.Observe("provider denied", now.AddMinutes(5)));
        }

        [Fact]
        public void RegistryHintStormResolvesOncePerPidSecondWithoutSuppressingOtherPids()
        {
            var dispatcher = new EtwEventDispatcher(null!, null!, null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<EtwEventDispatcher>.Instance);
            var now = DateTime.UtcNow;
            Assert.True(dispatcher.AdmitRegistryHint(100, now));
            for (int i = 0; i < 10000; i++) Assert.False(dispatcher.AdmitRegistryHint(100, now.AddMilliseconds(500)));
            Assert.True(dispatcher.AdmitRegistryHint(101, now));
            Assert.True(dispatcher.AdmitRegistryHint(100, now.AddSeconds(1)));
            Assert.True(dispatcher.AdmitRegistryHint(100, now.AddSeconds(-1)));
        }

        [Fact]
        public void PartialScanRetainsPathErrorAndRetryDetails()
        {
            var progress = new SensorProgress(TimeSpan.FromMinutes(1));
            string detail = FileVerdictScanner.DescribeWalkFailure(@"C:\locked", new UnauthorizedAccessException());
            FileVerdictScanner.UpdateCoverageProgress(progress, true, 30, detail + "; retry scheduled");
            Assert.Contains(@"C:\locked", progress.Snapshot().Error!);
            Assert.Contains("UnauthorizedAccessException", progress.Snapshot().Error!);
            Assert.Contains("retry scheduled", progress.Snapshot().Error!);
        }

        [Theory]
        [InlineData("Sentinel-Offline-Sentinel.Service.exe-IN", true)]
        [InlineData("Sentinel-Offline-Sentinel.Agent.exe-OUT", true)]
        [InlineData("Sentinel-Offline-other.exe-IN", false)]
        [InlineData("Sentinel-Offline-Sentinel.Service.exe-IN-extra", false)]
        public void DuplicateCleanupOwnsOnlySixExactNames(string name, bool owned)
            => Assert.Equal(owned, WindowsSelfNetworkFirewall.IsOwnedName(name));
    }
}
