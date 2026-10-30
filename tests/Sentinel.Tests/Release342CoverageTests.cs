using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class Release342CoverageTests
    {
        [Theory]
        [InlineData("S-1-5-21-1-2-3-1001", true)]
        [InlineData("S-1-12-1-1-2-3-4", true)]
        [InlineData("S-1-5-18", false)]
        [InlineData("S-1-5-21-1-2-3-1001_Classes", false)]
        [InlineData("S-1-5-21-..\\software", false)]
        public void LoadedUserSurfacesExcludeSystemAndClassHives(string sid, bool expected)
            => Assert.Equal(expected, UserPersistenceObservation.IsInteractiveHive(sid));

        [Fact]
        public void UserPersistenceObservationCannotKillOrRemoveValues()
        {
            var observation = UserPersistenceObservation.Create("S-1-5-21-1-2-3-1001", "Policies Explorer Run", "Loader");
            ResponsePolicy.EnforceDispatchPolicy(observation);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Equal("Unknown", observation.Metadata!["Attribution"]);
        }

        [Fact]
        public void MtpStagingContextCannotAuthorizeProcessTermination()
        {
            var observation = MtpTransferGuard.CreateTransferObservation(4242, "arbitrary", "document.zip", "Phone");
            ResponsePolicy.EnforceDispatchPolicy(observation);
            Assert.Equal(DetectionTier.Tier2Indicator, observation.Tier);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Equal("Observed", observation.Metadata!["Action"]);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(observation));
        }

        [Theory]
        [InlineData(null, false)] [InlineData(true, false)] [InlineData(false, true)]
        public void OnlyKnownNoncriticalProcessesCanBeTerminated(bool? critical, bool allowed)
            => Assert.Equal(allowed, ProcessTerminationSafety.Allows(critical));

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\Policy.vpol", true)]
        [InlineData(@"C:\Users\a\AppData\Roaming\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\Policy.vpol", true)]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat", true)]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\11111111-1111-1111-1111-111111111111.vcrd", true)]
        [InlineData(@"C:\Users\a\Downloads\Policy.vpol", false)]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\fake\Policy.vpol", false)]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat.bak", false)]
        [InlineData(@"C:\Users\a\AppData\Local\Microsoft\Vault\..\Latest.dat", false)]
        public void VaultReadScopeRequiresActualCredentialStoreLayout(string path, bool expected)
            => Assert.Equal(expected, CredentialReadTracker.IsSensitivePath(path));

        private static byte[] Artifact(string text, bool wide)
        {
            var bytes = new byte[2048]; bytes[0] = 77; bytes[1] = 90;
            Array.Copy(BitConverter.GetBytes(64), 0, bytes, 0x3c, 4);
            Array.Copy(BitConverter.GetBytes(0x4550), 0, bytes, 64, 4);
            var marker = (wide ? Encoding.Unicode : Encoding.UTF8).GetBytes(text);
            Array.Copy(marker, 0, bytes, 128, marker.Length); return bytes;
        }
        [Theory]
        [InlineData(false)] [InlineData(true)]
        public void ReportedMarkerPairInPeIsObserveOnlyAndStreamPositionIsPreserved(bool wide)
        {
            var bytes = Artifact("|Ghost| WhyYouReverseMe..ImInnocent..LoveYouu..", wide);
            using var stream = new MemoryStream(bytes); stream.Position = 23;
            Assert.True(RatArtifactInspector.Inspect(stream)); Assert.Equal(23, stream.Position);
            var observation = RatArtifactInspector.Observation(@"C:\arbitrary-name.exe");
            ResponsePolicy.EnforceDispatchPolicy(observation);
            Assert.Equal(DetectionTier.Tier2Indicator, observation.Tier);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(observation));
        }
        [Theory]
        [InlineData("|Ghost|")] [InlineData("WhyYouReverseMe..ImInnocent..LoveYouu..")]
        public void SingleMarkerDoesNotMatch(string marker) => Assert.False(RatArtifactInspector.Matches(Artifact(marker, false)));
        [Fact]
        public void DocumentationMalformedPeAndOversizeInputDoNotMatch()
        {
            Assert.False(RatArtifactInspector.Matches(Encoding.UTF8.GetBytes("|Ghost| WhyYouReverseMe..ImInnocent..LoveYouu..")));
            var malformed = Artifact("|Ghost| WhyYouReverseMe..ImInnocent..LoveYouu..", false); malformed[64] = 0;
            Assert.False(RatArtifactInspector.Matches(malformed));
            Assert.False(RatArtifactInspector.Matches(new byte[2 * 1024 * 1024 + 1]));
        }
        [Fact]
        public void FileReputationAnalysisSurfacesReportedArtifactEvidence()
        {
            string file = Path.Combine(Path.GetTempPath(), "Sentinel342_" + Guid.NewGuid().ToString("N") + ".exe");
            try
            {
                File.WriteAllBytes(file, Artifact("|Ghost| WhyYouReverseMe..ImInnocent..LoveYouu..", false));
                var engine = new FileReputationEngine(null!, null!, null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<FileReputationEngine>.Instance);
                var method = typeof(FileReputationEngine).GetMethod("AnalyzeStaticProperties", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                var result = (StaticAnalysisResult)method.Invoke(engine, new object[] { file, new FileInfo(file).Length })!;
                Assert.True(result.HasReportedRatMarkers);
            }
            finally { if (File.Exists(file)) File.Delete(file); }
        }

        [Fact]
        public void Utf16MarkersMayHaveIndependentByteAlignment()
        {
            var bytes = Artifact("", false);
            Array.Copy(Encoding.Unicode.GetBytes("|Ghost|"), 0, bytes, 129, 14);
            var second = Encoding.Unicode.GetBytes("WhyYouReverseMe..ImInnocent..LoveYouu..");
            Array.Copy(second, 0, bytes, 300, second.Length);
            Assert.True(RatArtifactInspector.Matches(bytes));
        }
        [Fact]
        public void OldRuleIndexDoesNotSkipFilesAndCurrentIndexRoundTrips()
        {
            string dir = Path.Combine(Path.GetTempPath(), "Sentinel342Index_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string file = Path.Combine(dir, "fixture.exe"); File.WriteAllText(file, "inert");
                var info = new FileInfo(file);
                File.WriteAllText(Path.Combine(dir, "scan_index.dat"), info.Length + "|" + info.LastWriteTimeUtc.Ticks + "|" + file);
                using (var index = new FileScanIndex(dir)) { Assert.False(index.IsUnchangedSinceScan(file)); index.MarkScanned(file); index.TryFlush(true); }
                using (var index = new FileScanIndex(dir)) Assert.True(index.IsUnchangedSinceScan(file));
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void StableFilesDoNotPayASettlingDelayAndDirectoryLinksAreNotFollowed()
        {
            var now = DateTime.UtcNow;
            Assert.False(FileVerdictScanner.NeedsStabilization(now.AddDays(-1), now));
            Assert.True(FileVerdictScanner.NeedsStabilization(now, now));
            Assert.True(FileVerdictScanner.NeedsStabilization(now.AddDays(1), now));
            Assert.False(FileVerdictScanner.ShouldTraverseDirectory(FileAttributes.Directory | FileAttributes.ReparsePoint));
            Assert.True(FileVerdictScanner.ShouldTraverseDirectory(FileAttributes.Directory));
        }
        [Fact]
        public void EtwPayloadIsCopiedBeforeNativeBufferReuseAndQueueDoesNotBlockProducer()
        {
            using var gate = new ManualResetEventSlim(); using var entered = new ManualResetEventSlim();
            using var done = new CountdownEvent(2); var observed = new ConcurrentQueue<byte>();
            using var dispatcher = new BoundedEtwDispatcher(_ => { }, 2, 16);
            var native = Marshal.AllocHGlobal(8);
            try
            {
                Marshal.WriteByte(native, 42);
                var raw = new EtwRawEvent { UserData = native, UserDataLength = 8 };
                Assert.True(dispatcher.TryDispatch(raw, evt => { entered.Set(); gate.Wait(TimeSpan.FromSeconds(5)); observed.Enqueue(Marshal.ReadByte(evt.UserData)); done.Signal(); }));
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                Marshal.WriteByte(native, 43);
                Assert.True(dispatcher.TryDispatch(raw, evt => { observed.Enqueue(Marshal.ReadByte(evt.UserData)); done.Signal(); }));
                Assert.False(dispatcher.TryDispatch(raw, _ => throw new Exception("Must not enqueue beyond capacity")));
                Marshal.FreeHGlobal(native); native = IntPtr.Zero; gate.Set();
                Assert.True(done.Wait(TimeSpan.FromSeconds(5)));
                Assert.Equal(new byte[] { 42, 43 }, observed.ToArray());
            }
            finally { gate.Set(); if (native != IntPtr.Zero) Marshal.FreeHGlobal(native); }
        }
        [Fact]
        public void AStuckHandlerCannotBeReportedHealthyJustBecauseItsThreadIsAlive()
        {
            var health = new EtwHealthSnapshot { QuerySucceeded = true, ConsumerAlive = true, DispatchHandlerBusyMs = 6000 };
            for (int i = 0; i < 10; i++) health.ProviderStatus[i.ToString()] = 0;
            Assert.Contains("worker liveness does not establish progress", EtwCollectionPolicy.Degradation(health, false)!);
        }

        [Fact]
        public void FailedEtwHandlerIsReportedAndDoesNotStopLaterEvents()
        {
            using var failed = new ManualResetEventSlim(); using var completed = new ManualResetEventSlim();
            using var dispatcher = new BoundedEtwDispatcher(_ => failed.Set());
            Assert.True(dispatcher.TryDispatch(new EtwRawEvent(), _ => throw new InvalidOperationException("Inert fixture")));
            Assert.True(failed.Wait(TimeSpan.FromSeconds(5)));
            Assert.True(dispatcher.TryDispatch(new EtwRawEvent(), _ => completed.Set()));
            Assert.True(completed.Wait(TimeSpan.FromSeconds(5)));
            Assert.True(dispatcher.IsAlive);
        }

        [Fact]
        public void EtwByteBudgetRejectsBeforeCopyAndReleasesReservations()
        {
            using var dispatcher = new BoundedEtwDispatcher(_ => { }, 2, 1);
            Assert.False(dispatcher.TryDispatch(new EtwRawEvent { UserData = new IntPtr(1), UserDataLength = 8 }, _ => { }));
            Assert.Equal(0, dispatcher.QueuedBytes);
            Assert.Equal(0, dispatcher.QueueDepth);
        }
    }
}
