using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ProtectionEvidenceTests
    {
        [Theory]
        [InlineData(SignalType.Ransomware)]
        [InlineData(SignalType.LsassAccess)]
        [InlineData(SignalType.ReverseShell)]
        public void ImmediateTier1IsReportedWithoutWaitingForChain(SignalType type)
        {
            var detection = new DetectionEvent
            {
                RuleName = "Immediate terminal behavior", SignalType = type,
                Tier = DetectionTier.Tier1Behavioral, Confidence = 0.95,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };
            var config = new SentinelConfig { SilentObserve = true };
            Assert.True(ResponsePolicy.ShouldNotifyUser(detection, config));
            Assert.True(ResponsePolicy.ShouldAutoReportIncident(detection, config));
            Assert.Empty(detection.Metadata);
        }

        [Theory]
        [InlineData(DetectionTier.Tier2Indicator, 0.99, ResponseAction.KillProcessTree, false)]
        [InlineData(DetectionTier.Tier1Behavioral, 0.50, ResponseAction.KillProcessTree, false)]
        [InlineData(DetectionTier.Tier1Behavioral, 0.95, ResponseAction.LogOnly, false)]
        [InlineData(DetectionTier.Tier1Behavioral, 0.95, ResponseAction.NetworkIsolate, true)]
        public void ReportingRequiresTerminalAuthority(DetectionTier tier, double confidence,
            ResponseAction action, bool expected)
        {
            var detection = new DetectionEvent
            {
                RuleName = "Terminal evidence", SignalType = SignalType.NetworkC2,
                Tier = tier, Confidence = confidence, AuthorizedResponse = action
            };
            Assert.Equal(expected, ResponsePolicy.ShouldAutoReportIncident(detection,
                new SentinelConfig { SilentObserve = true }));
        }

        [Fact]
        public void WeakIndicatorDoesNotAcquireIncidentOrKillAuthority()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Reported marker", SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier1Behavioral, Confidence = 0.99,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" }
            };
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
            Assert.False(ResponsePolicy.ShouldAutoReportIncident(detection, new SentinelConfig()));
        }

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Local\Programs\Kiro\kiro.exe")]
        [InlineData(@"C:\Users\a\AppData\Local\kiro\kiro.exe")]
        [InlineData(@"C:\Users\a\JetBrains\kiro.exe")]
        [InlineData(@"C:\Users\a\fake\Program Files\Kiro\kiro.exe")]
        [InlineData(@"C:\Program Files\Kiro\kiro.exe")]
        public void IdeFolderCannotSubstituteForSignature(string path)
        {
            Assert.False(ChainTracer.IsLegitimateIdeHost(path, "kiro.exe", _ => false));
            Assert.True(ChainTracer.IsLegitimateIdeHost(path, "kiro.exe", _ => true));
            Assert.False(ChainTracer.IsLegitimateIdeHost(path, "kiro.exe",
                _ => throw new InvalidOperationException("Identity unavailable")));
        }

        [Theory]
        [InlineData(@"C:\Users\a\Downloads\kiro.exe")]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\kiro.exe")]
        public void StagingLocationRemainsUntrustedEvenWhenSigned(string path)
            => Assert.False(ChainTracer.IsLegitimateIdeHost(path, "kiro.exe", _ => true));

        [Theory]
        [InlineData("kiro.exe")]
        [InlineData("chrome.exe")]
        [InlineData("cursor.exe")]
        public async Task SignedHostFirstSignalStillEvaluatesAvailableCorrelation(string name)
        {
            var engine = new BehavioralCorrelationEngine(_ => @"C:\signed-host.exe",
                _ => 1, _ => true);
            var emitted = new List<DetectionEvent>();
            engine.Initialize(d => { emitted.Add(d); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "WPAD Proxy Changed", ProcessId = 0, Timestamp = DateTime.UtcNow,
                Tier = DetectionTier.Tier2Indicator
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beacon", ProcessId = 4242, ProcessName = name,
                Timestamp = DateTime.UtcNow, SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier2Indicator
            });
            Assert.Contains(emitted, d => d.RuleName == "WPAD Proxy Hijack Chain");
        }

        [Theory]
        [InlineData("evidence_pack_created")]
        [InlineData("incident_reporting_failed")]
        [InlineData("evidence_pack_skipped")]
        public async Task ReportingOutcomesHaveDurableLedgerRecords(string type)
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel_reporting_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var logger = new JsonlEventLogger(Path.Combine(directory, "events.jsonl"));
            try
            {
                await logger.LogEventAsync(type, new { RuleName = "Terminal evidence", Reason = "Test" });
                Assert.False(logger.AuditIntegrityDegraded);
                var checkpoint = logger.GetAuditCheckpoint();
                Assert.NotNull(checkpoint);
                Assert.Equal(1, checkpoint!.Sequence);
                using var reader = File.OpenText(Assert.Single(Directory.GetFiles(directory, "audit-chain-*.jsonl")));
                Assert.Equal(1, EvidenceLedger.Verify(reader).Sequence);
            }
            finally
            {
                await logger.DisposeAsync();
                Directory.Delete(directory, true);
            }
        }
    }
}
