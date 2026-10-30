using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class Release346RegressionTests
    {
        [Fact]
        public void RegistryFloodIsCoalescedBeforePayloadQueueWithoutSuppressingOtherPidsOrRecovery()
        {
            var admission = new RegistryHintAdmission();
            long now = DateTime.UtcNow.ToFileTimeUtc();
            Assert.True(admission.Admit(123, now));
            for (int i = 0; i < 10000; i++) Assert.False(admission.Admit(123, now + i));
            Assert.True(admission.Admit(456, now));
            Assert.True(admission.Admit(123, now + TimeSpan.TicksPerSecond));
            Assert.True(admission.Admit(123, now - 1));
        }
        [Fact]
        public void UnknownExternalPluginIsReviewOnlyWithoutBecomingTrustedAndPlantsStayActionable()
        {
            var external = ModuleIdentity.Evaluate(@"D:\OSHost\taskhostw.exe", @"D:\InstalledTools\overlay.dll", _ => false);
            Assert.False(external.Allowed);
            Assert.True(DllUnloadEngine.IsReviewOnlyIdentity(external));
            var plant = ModuleIdentity.Evaluate(@"D:\InstalledTools\host.exe", @"C:\Windows\Temp\version.dll", _ => false);
            Assert.False(plant.Allowed);
            Assert.False(DllUnloadEngine.IsReviewOnlyIdentity(plant));
            var drop = ModuleIdentity.Evaluate(@"D:\OSHost\taskhostw.exe", @"C:\Users\Alice\AppData\Local\Temp\overlay.dll", _ => false);
            Assert.False(DllUnloadEngine.IsReviewOnlyIdentity(drop));
        }
        private sealed class Handler : HttpMessageHandler
        {
            internal int FeedRequests;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                if (request.RequestUri!.AbsoluteUri == OnlineHashReputation.MalwareFeed) FeedRequests++;
                Assert.DoesNotContain("/export/", request.RequestUri.AbsoluteUri);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Gone) { Content = new StringContent("retired") });
            }
        }
        [Theory]
        [InlineData(null)]
        [InlineData("bad\r\nkey")]
        [InlineData("fixture-key")]
        public async Task MissingCredentialsAndGoneResponsesCannotCreateMalwareOrSafeVerdicts(string? key)
        {
            var handler = new Handler();
            using var client = new HttpClient(handler);
            using var online = new OnlineHashReputation(client, NullLogger<OnlineHashReputation>.Instance, malwareBazaarApiKey: key);
            Assert.Equal(HashVerdict.Unknown, await online.QueryAsync(new string('a', 64), CancellationToken.None));
            Assert.Equal(key == "fixture-key" ? 1 : 0, handler.FeedRequests);
        }
        [Theory]
        [InlineData("{\"query_status\":\"no_results\",\"data\":[]}")]
        [InlineData("{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"invalid\"}]}")]
        [InlineData("{\"query_status\":\"ok\",\"data\":[]}")]
        public void UnconfirmedProviderResponsesNeverBecomeMalwareEvidence(string body)
            => Assert.Null(OnlineHashReputation.ParseMalwareFeed(body));
    }
}
