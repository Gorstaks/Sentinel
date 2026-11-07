using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// "Network Tamper: Local MitM Chain" after the VPN shield moved out of Sentinel (GVPN is a
    /// separate project). The composite still needs >= 2 independent tamper vectors and is still
    /// a confirmed Tier1 report, but it is LogOnly end to end: chain confirmation and composite
    /// promotion must never turn this PID-0 report into a process kill.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class NetworkTamperCompositeTests
    {
        public NetworkTamperCompositeTests() => ResponsePolicy.ResetForTests();

        private static DetectionEvent Tamper(string rule) => new()
        {
            RuleName = rule,
            ProcessId = 0,
            ProcessName = "SYSTEM",
            Confidence = 0.9,
            Tier = DetectionTier.Tier1Behavioral,
            SignalType = SignalType.SecurityEvasion,
            Timestamp = DateTime.UtcNow,
        };

        private static DetectionEvent TamperFromObservation(string rule, string observationKey)
        {
            var d = Tamper(rule);
            d.Metadata[BehavioralCorrelationEngine.ObservationKeyMeta] = observationKey;
            return d;
        }

        private static async Task<DetectionEvent?> Correlate(params DetectionEvent[] signals)
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? emitted = null;
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });
            foreach (var s in signals)
                await engine.RegisterSignalAsync(s);
            return emitted;
        }

        // ---- Composite firing rules (unchanged by the shield removal) ----

        [Fact]
        public async Task TwoDistinctTamperVectors_FireReportOnlyComposite()
        {
            var emitted = await Correlate(
                Tamper("ARP Spoof: Gateway MAC Changed"),
                Tamper("Network: Unauthorized DNS Change"));

            Assert.NotNull(emitted);
            Assert.Equal("Network Tamper: Local MitM Chain", emitted!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, emitted.Tier);
            Assert.Equal(ResponseAction.LogOnly, emitted.AuthorizedResponse);
            Assert.False(emitted.KillAuthorized);
            Assert.Equal(ResponsePolicy.NetworkTamperOutcome, emitted.Metadata[ResponsePolicy.TerminalOutcomeKey]);
            Assert.True(ResponsePolicy.IsReportOnlyNetworkTamper(emitted));
        }

        [Fact]
        public async Task SingleTamperVector_DoesNotFireComposite()
        {
            Assert.Null(await Correlate(
                Tamper("ARP Spoof: Gateway MAC Changed"),
                Tamper("ARP Spoof: Multiple IPs Sharing MAC")));
        }

        [Fact]
        public async Task WpadPlusDns_FireComposite()
        {
            var emitted = await Correlate(
                Tamper("WPAD Auto-Proxy PAC Changed"),
                Tamper("Network: Unauthorized DNS Change"));
            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
        }

        [Fact]
        public async Task WifiDeauthPlusEvilTwin_FireComposite()
        {
            var emitted = await Correlate(
                TamperFromObservation("WiFi Security: Deauthentication Flood Detected", "wifi-deauth:HomeNet"),
                TamperFromObservation("WiFi Security: BSSID Changed (Possible Evil Twin)", "wifi-bssid:00-de-ad-be-ef-00"));
            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
        }

        [Fact]
        public async Task WpadAlone_DoesNotFireComposite()
        {
            Assert.Null(await Correlate(
                Tamper("WPAD Auto-Proxy PAC Configured"),
                Tamper("WPAD Auto-Detect With Remote PAC")));
        }

        [Fact]
        public async Task TwoVectorsFromSameObservation_DoNotFireComposite()
        {
            Assert.Null(await Correlate(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:192.168.1.1"),
                TamperFromObservation("Route Injected: Default Gateway", "gw-mac:192.168.1.1")));
        }

        [Fact]
        public async Task MixedKeyedAndLegacySignals_RemainIndependent()
        {
            var emitted = await Correlate(
                TamperFromObservation("ARP Spoof: Gateway MAC Changed", "gw-mac:aa-bb-cc-dd-ee-ff"),
                Tamper("Network Bridge Detected"));
            Assert.NotNull(emitted);
            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
        }

        // ---- Report-only survives every promotion path ----

        [Fact]
        public async Task ApplyTierLaw_KeepsCompositeLogOnly()
        {
            var emitted = await Correlate(
                Tamper("ARP Spoof: Gateway MAC Changed"),
                Tamper("Network: Unauthorized DNS Change"));

            ResponsePolicy.ApplyTierLaw(emitted!);

            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
            Assert.False(emitted.KillAuthorized);
        }

        [Fact]
        public async Task PromoteChainConfirmedFields_KeepsCompositeLogOnly()
        {
            var emitted = await Correlate(
                Tamper("ARP Spoof: Gateway MAC Changed"),
                Tamper("Network: Unauthorized DNS Change"));

            ResponsePolicy.PromoteChainConfirmedFields(emitted!);

            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
            Assert.Equal("true", emitted.Metadata[ResponsePolicy.ChainConfirmedKey]);
        }

        [Fact]
        public void NetworkTamperTag_CannotShedResponse_OnProcessDetections()
        {
            var d = Tamper("Some Process Rule");
            d.ProcessId = 4321;
            d.Metadata[ResponsePolicy.TerminalOutcomeKey] = ResponsePolicy.NetworkTamperOutcome;
            Assert.False(ResponsePolicy.IsReportOnlyNetworkTamper(d));
        }

        [Fact]
        public void RetiredVpnShieldAction_IsReportOnly()
        {
#pragma warning disable CS0618 // exercising the retired value on purpose
            var d = new DetectionEvent { AuthorizedResponse = ResponseAction.VpnShieldUp, ProcessId = 1234 };
            Assert.True(ResponsePolicy.IsReportOnlyNetworkTamper(d));
            Assert.False(d.KillAuthorized);
            // Stable serialized numbering: the retired slot keeps every later action's value.
            Assert.Equal(3, (int)ResponseAction.VpnShieldUp);
#pragma warning restore CS0618
            Assert.Equal(4, (int)ResponseAction.KillProcess);
        }

        [Fact]
        public async Task ResponseEngine_ReportsComposite_WithoutDestructiveAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_nettamper_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var engine = new AdvancedResponseEngine(config, new SentinelMetrics(), logger, new QuarantineManager(tempDir));

                var composite = await Correlate(
                    Tamper("ARP Spoof: Gateway MAC Changed"),
                    Tamper("Network: Unauthorized DNS Change"));
                await engine.HandleAsync(composite!);
                await logger.DisposeAsync();

                var lines = File.ReadAllLines(logPath);
                Assert.DoesNotContain(lines, l =>
                    l.Contains("\"ActionTaken\":\"KILL") || l.Contains("QUARANTINE") ||
                    l.Contains("NETWORK_ISOLATE") || l.Contains("VPN_SHIELD"));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
    }

    /// <summary>Interface classification used by the network monitors when a VPN client is present.</summary>
    public class VpnTunnelClassifierTests
    {
        [Theory]
        [InlineData(VpnTunnelClassifier.IfTypePpp, "GVPN-L2TP", true)]                         // RAS dial-up
        [InlineData(VpnTunnelClassifier.IfTypePropVirtual, "WireGuard Tunnel", true)]
        [InlineData(VpnTunnelClassifier.IfTypeTunnel, "Some IPsec Tunnel", true)]
        [InlineData(VpnTunnelClassifier.IfTypeEthernet, "TAP-Windows Adapter V9", true)]       // OpenVPN / GVPN TAP
        [InlineData(VpnTunnelClassifier.IfTypeEthernet, "WAN Miniport (IKEv2)", true)]
        [InlineData(VpnTunnelClassifier.IfTypeEthernet, "Intel(R) Ethernet Connection I219-V", false)]
        [InlineData(VpnTunnelClassifier.IfTypeEthernet, "Realtek PCIe GbE Family Controller", false)]
        [InlineData(VpnTunnelClassifier.IfTypeTunnel, "Teredo Tunneling Pseudo-Interface", false)] // IPv6 transition
        [InlineData(VpnTunnelClassifier.IfTypeTunnel, "Microsoft ISATAP Adapter", false)]
        [InlineData(VpnTunnelClassifier.IfTypeIeee80211, "Contoso VPN-ready Wi-Fi 6", false)]   // Wi-Fi never by text
        [InlineData(VpnTunnelClassifier.IfTypeEthernet, null, false)]
        public void IsTunnel_UsesTypeAndDriverDescription(int ifType, string? description, bool expected)
        {
            Assert.Equal(expected, VpnTunnelClassifier.IsTunnel(ifType, description));
        }

        [Theory]
        [InlineData(0x00000000u, 0x00000000u, true)]   // 0.0.0.0/0
        [InlineData(0x00000000u, 0x00000080u, true)]   // 0.0.0.0/1
        [InlineData(0x00000080u, 0x00000080u, true)]   // 128.0.0.0/1
        [InlineData(0x0000000Au, 0x000000FFu, false)]  // 10.0.0.0/8
        [InlineData(0x0101A8C0u, 0xFFFFFFFFu, false)]  // 192.168.1.1/32
        public void IsDefaultClassRoute_RecognisesFullAndSplitDefaults(uint destination, uint mask, bool expected)
        {
            Assert.Equal(expected, VpnTunnelClassifier.IsDefaultClassRoute(destination, mask));
        }

        [Fact]
        public void MarkTunnel_IsHonouredOnlyForHostWideEvents()
        {
            var d = new DetectionEvent { ProcessId = 0 };
            VpnTunnelClassifier.MarkTunnel(d.Metadata);
            Assert.True(VpnTunnelClassifier.IsTunnelObservation(d));
            d.ProcessId = 9999;
            Assert.False(VpnTunnelClassifier.IsTunnelObservation(d));
            Assert.False(VpnTunnelClassifier.IsTunnelObservation(null));
        }
    }

    /// <summary>Verdict logic of the observe-only VPN tunnel state / bypass monitor.</summary>
    public class VpnTunnelLeakMonitorTests
    {
        private static TunnelSnapshot Up(Action<TunnelSnapshot>? configure = null)
        {
            var s = new TunnelSnapshot { PublicIpv4ViaTunnel = true };
            s.Tunnels.Add("TAP-Windows Adapter V9");
            configure?.Invoke(s);
            return s;
        }

        [Fact]
        public void NoTunnel_NoFindings()
        {
            Assert.Empty(VpnTunnelLeakMonitor.Evaluate(false, new TunnelSnapshot()));
        }

        [Fact]
        public void TunnelComingUp_ReportsConnected_Only()
        {
            Assert.Equal(new[] { TunnelFinding.Connected }, VpnTunnelLeakMonitor.Evaluate(false, Up()).ToArray());
        }

        [Fact]
        public void HealthyFullTunnel_NoFindingsAfterConnect()
        {
            Assert.Empty(VpnTunnelLeakMonitor.Evaluate(true, Up()));
        }

        [Fact]
        public void TunnelGoingDown_ReportsDisconnected()
        {
            Assert.Equal(new[] { TunnelFinding.Disconnected },
                VpnTunnelLeakMonitor.Evaluate(true, new TunnelSnapshot()).ToArray());
        }

        [Fact]
        public void PublicIpv4OnPhysicalAdapter_ReportsIpv4Bypass()
        {
            var findings = VpnTunnelLeakMonitor.Evaluate(true, Up(s => s.PublicIpv4ViaTunnel = false));
            Assert.Contains(TunnelFinding.Ipv4Bypass, findings);
        }

        [Fact]
        public void UnknownRoute_IsNotABypassVerdict()
        {
            Assert.Empty(VpnTunnelLeakMonitor.Evaluate(true, Up(s => s.PublicIpv4ViaTunnel = null)));
        }

        [Fact]
        public void PhysicalIpv6_WithIpv4OnlyTunnel_ReportsIpv6Bypass()
        {
            var findings = VpnTunnelLeakMonitor.Evaluate(true, Up(s => s.PhysicalHasIpv6Path = true));
            Assert.Contains(TunnelFinding.Ipv6Bypass, findings);

            var covered = VpnTunnelLeakMonitor.Evaluate(true, Up(s => { s.PhysicalHasIpv6Path = true; s.TunnelHasIpv6 = true; }));
            Assert.DoesNotContain(TunnelFinding.Ipv6Bypass, covered);
        }

        [Fact]
        public void FullTunnelResolvers_PlusPhysicalResolvers_ReportsResolverOutsideTunnel()
        {
            var findings = VpnTunnelLeakMonitor.Evaluate(true, Up(s =>
            {
                s.TunnelHasResolvers = true;
                s.PhysicalResolvers.Add("192.168.1.1");
            }));
            Assert.Contains(TunnelFinding.ResolverOutsideTunnel, findings);
        }

        [Fact]
        public void SplitTunnel_DoesNotAlsoClaimResolverLeak()
        {
            var findings = VpnTunnelLeakMonitor.Evaluate(true, Up(s =>
            {
                s.PublicIpv4ViaTunnel = false;
                s.TunnelHasResolvers = true;
                s.PhysicalResolvers.Add("192.168.1.1");
            }));
            Assert.Contains(TunnelFinding.Ipv4Bypass, findings);
            Assert.DoesNotContain(TunnelFinding.ResolverOutsideTunnel, findings);
        }

        [Theory]
        [InlineData("2a02:6b8::1", true)]
        [InlineData("fe80::1", false)]          // link-local
        [InlineData("fd12:3456::1", false)]     // unique local
        [InlineData("2001:0:4136:e378::1", false)] // Teredo
        [InlineData("::1", false)]
        [InlineData("192.168.1.10", false)]
        public void IsGlobalIpv6_ExcludesNonRoutableScopes(string address, bool expected)
        {
            Assert.Equal(expected, VpnTunnelLeakMonitor.IsGlobalIpv6(IPAddress.Parse(address)));
        }
    }
}
