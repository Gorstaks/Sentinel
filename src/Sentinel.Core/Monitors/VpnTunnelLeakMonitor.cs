// VPN tunnel state and leak observation - for hosts that run Sentinel next to a VPN client
// (GVPN, OpenVPN, WireGuard, Tailscale, RAS, vendor clients). Sentinel does not run tunnels.
//
// Sentinel observes sockets per process before a tunnel encrypts them, so a VPN does not blind
// its process/connection telemetry. What a VPN user actually needs from a host monitor is to know
// when traffic is NOT going through the tunnel: the tunnel dropped, IPv4 routes bypass it, IPv6
// leaves on the physical adapter, or resolvers remain on the physical adapter.
//
// Observe-only: every event is Tier2 / LogOnly, tagged as a tunnel observation (never a LAN MitM
// leg) and WeakObserveSeed. No firewall, route or adapter mutation - enforcement (a kill switch)
// belongs to the VPN client. Uses only OS state (IP Helper / NetworkInformation), never a VPN
// client's own log, which is user-writable and therefore attacker-controllable.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>One poll of tunnel-relevant interface state. Pure data so the verdicts are testable.</summary>
    public sealed class TunnelSnapshot
    {
        /// <summary>Descriptions of up VPN/overlay tunnel interfaces.</summary>
        public List<string> Tunnels { get; } = new();

        /// <summary>
        /// True when the route for a public IPv4 destination uses a tunnel interface, false when it
        /// uses another interface, null when the route lookup failed.
        /// </summary>
        public bool? PublicIpv4ViaTunnel { get; set; }

        /// <summary>Description of the interface carrying public IPv4 traffic, for evidence.</summary>
        public string PublicIpv4Interface { get; set; } = string.Empty;

        /// <summary>A non-tunnel adapter has a global IPv6 address and an IPv6 gateway.</summary>
        public bool PhysicalHasIpv6Path { get; set; }

        /// <summary>A tunnel interface has a global IPv6 address or an IPv6 gateway.</summary>
        public bool TunnelHasIpv6 { get; set; }

        /// <summary>A tunnel interface has DNS servers configured.</summary>
        public bool TunnelHasResolvers { get; set; }

        /// <summary>Resolvers configured on up non-tunnel adapters.</summary>
        public List<string> PhysicalResolvers { get; } = new();

        public bool TunnelUp => Tunnels.Count > 0;
    }

    public enum TunnelFinding
    {
        Connected,
        Disconnected,
        Ipv4Bypass,
        Ipv6Bypass,
        ResolverOutsideTunnel,
    }

    public sealed class VpnTunnelLeakMonitor : BackgroundService
    {
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

        // Route lookup only (GetBestInterface sends no packet). 1.1.1.1 is a stable public address.
        private static readonly uint PublicIpv4Probe = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);

        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<VpnTunnelLeakMonitor> _logger;

        // Per-instance state (no static mutable state). Findings are reported once per tunnel
        // session; the set resets when the tunnel goes down.
        private bool _tunnelWasUp;
        private readonly HashSet<TunnelFinding> _reportedThisSession = new();

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        public VpnTunnelLeakMonitor(DetectionEngine detectionEngine, ILogger<VpnTunnelLeakMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[VpnTunnelLeakMonitor] Started - VPN tunnel state and bypass observation (observe-only)");
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { await ScanAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[VpnTunnelLeakMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            var snapshot = TakeSnapshot();
            var findings = Evaluate(_tunnelWasUp, snapshot);
            _tunnelWasUp = snapshot.TunnelUp;

            foreach (var finding in findings)
            {
                ct.ThrowIfCancellationRequested();
                if (finding == TunnelFinding.Disconnected)
                    _reportedThisSession.Clear();
                else if (!_reportedThisSession.Add(finding))
                    continue;

                await _detectionEngine.EmitAsync(BuildEvent(finding, snapshot)).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Verdicts for one poll. <paramref name="tunnelWasUp"/> is the previous poll's state.
        /// Bypass findings are only evaluated while a tunnel is up.
        /// </summary>
        public static IReadOnlyList<TunnelFinding> Evaluate(bool tunnelWasUp, TunnelSnapshot snapshot)
        {
            var findings = new List<TunnelFinding>();
            if (snapshot == null) return findings;

            if (!snapshot.TunnelUp)
            {
                if (tunnelWasUp) findings.Add(TunnelFinding.Disconnected);
                return findings;
            }

            if (!tunnelWasUp) findings.Add(TunnelFinding.Connected);

            if (snapshot.PublicIpv4ViaTunnel == false)
                findings.Add(TunnelFinding.Ipv4Bypass);

            if (snapshot.PhysicalHasIpv6Path && !snapshot.TunnelHasIpv6)
                findings.Add(TunnelFinding.Ipv6Bypass);

            // Only meaningful for a full tunnel that brings its own resolvers: Windows may still
            // send queries to resolvers on other adapters (multi-homed name resolution).
            if (snapshot.PublicIpv4ViaTunnel == true && snapshot.TunnelHasResolvers &&
                snapshot.PhysicalResolvers.Count > 0)
                findings.Add(TunnelFinding.ResolverOutsideTunnel);

            return findings;
        }

        /// <summary>Global unicast IPv6 (not loopback, link-local, site-local, ULA fc00::/7 or Teredo).</summary>
        public static bool IsGlobalIpv6(IPAddress? address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetworkV6) return false;
            if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal ||
                address.IsIPv6Teredo || address.IsIPv6Multicast)
                return false;
            var b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return false; // unique local fc00::/7
            return !address.Equals(IPAddress.IPv6Any);
        }

        private TunnelSnapshot TakeSnapshot()
        {
            var snapshot = new TunnelSnapshot();
            var tunnelIpv4Indexes = new HashSet<int>();
            var descriptionByIpv4Index = new Dictionary<int, string>();

            NetworkInterface[] interfaces;
            try { interfaces = NetworkInterface.GetAllNetworkInterfaces(); }
            catch (NetworkInformationException ex)
            {
                _logger.LogDebug(ex, "[VpnTunnelLeakMonitor] interface enumeration failed");
                return snapshot;
            }

            foreach (var ni in interfaces)
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch (NetworkInformationException ex)
                {
                    _logger.LogDebug(ex, "[VpnTunnelLeakMonitor] IP properties unavailable for {Name}", ni.Name);
                    continue;
                }

                bool tunnel = VpnTunnelClassifier.IsTunnel(ni);
                int ipv4Index = TryGetIpv4Index(props);
                if (ipv4Index > 0) descriptionByIpv4Index[ipv4Index] = ni.Description;

                bool hasGlobalV6 = props.UnicastAddresses.Any(u => IsGlobalIpv6(u.Address));
                bool hasV6Gateway = props.GatewayAddresses.Any(g =>
                    g.Address.AddressFamily == AddressFamily.InterNetworkV6 && !g.Address.Equals(IPAddress.IPv6Any));
                var resolvers = props.DnsAddresses
                    .Where(a => !(a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6SiteLocal))
                    .Select(a => a.ToString())
                    .ToList();

                if (tunnel)
                {
                    snapshot.Tunnels.Add(ni.Description);
                    if (ipv4Index > 0) tunnelIpv4Indexes.Add(ipv4Index);
                    if (hasGlobalV6 || hasV6Gateway) snapshot.TunnelHasIpv6 = true;
                    if (resolvers.Count > 0) snapshot.TunnelHasResolvers = true;
                }
                else
                {
                    if (hasGlobalV6 && hasV6Gateway) snapshot.PhysicalHasIpv6Path = true;
                    snapshot.PhysicalResolvers.AddRange(resolvers);
                }
            }

            if (snapshot.TunnelUp)
            {
                int err = GetBestInterface(PublicIpv4Probe, out int bestIndex);
                if (err == 0)
                {
                    snapshot.PublicIpv4ViaTunnel = tunnelIpv4Indexes.Contains(bestIndex);
                    snapshot.PublicIpv4Interface = descriptionByIpv4Index.TryGetValue(bestIndex, out var d)
                        ? d : $"interface {bestIndex}";
                }
                else
                {
                    _logger.LogDebug("[VpnTunnelLeakMonitor] GetBestInterface failed ({Error})", err);
                }
            }

            return snapshot;
        }

        private static int TryGetIpv4Index(IPInterfaceProperties props)
        {
            try { return props.GetIPv4Properties()?.Index ?? 0; }
            catch (NetworkInformationException)
            {
                // IPv4 is not enabled on this interface - expected for some tunnels.
                return 0;
            }
        }

        private static DetectionEvent BuildEvent(TunnelFinding finding, TunnelSnapshot snapshot)
        {
            var tunnels = string.Join(", ", snapshot.Tunnels);
            string rule, evidence, reasoning;
            double confidence;

            switch (finding)
            {
                case TunnelFinding.Connected:
                    rule = "VPN Tunnel: Connected";
                    evidence = $"VPN/overlay tunnel interface up: {tunnels}.";
                    reasoning = "A VPN tunnel is active. Recorded for context: Sentinel keeps per-process " +
                                "connection visibility because it observes sockets before the tunnel encrypts them.";
                    confidence = 0.15;
                    break;
                case TunnelFinding.Disconnected:
                    rule = "VPN Tunnel: Disconnected";
                    evidence = "No VPN/overlay tunnel interface is up any more.";
                    reasoning = "The VPN tunnel went down. Unless the VPN client's kill switch blocks traffic, " +
                                "connections now leave through the physical network adapter.";
                    confidence = 0.30;
                    break;
                case TunnelFinding.Ipv4Bypass:
                    rule = "VPN Tunnel: IPv4 Traffic Bypasses Tunnel";
                    evidence = $"Tunnel up ({tunnels}) but public IPv4 traffic routes via '{snapshot.PublicIpv4Interface}'.";
                    reasoning = "A VPN tunnel is up, yet the route for public IPv4 destinations does not use it. " +
                                "Expected for split-tunnel VPNs; otherwise traffic is leaking outside the tunnel " +
                                "(route not installed, overridden, or the tunnel only carries private subnets).";
                    confidence = 0.40;
                    break;
                case TunnelFinding.Ipv6Bypass:
                    rule = "VPN Tunnel: IPv6 Traffic Bypasses Tunnel";
                    evidence = $"Tunnel up ({tunnels}) without IPv6, while a physical adapter has a global IPv6 address and gateway.";
                    reasoning = "The VPN tunnel carries no IPv6, but the physical network offers an IPv6 route. " +
                                "IPv6-capable destinations (many large sites) are reached outside the tunnel " +
                                "unless the VPN client blocks IPv6.";
                    confidence = 0.45;
                    break;
                default:
                    rule = "VPN Tunnel: Resolver Outside Tunnel";
                    evidence = $"Full tunnel up ({tunnels}) with its own resolvers, while physical adapters keep resolvers: " +
                               $"{string.Join(", ", snapshot.PhysicalResolvers.Distinct())}.";
                    reasoning = "Windows can send name queries to resolvers on every adapter. Resolvers left on the " +
                                "physical adapter can reveal visited domains to the local network or ISP even though " +
                                "the traffic itself uses the tunnel.";
                    confidence = 0.30;
                    break;
            }

            return new DetectionEvent
            {
                RuleName = rule,
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.Generic,
                Timestamp = DateTime.UtcNow,
                Metadata = VpnTunnelClassifier.MarkTunnel(new Dictionary<string, string>
                {
                    ["TunnelFinding"] = finding.ToString(),
                    ["Tunnels"] = tunnels,
                    ["ObserveOnly"] = "true",
                    ["WeakObserveSeed"] = "true",
                    [BehavioralCorrelationEngine.ObservationKeyMeta] = $"vpn-tunnel:{finding}"
                })
            };
        }
    }
}
