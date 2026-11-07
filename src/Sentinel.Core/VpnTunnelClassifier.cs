using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace Sentinel.Core
{
    /// <summary>
    /// Classifies network interfaces as VPN / overlay tunnels so network monitors behave
    /// correctly when Sentinel runs next to a VPN client (GVPN, OpenVPN, WireGuard, Tailscale,
    /// RAS L2TP/IKEv2/SSTP, vendor clients).
    ///
    /// Sentinel does not run VPN tunnels itself. A tunnel interface coming up is a host-side
    /// path the user installed, not a man-in-the-middle on the LAN, so its adapter, gateway and
    /// routes are reported as observations and never feed the LAN MitM composite.
    ///
    /// Trust anchors (adversarial review): classification uses the IANA interface type and the
    /// DRIVER-supplied interface description. It never uses the connection name, which any user
    /// can rename ("Ethernet" -> "VPN"). Wi-Fi interfaces are never classified as tunnels by
    /// description. The effect of a tunnel classification is limited to demoting that
    /// interface's route/gateway/adapter observations to logged Tier2 that do not count as LAN
    /// MitM legs; ARP, DNS, bridge, WPAD and Wi-Fi legs are unaffected.
    ///
    /// Stateless and thread-safe: no mutable static state.
    /// </summary>
    public static class VpnTunnelClassifier
    {
        /// <summary>Metadata key a Sentinel network monitor sets on an observation about a tunnel interface.</summary>
        public const string TunnelAdapterMeta = "TunnelAdapter";

        // IANA ifType values (ipifcons.h).
        public const int IfTypeEthernet = 6;
        public const int IfTypePropVirtual = 53;   // Wintun / WireGuard / many userland tunnels
        public const int IfTypePpp = 23;           // RAS: L2TP, PPTP, SSTP, IKEv2, PPPoE dial-up
        public const int IfTypeIeee80211 = 71;     // Wi-Fi
        public const int IfTypeTunnel = 131;       // encapsulation tunnels

        /// <summary>Driver description fragments of VPN / overlay adapters (lower case).</summary>
        private static readonly string[] TunnelDescriptionFragments =
        {
            "wireguard", "wintun", "tailscale", "nordlynx", "openvpn", "tap-windows", "tap-win32",
            "tap0901", "tap adapter", "proton", "warp", "zerotier", "wan miniport", "fortinet",
            "anyconnect", "pangp", "globalprotect", "juniper", "pulse secure", "mullvad",
            "expressvpn", "surfshark", "windscribe", "softether", "vpn",
        };

        /// <summary>
        /// IPv6 transition pseudo-interfaces are tunnel-typed but are not VPNs: they never carry
        /// the user's traffic to a VPN server, so they must not make a "tunnel is up" verdict.
        /// </summary>
        private static readonly string[] TransitionDescriptionFragments =
        {
            "teredo", "isatap", "6to4", "ip-https", "iphttps",
        };

        /// <summary>
        /// True when the interface is a VPN/overlay tunnel. <paramref name="ifType"/> is the IANA
        /// ifType; <paramref name="description"/> is the driver-supplied description.
        /// </summary>
        public static bool IsTunnel(int ifType, string? description)
        {
            var d = (description ?? string.Empty).ToLowerInvariant();
            foreach (var f in TransitionDescriptionFragments)
                if (d.Contains(f)) return false;

            if (ifType == IfTypePpp || ifType == IfTypeTunnel || ifType == IfTypePropVirtual)
                return true;

            // A Wi-Fi radio is never a tunnel, whatever its driver text says.
            if (ifType == IfTypeIeee80211)
                return false;

            foreach (var f in TunnelDescriptionFragments)
                if (d.Contains(f)) return true;
            return false;
        }

        /// <summary>Classifies a live <see cref="NetworkInterface"/> (type + driver description only).</summary>
        public static bool IsTunnel(NetworkInterface? ni)
        {
            if (ni == null) return false;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) return false;
            string description;
            try { description = ni.Description; }
            catch (NetworkInformationException) { description = string.Empty; }
            return IsTunnel((int)ni.NetworkInterfaceType, description);
        }

        /// <summary>
        /// True for an observation a Sentinel monitor tagged as being about a tunnel interface.
        /// Restricted to host-wide monitor events (PID 0-4): a process-attributed detection can
        /// never use the tag to leave the correlation buffers.
        /// </summary>
        public static bool IsTunnelObservation(DetectionEvent? signal)
        {
            if (signal == null || signal.ProcessId > 4 || signal.Metadata == null) return false;
            return signal.Metadata.TryGetValue(TunnelAdapterMeta, out var v) &&
                   string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Tags observation metadata as being about a tunnel interface.</summary>
        public static Dictionary<string, string> MarkTunnel(Dictionary<string, string> metadata)
        {
            metadata[TunnelAdapterMeta] = "true";
            return metadata;
        }

        /// <summary>
        /// True for a route that captures all IPv4 traffic: 0.0.0.0/0 or one half of the
        /// 0.0.0.0/1 + 128.0.0.0/1 split most VPN clients install. Arguments are in network byte
        /// order as returned by GetIpForwardTable.
        /// </summary>
        public static bool IsDefaultClassRoute(uint destination, uint mask)
        {
            if (destination == 0 && mask == 0) return true;
            const uint SlashOne = 0x00000080;        // 128.0.0.0 in network byte order
            return mask == SlashOne && (destination == 0 || destination == SlashOne);
        }
    }
}
