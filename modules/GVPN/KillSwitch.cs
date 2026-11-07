using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace GVPN
{
    /// <summary>
    /// Leak protection via one Windows Firewall rule: block all outbound traffic on the physical
    /// adapters to every address except the VPN server being used. The tunnel adapter and
    /// loopback are not covered, so tunnelled traffic keeps flowing while nothing can bypass the
    /// tunnel. A single block rule is used because in Windows Firewall a block rule always
    /// overrides allow rules (the old block-all + allow-OpenVPN design blocked OpenVPN too).
    /// The rule persists if GVPN crashes (fail closed) and is removed on Disable, on Exit, and by
    /// the Sentinel uninstaller.
    /// </summary>
    public class KillSwitch
    {
        public const string RuleName = "GVPN Kill Switch";
        private static readonly string[] LegacyRuleNames =
        {
            "GVPN Allow OpenVPN", "GVPN Allow Loopback", "GVPN Allow DNS", "GVPN Allow Sentinel"
        };

        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_ACTION_BLOCK = 0;
        private const int NET_FW_IP_PROTOCOL_ANY = 256;
        private const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;

        private readonly Logger logger;
        private readonly string tunnelAdapterName;
        private readonly object sync = new object();

        public bool IsEnabled { get; private set; }

        public KillSwitch(Logger logger, string tunnelAdapterName)
        {
            this.logger = logger;
            this.tunnelAdapterName = tunnelAdapterName;
            // A rule left by a previous run (crash, reboot) means the kill switch is still on.
            IsEnabled = RuleExists(RuleName);
            if (IsEnabled)
                logger.Log("Kill switch rule found from previous session - kill switch is ON");
        }

        /// <summary>Turns the kill switch on. allowedServerIp may be null (block everything).</summary>
        public bool Enable(string allowedServerIp)
        {
            IsEnabled = true;
            return Apply(allowedServerIp);
        }

        /// <summary>(Re)writes the rule so only allowedServerIp is reachable outside the tunnel.</summary>
        public bool Apply(string allowedServerIp)
        {
            lock (sync)
            {
                try
                {
                    dynamic policy = CreatePolicy();
                    RemoveAll(policy, RuleName);
                    foreach (string legacy in LegacyRuleNames)
                        RemoveAll(policy, legacy);

                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
                    rule.Name = RuleName;
                    rule.Description = "GVPN kill switch: blocks traffic that would bypass the VPN tunnel.";
                    rule.Grouping = "GVPN";
                    rule.Direction = NET_FW_RULE_DIR_OUT;
                    rule.Action = NET_FW_ACTION_BLOCK;
                    rule.Protocol = NET_FW_IP_PROTOCOL_ANY;
                    rule.Profiles = NET_FW_PROFILE2_ALL;
                    rule.RemoteAddresses = BlockedRemoteAddresses(allowedServerIp);

                    object[] physical = PhysicalAdapterNames();
                    if (physical.Length > 0)
                        rule.Interfaces = physical;
                    else
                        logger.Log("Kill switch: no physical adapters found; rule covers all interfaces");

                    rule.Enabled = true;
                    policy.Rules.Add(rule);
                    logger.Log("Kill switch applied (allowed server: " + (allowedServerIp ?? "none") + ", adapters: " + string.Join(", ", physical.Cast<string>()) + ")");
                    return true;
                }
                catch (Exception ex)
                {
                    logger.Log("Kill switch apply failed: " + ex.Message);
                    return false;
                }
            }
        }

        public bool Disable()
        {
            lock (sync)
            {
                IsEnabled = false;
                try
                {
                    dynamic policy = CreatePolicy();
                    RemoveAll(policy, RuleName);
                    foreach (string legacy in LegacyRuleNames)
                        RemoveAll(policy, legacy);
                    logger.Log("Kill switch disabled");
                    return true;
                }
                catch (Exception ex)
                {
                    logger.Log("Kill switch disable failed: " + ex.Message);
                    return false;
                }
            }
        }

        private static dynamic CreatePolicy()
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
        }

        private static void RemoveAll(dynamic policy, string name)
        {
            // Rules.Remove deletes one rule per call; duplicates may exist from older builds.
            for (int i = 0; i < 20 && RuleExists(policy, name); i++)
                policy.Rules.Remove(name);
        }

        private static bool RuleExists(string name)
        {
            try { return RuleExists(CreatePolicy(), name); }
            catch { return false; }
        }

        private static bool RuleExists(dynamic policy, string name)
        {
            try
            {
                dynamic r = policy.Rules.Item(name);
                return r != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Every IPv4 address except the VPN server and the limited broadcast (DHCP must keep
        /// working so the physical link stays up), plus all IPv6 (the tunnel is IPv4 only).
        /// </summary>
        private static string BlockedRemoteAddresses(string allowedServerIp)
        {
            var ranges = new List<string>();
            IPAddress ip;
            if (allowedServerIp != null && IPAddress.TryParse(allowedServerIp, out ip) && ip.AddressFamily == AddressFamily.InterNetwork)
            {
                uint v = ToUInt(ip);
                if (v > 0)
                    ranges.Add("0.0.0.0-" + FromUInt(v - 1));
                if (v < 0xFFFFFFFE)
                    ranges.Add(FromUInt(v + 1) + "-255.255.255.254");
            }
            else
            {
                ranges.Add("0.0.0.0-255.255.255.254");
            }
            ranges.Add("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            return string.Join(",", ranges);
        }

        private object[] PhysicalAdapterNames()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                             && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel
                             && !string.Equals(n.Name, tunnelAdapterName, StringComparison.OrdinalIgnoreCase))
                    .Select(n => (object)n.Name)
                    .ToArray();
            }
            catch
            {
                return new object[0];
            }
        }

        private static uint ToUInt(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static string FromUInt(uint v)
        {
            return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
        }
    }
}
