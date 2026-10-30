using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    public sealed class SelfNetworkBlockRule
    {
        public string Name { get; }
        public string ApplicationPath { get; }
        public int Direction { get; }
        public const string Group = "Sentinel Offline Isolation";
        // All non-loopback IPv4/IPv6 destinations, including LAN and link-local addresses.
        // Explicit block rules win over allow rules; loopback must be excluded from the block.
        public const string RemoteAddresses = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        public SelfNetworkBlockRule(string name, string applicationPath, int direction)
        {
            Name = name;
            ApplicationPath = applicationPath;
            Direction = direction;
        }
    }

    public interface ISelfNetworkFirewall
    {
        void UpsertAndVerify(SelfNetworkBlockRule rule);
        void Remove(string name);
        void VerifyEnabled();
    }

    /// <summary>Owns only fixed, program-scoped rules; never changes the host's default policy.</summary>
    public sealed class SelfNetworkIsolation
    {
        private readonly ISelfNetworkFirewall _firewall;
        private readonly string _installDirectory;
        public SelfNetworkIsolation(ISelfNetworkFirewall firewall, string installDirectory)
        {
            _firewall = firewall;
            _installDirectory = Path.GetFullPath(installDirectory);
        }

        public IEnumerable<SelfNetworkBlockRule> Rules
        {
            get
            {
                // Guard is Sentinel.Service.exe --watchdog, so this Service image rule covers
                // both Service and Guard. Two image rules protect the three core processes.
                foreach (var executable in new[] { "Sentinel.Service.exe", "Sentinel.Agent.exe" })
                    yield return new SelfNetworkBlockRule("Sentinel-Offline-" + executable + "-IN",
                        Path.Combine(_installDirectory, executable), 1);
            }
        }

        public void Apply()
        {
            // Establish inbound protection before retiring the obsolete outbound policy.
            foreach (var rule in Rules) _firewall.UpsertAndVerify(rule);
            foreach (var retired in RetiredRuleNames) _firewall.Remove(retired);
            _firewall.VerifyEnabled();
        }

        public static IEnumerable<string> RetiredRuleNames
        {
            get
            {
                foreach (var exe in new[] { "Sentinel.Service.exe", "Sentinel.Agent.exe", "SentinelAutoRotate.exe" })
                    foreach (var suffix in new[] { "-OUT", "-OUT-Repair" })
                        yield return "Sentinel-Offline-" + exe + suffix;
                yield return "Sentinel-Offline-SentinelAutoRotate.exe-IN";
                yield return "Sentinel-Offline-SentinelAutoRotate.exe-IN-Repair";
            }
        }

        public void Remove()
        {
            foreach (var rule in Rules) _firewall.Remove(rule.Name);
            foreach (var retired in RetiredRuleNames) _firewall.Remove(retired);
        }
    }
}
