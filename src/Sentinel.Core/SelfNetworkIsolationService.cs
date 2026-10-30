using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class WindowsSelfNetworkFirewall : ISelfNetworkFirewall
    {
        private readonly object _gate = new();
        private Dictionary<string, int>? _duplicateCounts;
        public void UpsertAndVerify(SelfNetworkBlockRule rule)
        {
            lock (_gate) UpsertCore(rule);
        }
        private void UpsertCore(SelfNetworkBlockRule rule)
        {
            if (!IsOwnedName(rule.Name)) throw new ArgumentException("Rule is outside Sentinel's reserved isolation names", nameof(rule));
            object? policyObject = null;
            object? rulesObject = null;
            object? ruleObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                rulesObject = policy.Rules;
                dynamic rules = rulesObject!;
                _duplicateCounts ??= InventoryDuplicates(rules);
                if (_duplicateCounts.TryGetValue(rule.Name, out int duplicates) && duplicates > 1)
                {
                    RemoveDuplicateName(rules, rule.Name, duplicates);
                    _duplicateCounts.Remove(rule.Name);
                }
                ruleObject = WindowsPortBlockPolicy.ReadExistingRule(() => (object?)rules.Item(rule.Name));
                if (ruleObject != null)
                {
                    if (Matches(ruleObject, rule)) return;
                    // Recreate a mismatched owned object, rather than retaining stale scope.
                    dynamic existing = ruleObject;
                    if (!string.Equals((string)existing.Grouping, SelfNetworkBlockRule.Group, StringComparison.Ordinal))
                        throw new InvalidOperationException("Foreign firewall rule collides with " + rule.Name);
                    rules.Remove(rule.Name);
                    var old = ruleObject; ruleObject = null; Release(old);
                }
                ruleObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!);
                dynamic native = ruleObject!;
                native.Name = rule.Name;
                native.Description = "Blocks unsolicited non-loopback inbound traffic. Outbound traffic and local dashboard/IPC remain available.";
                native.Grouping = SelfNetworkBlockRule.Group;
                native.ApplicationName = rule.ApplicationPath;
                native.Protocol = 256; // NET_FW_IP_PROTOCOL_ANY
                native.LocalAddresses = "*";
                native.RemoteAddresses = SelfNetworkBlockRule.RemoteAddresses;
                native.Direction = rule.Direction;
                native.Profiles = 7; // Domain, Private, Public
                native.Action = 0; // NET_FW_ACTION_BLOCK
                native.InterfaceTypes = "All";
                native.Enabled = true;
                rules.Add(native);
                var created = ruleObject; ruleObject = null; Release(created);
                ruleObject = rules.Item(rule.Name);
                if (!Matches(ruleObject, rule))
                    throw new InvalidOperationException("Self isolation rule verification failed: " + rule.Name);
            }
            finally
            {
                Release(ruleObject); Release(rulesObject); Release(policyObject);
            }
        }

        internal static bool Matches(object candidate, SelfNetworkBlockRule rule)
        {
            dynamic native = candidate;
            return (bool)native.Enabled && (int)native.Action == 0 && (int)native.Direction == rule.Direction
                && (int)native.Profiles == 7 && (int)native.Protocol == 256
                && string.Equals((string)native.Grouping, SelfNetworkBlockRule.Group, StringComparison.Ordinal)
                && string.Equals((string)native.ApplicationName, rule.ApplicationPath, StringComparison.OrdinalIgnoreCase)
                && string.Equals(((string)native.RemoteAddresses).Replace(" ", ""), SelfNetworkBlockRule.RemoteAddresses, StringComparison.OrdinalIgnoreCase)
                && string.Equals((string)native.LocalAddresses, "*", StringComparison.Ordinal)
                && string.Equals((string)native.InterfaceTypes, "All", StringComparison.OrdinalIgnoreCase)
                && WindowsPortBlockPolicy.UnscopedInterfaces(native.Interfaces)
                && string.IsNullOrEmpty((string)native.ServiceName);
        }

        private static Dictionary<string, int> InventoryDuplicates(dynamic rules)
        {
            // Inventory once per adapter, not once per minute/rule. Remove only the
            // six exact reserved names when EVERY colliding item has our grouping.
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            var collisions = new HashSet<string>(StringComparer.Ordinal);
            foreach (dynamic entry in rules)
            {
                try
                {
                    string name = (string)entry.Name;
                    if (!IsOwnedName(name)) continue;
                    counts.TryGetValue(name, out int count); counts[name] = count + 1;
                    if (!string.Equals((string)entry.Grouping, SelfNetworkBlockRule.Group, StringComparison.Ordinal)) collisions.Add(name);
                }
                finally { Release(entry); }
            }
            foreach (var pair in counts)
                if (pair.Value > 1 && collisions.Contains(pair.Key))
                    throw new InvalidOperationException("Foreign duplicate firewall name: " + pair.Key);
            return counts;
        }
        private static void RemoveDuplicateName(dynamic rules, string name, int count)
        {
            // Touch only the rule being recreated now; other directions keep their
            // existing protection until their own verified upsert.
            for (int i = 0; i <= count; i++)
            {
                object? remaining = WindowsPortBlockPolicy.ReadExistingRule(() => (object?)rules.Item(name));
                if (remaining == null) return;
                try
                {
                    dynamic current = remaining;
                    if (!string.Equals((string)current.Grouping, SelfNetworkBlockRule.Group, StringComparison.Ordinal))
                        throw new InvalidOperationException("Firewall ownership changed during duplicate cleanup");
                    if (i == count) throw new InvalidOperationException("Firewall duplicate removal made no progress");
                    rules.Remove(name);
                }
                finally { Release(remaining); }
            }
        }
        internal static bool IsOwnedName(string name)
        {
            foreach (string exe in new[] { "Sentinel.Service.exe", "Sentinel.Agent.exe", "SentinelAutoRotate.exe" })
                if (name == "Sentinel-Offline-" + exe + "-IN" || name == "Sentinel-Offline-" + exe + "-OUT") return true;
            return false;
        }

        public void VerifyEnabled()
        {
            object? policyObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                foreach (var profile in new[] { 1, 2, 4 })
                    if (!(bool)policy.FirewallEnabled[profile])
                        throw new InvalidOperationException("Windows Firewall profile " + profile + " is disabled; self isolation is not enforced.");
            }
            finally { Release(policyObject); }
        }

        public void Remove(string name)
        {
            object? policyObject = null;
            object? rulesObject = null;
            try
            {
                policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
                dynamic policy = policyObject!;
                rulesObject = policy.Rules;
                dynamic rules = rulesObject!;
                for (int removed = 0; removed < 1024; removed++)
                {
                    object? candidate = WindowsPortBlockPolicy.ReadExistingRule(() => (object?)rules.Item(name));
                    if (candidate == null) return;
                    try
                    {
                        if (!string.Equals((string)((dynamic)candidate).Grouping, SelfNetworkBlockRule.Group, StringComparison.Ordinal))
                            throw new InvalidOperationException("Foreign firewall rule collides with " + name);
                    }
                    finally { Release(candidate); }
                    try { rules.Remove(name); }
                    catch (Exception ex) when (ex.HResult == unchecked((int)0x80070002) || ex.HResult == unchecked((int)0x80070490)) { return; }
                }
                throw new InvalidOperationException("Owned firewall duplicate-removal budget exceeded: " + name);
            }
            finally { Release(rulesObject); Release(policyObject); }
        }

        private static void Release(object? value)
        {
            if (value != null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
        }
    }

    public sealed class SelfNetworkIsolationService : BackgroundService
    {
        private readonly SelfNetworkIsolation _isolation;
        private readonly ILogger<SelfNetworkIsolationService> _logger;
        public SelfNetworkIsolationService(ISelfNetworkFirewall firewall, ILogger<SelfNetworkIsolationService> logger)
        {
            _isolation = new SelfNetworkIsolation(firewall, AppDomain.CurrentDomain.BaseDirectory);
            _logger = logger;
        }
        protected override Task ExecuteAsync(CancellationToken ct) => Task.Run(() => RunAsync(ct), ct);
        private async Task RunAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    _isolation.Apply();
                    _logger.LogInformation("[SelfNetworkIsolation] Inbound-only blocks verified for Service, Agent and Guard (shared Service image); outbound traffic remains available");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SelfNetworkIsolation] Firewall isolation could not be enforced; local detection continues. Retrying in 60 seconds");
                }
                try { await Task.Delay(TimeSpan.FromSeconds(60), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            }
        }
    }
}
