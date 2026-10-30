using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class Release343WindowsTests
    {
        [EndpointWindowsAdminFact]
        public void SelfIsolationRepairsDuplicatesAndRepeatedApplyDoesNotGrowRuleCount()
        {
            object policyObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
            dynamic policy = policyObject; object rulesObject = policy.Rules; dynamic rules = rulesObject;
            string root = Path.Combine(Path.GetTempPath(), "Sentinel343_" + Guid.NewGuid().ToString("N"));
            var specs = new SelfNetworkIsolation(new WindowsSelfNetworkFirewall(), root).Rules.ToArray();
            string unrelated = "Sentinel343-Unrelated-" + Guid.NewGuid().ToString("N");
            try
            {
                // This fixture is restricted to disposable CI: never replace an installed
                // Sentinel policy on a developer's machine.
                foreach (var spec in specs)
                {
                    object? existing = WindowsPortBlockPolicy.ReadExistingRule(() => (object?)rules.Item(spec.Name));
                    try { Assert.Null(existing); }
                    finally { if (existing != null) Marshal.FinalReleaseComObject(existing); }
                }
                AddSeed(rules, specs[1].Name, specs[1].ApplicationPath, "foreign fixture group");
                Assert.Throws<InvalidOperationException>(() => new WindowsSelfNetworkFirewall().UpsertAndVerify(specs[1]));
                object collision = rules.Item(specs[1].Name);
                try { Assert.Equal("foreign fixture group", (string)((dynamic)collision).Grouping); }
                finally { Marshal.FinalReleaseComObject(collision); }
                RemoveTestRule(rules, specs[1].Name, root);
                AddSeed(rules, specs[0].Name, specs[0].ApplicationPath, SelfNetworkBlockRule.Group);
                AddSeed(rules, specs[0].Name, specs[0].ApplicationPath, SelfNetworkBlockRule.Group);
                AddSeed(rules, unrelated, Path.Combine(root, "unrelated.exe"), "unrelated");
                var firewall = new WindowsSelfNetworkFirewall();
                var isolation = new SelfNetworkIsolation(firewall, root);
                isolation.Apply();
                var first = Counts(rules, specs);
                isolation.Apply(); isolation.Apply();
                var second = Counts(rules, specs);
                foreach (var spec in specs)
                {
                    Assert.Equal(1, first[spec.Name]); Assert.Equal(1, second[spec.Name]);
                    object observed = rules.Item(spec.Name);
                    try { Assert.True(WindowsSelfNetworkFirewall.Matches(observed, spec)); }
                    finally { Marshal.FinalReleaseComObject(observed); }
                }
                object preserved = rules.Item(unrelated);
                Marshal.FinalReleaseComObject(preserved);
            }
            finally
            {
                // All test rules target nonexistent executables in the private temp path.
                foreach (var spec in specs) RemoveTestRule(rules, spec.Name, root);
                RemoveTestRule(rules, unrelated, root);
                Marshal.FinalReleaseComObject(rulesObject); Marshal.FinalReleaseComObject(policyObject);
            }
        }
        private static void AddSeed(dynamic rules, string name, string app, string group)
        {
            object ruleObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!)!;
            try
            {
                dynamic rule = ruleObject; rule.Name = name; rule.ApplicationName = app;
                rule.Grouping = group; rule.Direction = 2; rule.Action = 0; rule.Profiles = 7;
                rule.Protocol = 256; rule.Enabled = true; rules.Add(rule);
            }
            finally { Marshal.FinalReleaseComObject(ruleObject); }
        }
        private static Dictionary<string, int> Counts(dynamic rules, SelfNetworkBlockRule[] specs)
        {
            var counts = specs.ToDictionary(s => s.Name, _ => 0);
            foreach (dynamic rule in rules)
                try { string name = (string)rule.Name; if (counts.ContainsKey(name)) counts[name]++; }
                finally { Marshal.FinalReleaseComObject(rule); }
            return counts;
        }
        private static void RemoveTestRule(dynamic rules, string name, string root)
        {
            for (int i = 0; i < 8; i++)
            {
                object? item = WindowsPortBlockPolicy.ReadExistingRule(() => (object?)rules.Item(name));
                if (item == null) return;
                try
                {
                    dynamic current = item;
                    // An existing installed rule is preserved even if the assertion failed.
                    if (!((string)current.ApplicationName).StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return;
                    rules.Remove(name);
                }
                finally { Marshal.FinalReleaseComObject(item); }
            }
        }
    }
}
