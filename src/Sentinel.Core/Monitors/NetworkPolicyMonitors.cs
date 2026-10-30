using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>Registry integrity for real legacy/modern IPsec, NRPT and persistent routes.
    /// No registry contents, credentials or raw policy blobs are emitted or uploaded.</summary>
    public sealed class NetworkPolicyInventoryMonitor : BackgroundService, ISensorProgressSource
    {
        private readonly DetectionEngine _detections;
        private readonly ILogger<NetworkPolicyInventoryMonitor> _logger;
        private readonly Dictionary<string, string> _previous = new(StringComparer.Ordinal);
        public SensorProgress Progress { get; } = new(TimeSpan.FromMinutes(2)) {
            Scope = "Local IPsec/connection-security, DNS policy and persistent-route registry integrity; not packet enforcement or IPsec security-association verification" };
        public NetworkPolicyInventoryMonitor(DetectionEngine detections, ILogger<NetworkPolicyInventoryMonitor> logger)
        { _detections = detections; _logger = logger; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                        Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32);
                    foreach (var root in new[] {
                        @"SOFTWARE\Policies\Microsoft\Windows\IPSec",
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules",
                        @"SOFTWARE\Policies\Microsoft\WindowsFirewall\ConSecRules",
                        @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" })
                    {
                        ct.ThrowIfCancellationRequested();
                        var hash = Fingerprint(machine, root, ct);
                        if (_previous.TryGetValue(root, out var before) && before != hash)
                            await _detections.EmitAsync(CreateObservation(root)).ConfigureAwait(false);
                        _previous[root] = hash;
                    }
                    Progress.Succeeded();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) {
                    Progress.Failed(ex.Message); _logger.LogWarning(ex, "Network policy inventory unavailable; enforcement is not inferred");
                }
                await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            }
        }
        internal static DetectionEvent CreateObservation(string root) => new()
        {
            RuleName = "Network Policy: Configuration Changed", ProcessId = 0, ProcessName = "SYSTEM",
            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
            Confidence = 0.5, Evidence = "Configuration changed under HKLM\\" + root,
            Reasoning = "Registry integrity change only. Administrative updates, VPNs and Group Policy can legitimately change this state. Startup baseline is not proof of trust; active IPsec enforcement was not tested.",
            Metadata = new Dictionary<string, string> { ["PolicyScope"] = root,
                ["WeakObserveSeed"] = "true", ["ActorAttribution"] = "Unproven" }
        };
        internal static string Fingerprint(RegistryKey machine, string root, CancellationToken ct)
        {
            using var bytes = new MemoryStream(); using var writer = new BinaryWriter(bytes, Encoding.UTF8, true);
            var pending = new Stack<string>(); pending.Push(root); int keys = 0, values = 0;
            while (pending.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                if (++keys > 1024) throw new IOException("Policy key budget exceeded; inventory incomplete");
                string path = pending.Pop(); using var key = machine.OpenSubKey(path);
                writer.Write(path); writer.Write(key != null);
                if (key == null) continue;
                var names = key.GetValueNames(); Array.Sort(names, StringComparer.Ordinal);
                foreach (var name in names)
                {
                    if (++values > 8192) throw new IOException("Policy value budget exceeded; inventory incomplete");
                    writer.Write(name); writer.Write((int)key.GetValueKind(name));
                    var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    var data = value as byte[] ?? Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(value));
                    if (data.Length > 1024 * 1024 || bytes.Length + data.Length > 8 * 1024 * 1024)
                        throw new IOException("Policy byte budget exceeded; inventory incomplete");
                    writer.Write(data.Length); writer.Write(data);
                }
                var children = key.GetSubKeyNames(); Array.Sort(children, StringComparer.Ordinal);
                if (children.Length + pending.Count > 1024) throw new IOException("Policy child-key budget exceeded; inventory incomplete");
                foreach (var child in children) pending.Push(path + "\\" + child);
            }
            writer.Flush(); bytes.Position = 0; using var sha = SHA256.Create();
            return ConvertHex.ToHexString(sha.ComputeHash(bytes));
        }
    }
}
