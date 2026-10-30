using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    internal static class EtwCollectionPolicy
    {
        // Same policy for native event-ID filters and the managed callback fallback.
        // Header-only: never parse payloads or resolve processes on ProcessTrace.
        internal static bool Consumes(Guid provider, ushort id)
        {
            if (provider == UnifiedEtwSession.Providers.KernelProcess) return id == 1 || id == 2 || id == 5;
            if (provider == UnifiedEtwSession.Providers.KernelFile) return id == 10 || id == 11 || id == 15;
            if (provider == UnifiedEtwSession.Providers.KernelRegistry) return id == 1 || id == 3 || id == 5 || id == 6;
            if (provider == UnifiedEtwSession.Providers.KernelNetwork) return id == 12 || id == 15 || id == 42 || id == 43 || id == 56 || id == 57;
            if (provider == UnifiedEtwSession.Providers.DnsClient) return id == 3006 || id == 3008;
            if (provider == UnifiedEtwSession.Providers.PowerShell) return id == 4104;
            if (provider == UnifiedEtwSession.Providers.Firewall) return id == 2004 || id == 2005 || id == 2006;
            if (provider == UnifiedEtwSession.Providers.TaskScheduler) return id == 106 || id == 140 || id == 141;
            if (provider == UnifiedEtwSession.Providers.WmiActivity) return id == 5859 || id == 5860 || id == 5861;
            return true; // TI and externally registered providers: no guessed event schema.
        }
        // Only events actually consumed by EtwEventDispatcher. Threat Intelligence remains
        // unfiltered: its provider-specific opcode coverage must not be guessed.
        internal static ushort[] EventIds(Guid provider)
        {
            if (provider == UnifiedEtwSession.Providers.KernelProcess) return new ushort[] { 1, 2, 5 };
            if (provider == UnifiedEtwSession.Providers.KernelFile) return new ushort[] { 10, 11, 15 };
            if (provider == UnifiedEtwSession.Providers.KernelRegistry) return new ushort[] { 1, 3, 5, 6 };
            if (provider == UnifiedEtwSession.Providers.KernelNetwork) return new ushort[] { 12, 15, 42, 43, 56, 57 };
            if (provider == UnifiedEtwSession.Providers.DnsClient) return new ushort[] { 3006, 3008 };
            if (provider == UnifiedEtwSession.Providers.PowerShell) return new ushort[] { 4104 };
            if (provider == UnifiedEtwSession.Providers.Firewall) return new ushort[] { 2004, 2005, 2006 };
            if (provider == UnifiedEtwSession.Providers.TaskScheduler) return new ushort[] { 106, 140, 141 };
            if (provider == UnifiedEtwSession.Providers.WmiActivity) return new ushort[] { 5859, 5860, 5861 };
            return Array.Empty<ushort>();
        }

        internal static string? Degradation(EtwHealthSnapshot health, bool lossIncreased)
        {
            var reasons = new List<string>();
            if (!health.QuerySucceeded) reasons.Add("ETW session query unavailable");
            if (health.ProviderStatus.Count != 10) reasons.Add("Incomplete ETW provider status inventory");
            foreach (var provider in health.ProviderStatus.Where(p => p.Value != 0).OrderBy(p => p.Key))
                reasons.Add(provider.Key == UnifiedEtwSession.Providers.ThreatIntelligence.ToString() && provider.Value == 5
                    ? "Threat-Intelligence provider access denied by Windows; protected-provider access is not granted by SYSTEM alone. Other sensors are not equivalent coverage."
                    : "ETW provider " + provider.Key + ": Win32 " + provider.Value);
            if (health.ProviderFilterStatus.Any(p => p.Value != 0))
                reasons.Add("Native event-ID filtering unavailable for one or more providers; unfiltered fallback is in use where enable succeeded");
            if (health.DispatchHandlerBusyMs > 5000) reasons.Add("ETW analysis handler has not completed for more than five seconds; worker liveness does not establish progress");
            if (lossIncreased) reasons.Add("New ETW events/buffers or dispatch loss; retained events are incomplete");
            return reasons.Count == 0 ? null : string.Join("; ", reasons);
        }
    }
}
