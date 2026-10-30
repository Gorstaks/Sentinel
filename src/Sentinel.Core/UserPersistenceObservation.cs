using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    internal static class UserPersistenceObservation
    {
        internal static bool IsInteractiveHive(string name) => name.Length <= 184 &&
            (name.StartsWith("S-1-5-21-", StringComparison.Ordinal) || name.StartsWith("S-1-12-1-", StringComparison.Ordinal)) &&
            name.All(c => c == 'S' || c == '-' || c >= '0' && c <= '9') && !name.EndsWith("-", StringComparison.Ordinal);
        internal static DetectionEvent Create(string hive, string surface, string valueName) => new()
        {
            RuleName = "Persistence: User Autostart Surface Observed", ProcessId = 0, ProcessName = "SYSTEM",
            Confidence = 0.50, Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic,
            Evidence = "A nonempty value was first observed or changed in a loaded interactive-user persistence surface. Value contents are omitted.",
            Reasoning = "Policies Explorer Run and protocol-association values can support persistence or UAC bypass, but legitimate policy also uses them. Observation time is not creation time; actor is unknown. No removal is authorized.",
            Metadata = new Dictionary<string, string>
            {
                ["UserHive"] = hive, ["Surface"] = surface, ["ValueName"] = valueName,
                ["WeakObserveSeed"] = "true", ["Attribution"] = "Unknown"
            }
        };
    }
}
