using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>Privacy hints are distinct observations, never standalone kill authority.</summary>
    internal static class PrivacyActivityPolicy
    {
        internal static bool IsObservation(DetectionEvent signal)
        {
            var rule = signal.RuleName ?? "";
            return rule.StartsWith("Privacy:", StringComparison.Ordinal) ||
                rule.StartsWith("Screen Capture:", StringComparison.Ordinal) ||
                rule.StartsWith("UI Overlay:", StringComparison.Ordinal) ||
                rule.StartsWith("Clickjacking:", StringComparison.Ordinal) ||
                rule.StartsWith("Input Integrity:", StringComparison.Ordinal) ||
                rule.StartsWith("Webcam Hijack:", StringComparison.Ordinal) ||
                rule.StartsWith("Audio Hijack:", StringComparison.Ordinal);
        }

        internal static void Apply(DetectionEvent signal)
        {
            signal.Tier = DetectionTier.Tier2Indicator;
            signal.AuthorizedResponse = ResponseAction.LogOnly;
            signal.Family = null;
            signal.Metadata ??= new Dictionary<string, string>();
            signal.Metadata.Remove("ChainConfirmed");
            signal.Metadata["WeakObserveSeed"] = "true";
            signal.Metadata["PrivacyActivity"] = "true";
            signal.Metadata["UserInitiated"] = "Unknown";
            bool overlay = signal.RuleName.IndexOf("Overlay", StringComparison.OrdinalIgnoreCase) >= 0;
            signal.Metadata["PrivacyCategory"] = overlay ? "Overlay" :
                signal.RuleName.IndexOf("Microphone", StringComparison.OrdinalIgnoreCase) >= 0 ? "Microphone" :
                signal.RuleName.IndexOf("Webcam", StringComparison.OrdinalIgnoreCase) >= 0 ? "Camera" :
                signal.RuleName.StartsWith("Input Integrity:", StringComparison.Ordinal) ? "Input" : "ScreenOrDesktop";
            signal.Metadata["ReviewPriority"] = overlay ? "High" : "Normal";
            // Foreground PID on an input hook is a potential victim, not the injection owner.
            // ConsentStore entries have no verified live process owner. Neither can authorize targeting.
            signal.Metadata["ActorAttribution"] = overlay || signal.RuleName.StartsWith("Screen Capture:", StringComparison.Ordinal)
                ? "WindowOrModuleOwner; capture intent unproven" : "Unproven";
        }

        internal static bool HasConfirmedCompromise(IReadOnlyList<DetectionEvent> signals, long liveBirth, DateTime now)
        {
            if (liveBirth <= 0) return false;
            bool Fresh(DetectionEvent s) => s.ProcessId > 4 && s.Timestamp <= now &&
                now - s.Timestamp <= TimeSpan.FromSeconds(30) && s.Metadata != null &&
                s.Metadata.TryGetValue("ProcessCreationTime", out var birth) && long.TryParse(birth, out var value) &&
                value == liveBirth && liveBirth <= s.Timestamp.ToFileTimeUtc();
            foreach (var privacy in signals.Where(s => Fresh(s) && IsObservation(s) &&
                s.Metadata!.TryGetValue("ActorAttribution", out var owner) && owner == "VerifiedWindowOwner"))
                if (signals.Any(attack => Fresh(attack) && attack.ProcessId == privacy.ProcessId &&
                    !IsObservation(attack) && attack.Tier == DetectionTier.Tier1Behavioral &&
                    attack.Confidence >= ResponsePolicy.DefaultMinTier1Confidence &&
                    attack.SignalType == SignalType.ReverseShell &&
                    attack.Metadata!.TryGetValue("BehavioralProof", out var proof) && proof == "SocketCommandLoop" &&
                    !(attack.Metadata.TryGetValue("ConsultantSignal", out var consultant) && consultant == "true")))
                    return true;
            return false;
        }
    }
}
