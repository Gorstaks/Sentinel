using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>Native NanoAV coverage; all verdicts/actions use Sentinel's existing pipeline.</summary>
    internal static class NanoAvCoverage
    {
        internal static bool IsScannableExtension(string? extension)
        {
            switch (extension?.ToLowerInvariant())
            {
                case ".ocx": case ".com": case ".cpl": case ".drv": case ".winmd":
                case ".psm1": case ".psd1": case ".vbe": case ".jse": case ".wsf":
                case ".wsh": case ".sct": case ".reg": case ".py": case ".pyw":
                case ".pyd": case ".sh": case ".lnk": case ".xll": case ".chm":
                case ".docm": case ".xlsm": case ".pptm": case ".dotm": case ".xlam":
                    return true;
                default: return false;
            }
        }
    }

    [RuleCategory(DetectionCategory.ReverseShell)]
    public sealed class NanoAvBehaviorRule : IDetectionRule
    {
        public string Name => "NanoAV: Native Socket Shell";
        private readonly RawSocketRedirectRule _socketRule;
        public NanoAvBehaviorRule(RawSocketRedirectRule socketRule) { _socketRule = socketRule; }
        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry process)
            {
                var host = Path.GetFileNameWithoutExtension(process.ProcessName ?? "");
                if (host.Equals("powershell", StringComparison.OrdinalIgnoreCase) || host.Equals("pwsh", StringComparison.OrdinalIgnoreCase))
                    return null; // The registered PowerShell rule already authors this exact proof.
            }
            var finding = _socketRule.Evaluate(context);
            if (finding == null) return null;
            finding.Metadata ??= new Dictionary<string, string>();
            finding.Metadata["CoverageModule"] = "NanoAV integrated";
            finding.Metadata["BehavioralProof"] = "SocketCommandLoop";
            // Keep the terminal rule identity: a single complete socket-shell behavior
            // authorizes immediate Tier1 response; no weak-indicator score is imported.
            return finding;
        }
    }
}
