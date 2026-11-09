using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.SecurityEvasion)]
    public class AttackToolsRule : IDetectionRule
    {
        public string Name => "AttackToolsRule";

        // Indicator data lives in Indicators/indicators.txt, deflated into the assembly (see IndicatorCatalog).
        // Plaintext literals made the unsigned PE match stealer/RAT signatures; runtime string
        // splitting is scored as evasion. A compressed data resource is neither. Do not reinline.
        private static readonly (string Pattern, string Category)[] ToolSignatures = IndicatorCatalog.Pairs("attackTools.signatures");

        /// <summary>
        /// Checks if a pattern appears in the text at a word boundary (preceded/followed by
        /// non-alphanumeric characters or string start/end). Prevents substring false positives
        /// where e.g. "fscan" matches inside "filesystem_scanner.exe".
        /// </summary>
        private static bool HasWordBoundaryMatch(string text, string pattern)
        {
            int idx = -1;
            while ((idx = text.IndexOf(pattern, idx + 1)) >= 0)
            {
                bool leftBound = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
                int endIdx = idx + pattern.Length;
                bool rightBound = endIdx >= text.Length || !char.IsLetterOrDigit(text[endIdx]);
                if (leftBound && rightBound) return true;
            }
            return false;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                var image = pt.ImagePath;

                // Custom check for symlink/junction abuse targeting system folders (BlueHammer, etc.)
                if ((cmd.Contains("mklink") || 
                     cmd.Contains("junction")) &&
                    (cmd.Contains(@"\system32\config") ||
                     cmd.Contains(@"\windows defender") ||
                     cmd.Contains(@"\config\system") ||
                     cmd.Contains(@"\config\sam") ||
                     cmd.Contains(@"\config\security")))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.SuspiciousProcess,
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Junction LPE attempt detected: '{cmd}'",
                        Reasoning = "Process attempted to create an NTFS directory junction or symlink targeting sensitive Windows configuration or Defender update directories. " +
                                    "This is a signature pattern of local privilege escalation exploits like BlueHammer."
                    };
                }

                foreach (var (pattern, category) in ToolSignatures)
                {
                    if (cmd.Contains(pattern) ||
                        image.Contains(pattern))
                    {
                        // For short APT tool names, require word-boundary or filename-exact match
                        // to avoid false positives from substring matches
                        if (category.StartsWith("APTTool:"))
                        {
                            var fileName = Path.GetFileNameWithoutExtension(pt.ImagePath).ToLowerInvariant();
                            bool isExactFilename = fileName.Equals(pattern);
                            // Check for word boundary in command line: pattern preceded/followed by non-alphanumeric
                            bool hasWordBoundary = HasWordBoundaryMatch(cmd, pattern);
                            if (!isExactFilename && !hasWordBoundary)
                                continue; // Substring match without boundary - skip
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = category.Equals("C2") ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
                            // Only C2-category tool hits are a terminal C2Beacon; other tool
                            // categories (CredTool/ADTool/LOLBin) are not tagged terminal here
                            // and continue to classify via the existing substring path.
                            Family = category.Equals("C2") ? TerminalFamily.C2Beacon : (TerminalFamily?)null,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Attack tool detected: {category} (pattern: '{pattern}') in {pt.ProcessName} (PID {pt.ProcessId})",
                            Reasoning = $"Process command line or image path matches a known offensive security tool ({category}). Kill authorized."
                        };
                    }
                }
            }
            return null;
        }
    }

}
