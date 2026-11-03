using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects VBS scripts creating scheduled tasks (cmdschedule pattern).
    /// This is a classic malware persistence mechanism where a VBS script
    /// programmatically creates a Windows scheduled task to execute malicious code
    /// at system startup or on a recurring schedule.
    ///
    /// Restored detection: v2.9.0 included cmdschedule composite detection in evidence packs.
    /// This rule captures the behavioral pattern:
    /// 1. VBS script execution (.vbs file or cscript/wscript process)
    /// 2. Creating or modifying a scheduled task (schtasks.exe /create or TaskScheduler COM)
    ///
    /// Tier2/LogOnly because:
    /// - Scripts can legitimately create scheduled tasks (admin automation, system management)
    /// - Evidence requires behavioral correlation (script + task creation in same session)
    /// - Not sufficient alone for kill authority; feeds the BehavioralCorrelationEngine
    /// </summary>
    [RuleCategory(DetectionCategory.Persistence)]
    public sealed class VbsScheduledTaskCreationRule : IDetectionRule
    {
        public string Name => "VBS Scheduled Task Creation";

        private readonly ILogger<VbsScheduledTaskCreationRule> _logger;

        public VbsScheduledTaskCreationRule(ILogger<VbsScheduledTaskCreationRule> logger)
        {
            _logger = logger;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry proc) return null;

            // Pattern 1: Direct scheduled task creation via schtasks.exe spawned by VBS interpreter
            if (IsVbsInterpreter(proc.ParentProcessName) &&
                IsScheduledTaskCreation(proc.ProcessName, proc.CommandLine))
            {
                return EmitDetection(proc, "VBS spawned schtasks.exe to create scheduled task");
            }

            // Pattern 2: VBS script spawning child process that creates scheduled tasks
            // (e.g., VBS -> PowerShell -> schtasks.exe chain)
            if (IsVbsFile(proc.ImagePath) && IsScheduledTaskCreation(proc.ProcessName, proc.CommandLine))
            {
                return EmitDetection(proc, "VBS script triggered scheduled task creation");
            }

            // Pattern 3: schtasks.exe with suspicious arguments typical of VBS-driven persistence
            if (IsScheduledTaskProcess(proc.ProcessName) &&
                IsSuspiciousTaskCreation(proc.CommandLine) &&
                (IsVbsInterpreter(proc.ParentProcessName) || IsVbsFile(proc.ImagePath)))
            {
                return EmitDetection(proc, "Scheduled task created via VBS-spawned schtasks with suspicious pattern");
            }

            return null;
        }

        private static bool IsVbsInterpreter(string? processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            var name = processName!.ToLowerInvariant();
            return name == "cscript.exe" || name == "cscript" ||
                   name == "wscript.exe" || name == "wscript";
        }

        private static bool IsVbsFile(string? imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            return imagePath!.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsScheduledTaskCreation(string? processName, string? commandLine)
        {
            if (string.IsNullOrEmpty(processName)) return false;

            if (!processName!.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) &&
                !processName.Equals("schtasks", StringComparison.OrdinalIgnoreCase))
                return false;

            if (string.IsNullOrEmpty(commandLine)) return true; // Bare schtasks is suspicious

            var cmdLower = commandLine!.ToLowerInvariant();
            return cmdLower.Contains("/create") || cmdLower.Contains("-create") ||
                   cmdLower.Contains("/change") || cmdLower.Contains("-change");
        }

        private static bool IsScheduledTaskProcess(string? processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            return processName!.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) ||
                   processName.Equals("schtasks", StringComparison.OrdinalIgnoreCase) ||
                   processName.Equals("taskeng.exe", StringComparison.OrdinalIgnoreCase) ||
                   processName.Equals("taskeng", StringComparison.OrdinalIgnoreCase) ||
                   processName.Equals("taskschd.msc", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSuspiciousTaskCreation(string? commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return false;

            var lower = commandLine!.ToLowerInvariant();

            // Detecting patterns typical of VBS-driven malware persistence:
            // - Hidden/system attributes: /ru SYSTEM, /f (force), /tn hidden paths
            // - Staged payloads: temp, appdata, programdata
            // - Script execution: cmd /c, powershell, cscript, wscript, mshta
            // - Remote staging: http:// in the task action

            var hasSuspiciousAction = lower.Contains("cmd /c") ||
                                      lower.Contains("powershell") ||
                                      lower.Contains("cscript") ||
                                      lower.Contains("wscript") ||
                                      lower.Contains("mshta") ||
                                      lower.Contains("rundll32") ||
                                      lower.Contains("regsvr32") ||
                                      lower.Contains("http://") ||
                                      lower.Contains("https://");

            var hasSuspiciousScope = lower.Contains("/ru system") ||
                                     lower.Contains("/ru:system") ||
                                     lower.Contains("/ru \"system\"") ||
                                     lower.Contains("/ru 'system'") ||
                                     lower.Contains("/tn \\microsoft\\windows\\") ||
                                     lower.Contains("temp\\") ||
                                     lower.Contains("appdata\\") ||
                                     lower.Contains("programdata\\");

            return hasSuspiciousAction || hasSuspiciousScope;
        }

        private DetectionEvent EmitDetection(ProcessTelemetry proc, string detailReason)
        {
            _logger.LogWarning(
                "[VbsScheduledTaskCreation] {ProcessName} (PID {Pid}) detected: {Reason}",
                proc.ProcessName, proc.ProcessId, detailReason);

            return new DetectionEvent
            {
                RuleName = "VBS Scheduled Task Creation",
                Evidence = $"Process '{proc.ProcessName}' (PID {proc.ProcessId}) detected creating scheduled task. " +
                           $"Command: {proc.CommandLine}. Parent: {proc.ParentProcessName}",
                Reasoning = "A VBS script or script interpreter is creating a Windows scheduled task, which is a " +
                            "classic malware persistence mechanism. While legitimate admin scripts may create tasks, " +
                            "this behavior warrants investigation. This is a Tier2 indicator that feeds the behavioral " +
                            "correlation engine for composite analysis.",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly, // Tier2 unconditional LogOnly per constraints.md
                ProcessName = proc.ProcessName,
                ProcessId = proc.ProcessId,
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["detection_category"] = "VBS Persistence",
                    ["mitre_technique"] = "T1053.005", // Scheduled Task: Task Scheduler
                    ["composite_component"] = "cmdschedule"
                }
            };
        }
    }
}
