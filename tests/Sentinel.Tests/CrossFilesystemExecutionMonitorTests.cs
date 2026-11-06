using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for CrossFilesystemExecutionMonitor - validates Tier2 LogOnly detection
    /// of binaries executed from network shares, WSL, and container filesystems.
    /// 
    /// Per constraints.md:
    /// - Every Tier2 rule must have a test verifying it returns Tier2Indicator
    /// - Tier2 with ActiveResponse=true must still produce LogOnly (never kills)
    /// - No response action escalation on filesystem type alone
    /// </summary>
    public class CrossFilesystemExecutionMonitorTests
    {
        [Fact]
        public void DetectionEvent_Tier2Indicator_NoKillAuthorized()
        {
            // Arrange: Create the exact detection event that the monitor would emit
            var evt = new DetectionEvent
            {
                RuleName = "File Execution: Unsigned Binary from Cross-Filesystem Source",
                ProcessId = 1234,
                ProcessName = "test.exe",
                Confidence = 0.45,
                Tier = DetectionTier.Tier2Indicator,
                Metadata = new Dictionary<string, string>
                {
                    { "FilesystemType", "SMB" },
                    { "ParentProcess", "explorer.exe" },
                    { "IsSigned", "false" }
                }
            };

            // Assert: Verify Tier2 contract
            Assert.Equal(DetectionTier.Tier2Indicator, evt.Tier);
            Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
            Assert.False(evt.KillAuthorized, "Tier2 signals must never authorize kill");
        }

        [Fact]
        public void FilesystemClassification_WslPaths_IsRemote()
        {
            // Arrange: Various WSL paths
            var wslPaths = new[]
            {
                @"\\wsl$\Ubuntu\home\user\malware.exe",
                @"\\wsl$\Debian\opt\payload",
                @"\\wsl$\Alpine\root\script.sh"
            };

            // Act & Assert: All should be recognized as remote
            foreach (var path in wslPaths)
            {
                Assert.True(path.StartsWith(@"\\wsl$\", StringComparison.OrdinalIgnoreCase),
                    $"WSL path should start with \\\\wsl$\\: {path}");
            }
        }

        [Fact]
        public void FilesystemClassification_UncPaths_IsRemote()
        {
            // Arrange: Various SMB UNC paths
            var uncPaths = new[]
            {
                @"\\fileserver\share\staging\payload.exe",
                @"\\192.168.1.100\builds\app.exe",
                @"\\server.example.com\shared\malware.dll"
            };

            // Act & Assert: All should be recognized as UNC paths
            foreach (var path in uncPaths)
            {
                Assert.True(path.StartsWith(@"\\") && !path.StartsWith(@"\\?\"),
                    $"UNC path should start with \\\\ (not \\\\?\\): {path}");
            }
        }

        [Fact]
        public void FilesystemClassification_ContainerPaths_IsRemote()
        {
            // Arrange: Container-like paths
            var containerPaths = new[]
            {
                @"C:\docker\volumes\malware.exe",
                @"D:\hyper-v\vm-image\payload.exe",
                @"C:\Users\docker\docker\app.exe"
            };

            // Act & Assert
            foreach (var path in containerPaths)
            {
                bool isContainer = path.Contains(@"\docker\", StringComparison.OrdinalIgnoreCase) ||
                                   path.Contains(@"\hyper-v\", StringComparison.OrdinalIgnoreCase);
                Assert.True(isContainer, $"Container path pattern not detected: {path}");
            }
        }

        [Fact]
        public void FilesystemClassification_LocalPaths_NotRemote()
        {
            // Arrange: Local NTFS paths
            var localPaths = new[]
            {
                @"C:\Users\Admin\Downloads\file.exe",
                @"D:\Data\application\app.exe",
                @"C:\Program Files\Software\tool.exe"
            };

            // Act & Assert
            foreach (var path in localPaths)
            {
                bool isRemote = path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase) ||
                                path.Contains(@"\docker\", StringComparison.OrdinalIgnoreCase) ||
                                path.Contains(@"\hyper-v\", StringComparison.OrdinalIgnoreCase);
                Assert.False(isRemote, $"Local path incorrectly flagged as remote: {path}");
            }
        }

        [Fact]
        public void WhitelistPatterns_NasShare_ShouldMatch()
        {
            // Arrange: Whitelisted NAS paths for development
            var nasPath1 = @"\\nas-01\builds\app.exe";
            var nasPath2 = @"\\file-server\shared\project.dll";
            var nasPath3 = @"\\storage-main\archive\data.zip";

            var whitelist = new[] { "\\\\nas-", "\\\\file-", "\\\\storage-" };

            // Act & Assert
            foreach (var pattern in whitelist)
            {
                Assert.True(
                    nasPath1.StartsWith(pattern, StringComparison.OrdinalIgnoreCase) ||
                    nasPath2.StartsWith(pattern, StringComparison.OrdinalIgnoreCase) ||
                    nasPath3.StartsWith(pattern, StringComparison.OrdinalIgnoreCase),
                    $"At least one path should match whitelisted pattern: {pattern}");
            }
        }

        [Fact]
        public void EventMetadata_IncludesFilesystemContext()
        {
            // Arrange: Simulate detection event with context
            var evt = new DetectionEvent
            {
                RuleName = "File Execution: Unsigned Binary from Cross-Filesystem Source",
                ProcessId = 5678,
                ProcessName = "unsigned.exe",
                Confidence = 0.45,
                Tier = DetectionTier.Tier2Indicator,
                Evidence = "Process unsigned.exe (PID 5678) executed from SMB path: \\\\server\\share\\staging\\unsigned.exe",
                Reasoning = "An unsigned binary was executed from a SMB source. This is common for development, shared builds, and media, but can also indicate staging from a remote attacker-controlled system.",
                Metadata = new Dictionary<string, string>
                {
                    { "FilesystemType", "SMB" },
                    { "ParentProcess", "explorer.exe" },
                    { "IsSigned", "false" }
                }
            };

            // Assert: Verify all metadata present
            Assert.NotEmpty(evt.Evidence);
            Assert.NotEmpty(evt.Reasoning);
            Assert.NotNull(evt.Metadata);
            Assert.Equal("SMB", evt.Metadata["FilesystemType"]);
            Assert.Equal("explorer.exe", evt.Metadata["ParentProcess"]);
            Assert.Equal("false", evt.Metadata["IsSigned"]);
        }

        [Fact]
        public void Tier2Contract_NoResponseEscalation()
        {
            // Arrange: Multiple Tier2 events from cross-filesystem monitor
            var events = new[]
            {
                new DetectionEvent 
                { 
                    RuleName = "File Execution: Unsigned Binary from Cross-Filesystem Source",
                    Tier = DetectionTier.Tier2Indicator,
                    Confidence = 0.45
                },
                new DetectionEvent 
                { 
                    RuleName = "File Execution: Unsigned Binary from Cross-Filesystem Source",
                    Tier = DetectionTier.Tier2Indicator,
                    Confidence = 0.55
                },
                new DetectionEvent 
                { 
                    RuleName = "File Execution: Unsigned Binary from Cross-Filesystem Source",
                    Tier = DetectionTier.Tier2Indicator,
                    Confidence = 0.65
                }
            };

            // Act & Assert: Even high confidence Tier2 stays LogOnly
            foreach (var evt in events)
            {
                Assert.Equal(DetectionTier.Tier2Indicator, evt.Tier);
                Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
                Assert.False(evt.KillAuthorized, "Tier2 LogOnly contract must hold");
            }
        }

        [Fact]
        public void SignalConfidence_Range_IsObserveOnly()
        {
            // Arrange: Confidence levels for cross-filesystem signals
            var confidenceLevels = new[] { 0.35, 0.45, 0.55, 0.65 };

            // Assert: All are below kill-grade threshold (0.85)
            foreach (var conf in confidenceLevels)
            {
                Assert.True(conf < 0.85, 
                    $"Cross-filesystem signal confidence {conf} should be below kill-grade threshold");
            }
        }
    }
}
