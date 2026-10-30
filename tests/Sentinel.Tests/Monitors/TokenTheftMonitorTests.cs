using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for TokenTheftMonitor - verifies path classification, legitimate system
    /// token holder detection, impersonator allowlisting, and OS process identification.
    /// </summary>
    public class TokenTheftMonitorTests
    {
        // 
        // IsSuspiciousPath - staging/drop locations
        // 

        [Theory]
        [InlineData(@"C:\Users\victim\AppData\Local\Temp\payload.exe")]
        [InlineData(@"C:\Windows\Temp\dropper.exe")]
        [InlineData(@"C:\Users\victim\Downloads\exploit.exe")]
        [InlineData(@"C:\Users\Public\malware.exe")]
        [InlineData(@"C:\ProgramData\Temp\stager.exe")]
        [InlineData(@"C:\Users\victim\Desktop\evil.exe")]
        public void IsSuspiciousPath_ReturnsTrue_ForDropLocations(string path)
        {
            Assert.True(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Theory]
        [InlineData(@"C:\Program Files\App\legitimate.exe")]
        [InlineData(@"C:\Program Files (x86)\Tool\tool.exe")]
        [InlineData(@"C:\Windows\System32\svchost.exe")]
        [InlineData("")]
        [InlineData(null)]
        public void IsSuspiciousPath_ReturnsFalse_ForLegitPaths(string? path)
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(path!));
        }

        // 
        // v3.5.2 regression: Windows Update / MSRT servicing paths are trusted SYSTEM-token
        // locations, not suspicious drops. The Malicious Software Removal Tool
        // (Windows-KB890830) was killed because its SoftwareDistribution staging path was
        // classified as neither a service path nor Program Files, falling into the kill branch.
        // 

        [Theory]
        [InlineData(@"C:\Windows\SoftwareDistribution\Download\Install\Windows-KB890830-x64-V5.146.exe")]
        [InlineData(@"C:\Windows\servicing\TrustedInstaller.exe")]
        [InlineData(@"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_x\TiWorker.exe")]
        [InlineData(@"C:\Windows\UUS\amd64\MoUsoCoreWorker.exe")]
        public void ServicingPaths_AreTrustedSystemImagePaths(string path)
        {
            // The anchor used to exempt a whitelisted name must accept genuine servicing trees.
            Assert.True(TokenTheftMonitor.IsTrustedSystemImagePath(path),
                $"expected servicing path to be trusted: {path}");
        }

        [Theory]
        [InlineData(@"C:\Windows\SoftwareDistribution\Download\Install\Windows-KB890830-x64-V5.146.exe")]
        [InlineData(@"C:\Windows\servicing\TrustedInstaller.exe")]
        public void ServicingPaths_AreNotSuspicious(string path)
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Theory]
        // A \temp segment inside a servicing-looking path must still be rejected (anti-slip).
        [InlineData(@"C:\Windows\SoftwareDistribution\Download\Temp\evil.exe")]
        [InlineData(@"C:\Users\victim\AppData\Local\Temp\Windows-KB890830-x64.exe")]
        public void ServicingLookalikeDropPaths_AreNotTrusted(string path)
        {
            Assert.False(TokenTheftMonitor.IsTrustedSystemImagePath(path),
                $"a drop path merely resembling a servicing path must not be trusted: {path}");
        }

        // 
        // IsLegitimateSystemTokenHolder - known SYSTEM services
        // 

        [Theory]
        [InlineData("svchost")]
        [InlineData("svchost.exe")]
        [InlineData("lsass")]
        [InlineData("services")]
        [InlineData("csrss")]
        [InlineData("wininit")]
        [InlineData("smss")]
        [InlineData("MsMpEng")]
        public void IsLegitimateSystemTokenHolder_ReturnsTrue_ForSystemServices(string name)
        {
            Assert.True(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Theory]
        [InlineData("malware.exe")]
        [InlineData("beacon.exe")]
        [InlineData("unknown")]
        [InlineData("")]
        [InlineData(null)]
        public void IsLegitimateSystemTokenHolder_ReturnsFalse_ForUnknown(string? name)
        {
            Assert.False(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name!));
        }

        // 
        // IsLegitimateImpersonator - services that legitimately impersonate
        // 

        [Theory]
        [InlineData("sqlservr")]
        [InlineData("w3wp")]
        [InlineData("iisexpress")]
        public void IsLegitimateImpersonator_ReturnsTrue_ForKnownServices(string name)
        {
            Assert.True(TokenTheftMonitor.IsLegitimateImpersonator(name));
        }

        [Theory]
        [InlineData("evil.exe")]
        [InlineData("mimikatz")]
        [InlineData("")]
        public void IsLegitimateImpersonator_ReturnsFalse_ForUnknown(string name)
        {
            Assert.False(TokenTheftMonitor.IsLegitimateImpersonator(name));
        }

        // 
        // IsLikelyProtectedOsProcess
        // 

        [Theory]
        [InlineData("svchost")]
        [InlineData("Registry")]
        [InlineData("Memory Compression")]
        [InlineData("Secure System")]
        public void IsLikelyProtectedOsProcess_ReturnsTrue_ForOsProcesses(string name)
        {
            Assert.True(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("notepad")]
        [InlineData("malware.exe")]
        public void IsLikelyProtectedOsProcess_ReturnsFalse_ForUserProcesses(string name)
        {
            Assert.False(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
        }

        // 
        // Token theft signal model
        // 

        [Fact]
        public void TokenTheftSignal_SystemToken_Model()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 1234,
                ProcessName = "evil.exe",
                TokenUserName = "NT AUTHORITY\\SYSTEM",
                TheftType = TokenTheftType.SystemTokenFromUserProcess,
                ImagePath = @"C:\Temp\evil.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(TokenTheftType.SystemTokenFromUserProcess, signal.TheftType);
            Assert.True(signal.HasImpersonatePrivilege);
        }

        [Fact]
        public void TokenTheft_IsPresidentsLaw()
        {
            // Privilege escalation = President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("SeImpersonatePrivilege from Suspicious Path"));
        }
    }
}
