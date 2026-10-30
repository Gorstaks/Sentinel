using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Regression coverage for the v3.5.2 Windows OS-image servicing-actor trust gate.
    ///
    /// The gate is what prevents Sentinel from terminating legitimate Windows servicing
    /// processes (TrustedInstaller/TiWorker tripping the mass-deletion rule, the Windows
    /// Update standalone installer / MSRT tripping the SYSTEM-integrity-jump rule). It must
    /// grant trust ONLY when anchored on non-attacker-controllable facts:
    ///   (1) the image lives in a trusted, ACL-protected OS servicing tree, AND
    ///   (2) the binary carries a valid Microsoft signature.
    /// Process name alone - which an attacker fully controls - must never grant trust.
    ///
    /// The test project targets net48-windows, so these assertions run against the real OS
    /// binaries present on the Windows test host.
    /// </summary>
    public class WindowsServicingTrustTests
    {
        private static string System32 =>
            Environment.GetFolderPath(Environment.SpecialFolder.System);

        // 
        // Trusted-tree path classification (anchor #1)
        // 

        [Fact]
        public void System32_IsTrustedServicingTree()
        {
            var svchost = Path.Combine(System32, "svchost.exe"); // always present, catalog-signed
            Assert.True(File.Exists(svchost), $"expected {svchost} to exist on a Windows host");
            Assert.True(WindowsServicingTrust.IsInTrustedServicingTree(svchost));
        }

        [Fact]
        public void WinSxS_IsTrustedServicingTree()
        {
            var winDir = Path.GetDirectoryName(System32)!;
            var winsxs = Path.Combine(winDir, "WinSxS", "anything.dll");
            Assert.True(WindowsServicingTrust.IsInTrustedServicingTree(winsxs));
        }

        [Fact]
        public void SoftwareDistribution_IsTrustedServicingTree()
        {
            var winDir = Path.GetDirectoryName(System32)!;
            var wu = Path.Combine(winDir, "SoftwareDistribution", "Download", "staged.exe");
            Assert.True(WindowsServicingTrust.IsInTrustedServicingTree(wu));
        }

        [Fact]
        public void UserWritablePaths_AreNotTrustedTrees()
        {
            // These must NEVER be trusted - they are attacker-plantable.
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(@"C:\Users\victim\Downloads\tiworker.exe"));
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(@"C:\Users\victim\AppData\Local\Temp\dism.exe"));
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(@"C:\ProgramData\evil\Windows-KB890830-x64.exe"));
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(@"C:\Temp\trustedinstaller.exe"));
        }

        [Fact]
        public void EmptyOrNullPath_IsNotTrusted()
        {
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(null));
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree(""));
            Assert.False(WindowsServicingTrust.IsInTrustedServicingTree("   "));
        }

        // 
        // Full authoritative check: tree AND Microsoft signature (both anchors)
        // 

        [Fact]
        public void GenuineSystem32Binary_IsServicingActor()
        {
            // svchost.exe: in System32 (trusted tree) and Microsoft catalog-signed. Both anchors hold.
            var svchost = Path.Combine(System32, "svchost.exe");
            Assert.True(File.Exists(svchost));
            Assert.True(WindowsServicingTrust.IsGenuineServicingActor(svchost));
        }

        [Fact]
        public void TrustedInstaller_IsServicingActor()
        {
            var winDir = Path.GetDirectoryName(System32)!;
            var ti = Path.Combine(winDir, "servicing", "TrustedInstaller.exe");
            if (!File.Exists(ti))
                return; // not present on this host - nothing to assert
            Assert.True(WindowsServicingTrust.IsGenuineServicingActor(ti));
        }

        [Fact]
        public void TrustedNameInUserPath_IsNotServicingActor()
        {
            // The core anti-spoof guarantee: an attacker-named binary in a user-writable
            // path must fail the gate even though its NAME matches a servicing actor.
            Assert.False(WindowsServicingTrust.IsGenuineServicingActor(@"C:\Users\victim\Downloads\TiWorker.exe"));
            Assert.False(WindowsServicingTrust.IsGenuineServicingActor(@"C:\ProgramData\x\Windows-KB890830-x64-V5.146.exe"));
        }

        [Fact]
        public void SignedBinaryOutsideTrustedTree_IsNotServicingActor()
        {
            // Copy a genuinely Microsoft-signed System32 binary OUT to a user-writable temp path.
            // Signature anchor holds, but the trusted-tree anchor fails -> must NOT be trusted.
            var src = Path.Combine(System32, "svchost.exe");
            if (!File.Exists(src))
                return;
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-svc-trust-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var dst = Path.Combine(dir, "svchost.exe");
            try
            {
                File.Copy(src, dst, overwrite: true);
                Assert.False(WindowsServicingTrust.IsGenuineServicingActor(dst),
                    "a signed OS binary copied into a user-writable path must not be treated as a servicing actor");
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { }
            }
        }

        [Fact]
        public void KernelAndInvalidPids_AreNotServicingActors()
        {
            Assert.False(WindowsServicingTrust.IsGenuineServicingActor(0));
            Assert.False(WindowsServicingTrust.IsGenuineServicingActor(4));
            Assert.False(WindowsServicingTrust.IsGenuineServicingActor(-1));
        }

        // 
        // Name advisory (never a trust decision on its own)
        // 

        [Theory]
        [InlineData("tiworker")]
        [InlineData("TiWorker.exe")]
        [InlineData("TrustedInstaller")]
        [InlineData("dism")]
        [InlineData("wusa")]
        [InlineData("mrt")]
        [InlineData("Windows-KB890830-x64-V5.146")]
        public void KnownServicingNames_AreRecognizedByNameAdvisory(string name)
        {
            Assert.True(WindowsServicingTrust.NameLooksLikeServicingActor(name));
        }

        [Theory]
        [InlineData("evil")]
        [InlineData("notepad")]
        [InlineData("")]
        [InlineData(null)]
        public void UnknownNames_AreNotServicingActorNames(string? name)
        {
            Assert.False(WindowsServicingTrust.NameLooksLikeServicingActor(name));
        }

        // 
        // Strict gate (response chokepoint): must NOT protect signed LOLBins
        // 

        [Theory]
        [InlineData("powershell")]
        [InlineData("cmd")]
        [InlineData("rundll32")]
        [InlineData("mshta")]
        [InlineData("regsvr32")]
        [InlineData("notepad")]
        public void StrictGate_DoesNotProtectSignedLolbins(string lolbin)
        {
            // Even though these are Microsoft-signed and live in System32 (so the broad
            // IsGenuineServicingActor would trust them), the strict gate used at the response
            // chokepoint must reject them by name - they are legitimately killable when weaponized.
            var path = Path.Combine(System32, lolbin + ".exe");
            Assert.False(WindowsServicingTrust.IsGenuineServicingActorStrict(lolbin, path),
                $"strict gate must not protect signed LOLBin '{lolbin}'");
        }

        [Fact]
        public void StrictGate_ProtectsGenuineNamedServicingActor()
        {
            // TrustedInstaller: name advisory matches AND it passes both anchors (servicing tree
            // + Microsoft catalog signature). This is the case the response gate must protect.
            var winDir = Path.GetDirectoryName(System32)!;
            var ti = Path.Combine(winDir, "servicing", "TrustedInstaller.exe");
            if (!File.Exists(ti)) return; // not present on this host
            Assert.True(WindowsServicingTrust.IsGenuineServicingActorStrict("TrustedInstaller", ti));
        }

        [Fact]
        public void StrictGate_RejectsServicingNameInUserPath()
        {
            // Correct name, but user-writable path -> strict gate must reject (tree anchor fails).
            Assert.False(WindowsServicingTrust.IsGenuineServicingActorStrict(
                "TiWorker", @"C:\Users\victim\Downloads\TiWorker.exe"));
        }
    }
}
