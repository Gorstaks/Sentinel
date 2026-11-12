using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class AuditWindowsRegressionTests
    {
        [Theory]
        [InlineData(@"C:\Users\alice\AppData\Local\Programs\epic games\payload.exe")]
        [InlineData(@"C:\Users\alice\steamapps\common\payload.exe")]
        [InlineData(@"C:\Games\steamapps\common\payload.exe")]
        public void WritableGameDirectoryDoesNotGrantResponseImmunity(string path)
        {
            Assert.False(AlwaysOnPolicies.IsProtectedGamePath(path));
            var detection = new DetectionEvent { Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree };
            Assert.False(AlwaysOnPolicies.ApplyGameProtection(detection, path));
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
        }

        [Fact]
        public void InstallerPreservesPreviousExecutableDigestBeforeCleanup()
        {
            var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var old = Path.Combine(directory, "Sentinel.Service.exe.old");
                File.WriteAllBytes(old, new byte[] { 4, 5, 6 });
                SecureCacheStore.PreserveLegacyExecutableHashes(directory);
                using var sha = SHA256.Create();
                Assert.Equal(sha.ComputeHash(File.ReadAllBytes(old)),
                    File.ReadAllBytes(Path.Combine(directory, "Sentinel.Service.exe.cache-legacy-sha256")));
            }
            finally { Directory.Delete(directory, true); }
        }

        [Fact]
        public void CacheKeyIsStableAndIncompatiblePolicyIsPreservedBeforeReplacement()
        {
            var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                var store = new SecureCacheStore(directory);
                store.Save("policy", "domains", "example.invalid");
                var reopened = new SecureCacheStore(directory);
                Assert.Equal("example.invalid", reopened.Load("policy", "domains"));
                var cache = Path.Combine(directory, "policy.cache");
                File.WriteAllBytes(cache, new byte[] { 1, 2, 3 });
                Assert.Null(reopened.Load("policy", "domains"));
                Assert.True(File.Exists(cache));
                reopened.Save("policy", "domains", "replacement.invalid");
                var backup = Assert.Single(Directory.GetFiles(directory, "policy.cache.incompatible-*"));
                Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(backup));
                Assert.Equal("replacement.invalid", reopened.Load("policy", "domains"));
                var method = typeof(SecureCacheStore).GetMethod("GenerateBootBoundKey", BindingFlags.Static | BindingFlags.NonPublic)!;
                var stable = (byte[])method.Invoke(null, new object[] { directory, false, false })!;
                var legacy = (byte[])method.Invoke(null, new object[] { directory, false, true })!;
                Assert.False(stable.SequenceEqual(legacy));
                var raw = Encoding.UTF8.GetBytes("domains:legacy.invalid");
                using var hmac = new HMACSHA256(legacy);
                var payload = hmac.ComputeHash(raw).Concat(raw).ToArray();
                var protect = typeof(SecureCacheStore).GetMethod("Protect", BindingFlags.Static | BindingFlags.NonPublic)!;
                File.WriteAllBytes(cache, (byte[])protect.Invoke(null, new object[] { payload })!);
                Assert.Equal("legacy.invalid", reopened.Load("policy", "domains"));
                var unprotect = typeof(SecureCacheStore).GetMethod("Unprotect", BindingFlags.Static | BindingFlags.NonPublic)!;
                var migrated = (byte[])unprotect.Invoke(null, new object[] { File.ReadAllBytes(cache) })!;
                using var stableHmac = new HMACSHA256(stable);
                Assert.Equal(stableHmac.ComputeHash(raw), migrated.Take(32).ToArray());
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }
    }
}
