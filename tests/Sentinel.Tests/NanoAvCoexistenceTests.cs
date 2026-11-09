using System;
using System.IO;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class NanoAvCoexistenceTests
{
    [WindowsContainmentFact]
    public void SentinelExemptsCoInstalledNanoAvButNotACopyElsewhere()
    {
        Assert.True(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(AppContext.BaseDirectory, "NanoAV.exe")));
        Assert.False(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(Path.GetTempPath(), "NanoAV.exe")));
        Assert.False(SelfPathGuard.IsInstalledNanoAvBinary(Path.Combine(AppContext.BaseDirectory, "NanoAV-other.exe")));
    }

    [Theory]
    [InlineData("identical", true)]
    [InlineData("modified", false)]
    [InlineData("elsewhere", false)]
    [InlineData("missing-source", false)]
    [InlineData("missing-copy", false)]
    [InlineData("no-path", false)]
    public void RuntimeCopyExemptionRequiresExactPathAndPayload(string scenario, bool expected)
    {
        string directory = Path.Combine(Path.GetTempPath(), "NanoAvCopy_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string source = Path.Combine(directory, "NanoAV.exe");
            string copy = Path.Combine(directory, "NanoAV.dll");
            File.WriteAllText(source, "fixture payload");
            File.WriteAllText(copy, "fixture payload");
            string? requested = copy;
            if (scenario == "modified") File.WriteAllText(copy, "modifiedpayload");
            if (scenario == "elsewhere")
            {
                requested = Path.Combine(directory, "outside-NanoAV.dll");
                File.Copy(copy, requested);
            }
            if (scenario == "missing-source") File.Delete(source);
            if (scenario == "missing-copy") File.Delete(copy);
            if (scenario == "no-path") requested = null;
            Assert.Equal(expected, SelfPathGuard.MatchesNanoAvRuntimeCopy(requested, source, copy));
        }
        finally { Directory.Delete(directory, true); }
    }
}
