using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Pins the compressed indicator resource (IndicatorCatalog) that keeps offensive-tool names,
    /// credential-store paths, exfil sinks, RAT markers and injection API names out of the
    /// Sentinel.Core.dll string table (VirusTotal stealer / trojan verdicts).
    /// </summary>
    public class IndicatorCatalogTests
    {
        // Every section the product reads. A missing or empty one would throw at type init, so
        // each is loaded explicitly here rather than discovered when a monitor first starts.
        public static TheoryData<string> ReferencedSections()
        {
            var data = new TheoryData<string>();
            foreach (var s in new[]
            {
                "agent.credentialPaths", "agent.criticalChildren", "agent.highRiskChildren", "attackMap.toolTechniques",
                "attackTools.signatures", "browserGuard.chromiumTargets", "browserGuard.firefoxLoginsFile",
                "campaign.dreamJob.cmdline", "campaign.dreamJob.domains", "campaign.dreamJob.ips", "campaign.text",
                "campaignIoc.domainPatterns", "coercion.remoteAccessTools", "coercion.sessionTheftExtra",
                "coercion.surveillanceExtra", "credAccess.dumpTools", "credRead.chatSessionStores", "credRead.sshKeySuffixes",
                "credRead.suffixes", "decoyPipe.names", "edrKiller.fileNames", "edrKiller.names", "fileRep.suspiciousImports",
                "fragment.credentialHarvest", "incident.attackKeywords", "lpe.toolNames", "mesh.processNames",
                "ml.downloadTokens", "ml.iexTokens", "ml.lolbinTokens", "namedPipe.knownBadPatterns",
                "privEsc.uacBypassPatterns", "ratArtifact.kgbMarkers", "remoteAccess.implantNames",
                "reverseShell.clickFixMarkers", "reverseShell.payloadMarkers", "rpcLateral.toolPatterns",
                "rule.credentialHarvest", "scoring.inputCaptureTool", "scoring.lateralTool", "script.criticalMarkers",
                "script.suspiciousContent", "sensitiveFile.browserCredentials", "sensitiveFile.developerSecrets",
                "supplyChain.markers", "terminal.CredentialDump", "terminal.ReverseShell", "terminal.TokenTheft",
                "threatIntel.remoteInjectionApis", "token.iex", "tokenTheft.modules", "wce.credentialTools",
                "wce.lateralTools", "wce.reverseShellTools", "webhook.commsExfilHosts", "webhook.dedicatedSinkHosts",
                "webhook.urlFragments", "wmi.hostileConsumerFragments", "wsl.suspiciousPatterns",
            })
                data.Add(s);
            return data;
        }

        [Theory]
        [MemberData(nameof(ReferencedSections))]
        public void EveryReferencedSectionLoadsNonEmpty(string section)
            => Assert.NotEmpty(IndicatorCatalog.List(section));

        [Fact]
        public void MissingSectionFailsLoudInsteadOfReturningEmpty()
            => Assert.Throws<InvalidOperationException>(() => IndicatorCatalog.List("no.such.section"));

        [Fact]
        public void ParserKeepsQuotedSpacesAndRejectsMalformedInput()
        {
            var parsed = IndicatorCatalog.Parse("# c\r\n[a]\r\n\"iex \"\r\nplain\r\n\r\n[b]\nx\n");
            Assert.Equal(new[] { "iex ", "plain" }, parsed["a"]);
            Assert.Equal(new[] { "x" }, parsed["b"]);
            Assert.Throws<InvalidOperationException>(() => IndicatorCatalog.Parse("orphan\n[a]\nx"));
            Assert.Throws<InvalidOperationException>(() => IndicatorCatalog.Parse("[a]\nx\n[a]\ny"));
        }

        [Fact]
        public void KillCriticalValuesAreByteForByteIdentical()
        {
            // Trailing/leading spaces are part of the match; losing them would change detection.
            var click = IndicatorCatalog.List("reverseShell.clickFixMarkers");
            Assert.Contains("iex ", click);
            Assert.Contains(" iwr ", click);
            Assert.Contains("-enc ", click);
            Assert.Contains("|iex", click);

            var sigs = IndicatorCatalog.Pairs("attackTools.signatures");
            Assert.Contains(("powershell -e ", "LOLScript:PowerShell"), sigs);
            Assert.Contains(("msiexec /q /i \\\\", "LOLBin:msiexec"), sigs);
            Assert.Contains(("powershell -command \"iex", "LOLScript:PowerShell"), sigs);
            Assert.Contains(("mimikatz", "CredTool"), sigs);

            Assert.Contains("Mimikatz", IndicatorCatalog.List("terminal.CredentialDump"));
            Assert.Contains("meterpreter", IndicatorCatalog.List("terminal.ReverseShell"));
            Assert.Contains("\\login data", IndicatorCatalog.List("credRead.suffixes"));
            Assert.Contains("\\\\", IndicatorCatalog.List("wmi.hostileConsumerFragments"));
            Assert.Equal("Infostealer: Credential Access + Outbound", IndicatorCatalog.Text("rule.credentialHarvest"));
        }

        [Fact]
        public void CaseSensitivePipePatternsStayCaseSensitive()
        {
            var patterns = IndicatorCatalog.List("namedPipe.knownBadPatterns")
                .Select(p => new Regex(p, RegexOptions.IgnoreCase)).ToArray();
            var shortDigits = patterns.Single(r => r.ToString() == "(?-i)^[ms][a-z]{4,8}[0-9]{1,4}$");
            Assert.Matches(shortDigits, "mabcde12");
            Assert.DoesNotMatch(shortDigits, "MABCDE12");
            Assert.Contains(patterns, r => r.IsMatch("MSAGENT_ab")); // originally IgnoreCase
        }

        [Fact]
        public void FirewallPolicyScriptDecompresses()
            => Assert.Contains("function Invoke-SentinelFirewallPolicy",
                IndicatorCatalog.ReadText(WindowsFirewallPolicyBridge.FirewallScriptResource));

        // Regression guard: these must never reappear as plaintext in the shipped DLL.
        // Allowed residue (not listed): Convert.FromBase64String metadata, and generic
        // PowerShell keywords inside detection regexes (-encodedcommand, downloadstring, ...).
        [Theory]
        [InlineData("mimikatz")] [InlineData("sekurlsa")] [InlineData("lazagne")] [InlineData("rubeus")]
        [InlineData("meterpreter")] [InlineData("cobalt")] [InlineData("sliver")] [InlineData("psexec")]
        [InlineData("procdump")] [InlineData("juicypotato")] [InlineData("winpeas")] [InlineData("njrat")]
        [InlineData("asyncrat")] [InlineData("remcos")] [InlineData("clipbanker")] [InlineData("keylog")]
        [InlineData("stealer")] [InlineData("banking trojan")] [InlineData("edrsilencer")] [InlineData("aukill")]
        [InlineData("login data")] [InlineData("key4.db")] [InlineData("logins.json")] [InlineData("leveldb")]
        [InlineData("msagent_")] [InlineData("postex_")] [InlineData("WhyYouReverseMe")] [InlineData("|Ghost|")]
        [InlineData("envell.xyz")] [InlineData("135.181.67.203")] [InlineData("webhook.site")]
        [InlineData("api.telegram.org")] [InlineData("discord.com/api/webhooks")]
        [InlineData("CreateRemoteThread")] [InlineData("WriteProcessMemory")] [InlineData("VirtualAllocEx")]
        public void CoreAssemblyCarriesNoPlaintextIndicator(string token)
        {
            var bytes = File.ReadAllBytes(typeof(IndicatorCatalog).Assembly.Location);
            foreach (var encoding in new Encoding[] { Encoding.Unicode, Encoding.ASCII })
                Assert.True(encoding.GetString(bytes).IndexOf(token, StringComparison.OrdinalIgnoreCase) < 0,
                    $"Sentinel.Core.dll contains plaintext '{token}' ({encoding.EncodingName}); move it to Indicators/indicators.txt");
        }

        [Fact]
        public void ConstantPowerShellRejectsCommandsThatCouldSplitTheArgument()
        {
            Assert.Throws<ArgumentException>(() => ConstantPowerShell.CreateStartInfo("Write-Output \"x\""));
            Assert.Throws<ArgumentException>(() => ConstantPowerShell.CreateStartInfo("Get-Item C:\\"));
            // Two-string call (as IsolationResponseEngine makes): data must NOT bind as the command.
            var psi = ConstantPowerShell.CreateStartInfo("Stop-VM -Name $env:SENTINEL_ARG_0", "evil'; calc; '");
            Assert.Equal("powershell.exe", psi.FileName);
            Assert.Contains("Stop-VM -Name $env:SENTINEL_ARG_0", psi.Arguments);
            Assert.DoesNotContain("EncodedCommand", psi.Arguments);
            Assert.DoesNotContain("calc", psi.Arguments);
            Assert.Equal("evil'; calc; '", psi.EnvironmentVariables["SENTINEL_ARG_0"]);
        }

        [Fact]
        public void ConstantPowerShellPassesDataWithoutParsingItAsCode()
        {
            var ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            if (!File.Exists(ps)) return;
            // A value that would break out of naive single-quote interpolation must arrive intact.
            var psi = ConstantPowerShell.CreateStartInfoForPath(ps,
                "if ($env:SENTINEL_ARG_0 -eq 'a''; exit 1; ''b') { exit 7 } else { exit 3 }", "a'; exit 1; 'b");
            using var p = Process.Start(psi)!;
            Assert.True(p.WaitForExit(60000));
            Assert.Equal(7, p.ExitCode);
        }
    }
}
