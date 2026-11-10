using System;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - Allowlist and observed-target binding for <c>ResponseAction.RemoveRegistryEntry</c>.
    /// The executor used to delete whatever hive/key/value/subkey the event metadata named, guarded
    /// only by <c>Contains("Services")</c> / <c>Contains("CLSID")</c>. It now deletes only the three
    /// persistence shapes the monitors emit, only at their exact roots, and only when the live
    /// registry still matches what the monitor observed and still points at a user-writable
    /// location. Anything else is refused. Pure functions so the rules are unit-tested.
    /// </summary>
    public static class RegistryRemovalPolicy
    {
        private static readonly string[] RunRoots =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        private static readonly string[] ExtensionPolicyRoots =
        {
            @"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
            @"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
            @"Software\Policies\Chromium\ExtensionInstallForcelist",
        };

        public const string ServicesRoot = @"System\CurrentControlSet\Services";

        private static readonly Regex ServiceNamePattern = new Regex(@"^[A-Za-z0-9_.\-$ ]{1,256}$", RegexOptions.CultureInvariant);
        private static readonly Regex ClsidPattern = new Regex(@"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$", RegexOptions.CultureInvariant);

        // Sentinel's own services and the core security stack are never removable here.
        private static readonly string[] ProtectedServices =
        {
            "Sentinel", "SentinelGuard", "WinDefend", "WdNisSvc", "Sense", "MDCoreSvc", "SecurityHealthService",
            "EventLog", "BFE", "mpssvc", "RpcSs", "DcomLaunch", "LSM", "samss", "Winmgmt", "wuauserv", "TrustedInstaller",
        };

        public static bool ValueRemovalAllowed(string? hive, string? keyPath, string? valueName, out string reason)
        {
            reason = "";
            if (!string.Equals(hive, "HKLM", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(hive, "HKCU", StringComparison.OrdinalIgnoreCase))
            { reason = "hive not allowed"; return false; }
            if (string.IsNullOrEmpty(valueName) || valueName!.Length > 260 || HasControlCharacters(valueName))
            { reason = "invalid value name"; return false; }
            var key = (keyPath ?? "").Trim('\\');
            bool root = IsOneOf(key, RunRoots) ||
                        (IsOneOf(key, ExtensionPolicyRoots));
            if (!root) { reason = "key is not an allowed autorun or extension-policy root"; return false; }
            if (string.Equals(valueName, "SentinelAgent", StringComparison.OrdinalIgnoreCase))
            { reason = "Sentinel's own autorun value"; return false; }
            return true;
        }

        public static bool ServiceRemovalAllowed(
            string? keyPath, string? serviceName, string? liveImagePath, int? liveServiceType,
            string? observedImagePath, out string reason)
        {
            reason = "";
            if (!string.Equals((keyPath ?? "").Trim('\\'), ServicesRoot, StringComparison.OrdinalIgnoreCase))
            { reason = "key is not the Services root"; return false; }
            if (string.IsNullOrEmpty(serviceName) || !ServiceNamePattern.IsMatch(serviceName!))
            { reason = "invalid service name"; return false; }
            if (Array.Exists(ProtectedServices, p => string.Equals(p, serviceName, StringComparison.OrdinalIgnoreCase)))
            { reason = "protected service"; return false; }
            if (liveServiceType.HasValue && (liveServiceType.Value & 0x30) == 0)
            { reason = "not a Win32 service (driver or other type)"; return false; }
            if (string.IsNullOrEmpty(liveImagePath))
            { reason = "service has no readable image path"; return false; }
            if (!string.IsNullOrEmpty(observedImagePath) &&
                !string.Equals(observedImagePath!.Trim(), liveImagePath!.Trim(), StringComparison.OrdinalIgnoreCase))
            { reason = "image path changed since it was observed"; return false; }
            if (!IsUserWritableLocation(liveImagePath!))
            { reason = "image path is not in a user-writable location"; return false; }
            return true;
        }

        public static bool ClsidRemovalAllowed(
            string? keyPath, string? clsid, string? liveServerPath, string? observedServerPath, out string reason)
        {
            reason = "";
            if (string.IsNullOrEmpty(clsid) || !ClsidPattern.IsMatch(clsid!))
            { reason = "invalid CLSID"; return false; }
            var expectedKey = @"CLSID\" + clsid + @"\InprocServer32";
            if (!string.Equals((keyPath ?? "").Trim('\\'), expectedKey, StringComparison.OrdinalIgnoreCase))
            { reason = "key does not match the CLSID InprocServer32 path"; return false; }
            if (string.IsNullOrEmpty(liveServerPath))
            { reason = "no live InprocServer32 value"; return false; }
            if (!string.IsNullOrEmpty(observedServerPath) &&
                !string.Equals(observedServerPath!.Trim(), liveServerPath!.Trim(), StringComparison.OrdinalIgnoreCase))
            { reason = "server path changed since it was observed"; return false; }
            if (!IsUserWritableLocation(liveServerPath!))
            { reason = "server path is not in a user-writable location"; return false; }
            return true;
        }

        /// <summary>
        /// True for a path under a user-writable area and not under Windows or Program Files.
        /// Anything unresolvable is not treated as user-writable (fail closed: no deletion).
        /// </summary>
        public static bool IsUserWritableLocation(string path)
        {
            var p = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"')).Replace('/', '\\').ToLowerInvariant();
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant().TrimEnd('\\') + "\\";
            if (p.StartsWith(win, StringComparison.Ordinal) &&
                !(p.StartsWith(win + "temp\\", StringComparison.Ordinal) || p.StartsWith(win + "tasks\\", StringComparison.Ordinal)))
                return false;
            foreach (var root in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            })
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (p.StartsWith(root.ToLowerInvariant().TrimEnd('\\') + "\\", StringComparison.Ordinal)) return false;
            }
            return p.Contains(@"\appdata\") || p.Contains(@"\temp\") || p.Contains(@"\tmp\") ||
                   p.Contains(@"\users\") || p.Contains(@"\programdata\") || p.Contains(@"\downloads\");
        }

        private static bool IsOneOf(string key, string[] roots)
        {
            foreach (var r in roots)
                if (string.Equals(key, r, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool HasControlCharacters(string value)
        {
            foreach (var c in value) if (c < 32) return true;
            return false;
        }
    }
}
