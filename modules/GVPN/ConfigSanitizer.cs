using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace GVPN
{
    /// <summary>
    /// Rebuilds an untrusted VPNGate OpenVPN config from an allowlist. VPNGate servers are run by
    /// volunteers and GVPN runs openvpn.exe elevated, so a hostile config could otherwise run code
    /// as admin (plugin, up/down scripts, script-security) or touch files (log, writepid, cd,
    /// external ca/cert paths). Anything not on the allowlist is dropped. Returns null when the
    /// result is not a usable client config.
    /// </summary>
    public static class ConfigSanitizer
    {
        // Directive -> allowed argument pattern (null = no arguments).
        private static readonly Dictionary<string, Regex> AllowedDirectives = new Dictionary<string, Regex>(StringComparer.OrdinalIgnoreCase)
        {
            { "client", null },
            { "nobind", null },
            { "persist-key", null },
            { "persist-tun", null },
            { "float", null },
            { "auth-nocache", null },
            { "cipher", new Regex(@"^[A-Za-z0-9\-]{1,40}$") },
            { "data-ciphers", new Regex(@"^[A-Za-z0-9\-:]{1,200}$") },
            { "data-ciphers-fallback", new Regex(@"^[A-Za-z0-9\-]{1,40}$") },
            { "auth", new Regex(@"^[A-Za-z0-9\-]{1,20}$") },
            { "key-direction", new Regex(@"^[01]$") },
            { "remote-cert-tls", new Regex(@"^(server)$") },
            { "tls-version-min", new Regex(@"^1\.[0-3]$") },
            { "tun-mtu", new Regex(@"^\d{3,5}$") },
            { "mssfix", new Regex(@"^\d{0,5}$") },
            { "keepalive", new Regex(@"^\d{1,5} \d{1,5}$") },
            { "ping", new Regex(@"^\d{1,5}$") },
            { "ping-restart", new Regex(@"^\d{1,5}$") },
            { "reneg-sec", new Regex(@"^\d{1,6}$") }
        };

        // Inline key material blocks; no file paths.
        private static readonly HashSet<string> AllowedBlocks = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ca", "cert", "key", "tls-auth", "tls-crypt", "extra-certs"
        };

        private static readonly Regex BlockOpen = new Regex(@"^<([A-Za-z\-]+)>$");

        public static string Sanitize(string config, string serverIp, out int port, out string proto)
        {
            port = 0;
            proto = "udp";
            if (string.IsNullOrEmpty(config))
                return null;

            var output = new StringBuilder();
            var lines = config.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            bool haveCa = false, haveClient = false;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.Length == 0 || line[0] == '#' || line[0] == ';')
                    continue;

                Match block = BlockOpen.Match(line);
                if (block.Success)
                {
                    string tag = block.Groups[1].Value;
                    string close = "</" + tag + ">";
                    var body = new StringBuilder();
                    int j = i + 1;
                    while (j < lines.Length && !string.Equals(lines[j].Trim(), close, StringComparison.OrdinalIgnoreCase))
                    {
                        body.Append(lines[j].Trim()).Append('\n');
                        j++;
                    }
                    if (j >= lines.Length)
                        return null; // unterminated block
                    i = j;

                    if (!AllowedBlocks.Contains(tag))
                        continue;
                    if (tag.Equals("ca", StringComparison.OrdinalIgnoreCase))
                        haveCa = true;
                    output.Append('<').Append(tag.ToLowerInvariant()).Append(">\n").Append(body).Append("</").Append(tag.ToLowerInvariant()).Append(">\n");
                    continue;
                }

                string[] parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                string key = parts[0];
                string args = parts.Length > 1 ? Regex.Replace(parts[1].Trim(), @"\s+", " ") : "";

                if (key.Equals("remote", StringComparison.OrdinalIgnoreCase))
                {
                    // Only the first port is used; the host is always the IP from the server list
                    // so the kill switch exception matches the address actually dialled.
                    if (port == 0)
                    {
                        string[] r = args.Split(' ');
                        int p;
                        if (r.Length >= 2 && int.TryParse(r[1], out p) && p > 0 && p < 65536)
                            port = p;
                    }
                    continue;
                }
                if (key.Equals("proto", StringComparison.OrdinalIgnoreCase))
                {
                    string a = args.ToLowerInvariant();
                    if (a == "udp" || a == "udp4") proto = "udp";
                    else if (a == "tcp" || a == "tcp4" || a == "tcp-client") proto = "tcp";
                    else return null;
                    continue;
                }
                if (key.Equals("dev", StringComparison.OrdinalIgnoreCase))
                {
                    if (!args.Equals("tun", StringComparison.OrdinalIgnoreCase))
                        return null; // GVPN's adapter is a TUN-mode TAP device
                    continue;
                }

                Regex pattern;
                if (!AllowedDirectives.TryGetValue(key, out pattern))
                    continue;
                if (pattern == null ? args.Length != 0 : !pattern.IsMatch(args))
                    continue;
                if (key.Equals("client", StringComparison.OrdinalIgnoreCase))
                    haveClient = true;

                output.Append(key.ToLowerInvariant());
                if (args.Length > 0) output.Append(' ').Append(args);
                output.Append('\n');
            }

            if (!haveCa || !haveClient || port == 0)
                return null;

            string head = "dev tun\nproto " + (proto == "tcp" ? "tcp-client" : "udp") + "\nremote " + serverIp + " " + port + "\n";
            return head + output;
        }
    }
}
