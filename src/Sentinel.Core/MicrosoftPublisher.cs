using System;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - "Microsoft-signed" used to mean the signer text contained "Microsoft" or "Windows". Any
    /// code-signing certificate for "Windows Optimizer Ltd" or "Microsoft Tools LLC" passed. The common
    /// name must now equal a known Microsoft code-signing identity exactly. Callers still pair this with a
    /// valid Authenticode signature and, where a trust decision is made, a trusted-root location.
    /// </summary>
    public static class MicrosoftPublisher
    {
        private static readonly string[] KnownCommonNames =
        {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Publisher",
            "Microsoft Windows Hardware Compatibility Publisher",
        };

        /// <summary>Accepts either a bare common name or a full distinguished name containing CN=.</summary>
        public static bool IsMicrosoftCommonName(string? signerOrSubject)
        {
            if (string.IsNullOrWhiteSpace(signerOrSubject)) return false;
            var cn = ExtractCommonName(signerOrSubject!);
            foreach (var known in KnownCommonNames)
                if (string.Equals(cn, known, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        internal static string ExtractCommonName(string value)
        {
            var text = value.Trim();
            var start = text.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (start < 0) return text;
            start += 3;
            if (start < text.Length && text[start] == '"')
            {
                var end = text.IndexOf('"', start + 1);
                return (end > start ? text.Substring(start + 1, end - start - 1) : text.Substring(start + 1)).Trim();
            }
            var comma = text.IndexOf(',', start);
            return (comma > start ? text.Substring(start, comma - start) : text.Substring(start)).Trim();
        }
    }
}
