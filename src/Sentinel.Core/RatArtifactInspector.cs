using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace Sentinel.Core
{
    internal static class RatArtifactInspector
    {
        // Group-IB KGB RAT report supplied by the user, October 14 2026.
        // Two reported independent markers in a PE, not a filename/hash kill rule.
        internal static bool Matches(byte[] bytes)
        {
            if (bytes.Length < 64 || bytes.Length > 2 * 1024 * 1024 || bytes[0] != 'M' || bytes[1] != 'Z') return false;
            int pe = BitConverter.ToInt32(bytes, 0x3c);
            if (pe < 64 || pe > bytes.Length - 4 || BitConverter.ToUInt32(bytes, pe) != 0x4550) return false;
            return HasMarker(bytes, "|Ghost|") && HasMarker(bytes, "WhyYouReverseMe..ImInnocent..LoveYouu..");
        }
        private static bool HasMarker(byte[] bytes, string marker)
            => Contains(bytes, Encoding.UTF8.GetBytes(marker)) || Contains(bytes, Encoding.Unicode.GetBytes(marker));
        private static bool Contains(byte[] bytes, byte[] marker)
        {
            int start = 0;
            while ((start = Array.IndexOf(bytes, marker[0], start)) >= 0 && start <= bytes.Length - marker.Length)
            {
                int i = 1;
                while (i < marker.Length && bytes[start + i] == marker[i]) i++;
                if (i == marker.Length) return true;
                start++;
                if (start >= bytes.Length) break;
            }
            return false;
        }
        internal static bool Inspect(Stream stream)
        {
            long position = stream.Position;
            try
            {
                stream.Position = 0;
                var bytes = new byte[(int)Math.Min(stream.Length, 2 * 1024 * 1024)];
                int read = 0, count;
                while (read < bytes.Length && (count = stream.Read(bytes, read, bytes.Length - read)) > 0) read += count;
                return read == bytes.Length && Matches(bytes);
            }
            finally { stream.Position = position; }
        }
        internal static DetectionEvent Observation(string file) => new()
        {
            RuleName = "File Content: KGB RAT Reported Marker Pair", ProcessId = 0,
            ProcessName = Path.GetFileName(file), Confidence = 0.65,
            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic,
            Evidence = "A bounded PE content read found both reported KGB/NjRAT-derived markers; filename is not used for matching.",
            Reasoning = "Static artifact evidence only. Embedded examples or modified binaries can match; encrypted/changed markers can evade it. No execution or malware-family attribution is proven.",
            Metadata = new Dictionary<string, string> { ["FilePath"] = file, ["WeakObserveSeed"] = "true", ["ArtifactFamily"] = "KGB RAT report" }
        };
    }
}
