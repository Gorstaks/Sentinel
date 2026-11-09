using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// Detection indicator data (offensive tool names, credential-store paths, exfil sinks,
    /// injection API names, downloader keywords) loaded from a compressed embedded resource.
    ///
    /// Why: static AV/ML engines substring-match a PE for these words. An EDR that ships
    /// them as plaintext string literals looks to those engines exactly like the stealers,
    /// RATs and injectors it detects (VirusTotal "stealer" / "generic trojan" verdicts).
    /// Source of truth is the readable <c>Indicators/indicators.txt</c>; the build deflates
    /// it into the assembly. This is ordinary compressed data (as AV signature databases
    /// ship), not in-code string hiding, which ML engines score as evasion.
    ///
    /// Fail-loud: a missing resource or section throws instead of returning an empty list,
    /// so detection can never silently disappear. IndicatorCatalogTests pins every section.
    /// </summary>
    internal static class IndicatorCatalog
    {
        internal const string ResourceName = "Sentinel.Core.Indicators.bin";
        private const string PairSeparator = " => ";

        private static readonly Lazy<Dictionary<string, string[]>> Sections =
            new(() => Parse(ReadText(ResourceName)), LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>All values of <paramref name="section"/> (fresh copy).</summary>
        public static string[] List(string section)
        {
            if (!Sections.Value.TryGetValue(section, out var values) || values.Length == 0)
                throw new InvalidOperationException($"Indicator section '{section}' is missing or empty");
            return (string[])values.Clone();
        }

        /// <summary>Case-insensitive set of the values of <paramref name="section"/>.</summary>
        public static HashSet<string> Set(string section)
            => new(List(section), StringComparer.OrdinalIgnoreCase);

        /// <summary>Lower-cased values, for call sites that match against lower-cased input.</summary>
        public static string[] Lower(string section)
            => List(section).Select(v => v.ToLowerInvariant()).ToArray();

        /// <summary>Key/value pairs written as <c>key => value</c>.</summary>
        public static (string Key, string Value)[] Pairs(string section)
            => List(section).Select(line =>
            {
                int i = line.IndexOf(PairSeparator, StringComparison.Ordinal);
                if (i <= 0)
                    throw new InvalidOperationException($"Indicator section '{section}' has a malformed pair: no '{PairSeparator.Trim()}'");
                return (line.Substring(0, i), line.Substring(i + PairSeparator.Length));
            }).ToArray();

        /// <summary>Single text value: all lines of the section joined with one space.</summary>
        public static string Text(string section) => string.Join(" ", List(section));

        /// <summary>True when any value of <paramref name="section"/> occurs in <paramref name="text"/> (ordinal ignore-case).</summary>
        public static bool ContainsAny(string? text, string[] values)
        {
            if (string.IsNullOrEmpty(text)) return false;
            foreach (var v in values)
                if (text!.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        internal static IReadOnlyCollection<string> SectionNames => Sections.Value.Keys;

        /// <summary>Reads a deflate-compressed embedded resource of this assembly as UTF-8 text.</summary>
        internal static string ReadText(string logicalName)
        {
            using var raw = typeof(IndicatorCatalog).Assembly.GetManifestResourceStream(logicalName)
                ?? throw new InvalidOperationException($"Embedded resource '{logicalName}' is missing");
            using var inflate = new DeflateStream(raw, CompressionMode.Decompress);
            using var reader = new StreamReader(inflate, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
            return reader.ReadToEnd();
        }

        /// <summary>
        /// Format: <c>[section]</c> headers; one value per line; lines starting with <c>#</c> and
        /// blank lines are ignored. A value wrapped in double quotes keeps leading/trailing spaces.
        /// </summary>
        internal static Dictionary<string, string[]> Parse(string text)
        {
            var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            List<string>? current = null;
            foreach (var rawLine in text.Split('\n'))
            {
                var line = rawLine.TrimEnd('\r');
                if (line.Trim().Length == 0 || line.TrimStart().StartsWith("#", StringComparison.Ordinal))
                    continue;
                var trimmed = line.Trim();
                if (trimmed.StartsWith("[", StringComparison.Ordinal) && trimmed.EndsWith("]", StringComparison.Ordinal))
                {
                    var name = trimmed.Substring(1, trimmed.Length - 2).Trim();
                    if (result.ContainsKey(name))
                        throw new InvalidOperationException($"Duplicate indicator section '{name}'");
                    current = new List<string>();
                    result[name] = current;
                    continue;
                }
                if (current == null)
                    throw new InvalidOperationException("Indicator value appears before any [section] header");
                current.Add(trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[trimmed.Length - 1] == '"'
                    ? trimmed.Substring(1, trimmed.Length - 2)
                    : trimmed);
            }
            return result.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray(), StringComparer.Ordinal);
        }
    }
}
