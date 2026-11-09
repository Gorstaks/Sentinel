using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    // Manifest reference: Microsoft-Windows-Kernel-File, NameCreate v0, Read v0/v1.
    // Only sensitive names are retained; no cache/browser-event firehose enters fusion.
    internal sealed class CredentialReadTracker
    {
        private readonly object _gate = new();
        private readonly Dictionary<ulong, (string path, DateTime seen)> _names = new();
        private readonly Dictionary<(int pid, ulong key), DateTime> _recent = new();
        private const int Capacity = 4096;

        // Indicator data lives in Indicators/indicators.txt (compressed resource); see IndicatorCatalog.
        // All values are lower-case and matched ordinally against the lower-cased path, as before.
        private static readonly string[] SensitiveSuffixes = IndicatorCatalog.List("credRead.suffixes");
        private static readonly string[] SshKeySuffixes = IndicatorCatalog.List("credRead.sshKeySuffixes");
        private static readonly string[] ChatSessionStores = IndicatorCatalog.List("credRead.chatSessionStores");

        internal static bool IsSensitivePath(string path)
        {
            var p = path.Replace('/', '\\').ToLowerInvariant();
            return IsWindowsVaultPath(p) ||
                SensitiveSuffixes.Any(s => p.EndsWith(s, StringComparison.Ordinal)) ||
                (p.Contains("\\.ssh\\") && SshKeySuffixes.Any(s => p.EndsWith(s, StringComparison.Ordinal))) ||
                (ChatSessionStores.Any(s => p.Contains(s)) &&
                 (p.EndsWith(".ldb", StringComparison.Ordinal) || p.EndsWith(".log", StringComparison.Ordinal)));
        }

        private static bool IsWindowsVaultPath(string path)
        {
            foreach (var root in new[] { @"\appdata\local\microsoft\vault\", @"\appdata\roaming\microsoft\vault\" })
            {
                int start = path.IndexOf(root, StringComparison.Ordinal);
                if (start < 0) continue;
                var parts = path.Substring(start + root.Length).Split('\\');
                if (parts.Length != 2) continue;
                if (parts[0] == "userprofileroaming" && parts[1] == "latest.dat") return true;
                if (!Guid.TryParse(parts[0], out _)) continue;
                if (parts[1] == "policy.vpol") return true;
                if (parts[1].EndsWith(".vcrd", StringComparison.Ordinal) &&
                    Guid.TryParse(parts[1].Substring(0, parts[1].Length - 5), out _)) return true;
            }
            return false;
        }

        internal string? Observe(EtwRawEvent evt)
        {
            int width = evt.PointerSize;
            if ((width != 4 && width != 8) || evt.UserData == IntPtr.Zero) return null;
            lock (_gate)
            {
                if ((evt.EventId == 10 || evt.EventId == 11) && evt.Version == 0)
                {
                    if (evt.UserDataLength < width + 2) return null;
                    ulong key = ReadPointer(evt.UserData, 0, width);
                    // Invalidate even an uninteresting replacement name (FileKey reuse).
                    _names.Remove(key);
                    if (evt.EventId == 11 || key == 0) return null;
                    int bytes = evt.UserDataLength - width;
                    if ((bytes & 1) != 0 || bytes > 2048) return null;
                    string name = Marshal.PtrToStringUni(IntPtr.Add(evt.UserData, width), bytes / 2) ?? "";
                    int end = name.IndexOf('\0');
                    if (end < 0) return null;
                    name = name.Substring(0, end);
                    if (!IsSensitivePath(name)) return null;
                    if (_names.Count >= Capacity) _names.Clear();
                    _names[key] = (name, evt.Timestamp);
                    return null;
                }
                if (evt.EventId != 15 || evt.Version > 1 || evt.ProcessId <= 4) return null;
                int offset = 8 + (evt.Version == 0 ? 3 : 2) * width;
                int minimum = offset + width + (evt.Version == 0 ? 8 : 16);
                if (evt.UserDataLength < minimum) return null;
                ulong fileKey = ReadPointer(evt.UserData, offset, width);
                if (!_names.TryGetValue(fileKey, out var entry)) return null;
                var age = evt.Timestamp - entry.seen;
                if (age < TimeSpan.Zero || age > TimeSpan.FromMinutes(2))
                {
                    _names.Remove(fileKey);
                    return null;
                }
                var identity = (evt.ProcessId, fileKey);
                if (_recent.TryGetValue(identity, out var last) && evt.Timestamp >= last &&
                    evt.Timestamp - last < TimeSpan.FromSeconds(20)) return null;
                if (_recent.Count >= Capacity) _recent.Clear();
                _recent[identity] = evt.Timestamp;
                return entry.path;
            }
        }

        private static ulong ReadPointer(IntPtr data, int offset, int width) => width == 8
            ? unchecked((ulong)Marshal.ReadInt64(data, offset))
            : unchecked((uint)Marshal.ReadInt32(data, offset));
    }
}
