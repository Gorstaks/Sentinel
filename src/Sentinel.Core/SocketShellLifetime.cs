using System;
namespace Sentinel.Core
{
    internal static class SocketShellLifetime
    {
        internal static bool TryResolve(DetectionEvent detection, Func<int, long> resolver, DateTime now, out long created)
        {
            created = 0;
            if (detection.ProcessId <= 4 || detection.Timestamp > now || now - detection.Timestamp > TimeSpan.FromSeconds(30)) return false;
            long live = resolver(detection.ProcessId);
            if (live <= 0 || live > detection.Timestamp.ToFileTimeUtc()) return false;
            if (detection.Metadata != null && detection.Metadata.TryGetValue("ProcessCreationTime", out var birth) &&
                (!long.TryParse(birth, out var recorded) || recorded != live)) return false;
            created = live;
            return true;
        }
    }
}
