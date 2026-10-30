using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    // Owned by the single ProcessTrace callback thread. No payload parsing or process opens.
    internal sealed class RegistryHintAdmission
    {
        private readonly Dictionary<int, long> _last = new();
        internal bool Admit(int pid, long fileTime)
        {
            if (_last.TryGetValue(pid, out long last) && fileTime >= last &&
                fileTime - last < TimeSpan.TicksPerSecond) return false;
            if (_last.Count >= 4096) _last.Clear();
            _last[pid] = fileTime;
            return true;
        }
    }
}
