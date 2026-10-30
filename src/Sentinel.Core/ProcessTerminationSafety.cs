using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    internal static class ProcessTerminationSafety
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessCritical(IntPtr process, [MarshalAs(UnmanagedType.Bool)] out bool critical);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
        internal static long CreationTime(IntPtr handle)
        {
            if (GetProcessTimes(handle, out long created, out _, out _, out _)) return created;
            Debug.WriteLine("[TerminationSafety] Pinned creation-time query unavailable: " + Marshal.GetLastWin32Error());
            return 0;
        }
        internal static bool Allows(bool? critical) => critical.HasValue && !critical.Value;
        internal static bool IsAllowed(IntPtr handle)
        {
            try
            {
                if (IsProcessCritical(handle, out bool critical)) return Allows(critical);
                Debug.WriteLine("[TerminationSafety] Criticality query unavailable: " + Marshal.GetLastWin32Error());
            }
            catch (Exception ex) when (ex is EntryPointNotFoundException || ex is DllNotFoundException)
            { Debug.WriteLine("[TerminationSafety] " + ex); }
            return false;
        }
    }
}
