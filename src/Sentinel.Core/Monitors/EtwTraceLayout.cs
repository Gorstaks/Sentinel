using System;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - Native EVENT_TRACE_PROPERTIES layout used by QueryAllTraces. WNODE_HEADER is 48 bytes on
    /// x86 and x64; LoggerThreadId is a HANDLE, so the trailing offsets depend on pointer size:
    /// x64 LogFileNameOffset=112, LoggerNameOffset=116, sizeof=120; x86 108, 112, 116.
    /// The session names are placed in a buffer after the struct.
    /// </summary>
    internal static class EtwTraceLayout
    {
        private const int LoggerThreadIdOffset = 104;
        private const int NameRegionBytes = 1024; // 512 UTF-16 characters each for log file and logger names

        internal static int LogFileNameOffsetField => LoggerThreadIdOffset + IntPtr.Size;
        internal static int LoggerNameOffsetField => LogFileNameOffsetField + 4;
        internal static int StructSize => LoggerNameOffsetField + 4 + (IntPtr.Size == 8 ? 0 : 0);
        internal static int BufferSize => StructSize + 2 * NameRegionBytes;

        /// <summary>Zero the buffer and set the sizes/offsets QueryAllTraces requires.</summary>
        internal static void Initialize(IntPtr buffer)
        {
            for (int i = 0; i < BufferSize; i += 4)
                Marshal.WriteInt32(buffer, i, 0);
            Marshal.WriteInt32(buffer, 0, BufferSize);                                  // Wnode.BufferSize
            Marshal.WriteInt32(buffer, LogFileNameOffsetField, StructSize);             // log file name region
            Marshal.WriteInt32(buffer, LoggerNameOffsetField, StructSize + NameRegionBytes); // logger name region
        }
    }
}
