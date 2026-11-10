using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - Client-side check that the process serving the IPC pipe is the Sentinel service.
    /// The HMAC key is readable by interactive sessions, so it cannot authenticate the server.
    /// The service runs in session 0; a squatter in a user session is rejected. When the server
    /// process can be opened (same-user squatter), its image must be the installed service binary.
    /// A process that cannot be opened is accepted only if it is in session 0.
    /// </summary>
    public static class PipeServerIdentity
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;
        public const string ServiceExeName = "Sentinel.Service.exe";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);

        public static bool IsLegitimateService(SafePipeHandle pipe)
        {
            try
            {
                if (!GetNamedPipeServerProcessId(pipe, out var pid) || pid == 0 || pid > int.MaxValue) return false;
                if (!ProcessIdToSessionId(pid, out var session) || session != 0) return false;

                var process = NativeResolver.OpenProcess(ProcessQueryLimitedInformation, false, (int)pid);
                if (process == IntPtr.Zero)
                    return true; // protected SYSTEM process in session 0
                try
                {
                    var builder = new StringBuilder(1024);
                    uint size = (uint)builder.Capacity;
                    if (!QueryFullProcessImageName(process, 0, builder, ref size)) return false;
                    return IsExpectedServiceImage(builder.ToString());
                }
                finally { CloseHandle(process); }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("[PipeServerIdentity] verification failed closed: " + ex.Message);
                return false;
            }
        }

        /// <summary>The server image must be Sentinel.Service.exe in the same directory as the caller's binaries.</summary>
        internal static bool IsExpectedServiceImage(string imagePath)
        {
            var expected = Path.Combine(AppContext.BaseDirectory, ServiceExeName);
            return string.Equals(Path.GetFullPath(imagePath), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase);
        }
    }
}
