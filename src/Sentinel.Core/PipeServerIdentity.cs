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
    ///
    /// The service runs in session 0, and a standard user cannot start a process there, so a
    /// squatter in a user session is rejected. The server session is read from the pipe handle
    /// itself (<c>GetNamedPipeServerSessionId</c>), which needs no access to the server process.
    /// 3.7.2: the first 3.7.1 build used <c>ProcessIdToSessionId</c>, which needs a process handle
    /// that a standard or non-elevated user is denied for a SYSTEM service, so every request was
    /// refused and the dashboard showed sensor health as unavailable.
    ///
    /// When the server process can also be opened (for example a same-user process), its image
    /// must be the installed <c>Sentinel.Service.exe</c>.
    /// </summary>
    public static class PipeServerIdentity
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;
        public const string ServiceExeName = "Sentinel.Service.exe";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out uint serverSessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);

        public static bool IsLegitimateService(SafePipeHandle pipe)
        {
            try
            {
                if (!GetNamedPipeServerSessionId(pipe, out var session)) return false;
                return IsAcceptable(session, () => TryGetServerImage(pipe));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("[PipeServerIdentity] verification failed closed: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Pure decision: the server must be in session 0. If its image path is readable it must be
        /// the installed service binary; an unreadable image (SYSTEM process the caller cannot open)
        /// is accepted on the session-0 fact alone.
        /// </summary>
        internal static bool IsAcceptable(uint serverSession, Func<string?> serverImage)
        {
            if (serverSession != 0) return false;
            var image = serverImage();
            return string.IsNullOrEmpty(image) || IsExpectedServiceImage(image!);
        }

        private static string? TryGetServerImage(SafePipeHandle pipe)
        {
            if (!GetNamedPipeServerProcessId(pipe, out var pid) || pid == 0 || pid > int.MaxValue) return null;
            var process = NativeResolver.OpenProcess(ProcessQueryLimitedInformation, false, (int)pid);
            if (process == IntPtr.Zero) return null;
            try
            {
                var builder = new StringBuilder(1024);
                uint size = (uint)builder.Capacity;
                return QueryFullProcessImageName(process, 0, builder, ref size) ? builder.ToString() : null;
            }
            finally { CloseHandle(process); }
        }

        /// <summary>The server image must be Sentinel.Service.exe in the same directory as the caller's binaries.</summary>
        internal static bool IsExpectedServiceImage(string imagePath)
        {
            var expected = Path.Combine(AppContext.BaseDirectory, ServiceExeName);
            return string.Equals(Path.GetFullPath(imagePath), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase);
        }
    }
}
