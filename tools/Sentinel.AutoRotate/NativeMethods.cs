// Sentinel.AutoRotate - P/Invoke declarations.
//
// All calls are synchronous. APIs:
//   netapi32.dll  : NetUserGetInfo, NetUserSetInfo (level 1003), NetUserModalsGet, NetUserModalsSet (level 1001), NetApiBufferFree
//   advapi32.dll  : LsaOpenPolicy / LsaStorePrivateData / LsaClose (legacy autologon cleanup only)
//   kernel32.dll  : WTSGetActiveConsoleSessionId, GetTickCount64
//   wtsapi32.dll  : WTSQuerySessionInformation / WTSFreeMemory

using System.Runtime.InteropServices;

namespace Sentinel.AutoRotate;

internal static class NativeMethods
{
    internal const uint NERR_Success = 0;
    internal const uint UF_ACCOUNTDISABLE = 0x0002;

    // ---- netapi32 ----------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct USER_INFO_1003
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1003_password;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserSetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string? servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        uint level,
        ref USER_INFO_1003 buf,
        out uint parm_err);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct USER_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_comment;
        public uint usri1_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_script_path;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserGetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string? servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        uint level,
        out IntPtr bufptr);

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_MODALS_INFO_0
    {
        public uint usrmod0_min_passwd_len;
        public uint usrmod0_max_passwd_age;
        public uint usrmod0_min_passwd_age;
        public uint usrmod0_force_logoff;
        public uint usrmod0_password_hist_len;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserModalsGet(
        [MarshalAs(UnmanagedType.LPWStr)] string? servername,
        uint level,
        out IntPtr bufptr);

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_MODALS_INFO_1001
    {
        public uint usrmod1001_min_passwd_len;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserModalsSet(
        [MarshalAs(UnmanagedType.LPWStr)] string? servername,
        uint level,
        ref USER_MODALS_INFO_1001 buf,
        out uint parm_err);

    [DllImport("netapi32.dll")]
    internal static extern uint NetApiBufferFree(IntPtr buffer);

    // ---- advapi32: LSA private data (legacy autologon cleanup) -------------------

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    internal const uint POLICY_CREATE_SECRET = 0x00000020;
    internal const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

    [DllImport("advapi32.dll")]
    internal static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaStorePrivateData(IntPtr policyHandle, ref LSA_UNICODE_STRING keyName, IntPtr privateData);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaClose(IntPtr policyHandle);

    // ---- kernel32 / wtsapi32 -----------------------------------------------------

    [DllImport("kernel32.dll")]
    internal static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll")]
    internal static extern ulong GetTickCount64();

    internal const int WTSUserName = 5;
    internal const int WTSDomainName = 7;

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);

    [DllImport("wtsapi32.dll")]
    internal static extern void WTSFreeMemory(IntPtr memory);

    internal const uint NoActiveConsoleSession = 0xFFFFFFFF;
}
