using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core
{
    /// <summary>
    /// 3.7.1 - Link-following guards for SYSTEM file mutation. A path checked and then deleted or
    /// ACL-changed can be redirected by a junction or hard link that a standard user controls.
    /// These checks refuse such paths; they do not make a path-based operation atomic.
    /// </summary>
    public static class FileObjectSafety
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

        /// <summary>True when the file or any ancestor directory is a reparse point (junction, symlink, placeholder).</summary>
        public static bool HasReparsePointInPath(string path)
        {
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(current); }
                catch (FileNotFoundException) { attributes = 0; }
                catch (DirectoryNotFoundException) { attributes = 0; }
                if ((attributes & FileAttributes.ReparsePoint) != 0) return true;
                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
                current = parent;
            }
            return false;
        }

        /// <summary>Number of hard links to the file, or -1 when it cannot be determined.</summary>
        public static int GetHardLinkCount(string path)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                return GetFileInformationByHandle(stream.SafeFileHandle, out var info) ? (int)info.NumberOfLinks : -1;
            }
            catch (IOException) { return -1; }
            catch (UnauthorizedAccessException) { return -1; }
        }

        /// <summary>Refusal reason, or null when the path passes both checks.</summary>
        public static string? RefusalReason(string path)
        {
            if (HasReparsePointInPath(path)) return "path contains a reparse point";
            var links = GetHardLinkCount(path);
            if (links != 1) return links < 0 ? "hard-link count could not be determined" : "file has multiple hard links";
            return null;
        }
    }
}
