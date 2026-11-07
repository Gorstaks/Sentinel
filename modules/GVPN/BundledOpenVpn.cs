using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace GVPN
{
    /// <summary>
    /// Locates the OpenVPN client + TAP driver GVPN uses.
    ///  - Sentinel install: setup places them in &lt;exe dir&gt;\openvpn.
    ///  - Standalone single exe: they are embedded as resources ("openvpn/...") and unpacked to
    ///    %ProgramFiles%\GVPN\openvpn. Program Files is writable by administrators only, so a
    ///    non-admin cannot plant an openvpn.exe that GVPN would then run elevated. Each start
    ///    compares every unpacked file's SHA-256 with the embedded copy and rewrites mismatches,
    ///    so a tampered or outdated file is replaced before use.
    /// </summary>
    public static class BundledOpenVpn
    {
        private const string ResourcePrefix = "openvpn/";

        private static string ExeDir
        {
            get { return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); }
        }

        public static string ExtractDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "GVPN", "openvpn"); }
        }

        /// <summary>Directory containing bin\openvpn.exe and drivers\, or null when none exists.</summary>
        public static string Directory
        {
            get
            {
                string beside = Path.Combine(ExeDir, "openvpn");
                if (File.Exists(Path.Combine(beside, @"bin\openvpn.exe")))
                    return beside;
                if (File.Exists(Path.Combine(ExtractDir, @"bin\openvpn.exe")))
                    return ExtractDir;
                return null;
            }
        }

        private static string[] EmbeddedNames()
        {
            return Assembly.GetExecutingAssembly().GetManifestResourceNames()
                .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal))
                .ToArray();
        }

        /// <summary>
        /// Unpacks the embedded files when this exe carries them and no copy sits beside the exe.
        /// Returns false only when unpacking was needed and failed.
        /// </summary>
        public static bool EnsureExtracted(Logger logger)
        {
            string[] names = EmbeddedNames();
            if (names.Length == 0)
                return true; // Sentinel build: files are installed beside GVPN.exe
            if (File.Exists(Path.Combine(ExeDir, @"openvpn\bin\openvpn.exe")))
                return true;

            int written = 0;
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();
                foreach (string name in names)
                {
                    string relative = name.Substring(ResourcePrefix.Length).Replace('/', Path.DirectorySeparatorChar);
                    if (relative.Contains("..") || Path.IsPathRooted(relative))
                        continue; // never write outside ExtractDir
                    string target = Path.Combine(ExtractDir, relative);

                    byte[] data;
                    using (Stream s = asm.GetManifestResourceStream(name))
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        data = ms.ToArray();
                    }

                    if (File.Exists(target) && SameHash(File.ReadAllBytes(target), data))
                        continue;

                    System.IO.Directory.CreateDirectory(Path.GetDirectoryName(target));
                    File.WriteAllBytes(target, data);
                    written++;
                }
                if (written > 0)
                    logger.Log("Unpacked " + written + " bundled OpenVPN file(s) to " + ExtractDir);
                return true;
            }
            catch (Exception ex)
            {
                // Typically openvpn.exe still running from an older GVPN; the existing copy is used.
                logger.Log("Could not unpack bundled OpenVPN to " + ExtractDir + ": " + ex.Message);
                return File.Exists(Path.Combine(ExtractDir, @"bin\openvpn.exe"));
            }
        }

        /// <summary>Removes the unpacked copy (GVPN.exe --uninstall).</summary>
        public static void RemoveExtracted(Logger logger)
        {
            string root = Path.GetDirectoryName(ExtractDir); // %ProgramFiles%\GVPN
            try
            {
                if (System.IO.Directory.Exists(root))
                {
                    System.IO.Directory.Delete(root, true);
                    logger.Log("Removed " + root);
                }
            }
            catch (Exception ex)
            {
                logger.Log("Could not remove " + root + ": " + ex.Message);
            }
        }

        private static bool SameHash(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            using (var sha = SHA256.Create())
                return sha.ComputeHash(a).SequenceEqual(sha.ComputeHash(b));
        }
    }
}
