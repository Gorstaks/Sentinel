using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Answers one narrow, high-stakes question: "Is this PID a genuine Windows
    /// OS-image servicing actor whose destructive-looking behavior (mass component
    /// deletion, running at SYSTEM integrity) is legitimate OS maintenance - not an
    /// attack?"
    ///
    /// Why this exists: Windows servicing actors (TrustedInstaller / TiWorker, DISM,
    /// the Windows Update standalone installer wusa/the KBxxxxxxx self-extractors, and
    /// the Malicious Software Removal Tool Windows-KB890830) do things that look exactly
    /// like ransomware/wipers and token theft to a purely-behavioral engine:
    ///   - TiWorker deletes hundreds of superseded component files during cleanup
    ///     (trips SlidingWindowMassDeletionRule: 100 deletions / 10s).
    ///   - MSRT and servicing hosts run at SYSTEM integrity by design
    ///     (trips TokenIntegrityMonitor's integrity-jump heuristic).
    /// Those rules are President's-Law (Ransomware / PrivilegeEscalation) categories,
    /// so the allowlist / IDE / game gates in the response engine deliberately do NOT
    /// suppress them. The result is Sentinel terminating Windows Update / MSRT.
    ///
    /// The trust anchor here is deliberately NOT the process name (an attacker can name
    /// a dropped binary "tiworker.exe"). It is the conjunction of two facts the attacker
    /// does not control:
    ///   1. The OS-recorded image path resides in a trusted, ACL-protected OS servicing
    ///      tree (System32 / WinSxS / the servicing packages tree / the Windows Update
    ///      download/cache tree). These are writable only by TrustedInstaller/SYSTEM.
    ///   2. The binary carries a valid Microsoft/Windows signature (embedded OR via the
    ///      catalog store, which is itself TrustedInstaller-protected).
    ///
    /// Either condition alone is insufficient:
    ///   - A trusted path without a valid MS signature could be a planted binary that
    ///     an already-SYSTEM attacker wrote - but at that point the host is fully owned
    ///     and killing the process is moot; we still require the signature.
    ///   - A valid MS signature in a user-writable path (a copied-out legit binary used
    ///     for a living-off-the-land attack) is NOT trusted here - the path gate fails.
    ///
    /// This is a LAST-RESORT exemption layered on top of the normal policy. It only ever
    /// turns a kill into LogOnly; it never authorizes an action.
    /// </summary>
    public static class WindowsServicingTrust
    {
        // Known OS-image servicing actor names. Advisory only - the real gate is the
        // trusted-path + MS-signature anchor below. Kept in sync with ServicingWindow
        // and extended with the Windows Update standalone / MSRT family.
        private static readonly string[] ServicingProcessNames =
        {
            "tiworker", "trustedinstaller", "dism", "dismhost",
            "wusa",                       // Windows Update Standalone Installer
            "windows-kb890830",           // Malicious Software Removal Tool (KB890830) self-extractor
            "mrt",                        // MSRT once extracted / installed
            "msmpeng",                    // Defender engine (runs at SYSTEM, heavy file I/O)
            "mpcmdrun",
            "poqexec",                    // Primitive Operations Queue executor (servicing commits)
            "cleanmgr",                   // Disk Cleanup (legitimate bulk deletion)
            "compattelrunner",
            "usoclient", "mousocoreworker",
            "sedlauncher", "sedsvc",      // servicing stack update launcher
        };

        /// <summary>
        /// True when the given image path lives in a trusted, OS-protected servicing tree.
        /// These locations are writable only by TrustedInstaller/SYSTEM, so a binary that
        /// actually resides here was placed by the OS servicing stack, not dropped by a
        /// user-context attacker. Comparison is done on the fully-resolved (final) path so
        /// junction / symlink / 8.3 tricks cannot forge a trusted prefix.
        /// </summary>
        public static bool IsInTrustedServicingTree(string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return false;

            string resolved;
            try
            {
                resolved = SelfPathGuard.TryGetFinalPath(imagePath!) ?? Path.GetFullPath(imagePath!);
            }
            catch { return false; }

            string winDir;
            string sysRoot;
            try
            {
                // %SystemRoot% (usually C:\Windows). GetFolderPath(Windows) is not available
                // on all targets, so derive from System32's parent for robustness.
                sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);     // ...\System32
                winDir = Path.GetDirectoryName(sysRoot) ?? @"C:\Windows";
            }
            catch { winDir = @"C:\Windows"; sysRoot = @"C:\Windows\System32"; }

            // Trusted servicing trees (all under %SystemRoot%, all TrustedInstaller/SYSTEM-owned).
            string[] trustedRoots =
            {
                sysRoot,                                              // System32 (mrt.exe, dism host, etc.)
                Path.Combine(winDir, "WinSxS"),                       // component store
                Path.Combine(winDir, "servicing"),                   // TrustedInstaller.exe, packages
                Path.Combine(winDir, "SoftwareDistribution"),        // Windows Update download/cache
                Path.Combine(winDir, "System32", "catroot"),
                Path.Combine(winDir, "System32", "catroot2"),
                Path.Combine(winDir, "SysWOW64"),
                Path.Combine(winDir, "WaaS"),                         // Windows-as-a-Service medic
                Path.Combine(winDir, "UUS"),                          // Unified Update Stack
            };

            foreach (var root in trustedRoots)
            {
                string normRoot;
                try { normRoot = Path.GetFullPath(root).TrimEnd('\\') + "\\"; }
                catch { continue; }
                if (resolved.StartsWith(normRoot, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// True when the file carries a valid Microsoft/Windows Authenticode or catalog
        /// signature.
        ///
        /// IMPORTANT: this does NOT reuse <see cref="SecurityValidation.VerifyAuthenticodeSignature"/>.
        /// That shared helper sets WTD_LIFETIME_SIGNING, which makes WinVerifyTrust reject a
        /// binary whose signing certificate has EXPIRED (HRESULT CERT_E_EXPIRED / 0x800B0101).
        /// Genuine Windows OS binaries are routinely catalog-signed with long-since-expired
        /// signing certs (that is normal and expected - the catalog countersignature/timestamp
        /// still proves authenticity), so that helper returns false for svchost.exe,
        /// TrustedInstaller.exe, mrt.exe, etc. Using it here would make the servicing gate never
        /// fire - the exact false positives we are fixing.
        ///
        /// Instead we verify with the correct flags for OS-image trust: embedded first, then the
        /// catalog store (which lives under the TrustedInstaller-protected
        /// %SystemRoot%\System32\catroot2), WITHOUT the lifetime-signing flag. An expired-but-
        /// genuine OS catalog signature is a valid Microsoft-origin anchor.
        /// </summary>
        public static bool IsMicrosoftSigned(string? imagePath, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return false;
            try
            {
                if (!File.Exists(imagePath)) return false;

                // Path 1: embedded Authenticode. CreateFromSignedFile succeeds only for an
                // embedded signature; confirm the embedded signer is Microsoft.
                string? embeddedSigner = TryGetEmbeddedSigner(imagePath!);
                if (embeddedSigner != null && IsMicrosoftSubject(embeddedSigner))
                {
                    if (VerifyEmbedded(imagePath!)) return true;
                }

                // Path 2: catalog signature (the common case for OS servicing binaries).
                return VerifyCatalogSignature(imagePath!, logger);
            }
            catch { return false; }
        }

        /// <summary>
        /// The authoritative check: a genuine Windows OS-image servicing actor. Requires
        /// BOTH a trusted servicing-tree residence AND a valid Microsoft signature. The
        /// process name is used only to log/attribute, never to grant trust on its own.
        /// </summary>
        public static bool IsGenuineServicingActor(int pid, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (pid <= 4) return false;
            string? imagePath;
            try { imagePath = SecurityValidation.GetProcessImagePath(pid); }
            catch { return false; }
            return IsGenuineServicingActor(imagePath, logger);
        }

        /// <summary>Path-based overload for callers that already resolved the image path.</summary>
        public static bool IsGenuineServicingActor(string? imagePath, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return false;
            // Non-attacker-controllable anchors only: trusted OS tree AND Microsoft signature.
            if (!IsInTrustedServicingTree(imagePath)) return false;
            if (!IsMicrosoftSigned(imagePath, logger)) return false;
            return true;
        }

        /// <summary>
        /// STRICT, name-scoped servicing-actor check for the central response chokepoint.
        /// Requires ALL THREE anchors: the process NAME matches a known servicing actor, the
        /// image lives in a trusted OS servicing tree, AND it is Microsoft-signed.
        ///
        /// Why name-scoped here: <see cref="IsGenuineServicingActor(int, Microsoft.Extensions.Logging.ILogger?)"/>
        /// trusts ANY Microsoft-signed binary in a trusted tree, which includes signed LOLBins
        /// (powershell, rundll32, mshta, regsvr32, cmd). Those are legitimately killable when they
        /// are the vehicle of an attack - a blanket exemption would let an attacker evade every
        /// kill by routing malicious activity through a signed System32 LOLBin. The response-engine
        /// gate that can override President's-Law MUST therefore be limited to processes that are
        /// actually servicing actors by name, not merely signed-and-in-System32. The behavioral
        /// detectors (mass-deletion, token monitors) can use the broader overload because they are
        /// already scoped to servicing-shaped behavior; the response override cannot.
        /// </summary>
        public static bool IsGenuineServicingActorStrict(string? processName, string? imagePath, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (!NameLooksLikeServicingActor(processName)) return false;
            return IsGenuineServicingActor(imagePath, logger);
        }

        /// <summary>
        /// Advisory: does the process NAME match a known servicing actor? Only meaningful
        /// alongside <see cref="IsGenuineServicingActor(int, Microsoft.Extensions.Logging.ILogger?)"/>;
        /// never a trust decision by itself.
        /// </summary>
        public static bool NameLooksLikeServicingActor(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = processName!.Trim();
            // Strip a trailing .exe if present.
            if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                n = n.Substring(0, n.Length - 4);
            foreach (var svc in ServicingProcessNames)
            {
                if (n.Equals(svc, StringComparison.OrdinalIgnoreCase)) return true;
                // MSRT self-extractor carries a version suffix, e.g. Windows-KB890830-x64-V5.146.
                if (n.StartsWith(svc, StringComparison.OrdinalIgnoreCase) &&
                    svc.StartsWith("windows-kb", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static bool IsMicrosoftSubject(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return false;
            return subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0
                   || subject.IndexOf("Windows Publisher", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string? TryGetEmbeddedSigner(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                using var cert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                return cert.Subject;
            }
            catch
            {
                return null; // no embedded signature (catalog-signed or unsigned)
            }
        }

        //  Native signature verification (correct flags for OS-image trust) 

        // WinVerifyTrust action GUID (WINTRUST_ACTION_GENERIC_VERIFY_V2).
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_CHOICE_CATALOG = 2;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const int WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
        // NOTE: WTD_LIFETIME_SIGNING_FLAG (0x800) is deliberately NOT used here - it rejects
        // genuine OS binaries whose signing cert has expired. See IsMicrosoftSigned.

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint FILE_SHARE_DELETE = 0x4;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref int pcbHash, IntPtr pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, IntPtr pbHash, int cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_CATALOG_INFO
        {
            public int cbStruct;
            public int dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public int cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pUnion; // pFile / pCatalog share this offset
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        /// <summary>Embedded-signature verification without the lifetime-signing flag.</summary>
        private static bool VerifyEmbedded(string filePath)
        {
            IntPtr fileInfoPtr = IntPtr.Zero;
            IntPtr dataPtr = IntPtr.Zero;
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero,
                };
                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pUnion = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                };
                dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                Marshal.StructureToPtr(data, dataPtr, false);

                var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

                // Close trust-provider state to avoid wintrust.dll leaks.
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, dataPtr, true);
                WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

                return result == 0;
            }
            catch { return false; }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
                if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
            }
        }

        /// <summary>
        /// Catalog-store verification without the lifetime-signing flag. The catalog store
        /// (%SystemRoot%\System32\catroot2) is ACL-protected and writable only by
        /// TrustedInstaller, so a file whose hash is present in a signed catalog is genuinely
        /// of Microsoft origin even if the catalog's signing cert has since expired.
        /// </summary>
        private static bool VerifyCatalogSignature(string filePath, Microsoft.Extensions.Logging.ILogger? logger)
        {
            IntPtr hCatAdmin = IntPtr.Zero;
            IntPtr hFile = INVALID_HANDLE_VALUE;
            IntPtr hashPtr = IntPtr.Zero;
            IntPtr hCatInfo = IntPtr.Zero;
            IntPtr catDataPtr = IntPtr.Zero;
            IntPtr catInfoPtr = IntPtr.Zero;
            try
            {
                if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                    return false;

                hFile = CreateFileW(filePath, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile == INVALID_HANDLE_VALUE) return false;

                int hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, IntPtr.Zero, 0);
                if (hashSize <= 0) return false;

                hashPtr = Marshal.AllocHGlobal(hashSize);
                if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, hashPtr, 0))
                    return false;

                IntPtr prev = IntPtr.Zero;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashPtr, hashSize, 0, ref prev);
                if (hCatInfo == IntPtr.Zero) return false; // hash not in any catalog

                var catInfo = new CATALOG_INFO { cbStruct = Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) return false;

                var hashBytes = new byte[hashSize];
                Marshal.Copy(hashPtr, hashBytes, 0, hashSize);
                string memberTag = BitConverter.ToString(hashBytes).Replace("-", "");

                var catWt = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catInfo.wszCatalogFile,
                    pcwszMemberTag = memberTag,
                    pcwszMemberFilePath = filePath,
                    hMemberFile = hFile,
                    pbCalculatedFileHash = hashPtr,
                    cbCalculatedFileHash = hashSize,
                    pcCatalogContext = IntPtr.Zero,
                    hCatAdmin = hCatAdmin,
                };
                catInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                Marshal.StructureToPtr(catWt, catInfoPtr, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_CATALOG,
                    pUnion = catInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                };
                catDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                Marshal.StructureToPtr(data, catDataPtr, false);

                var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref action, catDataPtr);

                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, catDataPtr, true);
                WinVerifyTrust(IntPtr.Zero, ref action, catDataPtr);

                return result == 0;
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[WindowsServicingTrust] Catalog verification failed for '{Path}'", filePath);
                return false;
            }
            finally
            {
                if (catInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(catInfoPtr);
                if (catDataPtr != IntPtr.Zero) Marshal.FreeHGlobal(catDataPtr);
                if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                if (hFile != IntPtr.Zero && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
                if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
    }
}
