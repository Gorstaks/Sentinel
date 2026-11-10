using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors volume mount/dismount events to detect:
    /// - RAM disk creation (ImDisk, OSFMount, SoftPerfect, Arsenal Image Mounter)
    /// - Persistent memory (PMEM/DAX) volume mounts
    /// - VeraCrypt/encrypted container mounts
    /// - VHD/VHDX mounts not initiated by Explorer/DiskMgmt
    /// - Any new volume appearing after service start
    /// - Attacker fallback drives created after phantom device prevention (auto-dismount)
    ///
    /// Addresses the blind spot where attackers stage payloads on volatile/unmapped
    /// volumes that FileActivityMonitor doesn't cover.
    ///
    /// v1.0.1: New monitor.
    /// v1.0.5: Auto-dismount attacker fallback drives correlated with phantom device blocks.
    ///         Fix SUBST drives invisible to WMI - now enumerated via DriveInfo.GetDrives().
    /// </summary>
    public sealed class VolumeMountMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly FileActivityMonitor _fileActivityMonitor;
        private readonly PhantomDeviceMonitor? _phantomDeviceMonitor;
        private readonly SentinelConfig _config;
        private readonly ILogger<VolumeMountMonitor> _logger;

        private readonly HashSet<string> _baselineVolumes = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _baselineDriveLetters = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedVolumes = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Grace period after service start during which new volumes are treated as
        /// late-initializing baseline volumes (slow USB mounts, delayed network drives,
        /// volumes whose WMI DeviceId changes during initialization). Volumes appearing
        /// in this window are baselined silently - never treated as attacker fallback.
        /// </summary>
        private static readonly TimeSpan StartupGracePeriod = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Time window after a phantom device block within which new volumes are
        /// treated as attacker fallback staging drives and auto-dismounted.
        /// </summary>
        private static readonly TimeSpan PhantomCorrelationWindow = TimeSpan.FromMinutes(2);

        private DateTimeOffset _startTime;

        // Known RAM disk driver device names and service names
        private static readonly HashSet<string> RamDiskDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "imdisk", "osfmount", "intmemdrv", "intmemdisk", "intmemsvc",
            "ramdriv", "ramdisk", "vfdwin", "vfd", "dataram", "softperfect",
            "arsenalimager", "aimdevice", "ramphantom", "primo", "primocache",
            "rstmemdrv", "rstmemdsk"
        };

        // Known PMEM/DAX driver names
        private static readonly HashSet<string> PmemDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "pmem", "pmemdrv", "nvdimm", "dax", "stornvme_pmem",
            "winpmem", "pmem_memmap"
        };

        // Known encrypted container volume drivers
        private static readonly HashSet<string> EncryptedContainerDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "veracrypt", "truecrypt", "bestcrypt", "diskcryptor",
            "pgpdisk", "jetico", "securstar"
        };

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DefineDosDevice(uint dwFlags, string lpDeviceName, string? lpTargetPath);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint QueryDosDevice(string lpDeviceName, char[] lpTargetPath, uint ucchMax);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string lpszVolumeMountPoint, [Out] System.Text.StringBuilder lpszVolumeName, uint cchBufferLength);

        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;

        public VolumeMountMonitor(
            DetectionEngine detectionEngine,
            FileActivityMonitor fileActivityMonitor,
            SentinelConfig config,
            ILogger<VolumeMountMonitor> logger,
            PhantomDeviceMonitor? phantomDeviceMonitor = null)
        {
            _detectionEngine = detectionEngine;
            _fileActivityMonitor = fileActivityMonitor;
            _config = config;
            _phantomDeviceMonitor = phantomDeviceMonitor;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[VolumeMountMonitor] Started - scanning for new volume mounts");

            _startTime = DateTimeOffset.UtcNow;

            // Strip any drive letters from EFI/System partitions - these should never be exposed.
            // Previous Sentinel versions or WMI enumeration side effects can cause Windows to
            // assign a letter to the ESP. Fix it on every startup.
            StripSystemPartitionDriveLetters();

            // Baseline current volumes (both DeviceId and drive letter for stable identification)
            // NOTE: SUBST drives are NEVER baselined - they are illegitimate regardless of when
            // they appear. An attacker can create persistence (Run key, scheduled task) that
            // creates the SUBST drive before Sentinel starts to evade runtime-only detection.
            foreach (var vol in GetMountedVolumes())
            {
                // Check if this is a SUBST drive - if so, kill it immediately at startup
                if (ResponsePolicy.MayPerformInlineHostMutation(_config) && !string.IsNullOrEmpty(vol.DriveLetter))
                {
                    var startupClassification = ClassifyVolume(vol);
                    if (string.Equals(startupClassification, "SUBST"))
                    {
                        _logger.LogWarning(
                            "[VolumeMountMonitor] SUBST drive {Drive} found at startup - dismounting (no legitimate SUBST drives exist)",
                            vol.DriveLetter);
                        _ = Task.Run(async () =>
                        {
                            await EmitFallbackDriveDetection(vol, startupClassification);
                            await DismountFallbackDrive(vol);
                            await ReportSubstCreatorCandidates(vol.DriveLetter!);
                            await ReportSubstPersistence(vol.DriveLetter!);
                        });
                        continue; // Do NOT baseline this drive
                    }
                }

                _baselineVolumes.Add(vol.DeviceId);
                if (!string.IsNullOrEmpty(vol.DriveLetter))
                    _baselineDriveLetters.Add(vol.DriveLetter!.TrimEnd('\\').ToUpperInvariant());
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    var currentVolumes = GetMountedVolumes();
                    bool inGracePeriod = DateTimeOffset.UtcNow - _startTime < StartupGracePeriod;

                    foreach (var vol in currentVolumes)
                    {
                        if (_baselineVolumes.Contains(vol.DeviceId)) continue;

                        // Strip drive letters from EFI/boot partitions regardless of when they appear
                        // (USB re-enumeration after sleep, hot-plug, etc. can re-assign letters)
                        if (ResponsePolicy.MayPerformInlineHostMutation(_config) && IsEfiPartition(vol))
                        {
                            _baselineVolumes.Add(vol.DeviceId);
                            if (!string.IsNullOrEmpty(vol.DriveLetter))
                            {
                                var letter = vol.DriveLetter!.TrimEnd('\\', ':');
                                if (!letter.Equals("C"))
                                {
                                    var psi = new ProcessStartInfo
                                    {
                                        FileName = "mountvol.exe",
                                        Arguments = $"{letter}: /D",
                                        UseShellExecute = false,
                                        CreateNoWindow = true,
                                        RedirectStandardOutput = true,
                                        RedirectStandardError = true
                                    };
                                    using var proc = Process.Start(psi);
                                    proc?.WaitForExit(5000);
                                    _logger.LogWarning(
                                        "[VolumeMountMonitor] Stripped drive letter {Letter}: from EFI partition at runtime (Label='{Label}')",
                                        letter, vol.Label);
                                }
                            }
                            continue;
                        }

                        // Check if this volume's drive letter was already present at startup
                        // (WMI can report different DeviceId strings for the same volume as it
                        // fully initializes - GUID paths resolve late, labels populate late, etc.)
                        var normalizedLetter = vol.DriveLetter?.TrimEnd('\\').ToUpperInvariant();
                        bool driveLetterWasBaselined = !string.IsNullOrEmpty(normalizedLetter) &&
                            _baselineDriveLetters.Contains(normalizedLetter!);

                        // Add to baseline (either way, we've seen it now)
                        _baselineVolumes.Add(vol.DeviceId);
                        if (!string.IsNullOrEmpty(normalizedLetter))
                            _baselineDriveLetters.Add(normalizedLetter!);

                        // During startup grace period OR if the drive letter was already baselined,
                        // this is a late-initializing volume - not attacker-created.
                        // EXCEPTION: SUBST drives are NEVER given grace - they are always illegitimate.
                        if (inGracePeriod || driveLetterWasBaselined)
                        {
                            var graceClassification = ClassifyVolume(vol);
                            if (string.Equals(graceClassification, "SUBST"))
                            {
                                // SUBST drives don't get grace period protection - fall through to dismount
                            }
                            else
                            {
                                _logger.LogDebug(
                                    "[VolumeMountMonitor] Baselined late-init volume {Drive} (DeviceId={Id}, grace={Grace}, letterKnown={Known})",
                                    vol.DriveLetter ?? "(no letter)", vol.DeviceId, inGracePeriod, driveLetterWasBaselined);
                                continue;
                            }
                        }

                        // Check cooldown (skip for SUBST - attacker may keep recreating)
                        if (_alertedVolumes.TryGetValue(vol.DeviceId, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                        {
                            // Even during cooldown, always kill SUBST drives
                            var quickClassification = ClassifyVolume(vol);
                            if (ResponsePolicy.MayPerformInlineHostMutation(_config) &&
                                string.Equals(quickClassification, "SUBST") &&
                                !string.IsNullOrEmpty(vol.DriveLetter))
                            {
                                await DismountFallbackDrive(vol);
                                await ReportSubstCreatorCandidates(vol.DriveLetter!);
                            }
                            continue;
                        }

                        _alertedVolumes[vol.DeviceId] = DateTimeOffset.UtcNow;

                        var classification = ClassifyVolume(vol);

                        // v1.0.5: SUBST drives appearing at runtime are ALWAYS malicious.
                        // There is no legitimate reason for a SUBST drive to be created after
                        // boot - these are the #1 attacker fallback technique for staging
                        // payloads after their primary C2 relay is cut off.
                        // No phantom device correlation required for SUBST - unconditional dismount (no process is killed; 3.7.1).
                        if (ResponsePolicy.MayPerformInlineHostMutation(_config) &&
                            string.Equals(classification, "SUBST") &&
                            !string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            _logger.LogWarning(
                                "[VolumeMountMonitor] SUBST drive {Drive} created at runtime - unconditional dismount (attacker fallback)",
                                vol.DriveLetter);
                            await EmitFallbackDriveDetection(vol, classification);
                            await DismountFallbackDrive(vol);
                            await ReportSubstCreatorCandidates(vol.DriveLetter!);
                            await ReportSubstPersistence(vol.DriveLetter!);


                            continue;
                        }

                        // For non-SUBST suspicious volumes (VHD, RAM disk, encrypted containers):
                        // require phantom device correlation to avoid dismounting legitimate
                        // developer VHDs or VeraCrypt containers.
                        bool isAttackerFallback = _phantomDeviceMonitor != null &&
                            ResponsePolicy.MayPerformInlineHostMutation(_config) &&
                            _phantomDeviceMonitor.HasRecentBlock(PhantomCorrelationWindow) &&
                            !IsLikelyLegitimateVolume(vol, classification);

                        if (isAttackerFallback && !string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            await EmitFallbackDriveDetection(vol, classification);
                            await DismountFallbackDrive(vol);
                            continue; // Don't extend FileActivityMonitor to a dismounted drive
                        }

                        await EmitVolumeDetection(vol, classification);

                        // Dynamically extend FileActivityMonitor coverage to new volume.
                        // v1.3.10: Skip CDRom/ISO-type drives - these are DISM/NTLite WIM mounts.
                        // Adding a FileSystemWatcher on a mounted WIM drive causes Restart Manager
                        // calls on every file event inside the image, which compete with the
                        // servicing tool's write locks and stall operations for minutes.
                        // FileVerdictScanner already excludes CDRom drives (DriveType check) and
                        // the servicing-process guard covers any stragglers.
                        if (!string.IsNullOrEmpty(vol.DriveLetter) &&
                            !string.Equals(classification, "ISO") &&
                            !IsWimMountDrive(vol.DriveLetter!))
                        {
                            _fileActivityMonitor.AddWatchPath(vol.DriveLetter!);
                            _logger.LogInformation(
                                "[VolumeMountMonitor] Extended FileActivityMonitor to new volume: {Drive}",
                                vol.DriveLetter);
                        }
                        else if (!string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            _logger.LogDebug(
                                "[VolumeMountMonitor] Skipped FileActivityMonitor extension for WIM/ISO volume: {Drive} ({Class})",
                                vol.DriveLetter, classification);
                        }
                    }

                    // Cleanup stale alerts
                    var stale = _alertedVolumes
                        .Where(kv => DateTimeOffset.UtcNow - kv.Value > TimeSpan.FromHours(1))
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in stale) _alertedVolumes.TryRemove(key, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[VolumeMountMonitor] Error"); }
            }
        }

        /// <summary>
        /// Dismounts an attacker-created fallback drive. Handles multiple creation methods:
        /// 1. SUBST drives (DefineDosDevice)
        /// 2. VHD/VHDX mounts (diskpart or PowerShell)
        /// 3. ImDisk/RAM drives (imdisk removal)
        /// 4. Generic mounted volumes (mountvol removal)
        /// </summary>
        private async Task DismountFallbackDrive(VolumeInfo vol)
        {
            var driveLetter = vol.DriveLetter!.TrimEnd('\\', ':');
            bool dismounted = false;

            try
            {
                // Method 1: Try removing as a SUBST drive (most common attacker technique)
                dismounted = RemoveSubstDrive(driveLetter);

                if (!dismounted)
                {
                    // Method 2: Try dismounting as a VHD
                    dismounted = await DismountVhd(driveLetter);
                }

                if (!dismounted)
                {
                    // Try dismounting as an ISO (virtual CD-ROM)
                    dismounted = await DismountIso(driveLetter);
                }

                if (!dismounted)
                {
                    // Method 3: Remove volume mount point (works for any mounted volume)
                    dismounted = RemoveVolumeMountPoint(driveLetter);
                }

                if (dismounted)
                {
                    _logger.LogWarning(
                        "[VolumeMountMonitor] DISMOUNTED attacker fallback drive {Drive}: (Label='{Label}', FS={FS})",
                        vol.DriveLetter, vol.Label, vol.FileSystem);
                }
                else
                {
                    _logger.LogError(
                        "[VolumeMountMonitor] Failed to dismount suspected fallback drive {Drive}",
                        vol.DriveLetter);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[VolumeMountMonitor] Error dismounting fallback drive {Drive}", vol.DriveLetter);
            }
        }

        /// <summary>
        /// Removes a SUBST-created virtual drive by calling DefineDosDevice with remove flags.
        /// This is the most common attacker fallback: 'subst S: C:\some\hidden\path'
        /// </summary>
        private bool RemoveSubstDrive(string driveLetter)
        {
            try
            {
                // First check if this is actually a SUBST drive by querying the DOS device
                var buffer = new char[260];
                uint result = QueryDosDevice($"{driveLetter}:", buffer, (uint)buffer.Length);
                if (result > 0)
                {
                    var target = new string(buffer, 0, (int)result).TrimEnd('\0');

                    // SUBST drives have targets like "\??\C:\path" (the \??\ prefix indicates substitution)
                    if (target.StartsWith(@"\??\"))
                    {
                        // Remove the SUBST mapping (works if SUBST is in our session / global)
                        bool removed = DefineDosDevice(
                            DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                            $"{driveLetter}:",
                            target);

                        if (removed)
                        {
                            _logger.LogWarning(
                                "[VolumeMountMonitor] Removed SUBST drive {Letter}: -> {Target}",
                                driveLetter, target);
                            return true;
                        }
                    }
                }

                // If DefineDosDevice failed or we can't see the drive (per-session SUBST in user session),
                // remove it by executing subst /D in the user's session
                return RemoveSubstDriveInUserSession(driveLetter);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] SUBST removal failed for {Letter}", driveLetter);
                return false;
            }
        }

        /// <summary>
        /// 3.7.1: observe-only. Reports processes that look like the SUBST creator. It never
        /// terminates anything. Process kill authority needs a Tier1 behavioral terminal through
        /// <see cref="AdvancedResponseEngine"/>; a SUBST mapping can be created by any standard
        /// user, so killing "the creator", its parent, or "recently started" processes would let a
        /// low-privilege user steer SYSTEM into terminating legitimate software.
        /// </summary>
        private async Task ReportSubstCreatorCandidates(string driveLetter)
        {
            var normalizedLetter = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();
            if (!IsSingleDriveLetter(normalizedLetter)) return;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CommandLine FROM Win32_Process " +
                    "WHERE Name = 'subst.exe' OR Name = 'cmd.exe' OR Name = 'powershell.exe' OR Name = 'pwsh.exe'");
                foreach (ManagementObject proc in searcher.Get())
                {
                    var cmdLine = proc["CommandLine"]?.ToString() ?? "";
                    var pid = Convert.ToInt32(proc["ProcessId"]);
                    var name = proc["Name"]?.ToString() ?? "";
                    if (pid <= 4) continue;
                    bool mentionsDrive = cmdLine.IndexOf("subst", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        cmdLine.IndexOf(normalizedLetter + ":", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!mentionsDrive) continue;
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "SUBST Drive Creator Candidate (observe-only)",
                        Evidence = $"Process {name} (PID {pid}) has a command line naming SUBST drive {normalizedLetter}:",
                        Reasoning = "A process command line mentions the SUBST drive that was just dismounted. " +
                                    "A command line is attacker-controlled and any user can run subst, so this is context only and never authorizes a kill.",
                        Confidence = 0.40,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = name,
                        ProcessId = pid
                    }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] SUBST creator candidate report failed");
            }
        }

        /// <summary>
        /// 3.7.1: observe-only. Reports HKLM Run/RunOnce values that would recreate the SUBST drive.
        /// It deletes nothing: matching on substrings of user-writable data and deleting would let
        /// a standard user make SYSTEM remove other software's autostart entries.
        /// </summary>
        private async Task ReportSubstPersistence(string driveLetter)
        {
            var normalizedLetter = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();
            if (!IsSingleDriveLetter(normalizedLetter)) return;
            foreach (var path in new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            })
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                    if (key == null) continue;
                    foreach (var valueName in key.GetValueNames())
                    {
                        var valueData = key.GetValue(valueName)?.ToString() ?? "";
                        if (valueData.IndexOf("subst", StringComparison.OrdinalIgnoreCase) < 0 ||
                            valueData.IndexOf(normalizedLetter + ":", StringComparison.OrdinalIgnoreCase) < 0)
                            continue;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "SUBST Drive Persistence Candidate (observe-only)",
                            Evidence = $"HKLM\\{path}\\{valueName} references SUBST drive {normalizedLetter}:",
                            Reasoning = "An autostart entry recreates a SUBST drive. Reported for review; Sentinel does not delete autostart entries on a substring match.",
                            Confidence = 0.40,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "registry",
                            ProcessId = 0
                        }).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[VolumeMountMonitor] SUBST persistence report failed for {Path}", path);
                }
            }
        }

        /// <summary>
        /// Strips drive letters from EFI System Partitions and Recovery partitions.
        /// These partitions should NEVER have a drive letter. If one is assigned (by a previous
        /// Sentinel version's WMI enumeration side effect, or by Windows disk management bugs),
        /// remove it immediately on startup to prevent user confusion and potential security issues.
        /// </summary>
        private void StripSystemPartitionDriveLetters()
        {
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!drive.IsReady) continue;

                        var fs = drive.DriveFormat;
                        if (!string.Equals(fs, "FAT32") &&
                            !string.Equals(fs, "FAT"))
                            continue;

                        var letter = drive.Name.TrimEnd('\\'); // e.g. "S:"
                        if (string.IsNullOrEmpty(letter)) continue;

                        var driveLetter = letter.TrimEnd(':');
                        if (driveLetter.Equals("C")) continue;

                        var capacity = drive.TotalSize;
                        var label = drive.VolumeLabel;

                        if (IsEfiPartitionByAttributes(capacity, label))
                        {
                            // Remove the drive letter
                            var psi = new ProcessStartInfo
                            {
                                FileName = "mountvol.exe",
                                Arguments = $"{driveLetter}: /D",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            using var proc = Process.Start(psi);
                            proc?.WaitForExit(5000);

                            var deviceId = GetVolumeGuidPath(drive.Name);
                            SetNoDefaultDriveLetter(deviceId, driveLetter);

                            _logger.LogWarning(
                                "[VolumeMountMonitor] Stripped drive letter {Letter}: from system partition (Label='{Label}', Size={Size}MB) - NoDefaultDriveLetter set",
                                driveLetter, label, capacity / (1024 * 1024));
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[VolumeMountMonitor] Failed to inspect drive {Drive} for EFI partition", drive.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] StripSystemPartitionDriveLetters failed");
            }
        }

        /// <summary>
        /// Permanently prevents a volume from being auto-assigned a drive letter by the
        /// Mount Point Manager. Without this, every Win32_Volume WMI query triggers
        /// re-assignment of letters to letterless volumes (known Windows behavior).
        /// Uses diskpart "automount disable" per-volume + registry SAN policy.
        /// </summary>
        private void SetNoDefaultDriveLetter(string volumeDeviceId, string driveLetter)
        {
            try
            {
                // Method 1: Use mountvol /N on the volume GUID path to set NoDefaultDriveLetter
                // volumeDeviceId from WMI looks like: \\?\Volume{guid}\
                if (!string.IsNullOrEmpty(volumeDeviceId))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "mountvol.exe",
                        Arguments = $"{driveLetter}: /N",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);
                }

                // Method 2: Set the MountMgr NoAutoMount registry key for this specific volume
                // HKLM\SYSTEM\MountedDevices - remove the \DosDevices\X: entry
                try
                {
                    using var mountedDevices = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices", writable: true);
                    if (mountedDevices != null)
                    {
                        var dosDeviceName = $@"\DosDevices\{driveLetter}:";
                        if (mountedDevices.GetValue(dosDeviceName) != null)
                        {
                            mountedDevices.DeleteValue(dosDeviceName, throwOnMissingValue: false);
                            _logger.LogDebug("[VolumeMountMonitor] Removed MountedDevices entry for {Letter}:", driveLetter);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[VolumeMountMonitor] MountedDevices cleanup failed for {Letter}", driveLetter);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] SetNoDefaultDriveLetter failed for {Letter}", driveLetter);
            }
        }

        /// <summary>
        /// Checks if a VolumeInfo represents an EFI/boot partition based on filesystem, label, and capacity.
        /// Used by both startup stripping and runtime scanning to prevent EFI partitions from
        /// being exposed with drive letters (VTOYEFI on Ventoy USBs, standard ESP, etc.)
        /// </summary>
        private bool IsEfiPartition(VolumeInfo vol)
        {
            if (string.IsNullOrEmpty(vol.FileSystem)) return false;
            if (!vol.FileSystem!.Equals("FAT32") &&
                !vol.FileSystem.Equals("FAT"))
                return false;

            // We don't have capacity in VolumeInfo from the scan loop - check by label only
            // for runtime detection. EFI partitions have distinctive labels.
            var label = vol.Label ?? "";
            return string.IsNullOrEmpty(label) ||
                   label.Contains("EFI") ||
                   label.Equals("SYSTEM") ||
                   label.Equals("ESP") ||
                   label.Equals("BOOT");
        }

        /// <summary>
        /// Checks if a volume with known attributes looks like an EFI/boot partition.
        /// Requires both label match AND small capacity (&lt;= 300MB) for accuracy.
        /// </summary>
        private static bool IsEfiPartitionByAttributes(long capacity, string label)
        {
            return capacity > 0 && capacity <= 300 * 1024 * 1024 &&
                (string.IsNullOrEmpty(label) ||
                 label.Contains("EFI") ||
                 label.Equals("SYSTEM") ||
                 label.Equals("ESP") ||
                 label.Equals("BOOT"));
        }

        /// <summary>
        /// Determines if a volume is likely legitimate and should NOT be auto-dismounted
        /// even if there's a recent phantom device block. This prevents false positives where
        /// an unrelated network device appearing on LAN causes a legitimate drive (USB stick,
        /// mapped network drive, external HDD) to get nuked.
        ///
        /// Attacker fallback drives are typically: SUBST drives, VHD/VHDX mounts, RAM disks,
        /// or encrypted containers - not standard removable/fixed volumes with NTFS/FAT/exFAT.
        /// </summary>
        private bool IsLikelyLegitimateVolume(VolumeInfo vol, string classification)
        {
            // SUBST drives, RAM disks, encrypted containers, and VHDs are never "likely legitimate"
            // in the context of phantom device correlation
            if (classification.Contains("SUBST") ||
                classification.Contains("RamDisk") ||
                classification.Contains("Encrypted") ||
                classification.Contains("VHD") ||
                classification.Contains("PMEM") ||
                classification.Contains("ISO"))
            {
                return false; // These are suspicious - allow fallback dismount
            }

            // Standard physical volumes (USB drives, external HDDs) with well-known filesystems
            // are very unlikely to be attacker-created fallback drives
            var knownFs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "NTFS", "FAT", "FAT32", "exFAT", "ReFS"
            };

            if (!string.IsNullOrEmpty(vol.FileSystem) && knownFs.Contains(vol.FileSystem!))
            {
                // Has a real filesystem - check if it's also a standard drive type
                if (!string.IsNullOrEmpty(vol.DriveLetter))
                {
                    try
                    {
                        var driveInfo = new DriveInfo(vol.DriveLetter!.TrimEnd('\\'));
                        if (driveInfo.DriveType == DriveType.Removable ||
                            driveInfo.DriveType == DriveType.Fixed ||
                            driveInfo.DriveType == DriveType.Network)
                        {
                            return true; // Standard removable/fixed/network drive - don't dismount
                        }
                    }
                    catch
                    {
                        // Drive not accessible - fall through to suspicious
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Queries WMI Win32_Volume for all currently mounted volumes.
        /// Returns volume info including DeviceId, drive letter, label, and filesystem.
        /// </summary>
        private string GetVolumeGuidPath(string driveName)
        {
            var sb = new System.Text.StringBuilder(64);
            if (GetVolumeNameForVolumeMountPoint(driveName, sb, (uint)sb.Capacity))
            {
                return sb.ToString();
            }
            return driveName;
        }

        /// <summary>
        /// Queries all currently mounted volumes.
        /// Returns volume info including DeviceId, drive letter, label, and filesystem.
        /// </summary>
        private List<VolumeInfo> GetMountedVolumes()
        {
            var volumes = new List<VolumeInfo>();
            var seenDriveLetters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        var driveLetter = drive.Name.TrimEnd('\\'); // e.g. "C:"
                        
                        // Check if it's a SUBST drive first
                        var buffer = new char[1024];
                        uint result = QueryDosDevice(driveLetter, buffer, (uint)buffer.Length);
                        bool isSubst = false;
                        if (result > 0)
                        {
                            var target = new string(buffer, 0, (int)result).TrimEnd('\0');
                            if (target.StartsWith(@"\??\"))
                            {
                                isSubst = true;
                            }
                        }

                        string deviceId;
                        string? label = null;
                        string? fileSystem = null;

                        if (isSubst)
                        {
                            deviceId = $"SUBST:{driveLetter}";
                        }
                        else
                        {
                            deviceId = GetVolumeGuidPath(drive.Name);
                            if (drive.IsReady)
                            {
                                label = drive.VolumeLabel;
                                fileSystem = drive.DriveFormat;
                            }
                        }

                        volumes.Add(new VolumeInfo
                        {
                            DeviceId = deviceId,
                            DriveLetter = driveLetter,
                            Label = label,
                            FileSystem = fileSystem
                        });

                        if (!string.IsNullOrEmpty(driveLetter))
                            seenDriveLetters.Add(driveLetter);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[VolumeMountMonitor] Failed to query drive info for {Drive}", drive.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] Drive enumeration failed");
            }

            // Second: query each active user session for SUBST drives the service can't see
            try
            {
                var sessionSubstDrives = EnumerateUserSessionSubstDrives();
                foreach (var (letter, target) in sessionSubstDrives)
                {
                    if (seenDriveLetters.Contains(letter)) continue;
                    // Avoid duplicates from Session 0 check above
                    if (volumes.Any(v => string.Equals(v.DriveLetter, letter)))
                        continue;

                    volumes.Add(new VolumeInfo
                    {
                        DeviceId = $"SUBST:{letter}",
                        DriveLetter = letter,
                        Label = null,
                        FileSystem = null
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] Drive enumeration failed");
            }

            return volumes;
        }

        /// <summary>
        /// Enumerates SUBST drives across all active user sessions by running 'subst' as each
        /// logged-in user. Required because SUBST creates per-session DOS device mappings that
        /// are invisible from Session 0 (where this service runs).
        /// </summary>
        private List<(string Letter, string Target)> EnumerateUserSessionSubstDrives()
        {
            var results = new List<(string, string)>();
            try
            {
                // Run 'subst' which lists all SUBST drives in the current session.
                // Since we're in Session 0, this only shows global ones. To see user-session
                // SUBST drives, we query WMI Win32_Process for any running 'subst.exe' or we
                // use the registry-based approach: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
                // entries that contain 'subst' indicate persistent SUBST drives.
                //
                // More reliable: enumerate \GLOBAL??\X: symlinks via NtQueryDirectoryObject,
                // or use 'query session' to find active sessions and impersonate.
                //
                // Practical approach: use PsExec-style session enumeration via WTSEnumerateSessions
                // and run subst in each session. But simplest for now: use tasklist + parse
                // or just run 'cmd /c subst' with CreateProcessAsUser for each session.
                //
                // SIMPLEST CORRECT APPROACH: Enumerate all drive letters visible from ALL sessions
                // by querying the object manager namespace \Sessions\N\DosDevices\ for each active
                // session. We use WMI Win32_LogonSession + registry approach as fallback.

                // Method 1: Check registry for persistent SUBST (Run keys across all user profiles)
                var profileList = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
                if (profileList != null)
                {
                    foreach (var sidString in profileList.GetSubKeyNames())
                    {
                        try
                        {
                            using var userRunKey = Registry.Users.OpenSubKey($@"{sidString}\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                            if (userRunKey == null) continue;

                            foreach (var valueName in userRunKey.GetValueNames())
                            {
                                var value = userRunKey.GetValue(valueName)?.ToString() ?? "";
                                if (value.Contains("subst"))
                                {
                                    // Parse drive letter from command like: subst S: C:\path
                                    var match = System.Text.RegularExpressions.Regex.Match(
                                        value, @"subst\s+([A-Za-z]):?\s+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                                    if (match.Success)
                                    {
                                        var letter = match.Groups[1].Value.ToUpperInvariant() + ":";
                                        var targetMatch = System.Text.RegularExpressions.Regex.Match(
                                            value, @"subst\s+[A-Za-z]:?\s+(.+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                                        var target = targetMatch.Success ? targetMatch.Groups[1].Value.Trim().Trim('"') : "unknown";
                                        results.Add((letter, target));
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }

                // Method 2: Run 'subst' via PsExec-like approach in each user session.
                // We use WTSGetActiveConsoleSessionId to find the interactive session and
                // spawn subst.exe there to enumerate + remove.
                uint activeSession = WTSGetActiveConsoleSessionId();
                if (activeSession != 0xFFFFFFFF && activeSession != 0)
                {
                    // There's an active user session - run 'subst' there to enumerate
                    var substOutput = RunInUserSession(activeSession, "subst.exe", "");
                    if (!string.IsNullOrEmpty(substOutput))
                    {
                        // Output format: "S:\: => C:\some\path"
                        foreach (var line in substOutput!.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            var parts = line.Split(new[] { "=>" }, StringSplitOptions.None);
                            if (parts.Length == 2)
                            {
                                var letter = parts[0].Trim().TrimEnd('\\', ':') + ":";
                                var target = parts[1].Trim();
                                if (!results.Any(r => r.Item1.Equals(letter)))
                                    results.Add((letter, target));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] EnumerateUserSessionSubstDrives failed");
            }
            return results;
        }

        /// <summary>
        /// Runs a command in the specified user session and returns its stdout.
        /// Uses CreateProcessAsUser with the session's token to execute in user context.
        /// </summary>
        private string? RunInUserSession(uint sessionId, string exePath, string arguments)
        {
            IntPtr userToken = IntPtr.Zero;
            IntPtr duplicateToken = IntPtr.Zero;
            try
            {
                if (!WTSQueryUserToken(sessionId, out userToken))
                {
                    _logger.LogDebug("[VolumeMountMonitor] WTSQueryUserToken failed for session {Session}", sessionId);
                    return null;
                }

                // Duplicate token for CreateProcessAsUser
                if (!DuplicateTokenEx(userToken, 0x10000000 /* GENERIC_ALL */, IntPtr.Zero,
                    2 /* SecurityImpersonation */, 1 /* TokenPrimary */, out duplicateToken))
                {
                    return null;
                }

                // Set up process to capture stdout via temp file, using cmd.exe but fully hidden
                var tempFile = Path.Combine(Path.GetTempPath(), $"sentinel_subst_{sessionId}_{Guid.NewGuid():N}.tmp");
                var cmdLine = string.IsNullOrEmpty(arguments)
                    ? $"cmd.exe /c \"{exePath}\" > \"{tempFile}\" 2>&1"
                    : $"cmd.exe /c \"{exePath}\" {arguments} > \"{tempFile}\" 2>&1";

                var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
                si.lpDesktop = @"winsta0\default";
                si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
                si.wShowWindow = 0;      // SW_HIDE

                if (CreateProcessAsUser(duplicateToken, null, cmdLine,
                    IntPtr.Zero, IntPtr.Zero, false,
                    0x08000000 /* CREATE_NO_WINDOW */,
                    IntPtr.Zero, null, ref si, out var pi))
                {
                    WaitForSingleObject(pi.hProcess, 5000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);

                    if (File.Exists(tempFile))
                    {
                        var output = File.ReadAllText(tempFile);
                        try { File.Delete(tempFile); } catch { }
                        return output;
                    }
                }
                else
                {
                    _logger.LogDebug("[VolumeMountMonitor] CreateProcessAsUser failed: {Error}", Marshal.GetLastWin32Error());
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] RunInUserSession failed");
            }
            finally
            {
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
                if (duplicateToken != IntPtr.Zero) CloseHandle(duplicateToken);
            }
            return null;
        }

        /// <summary>
        /// Removes a SUBST drive in the active user session (since SUBST is per-session).
        /// </summary>
        private bool RemoveSubstDriveInUserSession(string driveLetter)
        {
            try
            {
                uint activeSession = WTSGetActiveConsoleSessionId();
                if (activeSession == 0xFFFFFFFF)
                {
                    _logger.LogDebug("[VolumeMountMonitor] No active console session for SUBST removal");
                    return false;
                }

                // If we're in Session 0 and the SUBST is in user session, remove it there
                if (activeSession != 0)
                {
                    var output = RunInUserSession(activeSession, "subst.exe", $"/D {driveLetter}:");
                    _logger.LogWarning("[VolumeMountMonitor] Removed SUBST {Letter}: in user session {Session}",
                        driveLetter, activeSession);
                    return true; // subst /D doesn't produce output on success
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] RemoveSubstDriveInUserSession failed for {Letter}", driveLetter);
                return false;
            }
        }

        // P/Invoke for cross-session process creation
        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, int impersonationLevel, int tokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcessAsUser(IntPtr hToken, string? lpApplicationName,
            string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
            string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        /// <summary>
        /// Returns true when a drive letter looks like a DISM/NTLite WIM mount:
        ///   - DriveType is CDRom (how Windows exposes a mounted WIM image)
        ///   - OR a known servicing process (dism, dismhost, ntlite, tiworker) is currently
        ///     running - the mount may have just appeared before DriveType updates.
        ///
        /// v1.3.10: We skip extending FileActivityMonitor to these drives because every file
        /// event inside the mounted image triggers a Restart Manager handle scan that competes
        /// with DISM/NTLite's exclusive write locks, stalling feature-disable operations.
        /// </summary>
        private static bool IsWimMountDrive(string driveLetter)
        {
            try
            {
                var di = new DriveInfo(driveLetter.TrimEnd('\\'));
                if (di.DriveType == DriveType.CDRom)
                    return true;
            }
            catch { }

            // Also guard the race window: servicing process running but DriveType not yet CDRom
            try
            {
                foreach (var proc in System.Diagnostics.Process.GetProcesses())
                {
                    try
                    {
                        var n = proc.ProcessName;
                        proc.Dispose();
                        if (n.Equals("dism",             StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("dismhost",         StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("ntlite",           StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("tiworker",         StringComparison.OrdinalIgnoreCase) ||
                            n.Equals("trustedinstaller"))
                            return true;
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        /// <summary>
        /// Classifies a volume based on its backing driver/device characteristics.
        /// Returns a classification string: "RamDisk", "PMEM", "Encrypted", "VHD", "SUBST", or "Unknown".
        /// </summary>
        private string ClassifyVolume(VolumeInfo vol)
        {
            if (string.IsNullOrEmpty(vol.DriveLetter)) return "Unknown";

            try
            {
                // Check if it's a CDRom (virtual ISO mount)
                try
                {
                    var driveInfo = new DriveInfo(vol.DriveLetter!.TrimEnd('\\'));
                    if (driveInfo.DriveType == DriveType.CDRom)
                        return "ISO";
                }
                catch {}

                // Check if it's a SUBST drive
                var buffer = new char[260];
                uint result = QueryDosDevice(vol.DriveLetter!.TrimEnd('\\'), buffer, (uint)buffer.Length);
                if (result > 0)
                {
                    var target = new string(buffer, 0, (int)result).TrimEnd('\0');
                    if (target.StartsWith(@"\??\"))
                        return "SUBST";
                }

                // Check device backing via WMI Win32_DiskDrive -> service name
                using var searcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{vol.DriveLetter.TrimEnd('\\')}'}}" +
                    " WHERE AssocClass=Win32_LogicalDiskToPartition");
                foreach (ManagementObject partition in searcher.Get())
                {
                    using var diskSearcher = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partition["DeviceID"]}'}}" +
                        " WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject disk in diskSearcher.Get())
                    {
                        var pnpId = disk["PNPDeviceID"]?.ToString() ?? "";
                        var model = disk["Model"]?.ToString() ?? "";

                        // RAM disk drivers
                        if (RamDiskDrivers.Any(d => pnpId.Contains(d) ||
                                                     model.Contains(d)))
                            return "RamDisk";

                        // PMEM drivers
                        if (PmemDrivers.Any(d => pnpId.Contains(d)))
                            return "PMEM";

                        // VHD/VHDX (Microsoft Virtual Disk)
                        if (model.Contains("Virtual Disk") ||
                            pnpId.Contains("VHDMP"))
                            return "VHD";

                        // Encrypted containers
                        if (EncryptedContainerDrivers.Any(d => pnpId.Contains(d) ||
                                                               model.Contains(d)))
                            return "Encrypted";
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] Classification failed for {Drive}", vol.DriveLetter);
            }

            return "Unknown";
        }

        private async Task EmitVolumeDetection(VolumeInfo vol, string classification)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "New Volume Mount Detected",
                Evidence = $"Drive={vol.DriveLetter ?? "(no letter)"}, Label='{vol.Label}', FS={vol.FileSystem}, Type={classification}",
                Reasoning = $"A new volume ({classification}) appeared after Sentinel startup. " +
                            "This may be legitimate (USB drive, network mount) or suspicious (RAM disk, SUBST, encrypted container). " +
                            "FileActivityMonitor has been extended to cover this volume.",
                Confidence = classification == "Unknown" ? 0.40 : 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            });
        }

        private async Task EmitFallbackDriveDetection(VolumeInfo vol, string classification)
        {
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Attacker Fallback Drive: Correlated with Phantom Device Block",
                Evidence = $"Drive={vol.DriveLetter}, Label='{vol.Label}', FS={vol.FileSystem}, Type={classification}",
                Reasoning = "A new volume appeared within 2 minutes of a phantom device being blocked. " +
                            "This matches the attacker fallback pattern: after losing their C2 relay device, " +
                            "attackers create a local staging drive (SUBST, VHD, or RAM disk) to continue the attack. " +
                            "Auto-dismounting this volume.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "SYSTEM",
                ProcessId = 0
            });
        }

        internal static bool IsSingleDriveLetter(string? driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter)) return false;
            var s = driveLetter!.Trim().TrimEnd(':', '\\');
            return s.Length == 1 && char.IsLetter(s[0]);
        }

        /// <summary>
        /// Runs a constant PowerShell command; caller data goes only through SENTINEL_ARG_n
        /// environment variables. Output is not redirected, so an unread pipe cannot block.
        /// </summary>
        private static async Task<bool> RunConstantPowerShellAsync(string command, params string[] args)
        {
            using var proc = Process.Start(ConstantPowerShell.CreateStartInfo(command, args));
            if (proc == null) return false;
            await proc.WaitForExitAsync();
            return proc.ExitCode == 0;
        }

        private async Task<bool> DismountVhd(string driveLetter)
        {
            try
            {
                if (!IsSingleDriveLetter(driveLetter)) return false;
                var letter = driveLetter.Trim().TrimEnd(':', '\\').ToUpperInvariant();
                return await RunConstantPowerShellAsync(
                    "Dismount-VHD -DiskNumber ((Get-Partition -DriveLetter $env:SENTINEL_ARG_0).DiskNumber) -Confirm:$false",
                    letter);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] VHD dismount failed for {Letter}", driveLetter);
                return false;
            }
        }

        private async Task<bool> DismountIso(string driveLetter)
        {
            try
            {
                if (!IsSingleDriveLetter(driveLetter)) return false;
                var letter = driveLetter.Trim().TrimEnd(':', '\\').ToUpperInvariant();
                return await RunConstantPowerShellAsync(
                    "Dismount-DiskImage -DevicePath $env:SENTINEL_ARG_0 -ErrorAction SilentlyContinue",
                    $"\\\\.\\{letter}:");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] ISO dismount failed for {Letter}", driveLetter);
                return false;
            }
        }

        private bool RemoveVolumeMountPoint(string driveLetter)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "mountvol.exe",
                    Arguments = $"{driveLetter}: /D",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                proc.WaitForExit(10000);
                return proc.ExitCode == 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] mountvol removal failed for {Letter}", driveLetter);
                return false;
            }
        }
    }

    internal sealed class VolumeInfo
    {
        public string DeviceId { get; set; } = string.Empty;
        public string? DriveLetter { get; set; }
        public string? Label { get; set; }
        public string? FileSystem { get; set; }
    }
}

