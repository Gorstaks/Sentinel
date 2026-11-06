using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class FileVerdictScanner : BackgroundService, ISensorProgressSource
    {
        public SensorProgress Progress { get; } = new(TimeSpan.FromSeconds(30))
            { Scope = "File watcher subscription checks; does not prove every file was delivered/scanned. Overflow starts local watcher recovery and a fresh content walk; healthy subscriptions do not establish recovery until enumeration completes." };
        private readonly HashReputationService _reputationService;
        private readonly FileReputationEngine _reputationEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly FileScanIndex _scanIndex;
        private readonly QuarantineManager? _quarantine;
        private readonly JsonlEventLogger? _audit;
        private readonly ILogger<FileVerdictScanner> _logger;
        private readonly List<FileSystemWatcher> _watchers = new();
        private long _watcherFaultGeneration;
        private int _walkDirectoryErrors;
        private readonly ConcurrentQueue<string> _walkErrorExamples = new();
        private bool _requiresFreshWalk;
        private long _walkFiles, _walkSkipped, _walkDirectories;
        private DateTime _walkStarted;
        private string _walkVolume = "Pending";

        // All scannable extensions - matches Antivirus.ps1 coverage
        private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"
        };

        // Container / disk-image extensions worth a bounded content walk (zip-bomb / polyglot /
        // embedded-payload smuggling). These are inspected via FileReputationEngine's bomb-safe
        // ArchiveContentInspector - never extracted to disk. Kept separate from ScanExtensions so
        // container files also flow through hash reputation + the archive inspector.
        private static readonly HashSet<string> ContainerExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".jar", ".apk", ".xpi", ".vsix", ".nupkg", ".appx", ".appxbundle",
            ".msix", ".msixbundle", ".iso", ".img",
        };

        // Only real OS-owned servicing trees are omitted; a folder named mount/ntlite/uup
        // or an unrelated process with a servicing name can never disable scanning globally.
        internal static bool IsOsServicingTree(string path, string windowsDirectory)
        {
            if (string.IsNullOrWhiteSpace(windowsDirectory)) return false;
            string candidate = Path.GetFullPath(path).Replace('/', '\\').TrimEnd('\\');
            string root = Path.GetFullPath(windowsDirectory).Replace('/', '\\').TrimEnd('\\');
            foreach (var part in new[] { "winsxs", "servicing" })
            {
                string tree = root + "\\" + part;
                if (candidate.Equals(tree, StringComparison.OrdinalIgnoreCase) ||
                    candidate.StartsWith(tree + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        // Throttle: max concurrent API lookups to avoid hammering CIRCL/MalwareBazaar
        private readonly SemaphoreSlim _apiThrottle = new(4, 4);

        // Cap on concurrent real-time scan tasks (OnFileCreated / OnFileRenamed).
        // Each task holds async state + retry delays; without a cap a burst install can
        // queue thousands of tasks and spike RAM. Four concurrent scans bound memory; excess work marks a coverage gap for reconciliation.
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _pendingPaths = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _scanTaskThrottle = new(4, 4);
        private CancellationToken _realtimeToken;

        // Sentinel's own data directory and install directory must never be scanned: our
        // log files, verdict ADS writes, and scan index updates would re-enter the scanner
        // in a feedback loop. Computed once at startup (not per-event) from the running
        // process paths so the exclusion follows the actual install, not a hardcoded string.
        private static readonly string SentinelDataDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                         "Sentinel").ToLowerInvariant();
        private static readonly string SentinelInstallDir =
            Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').ToLowerInvariant();

        public FileVerdictScanner(
            HashReputationService reputationService,
            FileVerdictAds verdictAds,
            FileReputationEngine reputationEngine,
            DetectionEngine detectionEngine,
            FileScanIndex scanIndex,
            ILogger<FileVerdictScanner> logger, QuarantineManager? quarantine = null, JsonlEventLogger? audit = null)
        {
            _reputationService = reputationService;
            _reputationEngine = reputationEngine;
            _detectionEngine = detectionEngine;
            _scanIndex = scanIndex;
            _quarantine = quarantine; _audit = audit;
            _logger = logger;
        }

        // A coverage run that lasts at least this long is treated as healthy; restart delays reset after it.
        private static readonly TimeSpan CoverageHealthyRunThreshold = TimeSpan.FromMinutes(10);
        // Upper bound on the delay between coverage rebuilds during a fault storm.
        private static readonly TimeSpan MaxCoverageRestartDelay = TimeSpan.FromMinutes(10);

        // Each rebuild forces a full content walk of every fixed volume. Repeated watcher
        // overflows therefore back off exponentially (5 s, 10 s, 20 s, ... capped) so the
        // walk cannot run back to back and pin the CPU.
        internal static TimeSpan CoverageRestartDelay(int consecutiveLosses)
        {
            int exponent = Math.Min(Math.Max(consecutiveLosses - 1, 0), 10);
            double seconds = Math.Min(5 * Math.Pow(2, exponent), MaxCoverageRestartDelay.TotalSeconds);
            return TimeSpan.FromSeconds(seconds);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            int consecutiveCoverageLosses = 0;
            while (!stoppingToken.IsCancellationRequested)
            {
                var runStarted = DateTime.UtcNow;
                try { await RunVolumeCoverageAsync(stoppingToken).ConfigureAwait(false); }
                catch (WatcherCoverageLostException)
                {
                    consecutiveCoverageLosses = DateTime.UtcNow - runStarted >= CoverageHealthyRunThreshold
                        ? 1
                        : consecutiveCoverageLosses + 1;
                    _requiresFreshWalk = true;
                    var delay = CoverageRestartDelay(consecutiveCoverageLosses);
                    _logger.LogWarning("[FileVerdictScanner] Rebuilding failed subscriptions and reconciling missed file content in {Delay}s; coverage remains degraded during the walk.", (int)delay.TotalSeconds);
                    await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                }
                catch (VolumeCoverageChangedException)
                {
                    _logger.LogInformation("[FileVerdictScanner] Mounted local volumes changed; rebuilding watchers and reconciling scan coverage.");
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                }
            }
        }

        private sealed class WatcherCoverageLostException : InvalidOperationException
        { internal WatcherCoverageLostException(string? message = null) : base(message) { } }

        private sealed class VolumeCoverageChangedException : InvalidOperationException { }

        private async Task RunVolumeCoverageAsync(CancellationToken stoppingToken)
        {
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            stoppingToken = lifetime.Token;
            _realtimeToken = stoppingToken;
            long generation = Interlocked.Read(ref _watcherFaultGeneration);
            ResetWalkProgress();
            ReleaseWatchers(); // a group restart must not accumulate duplicate subscriptions
            _logger.LogInformation("[FileVerdictScanner] Starting lazy verdict scan and file watchers...");
            string? startupError = null;

            // Start drive watchers for all scannable file types - PRIORITY: new files scanned immediately
            var drives = DriveInfo.GetDrives().Where(d => IsScannableDrive(d.DriveType, d.IsReady));
            foreach (var drive in drives)
            {
                try
                {
                    // FileSystemWatcher doesn't support multiple filters natively,
                    // so we watch all files and filter in the event handler
                    var watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                    {
                        IncludeSubdirectories = true,
                        Filter = "*.*",
                        InternalBufferSize = 64 * 1024,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size
                    };
                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileCreated;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnWatcherError;
                    _watchers.Add(watcher);
                    watcher.EnableRaisingEvents = true;
                }
                catch (Exception ex)
                {
                    startupError = $"File watcher unavailable for {drive.Name}: {ex.Message}";
                    Progress.Failed(startupError);
                    _logger.LogWarning(ex, "Failed to start FileSystemWatcher for drive {Drive}", drive.Name);
                }
            }

            // Lazy background walk - scans every file on every NTFS volume, skipping those already marked
            bool freshWalk = _requiresFreshWalk;
            Progress.Failed("File enumeration reconciliation in progress; watcher subscriptions alone do not establish coverage.");
            var walk = Task.Run(() => WalkDrivesAsync(stoppingToken, freshWalk), stoppingToken);
            DateTime? retryAfter = null;
            DateTime nextReputationWalk = DateTime.UtcNow.AddHours(6);
            try
            {
                if (startupError != null) throw new WatcherCoverageLostException(startupError);
                await SuperviseWatchersAsync(walk, () =>
                {
                    // A newly mounted drive needs a watcher AND an initial walk. Restart
                    // locally to reconcile both without consuming the failure restart budget.
                    var currentRoots = new HashSet<string>(DriveInfo.GetDrives()
                        .Where(d => IsScannableDrive(d.DriveType, d.IsReady))
                        .Select(d => d.RootDirectory.FullName), StringComparer.OrdinalIgnoreCase);
                    if (!currentRoots.SetEquals(_watchers.Select(w => w.Path)))
                    {
                        throw new VolumeCoverageChangedException();
                    }
                    if (generation != Interlocked.Read(ref _watcherFaultGeneration)) throw new WatcherCoverageLostException();
                    if (_watchers.Count == 0 || _watchers.Any(w => !w.EnableRaisingEvents))
                    {
                        Progress.Failed("No complete set of active file watcher subscriptions.");
                        throw new WatcherCoverageLostException(Progress.Snapshot().Error);
                    }
                    if (walk.IsFaulted) walk.GetAwaiter().GetResult();
                    if (walk.IsCompleted && DateTime.UtcNow >= nextReputationWalk)
                    {
                        ResetWalkProgress();
                        walk = Task.Run(() => WalkDrivesAsync(stoppingToken, true), stoppingToken);
                        nextReputationWalk = DateTime.UtcNow.AddHours(6);
                    }
                    if (walk.IsCompleted && Volatile.Read(ref _walkDirectoryErrors) > 0)
                    {
                        retryAfter ??= DateTime.UtcNow.AddMinutes(15);
                        if (DateTime.UtcNow >= retryAfter.Value)
                        {
                            // Keep subscriptions alive. Successful indexed files are skipped;
                            // unreadable files/directories are attempted again without changing ACLs.
                            ResetWalkProgress();
                            walk = Task.Run(() => WalkDrivesAsync(stoppingToken, false), stoppingToken);
                            retryAfter = null;
                        }
                    }
                    string failures = string.Join("; ", _walkErrorExamples.Take(3));
                    UpdateCoverageProgress(Progress, walk.IsCompleted, Volatile.Read(ref _walkDirectoryErrors),
                        "Volume " + _walkVolume + "; directories " + Interlocked.Read(ref _walkDirectories) +
                        "; evaluated " + Interlocked.Read(ref _walkFiles) + "; cached " + Interlocked.Read(ref _walkSkipped) +
                        "; elapsed " + (int)(DateTime.UtcNow - _walkStarted).TotalMinutes + " min. " +
                        (retryAfter.HasValue ? "Unreadable paths retry after " + retryAfter.Value.ToString("O") + ". " : "") + failures);
                    if (walk.IsCompleted && Volatile.Read(ref _walkDirectoryErrors) == 0) _requiresFreshWalk = false;
                }, stoppingToken).ConfigureAwait(false);
            }
            finally
            {
                lifetime.Cancel();
                ReleaseWatchers();
                try { await walk.ConfigureAwait(false); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { /* normal worker cancellation */ }
                // All realtime tasks share the cancelled worker lifetime. Drain before restart/disposal.
                for (int i = 0; i < 4; i++) await _scanTaskThrottle.WaitAsync().ConfigureAwait(false);
                _scanTaskThrottle.Release(4);
            }
        }

        private void ResetWalkProgress()
        {
            Interlocked.Exchange(ref _walkDirectoryErrors, 0);
            while (_walkErrorExamples.TryDequeue(out _)) { }
            Interlocked.Exchange(ref _walkFiles, 0); Interlocked.Exchange(ref _walkSkipped, 0);
            Interlocked.Exchange(ref _walkDirectories, 0); _walkStarted = DateTime.UtcNow;
        }
        private void RecordWalkFailure(string path, Exception error)
        {
            if (Interlocked.Increment(ref _walkDirectoryErrors) <= 64)
                _walkErrorExamples.Enqueue(DescribeWalkFailure(path, error));
        }
        internal static string DescribeWalkFailure(string path, Exception error)
        {
            if (path.Length > 512) path = path.Substring(0, 512) + "...";
            return path + " (" + error.GetType().Name + ", 0x" + error.HResult.ToString("X8") + ")";
        }

        internal static bool ShouldTraverseDirectory(FileAttributes attributes)
            => (attributes & FileAttributes.ReparsePoint) == 0;

        internal static bool NeedsStabilization(DateTime lastWrite, DateTime now)
            => now - lastWrite < TimeSpan.FromSeconds(1);

        internal static void UpdateCoverageProgress(SensorProgress progress, bool walkCompleted, int directoryErrors, string? detail = null)
        {
            if (!walkCompleted) progress.Failed("File enumeration reconciliation is still in progress; missed events are not yet reconciled. " + detail);
            else if (directoryErrors > 0) progress.Failed("File enumeration incomplete: " + directoryErrors + " paths could not be read. Subscription health does not close this gap. " + detail);
            else progress.Succeeded();
        }

        internal static async Task SuperviseWatchersAsync(Task initialWalk, Action verifySubscriptions, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                if (initialWalk.IsFaulted) await initialWalk.ConfigureAwait(false);
                verifySubscriptions();
                // Finishing the initial scan does not finish real-time file watching.
                await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            }
        }

        private void ReleaseWatchers()
        {
            foreach (var watcher in _watchers)
            {
                watcher.Created -= OnFileCreated;
                watcher.Changed -= OnFileCreated;
                watcher.Renamed -= OnFileRenamed;
                watcher.Error -= OnWatcherError;
                watcher.Dispose();
            }
            _watchers.Clear();
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            var error = e.GetException();
            Interlocked.Increment(ref _watcherFaultGeneration);
            Progress.Failed("File watcher lost coverage: " + error.Message);
            _logger.LogWarning(error, "File watcher overflow/failure; file coverage requires reconciliation");
        }

        internal static bool IsScannableDrive(DriveType type, bool ready) =>
            ready && (type == DriveType.Fixed || type == DriveType.Removable);

        internal static bool IsScannable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(ext) && (ScanExtensions.Contains(ext) || NanoAvCoverage.IsScannableExtension(ext)))
                return true;

            // Container / disk-image files: bounded content inspection for smuggled payloads.
            if (!string.IsNullOrEmpty(ext) && ContainerExtensions.Contains(ext))
                return true;

            // HARDENING: Files without extensions (or unknown extensions) may still be
            // Windows PE executables - MalwareBazaar dumps, renamed payloads, and staged
            // binaries often lack extensions to evade extension-based scanning.
            // Check PE magic bytes (MZ header) for extensionless files.
            // An attacker can choose any extension. Unknown-extension PE files still receive
            // the same bounded scan; a .dat/.tmp rename is not an exclusion.
            return HasPeMagicBytes(filePath);
        }

        /// <summary>
        /// Checks if a file starts with the MZ magic bytes (0x4D 0x5A) indicating
        /// a Windows PE executable. Used to detect extensionless malware on disk.
        /// </summary>
        private static bool HasPeMagicBytes(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length < 2) return false;
                var b1 = fs.ReadByte();
                var b2 = fs.ReadByte();
                return b1 == 0x4D && b2 == 0x5A; // 'M' 'Z'
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true when <paramref name="filePath"/> is inside Sentinel's own data
        /// directory (ProgramData\Sentinel) or install directory. These paths must never
        /// be scanned: our log writes, scan_index flushes, and ADS updates would re-enter
        /// the scanner in a feedback loop and inflate RAM indefinitely.
        /// </summary>
        private static bool IsSentinelOwnPath(string filePath)
        {
            if (SelfPathGuard.IsNanoAvRuntimeCopy(filePath)) return true;
            if (string.IsNullOrEmpty(filePath)) return false;
            var lower = filePath.ToLowerInvariant();
            // Use StartsWith with a trailing separator so "SentinelOther" doesn't match.
            return lower.StartsWith(SentinelDataDir + "\\", StringComparison.Ordinal)
                || lower.StartsWith(SentinelInstallDir + "\\", StringComparison.Ordinal)
                || string.Equals(lower, SentinelDataDir, StringComparison.Ordinal)
                || string.Equals(lower, SentinelInstallDir, StringComparison.Ordinal);
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e) => QueueRealtimeScan(e.FullPath);
        private void OnFileRenamed(object sender, RenamedEventArgs e) => QueueRealtimeScan(e.FullPath);
        private void RealtimeGap()
        {
            Interlocked.Increment(ref _watcherFaultGeneration);
            Progress.Failed("Realtime file scan budget exceeded or writes continued; reconciliation required.");
        }
        private void QueueRealtimeScan(string path)
        {
            var ct = _realtimeToken;
            if (ct.IsCancellationRequested || IsSentinelOwnPath(path) || !IsScannable(path)) return;
            if (!_pendingPaths.TryAdd(path, 0)) { _pendingPaths.TryUpdate(path, 1, 0); return; }
            if (!_scanTaskThrottle.Wait(0)) { _pendingPaths.TryRemove(path, out _); RealtimeGap(); return; }
            _ = Task.Run(async () =>
            {
                try
                {
                    for (int pass = 0; pass < 3; pass++)
                    {
                        await ScanNewFileAsync(path, ct).ConfigureAwait(false);
                        if (!_pendingPaths.TryUpdate(path, 0, 1)) break;
                        if (pass == 2) RealtimeGap();
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { /* worker stopped */ }
                catch (Exception ex) { RealtimeGap(); _logger.LogWarning(ex, "Realtime file evaluation failed"); }
                finally
                {
                    if (_pendingPaths.TryRemove(path, out var dirty) && dirty != 0 && !ct.IsCancellationRequested) RealtimeGap();
                    _scanTaskThrottle.Release();
                }
            });
        }

        /// <summary>
        /// Fast-path for new/renamed files. Minimal delay, no lazy throttle.
        /// Goal: tag known-malicious files BEFORE they can execute for the first time.
        /// </summary>
        private async Task ScanNewFileAsync(string filePath, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;
            if (IsSentinelOwnPath(filePath)) return;

            if (IsOsServicingTree(filePath, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return;

            // Brief stabilization wait - just enough for the write to finish
            await Task.Delay(500, ct).ConfigureAwait(false);

            int retries = 3;
            while (retries > 0)
            {
                try
                {
                    // File.Exists also returns false on access denial. Only a real
                    // disappearance may be treated as no remaining file to inspect.
                    File.GetAttributes(filePath);

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromMilliseconds(300))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        await ScanFileInternalAsync(filePath, ct).ConfigureAwait(false);
                        return;
                    }
                }
                catch (FileNotFoundException) { return; }
                catch (DirectoryNotFoundException) { return; }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(800, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    RecordWalkFailure(filePath, ex);
                    _logger.LogDebug(ex, "Fast scan failed for new file: {FilePath}", filePath);
                    return;
                }
            }

            // If fast path failed, fall back to lazy scan with longer backoff
            await ScanFileWithBackoffAsync(filePath, ct).ConfigureAwait(false);
        }

        private async Task ScanFileWithBackoffAsync(string filePath, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;

            // Skip excluded paths
            if (IsOsServicingTree(filePath, Environment.GetFolderPath(Environment.SpecialFolder.Windows)))
            {
                return;
            }

            int retries = 5;
            while (retries > 0)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    File.GetAttributes(filePath); // access denial is not absence

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (NeedsStabilization(lastWrite, DateTime.UtcNow))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        await ScanFileInternalAsync(filePath, ct);
                        return;
                    }
                }
                catch (FileNotFoundException) { return; }
                catch (DirectoryNotFoundException) { return; }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(2000, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    RecordWalkFailure(filePath, ex);
                    _logger.LogDebug(ex, "Failed to scan file: {FilePath}", filePath);
                    return;
                }
            }

            RecordWalkFailure(filePath, new IOException("File did not stabilize or remained in use after retries"));
            _logger.LogDebug("File scan abandoned after retries (file likely in use): {FilePath}", filePath);
        }

        private async Task ScanFileInternalAsync(string filePath, CancellationToken ct = default)
        {
            try
            {
                // The engine hashes once and caches analysis for this process. Old ADS
                // verdicts cannot bypass newly added static checks after an upgrade.
                var before = new FileInfo(filePath);
                long originalLength = before.Length, originalWrite = before.LastWriteTimeUtc.Ticks;
                var reputationResult = await _reputationEngine.EvaluateFileAsync(filePath, ct);
                ct.ThrowIfCancellationRequested();
                string hash = reputationResult.Sha256;
                if (string.IsNullOrEmpty(hash)) throw new IOException("File evaluation did not return a completed content hash.");

                if (reputationResult.StaticAnalysis.HasReportedRatMarkers)
                    await _detectionEngine.EmitAsync(RatArtifactInspector.Observation(filePath)).ConfigureAwait(false);

                // Independent compiled file-containment policy. A fresh exact public malware
                // hash may contain a file at rest; it never promotes a Tier2 event or kills a process.
                if (_quarantine != null && _audit != null &&
                    await _reputationService.GetVerdictAsync(hash, ct).ConfigureAwait(false) == HashVerdict.Unsafe)
                {
                    var contained = await _quarantine.ContainKnownHashAsync(filePath, hash, _audit, ct).ConfigureAwait(false);
                    await _audit.LogEventAsync("file_policy", contained).ConfigureAwait(false);
                    _logger.LogWarning("[NanoAV integrated] File policy {Status}: {Path}: {Detail}",
                        contained.Status, filePath, contained.Detail);
                    if (contained.Status == ResponseExecutionStatus.PartiallyCompleted) return;
                }

                // Map composite verdict to legacy HashVerdict for ADS tagging
                HashVerdict verdict;
                switch (reputationResult.Verdict)
                {
                    case FileVerdict.Malicious:
                    case FileVerdict.HighRisk:
                        verdict = HashVerdict.Unsafe;
                        break;
                    case FileVerdict.Trusted:
                    case FileVerdict.LowRisk:
                        verdict = HashVerdict.Safe;
                        break;
                    default:
                        verdict = HashVerdict.Unknown;
                        break;
                }

                // Reputation stays in the central cache. Writing an ADS here would generate
                // Changed events for our own writes and can create an endless rescan feedback loop.

                // v1.6.4: Observe-only - log verdict but NEVER modify file permissions.
                // Sentinel is an EDR (detect + respond to behavior), not an antivirus.
                // Blocking execution based on reputation scores alone caused false positives
                // (including quarantining our own installer) and violates the design principle
                // that response actions only fire when a process is ACTIVELY malicious.
                // Content-smuggling signals are noteworthy on their own, even if the composite
                // verdict lands short of Unsafe - surface them explicitly so an analyst sees them.
                if (reputationResult.StaticAnalysis.IsMzZipPolyglot)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] MZ+ZIP polyglot detected: {FilePath} (SHA256: {Hash}) - runs as .exe but also extracts as a .zip archive.",
                        filePath, hash);
                }
                if (reputationResult.StaticAnalysis.HasEmbeddedScriptPayload)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] Embedded script payload in compressed stream: {FilePath} (SHA256: {Hash}) - decompresses to executable script content.",
                        filePath, hash);
                }

                // v2.8.4: Bounded archive / disk-image content smuggling (zip bomb, nested archive,
                // embedded PE / script host inside a .zip/.iso/.img). This is a CONTENT signal about
                // a file at rest - there is no live malicious process yet and an attacker fully
                // controls container/file names, so per Sentinel's constraints it can NEVER solo-
                // authorize a destructive response. We emit it as a Tier2 observe seed: it enriches
                // correlation and, if the smuggled payload is later executed and does something
                // terminal, the behavioral monitors + chain logic authorize the kill. Fail-closed
                // inspection aborts are surfaced too (a container we could not fully vet).
                var archiveContent = reputationResult.StaticAnalysis.ArchiveContent;
                if (archiveContent != null &&
                    (archiveContent.HasSmugglingSignal || archiveContent.InspectionAborted))
                {
                    await EmitArchiveContentObserveAsync(filePath, hash, archiveContent);
                }

                if (verdict == HashVerdict.Unsafe)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] File risk context (not runtime proof): {FilePath} (SHA256: {Hash}, Score={Score}, Verdict={Verdict})",
                        filePath, hash, reputationResult.CompositeScore, reputationResult.Verdict);
                }
                else if (reputationResult.Verdict == FileVerdict.Suspicious && reputationResult.CompositeScore >= 55)
                {
                    _logger.LogInformation(
                        "[FileVerdictScanner] Suspicious file: {FilePath} (Score={Score}, Entropy={Entropy:F2}, Signed={Signed})",
                        filePath, reputationResult.CompositeScore,
                        reputationResult.StaticAnalysis.Entropy, reputationResult.IsSigned);
                }

                // Evaluation completed for this content. Record cheap stat (path+size+mtime) so the
                // next drive walk skips this file entirely instead of re-reading and re-hashing it.
                // A later content change bumps size/mtime and invalidates this, forcing a re-scan.
                var after = new FileInfo(filePath);
                if (!after.Exists || after.Length != originalLength || after.LastWriteTimeUtc.Ticks != originalWrite)
                    throw new IOException("File changed during evaluation; not entered in the completed-scan index.");
                _scanIndex.MarkScanned(filePath);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                RecordWalkFailure(filePath, ex);
                _logger.LogDebug(ex, "Error in ScanFileInternalAsync for {FilePath}", filePath);
            }
        }

        /// <summary>
        /// Emit a Tier2 observe-tier detection for content-smuggling found inside a container at
        /// rest. Deliberately LogOnly + PID 0: a file's contents are attacker-controllable and no
        /// process is executing yet, so this must never solo-authorize a kill (Sentinel constraint).
        /// It seeds correlation - if the payload is extracted and detonated, behavioral monitors
        /// supply the kill-grade terminal leg and the chain logic authorizes any response.
        /// </summary>
        private async Task EmitArchiveContentObserveAsync(string filePath, string hash, ArchiveContentAnalysis ac)
        {
            try
            {
                string ruleName = ac.ZipBombShape
                    ? "Content Smuggling: Decompression Bomb in Container"
                    : ac.IsDiskImage
                        ? "Content Smuggling: Payload in Disk Image"
                        : "Content Smuggling: Payload in Archive";

                var evidence =
                    $"File={filePath}; SHA256={hash}; " +
                    $"container={(ac.IsDiskImage ? "disk-image" : "archive")}; " +
                    $"findings={ac.Describe()}; " +
                    $"entries={ac.EntryCount}; depth={ac.MaxNestingDepth}; " +
                    $"declaredBytes={ac.DeclaredUncompressedBytes}; containerBytes={ac.ContainerBytes}";

                _logger.LogWarning(
                    "[FileVerdictScanner] {Rule}: {FilePath} (SHA256: {Hash}) - {Findings}",
                    ruleName, filePath, hash, ac.Describe());

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = ruleName,
                    Evidence = evidence,
                    Reasoning =
                        "A container file at rest carries a smuggled payload or decompression-bomb " +
                        "shape (zip bomb / nested archive / embedded executable or script host, or " +
                        "an ISO/IMG carrying such content). This bypasses extension-based scanning " +
                        "because the payload only surfaces when the container is opened or mounted. " +
                        "Content and file names are attacker-controlled, so this is an OBSERVE-tier " +
                        "signal only - it never authorizes a response by itself. It seeds correlation " +
                        "so that if the payload is extracted and executed, the resulting behavioral " +
                        "terminal (reverse shell / C2 / credential theft / bomb expansion in the " +
                        "PseudoSandbox) completes a chain that can be responded to.",
                    // Confidence intentionally modest: this is a content heuristic, not a behavior.
                    Confidence = ac.ZipBombShape || ac.ContainsExecutable ? 0.55 : 0.40,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    SignalType = SignalType.SuspiciousProcess,
                    ProcessName = Path.GetFileName(filePath),
                    ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        ["FilePath"] = filePath,
                        ["Sha256"] = hash,
                        ["ContainerKind"] = ac.IsDiskImage ? "disk-image" : "archive",
                        ["ZipBombShape"] = ac.ZipBombShape.ToString(),
                        ["ContainsExecutable"] = ac.ContainsExecutable.ToString(),
                        ["ContainsScriptHost"] = ac.ContainsScriptHost.ToString(),
                        ["ContainsNestedArchive"] = ac.ContainsNestedArchive.ToString(),
                        ["MaxNestingDepth"] = ac.MaxNestingDepth.ToString(),
                        ["MaxEntryRatio"] = ac.MaxEntryRatio.ToString("F0"),
                        ["OverallRatio"] = ac.OverallRatio.ToString("F0"),
                        ["InspectionAborted"] = ac.InspectionAborted.ToString(),
                        // Weak observe seed marker - keeps it out of any solo kill-grade path.
                        ["WeakObserveSeed"] = "true",
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileVerdictScanner] Failed to emit archive-content observe for {FilePath}", filePath);
            }
        }

        private async Task WalkDrivesAsync(CancellationToken ct, bool freshWalk)
        {
            // Wait a bit after startup to let higher-priority monitors initialize
            await Task.Delay(TimeSpan.FromSeconds(30), ct);

            var drives = DriveInfo.GetDrives().Where(d => IsScannableDrive(d.DriveType, d.IsReady));
            foreach (var drive in drives)
            {
                if (ct.IsCancellationRequested) break;
                _logger.LogInformation("[FileVerdictScanner] Starting lazy walk of {Drive}", drive.Name);
                try
                {
                    _walkVolume = drive.Name;
                    await TraverseDirectoryAsync(drive.RootDirectory.FullName, ct, freshWalk);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    RecordWalkFailure(drive.Name, ex);
                    _logger.LogDebug(ex, "Error initiating drive walk for {Drive}", drive.Name);
                }
            }
            int errors = Volatile.Read(ref _walkDirectoryErrors);
            if (_audit != null)
                await _audit.LogEventAsync("file_scan_coverage", new
                {
                    Completed = !ct.IsCancellationRequested,
                    IncompletePaths = errors,
                    FailureExamples = _walkErrorExamples.ToArray(),
                    FailureExamplesTruncated = errors > 64,
                    Directories = Interlocked.Read(ref _walkDirectories),
                    Evaluated = Interlocked.Read(ref _walkFiles),
                    Cached = Interlocked.Read(ref _walkSkipped),
                    LastVolume = _walkVolume,
                    ElapsedSeconds = (DateTime.UtcNow - _walkStarted).TotalSeconds,
                    FreshWalk = freshWalk
                }, ct).ConfigureAwait(false);
            _logger.LogInformation("[FileVerdictScanner] Lazy walk finished with {Errors} incomplete paths.", errors);
        }

        private async Task TraverseDirectoryAsync(string rootDir, CancellationToken ct, bool freshWalk)
        {
            var queue = new Queue<string>();
            queue.Enqueue(rootDir);

            while (queue.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var currentDir = queue.Dequeue();
                Interlocked.Increment(ref _walkDirectories);

                // Skip excluded directories
                if (IsOsServicingTree(currentDir, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) continue;

                // Never walk Sentinel's own data/install directories: our own log writes,
                // scan_index flushes, and ADS tags would re-enter the scanner in a loop.
                if (IsSentinelOwnPath(currentDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (!IsScannable(file)) continue;

                        // Cheap skip: if this exact file (same size + last-write time) was already
                        // scanned, there is nothing new to learn - avoid the full-file read + SHA256.
                        // This is what stops the walk from re-hashing every executable on every pass
                        // (the sustained-MB/s HDD firehose). Any content change bumps size/mtime and
                        // invalidates the entry, forcing a fresh scan.
                        if (!freshWalk && _scanIndex.IsUnchangedSinceScan(file))
                        { Interlocked.Increment(ref _walkSkipped); continue; }
                        await ScanFileWithBackoffAsync(file, ct);
                        Interlocked.Increment(ref _walkFiles);
                        await Task.Delay(20, ct);
                    }

                    foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        var name = Path.GetFileName(subDir).ToLowerInvariant();
                        if (name == "$recycle.bin" || name == "system volume information") continue;

                        try { if (ShouldTraverseDirectory(File.GetAttributes(subDir))) queue.Enqueue(subDir); }
                        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                        {
                            RecordWalkFailure(subDir, ex);
                            _logger.LogDebug(ex, "Directory attributes unavailable: {Directory}", subDir);
                        }
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    RecordWalkFailure(currentDir, ex);
                    _logger.LogDebug(ex, "Error traversing directory: {Directory}", currentDir);
                }
            }
        }

        public override void Dispose()
        {
            _apiThrottle.Dispose();
            _scanTaskThrottle.Dispose();
            ReleaseWatchers();
            base.Dispose();
        }
    }
}
