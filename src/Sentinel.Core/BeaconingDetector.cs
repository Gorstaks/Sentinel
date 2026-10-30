using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Bounded endpoint timing context. Periodicity and TCP snapshot polling
    /// do not prove command/control and never authorize a response on their own.</summary>
    public sealed class BeaconingDetector : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BeaconingDetector> _logger;

        private readonly ConcurrentDictionary<string, ConnectionHistory> _history = new();

        private const int MinObservations = 5;
        private const double MaxBeaconCv = 0.40;
        private const double MinBeaconIntervalSec = 5.0;
        private const double MaxBeaconIntervalSec = 1800.0;
        private const int MaxHistoryPerKey = 50;

        private readonly BehavioralBaselineService? _baseline;
        private readonly ContextBus? _contextBus;

        public BeaconingDetector(
            DetectionEngine de,
            ILogger<BeaconingDetector> l,
            AllowlistService? allowlist = null,
            BehavioralBaselineService? baseline = null,
            FileVerdictAds? fileVerdictAds = null,
            ContextBus? contextBus = null)
        {
            _detectionEngine = de;
            _logger = l;
            _baseline = baseline;
            _contextBus = contextBus;
        }

        /// <summary>
        /// Called by NetworkMonitor for every observed connection.
        /// Records the timestamp for statistical analysis.
        /// No name-based exemptions - trust is verified cryptographically at analysis time.
        /// </summary>
        public void RecordConnection(string remoteAddress, int remotePort, int processId, string processName, string? imagePath, string state)
        {
            if (state != "Established") return;

            if (_baseline != null && _baseline.IsKnownNetworkDestination(processName, remoteAddress, remotePort))
            {
                return;
            }

            if (_history.Count >= 16384) { _history.Clear(); _logger.LogWarning("Endpoint timing history budget reached; context reset, not a clean-system verdict"); }
            var key = $"{processId}:{remoteAddress}:{remotePort}";
            var history = _history.GetOrAdd(key, _ => new ConnectionHistory(
                processId, processName, remoteAddress, remotePort, imagePath));

            // Update image path if it was initially null but is now available
            if (string.IsNullOrEmpty(history.ImagePath) && !string.IsNullOrEmpty(imagePath))
                history.ImagePath = imagePath;

            history.Record(DateTimeOffset.UtcNow);


        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BeaconingDetector] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30_000, ct);
                    await AnalyzeAllAsync();
                    PruneStaleHistory();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BeaconingDetector] Analysis error"); }
            }
        }

        private async Task AnalyzeAllAsync()
        {
            foreach (var kvp in _history)
            {
                var history = kvp.Value;
                if (history.HasFired &&
                    history.LastSeen.AddMinutes(15) > DateTimeOffset.UtcNow)
                    continue;
                history.HasFired = false;

                var intervals = history.GetIntervals();
                if (intervals.Count < MinObservations) continue;

                double mean = intervals.Average();
                double stddev = StdDev(intervals, mean);
                double cv = mean > 0 ? stddev / mean : double.MaxValue;

                if (cv > MaxBeaconCv) continue;
                if (mean < MinBeaconIntervalSec) continue;
                if (mean > MaxBeaconIntervalSec) continue;

                // Stricter threshold for port 80/443: require CV < 0.20 to reduce false positives
                // from legitimate HTTP/HTTPS polling (e.g., keep-alive, long-polling, websockets)
                if (history.RemotePort is 80 or 443 && cv >= 0.20) continue;

                history.HasFired = true;

                double cvFactor = Math.Max(0, 1.0 - cv / 0.40);
                double countFactor = Math.Min(1.0, intervals.Count / 20.0);
                double confidence = Math.Min(0.95, 0.70 + cvFactor * 0.20 + countFactor * 0.08);

                // Torrent / P2P / bulk-transfer clients maintain many regular peer
                // connections that can trip the statistical beacon gates. Recognized
                // bulk-transfer clients are demoted to Tier2 + LogOnly so the C2/beaconing
                // response never kills (or network-isolates) them. The detection is still
                // emitted and logged; the hard "Tier2 never acts" rule guarantees no kill.
                // Mirrors DataExfiltrationMonitor's BulkTransferNoise precedent.
                bool isBulkTransfer = ShouldDemoteBeaconToObserve(history.ProcessName);

                // Regular timing is common in games, launchers, updates and messaging.
                // It is context, not independent command/control proof or response authority.
                var responseAction = ResponseAction.LogOnly;
                var tier = DetectionTier.Tier2Indicator;

                string intervalDesc = mean < 60 ? $"{mean:F1}s" : $"{mean / 60:F1}min";

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network: Endpoint Timing Observation",
                    Evidence = $"Process '{history.ProcessName}' (PID {history.ProcessId}) endpoint observed at " +
                               $"{history.RemoteAddress}:{history.RemotePort} every ~{intervalDesc} " +
                               $"(CV={cv:F3}, n={intervals.Count})",
                    Reasoning = $"Statistical analysis of {intervals.Count} connection intervals: " +
                                $"mean={intervalDesc}, stddev={stddev:F1}s, CV={cv:F3}. " +
                                "Regular timing can result from polling an existing connection, not separate new connections. " +
                                "Legitimate software can also use regular timers; this does not prove C2. " +
                                "This detection is signature-independent.",
                    Confidence = confidence,
                    Tier = tier,
                    AuthorizedResponse = responseAction,
                    ProcessName = history.ProcessName,
                    ProcessId = history.ProcessId,
                    SignalType = SignalType.Generic,
                    Metadata = new()
                    {
                        ["C2StatisticalOnly"] = "true", ["WeakObserveSeed"] = "true",
                        ["TargetIP"] = history.RemoteAddress,
                        ["RemoteAddress"] = history.RemoteAddress,
                        ["RemotePort"] = history.RemotePort.ToString(),
                        ["MeanIntervalSec"] = mean.ToString("F2"),
                        ["CoefficientOfVariation"] = cv.ToString("F4"),
                        ["ObservationCount"] = intervals.Count.ToString(),
                        ["BulkTransfer"] = isBulkTransfer ? "true" : "false"
                    }
                });

                // Publish enrichment signal for cross-monitor consumption
                _contextBus?.Publish(new NetworkTimingSignal
                {
                    ProcessId = history.ProcessId,
                    ProcessName = history.ProcessName,
                    SourceMonitor = "BeaconingDetector",
                    RemoteAddress = history.RemoteAddress,
                    RemotePort = history.RemotePort,
                    CoefficientOfVariation = cv,
                    MeanIntervalSeconds = mean,
                    Confidence = confidence,
                    ObservationCount = intervals.Count
                });
            }
        }

        /// <summary>Legacy diagnostic label only; timing is observe-only for every process.</summary>
        internal static bool ShouldDemoteBeaconToObserve(string? processName)
        {
            return BulkTransferNoise.IsBulkTransferProcessName(processName);
        }

        private void PruneStaleHistory()
        {
            var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromHours(2);
            foreach (var key in _history.Keys.ToList())
            {
                if (_history.TryGetValue(key, out var h) && h.LastSeen < cutoff)
                    _history.TryRemove(key, out _);
            }


        }

        private static double StdDev(IReadOnlyList<double> values, double mean)
        {
            if (values.Count < 2) return 0;
            double variance = values.Sum(v => (v - mean) * (v - mean)) / (values.Count - 1);
            return Math.Sqrt(variance);
        }
    }

    public sealed class ConnectionHistory
    {
        private readonly List<DateTimeOffset> _timestamps = new();
        private readonly object _lock = new();
        private const int MaxHistory = 50;

        public int ProcessId { get; }
        public string ProcessName { get; }
        public string RemoteAddress { get; }
        public int RemotePort { get; }
        public string? ImagePath { get; set; }
        public bool HasFired { get; set; }
        public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

        public ConnectionHistory(int pid, string name, string remote, int port, string? imagePath = null)
        {
            ProcessId = pid;
            ProcessName = name;
            RemoteAddress = remote;
            RemotePort = port;
            ImagePath = imagePath;
        }

        public void Record(DateTimeOffset timestamp)
        {
            lock (_lock)
            {
                _timestamps.Add(timestamp);
                LastSeen = timestamp;
                if (_timestamps.Count > MaxHistory)
                    _timestamps.RemoveAt(0);
            }
        }

        public IReadOnlyList<double> GetIntervals()
        {
            lock (_lock)
            {
                if (_timestamps.Count < 2) return Array.Empty<double>();
                var sorted = _timestamps.OrderBy(t => t).ToList();
                return sorted
                    .Zip(sorted.Skip(1), (a, b) => (b - a).TotalSeconds)
                    .ToList();
            }
        }
    }
}
