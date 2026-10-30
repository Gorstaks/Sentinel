using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Targeted metadata read for a reported overlay owner, not a second process census.
    /// At most two reads run; normal privacy hints never block the terminal telemetry queue.</summary>
    public sealed class PrivacyOverlayProofInspector
    {
        private readonly RawSocketRedirectRule _socket;
        private readonly ILogger<PrivacyOverlayProofInspector> _logger;
        private readonly Func<int, long> _birth;
        private readonly Func<int, ProcessTelemetry?> _read;
        private readonly ConcurrentDictionary<int, (long birth, DateTime until)> _attempts = new();
        private int _running, _reads;
        public PrivacyOverlayProofInspector(RawSocketRedirectRule socket, ILogger<PrivacyOverlayProofInspector> logger)
            : this(socket, logger, WindowsProcessTreeOperations.GetCreationTime, ReadOwner) { }
        internal PrivacyOverlayProofInspector(RawSocketRedirectRule socket, ILogger<PrivacyOverlayProofInspector> logger,
            Func<int, long> birth, Func<int, ProcessTelemetry?> read)
        { _socket = socket; _logger = logger; _birth = birth; _read = read; }
        internal void Queue(DetectionEvent observation, CancellationToken ct, Func<DetectionEvent, Task> emit)
        {
            if (!Eligible(observation) || ct.IsCancellationRequested) return;
            if (Interlocked.Increment(ref _running) > 2) { Interlocked.Decrement(ref _running); return; }
            _ = Task.Run(async () => {
                try
                {
                    var proof = await InspectAsync(observation, ct).ConfigureAwait(false);
                    if (proof != null && !ct.IsCancellationRequested) await emit(proof).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { /* normal shutdown */ }
                catch (Exception ex) { _logger.LogWarning(ex, "Overlay owner metadata unavailable; no compromise inferred"); }
                finally { Interlocked.Decrement(ref _running); }
            });
        }
        private static bool Eligible(DetectionEvent observation) => observation.ProcessId > 4 &&
            (observation.RuleName == "Clickjacking: Suspicious Overlay Window" ||
             observation.RuleName == "UI Overlay: Transparent Fullscreen Overlay Detected") &&
            !(observation.Metadata != null && observation.Metadata.TryGetValue("ConsultantSignal", out var source) && string.Equals(source, "true", StringComparison.OrdinalIgnoreCase));
        internal async Task<DetectionEvent?> InspectAsync(DetectionEvent observation, CancellationToken ct)
        {
            if (!Eligible(observation) || !SocketShellLifetime.TryResolve(observation, _birth, DateTime.UtcNow, out long created)) return null;
            if (_attempts.TryGetValue(observation.ProcessId, out var prior) && prior.birth == created && prior.until > DateTime.UtcNow) return null;
            if (_attempts.Count >= 128) _attempts.Clear();
            _attempts[observation.ProcessId] = (created, DateTime.UtcNow.AddSeconds(30));
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(2));
            // A timed-out WMI read may still be running natively. Keep its slot until
            // that read actually returns; repeated failures cannot spawn unbounded workers.
            if (Interlocked.Increment(ref _reads) > 2) { Interlocked.Decrement(ref _reads); return null; }
            var read = Task.Run(() => {
                try { return _read(observation.ProcessId); }
                finally { Interlocked.Decrement(ref _reads); }
            });
            await BoundedIpcRequest.WithinDeadlineAsync(read, deadline.Token).ConfigureAwait(false);
            var process = await read.ConfigureAwait(false);
            if (process == null || process.ProcessId != observation.ProcessId || process.CommandLine.Length > 65536 ||
                _birth(process.ProcessId) != created) return null;
            process.Timestamp = DateTime.UtcNow;
            var proof = _socket.Evaluate(new FusedTelemetryContext { TriggeringEvent = process });
            if (proof == null) return null;
            proof.RuleName = "Privacy activity + confirmed reverse shell";
            proof.Confidence = 0.95;
            proof.Metadata ??= new Dictionary<string, string>();
            proof.Metadata["BehavioralProof"] = "SocketCommandLoop";
            proof.Metadata["ProcessCreationTime"] = created.ToString(CultureInfo.InvariantCulture);
            proof.Metadata["PrivacyComposite"] = "true";
            proof.Metadata["OverlayObservationRule"] = observation.RuleName;
            proof.Reasoning = "The observed overlay owner independently has supported socket-to-shell execution structure in its current command line. The same process lifetime was checked before and after metadata collection. Ordinary overlay/media use cannot supply this proof.";
            return proof;
        }
        private static ProcessTelemetry? ReadOwner(int pid)
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\cimv2"),
                new SelectQuery("Win32_Process", "ProcessId=" + pid.ToString(CultureInfo.InvariantCulture), new[] { "ProcessId", "Name", "CommandLine" }),
                new EnumerationOptions { ReturnImmediately = false, Timeout = TimeSpan.FromSeconds(2) });
            using var rows = searcher.Get();
            foreach (ManagementObject row in rows)
                using (row) return new ProcessTelemetry { ProcessId = Convert.ToInt32(row["ProcessId"], CultureInfo.InvariantCulture),
                    ProcessName = row["Name"]?.ToString() ?? "", CommandLine = row["CommandLine"]?.ToString() ?? "" };
            return null;
        }
    }
}
