using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public partial class BehavioralCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _privacyContext = new();
        private async Task RegisterPrivacyContextAsync(DetectionEvent signal)
        {
            bool privacy = PrivacyActivityPolicy.IsObservation(signal);
            bool proof = signal.SignalType == SignalType.ReverseShell && signal.Tier == DetectionTier.Tier1Behavioral &&
                signal.Metadata != null && signal.Metadata.TryGetValue("BehavioralProof", out var kind) && kind == "SocketCommandLoop";
            if ((!privacy && !proof) || signal.ProcessId <= 4) return;
            // Only an observed overlay window has a direct owner. Foreground input recipients,
            // registry capability entries and graphics DLL presence never identify a snooping actor.
            bool window = privacy && (signal.RuleName.StartsWith("UI Overlay:", StringComparison.Ordinal) ||
                signal.RuleName == "Clickjacking: Suspicious Overlay Window");
            if (privacy && !window) return;
            long live;
            try { live = _creationTimeResolver(signal.ProcessId); }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException ||
                ex is System.ComponentModel.Win32Exception || ex is DllNotFoundException)
            { return; } // Unavailable identity never grants action authority.
            if (live <= 0 || live > signal.Timestamp.ToFileTimeUtc()) return;
            signal.Metadata ??= new Dictionary<string, string>();
            if (signal.Metadata.TryGetValue("ProcessCreationTime", out var original) && original != live.ToString()) return;
            signal.Metadata["ProcessCreationTime"] = live.ToString();
            if (window) signal.Metadata["ActorAttribution"] = "VerifiedWindowOwner";
            if (_privacyContext.Count >= 256) _privacyContext.Clear();
            var buffer = _privacyContext.GetOrAdd(signal.ProcessId, _ => new List<DetectionEvent>());
            bool matched;
            lock (buffer)
            {
                buffer.RemoveAll(s => DateTime.UtcNow - s.Timestamp > TimeSpan.FromSeconds(30));
                if (buffer.Count >= 16) buffer.RemoveAt(0);
                buffer.Add(signal);
                matched = PrivacyActivityPolicy.HasConfirmedCompromise(buffer, live, DateTime.UtcNow);
                if (matched) buffer.Clear();
            }
            if (matched && _emitCallback != null)
                await _emitCallback(new DetectionEvent
                {
                    RuleName = "Privacy activity + confirmed reverse shell", ProcessId = signal.ProcessId,
                    ProcessName = signal.ProcessName, Tier = DetectionTier.Tier1Behavioral,
                    SignalType = SignalType.ReverseShell, Family = TerminalFamily.ReverseShell, Confidence = 0.95,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    Evidence = "Verified overlay owner and complete socket command-execution loop in the same current process lifetime.",
                    Reasoning = "Direct reverse-shell proof independently authorizes immediate response. Overlay context is additional evidence, not a required delay or proof of unauthorized recording.",
                    Metadata = new Dictionary<string, string> { ["ProcessCreationTime"] = live.ToString(),
                        ["BehavioralProof"] = "SocketCommandLoop", ["PrivacyComposite"] = "true" }
                }).ConfigureAwait(false);
        }
    }
}
