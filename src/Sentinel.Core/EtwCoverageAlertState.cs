using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>Changes alert immediately; continuing loss produces bounded reminders, not an incident per poll.</summary>
    internal sealed class EtwCoverageAlertState
    {
        private string? _reason;
        private DateTimeOffset _lastAlert;
        private DateTimeOffset? _healthySince;
        private readonly HashSet<string> _reportedReasons = new(StringComparer.Ordinal);
        internal bool IsDegraded => _reason != null;
        internal bool Observe(string? reason, DateTimeOffset now)
        {
            if (reason == null)
            {
                _healthySince ??= now;
                if (now - _healthySince.Value >= TimeSpan.FromSeconds(30))
                { _reason = null; _reportedReasons.Clear(); }
                return false;
            }
            _healthySince = null;
            // Report new reasons immediately. Removing a transient loss reason while
            // another gap remains must not create a fresh incident every other poll.
            bool addedReason = _reason == null;
            if (_reportedReasons.Count > 32) _reportedReasons.Clear();
            foreach (var part in reason.Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries))
                if (_reportedReasons.Add(part)) addedReason = true;
            bool emit = addedReason || now - _lastAlert >= TimeSpan.FromMinutes(5);
            _reason = reason;
            if (emit) _lastAlert = now;
            return emit;
        }
    }
}
