using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Core
{
    /// <summary>Admission precedes task allocation; no queue is retained when workers are busy.</summary>
    internal sealed class BoundedAsyncWork
    {
        private readonly object _gate = new();
        private readonly HashSet<Task> _tasks = new();
        private readonly int _capacity;
        private readonly ILogger _logger;
        private bool _stopped;
        internal BoundedAsyncWork(int capacity, ILogger? logger = null)
        {
            if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
            _capacity = capacity; _logger = logger ?? NullLogger.Instance;
        }
        internal bool TryRun(Func<Task> operation)
        {
            lock (_gate)
            {
                if (_stopped || _tasks.Count >= _capacity) return false;
                var task = Task.Run(async () =>
                {
                    try { await operation().ConfigureAwait(false); }
                    catch (Exception ex) { _logger.LogDebug(ex, "Bounded background work failed"); }
                });
                _tasks.Add(task);
                _ = task.ContinueWith(t => { lock (_gate) _tasks.Remove(t); },
                    System.Threading.CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                return true;
            }
        }
        internal Task CompleteAsync()
        {
            lock (_gate) { _stopped = true; return Task.WhenAll(_tasks.ToArray()); }
        }
    }
}
