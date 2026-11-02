using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace Sentinel.Core
{
    public sealed class ProcessTreeTerminationResult
    {
        public int RootProcessId { get; internal set; }
        public bool RootExited { get; internal set; }
        public bool DiscoveryComplete { get; internal set; }
        public List<int> ExitedProcessIds { get; } = new();
        public List<int> FailedProcessIds { get; } = new();
        public List<int> RefusedProcessIds { get; } = new();
        public string? Error { get; internal set; }
        public bool Success => RootExited && DiscoveryComplete &&
            FailedProcessIds.Count == 0 && RefusedProcessIds.Count == 0;
    }

    internal readonly struct ProcessTreeEntry
    {
        public ProcessTreeEntry(int pid, int parentPid) { ProcessId = pid; ParentProcessId = parentPid; }
        public int ProcessId { get; }
        public int ParentProcessId { get; }
    }

    internal interface IProcessTreeTarget : IDisposable
    {
        int ProcessId { get; }
        long CreationTime { get; }
        bool CanTerminate { get; }
        bool HasExited { get; }
        bool TerminateAndWait(int timeoutMilliseconds);
    }

    internal interface IProcessTreeOperations
    {
        IReadOnlyList<ProcessTreeEntry> Snapshot();
        IProcessTreeTarget? Open(int pid);
        long QueryCreationTime(int pid);
    }

    /// <summary>
    /// Bounded, verified userland containment. Keep process handles open throughout discovery
    /// and termination, and reject children older than their alleged parent (PID reuse).
    /// This cannot prevent a privileged process from escaping before it is observed.
    /// </summary>
    internal sealed class ProcessTreeTerminator
    {
        private readonly IProcessTreeOperations _operations;
        internal ProcessTreeTerminator(IProcessTreeOperations operations) => _operations = operations;

        internal ProcessTreeTerminationResult Terminate(int rootPid, long? expectedCreationTime = null,
            CancellationToken cancellationToken = default)
        {
            var result = new ProcessTreeTerminationResult { RootProcessId = rootPid };
            var targets = new Dictionary<int, IProcessTreeTarget>();
            var attempted = new HashSet<int>();
            var timer = Stopwatch.StartNew();
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rootPid <= 4 || rootPid == Process.GetCurrentProcess().Id)
                {
                    result.RefusedProcessIds.Add(rootPid);
                    return result;
                }
                var root = _operations.Open(rootPid);
                if (root == null)
                {
                    // Parent is gone, but we cannot safely attribute its former children.
                    result.RootExited = true;
                    result.Error = "Root already absent; descendant identity could not be established.";
                    return result;
                }
                targets.Add(rootPid, root);
                if ((expectedCreationTime.HasValue && root.CreationTime != expectedCreationTime.Value) ||
                    !root.CanTerminate)
                {
                    result.RefusedProcessIds.Add(rootPid);
                    return result;
                }

                // Rescan after each pass to catch children spawned during discovery. A final
                // stable snapshot is required for success; flood/time limits report incomplete.
                for (int pass = 0; pass < 4; pass++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var snapshot = _operations.Snapshot();
                    bool added;
                    do
                    {
                        added = false;
                        foreach (var entry in snapshot)
                        {
                            if (targets.ContainsKey(entry.ProcessId) || result.RefusedProcessIds.Contains(entry.ProcessId) ||
                                !targets.TryGetValue(entry.ParentProcessId, out var parent) ||
                                !parent.CanTerminate) continue;
                            if (targets.Count >= 4096 || timer.ElapsedMilliseconds >= 5000)
                                throw new TimeoutException("Process tree discovery exceeded its containment budget.");
                            // An incidental descendant may be un-openable: a PID-reused slot now
                            // held by a protected/elevated process, or a child racing its own exit
                            // (OpenProcess / GetProcessTimes can report ERROR_ACCESS_DENIED rather
                            // than ERROR_INVALID_PARAMETER). Skip it instead of aborting the whole
                            // containment - it is not the authorized root, whose open already
                            // succeeded. Continue containment, but record the unknown child: an
                            // access denial cannot certify that the entire tree was contained.
                            IProcessTreeTarget? child;
                            try { child = _operations.Open(entry.ProcessId); }
                            catch (Exception ex) when (ex is not OperationCanceledException)
                            {
                                // Toolhelp parent PIDs outlive the original parent. A protected
                                // older process may deny TERMINATE while allowing limited query.
                                // Exclude it only with positive birth-time proof; a failed query
                                // or a possible real descendant must still report incomplete.
                                try
                                {
                                    long created = _operations.QueryCreationTime(entry.ProcessId);
                                    if (created > 0 && created < parent.CreationTime) continue;
                                }
                                catch (Exception queryError) when (queryError is not OperationCanceledException)
                                {
                                    Debug.WriteLine($"Descendant identity unavailable for PID {entry.ProcessId}: {queryError.Message}");
                                }
                                result.RefusedProcessIds.Add(entry.ProcessId);
                                result.Error ??= "One or more descendants could not be opened for containment: " + ex.Message;
                                continue;
                            }
                            if (child == null) continue; // Already exited before opening.
                            if (child.CreationTime < parent.CreationTime)
                            {
                                child.Dispose(); // The recorded parent PID belongs to a newer process.
                                continue;
                            }
                            targets.Add(entry.ProcessId, child);
                            added = true;
                        }
                    } while (added);

                    var pending = targets.Values.Where(p => !attempted.Contains(p.ProcessId))
                        .OrderBy(p => p.ProcessId == rootPid ? 0 : 1).ToList();
                    if (pending.Count == 0)
                    {
                        result.DiscoveryComplete = result.RefusedProcessIds.Count == 0;
                        break;
                    }
                    // Stop producers before their descendants; handles pin each target's identity.
                    foreach (var target in pending)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        attempted.Add(target.ProcessId);
                        if (!target.CanTerminate)
                        {
                            result.RefusedProcessIds.Add(target.ProcessId);
                            continue;
                        }
                        try
                        {
                            int remaining = 5000 - (int)timer.ElapsedMilliseconds;
                            bool exited = target.HasExited || (remaining > 0 &&
                                target.TerminateAndWait(Math.Min(1000, remaining)));
                            if (exited) result.ExitedProcessIds.Add(target.ProcessId);
                            else result.FailedProcessIds.Add(target.ProcessId);
                            if (target.ProcessId == rootPid) result.RootExited = exited;
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            result.FailedProcessIds.Add(target.ProcessId);
                            result.Error = ex.Message;
                        }
                    }
                }
                if (!result.DiscoveryComplete)
                    result.Error ??= "Descendant discovery did not stabilize within the containment budget.";
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                Debug.WriteLine($"Process-tree containment incomplete for PID {rootPid}: {ex.Message}");
            }
            finally
            {
                foreach (var target in targets.Values) target.Dispose();
            }
            return result;
        }
    }
}
