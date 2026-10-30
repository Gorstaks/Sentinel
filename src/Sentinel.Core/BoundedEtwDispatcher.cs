using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Sentinel.Core
{
    // Never retain ETW-owned payload pointers beyond their callback. Copy only after
    // reserving bounded event/byte capacity, then perform analysis off ProcessTrace.
    internal sealed class BoundedEtwDispatcher : IDisposable
    {
        private sealed class Item
        {
            internal EtwRawEvent Event;
            internal byte[] Data = Array.Empty<byte>();
            internal Action<EtwRawEvent> Handler = null!;
        }
        private readonly BlockingCollection<Item> _queue = new();
        private readonly object _producerGate = new();
        private readonly SemaphoreSlim _slots;
        private readonly Thread _worker;
        private readonly Action<Exception> _failure;
        private readonly long _byteLimit;
        private long _bytes, _activeStarted;
        internal double HandlerBusyMs
        { get { long started = Interlocked.Read(ref _activeStarted); return started == 0 ? 0 : Math.Max(0, (Stopwatch.GetTimestamp() - started) * 1000.0 / Stopwatch.Frequency); } }
        private volatile bool _stopping;
        internal bool IsAlive => !_stopping && _worker.IsAlive;
        internal int QueueDepth { get { lock (_producerGate) return _stopping ? 0 : _queue.Count; } }
        internal long QueuedBytes => Interlocked.Read(ref _bytes);
        internal BoundedEtwDispatcher(Action<Exception> failure, int capacity = 2048, long byteLimit = 16 * 1024 * 1024)
        {
            _failure = failure; _byteLimit = byteLimit;
            _slots = new SemaphoreSlim(capacity, capacity);
            _worker = new Thread(Consume) { IsBackground = true, Name = "SentinelEtwDispatch" };
            _worker.Start();
        }
        internal bool TryDispatch(EtwRawEvent source, Action<EtwRawEvent> handler)
        {
            lock (_producerGate) return TryDispatchCore(source, handler);
        }
        private bool TryDispatchCore(EtwRawEvent source, Action<EtwRawEvent> handler)
        {
            if (_stopping || !_slots.Wait(0)) return false;
            int length = source.UserDataLength;
            bool reserved = false, transferred = false;
            try
            {
                long bytes = Interlocked.Add(ref _bytes, length); reserved = true;
                if (bytes > _byteLimit || length > 0 && source.UserData == IntPtr.Zero) return false;
                var copy = new byte[length];
                if (length > 0) Marshal.Copy(source.UserData, copy, 0, length);
                source.UserData = IntPtr.Zero;
                if (_stopping) return false;
                try { transferred = _queue.TryAdd(new Item { Event = source, Data = copy, Handler = handler }); }
                catch (InvalidOperationException) when (_stopping) { return false; }
                return transferred;
            }
            finally
            {
                if (!transferred) { if (reserved) Interlocked.Add(ref _bytes, -length); _slots.Release(); }
            }
        }
        private void Consume()
        {
            foreach (var item in _queue.GetConsumingEnumerable())
            {
                GCHandle pin = default;
                try
                {
                    if (_stopping) continue;
                    var raw = item.Event;
                    if (item.Data.Length > 0) { pin = GCHandle.Alloc(item.Data, GCHandleType.Pinned); raw.UserData = pin.AddrOfPinnedObject(); }
                    Interlocked.Exchange(ref _activeStarted, Stopwatch.GetTimestamp());
                    item.Handler(raw);
                }
                catch (Exception ex) { _failure(ex); }
                finally
                {
                    Interlocked.Exchange(ref _activeStarted, 0);
                    if (pin.IsAllocated) pin.Free();
                    Interlocked.Add(ref _bytes, -item.Data.Length); _slots.Release();
                }
            }
        }
        public void Dispose()
        {
            lock (_producerGate)
            {
                if (_stopping) return;
                _stopping = true; _queue.CompleteAdding();
            }
            if (!_worker.Join(5000)) throw new TimeoutException("ETW analysis worker did not stop within five seconds; shutdown is incomplete.");
            _queue.Dispose(); _slots.Dispose();
        }
    }
}
