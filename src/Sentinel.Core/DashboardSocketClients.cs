using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>Bounded push-only connections; slow clients cannot stall healthy clients.</summary>
    public sealed class DashboardSocketClients : IDisposable
    {
        private readonly object _gate = new();
        private readonly HashSet<WebSocket> _clients = new();
        private readonly TimeSpan _timeout;
        private readonly int _capacity;
        private bool _disposed;
        private readonly ILogger _logger;
        public DashboardSocketClients(int capacity = 32, TimeSpan? timeout = null, ILogger? logger = null)
        {
            if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
            _capacity = capacity; _timeout = timeout ?? TimeSpan.FromSeconds(2);
            if (_timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
            _logger = logger ?? NullLogger.Instance;
        }
        public int Count { get { lock (_gate) return _clients.Count; } }
        public bool TryAdd(WebSocket socket)
        { lock (_gate) return !_disposed && _clients.Count < _capacity && _clients.Add(socket); }
        public void Remove(WebSocket socket)
        { lock (_gate) _clients.Remove(socket); socket.Dispose(); }
        public async Task BroadcastAsync(byte[] data, CancellationToken ct)
        {
            WebSocket[] clients;
            lock (_gate) { clients = new WebSocket[_clients.Count]; _clients.CopyTo(clients); }
            var sends = new List<Task>();
            foreach (var client in clients) sends.Add(SendAsync(client, data, ct));
            await Task.WhenAll(sends).ConfigureAwait(false);
        }
        private async Task SendAsync(WebSocket client, byte[] data, CancellationToken ct)
        {
            try
            {
                if (client.State != WebSocketState.Open) { Remove(client); return; }
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(_timeout);
                var send = client.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Text, true, deadline.Token);
                var expired = Task.Delay(Timeout.Infinite, deadline.Token);
                if (await Task.WhenAny(send, expired).ConfigureAwait(false) != send)
                {
                    client.Abort();
                    _ = send.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    Remove(client);
                    return;
                }
                await send.ConfigureAwait(false);
                deadline.Cancel();
            }
            catch (Exception ex) { _logger.LogDebug(ex, "Dashboard socket retired after transport failure"); Remove(client); } // Transport failure retires this connection only.
        }
        public void Dispose()
        {
            lock (_gate)
            {
                _disposed = true;
                foreach (var socket in _clients) { socket.Abort(); socket.Dispose(); }
                _clients.Clear();
            }
        }
    }
}
