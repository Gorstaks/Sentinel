using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class AuditRegressionTests
    {
        [Fact]
        public void FingerprintDetectsMiddleModificationWithRestoredTimestamp()
        {
            var path = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(path, new byte[16384]);
                var time = File.GetLastWriteTimeUtc(path);
                var before = SignerTrustService.FileFingerprint(path);
                using (var stream = File.OpenWrite(path)) { stream.Position = 8192; stream.WriteByte(42); }
                File.SetLastWriteTimeUtc(path, time);
                Assert.NotEqual(before, SignerTrustService.FileFingerprint(path));
            }
            finally { File.Delete(path); }
        }

        [Fact]
        public void PruneRemovesOldEdgesFromLiveProcesses()
        {
            var graph = new EventGraph();
            graph.AddEdge("PID_123_demo", "FILE_old", "WROTE");
            var edges = (ConcurrentDictionary<string, List<GraphEdge>>)typeof(EventGraph)
                .GetField("_processEdges", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(graph)!;
            edges["PID_123_demo"][0].Timestamp = DateTime.UtcNow.AddHours(-1);
            Assert.Equal(0, graph.GetProcessDiversity(123).EdgeCount);
            graph.Prune(TimeSpan.FromMinutes(2));
            Assert.Empty(graph.GetProcessEdges("PID_123_demo"));
        }

        [Fact]
        public void ProcessGenerationResetClearsPreviousGraph()
        {
            var graph = new EventGraph();
            graph.AddEdge("PID_123_demo", "FILE_old", "WROTE");
            graph.AddEdge("PID_124_other", "FILE_other", "WROTE");
            graph.ResetProcess(123);
            Assert.Equal(0, graph.GetProcessDiversity(123).EdgeCount);
            Assert.Equal(1, graph.GetProcessDiversity(124).EdgeCount);
        }

        [Fact]
        public async Task JsonlRetriesIncompleteUtf8RecordExactlyOnce()
        {
            using var stream = new MemoryStream();
            var records = new List<string>();
            var first = Encoding.UTF8.GetBytes("{\"value\":\"ž");
            stream.Write(first, 0, first.Length);
            stream.Position = 0;
            var offset = await JsonlRecordReader.ReadAsync(stream, 0, line => { records.Add(line); return Task.CompletedTask; }, default);
            Assert.Equal(0, offset);
            Assert.Empty(records);
            stream.Position = stream.Length;
            var rest = Encoding.UTF8.GetBytes("\"}\r\n");
            stream.Write(rest, 0, rest.Length);
            stream.Position = offset;
            offset = await JsonlRecordReader.ReadAsync(stream, offset, line => { records.Add(line); return Task.CompletedTask; }, default);
            Assert.Equal(stream.Length, offset);
            Assert.Equal("{\"value\":\"ž\"}", Assert.Single(records));
        }

        [Fact]
        public async Task SocketTimeoutDoesNotPreventHealthyDeliveryAndRemovesSlowClient()
        {
            using var clients = new DashboardSocketClients(2, TimeSpan.FromMilliseconds(30));
            var slow = new TestSocket(true);
            var healthy = new TestSocket(false);
            Assert.True(clients.TryAdd(slow));
            Assert.True(clients.TryAdd(healthy));
            Assert.False(clients.TryAdd(new TestSocket(false)));
            await clients.BroadcastAsync(new byte[] { 1 }, default);
            Assert.Equal(1, healthy.Sends);
            Assert.Equal(1, clients.Count);
            Assert.True(slow.Disposed);
            clients.Remove(healthy);
            Assert.Equal(0, clients.Count);
        }

        [Fact]
        public async Task BackgroundWorkRejectsExcessAndDrainsAcceptedOperations()
        {
            var work = new BoundedAsyncWork(2);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            int completed = 0;
            Func<Task> operation = async () => { await release.Task; Interlocked.Increment(ref completed); };
            Assert.True(work.TryRun(operation));
            Assert.True(work.TryRun(operation));
            Assert.False(work.TryRun(operation));
            var drain = work.CompleteAsync();
            Assert.False(drain.IsCompleted);
            Assert.False(work.TryRun(operation));
            release.SetResult(true);
            await drain;
            Assert.Equal(2, completed);
        }

        private sealed class TestSocket : WebSocket
        {
            private readonly bool _slow;
            public bool Disposed;
            public int Sends;
            public TestSocket(bool slow) { _slow = slow; }
            public override WebSocketCloseStatus? CloseStatus => null;
            public override string? CloseStatusDescription => null;
            public override string? SubProtocol => null;
            public override WebSocketState State => Disposed ? WebSocketState.Closed : WebSocketState.Open;
            public override void Abort() { Disposed = true; }
            public override void Dispose() { Disposed = true; }
            public override Task CloseAsync(WebSocketCloseStatus status, string? description, CancellationToken ct) => Task.CompletedTask;
            public override Task CloseOutputAsync(WebSocketCloseStatus status, string? description, CancellationToken ct) => Task.CompletedTask;
            public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct) => throw new NotSupportedException();
            public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool end, CancellationToken ct)
            {
                Sends++;
                return _slow ? new TaskCompletionSource<bool>().Task : Task.CompletedTask;
            }
        }
    }
}
