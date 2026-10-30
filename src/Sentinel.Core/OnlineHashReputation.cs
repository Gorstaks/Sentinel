using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Fixed HTTPS hash-only lookups. No file uploads, proxy overrides or persistent verdict database.</summary>
    public sealed class OnlineHashReputation : IDisposable
    {
        internal const string MalwareFeed = "https://mb-api.abuse.ch/api/v1/";
        internal const string CirclLookup = "https://hashlookup.circl.lu/lookup/sha256/";
        private readonly HttpClient _client;
        private readonly ILogger<OnlineHashReputation> _logger;
        private readonly bool _ownsClient;
        private readonly string? _malwareBazaarApiKey;
        private readonly SemaphoreSlim _refresh = new(1, 1), _queries = new(2, 2);
        private readonly ConcurrentDictionary<string, (HashVerdict verdict, DateTimeOffset until)> _cache = new();
        private HashSet<string> _malware = new(StringComparer.OrdinalIgnoreCase);
        private long _loadedTicks, _retryTicks, _circlBudgetStart;
        private int _circlRequests;
        private readonly object _budget = new();
        private string _feedState = "Not checked", _circlState = "Not checked";
        public OnlineHashReputation(HttpClient client, ILogger<OnlineHashReputation> logger, bool ownsClient = false, string? malwareBazaarApiKey = null)
        {
            _client = client; _logger = logger; _ownsClient = ownsClient;
            if (!string.IsNullOrEmpty(malwareBazaarApiKey) && malwareBazaarApiKey!.Length <= 256 &&
                System.Linq.Enumerable.All(malwareBazaarApiKey, c => c > 32 && c < 127))
                _malwareBazaarApiKey = malwareBazaarApiKey;
            _feedState = _malwareBazaarApiKey == null ? "Not configured; MalwareBazaar Auth-Key required; verdict unknown" : "Not checked";
        }
        public object Snapshot() => new
        {
            Enabled = true, HashOnly = true, MalwareFeed = Volatile.Read(ref _feedState),
            Circl = Volatile.Read(ref _circlState), MalwareHashes = Volatile.Read(ref _malware).Count,
            FeedFresh = FeedFresh(), CacheEntries = _cache.Count
        };
        internal static bool ValidHash(string hash)
        {
            if (hash == null || hash.Length != 64) return false;
            foreach (char c in hash) if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) return false;
            return true;
        }
        private bool FeedFresh()
        {
            long loaded = Interlocked.Read(ref _loadedTicks), age = DateTime.UtcNow.Ticks - loaded;
            return loaded > 0 && age >= 0 && age < TimeSpan.FromHours(4).Ticks;
        }
        public async Task<HashVerdict> QueryAsync(string hash, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!ValidHash(hash)) return HashVerdict.Unknown;
            hash = hash.ToLowerInvariant();
            await RefreshFeedAsync(ct).ConfigureAwait(false);
            // A positive current malware match wins over any known-file observation.
            if (FeedFresh() && Volatile.Read(ref _malware).Contains(hash)) return HashVerdict.Unsafe;
            if (_cache.TryGetValue(hash, out var cached) && cached.until > DateTimeOffset.UtcNow) return cached.verdict;
            bool admitted;
            lock (_budget)
            {
                long now = DateTime.UtcNow.Ticks;
                if (now - _circlBudgetStart >= TimeSpan.FromMinutes(1).Ticks) { _circlBudgetStart = now; _circlRequests = 0; }
                admitted = _circlRequests < 60;
                if (admitted) _circlRequests++;
            }
            if (!admitted || !await _queries.WaitAsync(0, ct).ConfigureAwait(false)) return HashVerdict.Unknown;
            HashVerdict verdict = HashVerdict.Unknown;
            try
            {
                string? body = await GetBoundedAsync(CirclLookup + hash, 64 * 1024, ct).ConfigureAwait(false);
                if (body != null && IsExactCirclMatch(body, hash)) verdict = HashVerdict.Safe;
                Volatile.Write(ref _circlState, verdict == HashVerdict.Safe ? "Exact known-file match" : "No confirmed match");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                Volatile.Write(ref _circlState, "Unavailable; verdict unknown");
                _logger.LogDebug(ex, "Hash lookup unavailable; no verdict inferred");
            }
            finally { _queries.Release(); }
            if (_cache.Count >= 4096) _cache.Clear();
            _cache[hash] = (verdict, DateTimeOffset.UtcNow.AddMinutes(verdict == HashVerdict.Safe ? 15 : 1));
            return verdict;
        }
        private async Task RefreshFeedAsync(CancellationToken ct)
        {
            if (_malwareBazaarApiKey == null || FeedFresh() || DateTime.UtcNow.Ticks < Interlocked.Read(ref _retryTicks) ||
                !await _refresh.WaitAsync(0, ct).ConfigureAwait(false)) return;
            try
            {
                if (FeedFresh()) return;
                Interlocked.Exchange(ref _retryTicks, DateTime.UtcNow.AddMinutes(5).Ticks);
                string? body = await GetBoundedAsync(MalwareFeed, 8 * 1024 * 1024, ct, malwareFeed: true).ConfigureAwait(false);
                var hashes = ParseMalwareFeed(body);
                if (hashes == null) { Volatile.Write(ref _feedState, "Unavailable or invalid; verdict unknown"); return; }
                Volatile.Write(ref _malware, hashes);
                Interlocked.Exchange(ref _loadedTicks, DateTime.UtcNow.Ticks);
                Volatile.Write(ref _feedState, "Authenticated recent SHA256 feed (latest 100 samples)");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                Volatile.Write(ref _feedState, "Unavailable; verdict unknown");
                _logger.LogWarning(ex, "Malware hash feed unavailable; no malware verdict inferred");
            }
            finally { _refresh.Release(); }
        }
        internal static HashSet<string>? ParseMalwareFeed(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            using var json = JsonDocument.Parse(text!);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("query_status", out var status) || status.ValueKind != JsonValueKind.String ||
                status.GetString() != "ok" || !root.TryGetProperty("data", out var data) ||
                data.ValueKind != JsonValueKind.Array || data.GetArrayLength() > 100) return null;
            var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in data.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("sha256_hash", out var hash) ||
                    hash.ValueKind != JsonValueKind.String || !ValidHash(hash.GetString()!)) return null;
                hashes.Add(hash.GetString()!);
            }
            return hashes.Count == 0 ? null : hashes;
        }
        internal static bool IsExactCirclMatch(string body, string hash)
        {
            using var json = JsonDocument.Parse(body);
            return json.RootElement.ValueKind == JsonValueKind.Object &&
                json.RootElement.TryGetProperty("SHA-256", out var match) && match.ValueKind == JsonValueKind.String &&
                string.Equals(match.GetString(), hash, StringComparison.OrdinalIgnoreCase);
        }
        private async Task<string?> GetBoundedAsync(string url, int maxBytes, CancellationToken ct, bool malwareFeed = false)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(8));
            using var request = new HttpRequestMessage(malwareFeed ? HttpMethod.Post : HttpMethod.Get, url);
            if (malwareFeed)
            {
                request.Headers.Add("Auth-Key", _malwareBazaarApiKey);
                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    { ["query"] = "get_recent", ["selector"] = "100" });
            }
            request.Headers.UserAgent.ParseAdd("Sentinel/" + ProductInfo.Version);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;
            if (response.Content.Headers.ContentLength > maxBytes) return null;
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var data = new MemoryStream(); var bytes = new byte[8192];
            int count;
            while ((count = await stream.ReadAsync(bytes, 0, bytes.Length, deadline.Token).ConfigureAwait(false)) > 0)
            {
                if (data.Length + count > maxBytes) return null;
                data.Write(bytes, 0, count);
            }
            return new UTF8Encoding(false, true).GetString(data.ToArray());
        }
        public void Dispose()
        { if (_ownsClient) _client.Dispose(); _refresh.Dispose(); _queries.Dispose(); }
    }
}
