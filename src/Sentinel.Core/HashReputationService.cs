using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public enum HashVerdict { Safe, Unsafe, Unknown }

    /// <summary>Service-only online reputation; other hosts remain local unless explicitly wired.</summary>
    public class HashReputationService
    {
        private readonly OnlineHashReputation? _online;
        // Preserve the legacy constructor without restoring removed reporting/proxy transports.
        public HashReputationService(SecureCacheStore cacheStore, ThreatReportingConfig config,
            ILogger<HashReputationService> logger, HttpClient? circlClient = null,
            HttpClient? malwareBazaarClient = null, HttpClient? proxyClient = null) { }
        public HashReputationService(OnlineHashReputation online) { _online = online; }
        public Task<HashVerdict> GetVerdictAsync(string sha256,
            CancellationToken cancellationToken = default, string? sha1 = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return _online?.QueryAsync(sha256, cancellationToken) ?? Task.FromResult(HashVerdict.Unknown);
        }
        public object Snapshot() => _online?.Snapshot() ?? new { Enabled = false, HashOnly = true };
        internal static HashVerdict UnknownOnPinnedLookupFailure() => HashVerdict.Unknown;
    }
}
