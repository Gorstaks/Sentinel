# Hash reputation — current 3.4.5 policy

Online reputation is enabled in the Service through fixed HTTPS MalwareBazaar API and CIRCL hashlookup endpoints. MalwareBazaar requires an owner-provided Auth-Key; the retired anonymous export is no longer queried. The authenticated get_recent request fetches only the latest 100 SHA256 samples, cached for four hours with failure backoff. Missing credentials explicitly report Not configured and Unknown. This recent set is not the full malware corpus. CIRCL remains known-file context, never runtime trust.

Run the installed `Tools/set-malwarebazaar-key.ps1` (or repository `installer/set-malwarebazaar-key.ps1`) manually in elevated native Windows PowerShell to enter your key interactively, then restart the Sentinel service. `-Remove` removes it. The key is machine-DPAPI protected in the 64-bit HKLM\SOFTWARE\Sentinel\Credentials registry key with SYSTEM/Administrators-only access; the Service validates ownership/ACLs before reading it. No command-line key, environment variable or embedded credential is used. TLS validation, disabled redirects/cookies, bounded bytes/time/concurrency and CIRCL rate limits remain enforced. Only SHA256 hashes or the fixed recent-feed selector are sent; no file contents, paths or names are uploaded. Live authenticated access requires a real key and is not established by mocked tests.

A fresh exact malware match takes precedence over known-file context. CIRCL requires the returned SHA-256 to equal the requested hash. Malformed data, absence, failures, budget exhaustion and unsupported hashes yield Unknown, never a cached bad verdict. The Agent's legacy facade remains local/Unknown; this is host wiring, not an outbound firewall ban. Neither Safe nor static signatures grant runtime trust. Known-hash file containment is separately bounded and audited; hashes never authorize process kills. See [NanoAV integration](NANOAV.md).

Ops metrics disclose feed state, freshness and query/cache state. Outbound reporting and removed embedded credentials remain removed. Offline scans still provide local/static/ML analysis when providers are unavailable.

## Historical offline policy (superseded)

# Offline hash reputation (3.2.3)

`HashReputationService` is a compatibility facade that returns `Unknown`. It makes no HTTP or DNS requests, reads no legacy online reputation cache and grants no verdict to synthetic test hashes. Cancellation is still honored.

CIRCL, Team Cymru MHR, MalwareBazaar and VirusTotal queries have been removed. There is no supported client API-key or Worker configuration that restores them. Legacy encrypted settings cannot enable reporting or reputation transports.

`FileReputationEngine` retains local static PE, signer and optional ML context. The external-hash contribution is a neutral Unknown prior, and local composite results use the `filerepo-offline-v1` cache namespace so old online results cannot supply trust. File identity/reputation alone is not behavioral kill authority.

Bundled indicators and local/cached intelligence can become stale. Missing data is missing coverage, not a clean verdict. Supply intelligence through a trusted local update; Sentinel does not download feeds.

The retained [Worker](../worker/README.md) is a separate legacy server component. Deploying it does not reconnect the endpoint. For firewall enforcement, privilege boundaries and measured coverage, see [design](design.md) and [Windows validation](OFFLINE_VALIDATION.md).
