# Audit remediation

These changes address the nine findings recorded against commit
`14a704c4a0f731c7f99cb7d7be735f79ced163b2`.

| Finding | Result |
| --- | --- |
| Native signature resources | Embedded and catalog verification close WinTrust state in finally blocks; marshaled string members are destroyed before releasing their structures. DPAPI output uses LocalFree. |
| Stale signature verdicts | Fingerprints hash the complete file; verification holds a read lease that excludes writers and renames on Windows. The weaker metadata-only inner cache is removed. Unknown/unreadable identity fails closed. |
| Game-directory immunity | Response/reputation exclusions require a canonical Program Files installation, protected directory/file ACLs and a valid signature. Writable/per-user paths retain the separate memory-inspection compatibility hint. Detection and quarantine callers use the verified identity policy. |
| Reputation work growth | At most two operations are admitted before allocating a task or hashing. Excess optional reputation work is rejected and counted in debug logs; behavioral rules still execute. Accepted work is tracked for shutdown. |
| Retained WebSockets | Connections are bounded to 32 and removed on disconnect, transport failure and shutdown. |
| Stalled sends | Clients send independently with a two-second deadline; non-cooperative sockets are aborted and late faults observed. |
| Upgrade cache loss | New keys use stable installation material. The installer preserves public digests of previous service/agent executables before deleting .old files, allowing authenticated legacy caches to migrate under the service identity. Incompatible data is retained, with a backup before replacement. |
| Old graph evidence | Expired edges are pruned and excluded from diversity scoring. Process-start telemetry resets previous PID graph and fusion history. |
| Partial JSONL records | Byte offsets advance only through complete newline-delimited UTF-8 records. Partial records are reread on the next update; record allocation is bounded to 64 KiB. |

The installer migration cannot recover data already deleted by an earlier version.
For an upgrade performed outside the installer, retain the previous executable digest
as `<executable>.cache-legacy-sha256` (32 raw SHA-256 bytes) in the protected install
directory before replacing/removing the executable. Unavailable legacy key material
results in preserved incompatible data, never unauthenticated import.

Full-content fingerprinting and removing the weak inner cache increase signature
verification I/O. Windows soak testing must measure service/agent private bytes,
managed heap, handle count and scan latency before attributing the reported RAM
usage to a particular leak or claiming a measured improvement.

## Validation

The Linux workflow builds the complete Windows-targeted solution with warnings as
errors and runs portable audit, existing graph/signer, dashboard, Worker and Python
tests. The portable project links production algorithms; its throwing platform
stubs do not validate Windows signature APIs. Its CI job runs alongside the existing
Windows jobs. Windows-only regressions cover response immunity and DPAPI policy
persistence; they require the existing Windows CI runtime. Compilation of those
tests alone is not an execution result.

No installer, release or version bump is produced by this development change.
