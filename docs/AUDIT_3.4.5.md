# Sentinel 3.4.5 — pre-push red/blue audit

Performed as two engineering review passes by the implementation agent, using source inspection, supplied evidence and inert regression fixtures. This is not an independent penetration test, malware certification or proof of universal prevention. The attacker is assumed to know all source, thresholds, exclusions and documentation.

## Red-team pass

| Attack / failure hypothesis | Result and correction |
| --- | --- |
| Rename a payload to an unscanned extension or exempt-looking folder; run a fake servicing process | Unknown-extension files with PE content enter the scanner; remove generic mount/uup/ntlite/update substring exclusions and the any-servicing-name process global scan skip. Only exact actual OS servicing trees remain omitted; supported socket-shell behavior remains independent of a campaign filename. Arbitrary languages/packers remain a gap. |
| Exhaust the global kill budget, reuse a PID after a terminal observation, or combine unrelated privacy evidence | Supported direct socket-shell proof bypasses the global count budget while retaining identity, durable audit and native safety; a two-lifetime Windows fixture uses a one-kill budget. Fresh terminal response resolves creation time and passes it into pinned process-tree termination. Privacy correlation requires a current owner and matching lifetime; input foreground recipients/registry records cannot target a process. Critical/self/game safety remains explicit. |
| Present ports, predictable timing, an unsigned file or poisoned old verdict as decisive proof | Old NanoAV database is not imported. Statistical-only C2 and file reputation are context-only; signed/Safe verdicts cannot grant runtime trust. Supported complete socket-shell proof acts without a composite wait. |
| Induce certificate deletion through expiry/EKU/missing metadata or fake adder attribution | Explicit distrust check at both producer/dispatch and executor; adder-kill action stripped. Already-absent stores are not another actual removal. |
| Redirect automatic quarantine to a replacement file | Exact feed result is rechecked on a pinned object; durable audit and encrypted recovery precede disposition. No pathname delete, ownership seizure, holder kill or reboot deletion fallback. Reparse/critical/multilink/oversize/audit failure refuse; vault ancestors must be non-redirected, production ownership privileged and its fresh DACL excludes inherited/explicit user writes. Existing writable mappings remain a non-atomic content-race limit. |
| Forge provider failures/HTML/partial JSON or conflict a known-file answer with malware | Strict bounded parsing and exact SHA256 comparison; failures Unknown; fresh malware wins. Reputation-source compromise remains an explicit file-containment risk, not runtime kill authority. |
| Preserve obsolete outbound blocks through generated COM names | Retirement matches exact Name or DisplayName in local stores, and preserves unrelated groups. Native firewall read-back and outbound smoke remain required. |
| Bypass inbound policy with a unique/renamed rule | New rules do not inherit approval. Identity-bound approval, re-enabled-rule repair, outbound preservation and local/domain boundaries have regression checks. Reconciliation has a finite window, not atomic prevention. |
| Feed a fake NanoAV PID file or collide with an unrelated process/autorun | Migration uses exact expected image paths and one pinned noncritical process handle. Never reads the PID file. Data DLL ownership requires a hash matching a bundled payload; mismatched/ambiguous origin refuses migration before retiring runtime. Recovery data and unrelated instances survive; disposable Windows smoke is mandatory. |
| Manufacture DNS repair authority or restore/revoke while an old automatic repair is queued | Protected latest verified policy is rechecked under the operation gate. Fresh current fingerprints, snapshot/audit acceptance and read-back remain required. Original rollback state is preserved; restored/managed/ineligible/pending configurations are excluded. |
| Treat VPN host routes or arbitrary IPsec state as automatically malicious | Remove shape/count-only route deletion. New policy registry collection is Tier2 integrity evidence; no claim that a startup baseline, readable registry or legacy policy is trustworthy/enforced. |
| Exhaust realtime scans or exploit scanner's own ADS writes | Four workers, per-path coalescing, cancellation/drain, explicit overload reconciliation, no ADS writes and bounded analysis cache. Slow walks/unreadable files remain visible rather than healthy by assumption. |

## Blue-team pass

- Confirm useful coverage is actually registered in Service and Agent, not merely a dormant rule class. Keep terminal scheduling/action separate from composites; preserve durable audit and verified response receipts.
- Verify real Agent/Service separation: targeted Agent owner metadata supplies supported same-lifetime socket-shell proof without assuming cross-host correlation. Bounded background reads do not block terminal telemetry; timed-out native reads retain their concurrency slots until they return. Ordinary streaming, input recipients, consultant signals and PID reuse have negative fixtures.
- Preserve ordinary games, graphics, streaming, mic/webcam records and input heuristics as non-destructive context. Dashboard labels high-priority overlay review without claiming proven spying or a successful kill.
- Preserve NanoAV recovery evidence and source provenance; do not silently import its bad unsigned-file cache or claim the original engine was fixed while still launching it.
- Verify inbound-only intent, two image rules for three core processes, local and local-GPO reconciliation, exact rule identity, essential networking, outbound policy and domain-conflict reporting.
- Exercise approved DNS drift repair, stale authority, managed/ineligible refusal, original-state recovery and policy revocation with inert backends. IPsec monitoring scope distinguishes configuration integrity from active SAs/packet enforcement.
- Check builds and portable tests before pushing. Require native file recovery/audit refusal, policy fingerprinting, firewall/ETW/registry fixtures and legacy migration on disposable Windows in CI. Skips cannot satisfy the native endpoint gate.
- Do not infer STO crash causation or complete runtime coverage from the supplied logs. No claim of kernel resistance, independent IPsec filtering, complete AV parity, remote-session revocation or immunity from a determined high-profile attacker.

## Validation record

See [release validation boundaries](RELEASE_3.4.5.md). Pre-push build/regression commands and test outputs are reviewed before commit. Windows checks execute in CI against the pushed SHA; release publication remains gated by those results. Native checks unavailable on this Linux executor are explicitly pending until CI, never marked passed here. No live malware, keystrokes, audio/video capture, arbitrary registry import or packet-filter test against the user's PC is performed.


Final home-network review: remove blanket Sentinel-owned outbound game/client port blocks, retaining SMB/NetBIOS egress restrictions and inbound protection. Retire obsolete owned filters with group validation; preserve foreign collisions. Stop deleting legacy IPsec policies merely because they are named GSecurity. User-created legacy policies remain separate and may still affect connectivity. Hosting/LAN discovery can require explicit inbound approval; a game name alone cannot open an exception.


Pre-push validation completed: product and shipping-test cross-build zero warnings/errors; portable regressions 598 passed, twelve native Windows fixtures explicitly skipped; dashboard 36 passed; embedded firewall policy 53 checks passed; migration scripts parsed; workflow YAML and preserved upstream source scope verified. Windows CI and publication are pending at this commit, not claimed as passed by these local results.
