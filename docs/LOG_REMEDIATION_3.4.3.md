# Sentinel 3.4.3: detection and runtime reliability

The supplied 3.4.2 runtime snapshot exposed dispatch overload and incomplete file
coverage. The accompanying investigation transcript identified a separate shared
policy exception. This release addresses the confirmed code defects; the artifacts
do not establish infection, explain individual DLL outcomes, or identify the cause
of Chrome scrolling.

## Evidence and changes

| Finding | Evidence and correction |
| --- | --- |
| Detection evidence parsed as a path | `IsBenignInstallerNoise` fell back to free-text evidence and passed it into Framework `Path` APIs. Quotes/control characters can throw; redist words in prose could also acquire an exemption. Remove the fallback, reject malformed Windows path hints, test the full rule/policy/logging route, and identify diagnostic failures as evaluation or policy/dispatch. |
| ETW dispatch overload | Latest snapshot: 72,387,833 observed callbacks; 41,244,127 dispatch drops; zero reported native event/buffer loss. Drops are a subset of callbacks, about **57%**, not an additional denominator. These are lost analysis opportunities, not benign filtering. |
| Expensive shared work | One worker served all providers. File names were resolved to live processes before security-scope filtering; path-less registry writes repeatedly reopened process identities just to refresh a weak WMI host hint. Move scope checks earlier, coalesce only that hint lookup to once per PID/second, and use independent process/image, file, registry and remaining-provider queues. Each has 2,048 event slots and 4 MiB payload (8,192 / 16 MiB total). |
| Visibility-alert churn | The two event files include 3,276 ETW degradation detections. Alternating quiet/loss polls changed the reason text despite a continuing provider gap. Remember reported reasons until stable recovery, keep a 30-second recent-loss window, use five-minute reminders, and refresh ongoing-loss reconciliation at most once per minute. Coverage and cumulative loss remain visible. |
| Firewall rule growth | Repeated count increases of six match the six offline-isolation rules applied every minute. Adding fresh COM rule objects is not a safe name-based upsert. Inventory existing duplicates, remove only exact reserved names whose colliding entries all have Sentinel's grouping, recreate the affected rule, and verify matching objects in place on subsequent cycles. Foreign collisions cause explicit failure. |
| Incomplete file enumeration | The scan completed with 30 unreadable paths. Keep that gap visible with up to three path/type/HRESULT examples and schedule another incremental walk after 15 minutes while watchers remain active. Skip successful indexed files; retry failed files/directories. Do not mistake `File.Exists` returning false on access denial for confirmed disappearance. Continue past a child directory whose attributes cannot be read. |
| Token capability misclassified | Privilege observations were logged with Tier1/CredentialDump metadata despite no observed credential operation. Make the source Tier2/Generic and enforce context-only behavior at the shared dispatch/correlation boundary, including legacy family/composite metadata. Privilege possession alone cannot authorize response. |

The latest snapshot has **zero response attempts**. Across both event files, 11,603
response results are NotRequested; one older result is PartiallyCompleted. Do not
interpret the cumulative historical files as fresh process kills in 3.4.2. Both
supplied ledger files are internally consistent (158 and 3,513 records); without a
trusted external checkpoint that does not prove completeness or independent
integrity. Startup traces show three service starts, not evidence of an Agent crash
loop. The new uploads do not include the diagnostic exception log or NanoAV's own
action log; shared policy exception attribution also relies on the supplied
transcript and matching source.

## Validation

- Local validation: product/shipping-test cross-build **0 warnings / 0 errors**;
  selected portable tests **458 passed**, eight native Windows fixtures skipped;
  dashboard **33 passed**. The optional Windows Desktop ML trainer is outside the
  Linux cross-build. Windows pipeline/COM acceptance remains the CI gate.
- Portable tests use the production Core assembly, including malformed-path policy,
  terminal/nonterminal authority, native/managed event-filter parity, independent
  saturated queues, FIFO name/read order, registry hint coalescing, intermittent
  alert coalescing and partial-scan diagnostics. Existing payload-copy/byte-budget,
  credential-read and native missing-rule exception regressions remain in the run.
- Windows Framework tests exercise the complete rule -> policy -> local detection
  log path for the three reported rule classes. These use inert data and LogOnly
  observations, not malware, sockets or process termination.
- The required Windows endpoint CI gate now includes **eight native fixtures**.
  The new one seeds duplicate rules scoped to nonexistent executables under a
  private temporary directory, applies policy repeatedly, requires exactly one
  verified rule per owned name and preserves an unrelated rule. It refuses to
  overwrite an existing installed Sentinel policy and cleans up its test rules.
- Dashboard tests cover response truth, escaping and coverage presentation. New
  metrics distinguish genuine aggregate/lane rejection from unused event-ID
  filtering and intentionally coalesced registry hint refreshes. Lane rejection
  counters describe the current dispatcher instance; aggregate loss also includes
  handler/callback failures and persists across session restart.
- NanoAV source-preservation verification checks the original separate .NET module.
  `tools/validation/VerifyNanoAVSource.py` is a developer check, not NanoAV itself
  and not an installed endpoint dependency.

Linux checks cannot run native Windows Firewall/Framework behavior. The Build &
Test workflow must pass before release publication, with the native gate refusing
skipped fixtures. Passing tests does not prove sustained-load behavior on the
reported Windows installation; compare fresh per-lane loss and file-gap details
after installation. No claim of loss-free collection is made.

## Remaining boundaries

Protected Threat-Intelligence access denial remains an explicit Windows privilege
limit. FIFO order is retained within providers; separate lanes do not establish
cross-provider causality. CPU/OS/identity contention and slow image handlers can
still cause loss. Recovery snapshots cannot reconstruct lost events.

Duplicate repair is limited to Sentinel's reserved offline rules and does not
purge arbitrary firewall entries. Policy read-back is not a packet-enforcement
measurement. Persistent locked/denied files remain incomplete; retries do not
change ACLs or unlock processes. Scan metadata caches retain their documented
size/mtime limitations.

Neither the logs nor the installed extension list proves the cause of browser
scrolling. No extension was disabled or branded malicious. A controlled comparison
with extensions disabled and hardware/input checks is still needed on the actual
PC. An empty quarantine is not evidence that DLL remediation ran or should have
run. No live KGB RAT sample was obtained or executed; 3.4.2's report-based
observations retain their documented limits. NanoAV's independent response engine
and existing Sentinel coexistence modifications are unchanged.
