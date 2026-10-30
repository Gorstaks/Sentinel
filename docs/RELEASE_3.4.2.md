# 3.4.2 coverage, collection and dashboard changes

This release addresses the supplied KGB RAT analysis, the October runtime logs and
the dashboard screenshot. It adds report-based observations and safer response paths;
it does not establish that KGB RAT infected the user's machine or that every variant
will be detected or contained.

## KGB RAT and response safety

- A bounded PE content check requires both reported markers, `|Ghost|` and
  `WhyYouReverseMe..ImInnocent..LoveYouu..`, within the first 2 MiB. ASCII/UTF-8 and
  UTF-16LE strings may have independent alignment. A matching filename is irrelevant.
  File reputation exposes the finding and file scanning emits a Tier2 LogOnly
  observation. Matching embedded examples can still produce observations; encrypted,
  altered, or later-positioned markers can evade this check. It is not a kill rule.
- Kernel-File credential-read matching now includes structured Windows Vault paths:
  GUID-scoped `Policy.vpol`/GUID-named `.vcrd` files and
  `UserProfileRoaming\Latest.dat` beneath user AppData Microsoft Vault directories.
  Reads alone remain LogOnly. Existing corroboration requires independent behavioral
  evidence, fresh timestamps and the same live process lifetime. No passwords are read
  or decrypted by this matcher; it processes file-access metadata.
- The persistence-surface monitor inspects bounded loaded interactive-user hives for
  Policies Explorer Run and nonempty ms-settings/mscfile command associations. This
  avoids assuming SYSTEM's HKCU is the desktop user's hive. First observation and
  changes are distinguished from proven creation/actor attribution. Values are not
  removed and command contents are omitted from observations. Unloaded profiles,
  registry views, Startup `.url` interpretation and complete task cleanup remain gaps.
- Process-tree response queries runtime criticality through the pinned handle and
  checks again immediately before termination. Critical or unqueryable targets are
  refused. Sandbox termination uses the guarded tree path rather than unconditional
  job-wide termination; installer agent shutdown also checks own-image identity and
  criticality. The implementation never clears a critical flag to force termination.
  Query and termination are not atomic, and this is not a guarantee against a
  privileged attacker changing process state or every intrusive remediation failure.
- Remove the MTP monitor's direct process kill from ambiguous non-media staging
  context. Its observation is Tier2/LogOnly and cannot bypass response policy. Device
  presence, filenames and staging do not prove an actual malicious transfer.

The report's HVNC, keylogging, screen capture, ransomware and rootkit advertising is
not equivalent to validated Sentinel coverage. No live KGB sample was obtained or
executed. Tests use inert buffers and harmless owned processes; no test deliberately
marks a process critical. NanoAV's supplied engine and source-preservation scope are
unchanged.

## File scanning and ETW

The background walk previously waited two seconds before every file, including old
stable files, and then added a 200 ms per-file delay. Stable files now avoid that
settling wait; active writers retain bounded retries. The walk yields for 20 ms
between evaluations, skips directory reparse points to avoid cycles, threads
cancellation through evaluation and reports volume, directory/evaluation/cache counts,
elapsed time and unavailable paths. Errors remain incomplete coverage, not a clean
verdict. The file engine performs the content hash; the scanner no longer hashes the
same file first or lets old ADS verdicts bypass new checks. Persisted scan-index
headers are tied to the engine version, so the upgrade requires a fresh rule pass.
Metadata caching and explicit exclusions remain limitations, especially if an attacker
preserves size/mtime; enumeration is not proof every transient file was inspected.

ETW callbacks copy payloads while their native pointers are valid into an owned FIFO
queue, bounded to 2,048 in-flight/queued events and 16 MiB of payload. A separate
worker executes handlers so analysis cannot synchronously block ProcessTrace.
Exhaustion and handler failures increment dispatch-loss counters; events are not
silently treated as analyzed. Metrics expose queue depth, payload bytes and handler
busy time. A handler busy for more than five seconds degrades collection health even
if its thread remains alive. Shutdown stops intake and releases copied/pinned memory.

This can reduce callback pressure; it does not guarantee loss-free collection.
Native events lost before delivery and queue losses remain separate. Protected
Threat Intelligence access denial remains a Windows limitation; these changes neither
bypass it nor provide equivalent coverage. Historical events cannot be reconstructed.

## Dashboard organization

Overview now starts with compact coverage/activity cards and at most three collector
issues. The full roster is in Health & Metrics behind an explicit, keyboard-operable
show/hide control, with search and status filters in a bounded scrolling table. Task
liveness, checked collection, unverified collection and standby/completed tasks remain
separate. Unverified instrumentation is not mislabeled as an unsupported security
feature, and missing roster data stays explicit.

Native `<details>` and CSS Grid no longer control the layout: IE11 does not support
the former and cannot use the original modern Grid layout. Flex layouts, margins and
ES5 JavaScript preserve the existing legacy-browser fallback. Main status cannot turn
green merely because the service replied before collection health arrived. Detection
counts are labeled as observations in the latest 20 events, rather than falsely
claiming a full day's threats. Metrics distinguish application queue drops from ETW
native/dispatch losses and group activity, responses, collection and product data.
No response-disabling controls, screen capture or keylogging are added.

## Validation

- Product projects and shipping tests cross-build with warnings as errors. The optional
  Windows Desktop ML trainer is outside this Linux build.
- Selected production-assembly portable tests: **426 passed**, seven Windows fixtures
  skipped. The full native Framework suite and Windows ACL/ADS/path-specific cases
  remain for Windows CI.
- Dashboard: **32 tests passed**, including escaping, stale replies, collection
  warnings, large rosters, search/filtering and explicit disclosure.
- Chromium preview checks at 960×620 and 720×620 cover compact layout, navigation,
  filtering/disclosure and page errors using fixture data. These are not native IE11
  or installed-Windows UI validation.
- NanoAV source-preservation verification passes. The existing native endpoint CI
  gate exercises real process exit, native ETW delivery, policy read-back and related
  fixtures. Sustained load, actual interrupted-walk recovery, privileged criticality
  races and representative KGB sample detection still require isolated Windows work.

## References

- [Group-IB KGB RAT report](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/),
  analyzed from the full text supplied by the user; distinguish observed samples
  from advertised modules.
- [Microsoft IsProcessCritical](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocesscritical):
  query-limited access is sufficient; a failed query is not a noncritical result.
- [Can I Use: details/summary](https://caniuse.com/details): IE11 support is absent.
