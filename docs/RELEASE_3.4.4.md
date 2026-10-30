# Sentinel 3.4.4: startup, status and false-positive corrections

The supplied logs show a process that exists before host startup completes. The
second 3.4.3 startup enters `host.StartAsync()` at 21:07:31 UTC and completes at
21:19:20 UTC (nearly twelve minutes). The earlier metrics snapshot is still from
3.4.2; a later snapshot confirms 3.4.3 publishing resumed. A process entry in Task
Manager does not establish IPC readiness, and an IPC timeout does not establish
that Windows stopped the service.

## Changes

- Run initial native offline-isolation reconciliation and local firewall/WMI setup
  on background workers. These hosted services must return promptly from startup
  even if a native firewall call is slow. Matching policy is still verified and
  failures remain visible; moving the work does not certify firewall enforcement.
- Give IPC connect, request write and reply read one shared deadline. Keep the
  unauthenticated request cap at 16,384 characters and bound replies separately at 4,194,304
  characters so complete health/metrics rosters remain supported. Dispose timed-out
  pipe operations and observe their eventual exceptions. Authentication, mutation
  authorization and server-side request limits are unchanged.
- Report Service Controller state separately from IPC reachability. The dashboard
  distinguishes starting, stopping, running with IPC unavailable, explicitly stopped
  and unknown. Only an observed SCM Stopped state produces the new stopped label;
  an authenticated health reply still does not establish healthy collection.
- Remove hidden-window flags as a standalone ClickFix trigger. No process-name,
  tray-task-name or registry-path exemption is added: a command containing the tray
  path and an actual download/execute payload can still match. Existing download,
  encoding and execution patterns retain their prior behavior and limitations.
- Correct the About card and architecture documentation to list three persistent
  core roles: Service, Agent and Guard. Guard is a separate `Sentinel.Service.exe
  --watchdog` process. NanoAV and scheduled companions can add other processes.
- Label missing root-program certificate markers as **trust metadata unverified**,
  rather than an established suspicious root. Keep this finding Tier2/Generic,
  LogOnly and excluded from attack correlation. Missing properties/read failure,
  certificate subject and expiration do not establish malicious use. Explicit
  thumbprint distrust policy and its mutation safeguards remain unchanged.

## What the uploaded evidence means

Four incident packs at 21:05:59, 21:08:33, 21:12:33 and 21:15:34 UTC record the same
hidden PowerShell command setting `NotifyIconSettings` `IsPromoted=1`. Sentinel
verified four process kills and then attempted composite response against the
already-exited processes. These are false positives for the displayed command,
not evidence of remote control. The patched ClickFix rule returns no finding for
that command, preventing its false reverse-shell signal from seeding the follow-on
composite. Historical packs and logs are preserved; this release does not relabel
or delete stored evidence retroactively.

The certificate example is a Windows Hardware Compatibility certificate dated
1997–2002, thumbprint `109F1CAED645BB78B3EA2B94C0697C740733031C`. Its event explicitly
reports no removal and no file quarantine. This release neither grants trust based
on a Microsoft-looking subject nor removes it based on absent root-program markers.
No certificate bytes or chain were supplied, so authenticity and current chain use
are not established by the log text.

## Validation and limits

Regression coverage checks startup completion while a fake native firewall remains
blocked, SCM/IPC state distinctions, stalled IPC operations, replies larger than
16,384 characters, unchanged unauthenticated limits, the exact reported tray command, hidden
benign commands, preserved download/execute detection and review-only certificate
findings. Dashboard tests exercise the new status labels; About text is reviewed against the
installed Guard service definition. Existing native endpoint and packet-level firewall
gates remain required.

Local validation: product/shipping-test cross-build **zero warnings/errors**;
selected portable tests **476 passed**, eight native Windows fixtures skipped;
dashboard **34 passed**. Windows CI must execute its full suite and native gates.

A long first-start trace identifies delayed host readiness, not the exact blocked
native call. The supplied files omit `diagnostic.jsonl`. Other slow constructors,
OS calls, ACL/IPC failures or machine policy can still delay readiness; fresh host
logs are required to prove the reported installation recovers. A timed-out request
does not cancel a privileged operation already accepted by the server. This release
does not claim universal ClickFix/encoded-script safety or RAT detection.


The first independent release run exposed a timing-dependent synthetic pipeline
fixture failure after the main Windows suite passed. The fixture now uses a
non-refreshing injected ancestry source instead of starting an undisposed live
process-enumeration timer for every case, disposes the cache, shares the existing
ResponsePolicy test collection, and uses non-live odd synthetic PIDs. Its ten-second
deadline and LogOnly/no-KILL assertions are unchanged. Timeout reports now include
engine diagnostics and queue state. This fixture requires Windows Framework ACL
APIs and cannot run in the Linux portable host; Windows CI and release reruns are
required. No product response gate was weakened to accommodate the test.
