# Containment CI follow-up

The reported Windows endpoint smoke run passed 12 fixtures and failed one. Its
receipt recorded root exit and other exits, but two access-denied candidate descendants
made discovery incomplete. The assertion correctly refused to call that full-tree
success. No test assertion or incomplete-response rule has been relaxed.

Source inspection identifies an ordering gap: Toolhelp parent-PID associations can
refer to an earlier occupant of a reused PID. The terminator already excludes children
older than their alleged parent, but previously obtained termination rights before
checking age. A protected older process can deny that open before the age check runs.
This is a possible explanation for the reported CI failure; its exact refused-process
creation times were not supplied and Windows reproduction remains necessary.

The fallback now opens only a limited-query handle after an unsuccessful destructive
open. It excludes the candidate only when a positive creation timestamp is strictly
older than the pinned parent's timestamp. An unknown, equal/newer, or inaccessible
identity still records refusal and incomplete discovery. Root containment and containment
of other openable descendants continue. The query handle is disposed. No additional
privileges are enabled, and no termination-access denial is treated as success by itself.

Deterministic regressions cover an older protected candidate, possible real descendants,
zero/unknown creation time and a denied identity query. The socket-shell Windows fixture
also uses its existing creation-anchored timestamp helper for the first fresh signal,
matching the second signal's treatment of Windows clock granularity.

Local validation: all nine projects cross-build with zero warnings/errors; 153 selected
portable cases pass. The actual Windows smoke failure has not been rerun here.

## Independent policy failure in 3.5.9

The security-template test was reproduced locally and still fails at its global
privilege-rights check. The policy and that test remain unchanged at the user's request.
The current file also declares zero for all nine legacy audit categories and zero for
password minimum length/complexity. Whether advanced audit policy overrides the legacy
declarations depends on the target; this is not evidence that effective auditing is safe.
Adjusting the test to pass without resolving or explicitly reviewing those requirements
would hide the incompatibility. Version 3.5.9 is prepared for CI with this known policy
failure; it is not represented as an all-green release.

## Policy correction in 3.6.0

With subsequent user authorization, the shipping template removes its global privilege
and logon-right assignment block and declares success/failure auditing (`3`) for all
nine legacy categories. Zero/off overrides for password length, complexity/history and
FIPS policy are omitted so the template does not lower existing host settings. The
original policy assertions remain; additional guards reject those weakening overrides.

This does not reconstruct pre-installation rights or password policy on machines where
an older template was already applied. Restore such settings from a known-good host or
domain baseline. Effective audit policy may also depend on advanced/domain policy;
the static template test is not proof of target-host policy read-back or containment.
