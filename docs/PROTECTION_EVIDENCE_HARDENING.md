# Protection and evidence hardening

Immediate, authorized kill-grade Tier1 detections now pass silent-observation
notification/reporting gates without requiring the legacy `ChainConfirmed` metadata
flag. The reporter's existing confidence, attack-character, cooldown and capacity
checks still apply. Tier2 observations remain logged; they do not acquire destructive
authority from a score, a static marker, or repetition alone.

Signed IDE/browser host context no longer skips the first per-process correlation
evaluation. Available host-wide observations are evaluated through the same path as
other processes. Signing does not prove that a running host has not been compromised.

The chain tracer no longer accepts an IDE install-folder substring as an identity
anchor. A recognized IDE name also requires successful Authenticode verification,
including in per-user install locations. Temporary/download locations remain excluded.
This exemption protects an ancestor host during child response; it does not suppress
direct behavioral detections against that host.

Evidence-pack creation, reporting failures and cooldown/capacity skips now have explicit
JSONL records included in the daily hash-linked audit ledger. Reporter exceptions are
logged at error severity. A skipped or failed pack is distinguishable from no eligible
detection. This does not remove the ledger's documented size/retention limits or make it
immune to an administrator rewriting all copies.

These changes do not restore inaccessible protected ETW providers, recover dropped
events, complete an interrupted file walk, or establish KGB RAT coverage. Those limits
remain visible. Sentinel's marker regression tests intentionally contain inert reported
strings; finding those strings in the compiled test assembly is not proof of infection.
The installer takes product publish outputs, not the test build directories.

Original uploaded diagnostic files are not modified. No file has been disinfected or
deleted based on an unverified detection label.

Validation: all nine solution projects cross-build on Linux with zero warnings/errors.
Of 106 selected regression cases against the compiled production Core assembly, 103
passed. Three ledger integration cases could not run in the .NET 10/Linux harness:
the Framework logger's `DirectoryInfo.GetAccessControl()` API is unavailable there.
They compile for the product target and remain required Windows/.NET Framework tests;
they are not reported as passed or disabled. The full Framework suite, installed-host
signing checks, native containment tests, Defender validation and an installer build
remain required before shipping. Version 3.5.7 is prepared for Windows CI validation;
local cross-builds do not establish release publication or target-host readiness.
