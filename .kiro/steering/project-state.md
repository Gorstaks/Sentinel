---
inclusion: always
---

# Sentinel - Current Project State and Pre-Change Checklist

## Read history before acting (mandatory)

`docs/CHANGELOG.md` is the record of what was added, integrated, retired and why. It is too large
to load whole (8,000+ lines), so **search it** before you:

- treat a missing file, project, script, CI step or feature as a bug or an accident;
- restore, re-add or re-wire anything that is absent;
- remove, rename or "clean up" a component, setting or rule;
- propose a fix that changes behavior described in an earlier release.

How: grep `docs/CHANGELOG.md` (and `docs/*.md`) for the component name, then read the matching
version sections. If the changelog says something was integrated, retired or moved, follow that.
If history does not explain it, ask the owner - do not offer "restore it" as a default option.

## Current architecture facts (do not re-litigate)

- **NanoAV is integrated into Sentinel.Core (3.4.5).** There is no separate NanoAV runtime, module
  build or installer step. `installer/retire-nanoav.ps1` and its CI migration smoke were removed on
  purpose. `modules/NanoAV` is archived, hash-locked source for review only
  (`tools/validation/VerifyNanoAVSource.py`); never edit or build it as a product component.
- **GVPN is a separate project (3.6.8)** in `D:\Gorstak\GVPN` with its own repo, versioning and
  installer. Sentinel does not build, bundle, install, start or control any VPN and has no VPN
  response action. `ResponseAction.VpnShieldUp` is an `[Obsolete]` numeric slot kept only for
  serialized-log stability. Sentinel must coexist with any VPN client via `VpnTunnelClassifier`
  and `VpnTunnelLeakMonitor` (observe-only). Never trust a VPN client's log (user-writable).
- **`Network Tamper: Local MitM Chain` is a LogOnly report**, pinned by
  `ResponsePolicy.IsReportOnlyNetworkTamper`.

## Scope discipline

- Change only what the task needs. Do not edit unrelated files to "tidy up".
- A CI/build failure in a file you did not touch is still worth fixing, but say it was pre-existing
  and check history for that file first.
- When a doc, steering file or changelog entry describes a component you change, update it in the
  same change.

## Build, test and release (Windows)

- Build: `installer\build.bat` (delegates to `installer/build.ps1`). If PowerShell scripts are
  blocked by Group Policy, the owner must allow them; do not work around the policy silently.
- CI builds with `-warnaserror`, including tests. Nullable warnings (CS86xx) fail CI - keep test
  code nullable-clean too.
- If a `.csproj` is empty ("Root element is missing"), restore it with
  `git checkout -- <file>` and stop build servers (`dotnet build-server shutdown`) before rebuilding.
- Versioning: one patch per release (`workflow.md`). If `version.txt` is already at the target
  version and the installer was built, do **not** run `installer/release.ps1` (it bumps again);
  publish with `D:\Gorstak\push.ps1 -ProjectFilter sentinel`.
- Every release needs a `docs/CHANGELOG.md` section whose heading matches the released version.
- Never claim "built", "tests pass" or "verified" unless you ran it and saw the result. If you could
  not run it, say so plainly.
