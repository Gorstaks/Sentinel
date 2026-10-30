# 3.4.6 red/blue engineering review

This is a source and inert-fixture engineering review, not an independent penetration test or malware certification.

## Red-team questions

- Can an attacker rename a DLL to RTSSHooks64.dll to gain trust? No special filename/path exemption was introduced. A foreign-path identity result is still denied/unverified, but review-only. Explicit writable-drop and sideload-plant classifications remain actionable. A malicious external DLL that avoids concrete behavioral detection remains a coverage limit; unknown identity alone is not proof sufficient to kill a legitimate host.
- Can provider failure, HTML, HTTP 410, absent credentials or a malformed response produce a malware verdict? No. Provider status, schema, hash syntax and bounded sample count must validate. Only an exact current SHA256 match supplies file-policy evidence; a hash cannot authorize process termination.
- Can an Auth-Key leak to CIRCL, redirected hosts or the command line? The header is attached only to the fixed MalwareBazaar POST. Redirects/cookies stay disabled. Provisioning prompts securely and stores DPAPI bytes under a protected machine registry key. The Service rejects nonprivileged ownership, inherited ACLs and any nonprivileged allow ACE. SYSTEM/admin compromise remains outside this credential boundary.
- Can registry flooding hide process events by taking their queue slots? Lanes stay separate; repeated registry hints coalesce before queue allocation, with a bounded 4096-PID admission table. Admission is not a claim of complete collection. Overflow/loss accounting stays active. No file-read or process/image evidence is coalesced by this change.
- Can uninstall delete an owner's IPsec policy by name? The remaining Inno Setup GSecurity deletion was removed; no such policy-name deletion remains in the installer/runtime path.

- Can an un-openable child be silently ignored and full-tree containment declared verified? No. Preserve continued root/openable-child containment, but record refused child IDs and incomplete discovery; the receipt remains partial.

## Blue-team checks

The supplied metrics and rotated events were separated by time/version. A recorded taskhostw kill associated with RTSSHooks64.dll motivated the external-module review boundary. Historical NanoAV cache/deletions were not imported or treated as proof of present malware. Existing privacy, terminal socket-shell, file-containment and DNS/firewall authorization guards remain in force.

Regression coverage checks missing/malformed authentication, HTTP Gone remaining Unknown, authenticated request shape and header isolation, invalid provider data, foreign-plugin review without trust, continued writable/sideload classification, and pre-queue registry flood admission/clock recovery. A native private-registry fixture checks actual machine-DPAPI round-trip and rejection of an Authenticated Users read ACE. Build requires all thirteen native endpoint fixtures to execute and pass. Native Windows retains the recoverable-byte, audit-before-mutation, exact source-hash and owned-process lifetime fixtures. The active audit reader uses FileShare.ReadWrite | FileShare.Delete instead of weakening the writer's ownership.

## Validation

Pre-push checks: product and all shipping tests cross-build with zero warnings/errors; portable suite 607 passed, 12 native fixtures skipped; the new credential Windows fixture is cross-built and reserved for the mandatory thirteen-test native CI gate. Dashboard 36 passed; embedded firewall policy 53 checks passed. PowerShell scripts and workflow YAML parse, preserved upstream NanoAV source scope verifies, and whitespace checks pass. The older Framework-specific audit tests cannot execute in the .NET 10 Linux host and remain in the native Windows suite. Windows-only fixtures must pass in GitHub Actions before installer publication; portable execution does not satisfy that gate. Live authenticated MalwareBazaar service access cannot be validated without an owner-provided key. No key is fabricated or embedded.

## Upstream reconciliation

Fetched Kiro's main fixes through d10d1bb. Build & Test run 40240374907 and Release run 40240793615 succeeded before this release. Preserve those commits and their runtime/migration changes. The extra descendant-reporting change corrects receipt completeness without restoring the previous whole-operation abort. The installer still continues on legacy retirement failure; removal must be verified separately.

## Published artifact identity correction

Hashing the downloaded 3.4.5 installer confirms the VirusTotal hash 2ecdae69bf8b38de7470607dcd6dd0b309e77d65046098277c01cb3331dba8fe; the release manifest listing dca1ea35... is stale. Reading a checksum manifest alone does not establish the served asset's identity. Added a release step that downloads all four published assets and compares the manifest and three payloads with the tested build, using fixed artifact names rather than paths parsed from downloaded text. Inert PowerShell checks cover matching publication, changed installer bytes with stale checksum, and replaced manifest.
