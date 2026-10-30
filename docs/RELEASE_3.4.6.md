# Sentinel 3.4.6

This maintenance release addresses the 3.4.5 Windows test failures, a retired reputation endpoint, and compatibility/telemetry problems found in the supplied home-PC logs.

- Foreign-location DLLs with unverified publisher identity now produce a separate Tier2 review event, rather than killing the host just for that identity result. This addresses the recorded taskhostw/RTSSHooks64.dll containment. The module is not trusted; writable-drop and explicit sideload-plant defenses remain armed. No filename exemption is added for RivaTuner or any other overlay.
- Registry ETW hint coalescing happens on the single callback thread before payload copy/queue admission. Registry hints are per-PID invalidations, not credential-read evidence. Suppressed duplicate hints are counted separately from lost telemetry. Process, image, file and other event lanes remain independent.
- MalwareBazaar's retired anonymous export is replaced by its authenticated get_recent API (latest 100 SHA256 samples). It requires the owner's Auth-Key. Without one, malware reputation explicitly reports Not configured and remains Unknown; CIRCL known-file context remains available and never grants runtime trust. This limited recent corpus is not comprehensive antivirus coverage.
- An elevated, interactive `installer/set-malwarebazaar-key.ps1` stores the provider credential with machine DPAPI and SYSTEM/Administrators-only registry access. The Service rejects unprotected credentials. Restart the Service after provisioning or removal. No key is shipped, uploaded in reports, or passed on a command line.
- Connection-drop observations no longer assert that already-active endpoints are new C2 connections; alerts coalesce by process lifetime. Domain entropy explanations acknowledge normal CDN/browser protection use.
- Uninstall no longer deletes an owner-created IPsec policy merely because it is named GSecurity.
- Preserve Kiro's successful 3.4.5 CI fixes: closed audit handles before assertions, explicit certificate-distrust test expectations, creation-time-anchored socket-shell tests, migration Run-key creation, and continued containment of openable descendants. Add explicit policy assertions. Unknown descendants are now reported as incomplete/refused instead of allowing a verified full-tree success receipt; the root and openable children are still contained.
- Preserve Kiro's best-effort installer continuation when old NanoAV retirement fails. Such an installation does not certify that the old companion stopped; review the retirement log.
- Firewall smoke failures expose the actual exception in the public Actions summary.

## Evidence and limits

The latest metrics identify version 3.4.5, 139,897 ETW dispatch drops (124,734 in the registry lane), no native lost buffers/events, an unfinished file enumeration with protected-path failures, and no verified response in that service session. Historical rotated logs include older verified kills and certificate operations; those must not be attributed to the latest session. NanoAV's supplied log ends on October 24 and does not establish that its independent engine still ran after the upgrade.

Windows denies the protected Threat Intelligence ETW provider even to ordinary SYSTEM services. This release does not bypass that boundary or claim equivalent replacement visibility. Protected files and incomplete scans remain disclosed coverage gaps. Pre-queue coalescing is not proof that future workloads cannot drop events.

The VirusTotal sample SHA256 is `2ecdae69bf8b38de7470607dcd6dd0b309e77d65046098277c01cb3331dba8fe`. Downloading and hashing the actual published 3.4.5 installer confirms that same hash (11,877,931 bytes). Its published SHA256SUMS.txt instead lists `dca1ea359f500e746bfd37be68b3554e5c401ec28704e4d00d4957dec0ddc7b2`: the checksum manifest is stale. The earlier inference from the manifest alone that VirusTotal analyzed a different build was incorrect. Existing release assets are preserved; 3.4.6 adds post-publication download/byte verification against the build's manifest and artifacts, with regressions rejecting replaced bytes and stale manifests. This checks publication consistency, not malware safety or Authenticode identity.

The supplied sandbox traces show installer activity and low-confidence technique labels, not proof of rootkit/injection activity or of complete product safety. No antivirus exclusions, obfuscation or security-feature removal are used to suppress detections.

Validation and the red/blue engineering review are recorded in [AUDIT_3.4.6.md](AUDIT_3.4.6.md). Native Windows checks and installer publication remain gated by CI; Linux cross-builds are not native Windows execution.
