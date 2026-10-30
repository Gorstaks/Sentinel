# Sentinel documentation

Current source version: **3.4.5** (`version.txt`). See [release scope](RELEASE_3.4.5.md), [red/blue audit](AUDIT_3.4.5.md), [integrated NanoAV coverage](NANOAV.md) and [hash reputation](HASH_REPUTATION.md). Historical versioned sections do not override current behavior; a source version alone does not establish installer publication or native Windows validation.

## Current guidance

[DLL-loader and injected-payload coverage](LOADER_PAYLOAD_COVERAGE.md): RX/private-PE inspection, victim-only response, native fixtures and explicit remaining limits.

[Installer and relay coverage](INSTALLER_RELAY_COVERAGE.md): Python socket-shell signatures, credential-read corroboration, removable-drive scanning and Windows acceptance checks.

[Automatic exploit protection](../tools/Sentinel.ExploitShield/README.md):
online CVE/PoC collection, Windows Update applicability and automatic vendor fixes;
native task/WUA CI checks and explicit target-machine validation limits.

[Integrated NanoAV coverage](NANOAV.md): native port, migration/recovery, policy boundaries and archived upstream limitations.

| Document | Scope |
| --- | --- |
| [DNS repair](DNS_REPAIR.md) | Administrator-approved resolver repair, restoration, verification and platform limits |
| [Capability matrix](CAPABILITY_MATRIX.md) | Current remediation coverage and concrete remaining work |
| [Engineering gates](ENGINEERING_GATES.md) | Measurable improvement criteria, 3.3.3 evidence and remaining validation |
| [Design](design.md) | Runtime architecture, online/privacy boundaries, privilege boundaries, firewall enforcement and verified response outcomes |
| [Requirements](requirements.md) | Current functional/safety contracts, including 3.2.2 certificate and response corrections |
| [Constraints](constraints.md) | Implementation and response limits |
| [Threat model](THREAT_MODEL.md) | Current boundaries and residual risks, with clearly dated historical implementation notes |
| [Hash reputation](HASH_REPUTATION.md) | Bounded online SHA256 context and local fallback |
| [Certificate policy](CERTIFICATES.md) | Trust-marker observations, explicit distrust authorization and purpose/private-key limitations |
| [Windows validation](OFFLINE_VALIDATION.md) | Observed Windows test results and remaining domain/reboot/interactive/installer checks |
| [2026-10-18 regression review](REGRESSION_REVIEW_2026-10-18.md) | Follow-up change review, current cross-build/portable results and unrun Windows gates |
| [Rule packs](RULE_PACKS.md) | Local RSA signature verification; no endpoint pack downloads |
| [Diagnostics](../tools/Sentinel.Diagnostics/README.md) | Local replay, integrity checks and redacted export |
| [Offline model training](../src/Sentinel.Core/MlModels/README.md) | Optional local ML artifacts; soft signals only |
| [Roadmap](ROADMAP.md) | Future work, not shipped features or a promise to restore online transports |

## History and independent components

[CHANGELOG](CHANGELOG.md) records what each version changed. Older release entries remain historical; they are not rewritten to claim new behavior existed earlier. Versioned sections inside design/threat-model documents also retain history; current requirements and safety boundaries take precedence.

[Architecture council](architecture-council.md) is historical rationale. [Typed-family migration](typed-family-migration.md) and [ETW callstacks](etw-callstack-detection.md) describe their specific implementation work; current response policy still applies. [Engineering review](QUALITY_REVIEW.md) preserves its dated assessment and adds current validation; old scores are not current ratings. [VirusTotal notes](VIRUSTOTAL.md) are historical/manual AV investigations, not current detection counts or an endpoint upload feature.

The [legacy Worker](../worker/README.md) is a separately deployed server component retained in source and release assets. Sentinel 3.2.3 does not call it. Deploying/configuring the Worker cannot re-enable removed endpoint transports.

## Audit scope

This pass corrected stale current guidance about online sources/uploads, evidence survival, retired probes/feed monitors, always-on hardening, certificate-removal authority, RSA rule packs, response outcomes, version labels and validation status. It is a documentation consistency review against those implementations and observed CI results, not certification that every historical monitor table is an exhaustive live registration list or that every platform scenario was tested.

- [Read-only security audit and report privacy](SECURITY_AUDIT.md)

- [3.4.6 release notes](RELEASE_3.4.6.md) and [red/blue engineering review](AUDIT_3.4.6.md).

- [3.5.1 policy rollback and Defender acceptance](RELEASE_3.5.1.md).
