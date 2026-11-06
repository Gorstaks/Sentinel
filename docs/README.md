# Sentinel Documentation

**Current Version:** 3.6.4 (see [CHANGELOG.md](CHANGELOG.md) for release history)

## Core Documentation

Essential documents for understanding and operating Sentinel:

| Document | Purpose |
|----------|---------|
| [CHANGELOG.md](CHANGELOG.md) | Complete version history and changes for each release |
| [design.md](design.md) | Runtime architecture, detection pipeline, response flow, and privilege boundaries |
| [requirements.md](requirements.md) | Functional and safety contracts for all detection tiers and response actions |
| [constraints.md](constraints.md) | Hard constraints that must never be violated (no kernel drivers, userland-only, etc.) |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security boundaries, threat coverage, and residual risks |

## Feature Documentation

Specific feature and capability documentation:

| Document | Purpose |
|----------|---------|
| [DNS_REPAIR.md](DNS_REPAIR.md) | Administrator-approved DNS resolver repair and verification |
| [HASH_REPUTATION.md](HASH_REPUTATION.md) | Bounded online SHA256 hash reputation queries and local fallback |
| [CERTIFICATES.md](CERTIFICATES.md) | TLS root certificate distrust policy and validation |
| [NANOAV.md](NANOAV.md) | Integrated NanoAV threat intelligence coverage and limitations |
| [RULE_PACKS.md](RULE_PACKS.md) | Local RSA-signed rule packs (no endpoint downloads) |
| [ATTACK_COVERAGE_2026.md](ATTACK_COVERAGE_2026.md) | Current MITRE ATT&CK coverage and detection gaps |
| [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md) | Remediation coverage matrix and remaining work |

## Tools Documentation

- **[Sentinel.ExploitShield](../tools/Sentinel.ExploitShield/README.md)** - Automatic Windows CVE/PoC collection and patching
- **[Sentinel.Diagnostics](../tools/Sentinel.Diagnostics/README.md)** - Local event log replay and redacted export for diagnostics
- **[Sentinel.MlTrainer](../tools/Sentinel.MlTrainer/README.md)** - Optional offline ML model training (soft signals only)

## Historical References

These documents provide historical context and implementation rationale:

- [PROTECTION_EVIDENCE_HARDENING.md](PROTECTION_EVIDENCE_HARDENING.md) - Evidence pack creation and audit trail
- [EXPLOIT_PAYLOAD_PROTECTION.md](EXPLOIT_PAYLOAD_PROTECTION.md) - Exploit payload detection and containment
- [INSTALLER_RELAY_COVERAGE.md](INSTALLER_RELAY_COVERAGE.md) - Installer and relay attack coverage
- [LOADER_PAYLOAD_COVERAGE.md](LOADER_PAYLOAD_COVERAGE.md) - DLL loader and injected payload coverage
- [VIRUSTOTAL.md](VIRUSTOTAL.md) - Historical AV investigation notes (not real-time detection)
- [OFFLINE_VALIDATION.md](OFFLINE_VALIDATION.md) - Windows platform validation results

## Quick Reference

### For Operators
1. Start with [design.md](design.md) to understand the detection pipeline
2. Review [THREAT_MODEL.md](THREAT_MODEL.md) for what Sentinel protects against
3. Check [CHANGELOG.md](CHANGELOG.md) for new features in your version

### For Developers
1. Read [requirements.md](requirements.md) for detection tier contracts
2. Review [constraints.md](constraints.md) for hard rules
3. Check [design.md](design.md) for architecture
4. See individual tool READMEs for component-specific details

### For Security Reviews
1. Start with [THREAT_MODEL.md](THREAT_MODEL.md)
2. Review [constraints.md](constraints.md) for security guarantees
3. Check [CHANGELOG.md](CHANGELOG.md) for security fixes
4. See specific feature docs for implementation details

## Architecture Overview

```
Monitors → TelemetryFusionEngine → DetectionEngine → AdvancedResponseEngine → JsonlEventLogger
    ↓                ↓                    ↓                    ↓                      ↓
 Telemetry         Event                Detection           Response              Audit
 Sources           Enrichment            & Scoring          & Mutation            Trail
```

- **Monitors:** Real-time system activity observation (process, network, file, registry, etc.)
- **Fusion Engine:** Event enrichment, process chain tracking, correlation
- **Detection Engine:** Rule-based and behavioral anomaly detection with confidence scoring
- **Response Engine:** Response action authorization with Tier1/Tier2 enforcement
- **Event Logger:** Immutable audit trail in JSONL format

## Tier System

- **Tier1 (Behavioral):** High-confidence malicious activity requiring immediate response (kill/quarantine)
- **Tier2 (Indicator):** Lower-confidence signals for investigation and behavioral correlation (log-only)

See [requirements.md](requirements.md) for specific Tier1/Tier2 rules and authorization contracts.

## Version Support

Current version: **3.6.4**
- Supported OS: Windows 10, 11, Server 2019+
- Runtime: .NET Framework 4.8
- Deployment: As Windows Service + User-session Agent
