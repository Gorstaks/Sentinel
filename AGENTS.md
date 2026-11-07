# Sentinel Agent Guidelines

This repository follows strict architectural, workflow, and security rules:

1. **Workflow & Versioning**: Follow `.agents/rules/workflow.md` and `.kiro/steering/workflow.md`. Versions are strictly `MAJOR.MINOR.PATCH`, bumped by exactly one patch per release. Single source of truth is `version.txt`. Never jump versions. Releases use `installer/release.ps1` and `D:\Gorstak\push.ps1 -ProjectFilter sentinel`.
2. **Hard Constraints**: Follow `.agents/rules/constraints.md` and `.kiro/steering/constraints.md`. Userland only (no kernel drivers, no rootkits). Tier2 NEVER triggers response actions (LogOnly unconditionally). Authorized Tier1 responses act immediately; Tier2 never acts. Fail-closed. No string-built JSON. DI required everywhere.
3. **Git Rules**: Follow `.agents/rules/git-rules.md` and `.kiro/steering/git-rules.md`. NEVER type manual `git push --force` or `--force-with-lease`. The sanctioned release path is `push.ps1`.
4. **Architecture & Design**: See `docs/design.md`, `docs/requirements.md`, and `docs/constraints.md`.


## VPN coexistence (no bundled VPN)

GVPN is a **separate project** (`D:\Gorstak\GVPN`, its own repo and installer). Sentinel does not build,
bundle, install, start or control any VPN, and has no VPN response action. Setup only migrates a copy
that older releases bundled in `{app}\GVPN` (path-checked, so a standalone GVPN is never touched).

Sentinel must work correctly next to GVPN or any other VPN client:
- Classify tunnel interfaces with `VpnTunnelClassifier` (IANA type or driver description, never the
  user-renamable connection name). Tunnel routes/gateways/adapters are Tier2 context and are tagged
  (`TunnelAdapter=true`) so they never become LAN MitM legs.
- `VpnTunnelLeakMonitor` reports tunnel state and bypasses (IPv4 route, IPv6, resolvers), observe-only.
- Never trust a VPN client's own log (`vpn.log` is user-writable) for any allow/suppress decision.
- `ResponseAction.VpnShieldUp` is an `[Obsolete]` numeric slot kept for serialized-log stability. Do not use it.
