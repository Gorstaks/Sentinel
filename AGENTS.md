# Sentinel Agent Guidelines

This repository follows strict architectural, workflow, and security rules:

1. **Workflow & Versioning**: Follow `.agents/rules/workflow.md` and `.kiro/steering/workflow.md`. Versions are strictly `MAJOR.MINOR.PATCH`, bumped by exactly one patch per release. Single source of truth is `version.txt`. Never jump versions. Releases use `installer/release.ps1` and `D:\Gorstak\push.ps1 -ProjectFilter sentinel`.
2. **Hard Constraints**: Follow `.agents/rules/constraints.md` and `.kiro/steering/constraints.md`. Userland only (no kernel drivers, no rootkits). Tier2 NEVER triggers response actions (LogOnly unconditionally). Authorized Tier1 responses act immediately; Tier2 never acts. Fail-closed. No string-built JSON. DI required everywhere.
3. **Git Rules**: Follow `.agents/rules/git-rules.md` and `.kiro/steering/git-rules.md`. NEVER type manual `git push --force` or `--force-with-lease`. The sanctioned release path is `push.ps1`.
4. **Architecture & Design**: See `docs/design.md`, `docs/requirements.md`, and `docs/constraints.md`.


## Modules

### GVPN - Global VPN Manager

**Location**: `modules/GVPN/`

**Purpose**: Lightweight Windows VPN management module providing automatic L2TP/IPSec connection creation, monitoring, and auto-reconnection with kill switch.

**Build**: `modules/GVPN/build.ps1` → `bin/Release/GVPN.exe` (31 KB)

**Features**:
- Automatic VPN setup on first run (admin required once)
- Auto-reconnection with intelligent failover (5-server cascade)
- Kill switch for immediate traffic blocking
- System tray integration with one-click controls
- Comprehensive logging to `vpn.log`

**Integration Points**:
- Agent can deploy GVPN.exe to endpoints
- Monitor VPN status via `vpn.log` log aggregation
- Trigger VPN connections based on Sentinel policies
- Activate kill switch on threat detection

**Architecture**: Userland Windows Forms app, no kernel/persistence. Transparent in Task Manager. Respects Sentinel's hard constraints (fail-closed, LogOnly on uncertain signals).

**See Also**: `modules/GVPN/MODULE.md` for full documentation and Sentinel integration details.
