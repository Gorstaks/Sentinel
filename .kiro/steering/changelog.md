---
inclusion: auto
name: Sentinel Changelog
description: Full Sentinel version history and release notes. Load this when the request involves project history, when a file/feature/module/CI step/monitor is missing, was added, integrated, retired or changed, what shipped in a given version, release notes, or "why did we change X". Load it BEFORE restoring, re-adding or removing any component.
---

# Sentinel - Changelog

The complete, canonical version history and release notes for Sentinel live in
`docs/CHANGELOG.md`. It records what changed in each version (features, monitors, CVE
coverage, behavior/posture changes, integrations, retirements, fixes). Treat it as the source
of truth when answering questions about when or why something changed.

Rules (see also `project-state.md`):

- Before treating anything absent as a bug, search this file for it. Integrations and
  retirements (for example NanoAV integrated in 3.4.5, GVPN split out in 3.6.8) are recorded here.
- Add a section for every release, headed exactly `## [MAJOR.MINOR.PATCH] - YYYY-MM-DD`, newest
  first. Record removals and CI changes as well as features and fixes.

#[[file:../../docs/CHANGELOG.md]]
