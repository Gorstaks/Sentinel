# Runtime follow-up, November 2

The supplied capture records 3.5.7 starting on November 1 at 16:35:47 UTC and
continuing through November 2 at approximately 05:06 UTC. The latest metrics identify
3.5.7. The supplied fatal-crash file is byte-for-byte identical to the earlier capture;
its two historical startup cancellations are not new failures after this upgrade.

After the recorded 3.5.7 start, the event file contains 2,256 detections, all with
NotRequested/log-only response receipts. There are no recorded confirmed chains,
composites or attempted containment in that interval. This does not test the new
Tier1 pack path. The two new reported RAT marker observations reference compiled
Sentinel test assemblies containing deliberate marker fixtures; they do not establish
infection or a compromised installer.

The latest ETW snapshot reports 6,643 application dispatch losses, all in the File
lane; ProcessImage, Registry and Other report zero lane drops. File losses increase
throughout the capture. Native event/buffer loss counters are zero, which does not
erase the application losses. Protected Threat Intelligence provider access is still
denied by Windows. These are distinct limitations, not interchangeable indicators.

The file walk reports 45 unreadable paths and a scheduled retry. Its three visible
examples are locked operating-system files; those examples do not explain the other
42 failures or establish full disk coverage. The service working set rises from about
62 MB to 3,210 MB and handles from 529 to 8,670 over about 12.5 hours. This warrants
Windows resource profiling; the capture alone cannot identify the allocation owner.

Both supplied daily audit chains pass sequence, previous-hash and payload-hash
verification (451 and 126 records). No independently retained trusted checkpoint was
provided, so this does not prove origin or rule out complete rewriting/truncation.
Original uploaded logs remain unchanged.

## Follow-up changes

- Dispose temporary Process instances after ETW name lookups, including exceptions.
  This fixes a resource-lifetime issue found in source, without claiming it explains
  the entire observed memory/handle growth.
- Write a structured file_scan_coverage record when a walk finishes, including the
  incomplete-path count, up to 64 bounded path/error examples, sample-truncation flag,
  evaluated/cached counts and elapsed time. Keep the dashboard's brief three-example
  summary and incomplete health state. Include coverage records in the daily ledger.

These changes do not replay lost file events, bypass Windows provider protection,
make unreadable files clean, or establish resolution of sustained resource growth.
Windows load/recovery validation and a fresh installed-host capture remain necessary.

Local validation: nine solution projects cross-build with zero warnings/errors;
128 selected portable regressions against the production Core assembly pass,
including bounded dispatcher ordering, file-lane isolation and partial-scan health.
The Framework logger integration tests remain Windows-only checks; the Linux runner
cannot load its Framework ACL API. Version 3.5.8 is prepared for Windows CI;
cross-builds and portable tests do not establish installed-host readiness.
