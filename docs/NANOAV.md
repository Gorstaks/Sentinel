# NanoAV integration — current 3.4.6 behavior

NanoAV's useful coverage now runs inside Sentinel's managed pipeline. The original executable/DLL is **not loaded or launched**. This is a native port of selected capabilities, not execution of the unchanged upstream engine. The standalone source folder `modules/NanoAV` and its provenance manifest were removed in 3.7.0; git history keeps them. Do not run the archived standalone program expecting the fixes below.

- Service-only bounded HTTPS reputation: MalwareBazaar authenticated recent SHA256 API (owner-provided key, latest 100 samples; absent key explicitly Unknown) and CIRCL exact known-file lookups. Missing/failed/invalid results are Unknown. No file uploads, filenames, paths, webhooks or legacy database import. Known-file context never exempts a running process.
- Expanded native/script/macro-document coverage, PE-header checks regardless of an unknown extension, Created/Renamed/Changed watching, bounded realtime concurrency and periodic six-hour full re-evaluation after the prior walk completes. No completion guarantee for unreadable files or interrupted walks.
- Previously unregistered raw socket-shell coverage is registered in Service and Agent. Complete supported socket-to-shell behavior is Tier1 without a composite wait; a port, process name, unsigned DLL, suspicious IP prefix or routine encoded command cannot kill. Supported patterns and limitations are tested; this is not complete shell-language analysis.
- An exact current malware-feed match can invoke a separate compiled **file** policy: pinned file-object hash recheck, accepted durable audit, bounded encrypted recovery copy and delete-pending disposition on that same handle. No process kill, ownership seizure or deletion of a future pathname replacement. Refuse protected OS/self paths, reparse/redirection, multiple links, empty or >16 MiB files. Ordinary byte-range locking is not an atomic guarantee against existing writable mappings. Mapped/open files can defer removal; results say PartiallyCompleted, not proven neutralization.
- Static/ML/legacy ADS findings remain context only. Old Safe ADS no longer grants process trust. Scanner no longer writes ADS, avoiding Changed-event feedback. The analysis cache is bounded.

**3.6.8:** the one-time legacy-runtime retirement step (`installer/retire-nanoav.ps1`) is no longer part of the installer, and its CI migration smoke (`WindowsNanoAvMigrationSmoke.ps1`) is removed. NanoAV coverage is integrated in Sentinel.Core; there is no separate NanoAV runtime to retire. The paragraph below describes the earlier migration.

Earlier upgrades ran `installer/retire-nanoav.ps1` before replacing Sentinel: remove owned startup entries, stop only an exact bundled image through one pinned noncritical process handle, and remove old runtime copies. The ProgramData DLL must hash-match a bundled payload; ambiguous origin refuses migration before stopping runtime. Never use NanoAV_pids.txt as authority. Preserve `%ProgramData%\NanoAV\Quarantine`, Backup, logs and known_files.db; do not import its poisoned unsigned-file verdicts. A locked foreign host/old DLL aborts the retirement script with a log instead of killing Explorer. The installer preserves Kiro's best-effort upgrade behavior and continues after retirement failure; the old companion can therefore remain active. Installation success does not certify companion removal. Check `%ProgramData%\Sentinel\Logs\nanoav-retirement.log` and resolve any failure. Unrelated same-name processes/autoruns remain intact. Native disposable migration validation is mandatory in Build and Release.

The supplied STO crash/debug logs do not identify the faulting component or establish that NanoAV, Sentinel or MSI Afterburner caused the crash. The separate confirmed unsigned-cache bug is sufficient reason not to keep the old autonomous engine active.

## Historical 3.3.8 companion design (superseded)

# Independent NanoAV module (3.3.8)

NanoAV is packaged as its own `NanoAV.exe` and COM `NanoAV.dll`, built from the supplied NanoAV-main.zip. It does not reference Sentinel.Core or call Sentinel's tier, scoring or response-policy pipeline. The installer launches its original bootstrap after installing Sentinel. Its original COM registration, per-user Run key, online requests, caches, heuristics, quarantine, deletion and response decisions remain its own.

On installation/upgrade, remove only NanoAV's `.installed` bootstrap marker so the unchanged bootstrap refreshes its ProgramData DLL copy and current-user startup registration from the co-installed, coexistence-patched EXE. Preserve its configuration, database, logs, backups and quarantine. An already running older copy is not retroactively patched; the upgrade must complete and its startup path must point to the integrated copy.

## Exact source scope

Archive SHA-256: `232f33f15dba196eb462b047c843266c9506aba25e59c19cb74191b35b102ed8`.

Of 22 supplied files, 17 are byte-identical. Five have only coexistence call-site edits: `NanoC2Engine.cs`, `NanoFileScanner.cs`, `NanoMemoryScanner.cs`, `NanoPidRegistry.cs` and `NanoThreatAnalysis.cs` (21 inserted / 6 removed lines). The added `SentinelCoexistence.cs` helper (with shared `SentinelCoexistencePaths.cs` path logic) protects the resolved Sentinel installation and ProgramData/Sentinel files, checks the pinned Process object before individual kills, and skips a module-name-wide taskkill fallback that could include Sentinel. Unresolvable target identity is protected because it cannot safely be distinguished from Sentinel. Other NanoAV rules/settings are not rewritten. The original build script, README, config, entry point and assembly metadata are unchanged. The removed `UPSTREAM.json` recorded original and integrated per-file hashes.

Build/installer wiring, tests and Sentinel-side exclusions are outside the supplied source. Sentinel recognizes NanoAV in its own installation directory; a copied name elsewhere is not exempt. The original bootstrap's `%ProgramData%\NanoAV\NanoAV.dll` copy is exempt from Sentinel file scanning/quarantine only when its SHA-256 equals the co-installed EXE. Memory inspection and DLL remediation skip the co-installed NanoAV image. NanoAV is not included in Sentinel's own offline executable firewall blocks.

## Online and privacy boundary

This is an explicit exception to the offline product boundary: NanoAV retains CIRCL/Cymru/MalwareBazaar calls, reverse DNS, optional webhook code and its own firewall actions as supplied. These can disclose hashes, public IP/name lookups and, if separately configured, alert details. Sentinel Core/Service/Agent transports remain offline. No credentials are invented or embedded by this integration. The supplied MalwareBazaar key is empty; provider authentication, endpoints and availability are not certified. NanoAV logs/cache/quarantine remain under `%ProgramData%\NanoAV` and are not Sentinel's verified response receipts.

## Validation and retained limitations

Build from Command Prompt with `installer\build.bat` (or `build` inside the installer directory), or from PowerShell with `installer/build.ps1`. The batch entry point delegates to the same PowerShell implementation; both publish NanoAV before invoking Inno Setup. `build -StampOnly` prepares metadata without publishing or compiling an installer.

The full solution cross-build and separate EXE/COM DLL publication are checked without executing the scanner. Eighteen portable coexistence boundary cases pass; the installed-path Windows case is explicitly skipped on Linux and remains in the Windows test suite. Desktop-monitor behavior is unchanged; see [privacy review](PRIVACY_REVIEW_2026-10-21.md).

Preserving the supplied program also preserves its defects. Its process-start callback can request termination without first proving a threat; the unsigned-file cache can later drive a known-bad deletion. Its Main returns after starting monitoring, and the inspected startup does not schedule the C2/reverse-shell polling methods. These paths were not repaired because the requested source changes were limited to coexistence. Packaging does not establish that NanoAV remains resident, that every advertised engine runs, or that its live providers work. Validate startup/autorun, actual lifetime, feed responses, mutual process/file protection, upgrade and uninstall on a disposable Windows machine before relying on it. No detection-quality or mutual-protection guarantee against races or administrator tampering is claimed.

The supplied README attributes NanoAV to Gorstak and declares MIT licensing; that README and original notices are preserved. NanoAV keeps its original 1.0.0.0 assembly metadata inside the Sentinel 3.3.8 package.
