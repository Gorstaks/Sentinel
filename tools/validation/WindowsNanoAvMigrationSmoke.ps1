$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable GitHub-hosted Windows runner required' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root = Join-Path $env:RUNNER_TEMP ('SentinelNanoMigration_' + [Guid]::NewGuid().ToString('N'))
$owned = Join-Path $root 'Sentinel'
$foreign = Join-Path $root 'Unrelated'
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NanoAV'
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $data) { throw 'Refusing to overwrite pre-existing NanoAV recovery data' }
if (Get-ItemProperty -Path $run -Name NanoAV -ErrorAction SilentlyContinue) { throw 'Pre-existing NanoAV autorun' }
$taskService = New-Object -ComObject 'Schedule.Service'
$taskService.Connect(); $folder = $taskService.GetFolder('\')
$existing = @($folder.GetTasks(0) | Where-Object Name -eq 'NanoAV')
if ($existing.Count) { throw 'Pre-existing NanoAV task' }
$ownedProcess = $null; $foreignProcess = $null
try {
    New-Item -ItemType Directory -Path $owned,$foreign,(Join-Path $data 'Quarantine'),(Join-Path $data 'Backup') -Force | Out-Null
    $source = 'public class InertNanoMigrationFixture { public static void Main() { System.Threading.Thread.Sleep(120000); } }'
    Add-Type -TypeDefinition $source -OutputAssembly (Join-Path $owned 'NanoAV.exe') -OutputType ConsoleApplication
    Copy-Item (Join-Path $owned 'NanoAV.exe') (Join-Path $foreign 'NanoAV.exe')
    Copy-Item (Join-Path $owned 'NanoAV.exe') (Join-Path $data 'NanoAV.dll')
    Set-Content (Join-Path $data '.installed') 'inert fixture'
    Set-Content (Join-Path $data 'known_files.db') 'preserve poisoned legacy database; do not import'
    Set-Content (Join-Path $data 'NanoAV.log') 'preserve log'
    Set-Content (Join-Path $data 'Quarantine\inert.bin') 'preserve quarantined bytes'
    Set-Content (Join-Path $data 'Backup\inert.bin') 'preserve backup bytes'
    # A clean GitHub-hosted profile may not yet have the Run key; Set-ItemProperty sets a
    # value but requires the key to exist. Create it (idempotent) before writing the autorun.
    if (-not (Test-Path $run)) { New-Item -Path $run -Force | Out-Null }
    Set-ItemProperty -Path $run -Name NanoAV -Value ('"' + (Join-Path $owned 'NanoAV.exe') + '"')
    $task = $taskService.NewTask(0)
    $task.Actions.Create(0).Path = Join-Path $owned 'NanoAV.exe'
    $task.Principal.UserId = 'SYSTEM'; $task.Principal.LogonType = 5; $task.Principal.RunLevel = 1
    $null = $folder.RegisterTaskDefinition('NanoAV', $task, 6, 'SYSTEM', $null, 5)
    $ownedProcess = Start-Process (Join-Path $owned 'NanoAV.exe') -PassThru
    $foreignProcess = Start-Process (Join-Path $foreign 'NanoAV.exe') -PassThru
    Set-Content (Join-Path $data 'NanoAV_pids.txt') $foreignProcess.Id # A poisoned PID file must not select a target.
    Set-Content (Join-Path $data 'NanoAV.dll') 'Unverified standalone bytes must not be retired by name'
    $negative = Start-Process powershell.exe -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $repo 'installer\retire-nanoav.ps1') + '"'),'-SentinelDirectory',('"' + $owned + '"')) -PassThru -Wait -RedirectStandardError (Join-Path $root 'negative.err') -RedirectStandardOutput (Join-Path $root 'negative.out')
    if ($negative.ExitCode -eq 0) { throw 'Unverified data DLL ownership was accepted' }
    $negative.Dispose(); $ownedProcess.Refresh()
    if ($ownedProcess.HasExited -or -not (Test-Path (Join-Path $data 'NanoAV.dll'))) { throw 'Ambiguous migration mutated runtime state' }
    Copy-Item (Join-Path $owned 'NanoAV.exe') (Join-Path $data 'NanoAV.dll') -Force
    & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $repo 'installer\retire-nanoav.ps1') -SentinelDirectory $owned
    if ($LASTEXITCODE -ne 0) { throw 'Migration failed' }
    $ownedProcess.Refresh(); $foreignProcess.Refresh()
    if (-not $ownedProcess.HasExited) { throw 'Bundled companion still running' }
    if ($foreignProcess.HasExited) { throw 'Unrelated same-name process was terminated' }
    if (Test-Path (Join-Path $owned 'NanoAV.exe')) { throw 'Old bundled runtime remains' }
    if (Get-ItemProperty -Path $run -Name NanoAV -ErrorAction SilentlyContinue) { throw 'Bundled autorun remains' }
    if (@($folder.GetTasks(0) | Where-Object Name -eq 'NanoAV').Count) { throw 'Bundled startup task remains' }
    foreach ($file in @('known_files.db','NanoAV.log','NanoAV_pids.txt','Quarantine\inert.bin','Backup\inert.bin')) {
        if (-not (Test-Path (Join-Path $data $file))) { throw ('Lost recovery data: ' + $file) }
    }
    # A same-name autorun belonging to an unrelated standalone installation must survive retries.
    Set-ItemProperty -Path $run -Name NanoAV -Value ('"' + (Join-Path $foreign 'NanoAV.exe') + '"')
    & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $repo 'installer\retire-nanoav.ps1') -SentinelDirectory $owned
    if ($LASTEXITCODE -ne 0) { throw 'Repeated migration failed' }
    if (-not (Get-ItemProperty -Path $run -Name NanoAV -ErrorAction SilentlyContinue)) { throw 'Unrelated autorun was removed' }
    Write-Host 'PASS: native NanoAV migration, poisoned PID refusal, unrelated process/autorun preservation, recovery data and repeated migration'
} finally {
    foreach ($process in @($ownedProcess,$foreignProcess)) {
        if ($process) { try { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null } } finally { $process.Dispose() } }
    }
    Remove-ItemProperty -Path $run -Name NanoAV -ErrorAction SilentlyContinue
    try { $folder.DeleteTask('NanoAV', 0) } catch { Write-Verbose $_ }
    Remove-Item $data,$root -Recurse -Force -ErrorAction SilentlyContinue
}
