[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SentinelDirectory)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'NanoAV retirement requires the administrator installer context' }
$logDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Sentinel\Logs'
for ($parent = [IO.DirectoryInfo]::new($logDirectory); $null -ne $parent; $parent = $parent.Parent) {
    if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Migration log directory traverses a reparse point' }
}
[IO.Directory]::CreateDirectory($logDirectory) | Out-Null
Start-Transcript -Path (Join-Path $logDirectory 'nanoav-retirement.log') -Append | Out-Null
# Retirement only: never execute the old DLL, trust its PID file, import its verdicts,
# or remove quarantine, backups, databases or logs.
# Use OS known folders, not caller-controlled ProgramFiles environment overrides.
$roots = @($SentinelDirectory, (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Sentinel'))
$x86 = [Environment]::GetFolderPath('ProgramFilesX86')
if ($x86) { $roots += Join-Path $x86 'Sentinel' }
$executables = @($roots | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $_ 'NanoAV.exe')) } | Select-Object -Unique)
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NanoAV'
$libraries = @($roots | ForEach-Object { Join-Path $_ 'NanoAV.dll' })
function Binary-Hash([string]$path) {
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
$bundledHashes = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($executables) + @($libraries)) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { $null = $bundledHashes.Add((Binary-Hash $path)) }
}
$dataDll = Join-Path $data 'NanoAV.dll'
$ownsDataDll = $false
if (Test-Path -LiteralPath $dataDll -PathType Leaf) {
    $ownsDataDll = $bundledHashes.Contains((Binary-Hash $dataDll))
    if ($ownsDataDll) { $libraries += $dataDll }
    elseif ($bundledHashes.Count -gt 0) { throw 'NanoAV data DLL differs from bundled payloads; origin is unverified. Runtime/recovery data preserved; review before retrying migration.' }
    else { Write-Warning 'Preserved a standalone NanoAV data DLL with no bundled payload ownership evidence' }
}
function Same-Path([string]$left, [string]$right) {
    try { return [IO.Path]::GetFullPath($left).Equals([IO.Path]::GetFullPath($right), [StringComparison]::OrdinalIgnoreCase) }
    catch { return $false }
}
function Owned-Executable([string]$value) {
    if (-not $value) { return $false }
    foreach ($path in $executables) { if (Same-Path ($value.Trim('"')) $path) { return $true } }
    return $false
}
function Owned-RunCommand([string]$command) {
    if (-not $command -or $command.Length -gt 32768) { return $false }
    foreach ($path in $executables) {
        if ($command.Trim().Equals(('"' + $path + '"'), [StringComparison]::OrdinalIgnoreCase) -or
            $command.Trim().Equals($path, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($path in $libraries) {
        $pattern = '^(?:"[^"]*\\rundll32\.exe"|rundll32\.exe)\s+"' + [regex]::Escape($path) + '",DllMain\s*$'
        if ($command -match $pattern) { return $true }
    }
    return $false
}
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class NanoRetirementProcess {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessCritical(IntPtr h, out bool critical);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static bool StopOwned(int pid, string[] expected) {
        IntPtr h = OpenProcess(0x1000 | 0x100000 | 1, false, pid);
        if (h == IntPtr.Zero) {
            int error = Marshal.GetLastWin32Error();
            if (error == 87) return false;
            throw new Win32Exception(error, "Cannot inspect NanoAV retirement target");
        }
        try {
            var path = new StringBuilder(32768); int size = path.Capacity;
            if (!QueryFullProcessImageName(h, 0, path, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            bool owned = false;
            foreach (string candidate in expected)
                if (String.Equals(Path.GetFullPath(path.ToString()), Path.GetFullPath(candidate), StringComparison.OrdinalIgnoreCase)) owned = true;
            if (!owned) return false;
            bool critical;
            if (!IsProcessCritical(h, out critical) || critical) throw new InvalidOperationException("Refusing critical/unknown NanoAV target");
            // Identity and termination use the same handle; PID reuse cannot select another process.
            if (!TerminateProcess(h, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (WaitForSingleObject(h, 5000) != 0) throw new TimeoutException("NanoAV did not exit");
            return true;
        } finally { CloseHandle(h); }
    }
}
'@
# Remove only a task whose every action targets an owned bundled executable.
$task = Get-ScheduledTask -TaskName 'NanoAV' -TaskPath '\' -ErrorAction SilentlyContinue
if ($task) {
    $actions = @($task.Actions)
    if ($actions.Count -gt 0 -and @($actions | Where-Object { -not (Owned-Executable $_.Execute) }).Count -eq 0) {
        Unregister-ScheduledTask -TaskName 'NanoAV' -TaskPath '\' -Confirm:$false
        Write-Output 'Removed bundled NanoAV startup task'
    } else { Write-Warning 'Preserved an unrelated task named NanoAV' }
}
foreach ($process in @(Get-Process -Name NanoAV -ErrorAction SilentlyContinue)) {
    try {
        Write-Output ('Attempting pinned bundled-runtime retirement for candidate PID ' + $process.Id + '; unrelated image paths will be preserved')
        if ([NanoRetirementProcess]::StopOwned($process.Id, [string[]]$executables)) { Write-Output ('Stopped bundled NanoAV PID ' + $process.Id) }
    } finally { $process.Dispose() }
}
# Loaded user hives include the installer identity and other logged-on users. Do not
# load offline profiles or remove a same-name autorun pointing to a standalone install.
foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::Users)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        try {
            $prefixes = @('')
            if ($hive -eq [Microsoft.Win32.RegistryHive]::Users) {
                $prefixes = @($base.GetSubKeyNames() | Where-Object { $_ -match '^S-1-(?:5-21|12-1)-[0-9-]+$' } | ForEach-Object { $_ + '\' })
            }
            foreach ($prefix in $prefixes) {
                $run = $base.OpenSubKey(($prefix + 'Software\Microsoft\Windows\CurrentVersion\Run'), $true)
                if ($run) {
                    try { if (Owned-RunCommand ([string]$run.GetValue('NanoAV', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))) { $run.DeleteValue('NanoAV', $false) } }
                    finally { $run.Dispose() }
                }
                $classesPath = $prefix + 'Software\Classes'
                $classes = $base.OpenSubKey($classesPath, $true)
                if (-not $classes) { continue }
                try {
                    $id = '{A0B8E5D2-4F3C-4A1B-9C8F-7E6D5A4B3C2D}'
                    $server = $classes.OpenSubKey(('CLSID\' + $id + '\InprocServer32'))
                    $owned = $false
                    if ($server) {
                        try {
                            $locations = @($server.GetValue('CodeBase'))
                            foreach ($version in $server.GetSubKeyNames()) {
                                $key = $server.OpenSubKey($version)
                                try { $locations += $key.GetValue('CodeBase') } finally { $key.Dispose() }
                            }
                            foreach ($location in $locations) {
                                $uri = $null
                                if ([Uri]::TryCreate([string]$location, [UriKind]::Absolute, [ref]$uri) -and $uri.IsFile) {
                                    foreach ($dll in $libraries) { if (Same-Path $uri.LocalPath $dll) { $owned = $true } }
                                }
                            }
                        } finally { $server.Dispose() }
                    }
                    if ($owned) {
                        $classes.DeleteSubKeyTree(('CLSID\' + $id), $false)
                        $prog = $classes.OpenSubKey('NanoAV.Server\CLSID')
                        if ($prog) {
                            try { $matches = ([string]$prog.GetValue('')).Trim('{}').Equals($id.Trim('{}'), [StringComparison]::OrdinalIgnoreCase) }
                            finally { $prog.Dispose() }
                            if ($matches) { $classes.DeleteSubKeyTree('NanoAV.Server', $false) }
                        }
                    }
                } finally { $classes.Dispose() }
            }
        } finally { $base.Dispose() }
    }
}
$runtimePaths = @($executables) + @($libraries)
if ($ownsDataDll) { $runtimePaths += Join-Path $data '.installed' }
foreach ($path in $runtimePaths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        catch { throw "NanoAV runtime file remains locked; close its host and retry Setup. Preserved recovery data. Path: $path" }
    }
}
Write-Output 'NanoAV retirement complete; quarantine, backup, logs and database preserved and not imported'

Stop-Transcript | Out-Null
