# OpenVPN Installer Helper for GVPN
# This script attempts to download and install OpenVPN
# Run with: powershell -ExecutionPolicy Bypass -File install-openvpn.ps1

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   OpenVPN Installer for GVPN         " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if already installed
$OpenVpnPath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
if ((Test-Path $OpenVpnPath) -and -not $Force) {
    Write-Host "OpenVPN is already installed at:" -ForegroundColor Green
    Write-Host "  $OpenVpnPath" -ForegroundColor Green
    exit 0
}

$TempDir = "$env:TEMP\gvpn-openvpn-install"
$MsiPath = "$TempDir\OpenVPN-2.6.8-amd64.msi"

# Create temp directory
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "`nAttempting to download OpenVPN 2.6.8..."

# Try multiple download methods
$DownloadUrl = "https://github.com/OpenVPN/openvpn-releases/releases/download/v2.6.8/OpenVPN-2.6.8-I601-amd64.msi"
$success = $false

# Method 1: PowerShell WebClient with TLS 1.2
Write-Host "  Method 1: PowerShell WebClient..." -ForegroundColor Yellow
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (New-Object Net.WebClient).DownloadFile($DownloadUrl, $MsiPath)
    $success = $true
    Write-Host "  ✓ Download succeeded" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed: $_" -ForegroundColor Red
}

# Method 2: curl
if (-not $success) {
    Write-Host "  Method 2: curl.exe..." -ForegroundColor Yellow
    $curlPath = "C:\Windows\System32\curl.exe"
    if (Test-Path $curlPath) {
        try {
            & $curlPath -L -o $MsiPath $DownloadUrl
            if ($LASTEXITCODE -eq 0 -and (Test-Path $MsiPath) -and ((Get-Item $MsiPath).Length -gt 1MB)) {
                $success = $true
                Write-Host "  ✓ Download succeeded" -ForegroundColor Green
            }
        } catch {
            Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        }
    }
}

# Method 3: Invoke-WebRequest (slower but more compatible)
if (-not $success) {
    Write-Host "  Method 3: Invoke-WebRequest..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $MsiPath -TimeoutSec 300 -UseBasicParsing
        if ((Test-Path $MsiPath) -and ((Get-Item $MsiPath).Length -gt 1MB)) {
            $success = $true
            Write-Host "  ✓ Download succeeded" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
    }
}

if (-not $success) {
    Write-Host "`n✗ Download failed with all methods" -ForegroundColor Red
    Write-Host "`nManual installation:" -ForegroundColor Yellow
    Write-Host "  1. Visit: https://openvpn.net/community-downloads/" -ForegroundColor Cyan
    Write-Host "  2. Download OpenVPN 2.6.8 (Windows, x64)" -ForegroundColor Cyan
    Write-Host "  3. Run the installer" -ForegroundColor Cyan
    Write-Host "  4. Re-launch GVPN" -ForegroundColor Cyan
    exit 1
}

# Install OpenVPN
Write-Host "`nInstalling OpenVPN from $MsiPath..."
try {
    $logPath = "$TempDir\OpenVPN-install.log"
    $process = Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /passive /norestart /l*v `"$logPath`"" -NoNewWindow -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Host "✓ Installation succeeded" -ForegroundColor Green
        
        # Verify installation
        Start-Sleep -Seconds 2
        if (Test-Path $OpenVpnPath) {
            Write-Host "`n========================================" -ForegroundColor Green
            Write-Host "   OpenVPN installed successfully!      " -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Green
            Write-Host "`nOpenVPN is ready. GVPN will now be able to connect." -ForegroundColor Green
            Write-Host "`nRestart GVPN to complete the setup." -ForegroundColor Yellow
            
            # Clean up
            Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            exit 0
        } else {
            Write-Host "✗ Installation completed but OpenVPN not found at expected location" -ForegroundColor Yellow
            Write-Host "  Check log: $logPath" -ForegroundColor Gray
        }
    } else {
        Write-Host "✗ Installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
        Write-Host "  Check log: $logPath" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ Installation error: $_" -ForegroundColor Red
}

Write-Host "`nManual installation:" -ForegroundColor Yellow
Write-Host "  1. Visit: https://openvpn.net/community-downloads/" -ForegroundColor Cyan
Write-Host "  2. Download OpenVPN 2.6.8 (Windows, x64)" -ForegroundColor Cyan
Write-Host "  3. Run the installer" -ForegroundColor Cyan
Write-Host "  4. Re-launch GVPN" -ForegroundColor Cyan
exit 1
