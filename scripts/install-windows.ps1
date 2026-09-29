<#
.SYNOPSIS
    Installs jocky.exe on Windows, registers a firewall inbound rule, and
    optionally adds it to the system PATH.

.DESCRIPTION
    Run this script once after extracting the JOCKY Windows ZIP package.
    It will:
      1. Copy jocky.exe to %ProgramFiles%\JOCKY\
      2. Add that directory to the system PATH (permanent, machine-wide)
      3. Create a Windows Firewall inbound rule so jocky.exe can accept
         inbound TCP connections without being blocked by Windows Defender
         Firewall (required if jocky is used as a local language server or
         any network-accessible service)
      4. Verify the installation

    Must be run as Administrator.

.PARAMETER InstallDir
    Destination directory. Default: C:\Program Files\JOCKY

.PARAMETER SkipFirewall
    Skip creating the Windows Firewall inbound rule.

.PARAMETER SkipPath
    Skip adding InstallDir to the system PATH.

.PARAMETER Uninstall
    Remove jocky.exe, the PATH entry, and the firewall rule.

.EXAMPLE
    # Normal install
    powershell.exe -ExecutionPolicy Bypass -File install-windows.ps1

.EXAMPLE
    # Uninstall
    powershell.exe -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDir   = "$env:ProgramFiles\JOCKY",
    [switch] $SkipFirewall,
    [switch] $SkipPath,
    [switch] $Uninstall
)

$ErrorActionPreference = "Stop"
$FW_RULE_NAME = "JOCKY - jocky.exe inbound (TCP)"

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal]
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Right-click and select 'Run as administrator'."
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($Uninstall) {
    Write-Host " JOCKY Windows Uninstaller" -ForegroundColor Cyan
} else {
    Write-Host " JOCKY Windows Installer" -ForegroundColor Cyan
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# UNINSTALL
if ($Uninstall) {
    $existing = Get-NetFirewallRule -DisplayName $FW_RULE_NAME -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $FW_RULE_NAME
        Write-Host "  [OK] Firewall rule removed." -ForegroundColor Green
    } else {
        Write-Host "  [--] No firewall rule found (already removed)." -ForegroundColor Yellow
    }

    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -like "*$InstallDir*") {
        $newPath = ($machinePath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        Write-Host "  [OK] Removed '$InstallDir' from system PATH." -ForegroundColor Green
    } else {
        Write-Host "  [--] '$InstallDir' was not in system PATH." -ForegroundColor Yellow
    }

    $exePath = Join-Path $InstallDir "jocky.exe"
    if (Test-Path $exePath) {
        Remove-Item $exePath -Force
        Write-Host "  [OK] Removed jocky.exe from '$InstallDir'." -ForegroundColor Green
    }
    if ((Test-Path $InstallDir) -and -not (Get-ChildItem $InstallDir)) {
        Remove-Item $InstallDir -Force
        Write-Host "  [OK] Removed empty install directory." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Uninstall complete." -ForegroundColor Green
    exit 0
}

# INSTALL

# Locate jocky.exe next to this script, or in the current directory
$scriptDir  = $PSScriptRoot
$candidates = @(
    (Join-Path $scriptDir "jocky.exe"),
    (Join-Path (Get-Location) "jocky.exe"),
    (Join-Path $scriptDir "..\target\release\jocky.exe")
)
$sourceExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $sourceExe) {
    Write-Error "Cannot find jocky.exe. Place install-windows.ps1 in the same folder as jocky.exe and try again."
    exit 1
}
$sourceExe = (Resolve-Path $sourceExe).Path
Write-Host "  Source: $sourceExe"

# 1. Copy binary
Write-Host ""
Write-Host "  [1/3] Installing to '$InstallDir'..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$destExe = Join-Path $InstallDir "jocky.exe"
Copy-Item -Path $sourceExe -Destination $destExe -Force
Write-Host "  [OK] jocky.exe copied to '$destExe'." -ForegroundColor Green

# 2. PATH
if (-not $SkipPath) {
    Write-Host ""
    Write-Host "  [2/3] Updating system PATH..."
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
        Write-Host "  [OK] Added '$InstallDir' to system PATH." -ForegroundColor Green
        Write-Host "       Restart your terminal (or run: refreshenv) to use 'jocky' everywhere." -ForegroundColor Yellow
    } else {
        Write-Host "  [--] '$InstallDir' is already in system PATH." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [2/3] Skipping PATH update (-SkipPath specified)."
}

# 3. Windows Firewall inbound rule
if (-not $SkipFirewall) {
    Write-Host ""
    Write-Host "  [3/3] Registering Windows Firewall inbound rule..."

    $stale = Get-NetFirewallRule -DisplayName $FW_RULE_NAME -ErrorAction SilentlyContinue
    if ($stale) {
        Remove-NetFirewallRule -DisplayName $FW_RULE_NAME
        Write-Host "  [--] Removed stale existing firewall rule." -ForegroundColor Yellow
    }

    New-NetFirewallRule `
        -DisplayName  $FW_RULE_NAME `
        -Description  "Allows inbound TCP connections to jocky.exe (JOCKY compiler / language server)." `
        -Direction    Inbound `
        -Protocol     TCP `
        -Action       Allow `
        -Program      $destExe `
        -Profile      Any `
        -Enabled      True | Out-Null

    Write-Host "  [OK] Firewall inbound rule created:" -ForegroundColor Green
    Write-Host "       Name:    $FW_RULE_NAME"
    Write-Host "       Program: $destExe"
    Write-Host "       Profile: Domain, Private, Public"
} else {
    Write-Host "  [3/3] Skipping firewall rule (-SkipFirewall specified)."
}

# Verification
Write-Host ""
Write-Host "------------------------------------------------------------"
Write-Host "Verification"
Write-Host "------------------------------------------------------------"

$installed = Get-Item $destExe
Write-Host "  Path:    $($installed.FullName)"
Write-Host "  Size:    $($installed.Length) bytes"
Write-Host "  SHA-256: $((Get-FileHash -Path $destExe -Algorithm SHA256).Hash)"

if (-not $SkipFirewall) {
    $rule = Get-NetFirewallRule -DisplayName $FW_RULE_NAME -ErrorAction SilentlyContinue
    if ($rule) {
        Write-Host "  FW Rule: $($rule.DisplayName) [Enabled=$($rule.Enabled), Action=$($rule.Action)]"
    } else {
        Write-Warning "  Firewall rule not found after creation - check Windows Firewall settings manually."
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Installation complete!  Run: jocky --version" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
exit 0
