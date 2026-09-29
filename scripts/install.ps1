<#
.SYNOPSIS
    JOCKY Installer for Windows — downloads and installs the compiler globally.

.DESCRIPTION
    One-liner install (run in PowerShell as Administrator):
      irm https://raw.githubusercontent.com/Aditya-180404/JOCKY/main/scripts/install.ps1 | iex

    Or download and run locally:
      powershell -ExecutionPolicy Bypass -File install.ps1

    After install, 'jocky' is available in any new terminal (added to system PATH).

.PARAMETER Version
    Specific version to install (e.g. "v0.1.0"). Defaults to latest.

.PARAMETER InstallDir
    Destination directory. Default: C:\Program Files\JOCKY

.PARAMETER Uninstall
    Remove JOCKY from your system.

.PARAMETER NoModifyPath
    Do not add InstallDir to PATH.

.PARAMETER NoFirewall
    Skip creating a Windows Firewall inbound rule.

.EXAMPLE
    # One-liner install (PowerShell, Admin):
    irm https://raw.githubusercontent.com/Aditya-180404/JOCKY/main/scripts/install.ps1 | iex

.EXAMPLE
    # Install specific version:
    & install.ps1 -Version v0.2.0

.EXAMPLE
    # Uninstall:
    & install.ps1 -Uninstall
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $Version      = "latest",
    [string] $InstallDir   = "$env:ProgramFiles\JOCKY",
    [switch] $Uninstall,
    [switch] $NoModifyPath,
    [switch] $NoFirewall
)

$ErrorActionPreference = "Stop"
$REPO        = "Aditya-180404/JOCKY"
$BINARY_NAME = "jocky.exe"
$FW_RULE     = "JOCKY - Compiler inbound (TCP)"

# ─── Colors via Write-Host ────────────────────────────────────────────────────
function Log   { param($m) Write-Host "[JOCKY] $m" -ForegroundColor Cyan }
function Ok    { param($m) Write-Host "  [OK] $m"   -ForegroundColor Green }
function Warn  { param($m) Write-Host "  [!]  $m"   -ForegroundColor Yellow }
function Err   { param($m) Write-Error "  [X]  $m";  exit 1 }
function Step  { param($m) Write-Host "`n── $m ──" -ForegroundColor White }

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   JOCKY Forensic Language Compiler   ║" -ForegroundColor Cyan
if ($Uninstall) {
    Write-Host "  ║          Uninstaller                 ║" -ForegroundColor Cyan
} else {
    Write-Host "  ║   Windows Installer                  ║" -ForegroundColor Cyan
}
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── Admin check ──────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Warn "Not running as Administrator — relaunching elevated..."
    Start-Process pwsh -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" $($MyInvocation.UnboundArguments)" -Verb RunAs
    exit 0
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Step "Uninstalling JOCKY"

    $dest = Join-Path $InstallDir $BINARY_NAME
    if (Test-Path $dest) {
        Remove-Item $dest -Force
        Ok "Removed $dest"
    } else {
        Warn "Binary not found at $dest"
    }

    # Remove from PATH
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -like "*$InstallDir*") {
        $newPath = ($machinePath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        Ok "Removed $InstallDir from system PATH"
    }

    # Remove firewall rule
    $rule = Get-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $FW_RULE
        Ok "Removed firewall rule"
    }

    Write-Host "`nJOCKY has been uninstalled." -ForegroundColor Green
    exit 0
}

# ─── Resolve version ──────────────────────────────────────────────────────────
Step "Resolving version"
if ($Version -eq "latest") {
    Log "Fetching latest release from GitHub..."
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing
        $Version = $release.tag_name
    } catch {
        Warn "No published GitHub release found; defaulting to v0.1.0"
        $Version = "v0.1.0"
    }
}
Ok "Version: $Version"

# ─── Download ─────────────────────────────────────────────────────────────────
Step "Downloading JOCKY $Version"

$VerStripped = $Version.TrimStart("v")
$AssetName   = "jocky_${VerStripped}_windows_amd64.zip"
$DownloadUrl = "https://github.com/$REPO/releases/download/$Version/jocky_${VerStripped}_windows_x86_64.zip"

$TmpDir  = Join-Path $env:TEMP "jocky_install_$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

Log "URL: $DownloadUrl"
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile (Join-Path $TmpDir $AssetName) -UseBasicParsing
    Ok "Downloaded $AssetName"
    Expand-Archive -Path (Join-Path $TmpDir $AssetName) -DestinationPath $TmpDir -Force
    $extractedExe = Get-ChildItem -Path $TmpDir -Recurse -Filter "jocky.exe" | Select-Object -First 1
    if (-not $extractedExe) { Err "jocky.exe not found in archive." }
} catch {
    # Fallback 1: try raw exe download from GitHub
    $RawUrl = "https://github.com/$REPO/releases/download/$Version/jocky-windows-x86_64.exe"
    Log "GitHub asset not found, trying raw binary: $RawUrl"
    $downloadSuccess = $false
    try {
        $rawPath = Join-Path $TmpDir "jocky.exe"
        Invoke-WebRequest -Uri $RawUrl -OutFile $rawPath -UseBasicParsing
        $extractedExe = Get-Item $rawPath
        Ok "Downloaded raw binary"
        $downloadSuccess = $true
    } catch {
        # Fallback 2: try server download endpoint
        $ServerUrl = if ($env:JOCKY_SERVER) { "$env:JOCKY_SERVER/api/downloads/windows" } else { "http://localhost:8080/api/downloads/windows" }
        Log "Trying server download: $ServerUrl"
        try {
            $zipPath = Join-Path $TmpDir "jocky_server.zip"
            Invoke-WebRequest -Uri $ServerUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $TmpDir -Force
            $extractedExe = Get-ChildItem -Path $TmpDir -Recurse -Filter "jocky.exe" | Select-Object -First 1
            if ($extractedExe) {
                Ok "Downloaded and extracted from server"
                $downloadSuccess = $true
            }
        } catch {
            Log "Server zip unavailable, checking server exe..."
        }

        if (-not $downloadSuccess) {
            # Fallback 3: try direct jocky.exe from server
            $ServerExe = if ($env:JOCKY_SERVER) { "$env:JOCKY_SERVER/api/downloads/jocky.exe" } else { "http://localhost:8080/api/downloads/jocky.exe" }
            try {
                $rawPath = Join-Path $TmpDir "jocky.exe"
                Invoke-WebRequest -Uri $ServerExe -OutFile $rawPath -UseBasicParsing
                $extractedExe = Get-Item $rawPath
                Ok "Downloaded jocky.exe from server"
                $downloadSuccess = $true
            } catch {
                Err "Download failed. Visit: https://github.com/$REPO/releases"
            }
        }
    }
}

# ─── Install ──────────────────────────────────────────────────────────────────
Step "Installing to $InstallDir"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$destExe = Join-Path $InstallDir $BINARY_NAME
Copy-Item -Path $extractedExe.FullName -Destination $destExe -Force
Ok "Installed → $destExe"

# Cleanup
Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ─── PATH ─────────────────────────────────────────────────────────────────────
Step "Configuring PATH"

if (-not $NoModifyPath) {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
        Ok "Added $InstallDir to system PATH"
        Warn "Open a new terminal (or run: refreshenv) to use 'jocky' everywhere"
    } else {
        Ok "$InstallDir already in PATH"
    }
} else {
    Warn "Skipping PATH update (-NoModifyPath). Add manually: $InstallDir"
}

# ─── Firewall ─────────────────────────────────────────────────────────────────
Step "Windows Firewall rule"

if (-not $NoFirewall) {
    $existing = Get-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue
    if ($existing) { Remove-NetFirewallRule -DisplayName $FW_RULE }

    New-NetFirewallRule `
        -DisplayName  $FW_RULE `
        -Description  "Allows inbound TCP connections to jocky.exe (JOCKY compiler)." `
        -Direction    Inbound `
        -Protocol     TCP `
        -Action       Allow `
        -Program      $destExe `
        -Profile      Any `
        -Enabled      True | Out-Null
    Ok "Firewall rule created: $FW_RULE"
} else {
    Warn "Skipping firewall rule (-NoFirewall)"
}

# ─── Verify ───────────────────────────────────────────────────────────────────
Step "Verification"
$installed = Get-Item $destExe
Write-Host "  Path:    $($installed.FullName)"
Write-Host "  Size:    $([math]::Round($installed.Length / 1MB, 2)) MB"
Write-Host "  SHA-256: $((Get-FileHash -Path $destExe -Algorithm SHA256).Hash)"

# ─── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  JOCKY installed successfully!         ║" -ForegroundColor Green
Write-Host "  ╠════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  Quick start (new terminal):           ║" -ForegroundColor Green
Write-Host "  ║    jocky --help                        ║" -ForegroundColor Green
Write-Host "  ║    jocky --version                     ║" -ForegroundColor Green
Write-Host "  ║    jocky script.jy                     ║" -ForegroundColor Green
Write-Host "  ╚════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
