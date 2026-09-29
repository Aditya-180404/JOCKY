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
    [string] $InstallDir   = "",
    [switch] $Uninstall,
    [switch] $NoModifyPath,
    [switch] $NoFirewall
)

$ErrorActionPreference = "Stop"
$REPO        = "Aditya-180404/JOCKY"
$BINARY_NAME = "jocky.exe"
$FW_RULE     = "JOCKY - Compiler inbound (TCP)"

# Enable TLS 1.2 / TLS 1.3 for older Windows PowerShell 5.1 environments
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# ─── Colors via Write-Host ────────────────────────────────────────────────────
function Log   { param($m) Write-Host "[JOCKY] $m" -ForegroundColor Cyan }
function Ok    { param($m) Write-Host "  [OK] $m"   -ForegroundColor Green }
function Warn  { param($m) Write-Host "  [!]  $m"   -ForegroundColor Yellow }
function Err   { param($m) Write-Error "  [X]  $m";  exit 1 }
function Step  { param($m) Write-Host "`n── $m ──" -ForegroundColor White }

# ─── Privilege & Directory Detection ──────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($isAdmin) {
        $InstallDir = "$env:ProgramFiles\JOCKY"
    } else {
        $InstallDir = "$env:LOCALAPPDATA\Programs\JOCKY"
    }
}

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

if ($isAdmin) {
    Log "Running elevated as Administrator — installing system-wide to: $InstallDir"
} else {
    Log "Running in user mode — installing for current user to: $InstallDir"
    Log "(Tip: To install system-wide into Program Files, run PowerShell as Administrator)"
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Step "Uninstalling JOCKY"

    $targets = @(
        $InstallDir,
        "$env:ProgramFiles\JOCKY",
        "$env:LOCALAPPDATA\Programs\JOCKY"
    ) | Select-Object -Unique

    foreach ($dir in $targets) {
        $dest = Join-Path $dir $BINARY_NAME
        if (Test-Path $dest) {
            Remove-Item $dest -Force -ErrorAction SilentlyContinue
            Ok "Removed $dest"
        }
        if ((Test-Path $dir) -and -not (Get-ChildItem -Path $dir -ErrorAction SilentlyContinue)) {
            Remove-Item $dir -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove from User and Machine PATH
    foreach ($scope in @("User", "Machine")) {
        try {
            $p = [Environment]::GetEnvironmentVariable("Path", $scope)
            if ($p) {
                $parts = $p -split ";" | Where-Object { $_ -and -not ($_ -like "*\JOCKY*") }
                $newPath = $parts -join ";"
                if ($newPath -ne $p) {
                    [Environment]::SetEnvironmentVariable("Path", $newPath, $scope)
                    Ok "Cleaned JOCKY from $scope PATH"
                }
            }
        } catch {}
    }

    # Remove firewall rule if elevated
    if ($isAdmin) {
        $rule = Get-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue
        if ($rule) {
            Remove-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue
            Ok "Removed firewall rule"
        }
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

$TmpDir  = Join-Path $env:TEMP "jocky_install_$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$downloadSuccess = $false
$extractedExe = $null

# Candidate download sources in order of preference:
$candidateSources = @(
    @{ Type = "zip"; Url = "https://github.com/$REPO/releases/download/$Version/jocky_${VerStripped}_windows_x86_64.zip"; Desc = "GitHub Release Archive" },
    @{ Type = "zip"; Url = "https://raw.githubusercontent.com/$REPO/main/jocky_0.1.0_windows_amd64.zip";                  Desc = "GitHub Repository Archive" },
    @{ Type = "exe"; Url = "https://raw.githubusercontent.com/$REPO/main/jocky.exe";                                      Desc = "GitHub Repository Executable" },
    @{ Type = "exe"; Url = "https://github.com/$REPO/releases/download/$Version/jocky-windows-x86_64.exe";                Desc = "GitHub Release Executable" }
)

if ($env:JOCKY_SERVER) {
    $candidateSources += @(
        @{ Type = "zip"; Url = "$env:JOCKY_SERVER/api/downloads/windows"; Desc = "Server Archive" },
        @{ Type = "exe"; Url = "$env:JOCKY_SERVER/api/downloads/jocky.exe"; Desc = "Server Executable" }
    )
}

foreach ($src in $candidateSources) {
    Log "Trying $($src.Desc)..."
    try {
        if ($src.Type -eq "zip") {
            $zipPath = Join-Path $TmpDir "jocky_download.zip"
            Invoke-WebRequest -Uri $src.Url -OutFile $zipPath -UseBasicParsing -TimeoutSec 60
            Expand-Archive -Path $zipPath -DestinationPath $TmpDir -Force
            $found = Get-ChildItem -Path $TmpDir -Recurse -Filter "jocky.exe" | Select-Object -First 1
            if ($found) {
                $extractedExe = $found
                $downloadSuccess = $true
                Ok "Downloaded and extracted $($src.Desc)"
                break
            }
        } elseif ($src.Type -eq "exe") {
            $rawPath = Join-Path $TmpDir "jocky.exe"
            Invoke-WebRequest -Uri $src.Url -OutFile $rawPath -UseBasicParsing -TimeoutSec 60
            if (Test-Path $rawPath) {
                $extractedExe = Get-Item $rawPath
                $downloadSuccess = $true
                Ok "Downloaded $($src.Desc)"
                break
            }
        }
    } catch {
        # Try next candidate
    }
}

if (-not $downloadSuccess -or -not $extractedExe) {
    Err "Download failed from all sources. Visit: https://github.com/$REPO"
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
    $pathScope = if ($isAdmin) { "Machine" } else { "User" }
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", $pathScope)
        if ($currentPath -notlike "*$InstallDir*") {
            $separator = if ($currentPath -and -not $currentPath.EndsWith(";")) { ";" } else { "" }
            [Environment]::SetEnvironmentVariable("Path", "$currentPath$separator$InstallDir", $pathScope)
            Ok "Added $InstallDir to $pathScope PATH"
            Warn "Open a new terminal (or run: refreshenv) to use 'jocky' everywhere"
        } else {
            Ok "$InstallDir already in $pathScope PATH"
        }
    } catch {
        Warn "Could not update $pathScope PATH: $_"
    }

    # Always update current session PATH so jocky works right away!
    if ($env:Path -notlike "*$InstallDir*") {
        $env:Path = "$env:Path;$InstallDir"
    }
} else {
    Warn "Skipping PATH update (-NoModifyPath). Add manually: $InstallDir"
}

# ─── Firewall ─────────────────────────────────────────────────────────────────
if ($isAdmin -and -not $NoFirewall) {
    Step "Windows Firewall rule"
    try {
        $existing = Get-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue
        if ($existing) { Remove-NetFirewallRule -DisplayName $FW_RULE -ErrorAction SilentlyContinue }

        New-NetFirewallRule `
            -DisplayName  $FW_RULE `
            -Description  "Allows inbound TCP connections to jocky.exe (JOCKY compiler)." `
            -Direction    Inbound `
            -Protocol     TCP `
            -Action       Allow `
            -Program      $destExe `
            -Profile      Any `
            -Enabled      True -ErrorAction SilentlyContinue | Out-Null
        Ok "Firewall rule created: $FW_RULE"
    } catch {
        Warn "Could not create firewall rule: $_"
    }
} elseif (-not $isAdmin) {
    Log "Skipping Windows Firewall rule (requires Administrator privileges)."
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
