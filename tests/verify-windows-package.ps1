# Windows Package Validation Script
param(
    [string]$ZipPath = "G:\jocky\jocky_0.1.0_windows_amd64.zip"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ZipPath)) {
    throw "Zip file not found at: $ZipPath"
}

$tempRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
$testDir = Join-Path $tempRoot ("jocky-pkg-test-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $testDir | Out-Null

try {
    Write-Host "[1/6] Extracting $ZipPath to $testDir..." -ForegroundColor Cyan
    Expand-Archive -Path $ZipPath -DestinationPath $testDir

    $exePath = Join-Path $testDir "jocky.exe"
    if (-not (Test-Path $exePath)) {
        throw "jocky.exe not found in extracted package root"
    }

    function Invoke-Jocky {
        param([string[]]$Arguments)
        if ($IsWindows -or ($null -eq $IsWindows -and [System.Environment]::OSVersion.Platform -match "Win")) {
            & $exePath @Arguments
        } else {
            & wine $exePath @Arguments
        }
    }

    Write-Host "[2/6] Verifying PE x64 architecture..." -ForegroundColor Cyan
    $bytes = [System.IO.File]::ReadAllBytes($exePath)
    if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "Invalid PE header (missing MZ magic)"
    }
    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    $machine = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0x8664) {
        throw "Expected AMD64 (0x8664), got: $machine"
    }
    Write-Host "      ✓ PE architecture: AMD64 / x86_64 confirmed" -ForegroundColor Green

    Write-Host "[3/6] Testing jocky.exe --version..." -ForegroundColor Cyan
    $ver = (Invoke-Jocky @("--version")) -join "`n"
    Write-Host "      Version output: $ver"
    if ($ver -notmatch "jocky 0.1.0") {
        throw "Unexpected version output: $ver"
    }
    Write-Host "      ✓ Version verified" -ForegroundColor Green

    Write-Host "[4/6] Testing jocky.exe doctor..." -ForegroundColor Cyan
    $doc = (Invoke-Jocky @("doctor")) -join "`n"
    if ($doc -notmatch "Total:\s+247") {
        throw "Doctor output does not report 247 capabilities"
    }
    Write-Host "      ✓ Doctor diagnostic passed" -ForegroundColor Green

    Write-Host "[5/6] Testing jocky.exe capabilities --format json..." -ForegroundColor Cyan
    $capsRaw = (Invoke-Jocky @("capabilities", "--format", "json")) -join "`n"
    $caps = $capsRaw | ConvertFrom-Json
    if ($caps.Length -ne 247) {
        throw "Expected 247 capabilities, got: $($caps.Length)"
    }
    Write-Host "      ✓ Capabilities count: 247 confirmed" -ForegroundColor Green

    Write-Host "[6/6] Computing SHA-256 digest..." -ForegroundColor Cyan
    $hash = (Get-FileHash -Algorithm SHA256 -Path $ZipPath).Hash
    $exeHash = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash
    $zipSize = (Get-Item $ZipPath).Length
    $exeSize = (Get-Item $exePath).Length
    Write-Host "      Package ZIP Size: $zipSize bytes"
    Write-Host "      Package ZIP SHA256: $hash"
    Write-Host "      jocky.exe Size: $exeSize bytes"
    Write-Host "      jocky.exe SHA256: $exeHash"

    Write-Host "`n==================================================" -ForegroundColor Green
    Write-Host "WINDOWS PACKAGE VALIDATION: ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    exit 0
} finally {
    Remove-Item -Recurse -Force -Path $testDir -ErrorAction SilentlyContinue
}
