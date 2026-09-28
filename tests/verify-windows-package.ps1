# Windows Package Validation Script
param(
    [string]$ZipPath = "G:\jockey\jockey_0.1.0_windows_amd64.zip"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ZipPath)) {
    throw "Zip file not found at: $ZipPath"
}

$testDir = Join-Path $env:TEMP ("jockey-pkg-test-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $testDir | Out-Null

try {
    Write-Host "[1/6] Extracting $ZipPath to $testDir..." -ForegroundColor Cyan
    Expand-Archive -Path $ZipPath -DestinationPath $testDir

    $exePath = Join-Path $testDir "jockey.exe"
    if (-not (Test-Path $exePath)) {
        throw "jockey.exe not found in extracted package root"
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

    Write-Host "[3/6] Testing jockey.exe --version..." -ForegroundColor Cyan
    $ver = & $exePath --version
    Write-Host "      Version output: $ver"
    if ($ver -notmatch "jockey 0.1.0") {
        throw "Unexpected version output: $ver"
    }
    Write-Host "      ✓ Version verified" -ForegroundColor Green

    Write-Host "[4/6] Testing jockey.exe doctor..." -ForegroundColor Cyan
    $doc = (& $exePath doctor) -join "`n"
    if ($doc -notmatch "Total:\s+247") {
        throw "Doctor output does not report 247 capabilities"
    }
    Write-Host "      ✓ Doctor diagnostic passed" -ForegroundColor Green

    Write-Host "[5/6] Testing jockey.exe capabilities --format json..." -ForegroundColor Cyan
    $capsRaw = (& $exePath capabilities --format json) -join "`n"
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
    Write-Host "      jockey.exe Size: $exeSize bytes"
    Write-Host "      jockey.exe SHA256: $exeHash"

    Write-Host "`n==================================================" -ForegroundColor Green
    Write-Host "WINDOWS PACKAGE VALIDATION: ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    exit 0
} finally {
    Remove-Item -Recurse -Force -Path $testDir -ErrorAction SilentlyContinue
}
