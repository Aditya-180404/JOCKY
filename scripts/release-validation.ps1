# JOCKY Release Validation Gate
# Single entry point for local full release qualification

$ErrorActionPreference = 'Stop'
$global:FailedGates = @()
$global:PassedGates = @()

function Run-Gate {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "GATE: $Name" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        Write-Host "✓ [PASS] $Name (completed in $($sw.Elapsed.TotalSeconds.ToString('F1'))s)" -ForegroundColor Green
        $global:PassedGates += $Name
    } catch {
        $sw.Stop()
        Write-Host "✗ [FAIL] $Name (failed after $($sw.Elapsed.TotalSeconds.ToString('F1'))s): $_" -ForegroundColor Red
        $global:FailedGates += "${Name}: $_"
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

# Configure LLVM 21 if present
if (Test-Path "C:\LLVM21") {
    $env:LLVM_SYS_211_PREFIX = "C:\LLVM21"
    $env:PATH = "C:\LLVM21\bin;$env:PATH"
}

Write-Host "************************************************************" -ForegroundColor Magenta
Write-Host "     JOCKY STRICT RELEASE VALIDATION MASTER GATE           " -ForegroundColor Magenta
Write-Host "************************************************************" -ForegroundColor Magenta
Write-Host "Repository: $repoRoot"
Write-Host "Time:       $([System.DateTime]::UtcNow.ToString('o')) UTC"
Write-Host "rustc:      $(& rustc --version)"
Write-Host "cargo:      $(& cargo --version)"
if (Get-Command llvm-config -ErrorAction SilentlyContinue) {
    Write-Host "LLVM:       $(& llvm-config --version)"
}

# 1. Formatting
Run-Gate "1. Code Formatting (cargo fmt)" {
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "Formatting check failed" }
}

# 2. Strict Clippy with All Features
Run-Gate "2. Linter & Static Analysis (clippy --all-features -D warnings)" {
    & cargo clippy --workspace --all-targets --all-features -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Clippy check failed" }
}

# 3. Workspace Tests with All Features
Run-Gate "3. Full Workspace Test Suite (cargo test --all-features)" {
    & cargo test --workspace --all-features
    if ($LASTEXITCODE -ne 0) { throw "Workspace unit/integration tests failed" }
}

# 4. Release Build
Run-Gate "4. Release Binary Compilation (cargo build --release)" {
    & cargo build --workspace --release
    if ($LASTEXITCODE -ne 0) { throw "Release build failed" }
}

# 5. PE Version Metadata Validation
Run-Gate "5. Windows PE Version Metadata" {
    $exePath = Join-Path $repoRoot "target\release\jocky.exe"
    if (-not (Test-Path $exePath)) { throw "jocky.exe not found" }
    $info = (Get-Item $exePath).VersionInfo
    if ($info.ProductName -ne "JOCKY") { throw "ProductName mismatch: $($info.ProductName)" }
    if ($info.FileDescription -ne "JOCKY Digital Forensics Platform") { throw "FileDescription mismatch: $($info.FileDescription)" }
    if ($info.CompanyName -ne "JOCKY") { throw "CompanyName mismatch: $($info.CompanyName)" }
    if ($info.ProductVersion -ne "0.1.0") { throw "ProductVersion mismatch: $($info.ProductVersion)" }
    Write-Host "      ✓ Product: $($info.ProductName), Version: $($info.ProductVersion)"
}

# 6. Authoritative Capability Matrix Audit
Run-Gate "6. Authoritative Capability Matrix (247 capabilities)" {
    $cliJson = (& .\target\release\jocky.exe capabilities --format json) -join "`n"
    $caps = $cliJson | ConvertFrom-Json
    if ($caps.Length -ne 247) { throw "CLI capabilities count mismatch: $($caps.Length) (expected 247)" }
    Write-Host "      ✓ 247 capabilities verified across registry"
}

# 7. Source Independence & Relocatable Project Validation
Run-Gate "7. Source-Independent Generated Projects" {
    & cargo test --package jocky-backend --test source_independence
    if ($LASTEXITCODE -ne 0) { throw "Source independence test failed" }
}

# 8. Forensic Pipeline Execution & Integrity Verification
Run-Gate "8. Forensic Pipeline (Check, Run, Verify, Tamper Detection)" {
    # Check
    & .\target\release\jocky.exe check examples\complete_forensic_triage.jy
    if ($LASTEXITCODE -ne 0) { throw "jocky check failed" }

    # Run
    $testOut = Join-Path $repoRoot "target\release-test-build"
    if (Test-Path $testOut) { Remove-Item -Recurse -Force $testOut }
    New-Item -ItemType Directory -Path $testOut | Out-Null

    & .\target\release\jocky.exe run examples\complete_forensic_triage.jy --output $testOut
    if ($LASTEXITCODE -ne 0) { throw "jocky run failed" }

    $evidenceFile = Join-Path $testOut "complete_forensic_triage_evidence.json"
    if (-not (Test-Path $evidenceFile)) {
        $evidenceFile = Join-Path $repoRoot "complete_forensic_triage_evidence.json"
    }
    $metaFile = "$evidenceFile.meta.json"
    if (-not (Test-Path $evidenceFile)) { throw "Evidence file not produced" }

    # Verify
    & .\target\release\jocky.exe evidence verify $evidenceFile --meta $metaFile
    if ($LASTEXITCODE -ne 0) { throw "Evidence verification failed" }

    # Tamper test
    $tamperedFile = Join-Path $env:TEMP "tamper_gate_test.json"
    $content = Get-Content $evidenceFile -Raw
    Set-Content -Path $tamperedFile -Value ($content + " ")
    $tamperProc = Start-Process -FilePath ".\target\release\jocky.exe" -ArgumentList "evidence", "verify", $tamperedFile, "--meta", $metaFile -NoNewWindow -Wait -PassThru
    Remove-Item -Force $tamperedFile -ErrorAction SilentlyContinue
    if ($tamperProc.ExitCode -eq 0) { throw "Tampered evidence was falsely validated!" }
    Write-Host "      ✓ Tamper detection confirmed"
}

# 9. Windows Distribution Package Build & Validation
Run-Gate "9. Windows ZIP Distribution Package" {
    & powershell.exe -ExecutionPolicy Bypass -File packaging\build-win.ps1
    if ($LASTEXITCODE -ne 0) { throw "Package build failed" }

    & powershell.exe -ExecutionPolicy Bypass -File tests\verify-windows-package.ps1
    if ($LASTEXITCODE -ne 0) { throw "Package verification failed" }
}

# 10. Authenticode Signing Pipeline Test
Run-Gate "10. Authenticode Signing Pipeline" {
    & powershell.exe -ExecutionPolicy Bypass -File scripts\sign-windows.ps1
    if ($LASTEXITCODE -ne 0) { throw "Sign script check failed" }
}

# 11. API Unit & Security Tests
Run-Gate "11. API Contracts & Download Security Tests" {
    & cargo test --package jocky-api
    if ($LASTEXITCODE -ne 0) { throw "API tests failed" }
}

# 12. Frontend Web IDE Build & Lint
Run-Gate "12. Frontend Web IDE (Lint & Production Build)" {
    Push-Location (Join-Path $repoRoot "apps\web")
    try {
        & npm run lint
        if ($LASTEXITCODE -ne 0) { throw "npm run lint failed" }

        & npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
    } finally {
        Pop-Location
    }
}

# Summary
Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "              RELEASE VALIDATION SUMMARY                    " -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

Write-Host "Passed gates: $($global:PassedGates.Count)" -ForegroundColor Green
foreach ($g in $global:PassedGates) {
    Write-Host "  [PASS] $g" -ForegroundColor Green
}

if ($global:FailedGates.Count -gt 0) {
    Write-Host "`nFailed gates: $($global:FailedGates.Count)" -ForegroundColor Red
    foreach ($f in $global:FailedGates) {
        Write-Host "  [FAIL] $f" -ForegroundColor Red
    }
    Write-Host "`nRELEASE STATUS: RELEASE BLOCKED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nRELEASE STATUS: RELEASE READY" -ForegroundColor Green
    Write-Host "All mandatory validation gates passed successfully." -ForegroundColor Green
    exit 0
}
