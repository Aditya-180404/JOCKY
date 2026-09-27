# JOCKEY Strict Evidence Integrity & Tamper Detection Test
# Performs exact 8-step test sequence:
# 1. Run investigation
# 2. Generate evidence
# 3. Verify original evidence
# 4. Modify one field
# 5. Verify modified evidence (MUST FAIL)
# 6. Verification MUST fail with non-zero exit
# 7. Restore original
# 8. Verification MUST succeed again

$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "JOCKEY STRICT EVIDENCE TAMPER DETECTION TEST" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Step 1 & 2: Run investigation & generate evidence
Write-Host "[Step 1 & 2] Executing investigation to generate fresh evidence..." -ForegroundColor Yellow
if (!(Test-Path "build")) { New-Item -ItemType Directory -Path "build" | Out-Null }
$runOutput = .\target\release\jockey.exe run examples/basic_system_triage.jy --output build/
$evPath = "build/system_triage.json"
$metaPath = "build/system_triage.json.meta.json"

if (!(Test-Path $evPath) -or !(Test-Path $metaPath)) {
    Write-Host "[FAIL] Evidence files were not generated at $evPath" -ForegroundColor Red
    exit 1
}
Write-Host "  -> Generated $evPath ($((Get-Item $evPath).Length) bytes)" -ForegroundColor Green

# Step 3: Verify original evidence
Write-Host "[Step 3] Verifying original untampered evidence..." -ForegroundColor Yellow
$verify1 = .\target\release\jockey.exe verify $evPath 2>&1 | Out-String
$verify1Valid = ($LASTEXITCODE -eq 0) -and ($verify1 -match "VALID")
if (!$verify1Valid) {
    Write-Host "[FAIL] Original evidence failed verification: $verify1" -ForegroundColor Red
    exit 1
}
Write-Host "  -> Original evidence verified VALID" -ForegroundColor Green

# Step 4: Modify one field
Write-Host "[Step 4] Tampering with one field in the evidence file..." -ForegroundColor Yellow
$backupPath = "build/system_triage_backup.json"
Copy-Item $evPath $backupPath -Force

$rawContent = [System.IO.File]::ReadAllText((Resolve-Path $evPath).Path)
# Mutate one byte or string in the payload
if ($rawContent -match "Windows") {
    $tampered = $rawContent -replace "Windows", "TamperedOS"
} elseif ($rawContent -match "DESKTOP") {
    $tampered = $rawContent -replace "DESKTOP", "TAMPERED"
} else {
    $tampered = $rawContent + " "
}
[System.IO.File]::WriteAllText((Resolve-Path $evPath).Path, $tampered)
Write-Host "  -> Evidence tampered" -ForegroundColor Green

# Step 5 & 6: Verify modified evidence - MUST FAIL
Write-Host "[Step 5 & 6] Verifying tampered evidence (MUST FAIL)..." -ForegroundColor Yellow
$verify2 = ""
$exitCode = 0
try {
    $p = Start-Process -FilePath ".\target\release\jockey.exe" -ArgumentList "verify `"$evPath`"" -NoNewWindow -Wait -PassThru -RedirectStandardError "build/tamper_err.txt" -RedirectStandardOutput "build/tamper_out.txt"
    $exitCode = $p.ExitCode
    $verify2 = (Get-Content "build/tamper_err.txt" -Raw) + (Get-Content "build/tamper_out.txt" -Raw)
} catch {
    $verify2 = $_.ToString()
    $exitCode = 1
}
$tamperDetected = ($exitCode -ne 0) -and ($verify2 -match "TAMPERED|Hash mismatch|mismatch|FAILED")
if (!$tamperDetected) {
    Write-Host "[FAIL] Tampered evidence was falsely reported as VALID! (ExitCode: $exitCode, Output: $verify2)" -ForegroundColor Red
    exit 1
}
Write-Host "  -> Tamper detected successfully with exit code ${exitCode}: $($verify2.Trim())" -ForegroundColor Green

# Step 7: Restore original
Write-Host "[Step 7] Restoring original evidence from backup..." -ForegroundColor Yellow
Copy-Item $backupPath $evPath -Force
Remove-Item $backupPath -Force
Write-Host "  -> Restored original evidence" -ForegroundColor Green

# Step 8: Verification MUST succeed again
Write-Host "[Step 8] Verifying restored original evidence (MUST SUCCEED)..." -ForegroundColor Yellow
$verify3 = .\target\release\jockey.exe verify $evPath 2>&1 | Out-String
$verify3Valid = ($LASTEXITCODE -eq 0) -and ($verify3 -match "VALID")
if (!$verify3Valid) {
    Write-Host "[FAIL] Restored evidence failed verification: $verify3" -ForegroundColor Red
    exit 1
}
Write-Host "  -> Restored evidence verified VALID" -ForegroundColor Green

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "TAMPER DETECTION TEST: 100% PASS (CRYPTOGRAPHICALLY SOUND)" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
exit 0
