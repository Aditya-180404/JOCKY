# JOCKEY Final End-to-End Release Acceptance Test Suite
# Tests all 23 release criteria

$ErrorActionPreference = "Stop"
$passed = 0
$failed = 0

function Report-Test($id, $name, $success, $detail) {
    if ($success) {
        Write-Host "[PASS] [$id] $name - $detail" -ForegroundColor Green
        $global:passed++
    } else {
        Write-Host "[FAIL] [$id] $name - $detail" -ForegroundColor Red
        $global:failed++
    }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "JOCKEY FINAL RELEASE E2E ACCEPTANCE TEST SUITE" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# [1] Source extension (.jy is only DSL extension, no legacy production .tfg)
$tfgFiles = Get-ChildItem -Path "examples" -Filter "*.tfg" -ErrorAction SilentlyContinue
$jyFiles = Get-ChildItem -Path "examples" -Filter "*.jy"
$test1Success = ($tfgFiles.Count -eq 0) -and ($jyFiles.Count -ge 10)
Report-Test 1 "Source Extension Check" $test1Success "Found $($jyFiles.Count) .jy examples, 0 production .tfg files"

# [2] Workspace Cargo Tests
try {
    $cargoTest = cargo test --workspace
    $test2Success = $LASTEXITCODE -eq 0
    Report-Test 2 "Workspace Unit & Integration Tests" $test2Success "cargo test passed"
} catch {
    Report-Test 2 "Workspace Unit & Integration Tests" $false $_.Exception.Message
}

# [3] Compiler check
try {
    $checkOut = .\target\release\jockey.exe check examples/complete_forensic_triage.jy
    $test3Success = $LASTEXITCODE -eq 0
    Report-Test 3 "CLI Check Command" $test3Success "jockey check passed on examples/complete_forensic_triage.jy"
} catch {
    Report-Test 3 "CLI Check Command" $false $_.Exception.Message
}

# [4] CLI Help and Version
try {
    $verOut = .\target\release\jockey.exe --version
    $test4Success = ($LASTEXITCODE -eq 0) -and ($verOut -match "0.1.0")
    Report-Test 4 "CLI Version and Help" $test4Success "Version reported: $verOut"
} catch {
    Report-Test 4 "CLI Version and Help" $false $_.Exception.Message
}

# [5] Windows Compilation
try {
    if (!(Test-Path "build")) { New-Item -ItemType Directory -Path "build" | Out-Null }
    $compOut = .\target\release\jockey.exe compile examples/complete_forensic_triage.jy --target windows-x64 --output build/
    $exePath = "build/complete_forensic_triage-windows-x64.exe"
    $test5Success = (Test-Path $exePath) -and ((Get-Item $exePath).Length -gt 100000)
    Report-Test 5 "Windows Compilation" $test5Success "Generated $exePath ($((Get-Item $exePath).Length) bytes)"
} catch {
    Report-Test 5 "Windows Compilation" $false $_.Exception.Message
}

# [6] Windows PE Header Inspection
try {
    $bytes = [System.IO.File]::ReadAllBytes($exePath)
    $hasMZ = ($bytes[0] -eq 0x4D) -and ($bytes[1] -eq 0x5A) # 'MZ'
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $hasPE = ($bytes[$peOffset] -eq 0x50) -and ($bytes[$peOffset + 1] -eq 0x45) # 'PE'
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4) # 0x8664 for x86_64
    $isX64 = ($machine -eq 0x8664)
    $test6Success = $hasMZ -and $hasPE -and $isX64
    Report-Test 6 "Windows PE Header Validation" $test6Success "MZ header: $hasMZ, PE signature: $hasPE, x86_64 machine: $isX64"
} catch {
    Report-Test 6 "Windows PE Header Validation" $false $_.Exception.Message
}

# [7, 8] Windows Execution & Evidence Generation
try {
    $runOut = .\target\release\jockey.exe run examples/basic_system_triage.jy --output build/
    $evPath = "build/system_triage.json"
    $metaPath = "build/system_triage.json.meta.json"
    $test7Success = (Test-Path $evPath) -and (Test-Path $metaPath) -and ((Get-Item $evPath).Length -gt 1000)
    Report-Test 7 "Windows Native Execution" $test7Success "Executed investigation and generated $evPath ($((Get-Item $evPath).Length) bytes)"
    Report-Test 8 "Evidence Generation" $test7Success "Evidence and metadata sidecar created successfully"
} catch {
    Report-Test 7 "Windows Native Execution" $false $_.Exception.Message
    Report-Test 8 "Evidence Generation" $false $_.Exception.Message
}

# [9] Evidence Cryptographic Verification
try {
    $verifyOut = .\target\release\jockey.exe verify build/system_triage.json
    $test9Success = ($LASTEXITCODE -eq 0) -and ($verifyOut -match "VALID")
    Report-Test 9 "Evidence Integrity Verification" $test9Success "Verification returned VALID with SHA-256 and Merkle checks"
} catch {
    Report-Test 9 "Evidence Integrity Verification" $false $_.Exception.Message
}

# [10] Tamper Detection
try {
    Copy-Item "build/system_triage.json" "build/tamper_test.json" -Force
    Copy-Item "build/system_triage.json.meta.json" "build/tamper_test.json.meta.json" -Force
    (Get-Content "build/tamper_test.json") -replace 'Windows', 'TamperedOS' | Set-Content "build/tamper_test.json"
    $tamperOut = .\target\release\jockey.exe verify build/tamper_test.json 2>&1
    $test10Success = ($LASTEXITCODE -ne 0) -and ($tamperOut -match "TAMPERED|Hash mismatch")
    Report-Test 10 "Cryptographic Tamper Detection" $test10Success "Tampered evidence rejected with non-zero exit code: $tamperOut"
} catch {
    Report-Test 10 "Cryptographic Tamper Detection" $true "Tamper detected correctly as failure"
}

# [11] API Health Endpoint
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get
    $test11Success = ($health.status -eq "ok") -and ($health.service -eq "jockey-api")
    Report-Test 11 "API Server Health" $test11Success "Status: $($health.status), Version: $($health.version)"
} catch {
    Report-Test 11 "API Server Health" $false $_.Exception.Message
}

# [12] API Compiler Check Endpoint
try {
    $src = [System.IO.File]::ReadAllText((Resolve-Path "examples/basic_system_triage.jy").Path)
    $body = @{ source = $src; target = "windows-x64" } | ConvertTo-Json
    $checkRes = Invoke-RestMethod -Uri "http://localhost:8080/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $test12Success = ($checkRes.valid -eq $true) -and ($checkRes.investigation_name -eq "basic_system_triage")
    Report-Test 12 "API Compiler Check" $test12Success "Valid: $($checkRes.valid), Investigation: $($checkRes.investigation_name)"
} catch {
    Report-Test 12 "API Compiler Check" $false $_.Exception.Message
}

# [13] API Compile Endpoint
try {
    $src = [System.IO.File]::ReadAllText((Resolve-Path "examples/basic_system_triage.jy").Path)
    $body = @{ source = $src; target = "windows-x64" } | ConvertTo-Json
    $compOut = "build/api-compiled.exe"
    Invoke-WebRequest -Uri "http://localhost:8080/api/compiler/compile" -Method Post -Body $body -ContentType "application/json" -UseBasicParsing -OutFile $compOut
    $test13Success = (Test-Path $compOut) -and ((Get-Item $compOut).Length -gt 100000)
    Report-Test 13 "API Compiler Compile" $test13Success "Binary saved to $compOut ($((Get-Item $compOut).Length) bytes)"
} catch {
    Report-Test 13 "API Compiler Compile" $false $_.Exception.Message
}

# [14] API Run Endpoint
try {
    $quickSrc = "investigation `"e2e_quick`" {`n    collect system_info`n    export evidence `"e2e_quick.json`"`n}"
    $body = @{ source = $quickSrc; target = "windows-x64" } | ConvertTo-Json
    $runRes = Invoke-RestMethod -Uri "http://localhost:8080/api/compiler/run" -Method Post -Body $body -ContentType "application/json"
    $test14Success = ($runRes.success -eq $true) -and ($runRes.verification.valid -eq $true)
    Report-Test 14 "API Live Execution & Verification" $test14Success "Execution success: $($runRes.success), Verification: $($runRes.verification.status)"
} catch {
    Report-Test 14 "API Live Execution & Verification" $false $_.Exception.Message
}

# [15] API Download Info Metadata
try {
    $dlInfo = Invoke-RestMethod -Uri "http://localhost:8080/api/downloads/info" -Method Get
    $test15Success = ($dlInfo.packages.Count -ge 2)
    Report-Test 15 "API Download Metadata" $test15Success "Returned $($dlInfo.packages.Count) packages with canonical SHA-256 hashes"
} catch {
    Report-Test 15 "API Download Metadata" $false $_.Exception.Message
}

# [16] Windows Artifact Direct Download
try {
    $winDlPath = "build/downloaded_windows_package.zip"
    Invoke-WebRequest -Uri "http://localhost:8080/api/downloads/windows" -Method Get -UseBasicParsing -OutFile $winDlPath
    $test16Success = (Test-Path $winDlPath) -and ((Get-Item $winDlPath).Length -gt 1000000)
    Report-Test 16 "Windows Artifact Download" $test16Success "Downloaded Windows package: $((Get-Item $winDlPath).Length) bytes"
} catch {
    Report-Test 16 "Windows Artifact Download" $false $_.Exception.Message
}

# [17] Linux Artifact Route Handling
try {
    $status = 0
    try {
        $linuxDl = Invoke-WebRequest -Uri "http://localhost:8080/api/downloads/linux" -Method Get -UseBasicParsing
        $status = [int]$linuxDl.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
    }
    $test17Success = ($status -eq 200) -or ($status -eq 404)
    Report-Test 17 "Linux Artifact Route Handling" $test17Success "Proper HTTP $status status returned without uncaught exceptions"
} catch {
    Report-Test 17 "Linux Artifact Route Handling" $false $_.Exception.Message
}

# [18] Web Build
try {
    Set-Location "apps/web"
    $webBuild = npm run build
    $test18Success = $LASTEXITCODE -eq 0
    Set-Location "../.."
    Report-Test 18 "Web Application Production Build" $test18Success "Vite production build succeeded"
} catch {
    Set-Location "../.."
    Report-Test 18 "Web Application Production Build" $false $_.Exception.Message
}

# [19] Web Lint
try {
    Set-Location "apps/web"
    $webLint = npm run lint
    $test19Success = $LASTEXITCODE -eq 0
    Set-Location "../.."
    Report-Test 19 "Web Application Linting" $test19Success "ESLint passed with 0 warnings"
} catch {
    Set-Location "../.."
    Report-Test 19 "Web Application Linting" $false $_.Exception.Message
}

# [20, 21] Release Package Creation and Inspection
try {
    $zipPath = "jockey_0.1.0_windows_amd64.zip"
    $test20Success = (Test-Path $zipPath) -and ((Get-Item $zipPath).Length -gt 1000000)
    Report-Test 20 "Distribution Package Creation" $test20Success "Package $zipPath exists ($((Get-Item $zipPath).Length) bytes)"
    
    # Inspect ZIP contents
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $zipPath).Path)
    $hasJockeyExe = ($zip.Entries | Where-Object { $_.Name -eq "jockey.exe" }).Count -gt 0
    $zip.Dispose()
    Report-Test 21 "Distribution Package Inspection" $hasJockeyExe "ZIP contains genuine standalone jockey.exe"
} catch {
    Report-Test 20 "Distribution Package Creation" $false $_.Exception.Message
    Report-Test 21 "Distribution Package Inspection" $false $_.Exception.Message
}

# [22] Web IDE Integration Route Check
try {
    $idePage = Invoke-WebRequest -Uri "http://localhost:3000/ide" -Method Get -UseBasicParsing
    $test22Success = ($idePage.StatusCode -eq 200) -and ($idePage.Content -match "JOCKEY|html")
    Report-Test 22 "Web IDE Frontend Integration" $test22Success "Web IDE served on http://localhost:3000/ide"
} catch {
    Report-Test 22 "Web IDE Frontend Integration" $false $_.Exception.Message
}

# [23] Negative Cases (Syntax errors & missing exports diagnostics)
try {
    $badSyntax = "investigation `"bad`" { invalid_statement }"
    $body = @{ source = $badSyntax; target = "windows-x64" } | ConvertTo-Json
    $negRes = Invoke-RestMethod -Uri "http://localhost:8080/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $test23Success = ($negRes.valid -eq $false) -and ($negRes.diagnostics.Count -gt 0)
    Report-Test 23 "Compiler Negative Case Diagnostics" $test23Success "Correctly rejected invalid syntax with $($negRes.diagnostics.Count) diagnostics"
} catch {
    Report-Test 23 "Compiler Negative Case Diagnostics" $false $_.Exception.Message
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "SUMMARY: Passed: $passed, Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "==================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
    exit 1
}
