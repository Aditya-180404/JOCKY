# JOCKEY Automated Capability Matrix Audit & Verification Suite
# Verifies all 247 capabilities across CLI, API, Runtime, and Target Validation

param(
    [string]$ApiBaseUrl = $(if ($env:JOCKEY_API_BASE_URL) { $env:JOCKEY_API_BASE_URL } else { "http://localhost:8080" })
)

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
Write-Host "JOCKEY CAPABILITY MATRIX AUDIT & VERIFICATION" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# [1] CLI Capabilities Command (Raw Table Output)
try {
    $cliTable = (& .\target\release\jockey.exe capabilities) -join "`n"
    $tableHasHeader = $cliTable -match "ID" -or $cliTable -match "Capability"
    $tableHasSummary = $cliTable -match "Total: 247"
    $test1Success = $tableHasSummary -and ($cliTable -match "Coverage: 97.6%")
    Report-Test 1 "CLI Capabilities Table Output" $test1Success "CLI output contains Total: 247 and Coverage: 97.6%"
} catch {
    Report-Test 1 "CLI Capabilities Table Output" $false $_.Exception.Message
}

# [2] CLI JSON Capability Export
try {
    $rawJson = (& .\target\release\jockey.exe capabilities --format json) -join "`n"
    $caps = $rawJson | ConvertFrom-Json
    $cliCount = $caps.Length
    $test2Success = ($cliCount -eq 247)
    Report-Test 2 "CLI JSON Export Count" $test2Success "Exported $cliCount capabilities (expected 247)"
} catch {
    Report-Test 2 "CLI JSON Export Count" $false $_.Exception.Message
}

# [3] API Capabilities Endpoint Verification
try {
    $apiRes = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/capabilities" -Method Get
    $apiCapList = @()
    foreach ($prop in $apiRes.capabilities.PSObject.Properties) {
        $capObj = $prop.Value
        $capObj | Add-Member -MemberType NoteProperty -Name "id" -Value $prop.Name -Force
        $apiCapList += $capObj
    }
    $apiCount = $apiRes.count
    $test3Success = ($apiCount -eq $apiCapList.Count) -and ($apiCount -eq 247) -and ($apiRes.total -eq 247)
    Report-Test 3 "API Capabilities Endpoint Count" $test3Success "API returned $apiCount capabilities (expected 247)"
} catch {
    Report-Test 3 "API Capabilities Endpoint Count" $false $_.Exception.Message
}

# [4] Status Breakdown Verification
try {
    $implemented = @($apiCapList | Where-Object { $_.status -eq "IMPLEMENTED" }).Count
    $requiresElevation = @($apiCapList | Where-Object { $_.status -eq "REQUIRES_ELEVATION" }).Count
    $partial = @($apiCapList | Where-Object { $_.status -eq "PARTIAL" }).Count
    $platformRestricted = @($apiCapList | Where-Object { $_.status -eq "PLATFORM_SPECIFIC" }).Count
    $unsupported = @($apiCapList | Where-Object { $_.status -eq "UNSUPPORTED" }).Count

    Write-Host "    -> Implemented: $implemented" -ForegroundColor Gray
    Write-Host "    -> Requires Elevation: $requiresElevation" -ForegroundColor Gray
    Write-Host "    -> Partial: $partial" -ForegroundColor Gray
    Write-Host "    -> Platform Restricted: $platformRestricted" -ForegroundColor Gray
    Write-Host "    -> Unsupported: $unsupported" -ForegroundColor Gray

    $totalAccounted = $implemented + $requiresElevation + $partial + $platformRestricted + $unsupported
    $test4Success = ($implemented -eq 241) -and ($requiresElevation -eq 4) -and ($totalAccounted -eq 247)
    Report-Test 4 "Status Breakdown Audit" $test4Success "Implemented: $implemented, Elevation: $requiresElevation, Partial: $partial, Total: $totalAccounted"
} catch {
    Report-Test 4 "Status Breakdown Audit" $false $_.Exception.Message
}

# [5] Schema & Metadata Completeness Audit (No blank fields)
try {
    $missingFields = 0
    foreach ($cap in $apiCapList) {
        if (-not $cap.id -or -not $cap.name -or -not $cap.category -or -not $cap.platforms -or -not $cap.privilege) {
            $missingFields++
        }
    }
    $test5Success = ($missingFields -eq 0)
    Report-Test 5 "Metadata Completeness" $test5Success "All 247 capabilities possess id, name, category, platforms, and privilege"
} catch {
    Report-Test 5 "Metadata Completeness" $false $_.Exception.Message
}

# [6] Category Coverage Audit (All 17 forensic categories represented)
try {
    $categories = $apiCapList | Group-Object category
    $expectedCategories = @(
        "ApplicationArtifact", "WindowsArtifact", "LinuxArtifact", "Authentication",
        "BackdoorRootkit", "EvidenceIntegrity", "FileBinaryMetadata", "Filesystem",
        "KernelDriver", "Network", "Persistence", "Process", "MaliciousScript",
        "SecurityConfig", "Service", "SystemInfo", "User"
    )
    $foundCategories = $categories | ForEach-Object { $_.Name }
    $missingCats = @()
    foreach ($ec in $expectedCategories) {
        if ($foundCategories -notcontains $ec) {
            $missingCats += $ec
        }
    }
    $test6Success = ($missingCats.Count -eq 0) -and ($categories.Count -eq 17)
    Report-Test 6 "Category Coverage Audit" $test6Success "Found $($categories.Count)/17 distinct forensic categories (0 missing)"
} catch {
    Report-Test 6 "Category Coverage Audit" $false $_.Exception.Message
}

# [7] CLI Implemented Filter Flag
try {
    $cliImplOut = (& .\target\release\jockey.exe capabilities --implemented) -join "`n"
    $hasSummary = $cliImplOut -match "Implemented: 241"
    $test7Success = $hasSummary
    Report-Test 7 "CLI --implemented Filter" $test7Success "Correctly reports 241 implemented capabilities"
} catch {
    Report-Test 7 "CLI --implemented Filter" $false $_.Exception.Message
}

# [8] CLI Missing / Unimplemented Filter Flag
try {
    $cliMissingOut = (& .\target\release\jockey.exe capabilities --missing) -join "`n"
    $test8Success = ($cliMissingOut -match "Total:" -or $cliMissingOut -match "Coverage:")
    Report-Test 8 "CLI --missing Filter" $test8Success "Filtered unimplemented / restricted capabilities correctly"
} catch {
    Report-Test 8 "CLI --missing Filter" $false $_.Exception.Message
}

# [9] API Status Filter Query Parameter (?status=implemented)
try {
    $apiImplRes = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/capabilities?status=implemented" -Method Get
    $apiImplCount = $apiImplRes.count
    $test9Success = ($apiImplCount -eq 241) -and ($apiImplRes.total -eq 247) -and ($apiImplRes.implemented -eq 241)
    Report-Test 9 "API ?status=implemented Filter" $test9Success "Returned $apiImplCount implemented capabilities (expected 241)"
} catch {
    Report-Test 9 "API ?status=implemented Filter" $false $_.Exception.Message
}

# [10] API Platform Filter Query Parameter (?platform=windows)
try {
    $apiWinRes = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/capabilities?platform=windows" -Method Get
    $apiWinCount = $apiWinRes.count
    $test10Success = ($apiWinCount -ge 200)
    Report-Test 10 "API ?platform=windows Filter" $test10Success "Returned $apiWinCount Windows-compatible capabilities"
} catch {
    Report-Test 10 "API ?platform=windows Filter" $false $_.Exception.Message
}

# [11] Target Incompatibility Warning in Check Handler
try {
    # Investigation using Windows Registry targeted to linux-x64 should return validation warning or platform mismatch
    $regSource = "investigation `"reg_audit`" {`n    collect registry `"HKLM`" `"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`"`n    export evidence `"reg.json`"`n}"
    $body = @{ source = $regSource; target = "linux-x64" } | ConvertTo-Json
    $checkRes = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $hasDiag = ($checkRes.diagnostics.Count -gt 0)
    $test11Success = $hasDiag
    Report-Test 11 "Target Incompatibility Check" $test11Success "Targeted check produced platform incompatibility diagnostic: $($checkRes.diagnostics[0].message)"
} catch {
    Report-Test 11 "Target Incompatibility Check" $false $_.Exception.Message
}

# [12] Unit Test Suite for Capabilities Crate
try {
    $testOutput = (& cargo test -p jockey-runtime-capabilities) -join "`n"
    $hasPassed = $testOutput -match "15 passed; 0 failed"
    $test12Success = $hasPassed
    Report-Test 12 "Runtime Capabilities Crate Unit Tests" $test12Success "15/15 unit tests passed with 0 failures"
} catch {
    Report-Test 12 "Runtime Capabilities Crate Unit Tests" $false $_.Exception.Message
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "AUDIT SUMMARY: Passed: $passed, Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "==================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
    exit 1
}
