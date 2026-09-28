# JOCKY Comprehensive Negative Test Suite
# Tests all error scenarios mandated by Section 17:
# 1. Invalid syntax
# 2. Unknown capability
# 3. Unsupported target
# 4. Windows-only capability on Linux target
# 5. Missing required export block / incomplete investigation
# 6. Malformed JSON Request
# 7. Nonexistent Investigation File CLI
# 8. Missing Evidence File Verification
# 9. Path Traversal Protection on Download API
# 10. Nonexistent Download Filename

param(
    [string]$ApiBaseUrl = $(if ($env:JOCKY_API_BASE_URL) { $env:JOCKY_API_BASE_URL } else { "http://localhost:8080" })
)

$negativeRunId = [guid]::NewGuid().ToString("N")
$cliErrorPath = Join-Path $env:TEMP "jocky-negative-cli-$negativeRunId.txt"
$verifyErrorPath = Join-Path $env:TEMP "jocky-negative-verify-$negativeRunId.txt"

$passed = 0
$failed = 0

function Report-Neg($id, $name, $success, $detail) {
    if ($success) {
        Write-Host "[PASS] [$id] $name - $detail" -ForegroundColor Green
        $global:passed++
    } else {
        Write-Host "[FAIL] [$id] $name - $detail" -ForegroundColor Red
        $global:failed++
    }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "JOCKY COMPREHENSIVE NEGATIVE TEST SUITE" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Invalid syntax
try {
    $badSyntax = "investigation `"broken`" { invalid_keyword unknown_call; }"
    $body = @{ source = $badSyntax; target = "windows-x64" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $ok = ($res.valid -eq $false) -and ($res.diagnostics.Count -gt 0)
    Report-Neg 1 "Invalid Syntax Rejection" $ok "Diagnosed $($res.diagnostics.Count) errors: $($res.diagnostics[0].message)"
} catch {
    Report-Neg 1 "Invalid Syntax Rejection" $false $_.Exception.Message
}

# 2. Unknown capability
try {
    $unkCap = "investigation `"unk`" { collect non_existent_capability_xyz export evidence `"out.json`" }"
    $body = @{ source = $unkCap; target = "windows-x64" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $diagText = ($res.diagnostics | ForEach-Object { $_.message }) -join " "
    $ok = ($res.valid -eq $false) -and ($diagText -match "Expected collect target|unknown|unrecognized|Unknown capability|error")
    Report-Neg 2 "Unknown Capability Rejection" $ok "Compiler rejected unknown capability: $diagText"
} catch {
    Report-Neg 2 "Unknown Capability Rejection" $false $_.Exception.Message
}

# 3. Unsupported target
try {
    $src = "investigation `"tgt_test`" { collect system_info export evidence `"out.json`" }"
    $body = @{ source = $src; target = "solaris-sparc" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $diagText = ($res.diagnostics | ForEach-Object { $_.message }) -join " "
    $ok = ($res.valid -eq $false) -and ($diagText -match "Unsupported target|target|unsupported")
    Report-Neg 3 "Unsupported Target Rejection" $ok "Rejected target 'solaris-sparc': $diagText"
} catch {
    Report-Neg 3 "Unsupported Target Rejection" $false $_.Exception.Message
}

# 4. Windows-only capability on Linux target
try {
    $winOnly = "investigation `"win_on_linux`" { collect registry `"HKLM`" `"SOFTWARE`" export evidence `"out.json`" }"
    $body = @{ source = $winOnly; target = "linux-x64" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $diagText = ($res.diagnostics | ForEach-Object { $_.message }) -join " "
    $ok = ($res.valid -eq $false) -and ($diagText -match "Windows|not supported|platform")
    Report-Neg 4 "Windows-only Capability on Linux Target" $ok "Target compatibility check caught restriction: $diagText"
} catch {
    Report-Neg 4 "Windows-only Capability on Linux Target" $false $_.Exception.Message
}

# 5. Missing required export block / incomplete investigation
try {
    $noExport = "investigation `"missing_export`" { collect system_info }"
    $body = @{ source = $noExport; target = "windows-x64" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body $body -ContentType "application/json"
    $diagText = ($res.diagnostics | ForEach-Object { $_.message }) -join " "
    $ok = ($res.valid -eq $false) -or ($diagText -match "export|warning|missing")
    Report-Neg 5 "Investigation Specification Validation" $ok "Result: valid=$($res.valid), Diags: $diagText"
} catch {
    Report-Neg 5 "Investigation Specification Validation" $false $_.Exception.Message
}

# 6. Malformed JSON Request
try {
    $code = 0
    try {
        $res = Invoke-WebRequest -Uri "$ApiBaseUrl/api/compiler/check" -Method Post -Body "{ not_valid_json " -ContentType "application/json" -UseBasicParsing
        $code = [int]$res.StatusCode
    } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    }
    $ok = ($code -ge 400) -and ($code -lt 500)
    Report-Neg 6 "Malformed JSON Request Handling" $ok "Returned HTTP error $code"
} catch {
    Report-Neg 6 "Malformed JSON Request Handling" $false $_.Exception.Message
}

# 7. Nonexistent Investigation File CLI
try {
    $p = Start-Process -FilePath ".\target\release\jocky.exe" -ArgumentList "check nonexistent_file_xyz.jy" -NoNewWindow -Wait -PassThru -RedirectStandardError $cliErrorPath
    $code = $p.ExitCode
    $err = Get-Content $cliErrorPath -Raw -ErrorAction SilentlyContinue
    $ok = ($code -ne 0)
    Report-Neg 7 "CLI Nonexistent File Error" $ok "Exited with code ${code}: $($err.Trim())"
} catch {
    Report-Neg 7 "CLI Nonexistent File Error" $false $_.Exception.Message
}

# 8. Missing Evidence File Verification
try {
    $p = Start-Process -FilePath ".\target\release\jocky.exe" -ArgumentList "verify nonexistent_evidence.json" -NoNewWindow -Wait -PassThru -RedirectStandardError $verifyErrorPath
    $code = $p.ExitCode
    $err = Get-Content $verifyErrorPath -Raw -ErrorAction SilentlyContinue
    $ok = ($code -ne 0)
    Report-Neg 8 "Missing Evidence Verification Failure" $ok "Exited with code ${code}: $($err.Trim())"
} catch {
    Report-Neg 8 "Missing Evidence Verification Failure" $false $_.Exception.Message
}

# 9. Path Traversal Protection on Download API
try {
    $code = 0
    try {
        $res = Invoke-WebRequest -Uri "$ApiBaseUrl/api/downloads/../../Cargo.toml" -Method Get -UseBasicParsing
        $code = [int]$res.StatusCode
    } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    }
    # Should be 400 or 404, never 200
    $ok = ($code -eq 400) -or ($code -eq 404)
    Report-Neg 9 "Path Traversal Protection" $ok "Path traversal rejected with HTTP $code"
} catch {
    Report-Neg 9 "Path Traversal Protection" $false $_.Exception.Message
}

# 10. Nonexistent Download Filename
try {
    $code = 0
    try {
        $res = Invoke-WebRequest -Uri "$ApiBaseUrl/api/downloads/totally_bogus_package.xyz" -Method Get -UseBasicParsing
        $code = [int]$res.StatusCode
    } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    }
    $ok = ($code -eq 404)
    Report-Neg 10 "Invalid Download Filename" $ok "Nonexistent file returned HTTP 404"
} catch {
    Report-Neg 10 "Invalid Download Filename" $false $_.Exception.Message
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "NEGATIVE TEST SUMMARY: Passed: $passed, Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "==================================================" -ForegroundColor Cyan

if ($failed -gt 0) { exit 1 } else { exit 0 }
