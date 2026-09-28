$ErrorActionPreference = "Stop"

$tempBase = [System.IO.Path]::GetTempPath()
$randId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$tempDir = Join-Path $tempBase ("jocky_exe_test_" + $randId)

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$downloadedExe = Join-Path $tempDir "jocky.exe"
Write-Host "Downloading standalone jocky.exe from API to: $downloadedExe"

Invoke-WebRequest -Uri "http://localhost:8080/api/downloads/jocky.exe" -OutFile $downloadedExe -UseBasicParsing

if (-not (Test-Path $downloadedExe)) {
    throw "jocky.exe was not downloaded!"
}
Write-Host "Downloaded standalone jocky.exe size: $((Get-Item $downloadedExe).Length) bytes"

Write-Host "--- Testing: jocky.exe --version ---"
& $downloadedExe --version

Write-Host "--- Testing: jocky.exe --help ---"
& $downloadedExe --help | Select-Object -First 6

Write-Host "--- Testing: jocky.exe capabilities --format json ---"
$capsJson = & $downloadedExe capabilities --format json
Write-Host "Capabilities count in JSON: $(($capsJson | ConvertFrom-Json).Count)"

Write-Host "--- Testing: jocky.exe doctor ---"
& $downloadedExe doctor

Write-Host "--- Testing: jocky.exe check examples\complete_forensic_triage.jy ---"
& $downloadedExe check examples\complete_forensic_triage.jy

Write-Host "--- Testing: jocky.exe run examples\basic_system_triage.jy ---"
& $downloadedExe run examples\basic_system_triage.jy --output $tempDir

$evidenceFile = Join-Path $tempDir "system_triage.json"
if (-not (Test-Path $evidenceFile)) {
    throw "Evidence file was not created by downloaded binary!"
}
Write-Host "Evidence generated: $evidenceFile ($((Get-Item $evidenceFile).Length) bytes)"

Write-Host "--- Testing: jocky.exe verify evidence.json ---"
& $downloadedExe verify $evidenceFile

Remove-Item -Recurse -Force $tempDir
Write-Host "SUCCESS: Downloaded standalone EXE passed all verification checks!"
