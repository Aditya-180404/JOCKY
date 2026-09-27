$ErrorActionPreference = "Stop"

$tempBase = [System.IO.Path]::GetTempPath()
$randId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$tempDir = Join-Path $tempBase ("jockey_exe_test_" + $randId)

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$downloadedExe = Join-Path $tempDir "jockey.exe"
Write-Host "Downloading standalone jockey.exe from API to: $downloadedExe"

Invoke-WebRequest -Uri "http://localhost:8080/api/downloads/jockey.exe" -OutFile $downloadedExe -UseBasicParsing

if (-not (Test-Path $downloadedExe)) {
    throw "jockey.exe was not downloaded!"
}
Write-Host "Downloaded standalone jockey.exe size: $((Get-Item $downloadedExe).Length) bytes"

Write-Host "--- Testing: jockey.exe --version ---"
& $downloadedExe --version

Write-Host "--- Testing: jockey.exe --help ---"
& $downloadedExe --help | Select-Object -First 6

Write-Host "--- Testing: jockey.exe capabilities --format json ---"
$capsJson = & $downloadedExe capabilities --format json
Write-Host "Capabilities count in JSON: $(($capsJson | ConvertFrom-Json).Count)"

Write-Host "--- Testing: jockey.exe doctor ---"
& $downloadedExe doctor

Write-Host "--- Testing: jockey.exe check examples\complete_forensic_triage.jy ---"
& $downloadedExe check examples\complete_forensic_triage.jy

Write-Host "--- Testing: jockey.exe run examples\basic_system_triage.jy ---"
& $downloadedExe run examples\basic_system_triage.jy --output $tempDir

$evidenceFile = Join-Path $tempDir "system_triage.json"
if (-not (Test-Path $evidenceFile)) {
    throw "Evidence file was not created by downloaded binary!"
}
Write-Host "Evidence generated: $evidenceFile ($((Get-Item $evidenceFile).Length) bytes)"

Write-Host "--- Testing: jockey.exe verify evidence.json ---"
& $downloadedExe verify $evidenceFile

Remove-Item -Recurse -Force $tempDir
Write-Host "SUCCESS: Downloaded standalone EXE passed all verification checks!"
