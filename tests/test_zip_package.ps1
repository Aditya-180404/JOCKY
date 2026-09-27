$ErrorActionPreference = "Stop"

$tempBase = [System.IO.Path]::GetTempPath()
$randId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$tempDir = Join-Path $tempBase ("jockey_zip_test_" + $randId)

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Write-Host "Extracting jockey_0.1.0_windows_amd64.zip to: $tempDir"

Expand-Archive -Path "jockey_0.1.0_windows_amd64.zip" -DestinationPath $tempDir -Force
$zipExe = Join-Path $tempDir "jockey.exe"

if (-not (Test-Path $zipExe)) {
    throw "jockey.exe not found in extracted zip archive!"
}
Write-Host "Extracted jockey.exe size: $((Get-Item $zipExe).Length) bytes"

Write-Host "--- Testing: jockey.exe --version ---"
& $zipExe --version

Write-Host "--- Testing: jockey.exe --help ---"
& $zipExe --help | Select-Object -First 6

Write-Host "--- Testing: jockey.exe capabilities --format json ---"
$capsJson = & $zipExe capabilities --format json
Write-Host "Capabilities count in JSON: $(($capsJson | ConvertFrom-Json).Count)"

Write-Host "--- Testing: jockey.exe doctor ---"
& $zipExe doctor

Write-Host "--- Testing: jockey.exe check examples\complete_forensic_triage.jy ---"
& $zipExe check examples\complete_forensic_triage.jy

Write-Host "--- Testing: jockey.exe run examples\basic_system_triage.jy ---"
& $zipExe run examples\basic_system_triage.jy --output $tempDir

$evidenceFile = Join-Path $tempDir "system_triage.json"
if (-not (Test-Path $evidenceFile)) {
    throw "Evidence file was not created by extracted binary!"
}
Write-Host "Evidence generated: $evidenceFile ($((Get-Item $evidenceFile).Length) bytes)"

Write-Host "--- Testing: jockey.exe verify evidence.json ---"
& $zipExe verify $evidenceFile

Remove-Item -Recurse -Force $tempDir
Write-Host "SUCCESS: Extracted ZIP binary passed all verification checks!"
