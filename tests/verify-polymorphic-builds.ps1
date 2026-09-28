# Verify Polymorphic Builds (Windows / PowerShell)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

$Jockey = if (Test-Path "target\release\jockey.exe") { "target\release\jockey.exe" } else { "target\debug\jockey.exe" }

Write-Host "[1/3] Building polymorphic variant A"
& $Jockey compile examples/process_triage.jy --output build/polymorph-a --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates
$fileA = (Get-ChildItem -Path "build/polymorph-a" -Filter "*.exe" -Recurse | Select-Object -First 1).FullName
if (-not $fileA) {
    $fileA = (Get-ChildItem -Path "build/polymorph-a" -Filter "*.manifest.json" -Recurse | Select-Object -First 1).FullName
}
$shaA = (Get-FileHash -Path $fileA -Algorithm SHA256).Hash

Start-Sleep -Seconds 1

Write-Host "[2/3] Building polymorphic variant B"
& $Jockey compile examples/process_triage.jy --output build/polymorph-b --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates
$fileB = (Get-ChildItem -Path "build/polymorph-b" -Filter "*.exe" -Recurse | Select-Object -First 1).FullName
if (-not $fileB) {
    $fileB = (Get-ChildItem -Path "build/polymorph-b" -Filter "*.manifest.json" -Recurse | Select-Object -First 1).FullName
}
$shaB = (Get-FileHash -Path $fileB -Algorithm SHA256).Hash

Start-Sleep -Seconds 1

Write-Host "[3/3] Building polymorphic variant C"
& $Jockey compile examples/process_triage.jy --output build/polymorph-c --polymorphic --cfg-flatten --encrypt-strings --junk-instructions --opaque-predicates
$fileC = (Get-ChildItem -Path "build/polymorph-c" -Filter "*.exe" -Recurse | Select-Object -First 1).FullName
if (-not $fileC) {
    $fileC = (Get-ChildItem -Path "build/polymorph-c" -Filter "*.manifest.json" -Recurse | Select-Object -First 1).FullName
}
$shaC = (Get-FileHash -Path $fileC -Algorithm SHA256).Hash

if ($shaA -eq $shaB -or $shaB -eq $shaC -or $shaA -eq $shaC) {
    Write-Error "Polymorphic build verification failed: hashes were not unique!`nA=$shaA`nB=$shaB`nC=$shaC"
    exit 1
}

Write-Host "Polymorphic build verification passed!"
Write-Host "A: $shaA"
Write-Host "B: $shaB"
Write-Host "C: $shaC"
