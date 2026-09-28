$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$staging = Join-Path $PSScriptRoot 'windows-stage'
$package = Join-Path $root 'jocky_0.1.0_windows_amd64.zip'

Write-Host "Building release binary for jocky-cli..."
Set-Location $root
cargo build --release -p jocky-cli

if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force $staging | Out-Null

Write-Host "Setting up staging directory..."
Copy-Item (Join-Path $root 'target/release/jocky.exe') $staging

Write-Host "Creating Windows archive..."
if (Test-Path $package) { Remove-Item $package -Force }
Compress-Archive -Path "$staging\*" -DestinationPath $package

Write-Host "Package successfully generated at: $package"
