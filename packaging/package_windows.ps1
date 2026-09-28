$ErrorActionPreference = "Stop"

Copy-Item "target/release/jocky.exe" "jocky.exe" -Force
if (-not (Test-Path "packages")) { New-Item -ItemType Directory -Path "packages" -Force | Out-Null }
Copy-Item "target/release/jocky.exe" "packages/jocky.exe" -Force

$tempBase = [System.IO.Path]::GetTempPath()
$randId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$zipTemp = Join-Path $tempBase ("jocky_pkg_" + $randId)

New-Item -ItemType Directory -Path $zipTemp -Force | Out-Null
Copy-Item "target/release/jocky.exe" (Join-Path $zipTemp "jocky.exe")
Compress-Archive -Path (Join-Path $zipTemp "jocky.exe") -DestinationPath "jocky_0.1.0_windows_amd64.zip" -Force
Copy-Item "jocky_0.1.0_windows_amd64.zip" "packages/jocky_0.1.0_windows_amd64.zip" -Force
Remove-Item -Recurse -Force $zipTemp

Write-Host "Windows artifacts updated successfully:"
Get-Item "jocky_0.1.0_windows_amd64.zip", "jocky.exe", "jocky_0.1.0_amd64.deb" | Format-Table Name, Length, LastWriteTime
