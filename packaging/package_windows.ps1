$ErrorActionPreference = "Stop"

Copy-Item "target/release/jockey.exe" "jockey.exe" -Force
if (-not (Test-Path "packages")) { New-Item -ItemType Directory -Path "packages" -Force | Out-Null }
Copy-Item "target/release/jockey.exe" "packages/jockey.exe" -Force

$tempBase = [System.IO.Path]::GetTempPath()
$randId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$zipTemp = Join-Path $tempBase ("jockey_pkg_" + $randId)

New-Item -ItemType Directory -Path $zipTemp -Force | Out-Null
Copy-Item "target/release/jockey.exe" (Join-Path $zipTemp "jockey.exe")
Compress-Archive -Path (Join-Path $zipTemp "jockey.exe") -DestinationPath "jockey_0.1.0_windows_amd64.zip" -Force
Copy-Item "jockey_0.1.0_windows_amd64.zip" "packages/jockey_0.1.0_windows_amd64.zip" -Force
Remove-Item -Recurse -Force $zipTemp

Write-Host "Windows artifacts updated successfully:"
Get-Item "jockey_0.1.0_windows_amd64.zip", "jockey.exe", "jockey_0.1.0_amd64.deb" | Format-Table Name, Length, LastWriteTime
