$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$staging = Join-Path $PSScriptRoot 'debian-stage'
$package = Join-Path $root 'traceforge_0.1.0_amd64.deb'

if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force (Join-Path $staging 'usr/bin') | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'debian/DEBIAN') (Join-Path $staging 'DEBIAN') -Recurse

$mount = "$($root -replace '\\','/'):/src"
docker run --rm -v $mount -w /src rust:latest cargo build --release -p traceforge-cli
Copy-Item (Join-Path $root 'target/release/traceforge') (Join-Path $staging 'usr/bin/traceforge')

docker run --rm -v "$($staging -replace '\\','/'):/pkg" -v "$($root -replace '\\','/'):/out" debian:trixie-slim sh -c 'chmod 755 /pkg/DEBIAN; chmod 755 /pkg/usr /pkg/usr/bin; chmod 644 /pkg/DEBIAN/control; dpkg-deb --build /pkg /out/traceforge_0.1.0_amd64.deb'
if ($LASTEXITCODE -ne 0) { throw "dpkg-deb failed with exit code $LASTEXITCODE" }
Write-Host "Package written to $package"
