$ErrorActionPreference = 'Stop'

Write-Host 'Starting JOCKY development environment' -ForegroundColor Cyan
Write-Host 'Starting containers (API & Web)...'
docker compose up -d
docker compose ps

$env:RUST_LOG = 'info'

Get-Process jocky-api -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host ''
Write-Host 'JOCKY services ready:' -ForegroundColor Green
Write-Host '  API:      http://localhost:8080'
Write-Host '  Frontend: http://localhost:3000'
Write-Host '  Web IDE:  http://localhost:3000/ide'
Write-Host ''
Write-Host 'Run .\scripts\doctor.ps1 to inspect service health.' -ForegroundColor Yellow
