$ErrorActionPreference = 'Stop'

Write-Host 'Starting TRACEFORGE development environment' -ForegroundColor Cyan
docker compose up -d --wait postgres redis minio
docker compose ps

$env:DATABASE_URL = 'postgres://traceforge:traceforge_dev@localhost:5433/traceforge'
$env:REDIS_URL = 'redis://localhost:6379'
$env:MINIO_ENDPOINT = 'http://localhost:9000'
$env:MINIO_ACCESS_KEY = 'traceforge'
$env:MINIO_SECRET_KEY = 'traceforge_dev'
$env:MINIO_BUCKET = 'traceforge-artifacts'
$env:RUST_LOG = 'info'

Get-Process traceforge-api -ErrorAction SilentlyContinue | Stop-Process -Force

Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$PWD'; cargo run -p traceforge-api"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$PWD\apps\web'; npm run dev"

Write-Host ''
Write-Host 'TRACEFORGE services starting:' -ForegroundColor Green
Write-Host '  API:      http://localhost:8080'
Write-Host '  Frontend: http://localhost:3000'
Write-Host '  Web IDE:  http://localhost:3000/ide'
Write-Host ''
Write-Host 'Run .\scripts\doctor.ps1 to inspect service health.' -ForegroundColor Yellow
