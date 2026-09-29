$ErrorActionPreference = 'Continue'

function Test-Command($Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { Write-Host "[PASS] ${Name}: $($command.Source)" -ForegroundColor Green; return $true }
    Write-Host "[FAIL] $Name is not available" -ForegroundColor Red
    return $false
}

Write-Host 'JOCKY DEVELOPMENT DOCTOR' -ForegroundColor Cyan
$null = Test-Command git
$null = Test-Command cargo
$null = Test-Command rustc
$null = Test-Command node
$null = Test-Command npm
$dockerOk = Test-Command docker

if ($dockerOk) {
    docker compose ps
}

$ports = @(3000, 8080)
foreach ($port in $ports) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listener) { Write-Host "[PASS] Port $port is listening" -ForegroundColor Green }
    else { Write-Host "[INFO] Port $port is not listening" -ForegroundColor Yellow }
}

try {
    $health = Invoke-RestMethod -Uri 'http://localhost:8080/health' -TimeoutSec 3
    if ($health.status -eq 'ok') { Write-Host '[PASS] JOCKY API health' -ForegroundColor Green }
    else { Write-Host '[FAIL] JOCKY API returned an unexpected health response' -ForegroundColor Red }
} catch {
    Write-Host '[INFO] JOCKY API is not reachable' -ForegroundColor Yellow
}

try {
    $frontend = Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:3000/' -TimeoutSec 3
    if ($frontend.StatusCode -eq 200) { Write-Host '[PASS] JOCKY frontend' -ForegroundColor Green }
} catch {
    Write-Host '[INFO] JOCKY frontend is not reachable' -ForegroundColor Yellow
}

if (Test-Path '.\target\release\jocky.exe') {
    Write-Host '[PASS] Release CLI exists' -ForegroundColor Green
    & .\target\release\jocky.exe --version
} else {
    Write-Host '[INFO] Release CLI not built' -ForegroundColor Yellow
}
