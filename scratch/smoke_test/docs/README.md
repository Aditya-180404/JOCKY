# TraceForge

A cloud-based digital-forensics development and distribution platform with a domain-specific language for forensic investigations.

## Overview

TraceForge enables investigators to:
- Write forensic investigation programs using the TraceForge language
- Validate and compile programs into portable forensic tools
- Version and publish tools to a centralized repository
- Execute tools on authorized forensic/lab machines
- Collect and verify forensic evidence cryptographically
- View investigation results from a web dashboard

## Architecture

```
TraceForge Cloud
├── Web Frontend (React + TypeScript + Vite + Tailwind)
├── Web IDE (Monaco Editor)
├── TraceForge Language & Compiler (Rust)
├── Compiler Service (Rust worker)
├── Tool Repository
├── Investigation Management
├── Evidence Management & Integrity (SHA-256, Merkle trees)
├── Authentication & RBAC
├── Audit Logging
└── REST API
```

## Project Structure

```
traceforge/
├── apps/
│   ├── web/          # Frontend application
│   └── api/          # Backend API
├── compiler/         # TraceForge compiler (Rust)
│   ├── lexer/
│   ├── parser/
│   ├── ast/
│   ├── semantic/
│   ├── ir/
│   ├── backend/
│   └── cli/
├── runtime/          # Forensic runtime library (Rust)
│   ├── system/
│   ├── process/
│   ├── network/
│   ├── filesystem/
│   ├── logs/
│   └── evidence/
├── services/
│   └── compiler-worker/
├── packages/
│   ├── shared-types/
│   └── api-client/
├── examples/
├── tests/
├── docs/
└── docker/
```

## Getting Started

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| [Rust](https://rustup.rs/) | 1.70+ | Compiler, API, CLI |
| [Node.js](https://nodejs.org/) | 20+ | Web frontend |
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Latest | PostgreSQL, Redis, MinIO |
| Git | Any | Clone repository |

---

### Step 1 — Clone the Repository

```powershell
git clone https://github.com/your-org/traceforge.git
cd traceforge
```

---

### Step 2 — Start Infrastructure (PostgreSQL + Redis + MinIO)

```powershell
# Copy environment template (only needed once)
copy .env.example .env

# Start backing services in the background
docker compose up -d postgres redis minio
```

Wait ~10 seconds for services to be ready. Verify with:

```powershell
docker compose ps
```

All three services should show **Up** / **healthy**.

---

### Step 3 — Start the API Server

Open a new terminal and run:

```powershell
$env:DATABASE_URL = "postgres://traceforge:traceforge_dev@localhost:5433/traceforge"
$env:RUST_LOG = "info"
cargo run -p traceforge-api
```

You should see:
```
INFO  Connected to PostgreSQL
INFO  Database migrations applied
INFO  Connected to Redis
INFO  Configured S3 client for MinIO
INFO  API server listening on http://0.0.0.0:8080
```

---

### Step 4 — Start the Web Frontend

Open a new terminal and run:

```powershell
cd apps\web
npm install          # first time only
npm run dev
```

You should see:
```
  VITE v5.x  ready in 500ms
  ➜  Local:   http://localhost:5173/
```

Open **http://localhost:5173** in your browser.

---

### Step 5 — Build the CLI

```powershell
cargo build --release -p traceforge-cli
```

The CLI binary is created at `target\release\traceforge.exe`.

Optionally add it to your PATH:

```powershell
$env:PATH += ";$PWD\target\release"
```

Verify:

```powershell
traceforge --version
# traceforge 0.1.0
```

---

### Step 6 — Run Your First Investigation

```powershell
# Validate a .tfg file
traceforge validate examples\process_triage.tfg

# Compile + execute (auto-detects Windows target)
traceforge run examples\process_triage.tfg

# Verify the evidence file integrity
traceforge verify process_triage_evidence.json
```

Expected output:
```
Integrity: VALID
SHA-256:   <hash>
Investigation: process_triage
Host:      YOUR-HOSTNAME
Collected: 2026-09-23T...
```

---

### Step 7 — Open the Web IDE

Navigate to **http://localhost:5173/ide** in your browser, or run:

```powershell
traceforge ide
```

Write `.tfg` code in the Monaco editor, click **Check** to validate, or **Execute** to run live forensic collection through the API.

---

### Quick-Start Script (All-in-One)

Save as `start.ps1` and run from the repo root:

```powershell
# start.ps1 — Start all TRACEFORGE services

Write-Host "Starting infrastructure..." -ForegroundColor Cyan
docker compose up -d postgres redis minio

Write-Host "Waiting for services to be ready..."
Start-Sleep -Seconds 8

Write-Host "Starting API server (background)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList `
  '-NoExit', '-Command', `
  '$env:DATABASE_URL="postgres://traceforge:traceforge_dev@localhost:5433/traceforge"; $env:RUST_LOG="info"; cargo run -p traceforge-api'

Write-Host "Starting web frontend (background)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList `
  '-NoExit', '-Command', `
  'cd apps\web; npm run dev'

Write-Host ""
Write-Host "TraceForge is starting up!" -ForegroundColor Green
Write-Host "  Web UI:  http://localhost:5173"
Write-Host "  Web IDE: http://localhost:5173/ide"
Write-Host "  API:     http://localhost:8080"
```

```powershell
.\start.ps1
```


## Language Example

```traceforge
investigation "process_triage" {
    collect system_info
    collect processes {
        pid
        name
        parent
        command_line
        start_time
        hash.sha256
    }
    collect network_connections
    export evidence "process_triage.json"
}
```

## Security

TraceForge is a **defensive** digital-forensics platform. It does not implement:
- Antivirus/EDR bypass techniques
- Process injection or hollowing
- Credential theft
- Persistence mechanisms
- Covert C2 infrastructure
- Malicious payload generation

All operations are explicit, auditable, permission-controlled, and reproducible.

## Documentation

- [Architecture](docs/architecture.md)
- [Language Reference](docs/language.md)
- [Compiler](docs/compiler.md)
- [API](docs/api.md)
- [Security Model](docs/security.md)
- [Development](docs/development.md)
- [Deployment](docs/deployment.md)
- [Threat Model](docs/threat-model.md)

## License

MIT License - see [LICENSE](LICENSE) for details.