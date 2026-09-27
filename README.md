# jockey

A local-first digital-forensics development platform with a domain-specific language for forensic investigations.

## Overview

jockey enables investigators to:
- Write forensic investigation programs using the jockey language
- Validate and compile programs into portable forensic tools
- Version and publish tools to a centralized repository
- Execute tools on authorized forensic/lab machines
- Collect and verify forensic evidence cryptographically
- View investigation results from a web dashboard

## Architecture

```
jockey Workspace
├── Web Frontend (React + TypeScript + Vite + Tailwind)
├── Web IDE (Monaco Editor)
├── jockey Language & Compiler (Rust)
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
jockey/
├── apps/
│   ├── web/          # Frontend application
│   └── api/          # Backend API
├── compiler/         # jockey compiler (Rust)
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
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Latest | Optional clean package/integration tests |
| Git | Any | Clone repository |

---

### Step 1 — Clone the Repository

```powershell
git clone https://github.com/Aditya-180404/jockey.git
cd jockey
```

---

### Step 2 — Start the Local API

```powershell
$env:JOCKEY_API_ADDR = "0.0.0.0:8080"
cargo run -p jockey-api
```

The local API exposes `/health` and compiler/download endpoints on port 8080. The current API does not require PostgreSQL, Redis, or MinIO to run these local workflows.

---

### Step 3 — Start the Web Frontend

Open a new terminal and run:

```powershell
cd apps\web
npm install          # first time only
npm run dev
```

You should see:
```
  VITE v5.x  ready in 500ms
  ➜  Local:   http://localhost:3000/
```

Open **http://localhost:3000** in your browser.

### Local Full-Stack Verification

Use separate terminals for the API and frontend. Do not terminate an API process you did not start.

```powershell
# Terminal 1: API
cargo run -p jockey-api

# Terminal 2: frontend
cd apps\web
npm ci
npm run dev
```

Verify `http://localhost:8080/health`, then open `http://localhost:3000/ide`. The IDE calls `/api/compiler/check`, `/api/compiler/compile`, `/api/compiler/run`, and `/api/compiler/verify`.

---

### Step 4 — Build the CLI

```powershell
cargo build --release -p jockey-cli
```

The CLI binary is created at `target\release\jockey.exe`.

Optionally add it to your PATH:

```powershell
$env:PATH += ";$PWD\target\release"
```

Verify:

```powershell
jockey --version
# jockey 0.1.0
```

---

### Step 5 — Run Your First Investigation

JOCKEY source files use the `.jy` extension.

```powershell
# Validate a .jy file
jockey validate examples\process_triage.jy

# Run an investigation (requires Rust/Cargo and the runtime source tree)
jockey run examples\process_triage.jy

# Verify the evidence file integrity
jockey verify process_triage_evidence.json
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

### Step 6 — Open the Web IDE

Navigate to **http://localhost:3000/ide** in your browser, or run:

```powershell
jockey ide
```

Write `.jy` code in the Monaco editor, click **Check** to validate, **Run** to collect evidence through the local API, and **Verify** to recheck evidence integrity. The current generated CLI run/build path still depends on the Rust toolchain and runtime source tree; packaged execution away from the source checkout is not yet release-ready.

---

## Language Example

```jockey
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

jockey is a **defensive** digital-forensics platform. It does not implement:
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
- [Capability Implementation Status](docs/capability-implementation-report.md)
- [Release Readiness Audit](docs/release-readiness-audit.md)

## License

MIT License - see [LICENSE](LICENSE) for details.