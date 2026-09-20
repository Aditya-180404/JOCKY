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

- Docker & Docker Compose
- Rust 1.70+ (for local compiler development)
- Node.js 20+ (for frontend development)

### Development Setup

```bash
# Copy environment template
cp .env.example .env

# Start all services
docker compose up --build
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