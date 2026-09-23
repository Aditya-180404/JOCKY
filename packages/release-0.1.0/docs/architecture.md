# TraceForge Architecture Specification

TraceForge is a domain-specific language (DSL), native optimizing compiler, and forensic execution runtime designed for digital forensics, incident response (DFIR), and security analysis.

```text
               TraceForge Architecture
+-------------------------------------------------------+
|                 TraceForge DSL (.tfg)                |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                    Compiler Pipeline                  |
|  Lexer  -->  Parser  -->  AST  -->  Semantic  -->  IR |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                     Code Generator                    |
|   Target Matrix: windows-x64, linux-x64, arm64 targets |
|   Outputs: Standalone Native Forensic Executable      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                 Forensic Runtime Engine               |
|  - runtime/system (OS, kernel, CPU, memory, uptime)   |
|  - runtime/process (PIDs, cmdlines, hashes, parents)  |
|  - runtime/network (TCP/UDP sockets, endpoints, PIDs) |
|  - runtime/filesystem (Walkdir, SHA-256, timestamps)  |
|  - runtime/logs (Journald, syslog, Windows events)    |
|  - runtime/security (Suspicious commandline/network)  |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|               Evidence & Cryptographic Layer          |
|  - Deterministic JSON Evidence Envelope               |
|  - SHA-256 Cryptographic Hash Sidecar (.meta.json)    |
|  - Merkle Tree & Proof Generation                     |
|  - Blockchain Anchor Interface (Proof of Existence)   |
|  - Read-Only Forensics & Non-Repudiation Chain        |
+-------------------------------------------------------+
```

---

## 1. Core Principles

1. **Read-Only Forensic Safety**: TraceForge collection primitives never alter system state, install persistent drivers, modify system files, or alter evidence. All collection operations are non-destructive.
2. **Deterministic Cryptographic Verification**: Every artifact produces a canonical SHA-256 digest and sidecar metadata file recording the investigation name, host identifier, execution timestamp, and source hash. Tampered files are rejected immediately.
3. **Standalone Native Deployment**: Compiled investigation binaries run without external runtime dependencies or interpreters on the target host.
4. **Strict Capability Model**: The compiler automatically infers required operating system capabilities (e.g. `ProcessRead`, `NetworkRead`, `SystemInfoRead`, `FilesystemRead`) during semantic analysis.
5. **Full Web & API Integration**: The platform provides a modern Web IDE with syntax highlighting, compiler diagnostics, and an Axum-based API server with Argon2 password hashing, JWT sessions, and PostgreSQL audit logging.

---

## 2. Monorepo Structure

```text
TRACEFORGE/
├── apps/
│   ├── api/             # Axum REST API server (auth, tools, investigations, evidence)
│   └── web/             # React + Vite + TypeScript web interface & Web IDE
├── compiler/
│   ├── ast/             # Abstract Syntax Tree definitions & diagnostics
│   ├── backend/         # Code generation backend for target platforms
│   ├── cli/             # `traceforge` CLI executable
│   ├── ir/              # Intermediate Representation & serialization
│   ├── lexer/           # Token scanner & span tracking
│   ├── parser/          # Recursive descent parser with error recovery
│   └── semantic/        # Semantic analysis & capability inference
├── runtime/
│   ├── evidence/        # Evidence envelope, hashing, Merkle trees & verification
│   ├── filesystem/      # Read-only filesystem walker & hash calculator
│   ├── logs/            # Forensic log parser & normalizer
│   ├── network/         # Platform network connection enumeration
│   ├── process/         # Platform process enumeration & metadata extractor
│   ├── security/        # Forensic anomaly detection & security heuristics
│   └── system/          # Platform system & OS telemetry collector
├── examples/            # Canonical .tfg investigation scripts
├── packages/            # Release archives, manifests, and shared types
└── docs/                # Architecture, DSL, CLI, and forensic documentation
```
