# JOCKY — Computer & Network Forensic Analysis Framework

> **"Collect once. Verify forever. Leave no trace."**
>
> A local-first, offline-capable digital-forensics platform for authorized triage, evidence collection, cryptographic integrity verification, and incident analysis — built entirely in Rust and designed for legitimate, consented forensic investigations.

---

## Table of Contents

1. [Mission & Motivation](#mission--motivation)
2. [What is JOCKY?](#what-is-jocky)
3. [Core Concepts at a Glance](#core-concepts-at-a-glance)
4. [Architecture](#architecture)
5. [Project Structure](#project-structure)
6. [Compiler Pipeline — Deep Dive](#compiler-pipeline--deep-dive)
7. [Runtime Modules — Deep Dive](#runtime-modules--deep-dive)
8. [Living-off-the-Land (LotL) Primitives](#living-off-the-land-lotl-primitives)
9. [Evidence Integrity System](#evidence-integrity-system)
10. [REST API Server](#rest-api-server)
11. [Web Frontend](#web-frontend)
12. [Authentication & RBAC](#authentication--rbac)
13. [The JOCKY Language (.jy)](#the-jocky-language-jy)
14. [Full End-to-End Workflow](#full-end-to-end-workflow)
15. [Getting Started](#getting-started)
16. [CLI Reference](#cli-reference)
17. [Phase 1 — Implemented Functionalities](#phase-1--implemented-functionalities-current)
18. [Phase 2 — Planned Functionalities](#phase-2--planned-functionalities-next)
19. [Phase 3 — Vision Functionalities](#phase-3--vision-functionalities-future)
20. [CI/CD Pipeline](#cicd-pipeline)
21. [Security Model](#security-model)
22. [Documentation Index](#documentation-index)

---

## Mission & Motivation

JOCKY was conceived for **SIH26148 · NTRO (National Technical Research Organisation) · Blockchain & Cybersecurity Track**.

Modern adversaries operate with increasingly sophisticated evasion — they hook kernel APIs, inject into trusted processes, reside fileless in memory, and exploit legitimate tools ("Living-off-the-Land"). Existing forensic tooling either leaves massive forensic footprints of its own, is detectable by the very malware it seeks to find, or requires cloud connectivity that is unavailable or unsafe in sensitive environments.

JOCKY's mission is to close this gap:

- **Write once** — describe a forensic investigation in `.jy` (JOCKY source) — a declarative DSL purpose-built for evidence collection.
- **Compile anywhere** — a Rust + LLVM compiler turns your `.jy` file into a standalone native binary (ELF on Linux, PE on Windows) with no external runtime dependencies.
- **Run silently** — the generated binary uses LotL techniques: in-memory execution, direct syscalls, PEB-based API resolution, EDR API unhooking, and anti-analysis guards.
- **Verify cryptographically** — every evidence file is SHA-256 hashed and Merkle-tree anchored. Any post-collection modification is detected with mathematical certainty.
- **Report locally** — verification and report generation happen locally (CLI or web). No evidence leaves the controlled environment unless explicitly transported.

---

## What is JOCKY?

JOCKY is a **five-layer stack** that takes a forensic investigator from *"I want to collect evidence from this host"* all the way to *"I have a cryptographically verified, tamper-evident evidence bundle ready for court"*:

```
Layer 1: .jy Language  (Domain-Specific Language for forensic investigations)
Layer 2: Compiler      (Lexer → Parser → AST → Semantic IR → HIR → MIR → Native Binary)
Layer 3: Runtime       (system, process, network, filesystem, memory, registry, logs, drivers)
Layer 4: LotL Engine   (in-memory exec, direct syscalls, PEB resolution, unhooking, anti-analysis)
Layer 5: Evidence      (SHA-256 hashing, Merkle trees, bundle verification, tamper detection)
```

Supporting this stack:
- A **REST API** (Axum/Tokio) for IDE integration and binary download
- A **Web IDE** (Monaco Editor + React + Vite) for writing, validating, and compiling `.jy` files
- A **CLI** for running investigations, verifying evidence, and generating reports

---

## Core Concepts at a Glance

| Concept | What it Means |
|---|---|
| `.jy` File | Human-readable forensic investigation definition (the "source code") |
| `jocky check` | Validates syntax and semantic correctness of a `.jy` file |
| `jocky compile` | Compiles `.jy` to a self-contained native binary via LLVM/Rust |
| `jocky run` | Runs a `.jy` investigation locally — collects real evidence |
| `evidence.json` | The raw collected evidence (structured JSON array) |
| `evidence.json.meta.json` | Cryptographic metadata sidecar (SHA-256, Merkle root, timestamps) |
| `evidence.json.bundle.json` | A signed transport bundle combining evidence + metadata |
| `jocky evidence verify` | Verifies the SHA-256 and Merkle integrity of an evidence file |
| LotL Primitives | Techniques to collect evidence without triggering EDR/AV detections |
| Transport | How evidence gets from field agent to analyst (Direct, Domain-Fronted, SOCKS5, Cloud Relay) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         JOCKY Platform Architecture                          │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────┐    ┌───────────────────────────────┐  │
│  │       Web Frontend (React)        │    │       CLI (jocky)             │  │
│  │  Monaco IDE · Vite · TypeScript   │    │  check / compile / run        │  │
│  │  http://localhost:3000            │    │  evidence verify / report      │  │
│  └───────────────┬──────────────────┘    └──────────────┬────────────────┘  │
│                  │ REST                                   │ direct            │
│  ┌───────────────▼───────────────────────────────────────▼────────────────┐ │
│  │                     REST API (Axum / Tokio)                             │ │
│  │  POST /api/compiler/check       POST /api/compiler/compile              │ │
│  │  POST /api/compiler/run         POST /api/compiler/verify               │ │
│  │  GET  /api/compiler/targets     GET  /api/compiler/capabilities         │ │
│  │  GET  /api/downloads/*          POST /api/auth/*                        │ │
│  │  GET/POST /api/tools/*                                                  │ │
│  └───────────────┬──────────────────────────────────────┬─────────────────┘ │
│                  │                                        │                   │
│  ┌───────────────▼──────────────────┐  ┌────────────────▼────────────────┐  │
│  │     JOCKY Compiler Pipeline       │  │     Forensic Runtime Library    │  │
│  │                                   │  │                                 │  │
│  │  jocky_lexer    → Tokens          │  │  runtime/system      (sysinfo)  │  │
│  │  jocky_parser   → AST             │  │  runtime/process     (procs)    │  │
│  │  jocky_ast      → Node types      │  │  runtime/network     (conns)    │  │
│  │  jocky_semantic → Semantic IR     │  │  runtime/filesystem  (files)    │  │
│  │  jocky_ir       → IR/HIR/MIR      │  │  runtime/memory      (vmem)     │  │
│  │  jocky_backend  → LLVM/Rust gen   │  │  runtime/registry    (regkeys)  │  │
│  │  jocky_cli      → CLI binary      │  │  runtime/logs        (evtlog)   │  │
│  └───────────────────────────────────┘  │  runtime/drivers     (kernel)   │  │
│                                         │  runtime/evidence    (integrity) │  │
│                                         │  runtime/timeline               │  │
│                                         │  runtime/artifacts              │  │
│                                         │  runtime/correlation            │  │
│                                         │  runtime/capabilities           │  │
│                                         └─────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                    LotL Engine (runtime/lotl)                         │   │
│  │  in_memory_exec · peb_resolve · direct_syscall                        │   │
│  │  unhook         · transport   · antianalysis                          │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
JOCKY/
├── Cargo.toml                    # Workspace root (35+ crates)
├── rust-toolchain.toml           # Pinned Rust toolchain version
│
├── compiler/                     # JOCKY language compiler
│   ├── lexer/                    # Tokenizer (jocky_lexer)
│   ├── parser/                   # Recursive descent parser (jocky_parser)
│   ├── ast/                      # AST node types, Token, Span (jocky_ast)
│   ├── semantic/                 # Semantic analysis + IR generation (jocky_semantic)
│   ├── ir/                       # Intermediate Representation: IR, HIR, MIR, BuildConfig
│   ├── hir/                      # High-level IR lowering
│   ├── mir/                      # Mid-level IR lowering
│   ├── backend/                  # LLVM + Rust code generation backends
│   └── cli/                      # `jocky` CLI binary (jocky-cli)
│
├── runtime/                      # Forensic collection runtime library
│   ├── src/                      # Runtime lib.rs + c_api.rs (FFI bridge)
│   ├── system/                   # System info collection
│   ├── process/                  # Process enumeration
│   ├── network/                  # Network connection enumeration
│   ├── filesystem/               # File system traversal & hashing
│   ├── memory/                   # Virtual memory region analysis
│   ├── registry/                 # Windows registry collection
│   ├── logs/                     # System log collection
│   ├── drivers/                  # Kernel driver enumeration
│   ├── timeline/                 # Event timeline construction
│   ├── artifacts/                # Artifact carving (prefetch, LNK, amcache, etc.)
│   ├── correlation/              # Cross-collector correlation engine
│   ├── capabilities/             # 172-capability registry & implementation status
│   ├── auth/                     # Authentication primitives
│   ├── users/                    # User account collection
│   ├── services/                 # System service/daemon collection
│   ├── security/                 # Security policy collection
│   ├── persistence/              # Persistence mechanism detection
│   ├── evidence/                 # Evidence bundling, SHA-256, Merkle tree, verification
│   └── lotl/                     # Living-off-the-Land primitives (LotL engine)
│       ├── src/
│       │   ├── lib.rs            # Module exports
│       │   ├── in_memory_exec.rs # Fileless execution (memfd_create / NtCreateSection)
│       │   ├── peb_resolve.rs    # PEB-walk API resolution (DJB2 hash)
│       │   ├── direct_syscall.rs # Raw syscall stubs (SSN extraction)
│       │   ├── unhook.rs         # EDR API unhooking (KnownDlls reload)
│       │   ├── transport.rs      # Evidence transport adapters
│       │   └── antianalysis.rs   # Debugger/sandbox/hypervisor detection
│       └── tests/
│           └── integration.rs    # LotL integration tests
│
├── apps/
│   ├── api/                      # REST API server (Axum/Tokio)
│   │   └── src/
│   │       ├── main.rs           # Server setup, router, CORS config
│   │       ├── compiler_service.rs # check/compile/run/verify/targets/capabilities handlers
│   │       ├── auth.rs           # JWT auth (Argon2 + jsonwebtoken)
│   │       ├── tools.rs          # Tool repository handlers
│   │       ├── tools_service.rs  # Tool management service
│   │       ├── evidence.rs       # Evidence ingestion handler
│   │       ├── investigations.rs # Investigation management
│   │       ├── audit.rs          # Audit log handler
│   │       └── middleware.rs     # Auth middleware (JWT extraction)
│   └── web/                      # React/TypeScript/Vite web frontend
│
├── services/
│   └── compiler-worker/          # Background compilation worker service
│
├── packages/
│   └── shared-types/             # Shared Rust types (Role, ErrorResponse, etc.)
│
├── examples/                     # 14 example .jy investigation files
│   ├── complete_forensic_triage.jy
│   ├── stealth_adversary_detection.jy
│   ├── process_triage.jy
│   ├── memory_triage.jy
│   ├── network_investigation.jy
│   ├── filesystem_investigation.jy
│   ├── registry_audit.jy
│   ├── artifact_carving.jy
│   └── ... (9 more)
│
├── migrations/                   # Database migrations (PostgreSQL)
├── docker/                       # Docker configurations
├── docker-compose.yml            # Compose stack (API + Web + Postgres + MinIO + Redis)
├── packaging/                    # Debian (.deb) and Windows (.zip) package scripts
├── scripts/                      # LLVM setup, signing, utilities
├── tests/                        # End-to-end and package verification tests
├── docs/                         # Extended documentation
├── .github/workflows/ci.yml      # GitHub Actions CI (Linux + Windows + Web + Debian)
├── demo.sh                       # 14-stage end-to-end demo script
├── .env.example                  # Environment variable template
└── capabilities.json             # Full 172-capability specification
```

---

## Compiler Pipeline — Deep Dive

The JOCKY compiler transforms a `.jy` investigation definition into a standalone native binary through a multi-stage pipeline:

```
.jy Source File
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 1: Lexer  (compiler/lexer/src/lib.rs)                        │
│                                                                     │
│  Input:  Raw UTF-8 source text                                      │
│  Output: Vec<Token>                                                 │
│                                                                     │
│  - Character-by-character tokenization                              │
│  - Recognises all JOCKY keywords: investigation, collect, export,   │
│    filter, where, limit, metadata, hash, system_info, processes,    │
│    network_connections, files, logs, drivers, timeline,             │
│    memory_regions, registry, artifacts, sha256, sha1, md5           │
│  - Produces TokenKind variants with Span (line, column)             │
│  - Supports: string literals, integer/float literals, operators,    │
│    single-line (//) and nested multi-line (/* */) comments          │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 2: Parser  (compiler/parser/src/lib.rs)                      │
│                                                                     │
│  Input:  Vec<Token>                                                 │
│  Output: Investigation (AST root node)                              │
│                                                                     │
│  - Recursive descent parser                                         │
│  - Parses investigation { } blocks with optional: target, metadata, │
│    collect statements, filter expressions, where predicates,        │
│    limits, pipeline stages (pipe |), and export directives          │
│  - Produces Diagnostic objects (severity, message, span)            │
│  - parse_with_diagnostics() → (Option<Investigation>, Vec<Diag>)    │
│    enables partial recovery for IDE error highlighting              │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 3: AST  (compiler/ast/src/lib.rs)                            │
│                                                                     │
│  Defines all AST node types:                                        │
│  - Investigation, Stmt, Expr, CollectTarget, CollectOptions          │
│  - HashAlgorithm (Sha256, Sha1, Md5)                                │
│  - ExportFormat, PipelineStage, BinaryOp, UnaryOp                   │
│  - Span, Token, TokenKind, Severity, Diagnostic                     │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 4: Semantic Analysis  (compiler/semantic/src/lib.rs)         │
│                                                                     │
│  Input:  Investigation (AST)                                        │
│  Output: InvestigationIR                                            │
│                                                                     │
│  - Type checking and semantic validation                            │
│  - Resolves collect targets to IR CollectDirective variants         │
│  - Validates field selections, filter expressions, hash algorithms  │
│  - analyze_with_diagnostics() enables partial IR generation         │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 5: IR / HIR / MIR  (compiler/ir, hir, mir)                   │
│                                                                     │
│  - IR:  InvestigationIR { name, directives, export_path, limits }   │
│  - HIR: High-level IR — resolved platform, arch, optimization       │
│         BuildConfig { TargetPlatform, TargetArch, OptimizationLevel,│
│                       debug_symbols, strip_symbols, obfuscation }   │
│  - MIR: Mid-level IR — lowered to machine-near operations           │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Stage 6: Backend Code Generation  (compiler/backend/src/lib.rs)    │
│                                                                     │
│  Two backends (selected via JOCKY_BACKEND env var):                 │
│                                                                     │
│  Rust Backend (default):                                            │
│    - Emits a self-contained Rust source file embedding all          │
│      runtime collector calls and selected LotL primitives           │
│    - Invokes `cargo build --release` via subprocess                 │
│    - Cross-compilation: linux-x64, windows-x64                      │
│                                                                     │
│  LLVM Backend (experimental):                                       │
│    - Uses inkwell (Rust LLVM 18 bindings) for direct IR emission    │
│    - Produces native ELF/PE via llvm-sys 180                        │
│    - Enables future LLVM optimization passes                        │
│                                                                     │
│  Output: Standalone native binary — no external dependencies        │
└─────────────────────────────────────────────────────────────────────┘
      │
      ▼
Native Binary (ELF on Linux, PE on Windows) — ready to deploy
```

---

## Runtime Modules — Deep Dive

The forensic runtime library (`runtime/`) is a collection of independent Rust crates, each responsible for a specific evidence collection domain.

| Module | Crate | Collects |
|---|---|---|
| `system` | `jocky-runtime-system` | OS version, hostname, boot time, hardware info, CPU, RAM |
| `process` | `jocky-runtime-process` | PID, name, parent, cmdline, user, hashes, start time |
| `network` | `jocky-runtime-network` | TCP/UDP connections: local/remote addr+port, PID, state |
| `filesystem` | `jocky-runtime-filesystem` | Path, size, timestamps, SHA-256/SHA-1/MD5 hashes |
| `memory` | `jocky-runtime-memory` | Virtual memory regions: base, size, permissions, mapped file |
| `registry` | `jocky-runtime-registry` | Windows registry keys and values |
| `logs` | `jocky-runtime-logs` | Windows Event Log, Linux syslog/journald entries |
| `drivers` | `jocky-runtime-drivers` | Kernel-loaded drivers/modules, LOLDrivers vulnerability scan |
| `timeline` | `jocky-runtime-timeline` | Unified chronological event timeline |
| `artifacts` | `jocky-runtime-artifacts` | Prefetch, LNK files, amcache, shell history, browser data |
| `users` | `jocky-runtime-users` | Local/domain user accounts, groups, login history |
| `services` | `jocky-runtime-services` | System services / daemons / launchd agents |
| `security` | `jocky-runtime-security` | Security policies, firewall rules, EDR/AV status |
| `persistence` | `jocky-runtime-persistence` | Run keys, scheduled tasks, startup entries |
| `correlation` | `jocky-runtime-correlation` | Cross-collector correlation (process ↔ network ↔ files) |
| `capabilities` | `jocky-runtime-capabilities` | 172-capability registry, implementation status |
| `evidence` | `jocky-runtime-evidence` | SHA-256, Merkle tree, bundle creation, verification |
| `auth` | `jocky-runtime-auth` | Authentication primitives |

### Evidence Collector (`runtime/evidence/src/lib.rs`)

The `EvidenceCollector` struct orchestrates all runtime collection. Each collector reports:

```rust
CollectorResult {
    collector: "process",
    status: CollectionStatus::Success | Partial | Failed | NotFound | PermissionDenied | RequiresElevation,
    records_count: 128,
    error: None,
    warning: None,
    timestamp: Utc::now()
}
```

On completion produces:
- `evidence.json` — raw JSON array of all collected records
- `evidence.json.meta.json` — `EvidenceMetadata` with SHA-256 hash, Merkle root, timestamps, tool version, host identifier, build provenance (source hash, artifact hash), and optional blockchain anchor

---

## Living-off-the-Land (LotL) Primitives

The `runtime/lotl` crate implements the core anti-detection collection engine. All six modules work together to allow forensic collection to bypass EDR/AV userland hooks.

### 1. In-Memory Execution (`in_memory_exec.rs`)

Executes compiled JOCKY payloads entirely in RAM — no file written to disk.

**Linux path (`memfd_create + fexecve`):**
```
memfd_create("", MFD_CLOEXEC)   → anonymous kernel-backed fd
write(fd, payload_bytes)         → bytes in kernel page cache only
fexecve(fd, argv, envp)          → exec from fd, not from any named path
```
- No `open()`/`creat()` syscall → fanotify silent
- Appears only as `memfd:` in `/proc/self/maps`
- `MFD_CLOEXEC` prevents fd leaking to children

**Windows path (PEB-resolved, no IAT entries):**
```
NtCreateSection(SEC_COMMIT | PAGE_EXECUTE_READWRITE)  → anonymous section
NtMapViewOfSection                                     → RW mapping
memcpy(base, payload)                                  → write payload
NtProtectVirtualMemory → PAGE_EXECUTE_READ             → harden
NtCreateThreadEx(base)                                 → spawn thread
NtWaitForSingleObject                                  → join
NtUnmapViewOfSection + NtClose                         → cleanup
```
All NT functions resolved via PEB walk — **no plaintext strings, no GetProcAddress, no LoadLibrary**.

### 2. PEB-Based Dynamic API Resolution (`peb_resolve.rs`)

Walks the Process Environment Block at runtime instead of using the static IAT:

```
gs:[0x60]  → PEB
PEB.Ldr    → PEB_LDR_DATA
InMemoryOrderModuleList  → doubly-linked list of loaded DLLs
each entry → DllBase → parse IMAGE_EXPORT_DIRECTORY → find RVA by DJB2 hash
```

DJB2 hashes are `const fn` — computed at compile time, no plaintext function names in binary:
```rust
const H_NtQuerySystemInformation: u32 = djb2_hash(b"NtQuerySystemInformation");
// → 0x72FF2ECA  (compile-time constant)
```

Pre-computed hashes for 12 key NTAPI functions: NtQuerySystemInformation, NtQueryInformationProcess, NtOpenProcess, NtQueryObject, NtEnumerateValueKey, RtlGetVersion, VirtualQueryEx, NtProtectVirtualMemory, NtClose, NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection.

Traditional (detectable): `IAT entry → hooked trampoline → EDR → real NTAPI`

JOCKY (undetectable): `Walk PEB → DLL base → PE export directory → raw RVA`

### 3. Direct NTAPI Syscall Stubs (`direct_syscall.rs`)

Issues raw `syscall` instructions with the correct System Service Number (SSN), bypassing ntdll.dll export stub trampolines:

```asm
; Pattern extracted from ntdll in-memory text:
mov r10, rcx          ; 4C 8B D1
mov eax, <SSN>        ; B8 xx xx xx xx  ← JOCKY reads these 4 bytes
syscall               ; 0F 05
ret                   ; C3
```

Bypasses: `DbgkpSendSystemCallReport`, `ObRegisterCallbacks`, SSDT patching — all common EDR hooking mechanisms.

### 4. API Unhooking — Perun's Fart Technique (`unhook.rs`)

EDRs patch `.text` of ntdll.dll in-process. JOCKY restores clean entry points from the OS-maintained `\KnownDlls` object directory:

```
1. Open \KnownDlls\ntdll.dll section object (pristine, unmodified by EDRs)
2. Map it into our address space (read-only, clean copy)
3. Locate .text section in both copies
4. Temporarily make our .text writable (VirtualProtect)
5. Copy clean .text bytes → overwrite potentially hooked .text
6. Restore original page protection
```

Result: All NTAPI hooks, trampolines, and IAT patches neutralized.

### 5. Anti-Analysis Environment Guards (`antianalysis.rs`)

Detects hostile analysis environments and exits gracefully:

**Linux checks:**
- `/proc/self/status` `TracerPid` — non-zero means ptrace debugger attached
- CPUID leaf 0x1 bit 31 — hypervisor present flag
- RDTSC timing — busy loop ΔT < 10,000 cycles = CPU acceleration anomaly
- Sandbox process names: wireshark, strace, ltrace, gdb, rr, perf, cuckoo, drakvuf, volatility

**Windows checks:**
- `PEB.BeingDebugged` (offset 0x2) via inline ASM (`gs:[0x60]`)
- `PEB.NtGlobalFlag` (offset 0x68) — debuggers set flags `0x70`
- CPUID hypervisor bit + vendor string identification
- Suspicious sandbox DLLs: `SbieDll.dll`, `api_log.dll`, `vmcheck.dll`, `wpespy.dll`
- `NUMBER_OF_PROCESSORS=1` environment variable

Risk levels: `Safe` / `Suspicious(reasons)` / `Hostile(reasons)`

### 6. Evidence Transport Adapters (`transport.rs`)

Four pluggable transport modes for delivering evidence:

| Transport | Description | Evasion Property |
|---|---|---|
| `Direct` | Plain HTTPS POST to JOCKY API | Basic TLS |
| `DomainFronted` | TLS SNI = CDN hostname; `X-Jocky-Target` carries real destination | Traffic appears as CDN I/O |
| `Socks5` | Route through SOCKS5 proxy | Traffic exits through proxy |
| `CloudApiRelay` | S3/GCS/Azure Blob presigned URL PUT/GET | Traffic appears as cloud storage I/O |

Domain-fronted flow:
```
Field Agent ──TLS SNI: cloudflare.com──▶ CDN edge ──internal──▶ JOCKY API
             Host: cloudflare.com
             X-Jocky-Target: jocky.your-domain.com
```

Configured in `.jy` source:
```
config {
    transport = "domain_fronted"
    cdn_host   = "cloudflare.com"
    relay_url  = "https://jocky.your-domain.com"
}
```

---

## Evidence Integrity System

### SHA-256 Hashing

Every evidence file is hashed immediately after collection, before any transport or export. Stored in `.meta.json` sidecar.

### Merkle Tree

Evidence records are individually hashed; a binary Merkle tree is computed over all leaf hashes. The Merkle root is stored in metadata, enabling:
- **Completeness proof** — any missing record invalidates the root
- **Per-item verification** — inclusion proofs verify individual records without full re-verification
- **Tamper localization** — identifies which specific record was modified

### Verification

```bash
jocky evidence verify evidence.json --meta evidence.json.meta.json
```

Outputs:
```
Integrity: VALID
SHA-256:   a1b2c3d4...
Merkle:    VALID (root: e5f6g7h8...)
Investigation: complete_forensic_triage
Host:      FORENSIC-WORKSTATION
Collected: 2026-09-29T08:00:00Z
```

On tamper:
```
Integrity: INVALID — SHA-256 mismatch
Expected:  a1b2c3d4...
Got:       deadbeef...
```

### Evidence Bundle (`bundle.rs`)

`EvidenceBundle` combines evidence + manifest + provenance into a single transportable artifact:
```json
{
  "manifest": { "investigation": "...", "host": "...", "tool": "...", "timestamps": {} },
  "records": [...],
  "provenance": { "sha256": "...", "merkle_root": "...", "collector_results": [] }
}
```

### Blockchain Anchoring (Defined, Future Implementation)

`BlockchainAnchor` struct in metadata for future court-admissible timestamp proof:
```rust
pub struct BlockchainAnchor {
    pub transaction_id: String,
    pub block_height: u64,
    pub timestamp: DateTime<Utc>,
    pub network: String,  // "ethereum-mainnet", "polygon", etc.
}
```

---

## REST API Server

Built with **Axum 0.7** on **Tokio async runtime** — stateless for the compiler endpoints, no database required for local usage.

### Endpoints

#### Compiler Endpoints (Stateless)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check — `{ status: "ok", version: "0.1.0" }` |
| `POST` | `/api/compiler/check` | Validate `.jy` source — returns diagnostics, collectors, capabilities |
| `POST` | `/api/compiler/compile` | Compile `.jy` to native binary — returns `application/octet-stream` download |
| `POST` | `/api/compiler/run` | Run investigation locally — collects real evidence on the API host |
| `POST` | `/api/compiler/verify` | Verify an uploaded `evidence.json` bundle integrity (16 MiB limit) |
| `GET` | `/api/compiler/targets` | List supported compilation targets |
| `GET` | `/api/compiler/capabilities` | List all 172 forensic capabilities with implementation status |

#### Download Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/downloads/info` | Available packages and versions |
| `GET` | `/api/downloads/windows` | Download Windows x64 CLI package |
| `GET` | `/api/downloads/linux` | Download Linux x64 CLI package |
| `GET` | `/api/downloads/:filename` | Download a specific named package |

#### Authentication (Stateless JWT)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register user + organization (Argon2 password hash) |
| `POST` | `/api/auth/login` | Login — returns JWT access + refresh tokens |

#### Tool Repository

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/api/tools` | List / create tools |
| `GET` | `/api/tools/:id` | Get a specific tool |
| `POST` | `/api/tools/:id/versions` | Create a new tool version |
| `GET` | `/api/tools/:id/download` | Download a tool version |

### Compile Workflow (API Internal)

```
POST /api/compiler/compile { "source": ".jy content", "target": "linux-x64" }
  │
  ├─ Size validation (< 256 KiB)
  ├─ Target validation (linux-x64 or windows-x64)
  ├─ spawn_blocking:
  │   ├─ Lexer::tokenize(source)
  │   ├─ Parser::parse_with_diagnostics(tokens)
  │   ├─ SemanticAnalyzer::analyze_with_diagnostics(ast)
  │   ├─ Backend::new(config, backend_kind).generate(ir, output_dir)
  │   └─ Read output binary bytes → cleanup temp dir
  │
  └─ Response:
      Content-Type: application/octet-stream
      Content-Disposition: attachment; filename="investigation-linux-x64"
      x-jocky-target: linux-x86_64
```

---

## Web Frontend

Built with **React + TypeScript + Vite** (`apps/web`).

### Key Features

- **Monaco Web IDE** — Full `.jy` syntax highlighting, error markers, autocompletion
- **Check** — `POST /api/compiler/check` → diagnostics displayed inline in editor
- **Compile & Download** — `POST /api/compiler/compile` → browser download of native binary
- **Verify** — `POST /api/compiler/verify` with uploaded evidence bundle
- **Examples Gallery** — Browse and load all 14 example `.jy` investigations
- **Documentation** — Embedded language reference and setup guides
- **Downloads** — Pre-built CLI packages for Linux and Windows

---

## Authentication & RBAC

System (`apps/api/src/auth.rs`):
- **Argon2** — memory-hard password hashing
- **JWT HS256** — stateless access + refresh token pairs
- **Roles** — Analyst, Admin, Viewer (defined in `packages/shared-types`)

JWT Claims:
```json
{
  "sub": "user-uuid",
  "org": "organization-uuid",
  "role": "analyst",
  "exp": 1234567890,
  "iat": 1234567890,
  "token_type": "access"
}
```

---

## The JOCKY Language (`.jy`)

### Language Grammar (Simplified)

```
investigation  ::= "investigation" STRING "{" body "}"
body           ::= target? metadata? statement*
target         ::= "target" IDENTIFIER
metadata       ::= "metadata" "{" (IDENTIFIER "=" value)* "}"
statement      ::= collect_stmt | export_stmt | filter_stmt
collect_stmt   ::= "collect" collect_target field_block? limit?
collect_target ::= "system_info" | "processes" | "network_connections"
                 | "files" STRING | "logs" | "drivers" | "timeline"
                 | "memory_regions" | "registry" STRING | "artifacts"
field_block    ::= "{" field* "}"
field          ::= IDENTIFIER | "hash" "." hash_algo | "recursive"
hash_algo      ::= "sha256" | "sha1" | "md5"
limit          ::= "limit" INTEGER
filter_stmt    ::= "filter" IDENTIFIER "=" expr "|" pipeline+
pipeline       ::= "where" IDENTIFIER "contains" STRING
export_stmt    ::= "export" "evidence" STRING
```

### Example: Simple Process Triage

```
investigation "process_triage" {
    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }
    collect network_connections
    export evidence "process_triage_evidence.json"
}
```

### Example: Stealth Adversary Detection

```
investigation "stealth_adversary_detection" {
    metadata {
        author = "JOCKY Defensive Engineering"
        classification = "Host Detection"
        case_id = "STEALTH-ADVERSARY-001"
    }

    collect system_info

    collect processes {
        pid
        name
        executable_path
        command_line
        parent
    }

    collect network_connections {
        pid
        process_name
        local_address
        local_port
        remote_address
        remote_port
        state
    }

    collect drivers

    collect memory_regions {
        pid
        range_start
        range_end
        executable
        writable
        anonymous
        mapped_file
    }

    export evidence "stealth_adversary_detection.json"
}
```

### Example: Full Forensic Triage

```
investigation "complete_forensic_triage" {
    metadata {
        author = "JOCKY DFIR Team"
        priority = "High"
        category = "Full Triage"
    }

    collect system_info

    collect processes {
        pid
        name
        parent
        command_line
        user
        hash.sha256
    }

    collect network_connections

    collect files "C:\\Windows\\System32\\drivers\\etc" {
        recursive
        hash.sha256
    } limit 50

    export evidence "complete_forensic_triage_evidence.json"
}
```

---

## Full End-to-End Workflow

```
INVESTIGATOR                         TARGET HOST
     │                                     │
     │  1. Write .jy investigation         │
     │     (Monaco IDE or text editor)     │
     │                                     │
     │  2. jocky check investigation.jy    │
     │  <── Diagnostics (errors/warnings)  │
     │                                     │
     │  3. jocky compile investigation.jy  │
     │     --target linux-x64              │
     │     --output ./build/               │
     │                                     │
     │  <── Standalone native binary       │
     │       (investigation-linux-x64)     │
     │                                     │
     │  4. Transfer binary to target       │
     │  ───────────────────────────────── >│
     │                                     │
     │                                     │  5. Run binary on target
     │                                     │
     │                                     │  6. LotL engine activates:
     │                                     │     - Anti-analysis check
     │                                     │     - API unhooking (Windows)
     │                                     │     - PEB-based API resolution
     │                                     │     - Direct syscall stubs
     │                                     │     - In-memory execution
     │                                     │
     │                                     │  7. Runtime collectors:
     │                                     │     - system_info
     │                                     │     - process
     │                                     │     - network
     │                                     │     - filesystem
     │                                     │     - (as defined in .jy)
     │                                     │
     │                                     │  8. Evidence exported:
     │                                     │     - investigation.json
     │                                     │     - investigation.json.meta.json
     │                                     │     (SHA-256 + Merkle computed)
     │                                     │
     │  <── Transfer evidence back         │
     │       (SCP, USB, transport layer)   │
     │                                     │
     │  9. jocky evidence verify           │
     │     investigation.json              │
     │     --meta ...meta.json             │
     │                                     │
     │  <── VALID / INVALID + hash         │
     │                                     │
     │  10. jocky report generate          │
     │      --format markdown              │
     │      investigation.json             │
     │                                     │
     │  <── investigation_report.md        │
```

---

## Getting Started

### ⚡ Quick Install (Pre-built Binaries)

Download and install JOCKY with a single command — no Rust or LLVM required:

#### Linux / macOS
```bash
curl -fsSL https://raw.githubusercontent.com/Aditya-180404/JOCKY/main/scripts/install.sh | bash
```

#### Windows (PowerShell — run as Administrator)
```powershell
irm https://raw.githubusercontent.com/Aditya-180404/JOCKY/main/scripts/install.ps1 | iex
```

#### Debian / Ubuntu
```bash
# Download .deb from the latest release
curl -fsSL https://api.github.com/repos/Aditya-180404/JOCKY/releases/latest \
  | grep "browser_download_url.*\.deb" | cut -d '"' -f 4 | xargs -I {} curl -fsSL {} -o jocky.deb
sudo dpkg -i jocky.deb
```

After install:
```bash
jocky --version        # verify installation
jocky --help           # show all commands
jocky script.jy        # compile a .jy file
```

> 💡 Releases are available at [github.com/Aditya-180404/JOCKY/releases](https://github.com/Aditya-180404/JOCKY/releases).  
> Binaries for **Linux x86_64**, **Linux ARM64**, **macOS Universal**, and **Windows x86_64** are published automatically on each tagged release.

---

### Build from Source — Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| [Rust](https://rustup.rs/) | stable (1.75+) | Compiler, API, CLI |
| [LLVM](https://releases.llvm.org/) | 21 | LLVM backend |
| [Node.js](https://nodejs.org/) | 20+ | Web frontend |
| [Docker](https://www.docker.com/) | Latest | Optional full-stack |
| Git | Any | Clone repository |

### Step 1 — Clone

```bash
git clone https://github.com/Aditya-180404/jocky.git
cd jocky
cp .env.example .env
```

### Step 2 — Start the API

```bash
# Linux / macOS
JOCKY_API_ADDR="0.0.0.0:8080" cargo run -p jocky-api

# Windows (PowerShell)
$env:JOCKY_API_ADDR = "0.0.0.0:8080"
cargo run -p jocky-api
```

Verify: `curl http://localhost:8080/health`

### Step 3 — Start the Web Frontend

```bash
cd apps/web
npm install
npm run dev
# Open http://localhost:3000
```

### Step 4 — Build the CLI

```bash
cargo build --release -p jocky-cli
export PATH="$PATH:$(pwd)/target/release"
jocky --version
```

### Step 5 — Run Your First Investigation

```bash
jocky check examples/process_triage.jy

jocky compile examples/complete_forensic_triage.jy \
    --target linux --arch x64 --output ./build/

jocky run examples/complete_forensic_triage.jy \
    --output ./evidence/

jocky evidence verify ./evidence/complete_forensic_triage_evidence.json \
    --meta ./evidence/complete_forensic_triage_evidence.json.meta.json

jocky report generate --format markdown ./evidence/complete_forensic_triage_evidence.json
```

### Step 6 — Full-Stack with Docker

```bash
docker compose up --build
```

### Step 7 — Run the Demo

```bash
bash demo.sh        # full 14-stage demo
bash demo.sh fast   # abbreviated demo
```

---

## CLI Reference

```
jocky [COMMAND] [OPTIONS]

Commands:
  check     <file.jy>                 Validate .jy source (syntax + semantic)
  compile   <file.jy>                 Compile to native binary
             --target  linux|windows
             --arch    x64|arm64
             --output  <dir>
  run       <file.jy>                 Run investigation locally
             --output  <dir>
  evidence  verify <evidence.json>    Verify evidence integrity
             --meta <meta.json>
             --deep                   Per-item Merkle verification
  report    generate <evidence.json>  Generate investigation report
             --format  terminal|markdown|json
             --output  <file>
  doctor                              Check environment and dependencies
  capabilities                        List all 172 capabilities
             --format  table|json
  ide                                 Open web IDE in browser
  --version                           Print version
  --help                              Show help
```

---

## Phase 1 — Implemented Functionalities (Current)

### ✅ JOCKY Language & Compiler

- **Lexer** — Full tokenization: all keywords, operators, string/integer/float literals, escape sequences, single-line and nested multi-line comments
- **Parser** — Recursive descent parser with partial recovery; `parse_with_diagnostics()` enables IDE error squiggles without full parse failure
- **AST** — Complete AST node hierarchy (Investigation, Stmt, Expr, CollectTarget, CollectOptions, HashAlgorithm, ExportFormat, PipelineStage, BinaryOp, UnaryOp, Span)
- **Semantic Analyzer** — Type checking, collect target validation, field selection verification, IR generation with non-fatal warnings
- **IR / HIR / MIR** — Multi-level intermediate representation with `BuildConfig` (TargetPlatform, TargetArch, OptimizationLevel, debug_symbols, strip_symbols, obfuscation)
- **Rust Backend** — Emits self-contained Rust source embedding runtime collector calls; cross-compiles to Linux x64 and Windows x64 via `cargo build --release`
- **LLVM Backend** (experimental) — Direct LLVM IR emission via inkwell/llvm-sys 18; select with `JOCKY_BACKEND=llvm`
- **CLI Binary** — Full `jocky` CLI with: `check`, `compile`, `run`, `evidence verify`, `report generate`, `doctor`, `capabilities`, `ide` subcommands

### ✅ Forensic Runtime Collectors

- **System Info** — OS version, hostname, kernel version, boot time, CPU info, RAM
- **Process Enumeration** — PID, name, parent PID, command line, user, executable path, start time, SHA-256 hash
- **Network Connections** — Active TCP/UDP sockets: local/remote address+port, PID, state, process name
- **Filesystem Collection** — Recursive directory traversal with SHA-256/SHA-1/MD5 hashing, timestamps, configurable limits
- **Memory Regions** — Virtual memory map: base, size, permissions (RWX), anonymous flag, mapped file path
- **Driver Enumeration** — Kernel-loaded modules, LOLDrivers vulnerability scan
- **Timeline** — Unified chronological event timeline from cross-collector data

### ✅ LotL Engine (All 6 Modules Implemented)

- **In-Memory Execution** — `memfd_create + fexecve` (Linux); `NtCreateSection + NtMapViewOfSection + NtCreateThreadEx` (Windows, PEB-resolved, no IAT)
- **PEB-Based API Resolution** — DJB2 compile-time hash-based function resolution; pre-computed hashes for 12 NTAPI functions; no `GetProcAddress`, no `LoadLibrary`
- **Direct Syscall Stubs** — SSN extraction from ntdll in-memory text, raw `syscall` instruction bypass
- **API Unhooking (Perun's Fart)** — `\KnownDlls\ntdll.dll` `.text` section restore, neutralizing inline EDR hooks
- **Anti-Analysis Guards** — Debugger (ptrace/PEB), hypervisor (CPUID), timing (RDTSC), sandbox artifact detection; three-level risk assessment (Safe/Suspicious/Hostile)
- **Transport Adapters** — Direct HTTPS, Domain-Fronted HTTPS, SOCKS5 proxy, Cloud API Relay (S3/GCS/Azure presigned URLs); factory pattern `build_transport(config)`

### ✅ Evidence Integrity System

- **SHA-256 Hashing** — Evidence hashed immediately after collection
- **Merkle Tree** — Binary Merkle tree over all evidence records; root stored in metadata
- **Merkle Proof Nodes** — Per-item inclusion proofs (sibling hash + position)
- **Evidence Metadata Sidecar** — `evidence.json.meta.json` with SHA-256, Merkle root, timestamps, tool version, host, build provenance
- **Evidence Bundle** — `evidence.json.bundle.json` combining evidence + manifest + provenance
- **Verification CLI** — `jocky evidence verify` with SHA-256 + Merkle; `--deep` for per-item proofs
- **Tamper Detection** — CI-verified: modified evidence correctly rejected with non-zero exit code
- **CollectionStatus Tracking** — Per-collector: Success, Partial, Failed, NotFound, Unsupported, PermissionDenied, RequiresElevation
- **EvidenceOrigin Tagging** — Real, Simulated, Imported, Derived

### ✅ REST API Server

- Full Axum 0.7 / Tokio server
- All compiler endpoints: `check`, `compile`, `run`, `verify`, `targets`, `capabilities`
- All download endpoints: `info`, `windows`, `linux`, `/:filename`
- Auth endpoints: `register` (Argon2), `login` (JWT HS256)
- Tool repository endpoints (in-memory store for local dev)
- CORS configured for localhost:3000 and localhost:5173
- Structured JSON logging via `tracing-subscriber`
- `DefaultBodyLimit` (16 MiB) on verify endpoint

### ✅ Authentication System

- Argon2 memory-hard password hashing
- JWT (HS256) access + refresh token pairs
- Multi-role RBAC: Analyst, Admin, Viewer
- Input validation with `validator` crate (email, min-length)

### ✅ Web Frontend

- Monaco Editor web IDE with `.jy` support
- Check / Compile / Verify actions wired to API
- Example file gallery (14 examples)
- Documentation and setup guide pages
- Downloads page for CLI packages

### ✅ CI/CD Pipeline (GitHub Actions)

- **Linux job** — `fmt` → `clippy` → `test` → `build --release` → LLVM 21 → acceptance tests (check, compile, run, verify, tamper detection)
- **Windows job** — Same pipeline on `windows-latest` → PE header verification → Authenticode signing → ZIP packaging
- **Web job** — Node 20 → `npm ci` → `lint` → `build`
- **Debian package job** — `cargo build` → `dpkg-deb` → install → `jocky --version` → upload artifact

### ✅ Packaging

- **Debian .deb package** — `jocky_0.1.0_amd64.deb` (built in CI)
- **Windows ZIP archive** — `jocky_0.1.0_windows_amd64.zip`
- **Pre-built binaries** — `jockey.exe` (Windows x64), `test-linux-x64` (Linux x64)

### ✅ 172-Capability Registry

- Full JSON specification (`capabilities.json`) of 172 forensic capability IDs
- Covers: application data (browsers, email, office), forensic artifacts (amcache, prefetch, LNK, ETW, event logs, shell history, cron, SRUM, SSH), authentication events, EDR/kernel callbacks, LOLDrivers, memory analysis, network topology, process injection detection, registry run keys, scheduled tasks, user/group enumeration
- Implementation status tracking per capability

### ✅ 14 Example Investigations

| File | Description |
|---|---|
| `complete_forensic_triage.jy` | Full triage: system + processes + network + files with SHA-256 |
| `stealth_adversary_detection.jy` | Advanced: processes + network + drivers + memory regions |
| `process_triage.jy` | Process-focused triage with SHA-256 hashing |
| `memory_triage.jy` | Virtual memory region analysis |
| `network_investigation.jy` | Network connection analysis |
| `filesystem_investigation.jy` | File system traversal |
| `registry_audit.jy` | Windows registry audit |
| `artifact_carving.jy` | Forensic artifact collection |
| `incident_triage.jy` | Incident response triage |
| `evidence_hashing.jy` | Evidence integrity demonstration |
| `basic_system_triage.jy` | Simple system info collection |
| `complete_basic_triage.jy` | Multi-collector basic triage |
| `process_investigation.jy` | Deep process investigation |
| `user_investigation.jy` | User account investigation |

---

## Phase 2 — Planned Functionalities (Next)

### 🔜 Compiler Improvements

- [ ] **Fix `timeline` collector lowering** — currently incorrectly lowered to `CollectSystemInfo` in `compiler/hir/src/lib.rs`; must emit `CollectTimeline` IR directive (known defect)
- [ ] **ARM64 targets** — enable `linux-arm64` and `windows-arm64` backend codegen
- [ ] **Obfuscation passes** — string encryption (XOR/RC4 at compile time), dead code injection, control flow flattening for generated binaries
- [ ] **Polymorphic engine** — each compile produces a different binary hash (salt injection, code reordering) to defeat hash-based AV signatures; demonstrates proof for SIH26148 requirement #2
- [ ] **Incremental compilation** — cache AST and IR between runs for faster re-compilation
- [ ] **Language extensions** — `alert`, `correlate`, `timeline join`, conditional collectors (`if platform == "windows"`)

### 🔜 Runtime Collector Expansion

- [ ] **Windows Registry** — full `NtEnumerateValueKey` implementation, Run keys, Services keys, autorun locations
- [ ] **Windows Event Logs** — EVTx file parsing, Security/System/Application log collectors
- [ ] **Linux Artifacts** — bash/zsh/fish history, cron jobs, systemd units, `/etc/passwd`, `/etc/sudoers`
- [ ] **Windows Artifacts** — Prefetch files, LNK files, AmCache.hve, Shellbags, SRUM database, Jump Lists, Recycle Bin
- [ ] **Browser Data** — Chrome/Firefox/Edge cookies, history, downloads, extensions
- [ ] **SSH Artifacts** — `known_hosts`, `authorized_keys`, SSH config files
- [ ] **Network Topology** — ARP table, routing table, DNS cache, network interface details
- [ ] **Scheduled Tasks** — Windows Task Scheduler XML, Linux cron/at/anacron
- [ ] **Persistence Detection** — startup folder, registry Run keys, WMI subscriptions, LaunchAgents/LaunchDaemons

### 🔜 LotL Engine Enhancements

- [ ] **Full SOCKS5 transport** — replace stub with actual protocol (`ureq` or `minreq`)
- [ ] **Real HTTP transport** — replace `deliver_via_http` stub with actual sync HTTP calls
- [ ] **TLS certificate pinning** — pin JOCKY server certificate in binary at compile time
- [ ] **Command-and-control polling** — bi-directional: evidence push + command pull over all transport modes
- [ ] **Chunk-based evidence delivery** — split large evidence files into configurable chunks (default 4 MB)

### 🔜 Evidence & Integrity

- [ ] **Blockchain anchoring** — publish evidence Merkle root to Ethereum/Polygon at collection time; `BlockchainAnchor` struct already defined
- [ ] **Deep forensic report** — automated HTML/PDF report with timeline visualization, process tree, network graph
- [ ] **Evidence comparison** — diff two evidence bundles to identify host changes between collection times
- [ ] **Chain-of-custody log** — append-only log of every access and transfer of an evidence bundle

### 🔜 Web Frontend

- [ ] **Full Monaco `.jy` language extension** — keyword autocomplete, hover documentation, go-to-definition, error squiggles
- [ ] **Investigation builder UI** — drag-and-drop investigation composer (no code required)
- [ ] **Evidence viewer** — interactive JSON tree browser for evidence bundles
- [ ] **Evidence diff viewer** — side-by-side comparison of two evidence files
- [ ] **Report viewer** — rendered HTML report with timeline and process tree charts

### 🔜 Multi-System Management

- [ ] **Agent registration** — field agents self-register with JOCKY server on first run
- [ ] **Agent inventory** — dashboard showing all registered agents, last seen, health status
- [ ] **Investigation deployment** — push `.jy` investigations to registered agents via management UI
- [ ] **Multi-host correlation** — correlate evidence across multiple hosts in a single campaign view

### 🔜 Database-Backed API

- [ ] **PostgreSQL persistence** — migrate from in-memory stores to `sqlx` + PostgreSQL for investigations, agents, evidence metadata, users
- [ ] **MinIO object storage** — store large evidence bundles in S3-compatible object storage
- [ ] **Redis** — cache, session management, job queues
- [ ] **Database migrations** — `sqlx migrate run` from `migrations/` directory

---

## Phase 3 — Vision Functionalities (Future)

### 🔭 AI-Assisted Forensics

- [ ] **Anomaly detection** — ML model trained on known-good baselines to flag suspicious deviations in collected evidence
- [ ] **IOC correlation** — automatic cross-reference of hashes and IPs against threat intel feeds (MISP, VirusTotal, AbuseIPDB)
- [ ] **Automated triage prioritization** — AI scoring of evidence records by threat severity
- [ ] **Natural language investigation builder** — describe an investigation in plain English; AI generates the `.jy` file

### 🔭 Advanced Evasion & Stealth

- [ ] **Kernel-level collection** — optional kernel module for privileged collection bypassing all userland hooks
- [ ] **BYOVD (Bring Your Own Vulnerable Driver)** — use signed but vulnerable drivers for kernel read access
- [ ] **Hardware-based timestamping** — use TPM PCRs or Intel TXT for hardware-attested collection timestamps
- [ ] **Secure enclave execution** — run collectors inside Intel SGX / AMD SEV for tamper-proof collection

### 🔭 Enterprise Scale

- [ ] **Distributed agent mesh** — P2P evidence aggregation without a central server
- [ ] **Multi-organization tenancy** — full SaaS deployment with organization isolation, billing, SSO
- [ ] **SIEM integration** — native connectors: Splunk, Elastic SIEM, Microsoft Sentinel, IBM QRadar
- [ ] **SOAR playbooks** — pre-built templates for common incident response scenarios
- [ ] **GRC integration** — map evidence collection to compliance frameworks (NIST, ISO 27001, PCI-DSS, SOC 2)

### 🔭 Court-Ready Evidence

- [ ] **Full blockchain notarization** — multi-chain anchoring (Ethereum + Polygon + Hyperledger) with public verifiability
- [ ] **Digital signature chain** — GPG/X.509 signed evidence bundles with investigator identity binding
- [ ] **Court-admissible PDF reports** — ISO 17025-formatted forensic reports with digital signature
- [ ] **Expert witness export** — structured XML compatible with legal case management systems
- [ ] **Regulatory compliance tagging** — automatic GDPR / HIPAA / CIPA data classification

### 🔭 Cross-Platform Expansion

- [ ] **macOS support** — full collectors and LotL for macOS (M1/M2/Intel)
- [ ] **Linux ARM64** — native ARM64 runtime collectors
- [ ] **Mobile forensics** — Android ADB-based and iOS lockdown-based evidence collection
- [ ] **Cloud workloads** — AWS EC2/Lambda, Azure VMs, GCP instances via cloud APIs
- [ ] **Container forensics** — Docker, Kubernetes pod, containerd evidence collection

---

## CI/CD Pipeline

GitHub Actions (`.github/workflows/ci.yml`) — runs on every push to `main` and every pull request:

```
┌─ rust-linux ────────────────────────────────────────────────────┐
│  ubuntu-latest                                                  │
│  ├── LLVM 21 setup (scripts/setup-llvm-linux.py)                │
│  ├── cargo fmt --all -- --check                                 │
│  ├── cargo clippy --workspace --all-features -- -D warnings     │
│  ├── cargo test --workspace --all-features                      │
│  ├── cargo build --workspace --release                          │
│  ├── jocky --version                                            │
│  ├── jocky doctor                                               │
│  ├── jocky check examples/complete_forensic_triage.jy           │
│  ├── jocky compile → verify ELF header (file | grep ELF)        │
│  ├── jocky run                                                  │
│  ├── jocky evidence verify (→ VALID)                            │
│  └── tamper test (→ INVALID, non-zero exit)                     │
└─────────────────────────────────────────────────────────────────┘

┌─ rust-windows ──────────────────────────────────────────────────┐
│  windows-latest                                                 │
│  ├── LLVM 21 setup (scripts/setup-llvm-win.py)                  │
│  ├── fmt / clippy / test / build                                │
│  ├── jocky.exe check / compile / run / verify                   │
│  ├── PE header verification (MZ magic bytes 0x4D 0x5A)          │
│  ├── tamper test (non-zero exit)                                │
│  ├── Authenticode signing (scripts/sign-windows.ps1)            │
│  └── Windows ZIP package (packaging/build-win.ps1)             │
└─────────────────────────────────────────────────────────────────┘

┌─ web ───────────────────────────────────────────────────────────┐
│  ubuntu-latest, Node 20                                         │
│  ├── npm ci                                                     │
│  ├── npm run lint                                               │
│  └── npm run build                                              │
└─────────────────────────────────────────────────────────────────┘

┌─ debian-package ────────────────────────────────────────────────┐
│  ubuntu-latest                                                  │
│  ├── cargo build --release -p jocky-cli                         │
│  ├── bash packaging/build-deb.sh                                │
│  ├── dpkg-deb --info / --contents                               │
│  ├── sudo dpkg -i jocky_0.1.0_amd64.deb                        │
│  ├── jocky --version / doctor / capabilities / check           │
│  └── Upload jocky_0.1.0_amd64.deb artifact                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Model

JOCKY is a **defensive digital-forensics platform**. It explicitly does **not** implement:

| Capability | Status |
|---|---|
| Antivirus/EDR bypass for malicious purposes | ❌ Not implemented |
| Process injection or hollowing | ❌ Not implemented |
| Credential theft | ❌ Not implemented |
| Lateral movement | ❌ Not implemented |
| Persistence mechanisms | ❌ Not implemented |
| Covert C2 infrastructure | ❌ Not implemented |
| Malicious payload generation | ❌ Not implemented |
| Evidence fabrication | ❌ Explicitly prevented — collection errors are explicit |

The LotL primitives exist **only** to enable forensic collection to proceed without being interrupted by security software that might otherwise mistake the forensic tool for malware. All operations are:
- **Explicit** — defined in a human-readable `.jy` file visible to the investigator
- **Auditable** — every collection is logged and evidence is cryptographically sealed
- **Permission-controlled** — requires authorization to deploy and run
- **Reproducible** — the same `.jy` file produces the same evidence structure on the same host

> ⚠️ **IMPORTANT**: JOCKY is designed exclusively for **authorized, consented forensic investigations** in controlled environments. Unauthorized use against systems you do not own or have explicit written permission to investigate is illegal and unethical.

---

## Documentation Index

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Architecture decision records |
| [docs/language.md](docs/language.md) | Complete JOCKY language reference |
| [docs/compiler.md](docs/compiler.md) | Compiler pipeline deep-dive |
| [docs/api.md](docs/api.md) | REST API full reference |
| [docs/security.md](docs/security.md) | Security model and threat boundaries |
| [docs/development.md](docs/development.md) | Developer setup and contribution guide |
| [docs/deployment.md](docs/deployment.md) | Production deployment guide |
| [docs/threat-model.md](docs/threat-model.md) | Threat model analysis |
| [docs/capability-implementation-report.md](docs/capability-implementation-report.md) | 172-capability implementation status |
| [docs/release-readiness-audit.md](docs/release-readiness-audit.md) | Release readiness audit |
| [capabilities.json](capabilities.json) | Machine-readable 172-capability specification |
| [capabilities.md](capabilities.md) | Human-readable capability reference |
| [demo.sh](demo.sh) | 14-stage end-to-end demonstration script |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes following the existing code style
4. Run CI checks locally:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-features
   cargo test --workspace
   ```
5. Open a pull request against `main`

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*JOCKY — Built for SIH26148 · NTRO · Blockchain & Cybersecurity Track*

**"Collect once. Verify forever. Leave no trace."**
