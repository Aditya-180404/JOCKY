# JOCKY: Complete Linux Run Guide (CLI & Web IDE)

> **Platform:** Linux (Debian, Ubuntu, Kali, RedHat, Arch x86_64)  
> **Project:** JOCKY — Digital Forensic Analysis Framework  
> **Track:** SIH26148 · NTRO (National Technical Research Organisation) · Blockchain & Cybersecurity Track  
> **Philosophy:** *"Collect once. Verify forever. Leave no trace."*

---

## Table of Contents

1. [Prerequisites & Package Installation](#1-prerequisites--package-installation)
2. [CLI Run Procedure (Command-by-Command)](#2-cli-run-procedure-command-by-command)
   - [2.1 Building or Installing the Binary](#21-building-or-installing-the-binary)
   - [2.2 Quick Verification (Doctor & Version)](#22-quick-verification-doctor--version)
   - [2.3 Validating & Inspecting `.jy` Scripts](#23-validating--inspecting-jy-scripts)
   - [2.4 Running Live Forensic Triage](#24-running-live-forensic-triage)
   - [2.5 Evidence Verification & Tamper Detection](#25-evidence-verification--tamper-detection)
   - [2.6 Report Generation](#26-report-generation)
   - [2.7 Full 14-Stage Automated Demo (`demo.sh`)](#27-full-14-stage-automated-demo-demosh)
3. [Web IDE Run Procedure (Browser GUI)](#3-web-ide-run-procedure-browser-gui)
   - [3.1 Starting the REST API Backend](#31-starting-the-rest-api-backend)
   - [3.2 Starting the React/Vite Web Interface](#32-starting-the-reactvite-web-interface)
   - [3.3 Running Full-Stack with Docker Compose](#33-running-full-stack-with-docker-compose)
4. [How It Works on Linux (Under the Hood)](#4-how-it-works-on-linux-under-the-hood)
   - [4.1 Fileless In-Memory Execution (`memfd_create` + `fexecve`)](#41-fileless-in-memory-execution-memfd_create--fexecve)
   - [4.2 Linux Anti-Analysis & Sandbox Evasion](#42-linux-anti-analysis--sandbox-evasion)
   - [4.3 Kernel & Forensic Runtime Collectors](#43-kernel--forensic-runtime-collectors)
   - [4.4 Merkle Tree Integrity System](#44-merkle-tree-integrity-system)

---

## 1. Prerequisites & Package Installation

On Ubuntu, Debian, or Kali Linux:

```bash
# 1. Update package manager
sudo apt-get update

# 2. Install build dependencies
sudo apt-get install -y build-essential curl git pkg-config libssl-dev

# 3. Install Rust & Cargo (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version
cargo --version

# 4. Install Node.js (v20+) & npm (for Web IDE)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
```

---

## 2. CLI Run Procedure (Command-by-Command)

Navigate to the project root:
```bash
cd /path/to/jocky
```

### 2.1 Building or Installing the Binary

#### Option A: Build with Cargo
```bash
cargo build --release -p jocky-cli
sudo cp target/release/jocky /usr/local/bin/jocky
jocky --version
```

#### Option B: Install Debian Package (.deb)
```bash
sudo dpkg -i packaging/jocky_0.1.0_amd64.deb
jocky --version
```

---

### 2.2 Quick Verification (Doctor & Version)

#### Check Version:
```bash
jocky --version
# Output: jocky 0.1.0
```

#### Run Environment & Capability Diagnostic:
```bash
jocky doctor
```
*Audits Linux kernel version, glibc environment, MSVC/LLVM targets, and reports the status of all **247 forensic capabilities** (97.6% implemented).*

---

### 2.3 Validating & Inspecting `.jy` Scripts

Validate an investigation definition without running it:

```bash
# Validate syntax and capabilities
jocky validate examples/process_triage.jy

# Inspect the Abstract Syntax Tree (AST) & Semantic IR
jocky inspect examples/process_triage.jy
```

---

### 2.4 Running Live Forensic Triage

Execute forensic collection on the live Linux host:

```bash
# Run triage and export evidence to directory
jocky run examples/process_triage.jy --output ./demo-output/
```

*Generated Artifacts:*
- `process_triage_evidence.json` (Structured forensic data)
- `process_triage_evidence.json.meta.json` (Cryptographic Merkle metadata sidecar)

---

### 2.5 Evidence Verification & Tamper Detection

#### Verify Untouched Evidence:
```bash
jocky evidence verify ./demo-output/process_triage_evidence.json \
  --meta ./demo-output/process_triage_evidence.json.meta.json
```
*Output:*
```
✓ Evidence Integrity: VALID
  SHA-256: Verified
  Merkle Root: Verified
```

#### Tamper Detection Verification:
Modify 1 byte in the evidence file:
```bash
# Introduce tampering
sed -i 's/"pid":/"__tampered__":/g' ./demo-output/tampered.json

# Attempt verification
jocky evidence verify ./demo-output/tampered.json \
  --meta ./demo-output/process_triage_evidence.json.meta.json
```
*Result:* Returns exit code `1` and prints `✗ Evidence TAMPERED / INTEGRITY FAILED`.

---

### 2.6 Report Generation

Generate formatted forensic reports for courtroom evidence or incident review:

```bash
# Output Markdown report to console
jocky report generate ./demo-output/process_triage_evidence.json --format markdown

# Save Markdown report to file
jocky report generate ./demo-output/process_triage_evidence.json --format markdown --output ./demo-output/report.md
```

---

### 2.7 Full 14-Stage Automated Demo (`demo.sh`)

To execute the complete acceptance test suite proving all problem-statement criteria:

```bash
# Full 14-stage verification
bash demo.sh

# Abbreviated fast demo
bash demo.sh fast
```

*The 14 stages verify: Binary Version, Language Validation, Live Collection, SHA-256/Merkle Integrity, Tamper Detection, Polymorphic Engine (3 unique hashes), In-Memory Exec, Anti-Analysis Guards, LotL Primitives, Stealth Transports, BYOVD Driver Scans, Capability Registry, Central API, and Full Test Suite.*

---

## 3. Web IDE Run Procedure (Browser GUI)

### 3.1 Starting the REST API Backend

In Terminal 1:
```bash
cd /path/to/jocky
export JOCKY_API_ADDR="0.0.0.0:8080"
cargo run -p jocky-api
```
*Verify with:* `curl http://localhost:8080/health` → `{"status": "ok", "version": "0.1.0"}`

### 3.2 Starting the React/Vite Web Interface

In Terminal 2:
```bash
cd /path/to/jocky/apps/web
npm install
npm run dev -- --host 0.0.0.0
```
Open **`http://localhost:3000`** in your browser.

- **Monaco Editor:** Write `.jy` scripts with live syntax highlighting and error diagnostics.
- **Compiler:** Click **Compile** to trigger cloud compilation and download the binary.
- **Visual Verifier:** Drag-and-drop evidence files to inspect Merkle integrity trees visually.

### 3.3 Running Full-Stack with Docker Compose

If you prefer containerized deployment:
```bash
docker compose up --build
```
- API accessible at: `http://localhost:8080`
- Web IDE accessible at: `http://localhost:3000`

---

## 4. How It Works on Linux (Under the Hood)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      LINUX EXECUTION ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Anti-Analysis Check (TracerPid, RDTSC timing loop, CPUID hypervisor)    │
│       │                                                                     │
│  2. In-Memory Execution (memfd_create + fexecve — zero disk footprint)     │
│       │                                                                     │
│  3. Kernel / Proc Extraction (/proc, /sys, Netlink sockets, eBPF telemetry) │
│       │                                                                     │
│  4. Leaf SHA-256 Hashing ──▶ Binary Merkle Tree Construction                │
│       │                                                                     │
│  5. Export evidence.json + .meta.json sidecar (Merkle root + signatures)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Fileless In-Memory Execution (`memfd_create` + `fexecve`)
- **Problem:** Writing temporary binary files to `/tmp` leaves file system inodes, updates timestamp records, and alerts host IDS/antivirus sensors.
- **Linux Implementation:** 
  1. JOCKY calls `memfd_create("kworker_proc", MFD_CLOEXEC)`, creating an anonymous memory-resident file descriptor without touching disk.
  2. Writes the payload directly into this memory descriptor.
  3. Executes the payload using `fexecve(fd, argv, envp)`.
- **Result:** Pure in-memory process execution; zero disk footprints, zero inode residue.

### 4.2 Linux Anti-Analysis & Sandbox Evasion
Before executing triage, JOCKY assesses host safety:
- **`TracerPid` Inspection:** Reads `/proc/self/status`. If `TracerPid != 0`, a `ptrace` debugger (such as GDB or Strace) is attached.
- **CPUID Hypervisor Flag:** Queries CPUID leaf `0x1` bit 31 to detect sandbox hypervisors (e.g., Cuckoo Sandbox, Drakvuf).
- **RDTSC Timing Check:** Executes a tight loop and measures elapsed CPU timestamp counter ticks. Accelerated sandbox clocks cause a timing anomaly.
- **Hostile Process Traps:** Scans for analysis tools (`wireshark`, `strace`, `ltrace`, `gdb`, `volatility`).

### 4.3 Kernel & Forensic Runtime Collectors
- **Processes:** Direct parsing of `/proc/[pid]/status`, `/proc/[pid]/cmdline`, `/proc/[pid]/maps`, and `/proc/[pid]/exe`.
- **Network Sockets:** Direct parsing of `/proc/net/tcp`, `/proc/net/udp`, and Linux Netlink socket tables.
- **Memory Analysis:** Scans `/proc/[pid]/smaps` to identify writable and executable (`RWX`) memory pages indicative of shellcode injection.
- **Kernel Drivers:** Audits loaded kernel modules via `/proc/modules` and cross-references against known vulnerable drivers (LOLDrivers / BYOVD).

### 4.4 Merkle Tree Integrity System
- Every collected JSON element is hashed with **SHA-256**.
- A balanced binary Merkle tree combines hashes in pairs up to a root hash.
- The root hash and inclusion proofs are stored in `evidence.json.meta.json`.
- Any post-collection alteration invalidates the Merkle root, guaranteeing cryptographic chain of custody for legal defense.
