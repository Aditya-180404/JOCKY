# JOCKY: Complete Windows Run Guide (CLI & Web IDE)

> **Platform:** Windows 10 / 11 / Server 2016+ (x86_64)  
> **Project:** JOCKY — Digital Forensic Analysis Framework  
> **Track:** SIH26148 · NTRO (National Technical Research Organisation) · Blockchain & Cybersecurity Track  
> **Philosophy:** *"Collect once. Verify forever. Leave no trace."*

---

## Table of Contents

1. [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2. [CLI Run Procedure (Command-by-Command)](#2-cli-run-procedure-command-by-command)
   - [2.1 Quick Verification (Doctor & Version)](#21-quick-verification-doctor--version)
   - [2.2 Validating & Inspecting `.jy` Scripts](#22-validating--inspecting-jy-scripts)
   - [2.3 Running Live Evidence Collection](#23-running-live-evidence-collection)
   - [2.4 Cryptographic Verification & Tamper Detection](#24-cryptographic-verification--tamper-detection)
   - [2.5 Generating Court-Admissible Forensic Reports](#25-generating-court-admissible-forensic-reports)
   - [2.6 Building the CLI from Source](#26-building-the-cli-from-source)
3. [Web IDE Run Procedure (Browser GUI)](#3-web-ide-run-procedure-browser-gui)
   - [3.1 Starting the REST API Backend](#31-starting-the-rest-api-backend)
   - [3.2 Starting the React/Vite Web Interface](#32-starting-the-reactvite-web-interface)
   - [3.3 Using the Monaco Web IDE (Step-by-Step)](#33-using-the-monaco-web-ide-step-by-step)
4. [Automated 1-Click PowerShell Demo](#4-automated-1-click-powershell-demo)
5. [How It Works on Windows (Under the Hood)](#5-how-it-works-on-windows-under-the-hood)
   - [5.1 PEB-Walk API Resolution (`peb_resolve.rs`)](#51-peb-walk-api-resolution-peb_resolvers)
   - [5.2 EDR Unhooking via KnownDlls (`unhook.rs`)](#52-edr-unhooking-via-knowndlls-unhookrs)
   - [5.3 Dynamic SSN Direct Syscalls (`direct_syscall.rs`)](#53-dynamic-ssn-direct-syscalls-direct_syscallrs)
   - [5.4 In-Memory Execution (`in_memory_exec.rs`)](#54-in-memory-execution-in_memory_execrs)
   - [5.5 Merkle Tree Cryptographic Integrity (`evidence/`)](#55-merkle-tree-cryptographic-integrity-evidence)

---

## 1. Prerequisites & Environment Setup

Ensure the following tools are installed on your Windows machine:

| Tool | Version | Purpose | Verify Command |
|---|---|---|---|
| **PowerShell** | 5.1+ or 7+ | Execution terminal (Run as Admin recommended) | `$PSVersionTable.PSVersion` |
| **Rust & Cargo** | 1.75+ (MSVC toolchain) | Compiler, API server, CLI builder | `cargo --version` |
| **Node.js** | 20+ (with npm) | Web IDE frontend | `node --version` |
| **Git** | Any | Version control | `git --version` |

Open **PowerShell** and navigate to the project directory:
```powershell
cd G:\jockey
```

---

## 2. CLI Run Procedure (Command-by-Command)

The repository includes a ready-to-run Windows executable: `.\jocky.exe`.

### 2.1 Quick Verification (Doctor & Version)

#### Check CLI Version:
```powershell
.\jocky.exe --version
```
*Expected Output:* `jocky 0.1.0`

#### Run System & Capability Diagnostic:
```powershell
.\jocky.exe doctor
```
*What this does:*
- Audits Windows OS version, host architecture (`x86_64`), and working directory.
- Verifies Rust toolchain (`rustc`, `cargo`, `rustup`).
- Validates the native MSVC compilation target (`x86_64-pc-windows-msvc`).
- Audits all **247 forensic capabilities** (97.6% implementation coverage).

---

### 2.2 Validating & Inspecting `.jy` Scripts

JOCKY uses a dedicated declarative DSL (`.jy`). You can validate and inspect scripts before compilation.

#### Validate Syntax and Semantic Capabilities:
```powershell
.\jocky.exe validate examples\basic_system_triage.jy
```
*Output:*
```
Tokens:
  [0] Investigation
  [1] String("basic_system_triage")
  ...
✓ Validation successful
  Investigation: basic_system_triage
  Required capabilities: ["PROCESS_READ", "SYSTEM_INFO_READ"]
```

#### Inspect AST & Intermediate Representation (IR):
```powershell
.\jocky.exe inspect examples\basic_system_triage.jy
```
*Shows the parsed JSON AST, collector operations, and required security capabilities.*

---

### 2.3 Running Live Evidence Collection

To execute forensic triage directly on the local Windows machine:

```powershell
.\jocky.exe run examples\basic_system_triage.jy --output .\demo-output\
```

*What happens during execution:*
1. Compiles the `.jy` script into an optimized standalone Windows binary.
2. Executes forensic collectors: System Information and Process Enumeration.
3. Automatically computes SHA-256 hashes for all items and creates the binary Merkle tree.
4. Outputs:
   - `system_triage.json` (Structured forensic evidence)
   - `system_triage.json.meta.json` (Cryptographic metadata sidecar with Merkle root)

---

### 2.4 Cryptographic Verification & Tamper Detection

JOCKY guarantees legal chain of custody. Any post-collection modification is detected with mathematical certainty.

#### Verify Untouched Evidence:
```powershell
.\jocky.exe evidence verify system_triage.json --meta system_triage.json.meta.json
```
- If untouched:
  ```
  ✓ Evidence Integrity: VALID
    SHA-256: Verified
    Merkle Root: Verified
  ```

#### Tamper Detection Demonstration:
If an attacker or rogue insider modifies even a single byte or character in `system_triage.json`:
```powershell
.\jocky.exe evidence verify system_triage_tampered.json --meta system_triage.json.meta.json
```
*Output:*
```
✗ Evidence TAMPERED / INTEGRITY FAILED
  Reason: SHA-256 mismatch
Error: Evidence failed integrity check: SHA-256 mismatch
```

#### Calculate Standalone SHA-256:
```powershell
.\jocky.exe hash system_triage.json
```

---

### 2.5 Generating Court-Admissible Forensic Reports

Convert raw JSON evidence into readable executive reports:

```powershell
# Display Markdown report in terminal:
.\jocky.exe report generate system_triage.json --format markdown

# Save Markdown report to file:
.\jocky.exe report generate system_triage.json --format markdown --output .\demo-output\report.md

# View generated report:
Get-Content .\demo-output\report.md | Select-Object -First 30
```

---

### 2.6 Building the CLI from Source

If you edit any code in the Rust crates:
```powershell
cargo build --release -p jocky-cli
Copy-Item target\release\jocky.exe .\jocky.exe -Force
```

---

## 3. Web IDE Run Procedure (Browser GUI)

JOCKY provides a browser-based **Monaco Web IDE** with syntax highlighting, live error markers, one-click compilation, and evidence verification.

### 3.1 Starting the REST API Backend

In your primary PowerShell terminal:
```powershell
cd G:\jockey
$env:JOCKY_API_ADDR = "127.0.0.1:8080"
cargo run -p jocky-api
```
*Verify the backend is active in another tab:*
```powershell
Invoke-RestMethod -Uri http://localhost:8080/health
# Returns: {"status": "ok", "version": "0.1.0"}
```

### 3.2 Starting the React/Vite Web Interface

In a **second** PowerShell terminal:
```powershell
cd G:\jockey\apps\web
npm install
npm run dev
```

The terminal will display the local Vite server URL:
```
  VITE v5.0.0  ready in 450 ms

  ➜  Local:   http://localhost:3000/
  ➜  Network: use --host to expose
```

Open **`http://localhost:3000`** (or `http://localhost:5173`) in Google Chrome, Edge, or Firefox.

### 3.3 Using the Monaco Web IDE (Step-by-Step)

1. **Monaco Code Editor:**
   - Write `.jy` scripts directly in the browser with custom syntax highlighting.
   - Load pre-built templates from the **Examples** dropdown (e.g., `basic_system_triage.jy`, `stealth_adversary_detection.jy`).
2. **Check Button:**
   - Triggers `POST /api/compiler/check`.
   - Returns real-time syntax and semantic errors directly as Monaco editor squiggles.
3. **Compile & Download:**
   - Select target (`windows-x64`).
   - Click **Compile** to trigger `POST /api/compiler/compile`.
   - The compiled standalone executable is downloaded directly through your browser.
4. **Evidence Verification Panel:**
   - Drag-and-drop an `evidence.json` and its `.meta.json` sidecar.
   - The browser validates cryptographic signatures and displays the green **VALID (SHA-256 + Merkle)** badge.

---

## 4. Automated 1-Click PowerShell Demo

To run an end-to-end automated demonstration on Windows:
```powershell
cd G:\jockey
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```

---

## 5. How It Works on Windows (Under the Hood)

JOCKY operates under a strict stealth model designed to collect evidence without alerting active malware or triggering defensive EDR hooks.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WINDOWS EXECUTION ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Anti-Analysis Check (CPUID, RDTSC timing, PEB.BeingDebugged)            │
│       │                                                                     │
│  2. Perun's Fart Unhooking (Map clean \KnownDlls\ntdll.dll .text section)   │
│       │                                                                     │
│  3. PEB-Walk API Resolution (DJB2 hash matching — no GetProcAddress)        │
│       │                                                                     │
│  4. Dynamic SSN Extraction & Direct Syscalls (syscall instruction)          │
│       │                                                                     │
│  5. In-Memory Execution (NtCreateSection + NtMapViewOfSection)              │
│       │                                                                     │
│  6. Evidence Serialization ──▶ SHA-256 ──▶ Binary Merkle Tree Construction  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 PEB-Walk API Resolution (`peb_resolve.rs`)
- **Problem:** EDRs monitor calls to `GetProcAddress` and `LoadLibraryA/W`.
- **Windows Implementation:** JOCKY retrieves the Process Environment Block pointer via `gs:[0x60]`, walks the `InLoadOrderModuleList`, parses the Export Directory Table of `ntdll.dll` and `kernel32.dll`, and hashes exported function names using the **DJB2 algorithm**.
- **Result:** Resolves function pointers dynamically without leaving plain-text strings in the binary or calling monitored APIs.

### 5.2 EDR Unhooking via KnownDlls (`unhook.rs` — "Perun's Fart")
- **Problem:** EDR agents (CrowdStrike, Defender, SentinelOne) inject `JMP` hooks into `ntdll.dll` inside monitored processes.
- **Windows Implementation:** 
  1. Opens the pristine section object `\KnownDlls\ntdll.dll` maintained by the Windows kernel.
  2. Maps a clean read-only copy into the process memory.
  3. Locates the `.text` code section.
  4. Temporarily makes our hooked `.text` page writable via `VirtualProtect(PAGE_EXECUTE_READWRITE)`.
  5. Copies the pristine instructions over the EDR hooks.
  6. Restores original page permissions.
- **Result:** All inline user-mode hooks and trampolines are neutralized.

### 5.3 Dynamic SSN Direct Syscalls (`direct_syscall.rs`)
- **Problem:** Security tools monitor Windows NT API function entries.
- **Windows Implementation:** JOCKY reads the clean `ntdll.dll` `.text` memory, extracts the System Service Number (SSN), and issues direct `syscall` assembly instructions.
- **Result:** Bypasses user-mode hooks entirely, transitioning directly into the kernel.

### 5.4 In-Memory Execution (`in_memory_exec.rs`)
- **Problem:** Dropping binaries to disk modifies MFT tables, creates USN journal entries, and alerts antivirus scanners.
- **Windows Implementation:** Uses `NtCreateSection` backed by the system paging file, maps it with `NtMapViewOfSection`, and invokes code via `NtCreateThreadEx`.
- **Result:** Zero disk writes; completely fileless execution.

### 5.5 Merkle Tree Cryptographic Integrity (`evidence/`)
- Every collected piece of evidence (process, network socket, registry key) is hashed with SHA-256.
- A balanced binary Merkle tree is computed from all record leaf hashes.
- The resulting **Merkle Root** is stored in `.meta.json`.
- When verified, JOCKY computes per-item inclusion proofs. If an adversary tampers with or deletes a single entry, the computed root mismatches and the evidence is rejected.
