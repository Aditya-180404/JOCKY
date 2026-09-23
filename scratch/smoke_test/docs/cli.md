# TraceForge CLI Reference

The `traceforge` CLI provides complete tooling for authoring, validating, compiling, running, and cryptographically verifying TraceForge investigations.

---

## 1. Installation

The `traceforge` binary can be run directly from the release package or built from source:

```powershell
# From release package
.\traceforge.exe --help

# From source
cargo build --release -p traceforge-cli
.\target\release\traceforge.exe --help
```

---

## 2. Command Overview

| Command | Syntax | Description |
|---|---|---|
| `check` | `traceforge check <file.tfg>` | Validate syntax, tokens, and semantic capability inference |
| `compile` | `traceforge compile <file.tfg> -t <target> -a <arch> -o <dir>` | Compile `.tfg` into a standalone native executable |
| `run` | `traceforge run <file.tfg>` | Compile and immediately execute an investigation |
| `verify` | `traceforge verify <evidence.json>` | Verify cryptographic integrity against its `.meta.json` sidecar |
| `inspect` | `traceforge inspect <file.tfg>` | Output AST and IR representations as JSON |
| `hash` | `traceforge hash <file.tfg>` | Compute canonical SHA-256 hash of a `.tfg` file |
| `fmt` | `traceforge fmt <file.tfg>` | Format and normalize `.tfg` investigation source |
| `target list` | `traceforge target list` | Display supported target platforms and architectures |
| `init` | `traceforge init <project_name>` | Scaffold a new project directory with sample investigation |

---

## 3. Usage Examples

### Validating a Script
```powershell
traceforge check examples\basic_system_triage.tfg
```
Output:
```text
Validating examples\basic_system_triage.tfg
Tokens:
  [0] Investigation
  ...
✓ Validation successful
  Investigation: basic_system_triage
  Required capabilities: ["SYSTEM_INFO_READ", "PROCESS_READ"]
```

### Compiling to Native Executable
```powershell
traceforge compile examples\basic_system_triage.tfg --target windows --arch x64 --output ./build
```
This produces `build/basic_system_triage.exe` and `build/basic_system_triage.meta.json`.

### Immediate Execution
```powershell
traceforge run examples\basic_system_triage.tfg
```
Executes collection on the local machine and outputs `system_triage.json` and `system_triage.json.meta.json`.

### Cryptographic Evidence Verification
```powershell
# Verifying genuine evidence
traceforge verify system_triage.json
# Output: Integrity: VALID

# Detecting tampered evidence
traceforge verify system_triage_tampered.json
# Output: Error: Artifact hash does not match any metadata file
```
