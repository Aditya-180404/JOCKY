# JOCKEY Evasion Architecture

**Audience:** SIH 2026 Technical Evaluation | NTRO Cybersecurity Team  
**Version:** 0.1.0 | **Date:** 2026-09-28

---

## Overview

JOCKEY is a defensive forensic DSL platform designed to perform complete computer and network forensic triage **even in hostile or compromised environments** where:

- Malicious software has hooked userland APIs to hide its presence.
- EDR/AV products restrict or terminate unsigned or unrecognised forensic tools.
- The adversary controls the kernel (rootkits, BYOVD-based EDR blind-spots).

The JOCKEY compiler pipeline applies four composable **anti-detection passes** before emitting the native forensic binary. These passes render the compiled tool unrecognisable to signature-based AV, file-reputation databases, and behavioural heuristics engines.

---

## 1. Control-Flow Graph (CFG) Flattening

**Module:** [`compiler/backend/src/obfuscation.rs`](../compiler/backend/src/obfuscation.rs) — `CfgFlatteningPass`

### Problem
Static analysis tools (IDA Pro, Ghidra, ClamAV heuristics) fingerprint programs by their control-flow graph shape — the sequential `call → push → compare → jmp` patterns that compilers predictably emit.

### Solution
`CfgFlatteningPass` converts the JOCKEY MIR's linear basic-block graph into a **state-machine dispatcher loop**:

```
BEFORE flattening:               AFTER flattening:
                                 
entry → collect_system           entry: state = S0 → dispatch
       ↓                          ↓
collect_network                  dispatch: switch(state) {
       ↓                           S0 → bb_collect_system
export_evidence                    S1 → bb_collect_network
                                   S2 → bb_export_evidence
                                 }
                                 Each bb sets state = S_next, jumps → dispatch
```

A decompiler sees an incomprehensible switch statement rather than a recognisable forensic enumeration pattern.

**State values** are assigned randomly per build (not 0, 1, 2…) so the switch arms look like random constants with no obvious sequential relationship.

**Enable via:** `jockey build --cfg-flatten` or `BuildConfig { obfuscation.cfg_flattening: true }`

---

## 2. String & Constant Encryption

**Module:** [`compiler/backend/src/obfuscation.rs`](../compiler/backend/src/obfuscation.rs) — `StringEncryptionPass`

### Problem
Forensic tools necessarily embed capability identifiers (`"network.connections"`), evidence field names, and investigation metadata as string literals. AV products use `strings(1)`-equivalent scanning to blocklist binaries containing these recognisable strings.

### Solution
`StringEncryptionPass` locates every `MirInstruction::ConstString` in the program, **XOR-encrypts it with a per-build 16-byte key**, and replaces it with two new instructions:

1. `EncryptedString { ciphertext: [0x4A, 0x3F, ...], xor_key: [0xC1, 0x7A, ...] }`  
   → Stores the encrypted payload (not a recognisable string).

2. `InlineDecrypt { dest, ciphertext, xor_key }`  
   → Emitted by the LLVM backend as an inline XOR loop that decrypts the string into a stack allocation at runtime.

**Result:** `strings /path/to/binary` returns only encrypted garbage. The capability ID `"network.connections"` exists nowhere in the binary's static content.

The XOR key is derived from `build_seed`, which is a nanosecond-precision UNIX timestamp at compile time — unique per build.

---

## 3. Polymorphic Binary Engine (Unique SHA-256 per Build)

**Module:** [`compiler/backend/src/obfuscation.rs`](../compiler/backend/src/obfuscation.rs) — `PolymorphicWatermarkPass` + `JunkInsertionPass`

### Problem
AV file-reputation databases (VirusTotal, Symantec QuScan, CrowdStrike) blocklist binaries by SHA-256 hash. If a JOCKEY binary is flagged, every subsequent compilation of the same investigation produces the same hash — permanently blocked.

### Solution
Three mechanisms ensure every compilation produces a unique binary hash:

| Mechanism | Description |
|---|---|
| `JunkInsertionPass` | Inserts 2–5 dead arithmetic instructions per basic block, changing the binary's code section |
| `PolymorphicWatermarkPass` | Embeds a 64-byte random blob in a `.jockeywm` section derived from the unique `build_seed` |
| String encryption key rotation | The per-build XOR key changes every compilation, altering all encrypted string payloads |

**Result:** The same `process_triage.jy` compiled 100 times produces 100 binaries with 100 different SHA-256 hashes, all functionally identical.

**CI test:** `tests/verify-polymorphic-builds.ps1` compiles 3 times and asserts all 3 SHA-256s differ.

---

## 4. Direct Syscall Stubs & PEB-Based API Resolution

**Module:** [`runtime/lotl/src/direct_syscall.rs`](../runtime/lotl/src/direct_syscall.rs), [`runtime/lotl/src/peb_resolve.rs`](../runtime/lotl/src/peb_resolve.rs)

### Problem
On Windows, EDR products install hooks in `ntdll.dll`'s Nt* export stubs and in the `kernel32.dll` / `advapi32.dll` wrapping layer. A normal forensic tool calling `EnumProcesses()` → `NtQuerySystemInformation()` goes through these hooks, which may terminate the tool or manipulate the returned data.

### Solution A — Direct NTAPI Syscalls
`DirectSyscall` discovers each Nt* function's **System Service Number (SSN)** by reading the `mov eax, <SSN>` instruction from `ntdll.dll`'s in-memory export stub (which contains the real SSN even after hooking), then issues a raw `syscall` instruction with that SSN, bypassing the hooked stub entirely:

```
HOOKED PATH:
  EnumProcesses() → ntdll!NtQuerySystemInformation hook → EDR analysis → real kernel

DIRECT SYSCALL PATH:
  Read SSN from ntdll stub → raw 'syscall' instruction → kernel directly
```

### Solution B — PEB-Based Dynamic API Resolution
`PebResolver` resolves Win32/NTAPI function pointers by walking the **Process Environment Block** (PEB → LDR → InMemoryOrderModuleList) and parsing PE export directories, without calling `GetProcAddress` (which itself is hookable). Function names are compared by **DJB2 hash** computed at compile time, so no plaintext function name strings appear in the binary.

```
HOOKED PATH:
  GetProcAddress("NtQuerySystemInformation") → IAT hook → EDR trampoline

PEB PATH:
  Walk PEB.Ldr → find ntdll base → parse ExportDirectory → match hash(name) → raw RVA
```

**Linux:** These mechanisms are not applicable. JOCKEY uses direct `/proc` filesystem reads which cannot be intercepted without kernel-level rootkits.

---

## 5. Anti-Debugging & Anti-Analysis Guards

**Module:** [`runtime/lotl/src/antianalysis.rs`](../runtime/lotl/src/antianalysis.rs)

### Purpose
Protect the investigation methodology. If a JOCKEY binary is run inside a malware sandbox or under a debugger, it exits gracefully rather than producing incorrect evidence or revealing its collection strategy.

### Checks

| Check | Linux | Windows |
|---|:---:|:---:|
| `/proc/self/status` TracerPid ≠ 0 | ✓ | — |
| PEB.BeingDebugged flag | — | ✓ |
| PEB.NtGlobalFlag heap debug bits | — | ✓ |
| CPUID hypervisor bit (leaf 1, ECX bit 31) | ✓ | ✓ |
| RDTSC timing anomaly (sandbox acceleration) | ✓ | ✓ |
| Suspicious process names (Cuckoo, Drakvuf, Wireshark) | ✓ | — |
| Sandbox DLL artefacts (SbieDll, api_log) | — | ✓ |
| `NUMBER_OF_PROCESSORS = 1` | — | ✓ |

**CLI flag:** `jockey build --no-guard` disables all anti-analysis checks for controlled lab environments.

---

## 7. API Unhooking (Perun's Fart / KnownDlls Reload)

**Module:** [`runtime/lotl/src/unhook.rs`](../runtime/lotl/src/unhook.rs) — `ApiUnhooker`

### Problem
EDR and AV sensors place inline hooks (e.g. `jmp <edr_trampoline>`) into the `.text` section of `ntdll.dll` inside monitored processes. When a forensic tool calls system APIs, the EDR intercepts the call, flags the heuristic behavior, or manipulates returned structures.

### Solution
`ApiUnhooker` maps a pristine, in-memory copy of `ntdll.dll` from the kernel's `\KnownDlls\ntdll.dll` object directory (which contains the untouched system image before userland hooks were placed). It locates the `.text` section in both the clean mapped section and the in-process module, temporarily adjusts memory protection using direct NTAPIs, and copies the clean bytes over the hooked functions.

```
HOOKED:  ntdll!NtQuerySystemInformation -> JMP EDR_Sensor -> Tampered / Blocked
RESTORE: Map \KnownDlls\ntdll.dll -> Copy clean .text bytes over in-process ntdll
RESULT:  ntdll!NtQuerySystemInformation restored to pristine kernel-entry stub
```

---

## 8. In-Memory File-Less Secondary Execution

**Module:** [`runtime/lotl/src/in_memory_exec.rs`](../runtime/lotl/src/in_memory_exec.rs) — `InMemoryScriptRunner`

### Problem
Dropping intermediate forensic scripts, temporary binaries, or batch files to disk creates NTFS `$MFT` and `$UsnJrnl` entries and triggers AV file-system minifilter drivers (`FLTMGR.SYS`).

### Solution
`InMemoryScriptRunner` executes secondary triage routines directly within process memory allocations. Investigation bytecode and command buffers are piped entirely in-memory without writing temporary payload files to disk, leaving zero persistent file artifacts.

---

## 9. Kernel Callback Tampering & EDR Subversion Detection

**Module:** [`runtime/security/src/lib.rs`](../runtime/security/src/lib.rs), [`runtime/drivers/src/lib.rs`](../runtime/drivers/src/lib.rs)

### Problem
Adversaries use BYOVD attacks (e.g. abusing `RTCore64.sys` or `gdrv.sys`) to disable Windows kernel notify routines (`PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `ObRegisterCallbacks`), blinding EDR agents.

### Solution
JOCKEY includes defensive forensic collectors:
1. **BYOVD Vulnerable Driver Audit**: Compares all loaded kernel drivers against known-vulnerable driver hashes and filenames from LOLDrivers.
2. **EDR Kernel Callback Tampering Detection**: Audits kernel callback registration points (`detect_kernel_callback_tampering()`) to identify disabled or zeroed EDR callback arrays, alerting investigators that kernel security visibility has been compromised.

---

## 10. SOCKS5 & Stealth Network Routing

**Module:** [`runtime/lotl/src/transport.rs`](../runtime/lotl/src/transport.rs) — `Socks5Transport`, [`runtime/network/src/proxy.rs`](../runtime/network/src/proxy.rs)

### Problem
Forensic tools that communicate directly over the host's primary network interface can alert perimeter firewalls or trigger network IDS heuristics.

### Solution
JOCKEY provides multi-vector transport evasion:
- **SOCKS5 Relay**: Routes investigative evidence and commands through local or remote SOCKS5 proxies (`Socks5Transport`).
- **Domain Fronting**: Camouflages HTTPS egress behind high-reputation CDN edge nodes (`DomainFrontedTransport`).
- **Cloud API Relay**: Uploads cryptographic evidence bundles directly to object storage presigned URLs (`CloudApiRelayTransport`).

---

## Compiler Flag Reference

| Flag | Short | Description |
|---|---|---|
| `--cfg-flatten` | `-F` | Enable CFG flattening pass |
| `--encrypt-strings` | `-E` | Enable string encryption pass |
| `--junk-instructions` | `-J` | Enable junk instruction insertion |
| `--opaque-predicates` | `-O` | Enable opaque predicate insertion |
| `--polymorphic` | `-P` | Enable polymorphic watermark (implies unique SHA-256) |
| `--full-evasion` | `-X` | Enable all passes (equivalent to -FEJOP) |
| `--no-guard` | | Disable anti-analysis environment guards |
| `--evasion-seed <N>` | | Set the build seed explicitly (default: current nanosecond timestamp) |

---

## SIH 2026 Compliance Matrix (Problem Statement 26148)

| Requirement | Implementing Module | Status |
|---|---|:---:|
| **Independent Programming Language ('JOCKY')** | `compiler/lexer`, `compiler/parser`, `compiler/ast`, `compiler/hir`, `compiler/mir` | ✅ Complete |
| **Cross-Platform Compiler (Windows PE & Ubuntu ELF)** | `compiler/backend/src/llvm.rs`, `compiler/backend/src/lib.rs` | ✅ Complete |
| **Custom LLVM Frontend Altering CFG & Binary Structures** | `compiler/backend/src/llvm_codegen.rs`, `obfuscation.rs::CfgFlatteningPass` | ✅ Complete |
| **Variable & String Encryption (XOR rotation per build)** | `compiler/backend/src/obfuscation.rs::StringEncryptionPass` | ✅ Complete |
| **Polymorphic Engine (Unique SHA-256 Per Build)** | `obfuscation.rs::PolymorphicWatermarkPass`, `tests/verify-polymorphic-builds.sh` | ✅ Complete |
| **Living-off-the-Land: Direct Syscalls (Bypass Hooked NTDLL)** | `runtime/lotl/src/direct_syscall.rs` | ✅ Complete |
| **Living-off-the-Land: PEB Dynamic API Resolution (DJB2 Hashes)** | `runtime/lotl/src/peb_resolve.rs` | ✅ Complete |
| **Living-off-the-Land: API Unhooking (KnownDlls Pristine Reload)** | `runtime/lotl/src/unhook.rs` | ✅ Complete |
| **In-Memory File-Less Secondary Execution** | `runtime/lotl/src/in_memory_exec.rs` | ✅ Complete |
| **Stealth Network Routing (SOCKS5 & Domain Fronting & Cloud APIs)** | `runtime/lotl/src/transport.rs` (Direct, DomainFronted, Socks5, CloudRelay) | ✅ Complete |
| **Kernel Subversion & BYOVD Detection** | `runtime/drivers/src/lib.rs` (LOLDrivers), `runtime/security/src/lib.rs` | ✅ Complete |
| **EDR Kernel Callback Tampering Analysis** | `runtime/security/src/lib.rs::detect_kernel_callback_tampering` | ✅ Complete |
| **Anti-Debugging & Environment Guards** | `runtime/lotl/src/antianalysis.rs` (RDTSC, CPUID, PEB, /proc) | ✅ Complete |
| **Central Management Interface (Simultaneous Multi-System)** | `apps/web` (React/Vite UI) + `apps/api` (Axum REST API) | ✅ Complete |
| **Stealth Adversary Detection Scripts (.jy)** | `examples/stealth_adversary_detection.jy`, `complete_forensic_triage.jy` | ✅ Complete |
| **Cryptographic Evidence Integrity (Chain of Custody)** | `runtime/evidence/src/lib.rs` (SHA-256, Merkle Trees, Bundle Signatures) | ✅ Complete |

