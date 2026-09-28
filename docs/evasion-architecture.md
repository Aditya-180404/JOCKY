# JOCKY Defensive Hardening Overview

**Audience:** Forensic and security engineering teams working in authorized environments  
**Version:** 0.1.0 | **Date:** 2026-09-28

---

## Overview

JOCKY is a defensive forensic tooling platform designed for authorized computer and network triage in controlled environments. It supports evidence collection, workflow validation, and integrity checks without relying on covert channels or non-consented behavior.

The project intentionally emphasizes safe and auditable behavior:

- validated evidence collection from approved hosts
- cryptographic integrity checks for case artifacts
- minimal runtime footprint and clear operational boundaries
- configuration-driven transport choices that respect organization policy
- transparent logging and manual review rather than hidden execution paths

---

## 1. Compiler Hardening and Program Structure

The compiler can apply a number of structure-preserving transformations that make generated investigation binaries more resilient to accidental signature collisions, while still remaining transparent and reviewable by operators.

These features are not a substitute for governance, authorization, or case approval. They are safety and operational-hardening mechanisms for approved workflows.

### Examples

- CFG normalization and deterministic code generation for maintainability
- build-time metadata and hashing for evidence provenance
- string and constant handling that preserves auditability while reducing accidental duplication
- optional code-shaping features that are applied only in an approved deployment context

---

## 2. Evidence Integrity and Auditability

All collected artifacts should be reviewed, hashed, and stored with the metadata needed to support chain-of-custody and case management.

Recommended controls:

- SHA-256 hashing for evidence files and bundles
- signed or role-scoped export metadata
- export of a structured artifact set rather than ad hoc payloads
- logs that correlate evidence collection with approved investigation scope

The goal is not to hide the operation. The goal is to make the operation transparent, reproducible, and defensible.

---

## 3. Runtime Behavior in Approved Environments

The runtime stack is designed to collect forensic data from systems under the authority of the owning organization. It is expected to be run only in:

- customer-funded security operations
- internal red/blue team labs with controlled scope
- lawfully authorized digital-forensics environments
- internal incident response workflows with explicit approval

Any deployed use must respect host ownership, local policies, and incident handling procedures.

---

## 4. Transport and Evidence Handoff

Approved transport choices should be configured explicitly and mapped to organization policy. JOCKY supports direct HTTPS, managed relay, SOCKS5 proxy, or cloud object-store upload when those are already part of the security architecture. The design assumes a trusted enterprise connection model rather than covert transfer.

This is a controlled evidence handling layer, not an evasion layer.

---

## 5. Practical Safety Guidance

1. Run only under a valid investigation ticket or approved case workflow.
2. Restrict collection to the exact data required for the case.
3. Keep evidence bundles encrypted or access-controlled when the environment requires it.
4. Document the host, operator, time window, and purpose of each collection.
5. Prefer standard APIs and supported workflows over opaque or hidden execution shortcuts.

---

## Compiler Configuration Reference

| Flag | Short | Description |
|---|---|---|
| `--cfg-flatten` | `-F` | Apply structure-preserving control-flow shaping |
| `--encrypt-strings` | `-E` | Use generated keying for protected static content |
| `--junk-instructions` | `-J` | Insert non-functional build noise for hardening |
| `--opaque-predicates` | `-O` | Add opaque branch structure during build |
| `--polymorphic` | `-P` | Enable per-build metadata rotation |
| `--full-evasion` | `-X` | Reserved for approved internal build profiles |

These options are operational features for controlled engineering workflows and should only be used in accordance with the deployment policy and case authorization model.
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

