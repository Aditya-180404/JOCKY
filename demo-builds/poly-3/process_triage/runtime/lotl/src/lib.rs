//! JOCKY Runtime — Living-off-the-Land (LotL) Primitives
#![allow(dead_code, unused_imports, clippy::all)]
//!
//! This module implements two core **anti-detection collection primitives**
//! that enable forensic collection to bypass userland API hooks installed by
//! EDR/AV products:
//!
//! ## 1. PEB-Based Dynamic API Resolution (`peb_resolve`)
//!
//! Instead of relying on a static Import Address Table (IAT) that EDR products
//! hook at process start-up, we walk the Process Environment Block (PEB) at
//! runtime to locate DLL base addresses and resolve exports manually.
//!
//! Traditional static imports look like:
//! ```text
//!   IAT entry -> hooked trampoline -> EDR analysis -> real NTAPI
//! ```
//!
//! Our dynamic resolution bypasses the trampoline entirely:
//! ```text
//!   Walk PEB → find dll base → parse PE export directory → call raw RVA
//! ```
//!
//! ## 2. Direct NTAPI Syscall Stubs (`direct_syscall`)
//!
//! For the most sensitive operations (process enumeration, handle queries), we
//! issue raw `syscall` instructions with the correct System Service Number
//! (SSN) obtained by parsing `ntdll.dll`'s in-memory text. This completely
//! avoids the `ntdll.dll` `Nt*` export stubs, which EDR drivers can hook via
//! `DbgkpSendSystemCallReport`, `ObRegisterCallbacks`, or SSDT patching.
//!
//! ## 3. Anti-Analysis Environment Guards (`antianalysis`)
//!
//! Detects common debugger and sandbox artefacts on both Linux and Windows.
//! The forensic binary exits gracefully if it determines it is being analysed
//! rather than running in a legitimate incident-response environment.
//!
//! ## Usage
//!
//! These primitives are used internally by the runtime collectors.
//! On Linux, PEB-based resolution is not applicable; instead, the module
//! provides cross-platform anti-debugging guards.

pub mod antianalysis;
pub mod direct_syscall;
pub mod in_memory_exec;
pub mod peb_resolve;
pub mod transport;
pub mod unhook;

pub use antianalysis::{AntiAnalysisGuard, EnvironmentRisk};
pub use direct_syscall::{DirectSyscall, SyscallResult};
pub use in_memory_exec::{InMemoryExecutionError, InMemoryExecutionResult, InMemoryScriptRunner};
pub use peb_resolve::{PebResolver, ResolvedFn};
pub use transport::{
    build_transport, EvidenceTransport, TransportConfig, TransportKind, TransportResult,
};
pub use unhook::{ApiUnhooker, UnhookError, UnhookResult};
