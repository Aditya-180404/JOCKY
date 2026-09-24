//! JOCKY Forensic Runtime
//!
//! # Architecture & Compatibility
//! JOCKY is a domain-specific forensic programming language and compiler framework.
//! The C-ABI symbols (`traceforge_rt_*` and `traceforge_runtime_*`) are intentional internal
//! ABI compatibility identifiers ensuring stable interoperability between the LLVM backend
//! code generator and the native runtime static library across platforms.

pub use traceforge_runtime_artifacts as artifacts;
pub use traceforge_runtime_drivers as drivers;
pub use traceforge_runtime_evidence::*;
pub use traceforge_runtime_filesystem::*;
pub use traceforge_runtime_logs::*;
pub use traceforge_runtime_memory as memory;
pub use traceforge_runtime_network::*;
pub use traceforge_runtime_process::*;
pub use traceforge_runtime_registry as registry;
pub use traceforge_runtime_system::*;
pub use traceforge_runtime_timeline as timeline;

pub mod c_api;
pub use c_api::*;
