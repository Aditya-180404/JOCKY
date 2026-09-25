//! JOCKY Forensic Runtime
//!
//! # Architecture & Compatibility
//! JOCKY is a domain-specific forensic programming language and compiler framework.
//! The C-ABI symbols (`jockey_rt_*` and `jockey_runtime_*`) are intentional internal
//! ABI compatibility identifiers ensuring stable interoperability between the LLVM backend
//! code generator and the native runtime static library across platforms.

pub use jockey_runtime_artifacts as artifacts;
pub use jockey_runtime_auth as auth;
pub use jockey_runtime_capabilities as capabilities;
pub use jockey_runtime_correlation as correlation;
pub use jockey_runtime_drivers as drivers;
pub use jockey_runtime_evidence::*;
pub use jockey_runtime_filesystem::*;
pub use jockey_runtime_logs::*;
pub use jockey_runtime_memory as memory;
pub use jockey_runtime_network::*;
pub use jockey_runtime_process::*;
pub use jockey_runtime_registry as registry;
pub use jockey_runtime_security as security;
pub use jockey_runtime_services as services;
pub use jockey_runtime_system::*;
pub use jockey_runtime_timeline as timeline;
pub use jockey_runtime_users as users;

pub mod c_api;
pub use c_api::*;
