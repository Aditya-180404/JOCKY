//! JOCKY Forensic Runtime
//!
//! # Architecture & Compatibility
//! JOCKY is a domain-specific forensic programming language and compiler framework.
//! The C-ABI symbols (`jocky_rt_*` and `jocky_runtime_*`) are intentional internal
//! ABI compatibility identifiers ensuring stable interoperability between the LLVM backend
//! code generator and the native runtime static library across platforms.

pub use jocky_runtime_artifacts as artifacts;
pub use jocky_runtime_auth as auth;
pub use jocky_runtime_capabilities as capabilities;
pub use jocky_runtime_correlation as correlation;
pub use jocky_runtime_drivers as drivers;
pub use jocky_runtime_evidence::*;
pub use jocky_runtime_filesystem::*;
pub use jocky_runtime_logs::*;
pub use jocky_runtime_memory as memory;
pub use jocky_runtime_network::*;
pub use jocky_runtime_process::*;
pub use jocky_runtime_registry as registry;
pub use jocky_runtime_security as security;
pub use jocky_runtime_services as services;
pub use jocky_runtime_system::*;
pub use jocky_runtime_timeline as timeline;
pub use jocky_runtime_users as users;

pub mod c_api;
pub use c_api::*;
