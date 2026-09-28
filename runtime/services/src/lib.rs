//! JOCKY Runtime - Service Enumeration
//!
//! Enumerates Windows services, systemd units, and kernel drivers.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServicesError {
    #[error("Failed to enumerate services: {0}")]
    EnumerationError(String),
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),
}

/// Service status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Stopped,
    Running,
    Paused,
    StartPending,
    StopPending,
    ContinuePending,
    PausePending,
    Unknown,
}

/// Service startup type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStartType {
    Boot,
    System,
    Auto,
    Demand,
    Disabled,
    Unknown,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name (internal name)
    pub name: String,
    /// Display name
    pub display_name: String,
    /// Service description
    pub description: Option<String>,
    /// Current status
    pub status: ServiceStatus,
    /// Startup type
    pub start_type: ServiceStartType,
    /// Binary/executable path
    pub binary_path: Option<String>,
    /// Service account (user context)
    pub service_account: Option<String>,
    /// Service dependencies (service names)
    pub dependencies: Vec<String>,
    /// Service PID (if running)
    pub pid: Option<u32>,
    /// SHA-256 hash of binary
    pub binary_hash: Option<String>,
    /// Signature verification status
    pub signature_status: Option<SignatureStatus>,
    /// Load order group
    pub load_order_group: Option<String>,
    /// Error control
    pub error_control: Option<String>,
    /// Tag ID
    pub tag_id: Option<u32>,
    /// Whether the service is interactive
    pub interactive: bool,
    /// Service type
    pub service_type: ServiceType,
    /// Source of this service info
    pub source: ServiceSource,
}

/// Service type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    KernelDriver,
    FileSystemDriver,
    Win32OwnProcess,
    Win32ShareProcess,
    InteractiveProcess,
    Unknown,
}

/// Signature verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    NotSigned,
    Unknown,
}

/// Source of service information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceSource {
    WindowsSCM,
    Systemd,
    InitD,
    Launchd,
}

/// Kernel driver information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    /// Driver name
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Driver path
    pub path: Option<String>,
    /// Driver status
    pub status: ServiceStatus,
    /// Start type
    pub start_type: ServiceStartType,
    /// Image base address
    pub image_base: Option<u64>,
    /// Image size
    pub image_size: Option<u64>,
    /// SHA-256 hash
    pub hash: Option<String>,
    /// Signature status
    pub signature_status: Option<SignatureStatus>,
    /// Signer name
    pub signer: Option<String>,
    /// Timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// BYOVD (Bring Your Own Vulnerable Driver) indicators
    pub byovd_indicators: Vec<ByovdIndicator>,
    /// Source
    pub source: ServiceSource,
}

/// BYOVD indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByovdIndicator {
    /// CVE identifier
    pub cve: String,
    /// Description
    pub description: String,
    /// Confidence level
    pub confidence: f32,
}

/// Systemd unit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitInfo {
    /// Unit name (e.g., nginx.service)
    pub name: String,
    /// Unit type (service, timer, socket, path, mount, etc.)
    pub unit_type: SystemdUnitType,
    /// Description
    pub description: Option<String>,
    /// Load state (loaded, not-found, error, etc.)
    pub load_state: String,
    /// Active state (active, inactive, activating, deactivating, failed)
    pub active_state: String,
    /// Sub state (running, exited, dead, etc.)
    pub sub_state: String,
    /// Unit file path
    pub unit_file_path: Option<String>,
    /// Drop-in files
    pub drop_in_paths: Vec<String>,
    /// ExecStart command
    pub exec_start: Option<String>,
    /// ExecStartPre commands
    pub exec_start_pre: Vec<String>,
    /// ExecStartPost commands
    pub exec_start_post: Vec<String>,
    /// ExecStop command
    pub exec_stop: Option<String>,
    /// ExecStopPost commands
    pub exec_stop_post: Vec<String>,
    /// User/group
    pub user: Option<String>,
    pub group: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Dependencies
    pub dependencies: Vec<String>,
    /// Wants
    pub wants: Vec<String>,
    /// Required by
    pub required_by: Vec<String>,
    /// Wanted by
    pub wanted_by: Vec<String>,
    /// PID (if running)
    pub pid: Option<u32>,
    /// Memory limit
    pub memory_limit: Option<String>,
    /// CPU limit
    pub cpu_limit: Option<String>,
    /// Restart policy
    pub restart: Option<String>,
    /// Restart sec
    pub restart_sec: Option<String>,
    /// Timer properties (for timer units)
    pub timer_properties: Option<TimerProperties>,
    /// Enabled state
    pub enabled: bool,
    /// Static state
    pub r#static: bool,
}

/// Systemd unit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemdUnitType {
    Service,
    Socket,
    Timer,
    Path,
    Mount,
    Automount,
    Swap,
    Target,
    Slice,
    Scope,
    Device,
    Unknown,
}

/// Timer properties for systemd timer units
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimerProperties {
    /// OnCalendar (calendar event)
    pub on_calendar: Option<String>,
    /// OnBootSec
    pub on_boot_sec: Option<String>,
    /// OnUnitActiveSec
    pub on_unit_active_sec: Option<String>,
    /// OnUnitInactiveSec
    pub on_unit_inactive_sec: Option<String>,
    /// Persistent
    pub persistent: Option<bool>,
    /// WakeSystem
    pub wake_system: Option<bool>,
    /// AccuracySec
    pub accuracy_sec: Option<String>,
    /// Next elapse
    pub next_elapse: Option<DateTime<Utc>>,
    /// Last elapse
    pub last_elapse: Option<DateTime<Utc>>,
}

/// Result of service enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesResult {
    pub services: Vec<ServiceInfo>,
    pub drivers: Vec<DriverInfo>,
    pub systemd_units: Vec<SystemdUnitInfo>,
    pub collection_time: DateTime<Utc>,
    pub errors: Vec<String>,
}

impl Default for ServicesResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ServicesResult {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            drivers: Vec::new(),
            systemd_units: Vec::new(),
            collection_time: Utc::now(),
            errors: Vec::new(),
        }
    }
}

/// Enumerate Windows services
#[cfg(target_os = "windows")]
pub fn enumerate_windows_services() -> Result<Vec<ServiceInfo>> {
    use std::process::Command;

    let mut services = Vec::new();

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Description,State,StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Compress",
        ])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(obj) => vec![serde_json::Value::Object(obj)],
                _ => vec![],
            };

            for item in items {
                let name = item
                    .get("Name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_name = item
                    .get("DisplayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = item
                    .get("Description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let state_str = item.get("State").and_then(|v| v.as_str()).unwrap_or("");
                let start_mode_str = item.get("StartMode").and_then(|v| v.as_str()).unwrap_or("");
                let path_name = item
                    .get("PathName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let start_name = item
                    .get("StartName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let pid = item
                    .get("ProcessId")
                    .and_then(|v| v.as_u64())
                    .map(|p| p as u32);

                let status = match state_str.to_lowercase().as_str() {
                    "running" => ServiceStatus::Running,
                    "stopped" => ServiceStatus::Stopped,
                    "paused" => ServiceStatus::Paused,
                    "start pending" => ServiceStatus::StartPending,
                    "stop pending" => ServiceStatus::StopPending,
                    _ => ServiceStatus::Unknown,
                };

                let start_type = match start_mode_str.to_lowercase().as_str() {
                    "auto" | "automatic" => ServiceStartType::Auto,
                    "manual" => ServiceStartType::Demand,
                    "disabled" => ServiceStartType::Disabled,
                    "boot" => ServiceStartType::Boot,
                    "system" => ServiceStartType::System,
                    _ => ServiceStartType::Unknown,
                };

                services.push(ServiceInfo {
                    name,
                    display_name,
                    description,
                    status,
                    start_type,
                    binary_path: path_name,
                    service_account: start_name,
                    dependencies: Vec::new(),
                    pid,
                    binary_hash: None,
                    signature_status: None,
                    load_order_group: None,
                    error_control: None,
                    tag_id: None,
                    interactive: false,
                    service_type: ServiceType::Win32OwnProcess,
                    source: ServiceSource::WindowsSCM,
                });
            }
        }
    }

    Ok(services)
}

/// Enumerate Windows kernel drivers
#[cfg(target_os = "windows")]
pub fn enumerate_windows_drivers() -> Result<Vec<DriverInfo>> {
    use std::process::Command;

    let mut drivers = Vec::new();

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json -Compress",
        ])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let items = match val {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(obj) => vec![serde_json::Value::Object(obj)],
                _ => vec![],
            };

            for item in items {
                let name = item
                    .get("Name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_name = item
                    .get("DisplayName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let state_str = item.get("State").and_then(|v| v.as_str()).unwrap_or("");
                let start_mode_str = item.get("StartMode").and_then(|v| v.as_str()).unwrap_or("");
                let path = item
                    .get("PathName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let status = match state_str.to_lowercase().as_str() {
                    "running" => ServiceStatus::Running,
                    "stopped" => ServiceStatus::Stopped,
                    _ => ServiceStatus::Unknown,
                };

                let start_type = match start_mode_str.to_lowercase().as_str() {
                    "boot" => ServiceStartType::Boot,
                    "system" => ServiceStartType::System,
                    "auto" | "automatic" => ServiceStartType::Auto,
                    "manual" => ServiceStartType::Demand,
                    "disabled" => ServiceStartType::Disabled,
                    _ => ServiceStartType::Unknown,
                };

                drivers.push(DriverInfo {
                    name,
                    display_name,
                    path,
                    status,
                    start_type,
                    image_base: None,
                    image_size: None,
                    hash: None,
                    signature_status: None,
                    signer: None,
                    timestamp: None,
                    byovd_indicators: Vec::new(),
                    source: ServiceSource::WindowsSCM,
                });
            }
        }
    }

    Ok(drivers)
}

/// Enumerate systemd units (Non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub fn enumerate_systemd_units() -> Result<Vec<SystemdUnitInfo>> {
    Ok(Vec::new())
}

/// Enumerate systemd units
#[cfg(target_os = "linux")]
pub fn enumerate_systemd_units() -> Result<Vec<SystemdUnitInfo>> {
    use std::fs;

    let mut units = Vec::new();

    // Read unit files from standard locations
    let unit_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
    ];

    for dir in unit_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("service")
                    || path.extension().and_then(|s| s.to_str()) == Some("timer")
                    || path.extension().and_then(|s| s.to_str()) == Some("socket")
                    || path.extension().and_then(|s| s.to_str()) == Some("path")
                    || path.extension().and_then(|s| s.to_str()) == Some("mount")
                    || path.extension().and_then(|s| s.to_str()) == Some("automount")
                    || path.extension().and_then(|s| s.to_str()) == Some("swap")
                    || path.extension().and_then(|s| s.to_str()) == Some("target")
                    || path.extension().and_then(|s| s.to_str()) == Some("slice")
                    || path.extension().and_then(|s| s.to_str()) == Some("scope")
                    || path.extension().and_then(|s| s.to_str()) == Some("device")
                {
                    if let Ok(unit) = parse_systemd_unit_file(&path) {
                        units.push(unit);
                    }
                }
            }
        }
    }

    // Also get runtime status via systemctl (if available)
    // This would require calling systemctl --no-pager list-units --all --plain

    Ok(units)
}

/// Parse a systemd unit file
#[cfg(target_os = "linux")]
fn parse_systemd_unit_file(path: &std::path::Path) -> Result<SystemdUnitInfo> {
    use std::fs;

    let content = fs::read_to_string(path)?;
    let name = path.file_name().unwrap().to_string_lossy().to_string();

    let unit_type = match path.extension().and_then(|s| s.to_str()) {
        Some("service") => SystemdUnitType::Service,
        Some("timer") => SystemdUnitType::Timer,
        Some("socket") => SystemdUnitType::Socket,
        Some("path") => SystemdUnitType::Path,
        Some("mount") => SystemdUnitType::Mount,
        Some("automount") => SystemdUnitType::Automount,
        Some("swap") => SystemdUnitType::Swap,
        Some("target") => SystemdUnitType::Target,
        Some("slice") => SystemdUnitType::Slice,
        Some("scope") => SystemdUnitType::Scope,
        Some("device") => SystemdUnitType::Device,
        _ => SystemdUnitType::Unknown,
    };

    let mut unit = SystemdUnitInfo {
        name: name.clone(),
        unit_type,
        description: None,
        load_state: "loaded".to_string(),
        active_state: "inactive".to_string(),
        sub_state: "dead".to_string(),
        unit_file_path: Some(path.to_string_lossy().to_string()),
        drop_in_paths: Vec::new(),
        exec_start: None,
        exec_start_pre: Vec::new(),
        exec_start_post: Vec::new(),
        exec_stop: None,
        exec_stop_post: Vec::new(),
        user: None,
        group: None,
        working_directory: None,
        environment: HashMap::new(),
        dependencies: Vec::new(),
        wants: Vec::new(),
        required_by: Vec::new(),
        wanted_by: Vec::new(),
        pid: None,
        memory_limit: None,
        cpu_limit: None,
        restart: None,
        restart_sec: None,
        timer_properties: None,
        enabled: false,
        r#static: false,
    };

    let mut current_section = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim();
        let value = parts[1].trim();

        match current_section.as_str() {
            "Unit" => {
                match key {
                    "Description" => unit.description = Some(value.to_string()),
                    "Requires" => {
                        unit.dependencies =
                            value.split_whitespace().map(|s| s.to_string()).collect()
                    }
                    "Wants" => {
                        unit.wants = value.split_whitespace().map(|s| s.to_string()).collect()
                    }
                    "After" | "Before" => {
                        // Ordering dependencies
                        unit.dependencies
                            .extend(value.split_whitespace().map(|s| s.to_string()));
                    }
                    _ => {}
                }
            }
            "Service" => match key {
                "ExecStart" => unit.exec_start = Some(value.to_string()),
                "ExecStartPre" => unit.exec_start_pre.push(value.to_string()),
                "ExecStartPost" => unit.exec_start_post.push(value.to_string()),
                "ExecStop" => unit.exec_stop = Some(value.to_string()),
                "ExecStopPost" => unit.exec_stop_post.push(value.to_string()),
                "User" => unit.user = Some(value.to_string()),
                "Group" => unit.group = Some(value.to_string()),
                "WorkingDirectory" => unit.working_directory = Some(value.to_string()),
                "Environment" => {
                    for env in value.split_whitespace() {
                        if let Some(eq_pos) = env.find('=') {
                            unit.environment
                                .insert(env[..eq_pos].to_string(), env[eq_pos + 1..].to_string());
                        }
                    }
                }
                "Restart" => unit.restart = Some(value.to_string()),
                "RestartSec" => unit.restart_sec = Some(value.to_string()),
                "MemoryLimit" => unit.memory_limit = Some(value.to_string()),
                "CPUQuota" => unit.cpu_limit = Some(value.to_string()),
                _ => {}
            },
            "Timer" => {
                let timer = unit.timer_properties.get_or_insert(TimerProperties {
                    on_calendar: None,
                    on_boot_sec: None,
                    on_unit_active_sec: None,
                    on_unit_inactive_sec: None,
                    persistent: None,
                    wake_system: None,
                    accuracy_sec: None,
                    next_elapse: None,
                    last_elapse: None,
                });
                match key {
                    "OnCalendar" => timer.on_calendar = Some(value.to_string()),
                    "OnBootSec" => timer.on_boot_sec = Some(value.to_string()),
                    "OnUnitActiveSec" => timer.on_unit_active_sec = Some(value.to_string()),
                    "OnUnitInactiveSec" => timer.on_unit_inactive_sec = Some(value.to_string()),
                    "Persistent" => timer.persistent = Some(value.parse().unwrap_or(false)),
                    "WakeSystem" => timer.wake_system = Some(value.parse().unwrap_or(false)),
                    "AccuracySec" => timer.accuracy_sec = Some(value.to_string()),
                    _ => {}
                }
            }
            "Install" => match key {
                "WantedBy" => {
                    unit.wanted_by = value.split_whitespace().map(|s| s.to_string()).collect()
                }
                "RequiredBy" => {
                    unit.required_by = value.split_whitespace().map(|s| s.to_string()).collect()
                }
                _ => {}
            },
            _ => {}
        }
    }

    // Check for drop-in files
    let dropin_dir = path.with_extension("d");
    if dropin_dir.exists() {
        if let Ok(entries) = fs::read_dir(&dropin_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("conf") {
                    unit.drop_in_paths
                        .push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }

    Ok(unit)
}

/// Enumerate Linux services (SysV init)
#[cfg(target_os = "linux")]
pub fn enumerate_linux_services() -> Result<Vec<ServiceInfo>> {
    use std::fs;
    use std::path::Path;

    let mut services = Vec::new();

    // Check /etc/init.d
    let init_d = Path::new("/etc/init.d");
    if init_d.exists() {
        if let Ok(entries) = fs::read_dir(init_d) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    // Try to get status
                    let status = get_init_d_status(&name);
                    services.push(ServiceInfo {
                        name: name.clone(),
                        display_name: name,
                        description: None,
                        status,
                        start_type: ServiceStartType::Unknown,
                        binary_path: Some(path.to_string_lossy().to_string()),
                        service_account: None,
                        dependencies: Vec::new(),
                        pid: None,
                        binary_hash: None,
                        signature_status: None,
                        load_order_group: None,
                        error_control: None,
                        tag_id: None,
                        interactive: false,
                        service_type: ServiceType::Win32OwnProcess,
                        source: ServiceSource::InitD,
                    });
                }
            }
        }
    }

    Ok(services)
}

/// Get SysV init script status
#[cfg(target_os = "linux")]
fn get_init_d_status(name: &str) -> ServiceStatus {
    use std::process::Command;

    let output = Command::new("service").args([name, "status"]).output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{} {}", stdout, stderr).to_lowercase();
            if combined.contains("running") || combined.contains("active") {
                ServiceStatus::Running
            } else if combined.contains("stopped")
                || combined.contains("inactive")
                || combined.contains("dead")
            {
                ServiceStatus::Stopped
            } else {
                ServiceStatus::Unknown
            }
        }
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Main entry point for service enumeration
pub fn enumerate_services() -> Result<ServicesResult> {
    let mut result = ServicesResult::new();

    #[cfg(target_os = "windows")]
    {
        result.services = enumerate_windows_services()?;
        result.drivers = enumerate_windows_drivers()?;
    }

    #[cfg(target_os = "linux")]
    {
        result.services = enumerate_linux_services()?;
        result.systemd_units = enumerate_systemd_units()?;
    }

    Ok(result)
}

/// Enumerate kernel drivers (alias for driver enumeration)
pub fn enumerate_drivers() -> Result<Vec<DriverInfo>> {
    #[cfg(target_os = "windows")]
    {
        enumerate_windows_drivers()
    }

    #[cfg(target_os = "linux")]
    {
        // Parse /proc/modules
        use std::fs;
        let mut drivers = Vec::new();
        if let Ok(content) = fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    drivers.push(DriverInfo {
                        name: parts[0].to_string(),
                        display_name: None,
                        path: None,
                        status: ServiceStatus::Running,
                        start_type: ServiceStartType::Unknown,
                        image_base: None,
                        image_size: parts[1].parse().ok(),
                        hash: None,
                        signature_status: None,
                        signer: None,
                        timestamp: None,
                        byovd_indicators: Vec::new(),
                        source: ServiceSource::InitD,
                    });
                }
            }
        }
        Ok(drivers)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(ServicesError::UnsupportedPlatform("Platform not supported".to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_services_result_creation() {
        let result = ServicesResult::new();
        assert!(result.services.is_empty());
        assert!(result.drivers.is_empty());
        assert!(result.systemd_units.is_empty());
    }
}
