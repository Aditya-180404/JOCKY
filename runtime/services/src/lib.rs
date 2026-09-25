//! JOCKEY Runtime - Service Enumeration
//!
//! Enumerates Windows services, systemd units, and kernel drivers.

use anyhow::{Context, Result};
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
    use std::ffi::OsString;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Services::*;
    use windows::Win32::System::Threading::*;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{BufReader, Read};

    let mut services = Vec::new();

    // Open SCM
    let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT)? };

    // Enumerate services
    let mut bytes_needed = 0u32;
    let mut services_returned = 0u32;
    let mut resume_handle = 0u32;

    // First call to get buffer size
    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            None,
        );
    }

    let mut buffer = vec![0u8; bytes_needed as usize];
    let enum_result = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(buffer.as_mut_ptr() as *mut _),
            bytes_needed,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            None,
        )
    };

    if enum_result.is_ok() {
        let enum_buffer = unsafe { &*(buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW) };
        let slice = unsafe { std::slice::from_raw_parts(enum_buffer, services_returned as usize) };

        for entry in slice {
            let name = String::from_utf16_lossy(&entry.lpServiceName[..entry.lpServiceName.iter().position(|&c| c == 0).unwrap_or(entry.lpServiceName.len())]);
            let display_name = String::from_utf16_lossy(&entry.lpDisplayName[..entry.lpDisplayName.iter().position(|&c| c == 0).unwrap_or(entry.lpDisplayName.len())]);

            // Open service for more details
            let service_name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            if let Ok(service) = unsafe { OpenServiceW(scm, PCWSTR(service_name_wide.as_ptr()), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) } {
                // Get config
                let mut config_bytes = 0u32;
                unsafe { QueryServiceConfigW(service, None, 0, &mut config_bytes); }
                let mut config_buffer = vec![0u8; config_bytes as usize];
                if unsafe { QueryServiceConfigW(service, Some(config_buffer.as_mut_ptr() as *mut _), config_bytes, &mut config_bytes) }.is_ok() {
                    let config = unsafe { &*(config_buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };

                    let binary_path = if !config.lpBinaryPathName.is_null() {
                        let len = (0..).take_while(|&i| unsafe { *config.lpBinaryPathName.offset(i) != 0 }).count();
                        Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(config.lpBinaryPathName, len) }))
                    } else {
                        None
                    };

                    let service_account = if !config.lpServiceStartName.is_null() {
                        let len = (0..).take_while(|&i| unsafe { *config.lpServiceStartName.offset(i) != 0 }).count();
                        Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(config.lpServiceStartName, len) }))
                    } else {
                        None
                    };

                    let load_order_group = if !config.lpLoadOrderGroup.is_null() {
                        let len = (0..).take_while(|&i| unsafe { *config.lpLoadOrderGroup.offset(i) != 0 }).count();
                        Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(config.lpLoadOrderGroup, len) }))
                    } else {
                        None
                    };

                    // Get dependencies
                    let mut dep_bytes = 0u32;
                    unsafe { QueryServiceConfig2W(service, SERVICE_CONFIG_DEPENDENCIES, None, 0, &mut dep_bytes); }
                    let mut dependencies = Vec::new();
                    if dep_bytes > 0 {
                        let mut dep_buffer = vec![0u8; dep_bytes as usize];
                        if unsafe { QueryServiceConfig2W(service, SERVICE_CONFIG_DEPENDENCIES, Some(dep_buffer.as_mut_ptr() as *mut _), dep_bytes, &mut dep_bytes) }.is_ok() {
                            let dep_str = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(dep_buffer.as_ptr() as *const u16, dep_bytes as usize / 2) });
                            dependencies = dep_str.split('\0').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                        }
                    }

                    // Compute binary hash
                    let binary_hash = binary_path.as_ref().and_then(|p| {
                        if let Ok(file) = File::open(p) {
                            let mut reader = BufReader::new(file);
                            let mut hasher = Sha256::new();
                            let mut buf = [0; 8192];
                            loop {
                                match reader.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(n) => hasher.update(&buf[..n]),
                                    Err(_) => return None,
                                }
                            }
                            Some(hex::encode(hasher.finalize()))
                        } else {
                            None
                        }
                    });

                    let service_info = ServiceInfo {
                        name,
                        display_name,
                        description: None, // Would need QueryServiceConfig2 with SERVICE_CONFIG_DESCRIPTION
                        status: match entry.ServiceStatusProcess.dwCurrentState {
                            SERVICE_STOPPED => ServiceStatus::Stopped,
                            SERVICE_RUNNING => ServiceStatus::Running,
                            SERVICE_PAUSED => ServiceStatus::Paused,
                            SERVICE_START_PENDING => ServiceStatus::StartPending,
                            SERVICE_STOP_PENDING => ServiceStatus::StopPending,
                            SERVICE_CONTINUE_PENDING => ServiceStatus::ContinuePending,
                            SERVICE_PAUSE_PENDING => ServiceStatus::PausePending,
                            _ => ServiceStatus::Unknown,
                        },
                        start_type: match config.dwStartType {
                            SERVICE_BOOT_START => ServiceStartType::Boot,
                            SERVICE_SYSTEM_START => ServiceStartType::System,
                            SERVICE_AUTO_START => ServiceStartType::Auto,
                            SERVICE_DEMAND_START => ServiceStartType::Demand,
                            SERVICE_DISABLED => ServiceStartType::Disabled,
                            _ => ServiceStartType::Unknown,
                        },
                        binary_path,
                        service_account,
                        dependencies,
                        pid: if entry.ServiceStatusProcess.dwProcessId != 0 {
                            Some(entry.ServiceStatusProcess.dwProcessId)
                        } else {
                            None
                        },
                        binary_hash,
                        signature_status: None, // Would need WinVerifyTrust
                        load_order_group,
                        error_control: Some(match config.dwErrorControl {
                            SERVICE_ERROR_IGNORE => "Ignore".to_string(),
                            SERVICE_ERROR_NORMAL => "Normal".to_string(),
                            SERVICE_ERROR_SEVERE => "Severe".to_string(),
                            SERVICE_ERROR_CRITICAL => "Critical".to_string(),
                            _ => "Unknown".to_string(),
                        }),
                        tag_id: if config.dwTagId != 0 { Some(config.dwTagId) } else { None },
                        interactive: config.dwServiceType & SERVICE_INTERACTIVE_PROCESS != 0,
                        service_type: match config.dwServiceType & 0xFF {
                            SERVICE_KERNEL_DRIVER => ServiceType::KernelDriver,
                            SERVICE_FILE_SYSTEM_DRIVER => ServiceType::FileSystemDriver,
                            SERVICE_WIN32_OWN_PROCESS => ServiceType::Win32OwnProcess,
                            SERVICE_WIN32_SHARE_PROCESS => ServiceType::Win32ShareProcess,
                            SERVICE_INTERACTIVE_PROCESS => ServiceType::InteractiveProcess,
                            _ => ServiceType::Unknown,
                        },
                        source: ServiceSource::WindowsSCM,
                    };
                    services.push(service_info);
                }
                unsafe { CloseServiceHandle(service); }
            }
        }
    }

    unsafe { CloseServiceHandle(scm); }

    Ok(services)
}

/// Enumerate Windows kernel drivers
#[cfg(target_os = "windows")]
pub fn enumerate_windows_drivers() -> Result<Vec<DriverInfo>> {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::SystemServices::*;
    use windows::Win32::System::Threading::*;
    use std::ffi::OsString;

    let mut drivers = Vec::new();

    // Use EnumDeviceDrivers
    let mut drivers_buffer = [0u64; 1024];
    let mut needed = 0u32;
    if unsafe { EnumDeviceDrivers(drivers_buffer.as_mut_ptr() as *mut _, (drivers_buffer.len() * 8) as u32, &mut needed) }.is_ok() {
        let count = (needed / 8) as usize;
        for i in 0..count {
            let base = drivers_buffer[i];
            if base == 0 { continue; }

            // Get driver name
            let mut name_buffer = [0u16; 256];
            let name_len = unsafe { GetDeviceDriverBaseNameW(base as *mut _, &mut name_buffer) };
            if name_len > 0 {
                let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);

                // Get driver path
                let mut path_buffer = [0u16; 1024];
                let path_len = unsafe { GetDeviceDriverFileNameW(base as *mut _, &mut path_buffer) };
                let path = if path_len > 0 {
                    Some(String::from_utf16_lossy(&path_buffer[..path_len as usize]))
                } else {
                    None
                };

                // Get driver info (would need more APIs for full details)
                drivers.push(DriverInfo {
                    name,
                    display_name: None,
                    path,
                    status: ServiceStatus::Running, // Loaded drivers are running
                    start_type: ServiceStartType::Unknown,
                    image_base: Some(base),
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

/// Enumerate systemd units
#[cfg(target_os = "linux")]
pub fn enumerate_systemd_units() -> Result<Vec<SystemdUnitInfo>> {
    use std::fs;
    use std::path::Path;

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
                    || path.extension().and_then(|s| s.to_str()) == Some("device") {
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
            current_section = line[1..line.len()-1].to_string();
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
                    "Requires" => unit.dependencies = value.split_whitespace().map(|s| s.to_string()).collect(),
                    "Wants" => unit.wants = value.split_whitespace().map(|s| s.to_string()).collect(),
                    "After" | "Before" => {
                        // Ordering dependencies
                        unit.dependencies.extend(value.split_whitespace().map(|s| s.to_string()));
                    }
                    _ => {}
                }
            }
            "Service" => {
                match key {
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
                                unit.environment.insert(env[..eq_pos].to_string(), env[eq_pos+1..].to_string());
                            }
                        }
                    }
                    "Restart" => unit.restart = Some(value.to_string()),
                    "RestartSec" => unit.restart_sec = Some(value.to_string()),
                    "MemoryLimit" => unit.memory_limit = Some(value.to_string()),
                    "CPUQuota" => unit.cpu_limit = Some(value.to_string()),
                    _ => {}
                }
            }
            "Timer" => {
                let mut timer = unit.timer_properties.get_or_insert(TimerProperties {
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
            "Install" => {
                match key {
                    "WantedBy" => unit.wanted_by = value.split_whitespace().map(|s| s.to_string()).collect(),
                    "RequiredBy" => unit.required_by = value.split_whitespace().map(|s| s.to_string()).collect(),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Check for drop-in files
    let dropin_dir = path.with_extension("d");
    if dropin_dir.exists() {
        if let Ok(entries) = fs::read_dir(&dropin_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("conf") {
                    unit.drop_in_paths.push(entry.path().to_string_lossy().to_string());
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

    let output = Command::new("service")
        .args([name, "status"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{} {}", stdout, stderr).to_lowercase();
            if combined.contains("running") || combined.contains("active") {
                ServiceStatus::Running
            } else if combined.contains("stopped") || combined.contains("inactive") || combined.contains("dead") {
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