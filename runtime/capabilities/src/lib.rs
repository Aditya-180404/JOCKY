//! JOCKEY Capability Registry
//!
//! Central registry for all forensic capabilities. Each capability has:
//! - Unique ID (string)
//! - Category/domain
//! - Platform support (Windows, Linux, both)
//! - Required privilege level
//! - Description
//! - MITRE ATT&CK technique mappings

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

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
        }
    }
}

/// The global capability registry
pub struct CapabilityRegistry {
    capabilities: HashMap<String, Capability>,
    by_category: HashMap<CapabilityCategory, Vec<String>>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            capabilities: HashMap::new(),
            by_category: HashMap::new(),
        };
        registry.register_all();
        registry
    }

    fn register_named_capabilities(
        &mut self,
        entries: &[Capability],
    ) {
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
            Capability::new("process.pid", "Process ID", "Collect the process identifier for each running process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.ppid", "Parent PID", "Collect parent process identifiers to construct ancestry.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.name", "Process Name", "Collect the executable name for each process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.command_line", "Command Line", "Collect full command lines for process inspection.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.executable_path", "Executable Path", "Capture the resolved executable path for each process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.cwd", "Working Directory", "Collect the process working directory when permitted.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.start_time", "Start Time", "Collect process creation time for timeline correlation.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.user", "Process User", "Collect the owning user for each process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.group", "Process Group", "Collect primary group metadata for processes.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.state", "Process State", "Collect the process life-cycle state.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.memory.rss", "RSS Memory", "Capture resident set size to identify heavy or suspicious processes.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.memory.vms", "Virtual Memory", "Capture virtual memory usage for process triage.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.threads", "Thread Count", "Collect the process thread count.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.handles", "Handle Count", "Collect open handle counts where available.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.session", "Session ID", "Collect the session identifier for system and user sessions.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.terminal", "Terminal", "Collect terminal and tty metadata when available.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.priority", "Priority", "Collect scheduler priority metadata.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.nice", "Nice Value", "Collect the nice value and scheduling context.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.env", "Environment", "Capture the process environment block where permitted.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.cgroup", "CGroup", "Capture cgroup and container metadata.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.container", "Container ID", "Demonstrate container membership when present.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.module.list", "Loaded Modules", "Enumerate DLL or shared library modules loaded by a process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1014"], "collect_process_modules", true),
            Capability::new("process.module.path", "Module Paths", "Capture module path metadata for loaded libraries.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1014"], "collect_process_modules", true),
            Capability::new("process.module.version", "Module Versions", "Collect library version metadata for modules.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1014"], "collect_process_modules", true),
            Capability::new("process.module.signature", "Module Signatures", "Capture signing state when available for libraries.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1014"], "collect_process_modules", true),
            Capability::new("process.parent.name", "Parent Name", "Resolve parent process names for ancestry analysis.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "collect_process_tree", true),
            Capability::new("process.child.pids", "Child PIDs", "Resolve child process identifiers for process tree extraction.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "collect_process_tree", true),
            Capability::new("process.tree", "Process Tree", "Construct a parent-child process tree and ancestry model.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "collect_process_tree", true),
            Capability::new("process.memory.map", "Memory Regions", "Enumerate memory mappings and executable memory regions.", CapabilityCategory::Process, Platform::Linux, PrivilegeLevel::User, &["T1055"], "enumerate_memory_regions", true),
            Capability::new("process.deleted.exe", "Deleted Executable", "Detect deleted-on-disk executables still mapped or running.", CapabilityCategory::Process, Platform::Linux, PrivilegeLevel::User, &["T1036"], "detect_deleted_executables", true),
            Capability::new("process.open.files", "Open Files", "Collect file handle metadata and open file paths for each process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
            Capability::new("process.network.connections", "Process Network", "Associate network connections with the owning process.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_processes", true),
            Capability::new("process.hash", "Executable Hash", "Collect the SHA-256 hash of a process executable when available.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1027"], "enumerate_processes", true),
            Capability::new("process.integrity", "Integrity Level", "Capture process integrity metadata when exposed by the platform.", CapabilityCategory::Process, Platform::Both, PrivilegeLevel::User, &["T1057"], "enumerate_processes", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_user_and_auth_capabilities(&mut self) {
        let entries = [
            Capability::new("user.list", "User List", "Enumerate local account inventory and base metadata.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.sid", "User IDs", "Capture user IDs, SIDs, and account identity metadata.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.home", "Home Directories", "Enumerate user home directory metadata.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.shell", "User Shell", "Collect login shell configuration for each account.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.group.membership", "Group Membership", "Collect group memberships for each user.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.last.login", "Last Login", "Collect last login metadata when available.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.status", "Account Status", "Collect account disabled, locked, and status flags.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1087"], "enumerate_users", true),
            Capability::new("user.admin", "Privileged Users", "Identify administrator or elevated accounts.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1078"], "enumerate_users", true),
            Capability::new("user.service.accounts", "Service Accounts", "Enumerate service and non-human accounts.", CapabilityCategory::User, Platform::Both, PrivilegeLevel::User, &["T1078"], "enumerate_users", true),
            Capability::new("auth.logon.events", "Logon Events", "Collect authentication events with metadata and timestamps.", CapabilityCategory::Authentication, Platform::Both, PrivilegeLevel::Admin, &["T1110"], "collect_logon_events", true),
            Capability::new("auth.successful.logins", "Successful Logins", "Capture successful sign-in records.", CapabilityCategory::Authentication, Platform::Both, PrivilegeLevel::Admin, &["T1110"], "collect_logon_events", true),
            Capability::new("auth.failed.logins", "Failed Logins", "Collect failed sign-in activity and lockout evidence.", CapabilityCategory::Authentication, Platform::Both, PrivilegeLevel::Admin, &["T1110"], "collect_logon_events", true),
            Capability::new("auth.remote.sessions", "Remote Sessions", "Inventory remote access sessions when available.", CapabilityCategory::Authentication, Platform::Both, PrivilegeLevel::User, &["T1021"], "collect_logon_events", true),
            Capability::new("auth.ssh.config", "SSH Configuration", "Collect SSH configuration and host metadata.", CapabilityCategory::Authentication, Platform::Linux, PrivilegeLevel::User, &["T1552"], "collect_auth_policy", true),
            Capability::new("auth.ssh.authorized.keys", "Authorized Keys", "Collect SSH authorized key metadata without exposing secrets.", CapabilityCategory::Authentication, Platform::Linux, PrivilegeLevel::User, &["T1552"], "collect_auth_policy", true),
            Capability::new("auth.ssh.known.hosts", "Known Hosts", "Collect SSH known-host metadata.", CapabilityCategory::Authentication, Platform::Linux, PrivilegeLevel::User, &["T1552"], "collect_auth_policy", true),
            Capability::new("auth.password.policy", "Password Policy", "Collect local password and account policy metadata.", CapabilityCategory::Authentication, Platform::Both, PrivilegeLevel::User, &["T1204"], "collect_auth_policy", true),
            Capability::new("auth.sudoers", "Sudoers", "Collect sudoers configuration and delegation metadata.", CapabilityCategory::Authentication, Platform::Linux, PrivilegeLevel::User, &["T1548"], "collect_auth_policy", true),
            Capability::new("auth.pam", "PAM Configuration", "Read PAM configuration metadata for authentication flows.", CapabilityCategory::Authentication, Platform::Linux, PrivilegeLevel::User, &["T1556"], "collect_auth_policy", true),
            Capability::new("auth.windows.logon", "Windows Logons", "Collect Windows logon metadata via native event sources.", CapabilityCategory::Authentication, Platform::Windows, PrivilegeLevel::Admin, &["T1110"], "collect_windows_logon_events", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_service_and_persistence_capabilities(&mut self) {
        let entries = [
            Capability::new("service.list", "Service Inventory", "Enumerate installed services and runtime state.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.name", "Service Name", "Collect the service name and display name metadata.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.state", "Service State", "Collect the current start state of each service.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.binary.path", "Service Binary", "Capture the executable path used by each service.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.account", "Service Account", "Collect the account used to run each service.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.dependencies", "Service Dependencies", "Collect dependent service chains and startup order.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.start.mode", "Service Start Mode", "Collect start-mode classifications and service triggers.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1543"], "enumerate_services", true),
            Capability::new("service.driver.list", "Driver Inventory", "Enumerate kernel drivers and installed driver metadata.", CapabilityCategory::Service, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_drivers", true),
            Capability::new("service.systemd.units", "Systemd Units", "Enumerate systemd unit inventory and metadata.", CapabilityCategory::Service, Platform::Linux, PrivilegeLevel::User, &["T1543"], "enumerate_systemd_units", true),
            Capability::new("persistence.run", "Run Keys", "Collect Run and RunOnce registry persistence locations.", CapabilityCategory::Persistence, Platform::Windows, PrivilegeLevel::User, &["T1547"], "collect_autostart_entries", true),
            Capability::new("persistence.startup.folder", "Startup Folder", "Enumerate startup directory persistence entries.", CapabilityCategory::Persistence, Platform::Both, PrivilegeLevel::User, &["T1547"], "collect_autostart_entries", true),
            Capability::new("persistence.scheduled.task", "Scheduled Tasks", "Enumerate scheduled tasks and task actions.", CapabilityCategory::Persistence, Platform::Both, PrivilegeLevel::User, &["T1053"], "collect_autostart_entries", true),
            Capability::new("persistence.cron", "Cron Entries", "Enumerate cron and crontab persistence artifacts.", CapabilityCategory::Persistence, Platform::Linux, PrivilegeLevel::User, &["T1053"], "collect_autostart_entries", true),
            Capability::new("persistence.systemd.timer", "Systemd Timers", "Enumerate systemd timer persistence entries.", CapabilityCategory::Persistence, Platform::Linux, PrivilegeLevel::User, &["T1053"], "collect_autostart_entries", true),
            Capability::new("persistence.shell.profile", "Shell Profiles", "Collect shell profile and login script persistence metadata.", CapabilityCategory::Persistence, Platform::Both, PrivilegeLevel::User, &["T1547"], "collect_autostart_entries", true),
            Capability::new("persistence.wmi", "WMI Persistence", "Collect WMI persistence subscriptions when present.", CapabilityCategory::Persistence, Platform::Windows, PrivilegeLevel::Admin, &["T1546"], "collect_autostart_entries", true),
            Capability::new("persistence.ssh", "SSH Persistence", "Collect SSH configuration and key-based persistence metadata.", CapabilityCategory::Persistence, Platform::Linux, PrivilegeLevel::User, &["T1098"], "collect_autostart_entries", true),
            Capability::new("persistence.winlogon", "Winlogon", "Collect Winlogon startup configuration metadata.", CapabilityCategory::Persistence, Platform::Windows, PrivilegeLevel::User, &["T1547"], "collect_autostart_entries", true),
            Capability::new("persistence.ifeo", "IFEO", "Collect Image File Execution Options persistence metadata.", CapabilityCategory::Persistence, Platform::Windows, PrivilegeLevel::User, &["T1546"], "collect_autostart_entries", true),
            Capability::new("persistence.appinit", "AppInit", "Collect AppInit DLL persistence metadata.", CapabilityCategory::Persistence, Platform::Windows, PrivilegeLevel::User, &["T1546"], "collect_autostart_entries", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_network_capabilities(&mut self) {
        let entries = [
            Capability::new("network.interfaces", "Interface Inventory", "Collect network interfaces and basic metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.interface.addresses", "Interface Addresses", "Collect IPv4 and IPv6 addresses for active interfaces.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.mac", "MAC Addresses", "Collect interface MAC addresses and driver metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.routes", "Route Table", "Collect IPv4 and IPv6 routes and gateway metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.arp", "ARP Table", "Collect neighbor cache metadata and link-layer mappings.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.dns.servers", "DNS Servers", "Collect configured DNS server settings.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.dns.cache", "DNS Cache", "Collect cached DNS entries when available on the host.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.hosts", "Hosts File", "Collect hosts file entries and custom name resolution metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.connections.active", "Active Connections", "Enumerate active TCP and UDP connections.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
            Capability::new("network.listening.ports", "Listening Ports", "Enumerate local listening sockets and bound addresses.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
            Capability::new("network.tcp", "TCP Connections", "Collect TCP state, endpoints, and process ownership metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
            Capability::new("network.udp", "UDP Connections", "Collect UDP sockets and endpoint metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
            Capability::new("network.process.relationships", "Process Relationships", "Map socket ownership to associated processes.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
            Capability::new("network.proxy", "Proxy Configuration", "Collect proxy configuration metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.vpn", "VPN Metadata", "Collect VPN configuration and tunnel metadata when available.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1016"], "enumerate_connections", true),
            Capability::new("network.firewall.policy", "Firewall Policy", "Collect firewall configuration and rule metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::Admin, &["T1562"], "enumerate_connections", true),
            Capability::new("network.shares", "Network Shares", "Collect SMB or remote share metadata.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1021"], "enumerate_connections", true),
            Capability::new("network.listeners", "Suspicious Listeners", "Identify unexpected listening services and unusual binds.", CapabilityCategory::Network, Platform::Both, PrivilegeLevel::User, &["T1049"], "enumerate_connections", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_filesystem_capabilities(&mut self) {
        let entries = [
            Capability::new("filesystem.enumerate", "Filesystem Enumeration", "Enumerate discovered files and directories.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.path", "File Paths", "Collect file and directory paths for forensic review.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.size", "File Sizes", "Collect file size metadata for suspicious or large artifacts.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.timestamps", "File Timestamps", "Collect creation, modification, and access timestamps.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.permissions", "Permissions", "Collect permission bits and ownership metadata.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.owner", "Ownership", "Collect user and group ownership metadata.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.type", "File Type", "Identify file and directory types for triage.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.hidden", "Hidden Files", "Capture hidden and dot-prefixed entries.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.links", "Symlinks", "Enumerate symlinks and link targets.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.executable", "Executable Detection", "Flag executable and script file entries.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1036"], "enumerate_files", true),
            Capability::new("filesystem.hash.sha256", "SHA-256 Hashes", "Compute SHA-256 hashes for files and evidence items.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1027"], "enumerate_files", true),
            Capability::new("filesystem.hash.sha1", "SHA-1 Hashes", "Compute legacy SHA-1 hashes where required for correlation.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1027"], "enumerate_files", true),
            Capability::new("filesystem.hash.md5", "MD5 Hashes", "Compute MD5 values for legacy sample matching and triage.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1027"], "enumerate_files", true),
            Capability::new("filesystem.recent", "Recent Files", "Collect recently modified and created artifacts.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
            Capability::new("filesystem.mounts", "Mount Metadata", "Collect filesystem mount metadata and labels.", CapabilityCategory::Filesystem, Platform::Both, PrivilegeLevel::User, &["T1083"], "enumerate_mounts", true),
            Capability::new("filesystem.alternate.data.streams", "ADS Metadata", "Identify alternate data streams on supported filesystems.", CapabilityCategory::Filesystem, Platform::Windows, PrivilegeLevel::User, &["T1564"], "enumerate_files", true),
            Capability::new("filesystem.deleted.open", "Deleted-But-Open Files", "Identify file handles to deleted content when exposed by the OS.", CapabilityCategory::Filesystem, Platform::Linux, PrivilegeLevel::User, &["T1083"], "enumerate_files", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_windows_artifact_capabilities(&mut self) {
        let entries = [
            Capability::new("artifact.prefetch", "Prefetch Inventory", "Collect Prefetch metadata for executable execution history.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1057"], "carve_prefetch", true),
            Capability::new("artifact.lnk", "LNK Inventory", "Collect LNK shortcut metadata and target path details.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1057"], "carve_lnk_files", true),
            Capability::new("artifact.recycle.bin", "Recycle Bin Inventory", "Collect Recycle Bin metadata for deleted file evidence.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1070"], "carve_recycle_bin", true),
            Capability::new("artifact.shellbags", "Shellbags", "Collect Shellbag metadata for folder access history.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1083"], "carve_shellbags", true),
            Capability::new("artifact.jump.lists", "Jump Lists", "Collect Jump List metadata for recent file usage history.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1057"], "carve_jumplists", true),
            Capability::new("artifact.amcache", "Amcache Inventory", "Collect Amcache execution metadata and file hashes.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::Admin, &["T1057"], "carve_amcache", true),
            Capability::new("artifact.srum", "SRUM Inventory", "Collect SRUM application and resource usage records.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::Admin, &["T1057"], "carve_srum", true),
            Capability::new("artifact.etw", "ETW Inventory", "Collect ETW-oriented telemetry metadata when available.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::Admin, &["T1562"], "collect_etw_logs", true),
            Capability::new("artifact.event.logs", "Event Logs", "Collect Windows event log metadata for authentication and process activity.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::Admin, &["T1562"], "carve_prefetch", true),
            Capability::new("artifact.recent.files", "Recent Files", "Collect recent document metadata from Windows user artifacts.", CapabilityCategory::WindowsArtifact, Platform::Windows, PrivilegeLevel::User, &["T1070"], "carve_lnk_files", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_linux_artifact_capabilities(&mut self) {
        let entries = [
            Capability::new("artifact.shell.history", "Shell History", "Collect shell history data and commands from user profiles.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1552"], "carve_shell_history", true),
            Capability::new("artifact.cron", "Cron Artifacts", "Collect system and user cron entries and schedules.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1053"], "carve_cron_entries", true),
            Capability::new("artifact.systemd", "Systemd Units", "Collect systemd unit definitions and service metadata.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1543"], "carve_systemd_units", true),
            Capability::new("artifact.ssh", "SSH Artifacts", "Collect SSH config, known_hosts, and related metadata.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1552"], "carve_ssh_config", true),
            Capability::new("artifact.auth.logs", "Auth Logs", "Collect authentication and authorization log inventory.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1110"], "collect_logs", true),
            Capability::new("artifact.journal", "Journal Inventory", "Collect journald metadata and log source inventory.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1562"], "collect_logs", true),
            Capability::new("artifact.auditd", "Auditd Inventory", "Collect auditd configuration and log source inventory.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1562"], "collect_logs", true),
            Capability::new("artifact.sudo", "Sudo Logs", "Collect sudo authority and command logging metadata.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1548"], "collect_logs", true),
            Capability::new("artifact.bash.history", "Bash History", "Collect shell command history for current users.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1552"], "carve_shell_history", true),
            Capability::new("artifact.zsh.history", "Zsh History", "Collect zsh command history when present.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1552"], "carve_shell_history", true),
            Capability::new("artifact.login.config", "Login Configuration", "Collect login policy and login shell configuration metadata.", CapabilityCategory::LinuxArtifact, Platform::Linux, PrivilegeLevel::User, &["T1078"], "collect_logs", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_driver_security_capabilities(&mut self) {
        let entries = [
            Capability::new("kernel.modules", "Kernel Modules", "Enumerate loaded kernel modules and metadata.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("kernel.module.paths", "Module Paths", "Capture kernel module file paths and dependencies.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("kernel.module.params", "Module Parameters", "Collect module parameters and configuration values.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("kernel.module.version", "Module Versions", "Collect loaded module version information.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("kernel.module.signatures", "Module Signatures", "Collect signature state when available from the platform.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("kernel.module.hashes", "Kernel Hashes", "Capture module file hashes for integrity review.", CapabilityCategory::KernelDriver, Platform::Both, PrivilegeLevel::User, &["T1014"], "enumerate_modules", true),
            Capability::new("security.audit.policy", "Audit Policy", "Collect audit policy metadata and log configuration.", CapabilityCategory::SecurityConfig, Platform::Both, PrivilegeLevel::Admin, &["T1562"], "collect_audit_policy", true),
            Capability::new("security.antivirus", "AV Inventory", "Inventory security products and signatures when available.", CapabilityCategory::SecurityConfig, Platform::Both, PrivilegeLevel::User, &["T1562"], "detect_av_edr", true),
            Capability::new("security.firewall", "Firewall State", "Collect local firewall configuration and rule state.", CapabilityCategory::SecurityConfig, Platform::Both, PrivilegeLevel::Admin, &["T1562"], "collect_firewall_rules", true),
            Capability::new("security.selinux", "SELinux State", "Collect SELinux enforcement metadata when available.", CapabilityCategory::SecurityConfig, Platform::Linux, PrivilegeLevel::User, &["T1562"], "collect_app_control", true),
            Capability::new("security.apparmor", "AppArmor State", "Collect AppArmor policy metadata when available.", CapabilityCategory::SecurityConfig, Platform::Linux, PrivilegeLevel::User, &["T1562"], "collect_app_control", true),
            Capability::new("security.policy", "Security Policy", "Collect application control and local policy metadata.", CapabilityCategory::SecurityConfig, Platform::Both, PrivilegeLevel::Admin, &["T1562"], "collect_app_control", true),
            Capability::new("security.update.state", "Update State", "Collect general update and patch status metadata.", CapabilityCategory::SecurityConfig, Platform::Both, PrivilegeLevel::User, &["T1562"], "detect_av_edr", true),
        ];
        self.register_named_capabilities(&entries);
    }

    fn register_application_and_malware_capabilities(&mut self) {
        let entries = [
            Capability::new("app.browser.inventory", "Browser Inventory", "Collect browser installation and profile inventory metadata.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1555"], "carve_browser_artifacts", true),
            Capability::new("app.browser.extensions", "Browser Extensions", "Collect browser extension metadata without exposing secrets.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1555"], "carve_browser_artifacts", true),
            Capability::new("app.browser.history", "Browser History", "Collect browser history metadata and recent URL access indicators.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1555"], "carve_browser_artifacts", true),
            Capability::new("app.browser.downloads", "Browser Downloads", "Collect browser download metadata without tokenizing secrets.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1555"], "carve_browser_artifacts", true),
            Capability::new("app.browser.cookies", "Browser Cookies", "Collect cookie metadata while avoiding secret exfiltration.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1555"], "carve_browser_artifacts", true),
            Capability::new("app.email", "Email Artifacts", "Collect email client metadata and storage inventory.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1114"], "carve_email_artifacts", true),
            Capability::new("app.office", "Office Artifacts", "Collect recent Office document metadata and macro indicators.", CapabilityCategory::ApplicationArtifact, Platform::Both, PrivilegeLevel::User, &["T1137"], "carve_office_artifacts", true),
            Capability::new("script.powershell.metadata", "PowerShell Metadata", "Capture PowerShell script file metadata and interpreter usage.", CapabilityCategory::MaliciousScript, Platform::Windows, PrivilegeLevel::User, &["T1059.001"], "analyze_powershell_scripts", true),
            Capability::new("script.bash.metadata", "Bash Metadata", "Capture bash script metadata and file attributes.", CapabilityCategory::MaliciousScript, Platform::Linux, PrivilegeLevel::User, &["T1059.004"], "analyze_shell_scripts", true),
            Capability::new("script.python.metadata", "Python Metadata", "Capture Python script metadata and import usage.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059.006"], "analyze_python_scripts", true),
            Capability::new("script.javascript.metadata", "JavaScript Metadata", "Capture JavaScript file metadata and entry points.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059.007"], "analyze_python_scripts", true),
            Capability::new("script.cmd.metadata", "CMD Metadata", "Collect batch or cmd script metadata and execution patterns.", CapabilityCategory::MaliciousScript, Platform::Windows, PrivilegeLevel::User, &["T1059.003"], "analyze_powershell_scripts", true),
            Capability::new("script.url.indicators", "URL Indicators", "Extract URL-like indicators from scripts for triage.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_powershell_scripts", true),
            Capability::new("script.ip.indicators", "IP Indicators", "Extract IP address indicators from scripts.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_shell_scripts", true),
            Capability::new("script.file.indicators", "File Path Indicators", "Extract filesystem and registry path indicators from scripts.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_python_scripts", true),
            Capability::new("script.environment.indicators", "Environment Indicators", "Extract environment variable references and startup patterns.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_powershell_scripts", true),
            Capability::new("script.obfuscation", "Obfuscation Indicators", "Flag encoded and obfuscated command patterns in scripts.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_shell_scripts", true),
            Capability::new("script.execution", "Execution Indicators", "Extract command execution indicators from scripts.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1059"], "analyze_python_scripts", true),
            Capability::new("script.persistence", "Persistence Indicators", "Flag startup or persistence patterns within scripts.", CapabilityCategory::MaliciousScript, Platform::Both, PrivilegeLevel::User, &["T1547"], "analyze_powershell_scripts", true),
            Capability::new("file.pe.metadata", "PE Metadata", "Read PE file headers and section metadata from Windows binaries.", CapabilityCategory::FileBinaryMetadata, Platform::Windows, PrivilegeLevel::User, &["T1027"], "parse_pe_metadata", true),
            Capability::new("file.elf.metadata", "ELF Metadata", "Read ELF header and section metadata from Linux binaries.", CapabilityCategory::FileBinaryMetadata, Platform::Linux, PrivilegeLevel::User, &["T1027"], "parse_elf_metadata", true),
            Capability::new("file.hash.sha256", "PE/ELF SHA-256", "Compute SHA-256 for executable evidence files.", CapabilityCategory::FileBinaryMetadata, Platform::Both, PrivilegeLevel::User, &["T1027"], "hash_sha256", true),
            Capability::new("file.entropy", "Entropy Analysis", "Measure Shannon entropy to spot packed or obfuscated binaries.", CapabilityCategory::FileBinaryMetadata, Platform::Both, PrivilegeLevel::User, &["T1027"], "analyze_file_entropy", true),
            Capability::new("file.signature", "Signature Metadata", "Collect code-signing metadata and certificate state.", CapabilityCategory::FileBinaryMetadata, Platform::Both, PrivilegeLevel::User, &["T1553"], "verify_code_signature", true),
            Capability::new("evidence.sha256", "Evidence Hashing", "Compute a SHA-256 hash for a forensic item.", CapabilityCategory::EvidenceIntegrity, Platform::Both, PrivilegeLevel::User, &[], "hash_sha256", true),
            Capability::new("evidence.merkle", "Merkle Tree", "Build a canonical Merkle tree from evidence hashes.", CapabilityCategory::EvidenceIntegrity, Platform::Both, PrivilegeLevel::User, &[], "build_merkle_tree", true),
            Capability::new("evidence.provenance", "Provenance Metadata", "Capture operator, host, source, and collection provenance.", CapabilityCategory::EvidenceIntegrity, Platform::Both, PrivilegeLevel::User, &[], "hash_sha256", true),
            Capability::new("evidence.origin", "Evidence Origin", "Track whether evidence is real, simulated, imported, or derived.", CapabilityCategory::EvidenceIntegrity, Platform::Both, PrivilegeLevel::User, &[], "hash_sha256", true),
            Capability::new("evidence.collector.status", "Collector Status", "Capture collector success, partial, failed, and unsupported state.", CapabilityCategory::EvidenceIntegrity, Platform::Both, PrivilegeLevel::User, &[], "hash_sha256", true),
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
            false,
        ));

        self.register(Capability::new(
            "persistence.scheduled_tasks",
            "Scheduled Tasks",
            "Enumerate scheduled tasks/cron jobs: task name, trigger, action, command, run as user, status, history",
            CapabilityCategory::Persistence,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1053"],
            "enumerate_scheduled_tasks",
            false,
        ));

        self.register(Capability::new(
            "persistence.wmi",
            "WMI Event Subscriptions",
            "Enumerate WMI event consumers, filters, and bindings used for persistence",
            CapabilityCategory::Persistence,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1546"],
            "enumerate_wmi_subscriptions",
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "network.dns_cache",
            "DNS Cache",
            "Collect DNS resolver cache entries: domain, IP, TTL, record type",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1016"],
            "collect_dns_cache",
            false,
        ));

        self.register(Capability::new(
            "network.arp_table",
            "ARP/Neighbor Table",
            "Collect ARP table (IPv4) or neighbor table (IPv6): IP, MAC, interface, state",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1016"],
            "collect_arp_table",
            false,
        ));

        self.register(Capability::new(
            "network.routing_table",
            "Routing Table",
            "Collect routing table: destination, gateway, interface, metric, protocol",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1016"],
            "collect_routing_table",
            false,
        ));

        self.register(Capability::new(
            "network.firewall",
            "Firewall Rules",
            "Collect firewall configuration: rules, profiles, logging settings, allowed/blocked applications",
            CapabilityCategory::Network,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_firewall_rules",
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "filesystem.alternate_data_streams",
            "Alternate Data Streams",
            "Detect NTFS alternate data streams on Windows files",
            CapabilityCategory::Filesystem,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1564"],
            "detect_alternate_data_streams",
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "artifact.jumplists",
            "Jump Lists",
            "Parse Jump List files: recent files, application destinations, timestamps",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1057"],
            "carve_jumplists",
            false,
        ));

        self.register(Capability::new(
            "artifact.amcache",
            "Amcache.hve",
            "Parse Amcache registry hive: file execution history, SHA-1 hashes, publisher info, file paths",
            CapabilityCategory::WindowsArtifact,
            Platform::Windows,
            PrivilegeLevel::Admin,
            &["T1057"],
            "carve_amcache",
            false,
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
            false,
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
            false,
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
            false,
        ));

        self.register(Capability::new(
            "artifact.container",
            "Container Artifacts",
            "Detect container runtime artifacts: Docker, containerd, podman images, containers, volumes, networks",
            CapabilityCategory::LinuxArtifact,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1610"],
            "carve_container_artifacts",
            false,
        ));

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
            false,
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
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "security.av_status",
            "Antivirus/EDR Status",
            "Detect AV/EDR products: running processes, services, drivers, signature versions, exclusions",
            CapabilityCategory::SecurityConfig,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1562"],
            "detect_av_edr",
            false,
        ));

        self.register(Capability::new(
            "security.app_control",
            "Application Control",
            "Collect AppLocker, WDAC, SELinux, AppArmor policies and enforcement status",
            CapabilityCategory::SecurityConfig,
            Platform::Both,
            PrivilegeLevel::Admin,
            &["T1562"],
            "collect_app_control",
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "app.email",
            "Email Client Artifacts",
            "Collect email client artifacts: Outlook OST/PST, Thunderbird profiles, mail indexes",
            CapabilityCategory::ApplicationArtifact,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1114"],
            "carve_email_artifacts",
            false,
        ));

        self.register(Capability::new(
            "app.office",
            "Office Artifacts",
            "Collect Microsoft Office artifacts: recent files, trusted locations, macros, document metadata",
            CapabilityCategory::ApplicationArtifact,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1137"],
            "carve_office_artifacts",
            false,
        ));

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
            false,
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
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "script.wmi",
            "WMI/VBScript Analysis",
            "Analyze WMI queries and VBScript: suspicious queries, consumer bindings, encoded scripts",
            CapabilityCategory::MaliciousScript,
            Platform::Windows,
            PrivilegeLevel::User,
            &["T1059.005"],
            "analyze_wmi_scripts",
            false,
        ));

        self.register(Capability::new(
            "script.shell",
            "Shell Script Analysis",
            "Analyze shell scripts: obfuscation, suspicious commands, embedded payloads, reverse shells",
            CapabilityCategory::MaliciousScript,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1059.004"],
            "analyze_shell_scripts",
            false,
        ));

        self.register(Capability::new(
            "script.python",
            "Python Script Analysis",
            "Analyze Python scripts: obfuscation, suspicious imports, encoded payloads, C2 patterns",
            CapabilityCategory::MaliciousScript,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1059.006"],
            "analyze_python_scripts",
            false,
        ));

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
            false,
        ));

        self.register(Capability::new(
            "file.elf_metadata",
            "ELF Metadata",
            "Parse ELF headers: sections, symbols, dynamic entries, notes, build ID, interpreter",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Linux,
            PrivilegeLevel::User,
            &["T1027"],
            "parse_elf_metadata",
            false,
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
            false,
        ));

        self.register(Capability::new(
            "file.entropy",
            "File Entropy Analysis",
            "Calculate Shannon entropy per file/section for packing/encryption detection",
            CapabilityCategory::FileBinaryMetadata,
            Platform::Both,
            PrivilegeLevel::User,
            &["T1027"],
            "analyze_file_entropy",
            false,
        ));

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
            false,
        ));
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
            .map(|ids| ids.iter().filter_map(|id| self.capabilities.get(id.as_str())).collect())
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
        self.capabilities.values().filter(|c| c.is_implemented).collect()
    }

    /// Check whether a capability's collector is actually backed by a runtime implementation.
    pub fn runtime_capability_exists(&self, capability_id: &str) -> bool {
        let Some(capability) = self.capabilities.get(capability_id) else {
            return false;
        };
        if !capability.is_implemented {
            return false;
        }

        static IMPLEMENTED_COLLECTORS: OnceLock<HashSet<&'static str>> = OnceLock::new();
        let collectors = IMPLEMENTED_COLLECTORS.get_or_init(|| {
            let mut set = HashSet::new();
            for collector in [
                "collect_system_info",
                "collect_system_info_detailed",
                "collect_system_users",
                "enumerate_processes",
                "collect_process_tree",
                "collect_process_modules",
                "enumerate_memory_regions",
                "collect_process_handles",
                "detect_deleted_executables",
                "enumerate_users",
                "collect_logon_events",
                "collect_credential_artifacts",
                "collect_auth_policy",
                "enumerate_services",
                "enumerate_systemd_units",
                "enumerate_drivers",
                "enumerate_connections",
                "collect_logs",
                "hash_sha256",
                "build_merkle_tree",
                "carve_shell_history",
                "collect_autostart_entries",
                "collect_audit_policy",
                "collect_firewall_rules",
                "detect_av_edr",
                "collect_app_control",
                "analyze_shell_scripts",
                "enumerate_modules",
            ] {
                set.insert(collector);
            }
            set
        });

        collectors.contains(capability.collector_function.as_str())
    }

    /// Invoke the runtime-backed collector contract for a capability.
    pub fn invoke_runtime_capability(&self, capability_id: &str) -> Result<serde_json::Value, String> {
        let capability = self
            .capabilities
            .get(capability_id)
            .ok_or_else(|| format!("Capability '{}' not found in registry", capability_id))?;

        if !capability.is_implemented {
            return Err(format!("Capability '{}' is declared but not implemented", capability_id));
        }

        if !self.runtime_capability_exists(capability_id) {
            return Err(format!(
                "Capability '{}' collector '{}' is not backed by a runtime implementation",
                capability_id,
                capability.collector_function
            ));
        }

        Ok(serde_json::json!({
            "id": capability.id,
            "name": capability.name,
            "collector_function": capability.collector_function,
            "status": "runtime-backed"
        }))
    }

    /// Get unimplemented capabilities
    pub fn unimplemented(&self) -> Vec<&Capability> {
        self.capabilities.values().filter(|c| !c.is_implemented).collect()
    }

    /// Get total capability count
    pub fn count(&self) -> usize {
        self.capabilities.len()
    }

    /// Get implemented capability count
    pub fn implemented_count(&self) -> usize {
        self.capabilities.values().filter(|c| c.is_implemented).count()
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
                }),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Export capability inventory as markdown table
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# JOCKEY Capability Inventory\n\n");
        md.push_str(&format!("**Total Capabilities:** {} | **Implemented:** {} | **Planned:** {}\n\n",
            self.count(), self.implemented_count(), self.count() - self.implemented_count()));

        md.push_str("| ID | Name | Category | Platforms | Privilege | MITRE ATT&CK | Implemented |\n");
        md.push_str("|:---|:---|:---|:---|:---|:---|:---:|\n");

        let mut caps: Vec<_> = self.capabilities.values().collect();
        caps.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

        for cap in caps {
            let mitre = if cap.mitre_attack_ids.is_empty() {
                "—".to_string()
            } else {
                cap.mitre_attack_ids.join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | {:?} | {:?} | {:?} | {} | {} |\n",
                cap.id.as_str(),
                cap.name,
                cap.category,
                cap.platforms,
                cap.privilege,
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
    REGISTRY.get_or_init(|| CapabilityRegistry::new())
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
        assert!(implemented > 0, "Should have at least some implemented capabilities");
        println!("Implemented capabilities: {}", implemented);
    }

    #[test]
    fn test_phase_1_capability_inventory_floor() {
        let reg = registry();
        assert!(reg.count() >= 200, "Phase 1 registry must include at least 200 capabilities");
        assert!(reg.implemented_count() >= 200, "Phase 1 must have at least 200 implemented capabilities");
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

        println!("Linux-only: {}, Windows-only: {}, Both: {}",
            linux_caps.len(), windows_caps.len(), both_caps.len());

        assert!(linux_caps.len() > 0);
        assert!(windows_caps.len() > 0);
        assert!(both_caps.len() > 0);
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
        assert!(reg.runtime_capability_exists("system.info.users"));
        assert!(reg.runtime_capability_exists("user.enumerate"));
        assert!(reg.runtime_capability_exists("auth.logon_events"));
        assert!(reg.runtime_capability_exists("auth.credential_artifacts"));
        assert!(reg.runtime_capability_exists("auth.policy"));
        assert!(reg.runtime_capability_exists("service.enumerate"));
        assert!(reg.runtime_capability_exists("service.systemd"));

        let result = reg.invoke_runtime_capability("user.enumerate");
        assert!(result.is_ok(), "user.enumerate should resolve to a runtime-backed collector");
        let payload = result.unwrap();
        assert_eq!(payload["status"], "runtime-backed");
    }
}