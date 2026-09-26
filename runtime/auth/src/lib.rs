//! JOCKEY Runtime - Authentication Collection
//!
//! Collects authentication events, credential artifacts, and authentication policies.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Failed to read auth log: {0}")]
    ReadError(String),
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Logon type (Windows)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogonType {
    Interactive = 2,
    Network = 3,
    Batch = 4,
    Service = 5,
    Proxy = 6,
    Unlock = 7,
    NetworkCleartext = 8,
    NewCredentials = 9,
    RemoteInteractive = 10,
    CachedInteractive = 11,
    CachedRemoteInteractive = 12,
    CachedUnlock = 13,
    Unknown,
}

/// Logon event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event ID (e.g., 4624 for success, 4625 for failure on Windows)
    pub event_id: u32,
    /// Logon type
    pub logon_type: LogonType,
    /// Account name
    pub account_name: String,
    /// Account domain
    pub account_domain: String,
    /// Logon ID (LUID on Windows)
    pub logon_id: String,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Source port
    pub source_port: Option<u16>,
    /// Workstation name
    pub workstation: Option<String>,
    /// Process name
    pub process_name: Option<String>,
    /// Process ID
    pub process_id: Option<u32>,
    /// Authentication package (NTLM, Kerberos, etc.)
    pub auth_package: Option<String>,
    /// Key length
    pub key_length: Option<u32>,
    /// Whether logon was successful
    pub success: bool,
    /// Failure reason (if failed)
    pub failure_reason: Option<String>,
    /// Sub-status (Windows)
    pub sub_status: Option<String>,
    /// Logon GUID
    pub logon_guid: Option<String>,
    /// Transmitted services
    pub transmitted_services: Option<String>,
    /// Package name (NTLM/SSL/Kerberos)
    pub package_name: Option<String>,
    /// Source
    pub source: AuthSource,
}

/// Source of authentication data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthSource {
    WindowsSecurityLog,
    LinuxAuthLog,
    LinuxSecureLog,
    LinuxBtmp,
    LinuxWtmp,
    WindowsEventLog,
}

/// Credential artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialArtifact {
    /// Artifact type
    pub artifact_type: CredentialArtifactType,
    /// File path
    pub path: String,
    /// Size in bytes
    pub size: Option<u64>,
    /// Last modified timestamp
    pub modified: Option<DateTime<Utc>>,
    /// Owner user
    pub owner: Option<String>,
    /// Permissions
    pub permissions: Option<String>,
    /// Hash (SHA-256)
    pub sha256: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Risk level
    pub risk_level: RiskLevel,
}

/// Type of credential artifact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialArtifactType {
    // Windows
    LsassDump,
    SamFile,
    NtdsDit,
    RegistrySAM,
    RegistrySecurity,
    RegistrySystem,
    CredentialManager,
    DpapiMasterKey,
    DpapiCredential,
    // Linux
    ShadowFile,
    PasswdFile,
    SudoersFile,
    SshPrivateKey,
    SshAuthorizedKeys,
    KerberosKeytab,
    GnomeKeyring,
    KdeWallet,
    ChromeLoginData,
    FirefoxLoginData,
    // Cross-platform
    BrowserCredentialStore,
    PasswordManager,
    ApiKey,
    Token,
    Certificate,
    PrivateKey,
}

/// Risk level for credential artifacts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Authentication policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPolicy {
    /// Policy type
    pub policy_type: AuthPolicyType,
    /// Policy name
    pub name: String,
    /// Policy value/setting
    pub value: String,
    /// Whether policy is enforced
    pub enforced: bool,
    /// Source file/location
    pub source: String,
    /// Description
    pub description: Option<String>,
}

/// Type of authentication policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthPolicyType {
    // Password policy
    MinPasswordLength,
    MinPasswordAge,
    MaxPasswordAge,
    PasswordHistory,
    PasswordComplexity,
    LockoutThreshold,
    LockoutDuration,
    LockoutResetTime,
    // Account policy
    AccountExpiration,
    InactiveAccountThreshold,
    // Kerberos
    MaxTicketAge,
    MaxRenewAge,
    // Sudo
    SudoTimeout,
    SudoRequirePassword,
    SudoLecture,
    // PAM
    PamModule,
    PamConfig,
    // SSH
    PermitRootLogin,
    PasswordAuthentication,
    PubkeyAuthentication,
    PermitEmptyPasswords,
    MaxAuthTries,
    // Windows
    LmCompatibilityLevel,
    NtlmMinClientSec,
    RestrictAnonymous,
    // General
    Custom(String),
}

/// Result of logon event collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonEventsResult {
    pub events: Vec<LogonEvent>,
    pub collection_time: DateTime<Utc>,
    pub sources: Vec<AuthSource>,
    pub errors: Vec<String>,
}

impl Default for LogonEventsResult {
    fn default() -> Self {
        Self::new()
    }
}

impl LogonEventsResult {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            collection_time: Utc::now(),
            sources: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Result of credential artifact collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialArtifactsResult {
    pub artifacts: Vec<CredentialArtifact>,
    pub collection_time: DateTime<Utc>,
    pub errors: Vec<String>,
}

impl Default for CredentialArtifactsResult {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialArtifactsResult {
    pub fn new() -> Self {
        Self {
            artifacts: Vec::new(),
            collection_time: Utc::now(),
            errors: Vec::new(),
        }
    }
}

/// Result of authentication policy collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPolicyResult {
    pub policies: Vec<AuthPolicy>,
    pub collection_time: DateTime<Utc>,
    pub errors: Vec<String>,
}

impl Default for AuthPolicyResult {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthPolicyResult {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            collection_time: Utc::now(),
            errors: Vec::new(),
        }
    }
}

/// Collect Windows logon events from Security Event Log
#[cfg(target_os = "windows")]
pub fn collect_windows_logon_events() -> Result<LogonEventsResult> {
    use std::process::Command;

    let mut result = LogonEventsResult::new();
    result.sources.push(AuthSource::WindowsSecurityLog);

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4634,4647,4672} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Json -Compress",
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
                let id = item.get("Id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let timestamp_str = item
                    .get("TimeCreated")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let msg = item.get("Message").and_then(|v| v.as_str()).unwrap_or("");

                let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                result.events.push(LogonEvent {
                    timestamp,
                    event_id: id,
                    logon_type: LogonType::Unknown,
                    account_name: String::new(),
                    account_domain: String::new(),
                    logon_id: String::new(),
                    source_ip: None,
                    source_port: None,
                    workstation: None,
                    process_name: None,
                    process_id: None,
                    auth_package: None,
                    key_length: None,
                    success: id == 4624,
                    failure_reason: if id == 4625 {
                        Some(msg.to_string())
                    } else {
                        None
                    },
                    sub_status: None,
                    logon_guid: None,
                    transmitted_services: None,
                    package_name: None,
                    source: AuthSource::WindowsSecurityLog,
                });
            }
        }
    }

    result
        .events
        .sort_by_key(|a| std::cmp::Reverse(a.timestamp));
    Ok(result)
}

/// Collect Linux auth.log events
#[cfg(target_os = "linux")]
pub fn collect_linux_logon_events() -> Result<LogonEventsResult> {
    use regex::Regex;
    use std::fs;

    let mut result = LogonEventsResult::new();
    result.sources.push(AuthSource::LinuxAuthLog);

    // Read /var/log/auth.log
    let auth_log =
        fs::read_to_string("/var/log/auth.log").context("Failed to read /var/log/auth.log")?;

    // Parse SSH logon events
    let ssh_accepted = Regex::new(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Accepted (\w+) for (\w+) from ([\d\.]+) port (\d+)",
    )?;
    let ssh_failed = Regex::new(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed (\w+) for (\w+) from ([\d\.]+) port (\d+)",
    )?;
    let sudo_log = Regex::new(r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*: USER=(\w+) ; COMMAND=(.+)")?;

    for line in auth_log.lines() {
        if let Some(caps) = ssh_accepted.captures(line) {
            let timestamp_str = &caps[1];
            let auth_method = &caps[2];
            let user = &caps[3];
            let ip = &caps[4];
            let port = caps[5].parse::<u16>().ok();

            let timestamp = parse_syslog_timestamp(timestamp_str);

            result.events.push(LogonEvent {
                timestamp,
                event_id: 4624,
                logon_type: LogonType::Network,
                account_name: user.to_string(),
                account_domain: "local".to_string(),
                logon_id: format!("ssh-{}", uuid::Uuid::new_v4()),
                source_ip: Some(ip.to_string()),
                source_port: port,
                workstation: None,
                process_name: Some("sshd".to_string()),
                process_id: None,
                auth_package: Some(auth_method.to_string()),
                key_length: None,
                success: true,
                failure_reason: None,
                sub_status: None,
                logon_guid: None,
                transmitted_services: None,
                package_name: Some(auth_method.to_string()),
                source: AuthSource::LinuxAuthLog,
            });
        } else if let Some(caps) = ssh_failed.captures(line) {
            let timestamp_str = &caps[1];
            let auth_method = &caps[2];
            let user = &caps[3];
            let ip = &caps[4];
            let port = caps[5].parse::<u16>().ok();

            let timestamp = parse_syslog_timestamp(timestamp_str);

            result.events.push(LogonEvent {
                timestamp,
                event_id: 4625,
                logon_type: LogonType::Network,
                account_name: user.to_string(),
                account_domain: "local".to_string(),
                logon_id: format!("ssh-{}", uuid::Uuid::new_v4()),
                source_ip: Some(ip.to_string()),
                source_port: port,
                workstation: None,
                process_name: Some("sshd".to_string()),
                process_id: None,
                auth_package: Some(auth_method.to_string()),
                key_length: None,
                success: false,
                failure_reason: Some("Authentication failed".to_string()),
                sub_status: None,
                logon_guid: None,
                transmitted_services: None,
                package_name: Some(auth_method.to_string()),
                source: AuthSource::LinuxAuthLog,
            });
        } else if let Some(caps) = sudo_log.captures(line) {
            let timestamp_str = &caps[1];
            let user = &caps[2];
            let command = &caps[3];

            let timestamp = parse_syslog_timestamp(timestamp_str);

            result.events.push(LogonEvent {
                timestamp,
                event_id: 4672, // Special privileges assigned
                logon_type: LogonType::Interactive,
                account_name: user.to_string(),
                account_domain: "local".to_string(),
                logon_id: format!("sudo-{}", uuid::Uuid::new_v4()),
                source_ip: None,
                source_port: None,
                workstation: None,
                process_name: Some("sudo".to_string()),
                process_id: None,
                auth_package: Some("sudo".to_string()),
                key_length: None,
                success: true,
                failure_reason: None,
                sub_status: None,
                logon_guid: None,
                transmitted_services: None,
                package_name: Some(format!("sudo: {}", command)),
                source: AuthSource::LinuxAuthLog,
            });
        }
    }

    // Sort by timestamp descending
    result.events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(result)
}

/// Parse syslog timestamp (e.g., "Sep 25 10:30:45")
#[allow(dead_code)]
fn parse_syslog_timestamp(ts: &str) -> DateTime<Utc> {
    use chrono::Datelike;

    let now = Utc::now();
    let year = now.year();
    DateTime::parse_from_str(
        &format!("{} {} {}", year, ts, now.offset()),
        "%Y %b %d %H:%M:%S %z",
    )
    .map(|dt| dt.with_timezone(&Utc))
    .unwrap_or_else(|_| Utc::now())
}

/// Collect credential artifacts
pub fn collect_credential_artifacts() -> Result<CredentialArtifactsResult> {
    let mut result = CredentialArtifactsResult::new();

    #[cfg(target_os = "linux")]
    {
        collect_linux_credential_artifacts(&mut result)?;
    }

    #[cfg(target_os = "windows")]
    {
        collect_windows_credential_artifacts(&mut result)?;
    }

    Ok(result)
}

/// Collect Linux credential artifacts
#[cfg(target_os = "linux")]
fn collect_linux_credential_artifacts(result: &mut CredentialArtifactsResult) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let artifacts_to_check = [
        (
            "/etc/shadow",
            CredentialArtifactType::ShadowFile,
            RiskLevel::Critical,
        ),
        (
            "/etc/passwd",
            CredentialArtifactType::PasswdFile,
            RiskLevel::Medium,
        ),
        (
            "/etc/sudoers",
            CredentialArtifactType::SudoersFile,
            RiskLevel::High,
        ),
        (
            "/etc/sudoers.d",
            CredentialArtifactType::SudoersFile,
            RiskLevel::High,
        ),
    ];

    for (path, artifact_type, risk_level) in artifacts_to_check {
        let path_buf = std::path::Path::new(path);
        if let Ok(metadata) = fs::metadata(path_buf) {
            let sha256 = if metadata.is_file() {
                Some(compute_file_hash(path_buf)?)
            } else {
                None
            };

            result.artifacts.push(CredentialArtifact {
                artifact_type,
                path: path.to_string(),
                size: Some(metadata.len()),
                modified: metadata.modified().ok().map(|t| DateTime::from(t)),
                owner: Some(metadata.uid().to_string()),
                permissions: Some(format!("{:o}", metadata.mode() & 0o777)),
                sha256,
                metadata: HashMap::new(),
                risk_level,
            });
        }
    }

    // Check SSH keys
    if let Ok(home_dirs) = fs::read_dir("/home") {
        for entry in home_dirs.flatten() {
            let ssh_dir = entry.path().join(".ssh");
            if ssh_dir.exists() {
                for key_file in fs::read_dir(&ssh_dir).into_iter().flatten().flatten() {
                    let path = key_file.path();
                    let name = path.file_name().unwrap().to_string_lossy();
                    if name.ends_with(".pub") {
                        continue;
                    }
                    if name == "id_rsa"
                        || name == "id_ed25519"
                        || name == "id_ecdsa"
                        || name == "id_dsa"
                    {
                        if let Ok(metadata) = fs::metadata(&path) {
                            result.artifacts.push(CredentialArtifact {
                                artifact_type: CredentialArtifactType::SshPrivateKey,
                                path: path.to_string_lossy().to_string(),
                                size: Some(metadata.len()),
                                modified: metadata.modified().ok().map(|t| DateTime::from(t)),
                                owner: Some(entry.file_name().to_string_lossy().to_string()),
                                permissions: Some(format!("{:o}", metadata.mode() & 0o777)),
                                sha256: Some(compute_file_hash(&path)?),
                                metadata: HashMap::new(),
                                risk_level: RiskLevel::Critical,
                            });
                        }
                    }
                }
            }
        }
    }

    // Check root SSH keys
    let root_ssh = std::path::Path::new("/root/.ssh");
    if root_ssh.exists() {
        for key_file in fs::read_dir(root_ssh).into_iter().flatten().flatten() {
            let path = key_file.path();
            let name = path.file_name().unwrap().to_string_lossy();
            if name == "id_rsa" || name == "id_ed25519" || name == "id_ecdsa" || name == "id_dsa" {
                if let Ok(metadata) = fs::metadata(&path) {
                    result.artifacts.push(CredentialArtifact {
                        artifact_type: CredentialArtifactType::SshPrivateKey,
                        path: path.to_string_lossy().to_string(),
                        size: Some(metadata.len()),
                        modified: metadata.modified().ok().map(|t| DateTime::from(t)),
                        owner: Some("root".to_string()),
                        permissions: Some(format!("{:o}", metadata.mode() & 0o777)),
                        sha256: Some(compute_file_hash(&path)?),
                        metadata: HashMap::new(),
                        risk_level: RiskLevel::Critical,
                    });
                }
            }
        }
    }

    Ok(())
}

/// Collect Windows credential artifacts
#[cfg(target_os = "windows")]
fn collect_windows_credential_artifacts(result: &mut CredentialArtifactsResult) -> Result<()> {
    use std::fs;
    use std::path::Path;
    use winreg::enums::*;
    use winreg::RegKey;

    let artifacts_to_check = [
        (
            r"C:\Windows\System32\config\SAM",
            CredentialArtifactType::SamFile,
            RiskLevel::Critical,
        ),
        (
            r"C:\Windows\System32\config\SYSTEM",
            CredentialArtifactType::RegistrySystem,
            RiskLevel::Critical,
        ),
        (
            r"C:\Windows\System32\config\SECURITY",
            CredentialArtifactType::RegistrySecurity,
            RiskLevel::Critical,
        ),
    ];

    for (path, artifact_type, risk_level) in artifacts_to_check {
        let path_buf = Path::new(path);
        if path_buf.exists() {
            if let Ok(metadata) = fs::metadata(path_buf) {
                result.artifacts.push(CredentialArtifact {
                    artifact_type,
                    path: path.to_string(),
                    size: Some(metadata.len()),
                    modified: metadata.modified().ok().map(DateTime::from),
                    owner: Some("SYSTEM".to_string()),
                    permissions: None,
                    sha256: Some(compute_file_hash(path_buf)?),
                    metadata: HashMap::new(),
                    risk_level,
                });
            }
        }
    }

    // Check for LSASS dumps (common locations)
    let lsass_paths = [
        r"C:\Windows\Temp\lsass.dmp",
        r"C:\Windows\Temp\lsass_dump.dmp",
        r"C:\Temp\lsass.dmp",
    ];

    for path in lsass_paths {
        let path_buf = Path::new(path);
        if path_buf.exists() {
            if let Ok(metadata) = fs::metadata(path_buf) {
                result.artifacts.push(CredentialArtifact {
                    artifact_type: CredentialArtifactType::LsassDump,
                    path: path.to_string(),
                    size: Some(metadata.len()),
                    modified: metadata.modified().ok().map(DateTime::from),
                    owner: None,
                    permissions: None,
                    sha256: Some(compute_file_hash(path_buf)?),
                    metadata: HashMap::new(),
                    risk_level: RiskLevel::Critical,
                });
            }
        }
    }

    // Check Credential Manager via registry
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(_creds_key) = hkcu.open_subkey("Software\\Microsoft\\Credentials") {
        result.artifacts.push(CredentialArtifact {
            artifact_type: CredentialArtifactType::CredentialManager,
            path: "HKCU\\Software\\Microsoft\\Credentials".to_string(),
            size: None,
            modified: None,
            owner: Some(whoami::username()),
            permissions: None,
            sha256: None,
            metadata: HashMap::new(),
            risk_level: RiskLevel::High,
        });
    }

    Ok(())
}

/// Compute SHA-256 hash of a file
fn compute_file_hash(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{BufReader, Read};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Collect authentication policies
pub fn collect_auth_policy() -> Result<AuthPolicyResult> {
    let mut result = AuthPolicyResult::new();

    #[cfg(target_os = "linux")]
    {
        collect_linux_auth_policies(&mut result)?;
    }

    #[cfg(target_os = "windows")]
    {
        collect_windows_auth_policies(&mut result)?;
    }

    Ok(result)
}

/// Collect Linux authentication policies
#[cfg(target_os = "linux")]
fn collect_linux_auth_policies(result: &mut AuthPolicyResult) -> Result<()> {
    use std::fs;

    // /etc/login.defs
    if let Ok(content) = fs::read_to_string("/etc/login.defs") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let (policy_type, desc) = match parts[0] {
                    "PASS_MAX_DAYS" => (AuthPolicyType::MaxPasswordAge, "Maximum password age"),
                    "PASS_MIN_DAYS" => (AuthPolicyType::MinPasswordAge, "Minimum password age"),
                    "PASS_MIN_LEN" => {
                        (AuthPolicyType::MinPasswordLength, "Minimum password length")
                    }
                    "PASS_WARN_AGE" => (
                        AuthPolicyType::Custom("PASS_WARN_AGE".to_string()),
                        "Password warning age",
                    ),
                    "LOGIN_RETRIES" => (AuthPolicyType::LockoutThreshold, "Login retry limit"),
                    "LOGIN_TIMEOUT" => (
                        AuthPolicyType::Custom("LOGIN_TIMEOUT".to_string()),
                        "Login timeout",
                    ),
                    "FAIL_DELAY" => (
                        AuthPolicyType::Custom("FAIL_DELAY".to_string()),
                        "Failed login delay",
                    ),
                    _ => continue,
                };

                result.policies.push(AuthPolicy {
                    policy_type,
                    name: parts[0].to_string(),
                    value: parts[1].to_string(),
                    enforced: true,
                    source: "/etc/login.defs".to_string(),
                    description: Some(desc.to_string()),
                });
            }
        }
    }

    // /etc/pam.d/common-auth
    if let Ok(content) = fs::read_to_string("/etc/pam.d/common-auth") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.contains("pam_faillock") || line.contains("pam_tally") {
                result.policies.push(AuthPolicy {
                    policy_type: AuthPolicyType::PamModule,
                    name: "pam_faillock/tally".to_string(),
                    value: line.to_string(),
                    enforced: true,
                    source: "/etc/pam.d/common-auth".to_string(),
                    description: Some("Account lockout PAM module".to_string()),
                });
            }
        }
    }

    // /etc/ssh/sshd_config
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let (policy_type, desc) = match parts[0].to_lowercase().as_str() {
                    "permitrootlogin" => (AuthPolicyType::PermitRootLogin, "Root login permission"),
                    "passwordauthentication" => (
                        AuthPolicyType::PasswordAuthentication,
                        "Password authentication",
                    ),
                    "pubkeyauthentication" => (
                        AuthPolicyType::PubkeyAuthentication,
                        "Public key authentication",
                    ),
                    "permitemptypasswords" => (
                        AuthPolicyType::PermitEmptyPasswords,
                        "Empty password permission",
                    ),
                    "maxauthtries" => {
                        (AuthPolicyType::MaxAuthTries, "Maximum authentication tries")
                    }
                    _ => continue,
                };

                result.policies.push(AuthPolicy {
                    policy_type,
                    name: parts[0].to_string(),
                    value: parts[1].to_string(),
                    enforced: true,
                    source: "/etc/ssh/sshd_config".to_string(),
                    description: Some(desc.to_string()),
                });
            }
        }
    }

    // /etc/sudoers
    if let Ok(content) = fs::read_to_string("/etc/sudoers") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.contains("Defaults") {
                if line.contains("timestamp_timeout") {
                    if let Some(val) = line.split('=').nth(1) {
                        result.policies.push(AuthPolicy {
                            policy_type: AuthPolicyType::SudoTimeout,
                            name: "timestamp_timeout".to_string(),
                            value: val.trim().to_string(),
                            enforced: true,
                            source: "/etc/sudoers".to_string(),
                            description: Some("Sudo timeout in minutes".to_string()),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Collect Windows authentication policies
#[cfg(target_os = "windows")]
fn collect_windows_auth_policies(result: &mut AuthPolicyResult) -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    // Password policy from registry
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // System access policies
    if let Ok(policy_key) = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\Lsa") {
        let policies_to_check = [
            (
                "LmCompatibilityLevel",
                AuthPolicyType::LmCompatibilityLevel,
                "LAN Manager authentication level",
            ),
            (
                "RestrictAnonymous",
                AuthPolicyType::RestrictAnonymous,
                "Anonymous access restriction",
            ),
            (
                "NoLMHash",
                AuthPolicyType::Custom("NoLMHash".to_string()),
                "Disable LM hash storage",
            ),
        ];

        for (name, policy_type, desc) in policies_to_check {
            if let Ok(value) = policy_key.get_value::<u32, _>(name) {
                result.policies.push(AuthPolicy {
                    policy_type,
                    name: name.to_string(),
                    value: value.to_string(),
                    enforced: true,
                    source: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
                    description: Some(desc.to_string()),
                });
            }
        }
    }

    // Account lockout policy
    if let Ok(_policy_key) =
        hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\RemoteAccess\\Policy")
    {
        // Not the right key - would need to use NetUserGetInfo or similar
    }

    // Use secedit export for full policy
    // This is simplified

    Ok(())
}

/// Main entry point for logon events collection
pub fn collect_logon_events() -> Result<LogonEventsResult> {
    #[cfg(target_os = "linux")]
    {
        collect_linux_logon_events()
    }

    #[cfg(target_os = "windows")]
    {
        collect_windows_logon_events()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(AuthError::UnsupportedPlatform("Platform not supported".to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logon_events_result_creation() {
        let result = LogonEventsResult::new();
        assert!(result.events.is_empty());
    }

    #[test]
    fn test_credential_artifacts_result_creation() {
        let result = CredentialArtifactsResult::new();
        assert!(result.artifacts.is_empty());
    }

    #[test]
    fn test_auth_policy_result_creation() {
        let result = AuthPolicyResult::new();
        assert!(result.policies.is_empty());
    }
}
