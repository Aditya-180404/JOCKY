//! jockey Runtime - Security Analysis Module
//!
//! Provides forensic detection capabilities for suspicious system behavior,
//! including process anomalies, unsigned executables, and unexpected locations.

use serde::{Deserialize, Serialize};

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Critical => write!(f, "CRITICAL"),
            FindingSeverity::High => write!(f, "HIGH"),
            FindingSeverity::Medium => write!(f, "MEDIUM"),
            FindingSeverity::Low => write!(f, "LOW"),
            FindingSeverity::Informational => write!(f, "INFO"),
        }
    }
}

/// A security finding produced by analysis modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub indicator: String,
    pub severity: FindingSeverity,
    pub evidence: String,
    pub reason: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub host: String,
    pub process: Option<String>,
    pub pid: Option<i32>,
    pub confidence: f64, // 0.0 - 1.0
    pub category: FindingCategory,
    /// MITRE ATT&CK technique ID (e.g. "T1059.001"). Empty string when no
    /// mapping exists for a given finding category.
    pub mitre_attack_id: String,
}

/// Categories of security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    SuspiciousProcess,
    UnsignedExecutable,
    UnexpectedLocation,
    SuspiciousNetwork,
    PersistenceMechanism,
    PrivilegeEscalation,
    SuspiciousCommandLine,
    SuspiciousParentChild,
    MemoryAnomaly,
    DriverAnomaly,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::SuspiciousProcess => write!(f, "Suspicious Process"),
            FindingCategory::UnsignedExecutable => write!(f, "Unsigned Executable"),
            FindingCategory::UnexpectedLocation => write!(f, "Unexpected Location"),
            FindingCategory::SuspiciousNetwork => write!(f, "Suspicious Network"),
            FindingCategory::PersistenceMechanism => write!(f, "Persistence Mechanism"),
            FindingCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            FindingCategory::SuspiciousCommandLine => write!(f, "Suspicious Command Line"),
            FindingCategory::SuspiciousParentChild => write!(f, "Suspicious Parent-Child"),
            FindingCategory::MemoryAnomaly => write!(f, "Memory Anomaly"),
            FindingCategory::DriverAnomaly => write!(f, "Driver Anomaly"),
        }
    }
}

impl FindingCategory {
    /// Returns the canonical MITRE ATT&CK technique ID for this category.
    /// See <https://attack.mitre.org/> for technique definitions.
    pub fn mitre_attack_id(&self) -> &'static str {
        match self {
            // T1059 — Command and Scripting Interpreter
            FindingCategory::SuspiciousCommandLine => "T1059",
            // T1055 — Process Injection (parent-child anomaly is a common precursor)
            FindingCategory::SuspiciousParentChild => "T1055",
            // T1036 — Masquerading / unexpected executable location
            FindingCategory::UnexpectedLocation => "T1036",
            // T1553 — Subvert Trust Controls (unsigned binaries bypass code-signing)
            FindingCategory::UnsignedExecutable => "T1553",
            // T1571 — Non-Standard Port (suspicious network port)
            FindingCategory::SuspiciousNetwork => "T1571",
            // T1547 — Boot or Logon Autostart Execution
            FindingCategory::PersistenceMechanism => "T1547",
            // T1068 — Exploitation for Privilege Escalation
            FindingCategory::PrivilegeEscalation => "T1068",
            // T1055.001 — Virtual Memory Anomaly
            FindingCategory::MemoryAnomaly => "T1055.001",
            // T1014 — Rootkit (driver anomaly)
            FindingCategory::DriverAnomaly => "T1014",
            // Generic suspicious process — T1057 Process Discovery
            FindingCategory::SuspiciousProcess => "T1057",
        }
    }
}

/// Well-known suspicious parent-child process relationships on Windows
const SUSPICIOUS_PARENT_CHILD: &[(&str, &str)] = &[
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("services.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("w3wp.exe", "cmd.exe"),
    ("w3wp.exe", "powershell.exe"),
];

/// Expected executable directories per platform
#[cfg(target_os = "windows")]
const EXPECTED_EXE_DIRS: &[&str] = &[
    r"C:\Windows\",
    r"C:\Windows\System32\",
    r"C:\Windows\SysWOW64\",
    r"C:\Program Files\",
    r"C:\Program Files (x86)\",
];

#[cfg(not(target_os = "windows"))]
const EXPECTED_EXE_DIRS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/bin/",
    "/sbin/",
    "/opt/",
];

/// Suspicious command-line patterns (case-insensitive matching)
const SUSPICIOUS_CMDLINE_PATTERNS: &[(&str, &str)] = &[
    ("-encodedcommand", "PowerShell encoded command execution"),
    ("-enc ", "PowerShell encoded command (abbreviated)"),
    ("invoke-expression", "PowerShell dynamic code execution"),
    ("iex(", "PowerShell IEX shorthand"),
    ("downloadstring", "Remote content download and execution"),
    ("downloadfile", "Remote file download"),
    ("frombase64string", "Base64 decoding in command line"),
    ("net user /add", "User account creation"),
    ("reg add", "Registry modification"),
    ("schtasks /create", "Scheduled task creation"),
    ("bitsadmin /transfer", "BITS transfer (potential download)"),
    ("certutil -urlcache", "Certutil file download"),
    ("mshta vbscript", "MSHTA script execution"),
    ("rundll32 javascript", "Rundll32 script execution"),
    ("wmic process call create", "WMI remote process creation"),
    ("/c whoami", "Reconnaissance command"),
    ("mimikatz", "Known credential tool"),
    ("procdump", "Process memory dump tool"),
];

/// SecurityAnalyzer performs forensic analysis on collected system data
pub struct SecurityAnalyzer {
    hostname: String,
    findings: Vec<SecurityFinding>,
}

impl SecurityAnalyzer {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            findings: Vec::new(),
        }
    }

    /// Analyze process list for suspicious parent-child relationships
    pub fn analyze_parent_child_relationships(&mut self, processes: &[serde_json::Value]) {
        // Build a PID → name lookup
        let mut pid_name: std::collections::HashMap<i32, String> = std::collections::HashMap::new();
        for proc in processes {
            if let (Some(pid), Some(name)) = (
                proc.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32),
                proc.get("name").and_then(|v| v.as_str()),
            ) {
                pid_name.insert(pid, name.to_lowercase());
            }
        }

        for proc in processes {
            let pid = proc.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
            let ppid = proc.get("ppid").and_then(|v| v.as_i64()).map(|v| v as i32);
            let name = proc.get("name").and_then(|v| v.as_str()).unwrap_or("");

            if let (Some(pid), Some(ppid)) = (pid, ppid) {
                if let Some(parent_name) = pid_name.get(&ppid) {
                    let child_lower = name.to_lowercase();
                    for (suspicious_parent, suspicious_child) in SUSPICIOUS_PARENT_CHILD {
                        if parent_name == *suspicious_parent && child_lower == *suspicious_child {
                            let category = FindingCategory::SuspiciousParentChild;
                            self.findings.push(SecurityFinding {
                                indicator: format!(
                                    "Suspicious parent-child: {} ({}) \u{2192} {} ({})",
                                    parent_name, ppid, name, pid
                                ),
                                severity: FindingSeverity::High,
                                evidence: format!("PID {} spawned by PID {}", pid, ppid),
                                reason: format!(
                                    "{} spawning {} is a common indicator of malicious macro or exploit activity",
                                    suspicious_parent, suspicious_child
                                ),
                                timestamp: chrono::Utc::now(),
                                host: self.hostname.clone(),
                                process: Some(name.to_string()),
                                pid: Some(pid),
                                confidence: 0.85,
                                mitre_attack_id: category.mitre_attack_id().to_string(),
                                category,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Analyze processes for unexpected executable locations
    pub fn analyze_executable_locations(&mut self, processes: &[serde_json::Value]) {
        for proc in processes {
            let pid = proc.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
            let name = proc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let exe_path = proc.get("executable_path").and_then(|v| v.as_str());

            if let Some(path) = exe_path {
                let path_lower = path.to_lowercase();
                let in_expected = EXPECTED_EXE_DIRS
                    .iter()
                    .any(|dir| path_lower.starts_with(&dir.to_lowercase()));

                if !in_expected {
                    // Check for executables in temp directories
                    let in_temp = path_lower.contains("\\temp\\")
                        || path_lower.contains("/tmp/")
                        || path_lower.contains("\\appdata\\local\\temp\\")
                        || path_lower.contains("\\downloads\\");

                    if in_temp {
                        let category = FindingCategory::UnexpectedLocation;
                        self.findings.push(SecurityFinding {
                            indicator: format!(
                                "Process running from temp/download directory: {}",
                                name
                            ),
                            severity: FindingSeverity::Medium,
                            evidence: format!("Path: {}", path),
                            reason: "Executables running from temporary or download directories may indicate malware or unauthorized software".to_string(),
                            timestamp: chrono::Utc::now(),
                            host: self.hostname.clone(),
                            process: Some(name.to_string()),
                            pid,
                            confidence: 0.6,
                            mitre_attack_id: category.mitre_attack_id().to_string(),
                            category,
                        });
                    }
                }
            }
        }
    }

    /// Analyze command lines for suspicious patterns
    pub fn analyze_command_lines(&mut self, processes: &[serde_json::Value]) {
        for proc in processes {
            let pid = proc.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
            let name = proc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let cmdline = proc
                .get("command_line")
                .and_then(|v| {
                    if let Some(arr) = v.as_array() {
                        Some(
                            arr.iter()
                                .filter_map(|e| e.as_str())
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    } else {
                        v.as_str().map(|s| s.to_string())
                    }
                })
                .unwrap_or_default();

            let cmdline_lower = cmdline.to_lowercase();

            for (pattern, description) in SUSPICIOUS_CMDLINE_PATTERNS {
                if cmdline_lower.contains(*pattern) {
                    let category = FindingCategory::SuspiciousCommandLine;
                    self.findings.push(SecurityFinding {
                        indicator: format!("Suspicious command line in {}: {}", name, description),
                        severity: FindingSeverity::High,
                        evidence: format!(
                            "Command: {}",
                            if cmdline.len() > 200 {
                                &cmdline[..200]
                            } else {
                                &cmdline
                            }
                        ),
                        reason: description.to_string(),
                        timestamp: chrono::Utc::now(),
                        host: self.hostname.clone(),
                        process: Some(name.to_string()),
                        pid,
                        confidence: 0.75,
                        mitre_attack_id: category.mitre_attack_id().to_string(),
                        category,
                    });
                    break; // One finding per process per category
                }
            }
        }
    }

    /// Analyze network connections for suspicious patterns
    pub fn analyze_network_connections(&mut self, connections: &[serde_json::Value]) {
        // Common suspicious ports
        let suspicious_ports: &[(u16, &str)] = &[
            (4444, "Metasploit default handler"),
            (5555, "Common reverse shell port"),
            (1337, "Common hacker port"),
            (31337, "Back Orifice default"),
            (12345, "NetBus default"),
            (6666, "IRC (potential C2)"),
            (6667, "IRC (potential C2)"),
            (9001, "Tor default"),
            (9050, "Tor SOCKS proxy"),
            (8443, "Alternative HTTPS (potential C2)"),
        ];

        for conn in connections {
            let remote_port = conn
                .get("remote_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let remote_addr = conn
                .get("remote_address")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0");
            let state = conn
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let pid = conn.get("pid").and_then(|v| v.as_u64()).map(|v| v as i32);
            let process_name = conn.get("process_name").and_then(|v| v.as_str());

            for (port, description) in suspicious_ports {
                if remote_port == *port && state.to_uppercase().contains("ESTABLISHED") {
                    self.findings.push(SecurityFinding {
                        indicator: format!(
                            "Connection to suspicious port {}: {}",
                            port, description
                        ),
                        severity: FindingSeverity::High,
                        evidence: format!(
                            "{}:{} → {}:{} ({})",
                            conn.get("local_address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?"),
                            conn.get("local_port").and_then(|v| v.as_u64()).unwrap_or(0),
                            remote_addr,
                            remote_port,
                            state
                        ),
                        reason: format!("Port {} is associated with: {}", port, description),
                        timestamp: chrono::Utc::now(),
                        host: self.hostname.clone(),
                        process: process_name.map(|s| s.to_string()),
                        pid,
                        confidence: 0.7,
                        mitre_attack_id: FindingCategory::SuspiciousNetwork
                            .mitre_attack_id()
                            .to_string(),
                        category: FindingCategory::SuspiciousNetwork,
                    });
                }
            }
        }
    }

    /// Analyze memory regions for injection indicators such as writable + executable + anonymous pages.
    pub fn analyze_memory_anomalies(&mut self, regions: &[serde_json::Value]) {
        for region in regions {
            let executable = region.get("executable").and_then(|v| v.as_bool()).unwrap_or(false);
            let writable = region.get("writable").and_then(|v| v.as_bool()).unwrap_or(false);
            let anonymous = region.get("anonymous").and_then(|v| v.as_bool()).unwrap_or(false);
            let mapped_file = region.get("mapped_file").and_then(|v| v.as_str()).unwrap_or("[anon]");
            let pid = region.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);

            if executable && writable && anonymous {
                let category = FindingCategory::MemoryAnomaly;
                self.findings.push(SecurityFinding {
                    indicator: "memory.injected".to_string(),
                    severity: FindingSeverity::High,
                    evidence: format!("PID {:?}: {} {} {} {}", pid, mapped_file, executable, writable, anonymous),
                    reason: "Writable+executable anonymous memory is a common indicator of shellcode or injected code execution".to_string(),
                    timestamp: chrono::Utc::now(),
                    host: self.hostname.clone(),
                    process: None,
                    pid,
                    confidence: 0.8,
                    mitre_attack_id: category.mitre_attack_id().to_string(),
                    category,
                });
            }
        }
    }

    /// Analyze loaded driver records for BYOVD or kernel abuse indicators.
    pub fn analyze_driver_anomalies(&mut self, drivers: &[serde_json::Value]) {
        for driver in drivers {
            let name = driver.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let vulns = driver
                .get("vulnerability_indicators")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if vulns.is_empty() {
                continue;
            }

            let mut highest = FindingSeverity::Medium;
            for vuln in &vulns {
                let severity = vuln.get("severity").and_then(|v| v.as_str()).unwrap_or("MEDIUM");
                if severity == "CRITICAL" {
                    highest = FindingSeverity::Critical;
                    break;
                }
                if severity == "HIGH" {
                    highest = FindingSeverity::High;
                }
            }

            let category = FindingCategory::DriverAnomaly;
            self.findings.push(SecurityFinding {
                indicator: format!("Driver vulnerability indicator: {}", name),
                severity: highest,
                evidence: format!("{}: {}", name, serde_json::to_string(&vulns).unwrap_or_default()),
                reason: "Loaded driver matches a known vulnerable-driver or BYOVD signature set".to_string(),
                timestamp: chrono::Utc::now(),
                host: self.hostname.clone(),
                process: None,
                pid: None,
                confidence: 0.82,
                mitre_attack_id: category.mitre_attack_id().to_string(),
                category,
            });
        }
    }

    /// Return all accumulated findings
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }

    /// Return findings as JSON
    pub fn findings_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.findings)
    }

    /// Run all analyses on provided data
    pub fn run_full_analysis(
        &mut self,
        processes: &[serde_json::Value],
        connections: &[serde_json::Value],
    ) {
        self.analyze_parent_child_relationships(processes);
        self.analyze_executable_locations(processes);
        self.analyze_command_lines(processes);
        self.analyze_network_connections(connections);
    }

    /// Run the full analysis with additional memory and driver evidence for injection and BYOVD detection.
    pub fn run_full_analysis_with_context(
        &mut self,
        processes: &[serde_json::Value],
        connections: &[serde_json::Value],
        memory_regions: &[serde_json::Value],
        drivers: &[serde_json::Value],
    ) {
        self.analyze_parent_child_relationships(processes);
        self.analyze_executable_locations(processes);
        self.analyze_command_lines(processes);
        self.analyze_network_connections(connections);
        self.analyze_memory_anomalies(memory_regions);
        self.analyze_driver_anomalies(drivers);
    }

    /// Generate a summary report
    pub fn summary(&self) -> SecuritySummary {
        let total = self.findings.len();
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Low)
            .count();
        let info = self
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Informational)
            .count();

        SecuritySummary {
            total_findings: total,
            critical,
            high,
            medium,
            low,
            informational: info,
            categories: self
                .findings
                .iter()
                .map(|f| f.category)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .map(|c| c.to_string())
                .collect(),
        }
    }
}

/// Summary statistics for a security analysis run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
    pub categories: Vec<String>,
}

pub fn collect_audit_policy() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let paths = [
        "/etc/audit/auditd.conf",
        "/etc/audit/rules.d",
        "/etc/security/limits.conf",
        "/etc/sudoers",
        "/etc/pam.d",
    ];

    for path in paths {
        let p = std::path::Path::new(path);
        if !p.exists() {
            continue;
        }

        let content = std::fs::read_to_string(p).unwrap_or_default();
        let suspicious = content.lines().any(|line| {
            let l = line.to_lowercase();
            l.contains("audit") || l.contains("pam") || l.contains("sudo")
        });
        results.push(serde_json::json!({
            "collector": "audit_policy",
            "path": path,
            "available": true,
            "suspicious": suspicious,
            "sample_lines": content.lines().take(20).collect::<Vec<_>>(),
        }));
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "audit_policy",
            "status": "not_available",
        }));
    }

    Ok(results)
}

pub fn collect_firewall_rules() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let commands: &[(&str, &[&str])] = &[
        ("iptables", &["iptables", "-S"]),
        ("nft", &["nft", "list", "ruleset"]),
        ("ufw", &["ufw", "status", "verbose"]),
    ];

    for (cmd, args) in commands {
        let output = std::process::Command::new(*cmd).args(*args).output();
        let Ok(out) = output else {
            continue;
        };
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stdout.is_empty() {
            continue;
        }
        results.push(serde_json::json!({
            "collector": "firewall",
            "engine": cmd,
            "output": stdout
                .lines()
                .take(50)
                .collect::<Vec<_>>(),
            "status": "present",
        }));
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "firewall",
            "status": "not_available",
        }));
    }

    Ok(results)
}

pub fn detect_av_edr() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let candidates = [
        "/usr/bin/clamd",
        "/usr/sbin/clamd",
        "/opt/osquery/bin/osqueryd",
        "/var/osquery/osqueryd",
        "/usr/bin/osqueryd",
        "/etc/falcon-sensor",
        "/etc/wazuh-agent",
        "/usr/sbin/rkhunter",
        "/usr/bin/aide",
    ];

    for path in candidates {
        let p = std::path::Path::new(path);
        if p.exists() {
            results.push(serde_json::json!({
                "collector": "av_edr",
                "product": p.file_name().unwrap_or_default().to_string_lossy(),
                "path": path,
                "status": "present",
            }));
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "av_edr",
            "status": "not_detected",
        }));
    }

    Ok(results)
}

pub fn collect_app_control() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let sources = [
        "/sys/fs/selinux/enforce",
        "/etc/selinux/config",
        "/sys/module/apparmor/parameters/enabled",
        "/sys/kernel/security/apparmor/profiles",
        "/etc/apparmor.d",
    ];

    for path in sources {
        let p = std::path::Path::new(path);
        if !p.exists() {
            continue;
        }
        let content = std::fs::read_to_string(p).unwrap_or_default();
        results.push(serde_json::json!({
            "collector": "app_control",
            "path": path,
            "value": if content.trim().is_empty() { "present" } else { content.trim() },
        }));
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "app_control",
            "status": "not_available",
        }));
    }

    Ok(results)
}

pub fn analyze_shell_scripts(search_path: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "shell_scripts",
            "status": "path_not_found",
            "path": search_path,
        })]);
    }

    let mut results = Vec::new();
    let suspicious_patterns = [
        "curl ",
        "wget ",
        "base64",
        "nc ",
        "/dev/tcp",
        "chmod +x",
        "python -c",
        "bash -i",
        "powershell -enc",
    ];

    fn scan_script(path: &std::path::Path, suspicious_patterns: &[&str], results: &mut Vec<serde_json::Value>) {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let matches: Vec<&str> = suspicious_patterns
            .iter()
            .copied()
            .filter(|pattern| content.to_lowercase().contains(*pattern))
            .collect();

        if !matches.is_empty() {
            results.push(serde_json::json!({
                "collector": "shell_scripts",
                "path": path.display().to_string(),
                "matches": matches,
                "suspicious": true,
            }));
        }
    }

    if path.is_file() {
        scan_script(path, &suspicious_patterns, &mut results);
    } else if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "sh" | "bash" | "zsh" | "ksh" | "bashrc" | "profile") {
                    scan_script(&p, &suspicious_patterns, &mut results);
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "shell_scripts",
            "status": "no_suspicious_scripts",
            "path": search_path,
        }));
    }

    Ok(results)
}

/// Rootkit indicator detector
pub fn detect_rootkit_indicators(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "rootkit_indicators",
            "status": "path_not_found",
            "path": search_path,
        })]);
    }

    let mut findings = Vec::new();
    let mut completed_checks = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let preload_path = std::path::Path::new("/etc/ld.so.preload");
        if let Ok(contents) = std::fs::read_to_string(preload_path) {
            completed_checks.push("ld_preload".to_string());
            for line in contents.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
                let library = std::path::Path::new(line);
                let suspicious_location = line.starts_with("/tmp/") || line.starts_with("/dev/shm/") || line.starts_with("/home/");
                if !library.exists() || suspicious_location {
                    findings.push(serde_json::json!({
                        "collector": "rootkit_indicators",
                        "indicator": "ld_preload_anomaly",
                        "path": line,
                        "exists": library.exists(),
                        "suspicious_location": suspicious_location,
                        "reason": if suspicious_location { "preload library configured from a user-writable location" } else { "configured preload library is missing" },
                    }));
                }
            }
        }

        if let (Ok(proc_modules), Ok(sys_modules)) = (std::fs::read_to_string("/proc/modules"), std::fs::read_dir("/sys/module")) {
            completed_checks.push("module_visibility_cross_check".to_string());
            let loaded = proc_modules.lines().filter_map(|line| line.split_whitespace().next()).collect::<std::collections::HashSet<_>>();
            let exposed = sys_modules.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect::<std::collections::HashSet<_>>();
            for module in loaded {
                if !exposed.contains(module) {
                    findings.push(serde_json::json!({
                        "collector": "rootkit_indicators",
                        "indicator": "module_visibility_mismatch",
                        "module": module,
                        "reason": "module appears in /proc/modules but is absent from /sys/module",
                    }));
                }
            }
        }

        if let Ok(proc_entries) = std::fs::read_dir("/proc") {
            completed_checks.push("deleted_running_executables".to_string());
            for entry in proc_entries.flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
                let exe_link = format!("/proc/{}/exe", pid);
                if let Ok(target) = std::fs::read_link(&exe_link) {
                    let target = target.to_string_lossy();
                    if target.ends_with(" (deleted)") {
                        findings.push(serde_json::json!({
                            "collector": "rootkit_indicators",
                            "indicator": "deleted_running_executable",
                            "pid": pid,
                            "executable": target.trim_end_matches(" (deleted)"),
                            "reason": "process executable has been unlinked while still mapped",
                        }));
                    }
                }
            }
        }
    }

    let unsupported_checks = ["hidden_processes", "hidden_files", "hidden_ports", "ssdt_hooks", "idt_hooks", "dkom", "system_call_table_integrity"];
    findings.insert(0, serde_json::json!({
        "collector": "rootkit_indicators",
        "status": "partial",
        "host_platform": std::env::consts::OS,
        "completed_checks": completed_checks,
        "unavailable_checks": unsupported_checks,
        "finding_count": findings.len(),
    }));
    let results = findings;
    Ok(results)
}

fn detect_packer_signatures(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    const PACKER_PATTERNS: &[(&str, &str)] = &[
        ("upx", "upx0"),
        ("upx", "upx1"),
        ("upx", "upx2"),
        ("upx", "upx3"),
        ("upx", "upx!"),
        ("aspack", "aspack"),
        ("aspack", "asprotect"),
        ("fsg", "fsg!"),
        ("pecompact", "pecompact"),
        ("nspack", "nspack"),
        ("mpress", "mpress"),
        ("kkrunchy", "kkrunchy"),
        ("winupack", "winupack"),
        ("themida", "themida"),
    ];

    let mut hits = Vec::new();
    for (label, pattern) in PACKER_PATTERNS {
        if text.contains(pattern) {
            hits.push(label.to_string());
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Binary anomaly detector
pub fn detect_binary_anomalies(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "binary_anomalies",
            "status": "path_not_found",
            "path": search_path,
        })]);
    }

    let mut results = Vec::new();

    for entry in walkdir_max_depth(path, 3) {
        if entry.is_file() {
            let ext = entry.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "exe" || ext == "dll" || ext == "so" || ext == "bin" || ext == "sys" {
                let bytes = std::fs::read(&entry).unwrap_or_default();
                if bytes.is_empty() {
                    continue;
                }

                let mut freq = [0u64; 256];
                for &b in &bytes {
                    freq[b as usize] += 1;
                }
                let len = bytes.len() as f64;
                let mut entropy = 0.0;
                for &count in &freq {
                    if count > 0 {
                        let p = count as f64 / len;
                        entropy -= p * p.log2();
                    }
                }

                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let packer_hits = detect_packer_signatures(&bytes);
                let mut anomalies = Vec::new();
                if entropy > 7.0 {
                    anomalies.push("high_entropy".to_string());
                }
                if !packer_hits.is_empty() {
                    anomalies.push("packing_signature".to_string());
                }
                let suspicious = !anomalies.is_empty();

                results.push(serde_json::json!({
                    "collector": "binary_anomalies",
                    "path": entry.display().to_string(),
                    "size_bytes": size,
                    "sha256": sha256,
                    "entropy": entropy,
                    "file_type": ext,
                    "anomalies": anomalies,
                    "packer_signatures": packer_hits,
                    "suspicious": suspicious,
                }));
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "binary_anomalies",
            "status": "no_artifacts_found",
            "path": search_path,
        }));
    }

    Ok(results)
}

/// Simple directory walker limited to max_depth (avoids pulling in walkdir crate)
fn walkdir_max_depth(dir: &std::path::Path, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    walk_recursive(dir, 0, max_depth, &mut results);
    results
}

fn walk_recursive(dir: &std::path::Path, depth: usize, max_depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth > max_depth {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        } else if path.is_dir() && depth < max_depth {
            walk_recursive(&path, depth + 1, max_depth, out);
        }
    }
}

/// Compute SHA-256 of a file (returns hex string, or "error:<msg>" on failure)
fn sha256_file(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return format!("error:{}", e),
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_suspicious_parent_child() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let processes = vec![
            json!({"pid": 100, "name": "winword.exe", "ppid": 1}),
            json!({"pid": 200, "name": "cmd.exe", "ppid": 100}),
        ];
        analyzer.analyze_parent_child_relationships(&processes);
        assert_eq!(analyzer.findings().len(), 1);
        assert_eq!(analyzer.findings()[0].severity, FindingSeverity::High);
        assert_eq!(
            analyzer.findings()[0].category,
            FindingCategory::SuspiciousParentChild
        );
    }

    #[test]
    fn test_suspicious_command_line() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let processes = vec![
            json!({"pid": 100, "name": "powershell.exe", "command_line": ["powershell.exe", "-EncodedCommand", "AAAA"]}),
        ];
        analyzer.analyze_command_lines(&processes);
        assert_eq!(analyzer.findings().len(), 1);
        assert_eq!(
            analyzer.findings()[0].category,
            FindingCategory::SuspiciousCommandLine
        );
    }

    #[test]
    fn test_suspicious_network() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let connections = vec![json!({
            "local_address": "10.0.0.1",
            "local_port": 54321,
            "remote_address": "192.168.1.100",
            "remote_port": 4444,
            "state": "ESTABLISHED",
            "pid": 1234,
            "process_name": "unknown.exe"
        })];
        analyzer.analyze_network_connections(&connections);
        assert_eq!(analyzer.findings().len(), 1);
        assert_eq!(
            analyzer.findings()[0].category,
            FindingCategory::SuspiciousNetwork
        );
    }

    #[test]
    fn test_normal_process_no_findings() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let processes = vec![
            json!({"pid": 1, "name": "init", "ppid": 0}),
            json!({"pid": 2, "name": "systemd", "ppid": 1}),
        ];
        analyzer.analyze_parent_child_relationships(&processes);
        assert!(analyzer.findings().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rootkit_checks_report_partial_kernel_coverage() {
        let records = detect_rootkit_indicators("/").unwrap();
        assert_eq!(records[0]["status"], "partial");
        assert!(records[0]["completed_checks"].as_array().unwrap().iter().any(|check| check == "deleted_running_executables"));
        assert!(records[0]["unavailable_checks"].as_array().unwrap().iter().any(|check| check == "ssdt_hooks"));
    }

    #[test]
    fn test_summary() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let processes = vec![
            json!({"pid": 100, "name": "winword.exe", "ppid": 1}),
            json!({"pid": 200, "name": "cmd.exe", "ppid": 100}),
        ];
        let connections = vec![json!({
            "remote_port": 4444,
            "remote_address": "10.0.0.1",
            "state": "ESTABLISHED"
        })];
        analyzer.run_full_analysis(&processes, &connections);
        let summary = analyzer.summary();
        assert!(summary.total_findings >= 2);
    }

    #[test]
    fn test_memory_injection_analysis() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let regions = vec![json!({
            "pid": 333,
            "mapped_file": "[anon]",
            "executable": true,
            "writable": true,
            "anonymous": true,
        })];
        analyzer.analyze_memory_anomalies(&regions);
        assert_eq!(analyzer.findings().len(), 1);
        assert_eq!(analyzer.findings()[0].category, FindingCategory::MemoryAnomaly);
    }

    #[test]
    fn test_driver_vulnerability_analysis() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let drivers = vec![json!({
            "name": "rtcore64",
            "vulnerability_indicators": [
                {"indicator_type": "known_vulnerable_driver", "severity": "CRITICAL"}
            ]
        })];
        analyzer.analyze_driver_anomalies(&drivers);
        assert_eq!(analyzer.findings().len(), 1);
        assert_eq!(analyzer.findings()[0].category, FindingCategory::DriverAnomaly);
        assert_eq!(analyzer.findings()[0].severity, FindingSeverity::Critical);
    }

    #[test]
    fn all_findings_carry_mitre_attack_id() {
        let mut analyzer = SecurityAnalyzer::new("test-host");
        let processes = vec![
            json!({"pid": 100, "name": "winword.exe", "ppid": 1}),
            json!({"pid": 200, "name": "cmd.exe", "ppid": 100}),
            json!({"pid": 300, "name": "powershell.exe", "ppid": 0,
                   "command_line": ["powershell.exe", "-EncodedCommand", "AAAA"]}),
        ];
        let connections = vec![json!({
            "local_address": "10.0.0.1", "local_port": 54321,
            "remote_address": "192.168.1.100", "remote_port": 4444,
            "state": "ESTABLISHED", "pid": 300, "process_name": "powershell.exe"
        })];
        analyzer.run_full_analysis(&processes, &connections);
        assert!(!analyzer.findings().is_empty());
        for finding in analyzer.findings() {
            assert!(
                !finding.mitre_attack_id.is_empty(),
                "Finding '{}' is missing a MITRE ATT&CK ID",
                finding.indicator
            );
        }
    }

    #[test]
    fn finding_category_mitre_ids_are_non_empty() {
        let categories = [
            FindingCategory::SuspiciousProcess,
            FindingCategory::UnsignedExecutable,
            FindingCategory::UnexpectedLocation,
            FindingCategory::SuspiciousNetwork,
            FindingCategory::PersistenceMechanism,
            FindingCategory::PrivilegeEscalation,
            FindingCategory::SuspiciousCommandLine,
            FindingCategory::SuspiciousParentChild,
            FindingCategory::MemoryAnomaly,
            FindingCategory::DriverAnomaly,
        ];
        for cat in &categories {
            let id = cat.mitre_attack_id();
            assert!(!id.is_empty(), "{:?} has no MITRE ATT&CK ID", cat);
            assert!(
                id.starts_with('T'),
                "{:?} MITRE ID '{}' does not start with 'T'",
                cat,
                id
            );
        }
    }

    #[test]
    fn test_collect_audit_policy_and_app_control() {
        let result = collect_audit_policy();
        assert!(result.is_ok(), "audit policy collection should work on Linux");

        let app = collect_app_control();
        assert!(app.is_ok(), "app control collection should work on Linux");
    }

    #[test]
    fn test_collect_firewall_rules_and_security_inventory() {
        let firewall = collect_firewall_rules();
        assert!(firewall.is_ok(), "firewall collection should return a result");

        let edr = detect_av_edr();
        assert!(edr.is_ok(), "AV/EDR inventory should return a result");
    }
}
