//! TraceForge Runtime - Security Analysis Module
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
                            self.findings.push(SecurityFinding {
                                indicator: format!(
                                    "Suspicious parent-child: {} ({}) → {} ({})",
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
                                category: FindingCategory::SuspiciousParentChild,
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
                        self.findings.push(SecurityFinding {
                            indicator: format!("Process running from temp/download directory: {}", name),
                            severity: FindingSeverity::Medium,
                            evidence: format!("Path: {}", path),
                            reason: "Executables running from temporary or download directories may indicate malware or unauthorized software".to_string(),
                            timestamp: chrono::Utc::now(),
                            host: self.hostname.clone(),
                            process: Some(name.to_string()),
                            pid,
                            confidence: 0.6,
                            category: FindingCategory::UnexpectedLocation,
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
                        category: FindingCategory::SuspiciousCommandLine,
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
                        category: FindingCategory::SuspiciousNetwork,
                    });
                }
            }
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
}
