//! TraceForge Runtime - Kernel Driver / Kernel Module Enumeration
//!
//! Defensive forensic enumeration of loaded kernel drivers and modules.
//! This module performs **read-only** observation only — no driver loading,
//! no exploitation, no kernel modification.
//!
//! Linux: Reads /proc/modules and /sys/module/*
//! Windows: Queries loaded driver list via NtQuerySystemInformation (read-only)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A loaded kernel driver or module record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverRecord {
    pub name: String,
    pub path: Option<String>,
    pub size_bytes: Option<u64>,
    pub load_order: Option<u64>,
    pub state: String,
    pub ref_count: Option<i64>,
    pub sha256: Option<String>,
    pub vulnerability_indicators: Vec<VulnerabilityIndicator>,
    pub collected_at: DateTime<Utc>,
}

/// A vulnerability indicator based on known bad driver signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: String,
    pub reference: Option<String>,
}

/// Known vulnerable driver name fragments (BYOVD indicators, defensive only)
/// These are names associated with publicly known vulnerable drivers used in BYOVD attacks.
/// Source: https://github.com/magicsword-io/LOLDrivers (community-maintained, public)
static KNOWN_VULNERABLE_DRIVER_NAMES: &[(&str, &str, &str)] = &[
    ("rtcore64", "MSI Afterburner vulnerable driver - BYOVD target", "CRITICAL"),
    ("gdrv", "Gigabyte driver vulnerable to BYOVD exploitation", "CRITICAL"),
    ("aswvmm", "Avast vulnerable driver", "HIGH"),
    ("asrdrv10", "ASRock vulnerable driver - privilege escalation risk", "HIGH"),
    ("cpuz", "CPU-Z driver - kernel memory read risk", "MEDIUM"),
    ("winio", "WinIO vulnerable driver - direct hardware access", "HIGH"),
    ("inpoutx64", "InpOut vulnerable driver - kernel I/O risk", "MEDIUM"),
    ("physmem", "PhysMem vulnerable driver - physical memory access", "CRITICAL"),
    ("amifldrv64", "AMI flash driver - kernel write risk", "HIGH"),
    ("drvmap", "Driver mapper tool associated with evasion", "HIGH"),
    ("atillk64", "ATI/AMD legacy driver - BYOVD target", "HIGH"),
    ("zemana", "Zemana AntiLogger driver - privilege escalation", "HIGH"),
];

/// Enumerate loaded kernel drivers/modules (defensive, read-only)
pub fn enumerate_drivers() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        enumerate_linux_modules()
    }

    #[cfg(target_os = "windows")]
    {
        enumerate_windows_drivers()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(vec![serde_json::json!({
            "error": "driver enumeration not supported on this platform",
            "platform": std::env::consts::OS
        })])
    }
}

#[cfg(target_os = "linux")]
fn enumerate_linux_modules() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    let modules_content = std::fs::read_to_string("/proc/modules")?;

    for line in modules_content.lines() {
        // Format: name size refcount depends live_status offset
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let name = parts[0].to_string();
        let size_bytes: u64 = parts[1].parse().unwrap_or(0);
        let ref_count: i64 = parts[2].parse().unwrap_or(-1);
        let state = parts[4].to_string();

        // Look for the module file on disk
        let (path, sha256) = find_linux_module_file(&name);

        // Check for vulnerability indicators
        let vulnerability_indicators = check_vulnerability_indicators(&name, sha256.as_deref());

        let record = DriverRecord {
            name: name.clone(),
            path,
            size_bytes: Some(size_bytes),
            load_order: None,
            state,
            ref_count: Some(ref_count),
            sha256,
            vulnerability_indicators,
            collected_at: Utc::now(),
        };

        records.push(serde_json::to_value(record)?);
    }

    Ok(records)
}

#[cfg(target_os = "linux")]
fn find_linux_module_file(name: &str) -> (Option<String>, Option<String>) {
    use std::process::Command;

    // Try modinfo to get path
    if let Ok(output) = Command::new("modinfo").args(["-n", name]).output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() && Path::new(&path_str).exists() {
                let sha256 = hash_file_sha256(&path_str).ok();
                return (Some(path_str), sha256);
            }
        }
    }

    // Fallback: search common locations
    let search_dirs = [
        format!("/lib/modules/{}/kernel", uname_r()),
        "/lib/modules".to_string(),
    ];
    for dir in &search_dirs {
        let candidates = [
            format!("{}/{}.ko", dir, name),
            format!("{}/{}.ko.xz", dir, name),
            format!("{}/{}.ko.gz", dir, name),
        ];
        for c in &candidates {
            if Path::new(c).exists() {
                let sha256 = hash_file_sha256(c).ok();
                return (Some(c.clone()), sha256);
            }
        }
    }

    (None, None)
}

#[cfg(target_os = "linux")]
fn uname_r() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Hash a file with SHA-256
pub fn hash_file_sha256(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Check driver name against known vulnerability indicators (defensive BYOVD detection)
pub fn check_vulnerability_indicators(
    name: &str,
    _sha256: Option<&str>,
) -> Vec<VulnerabilityIndicator> {
    let name_lower = name.to_lowercase();
    let mut indicators = Vec::new();

    for (fragment, description, severity) in KNOWN_VULNERABLE_DRIVER_NAMES {
        if name_lower.contains(fragment) {
            indicators.push(VulnerabilityIndicator {
                indicator_type: "known_vulnerable_driver".to_string(),
                description: description.to_string(),
                severity: severity.to_string(),
                reference: Some("https://github.com/magicsword-io/LOLDrivers".to_string()),
            });
        }
    }

    indicators
}

/// Summary of the driver enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverEnumerationSummary {
    pub total_drivers: usize,
    pub drivers_with_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
}

/// Calculate summary statistics from driver records
pub fn summarize_drivers(records: &[serde_json::Value]) -> DriverEnumerationSummary {
    let mut drivers_with_vulns = 0usize;
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;

    for record in records {
        if let Some(vulns) = record.get("vulnerability_indicators").and_then(|v| v.as_array()) {
            if !vulns.is_empty() {
                drivers_with_vulns += 1;
                for vuln in vulns {
                    match vuln.get("severity").and_then(|s| s.as_str()) {
                        Some("CRITICAL") => critical += 1,
                        Some("HIGH") => high += 1,
                        Some("MEDIUM") => medium += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    DriverEnumerationSummary {
        total_drivers: records.len(),
        drivers_with_vulnerabilities: drivers_with_vulns,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_indicator_detection() {
        let indicators = check_vulnerability_indicators("rtcore64", None);
        assert!(!indicators.is_empty());
        assert!(indicators[0].severity == "CRITICAL");
    }

    #[test]
    fn test_safe_driver_no_indicators() {
        let indicators = check_vulnerability_indicators("ext4", None);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_summary_empty_records() {
        let summary = summarize_drivers(&[]);
        assert_eq!(summary.total_drivers, 0);
        assert_eq!(summary.drivers_with_vulnerabilities, 0);
    }

    #[test]
    fn test_summary_with_vulnerable_record() {
        let record = serde_json::json!({
            "name": "rtcore64",
            "state": "Live",
            "vulnerability_indicators": [
                { "indicator_type": "known_vulnerable_driver", "description": "test", "severity": "CRITICAL" }
            ]
        });
        let summary = summarize_drivers(&[record]);
        assert_eq!(summary.total_drivers, 1);
        assert_eq!(summary.drivers_with_vulnerabilities, 1);
        assert_eq!(summary.critical_count, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_enumerate_linux_modules_returns_results() {
        let result = enumerate_linux_modules();
        assert!(result.is_ok(), "Module enumeration should succeed on Linux");
        let records = result.unwrap();
        // There should be at least a few kernel modules loaded on a typical Linux system
        assert!(!records.is_empty(), "Expected at least one kernel module");
    }
}
