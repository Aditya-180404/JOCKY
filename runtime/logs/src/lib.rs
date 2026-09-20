//! TraceForge Runtime - Log collection

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub level: Option<String>,
    pub message: String,
    pub source: String,
    pub raw_line: String,
}

pub fn collect_logs(source: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    match source {
        "system" => collect_journal_logs(),
        "auth" => collect_auth_logs(),
        "syslog" => collect_syslog_logs(),
        "kernel" => collect_kernel_logs(),
        path if Path::new(path).exists() => collect_file_logs(path),
        _ => Err(format!("Unknown log source: {}", source).into()),
    }
}

fn collect_journal_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    // Use journalctl on systemd systems
    let output = std::process::Command::new("journalctl")
        .args(["--no-pager", "-n", "1000", "-o", "json"])
        .output()?;

    if !output.status.success() {
        return Err("journalctl failed".into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let entry = LogEntry {
                timestamp: json.get("__REALTIME_TIMESTAMP")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|us| DateTime::from_timestamp_micros(us as i64).unwrap()),
                level: json.get("PRIORITY").and_then(|v| v.as_str()).map(|s| s.to_string()),
                message: json.get("MESSAGE").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                source: "journal".to_string(),
                raw_line: line.to_string(),
            };
            results.push(serde_json::to_value(entry)?);
        }
    }

    Ok(results)
}

fn collect_auth_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = "/var/log/auth.log";
    collect_file_logs(path)
}

fn collect_syslog_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = "/var/log/syslog";
    collect_file_logs(path)
}

fn collect_kernel_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = "/var/log/kern.log";
    collect_file_logs(path)
}

fn collect_file_logs(path: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut results = Vec::new();

    for (i, line) in content.lines().rev().take(1000).enumerate() {
        let entry = LogEntry {
            timestamp: None,
            level: extract_log_level(line),
            message: line.to_string(),
            source: path.to_string(),
            raw_line: line.to_string(),
        };
        results.push(serde_json::to_value(entry)?);
    }

    results.reverse();
    Ok(results)
}

fn extract_log_level(line: &str) -> Option<String> {
    let levels = ["ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE", "CRITICAL", "FATAL", "EMERG", "ALERT"];
    for level in levels {
        if line.contains(level) {
            return Some(level.to_string());
        }
    }
    None
}