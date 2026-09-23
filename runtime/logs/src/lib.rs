//! TraceForge Runtime - Log collection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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

#[cfg(not(target_os = "windows"))]
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
                timestamp: json
                    .get("__REALTIME_TIMESTAMP")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|us| DateTime::from_timestamp_micros(us as i64).unwrap()),
                level: json
                    .get("PRIORITY")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                message: json
                    .get("MESSAGE")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                source: "journal".to_string(),
                raw_line: line.to_string(),
            };
            results.push(serde_json::to_value(entry)?);
        }
    }

    Ok(results)
}

#[cfg(target_os = "windows")]
fn collect_journal_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-WinEvent -LogName System -MaxEvents 1000 | Select-Object TimeCreated,LevelDisplayName,Message,ProviderName,Id | ConvertTo-Json -Compress",
        ])
        .output()?;
    if !output.status.success() {
        return Err("Get-WinEvent failed for the System log".into());
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let items = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(item) => vec![serde_json::Value::Object(item)],
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(|item| {
            let timestamp = item
                .get("TimeCreated")
                .and_then(|value| value.as_str())
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc));
            let message = item
                .get("Message")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            serde_json::to_value(LogEntry {
                timestamp,
                level: item
                    .get("LevelDisplayName")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                message: message.clone(),
                source: item
                    .get("ProviderName")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Windows System")
                    .to_string(),
                raw_line: message,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn collect_auth_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    return Err(
        "Windows uses the system event log source; auth is not a Windows log source".into(),
    );
    #[cfg(not(target_os = "windows"))]
    let path = "/var/log/auth.log";
    #[cfg(not(target_os = "windows"))]
    collect_file_logs(path)
}

fn collect_syslog_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    return Err("syslog is not a Windows log source; use system".into());
    #[cfg(not(target_os = "windows"))]
    let path = "/var/log/syslog";
    #[cfg(not(target_os = "windows"))]
    collect_file_logs(path)
}

fn collect_kernel_logs() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    return Err("kernel log files are not a Windows log source; use system".into());
    #[cfg(not(target_os = "windows"))]
    let path = "/var/log/kern.log";
    #[cfg(not(target_os = "windows"))]
    collect_file_logs(path)
}

fn collect_file_logs(path: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut results = Vec::new();

    for line in content.lines().rev().take(1000) {
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
    let levels = [
        "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE", "CRITICAL", "FATAL", "EMERG", "ALERT",
    ];
    for level in levels {
        if line.contains(level) {
            return Some(level.to_string());
        }
    }
    None
}
