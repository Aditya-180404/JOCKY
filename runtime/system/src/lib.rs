//! TraceForge Runtime - System information collection

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_count: usize,
    pub total_memory_bytes: u64,
    pub boot_time: Option<chrono::DateTime<chrono::Utc>>,
    pub uptime_seconds: u64,
    pub timezone: String,
    pub locale: String,
}

impl SystemInfo {
    pub fn collect() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;

            let hostname = fs::read_to_string("/etc/hostname")?.trim().to_string();
            let os_release = fs::read_to_string("/etc/os-release")?;
            let os = os_release
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"'))
                .unwrap_or("Unknown")
                .to_string();

            let kernel = fs::read_to_string("/proc/version")?
                .split_whitespace()
                .nth(2)
                .unwrap_or("Unknown")
                .to_string();

            let arch = std::env::consts::ARCH.to_string();

            let cpu_count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);

            let meminfo = fs::read_to_string("/proc/meminfo")?;
            let total_memory_kb = meminfo
                .lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let total_memory_bytes = total_memory_kb * 1024;

            let boot_time = fs::read_to_string("/proc/stat")?
                .lines()
                .find(|l| l.starts_with("btime "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<i64>().ok())
                .map(|ts| chrono::DateTime::from_timestamp(ts, 0).unwrap());

            let uptime_str = fs::read_to_string("/proc/uptime")?;
            let uptime_seconds = uptime_str
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0) as u64;

            Ok(SystemInfo {
                hostname,
                os,
                os_version: "Unknown".to_string(), // Could parse from os-release
                kernel_version: kernel,
                architecture: arch,
                cpu_count,
                total_memory_bytes,
                boot_time,
                uptime_seconds,
                timezone: std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string()),
                locale: std::env::var("LANG").unwrap_or_else(|_| "C".to_string()),
            })
        }

        #[cfg(target_os = "windows")]
        {
            let hostname = std::process::Command::new("cmd")
                .args(["/C", "hostname"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "windows-host".to_string());

            let os_version = std::process::Command::new("cmd")
                .args(["/C", "ver"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "Windows".to_string());

            let architecture = std::env::consts::ARCH.to_string();
            let mem_output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize",
                ])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            let total_memory_bytes = mem_output.map(|kb| kb * 1024).unwrap_or(0);

            let uptime_seconds = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "[int]([DateTime]::UtcNow - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()).TotalSeconds"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);

            Ok(SystemInfo {
                hostname,
                os: "Windows".to_string(),
                os_version,
                kernel_version: "NT".to_string(),
                architecture,
                cpu_count: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                total_memory_bytes,
                boot_time: None,
                uptime_seconds,
                timezone: "UTC".to_string(),
                locale: "en-US".to_string(),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Ok(SystemInfo {
                hostname: "unknown".to_string(),
                os: "Unknown".to_string(),
                os_version: "Unknown".to_string(),
                kernel_version: "Unknown".to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                cpu_count: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                total_memory_bytes: 0,
                boot_time: None,
                uptime_seconds: 0,
                timezone: "UTC".to_string(),
                locale: "C".to_string(),
            })
        }
    }
}

pub fn collect_system_info() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let info = SystemInfo::collect()?;
    Ok(serde_json::to_value(info)?)
}
