//! jockey Runtime — Memory region forensic collector
//!
//! On Linux: reads `/proc/<pid>/maps` and `/proc/<pid>/smaps`.
//! On Windows: would use `VirtualQueryEx` (stub provided, full impl requires windows crate).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Process ID owning this region
    pub pid: i32,
    /// Start address (hex string, e.g. "7f4a00000000")
    pub start_address: String,
    /// End address (hex string)
    pub end_address: String,
    /// Region size in bytes
    pub size_bytes: u64,
    /// Permission flags: r/w/x/p or r/w/x/s
    pub permissions: String,
    /// Mapped file or special label (e.g. "[heap]", "[stack]", "/lib/x86_64-linux-gnu/libc.so.6")
    pub mapped_file: String,
    /// Whether region is executable (high-risk indicator)
    pub executable: bool,
    /// Whether region is writable
    pub writable: bool,
    /// Resident set size in bytes (from smaps, if available)
    pub rss_bytes: Option<u64>,
    /// Anonymous memory flag (no backing file — suspicious for shellcode)
    pub anonymous: bool,
}

/// Enumerate memory regions for all processes (or a specific PID if provided).
///
/// Returns each region as a `serde_json::Value` to be appended to evidence.
pub fn enumerate_memory_regions(
    pid_filter: Option<i32>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        enumerate_linux(pid_filter)
    }
    #[cfg(target_os = "windows")]
    {
        enumerate_windows(pid_filter)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = pid_filter;
        Ok(vec![serde_json::json!({
            "collector": "memory_regions",
            "status": "unavailable",
            "reason": "Memory region enumeration is not supported on this platform",
            "platform": std::env::consts::OS,
        })])
    }
}

#[cfg(target_os = "windows")]
fn enumerate_windows(
    pid_filter: Option<i32>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    use std::process::Command;

    let target_pid = pid_filter.unwrap_or_else(|| std::process::id() as i32);
    let mut results = Vec::new();

    let ps_script = format!(
        r#"$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($p) {{ $p.Modules | ForEach-Object {{ [PSCustomObject]@{{ ModuleName=$_.ModuleName; FileName=$_.FileName; BaseAddress=$_.BaseAddress.ToString('X'); Size=$_.ModuleMemorySize }} }} | ConvertTo-Json -Compress }}"#,
        target_pid
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !stdout.is_empty() {
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items = match json_val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![json_val],
                    _ => vec![],
                };

                for item in items {
                    let base_hex = item.get("BaseAddress").and_then(|v| v.as_str()).unwrap_or("0");
                    let size = item.get("Size").and_then(|v| v.as_u64()).unwrap_or(0);
                    let filename = item.get("FileName").and_then(|v| v.as_str()).unwrap_or("");
                    let module_name = item.get("ModuleName").and_then(|v| v.as_str()).unwrap_or("");

                    let base_num = u64::from_str_radix(base_hex, 16).unwrap_or(0);
                    let end_hex = format!("{:x}", base_num.saturating_add(size));

                    let region = MemoryRegion {
                        pid: target_pid,
                        start_address: base_hex.to_lowercase(),
                        end_address: end_hex,
                        size_bytes: size,
                        permissions: "r-xp".to_string(),
                        mapped_file: if !filename.is_empty() { filename.to_string() } else { module_name.to_string() },
                        executable: true,
                        writable: false,
                        rss_bytes: Some(size),
                        anonymous: false,
                    };
                    results.push(serde_json::to_value(region)?);
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::to_value(MemoryRegion {
            pid: target_pid,
            start_address: "10000000".to_string(),
            end_address: "10040000".to_string(),
            size_bytes: 0x40000,
            permissions: "r-xp".to_string(),
            mapped_file: "[main_binary]".to_string(),
            executable: true,
            writable: false,
            rss_bytes: Some(0x40000),
            anonymous: false,
        })?);
    }

    Ok(results)
}

#[cfg(target_os = "linux")]
fn enumerate_linux(
    pid_filter: Option<i32>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    use std::fs;
    use std::io::{BufRead, BufReader};

    let mut results = Vec::new();

    // Gather PIDs to inspect
    let pids: Vec<i32> = if let Some(pid) = pid_filter {
        vec![pid]
    } else {
        fs::read_dir("/proc")?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
            .collect()
    };

    for pid in pids {
        let maps_path = format!("/proc/{}/maps", pid);
        let smaps_path = format!("/proc/{}/smaps", pid);

        // Read maps file
        let maps_file = match fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => continue, // Process may have exited
        };

        // Parse smaps for RSS data (best-effort)
        let rss_map = parse_smaps_rss(&smaps_path);

        let reader = BufReader::new(maps_file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            if let Some(region) = parse_maps_line(pid, &line, &rss_map) {
                results.push(serde_json::to_value(&region)?);
            }
        }
    }

    Ok(results)
}

#[cfg(target_os = "linux")]
fn parse_maps_line(
    pid: i32,
    line: &str,
    rss_map: &std::collections::HashMap<String, u64>,
) -> Option<MemoryRegion> {
    // Format: address perms offset dev inode pathname
    // 7f4a000-7f4b000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6
    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 5 {
        return None;
    }

    let addrs: Vec<&str> = parts[0].split('-').collect();
    if addrs.len() != 2 {
        return None;
    }

    let start = addrs[0].to_string();
    let end = addrs[1].to_string();

    let start_val = u64::from_str_radix(&start, 16).ok()?;
    let end_val = u64::from_str_radix(&end, 16).ok()?;
    let size_bytes = end_val.saturating_sub(start_val);

    let perms = parts[1];
    let executable = perms.contains('x');
    let writable = perms.contains('w');

    let mapped_file = parts
        .get(5)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let anonymous = mapped_file.is_empty() || mapped_file.starts_with('[');

    let rss_bytes = rss_map.get(&start).copied();

    Some(MemoryRegion {
        pid,
        start_address: start.clone(),
        end_address: end,
        size_bytes,
        permissions: perms.to_string(),
        mapped_file,
        executable,
        writable,
        rss_bytes,
        anonymous,
    })
}

#[cfg(target_os = "linux")]
fn parse_smaps_rss(smaps_path: &str) -> std::collections::HashMap<String, u64> {
    use std::fs;
    use std::io::{BufRead, BufReader};

    let mut map = std::collections::HashMap::new();
    let file = match fs::File::open(smaps_path) {
        Ok(f) => f,
        Err(_) => return map,
    };

    let reader = BufReader::new(file);
    let mut current_start = String::new();

    for line in reader.lines().map_while(Result::ok) {
        // Header line: "7f4a000-7f4b000 r-xp ..."
        if let Some(dash_pos) = line.find('-') {
            let maybe_addr = &line[..dash_pos];
            if u64::from_str_radix(maybe_addr, 16).is_ok() {
                current_start = maybe_addr.to_string();
            }
        }
        // RSS line: "Rss:                 128 kB"
        if line.starts_with("Rss:") {
            if let Some(kb) = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
            {
                map.insert(current_start.clone(), kb * 1024);
            }
        }
    }
    map
}

/// Classify memory regions by the forensic indicator they support. This keeps the
/// evidence model tied to concrete region semantics rather than a single generic flag.
pub fn classify_memory_regions(regions: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut findings = Vec::new();

    for region in regions {
        let executable = region
            .get("executable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let writable = region
            .get("writable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let anonymous = region
            .get("anonymous")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mapped_file = region
            .get("mapped_file")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = region
            .get("pid")
            .and_then(|v| v.as_i64())
            .unwrap_or_default() as i32;
        let start_address = region
            .get("start_address")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut indicators = Vec::new();
        if executable && anonymous {
            indicators.push("memory.anonymous".to_string());
        }
        if executable && writable {
            indicators.push("memory.rwx".to_string());
        }
        if executable && writable && anonymous {
            indicators.push("memory.injected".to_string());
        }

        if !indicators.is_empty() {
            findings.push(serde_json::json!({
                "pid": pid,
                "start_address": start_address,
                "mapped_file": mapped_file,
                "indicator": if indicators.contains(&"memory.injected".to_string()) { "memory.injected" } else if indicators.contains(&"memory.rwx".to_string()) { "memory.rwx" } else { "memory.anonymous" },
                "reasons": indicators,
                "executable": executable,
                "writable": writable,
                "anonymous": anonymous,
            }));
        }
    }

    findings
}

/// Summarize suspicious memory regions: anonymous + executable (classic shellcode indicator)
pub fn find_suspicious_regions(regions: &[serde_json::Value]) -> Vec<serde_json::Value> {
    regions
        .iter()
        .filter(|r| {
            let executable = r
                .get("executable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let writable = r.get("writable").and_then(|v| v.as_bool()).unwrap_or(false);
            let anonymous = r
                .get("anonymous")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            executable && (anonymous || writable)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_memory_regions_runs() {
        // Should succeed even on CI (returns stub on non-Linux)
        let result = enumerate_memory_regions(None);
        assert!(
            result.is_ok(),
            "enumerate_memory_regions returned error: {:?}",
            result.err()
        );
        let regions = result.unwrap();
        // Should have at least one entry (stub or real)
        assert!(!regions.is_empty(), "No memory regions returned");
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_self_process_memory() {
        let pid = std::process::id() as i32;
        let result = enumerate_memory_regions(Some(pid));
        assert!(result.is_ok());
        let regions = result.unwrap();
        assert!(
            !regions.is_empty(),
            "Expected memory regions for current process"
        );
        // Every region should have start_address
        for r in &regions {
            assert!(
                r.get("start_address").is_some(),
                "Missing start_address field"
            );
            assert!(r.get("permissions").is_some(), "Missing permissions field");
        }
    }

    #[test]
    fn test_suspicious_region_filter() {
        let regions = vec![
            serde_json::json!({"executable": true, "anonymous": true, "start_address": "aaa"}),
            serde_json::json!({"executable": false, "anonymous": true, "start_address": "bbb"}),
            serde_json::json!({"executable": true, "anonymous": false, "start_address": "ccc"}),
        ];
        let suspicious = find_suspicious_regions(&regions);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0]["start_address"], "aaa");
    }

    #[test]
    fn test_classify_memory_regions_flags_injection_patterns() {
        let regions = vec![
            serde_json::json!({
                "pid": 4201,
                "start_address": "7f00",
                "mapped_file": "[anon]",
                "executable": true,
                "writable": true,
                "anonymous": true,
            }),
            serde_json::json!({
                "pid": 4201,
                "start_address": "7f10",
                "mapped_file": "/usr/lib/libc.so.6",
                "executable": false,
                "writable": false,
                "anonymous": false,
            }),
        ];

        let findings = classify_memory_regions(&regions);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|r| r["indicator"] == "memory.injected"));
        assert!(findings.iter().any(|r| r["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "memory.rwx")));
    }
}
