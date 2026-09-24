//! jockey Runtime - Process enumeration and information

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub command_line: Vec<String>,
    pub executable_path: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub state: Option<String>,
    pub memory_rss_bytes: Option<u64>,
    pub memory_vms_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub open_files: Vec<String>,
    pub network_connections: Vec<ProcessNetworkConnection>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
}

pub fn enumerate_processes(
    fields: &[String],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let procs = procfs::process::all_processes()?;
        let mut results = Vec::new();

        let boot_time_sec = procfs::boot_time_secs().ok();
        for proc_res in procs {
            let Ok(proc) = proc_res else { continue };
            let mut info = ProcessInfo {
                pid: proc.pid(),
                ppid: proc.stat().ok().map(|s| s.ppid),
                name: proc.stat().ok().map(|s| s.comm).unwrap_or_default(),
                command_line: proc.cmdline().ok().unwrap_or_default(),
                executable_path: proc.exe().ok().map(|p| p.to_string_lossy().to_string()),
                start_time: proc.stat().ok().and_then(|s| {
                    let start_time = s.starttime as f64 / procfs::ticks_per_second() as f64;
                    boot_time_sec.and_then(|boot_time| {
                        chrono::DateTime::from_timestamp(boot_time as i64 + start_time as i64, 0)
                    })
                }),
                user: proc.stat().ok().and_then(|_s| {
                    fs::read_to_string(format!("/proc/{}/status", proc.pid()))
                        .ok()
                        .and_then(|content| {
                            content
                                .lines()
                                .find(|l| l.starts_with("Uid:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|uid| uid.parse::<u32>().ok())
                                .and_then(get_username)
                        })
                }),
                group: proc.stat().ok().and_then(|_s| {
                    fs::read_to_string(format!("/proc/{}/status", proc.pid()))
                        .ok()
                        .and_then(|content| {
                            content
                                .lines()
                                .find(|l| l.starts_with("Gid:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|gid| gid.parse::<u32>().ok())
                                .and_then(get_groupname)
                        })
                }),
                state: proc.stat().ok().map(|s| format!("{:?}", s.state)),
                memory_rss_bytes: proc.stat().ok().map(|s| s.rss * procfs::page_size() as u64),
                memory_vms_bytes: proc.stat().ok().map(|s| s.vsize),
                cpu_percent: None, // Would need sampling over time
                open_files: Vec::new(),
                network_connections: Vec::new(),
                sha256: None,
            };

            // Collect open files
            if let Ok(fd_dir) = fs::read_dir(format!("/proc/{}/fd", proc.pid())) {
                for fd in fd_dir.flatten() {
                    if let Ok(target) = fs::read_link(fd.path()) {
                        info.open_files.push(target.to_string_lossy().to_string());
                    }
                }
            }

            // Calculate hash if requested
            if fields.iter().any(|f| f == "hash.sha256" || f == "sha256") {
                if let Some(exe_path) = &info.executable_path {
                    if let Ok(hash) = calculate_file_sha256(exe_path) {
                        info.sha256 = Some(hash);
                    }
                }
            }

            // Filter fields if specified
            let value = if fields.is_empty() {
                serde_json::to_value(info)?
            } else {
                let mut map = serde_json::Map::new();
                let full = serde_json::to_value(&info)?;
                if let serde_json::Value::Object(obj) = full {
                    for field in fields {
                        if let Some(val) = obj.get(field) {
                            map.insert(field.clone(), val.clone());
                        }
                    }
                }
                serde_json::Value::Object(map)
            };

            results.push(value);
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let mut got_processes = false;

        // Use Get-CimInstance Win32_Process for rich process data including
        // parent PID, full command line, and memory usage
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                r#"Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,WorkingSetSize,VirtualSize,CreationDate | ForEach-Object { [PSCustomObject]@{ ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name; ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; WorkingSetSize=$_.WorkingSetSize; VirtualSize=$_.VirtualSize; CreationDate=if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{$null} } } | ConvertTo-Json -Compress"#,
            ])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let items: Vec<serde_json::Value> = match val {
                    serde_json::Value::Array(arr) => arr,
                    serde_json::Value::Object(_) => vec![val],
                    _ => vec![],
                };

                for item in items {
                    let pid = item.get("ProcessId").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                    let ppid = item
                        .get("ParentProcessId")
                        .and_then(|v| v.as_i64())
                        .map(|v| v as i32);
                    let name = item
                        .get("Name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let exe_path = item
                        .get("ExecutablePath")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let cmdline_str = item
                        .get("CommandLine")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let command_line = if cmdline_str.is_empty() {
                        vec![name.clone()]
                    } else {
                        vec![cmdline_str.to_string()]
                    };
                    let memory_rss = item.get("WorkingSetSize").and_then(|v| v.as_u64());
                    let memory_vms = item.get("VirtualSize").and_then(|v| v.as_u64());
                    let start_time = item
                        .get("CreationDate")
                        .and_then(|v| v.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc));

                    let mut sha256 = None;
                    if fields.iter().any(|f| f == "hash.sha256" || f == "sha256") {
                        if let Some(path) = &exe_path {
                            if let Ok(hash) = calculate_file_sha256(path) {
                                sha256 = Some(hash);
                            }
                        }
                    }

                    // Fast user determination
                    let user = if pid == 0 || pid == 4 {
                        Some("SYSTEM".to_string())
                    } else {
                        Some(whoami::username())
                    };

                    let info = ProcessInfo {
                        pid,
                        ppid,
                        name: name.clone(),
                        command_line,
                        executable_path: exe_path,
                        start_time,
                        user,
                        group: None,
                        state: Some("running".to_string()),
                        memory_rss_bytes: memory_rss,
                        memory_vms_bytes: memory_vms,
                        cpu_percent: None,
                        open_files: Vec::new(),
                        network_connections: Vec::new(),
                        sha256,
                    };

                    let val = if fields.is_empty() {
                        serde_json::to_value(&info)?
                    } else {
                        let mut map = serde_json::Map::new();
                        let full = serde_json::to_value(&info)?;
                        if let serde_json::Value::Object(obj) = full {
                            for field in fields {
                                if let Some(v) = obj.get(field) {
                                    map.insert(field.clone(), v.clone());
                                }
                            }
                        }
                        serde_json::Value::Object(map)
                    };

                    results.push(val);
                }
                if !results.is_empty() {
                    got_processes = true;
                }
            }
        }

        // Fallback to tasklist if WMI query failed
        if !got_processes {
            if let Ok(output) = std::process::Command::new("tasklist")
                .args(["/FO", "CSV"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim_matches('"')).collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    let name = parts[0].to_string();
                    let pid = parts[1].parse::<i32>().unwrap_or(0);
                    let info = ProcessInfo {
                        pid,
                        ppid: None,
                        name: name.clone(),
                        command_line: vec![name],
                        executable_path: None,
                        start_time: None,
                        user: None,
                        group: None,
                        state: Some("running".to_string()),
                        memory_rss_bytes: None,
                        memory_vms_bytes: None,
                        cpu_percent: None,
                        open_files: Vec::new(),
                        network_connections: Vec::new(),
                        sha256: None,
                    };
                    let val = if fields.is_empty() {
                        serde_json::to_value(&info)?
                    } else {
                        let mut map = serde_json::Map::new();
                        let full = serde_json::to_value(&info)?;
                        if let serde_json::Value::Object(obj) = full {
                            for field in fields {
                                if let Some(v) = obj.get(field) {
                                    map.insert(field.clone(), v.clone());
                                }
                            }
                        }
                        serde_json::Value::Object(map)
                    };
                    results.push(val);
                }
            }
        }

        Ok(results)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "linux")]
fn get_username(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let passwd = libc::getpwuid(uid);
        if !passwd.is_null() {
            Some(
                CStr::from_ptr((*passwd).pw_name)
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn get_groupname(gid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let group = libc::getgrgid(gid);
        if !group.is_null() {
            Some(
                CStr::from_ptr((*group).gr_name)
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    }
}

fn calculate_file_sha256(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
