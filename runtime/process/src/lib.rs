//! TraceForge Runtime - Process enumeration and information

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;

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

pub fn enumerate_processes(fields: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
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
                user: proc.stat().ok().and_then(|s| {
                    fs::read_to_string(format!("/proc/{}/status", proc.pid())).ok()
                        .and_then(|content| {
                            content.lines()
                                .find(|l| l.starts_with("Uid:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|uid| uid.parse::<u32>().ok())
                                .and_then(|uid| get_username(uid))
                        })
                }),
                group: proc.stat().ok().and_then(|s| {
                    fs::read_to_string(format!("/proc/{}/status", proc.pid())).ok()
                        .and_then(|content| {
                            content.lines()
                                .find(|l| l.starts_with("Gid:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|gid| gid.parse::<u32>().ok())
                                .and_then(|gid| get_groupname(gid))
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
        // Windows implementation would use WMI or Windows APIs
        Ok(Vec::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

fn get_username(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let passwd = libc::getpwuid(uid);
        if !passwd.is_null() {
            Some(CStr::from_ptr((*passwd).pw_name).to_string_lossy().to_string())
        } else {
            None
        }
    }
}

fn get_groupname(gid: u32) -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let group = libc::getgrgid(gid);
        if !group.is_null() {
            Some(CStr::from_ptr((*group).gr_name).to_string_lossy().to_string())
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