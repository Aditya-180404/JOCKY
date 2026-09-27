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
    // Extended fields
    pub session_id: Option<u32>,
    pub terminal: Option<String>,
    pub cgroup: Option<String>,
    pub container_id: Option<String>,
    pub integrity_level: Option<String>,
    pub parent_name: Option<String>,
    pub child_pids: Vec<i32>,
    pub modules: Vec<ProcessModule>,
    pub deleted_executable: bool,
    pub command_line_full: Option<String>,
    pub environment: Vec<String>,
    pub working_directory: Option<String>,
    pub priority: Option<i32>,
    pub nice: Option<i32>,
    pub threads: Option<u32>,
    pub handles: Option<u32>,
    pub gdi_handles: Option<u32>,
    pub user_handles: Option<u32>,
    pub io_read_bytes: Option<u64>,
    pub io_write_bytes: Option<u64>,
    pub io_other_bytes: Option<u64>,
    pub page_faults: Option<u64>,
    pub context_switches: Option<u64>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessModule {
    pub name: String,
    pub path: String,
    pub base_address: String,
    pub size_bytes: u64,
    pub version: Option<String>,
    pub description: Option<String>,
    pub company: Option<String>,
    pub signed: Option<bool>,
    pub signature_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub process: ProcessInfo,
    pub children: Vec<ProcessTreeNode>,
}

pub fn enumerate_processes(
    fields: &[String],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let procs = procfs::process::all_processes()?;
        let mut results = Vec::new();

        let boot_time_sec = procfs::boot_time_secs().ok();
        let mut pid_to_info: std::collections::HashMap<i32, ProcessInfo> =
            std::collections::HashMap::new();

        // First pass: collect all processes
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
                cpu_percent: None,
                open_files: Vec::new(),
                network_connections: Vec::new(),
                sha256: None,
                session_id: proc.stat().ok().map(|s| s.session as u32),
                terminal: proc.stat().ok().and_then(|s| {
                    if s.tty_nr != 0 {
                        Some(format!("pts/{}", s.tty_nr & 0xFF))
                    } else {
                        None
                    }
                }),
                cgroup: fs::read_to_string(format!("/proc/{}/cgroup", proc.pid()))
                    .ok()
                    .map(|s| s.trim().to_string()),
                container_id: detect_container_id(proc.pid()),
                integrity_level: None,
                parent_name: None,
                child_pids: Vec::new(),
                modules: collect_modules_linux(proc.pid()),
                deleted_executable: is_executable_deleted(proc.pid()),
                command_line_full: proc.cmdline().ok().map(|cmd| cmd.join(" ")),
                environment: collect_environment_linux(proc.pid()),
                working_directory: proc.cwd().ok().map(|p| p.to_string_lossy().to_string()),
                priority: proc.stat().ok().map(|s| s.priority as i32),
                nice: proc.stat().ok().map(|s| s.nice as i32),
                threads: proc.stat().ok().map(|s| s.num_threads as u32),
                handles: None,
                gdi_handles: None,
                user_handles: None,
                io_read_bytes: proc.io().ok().map(|io| io.rchar),
                io_write_bytes: proc.io().ok().map(|io| io.wchar),
                io_other_bytes: proc.io().ok().map(|io| io.syscr + io.syscw),
                page_faults: proc.stat().ok().map(|s| s.minflt as u64 + s.majflt as u64),
                context_switches: None,
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

            pid_to_info.insert(info.pid, info);
        }

        // Second pass: build parent-child relationships
        let mut parent_to_children: std::collections::HashMap<i32, Vec<i32>> =
            std::collections::HashMap::new();
        for info in pid_to_info.values() {
            if let Some(ppid) = info.ppid {
                parent_to_children.entry(ppid).or_default().push(info.pid);
            }
        }

        // Add parent names and child PIDs
        // First collect parent names to avoid borrow issues
        let mut parent_names: std::collections::HashMap<i32, String> =
            std::collections::HashMap::new();
        for info in pid_to_info.values() {
            if let Some(ppid) = info.ppid {
                if let Some(parent) = pid_to_info.get(&ppid) {
                    parent_names.insert(info.pid, parent.name.clone());
                }
            }
        }
        for info in pid_to_info.values_mut() {
            if let Some(parent_name) = parent_names.get(&info.pid) {
                info.parent_name = Some(parent_name.clone());
            }
            if let Some(children) = parent_to_children.get(&info.pid) {
                info.child_pids = children.clone();
            }
        }

        // Convert to results
        for info in pid_to_info.values() {
            let value = if fields.is_empty() {
                serde_json::to_value(info)?
            } else {
                let mut map = serde_json::Map::new();
                let full = serde_json::to_value(info)?;
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
                r#"Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,WorkingSetSize,VirtualSize,CreationDate,SessionId,Priority,HandleCount,ThreadCount,PageFaults,ReadOperationCount,WriteOperationCount,OtherOperationCount | ForEach-Object { [PSCustomObject]@{ ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name; ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; WorkingSetSize=$_.WorkingSetSize; VirtualSize=$_.VirtualSize; CreationDate=if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{$null}; SessionId=$_.SessionId; Priority=$_.Priority; HandleCount=$_.HandleCount; ThreadCount=$_.ThreadCount; PageFaults=$_.PageFaults; ReadOperationCount=$_.ReadOperationCount; WriteOperationCount=$_.WriteOperationCount; OtherOperationCount=$_.OtherOperationCount } } | ConvertTo-Json -Compress"#,
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

                let mut pid_to_info: std::collections::HashMap<i32, ProcessInfo> =
                    std::collections::HashMap::new();

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
                    let session_id = item
                        .get("SessionId")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    let priority = item
                        .get("Priority")
                        .and_then(|v| v.as_i64())
                        .map(|v| v as i32);
                    let handles = item
                        .get("HandleCount")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    let threads = item
                        .get("ThreadCount")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    let page_faults = item.get("PageFaults").and_then(|v| v.as_u64());
                    let io_read = item.get("ReadOperationCount").and_then(|v| v.as_u64());
                    let io_write = item.get("WriteOperationCount").and_then(|v| v.as_u64());
                    let io_other = item.get("OtherOperationCount").and_then(|v| v.as_u64());

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

                    let working_directory = exe_path.as_deref().and_then(|p| {
                        std::path::Path::new(p)
                            .parent()
                            .map(|d| d.to_string_lossy().to_string())
                    });

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
                        session_id,
                        terminal: None,
                        cgroup: None,
                        container_id: None,
                        integrity_level: None,
                        parent_name: None,
                        child_pids: Vec::new(),
                        modules: Vec::new(),
                        deleted_executable: false, // Harder to detect on Windows
                        command_line_full: Some(cmdline_str.to_string()),
                        environment: Vec::new(),
                        working_directory,
                        priority,
                        nice: None,
                        threads,
                        handles: Some(handles.unwrap_or(0)),
                        gdi_handles: None,
                        user_handles: None,
                        io_read_bytes: io_read,
                        io_write_bytes: io_write,
                        io_other_bytes: io_other,
                        page_faults,
                        context_switches: None,
                    };

                    pid_to_info.insert(pid, info);
                }

                // Build parent-child relationships
                let mut parent_to_children: std::collections::HashMap<i32, Vec<i32>> =
                    std::collections::HashMap::new();
                for info in pid_to_info.values() {
                    if let Some(ppid) = info.ppid {
                        parent_to_children.entry(ppid).or_default().push(info.pid);
                    }
                }

                // Add parent names and child PIDs
                let pid_to_name: std::collections::HashMap<i32, String> = pid_to_info
                    .values()
                    .map(|i| (i.pid, i.name.clone()))
                    .collect();
                for info in pid_to_info.values_mut() {
                    if let Some(ppid) = info.ppid {
                        if let Some(parent_name) = pid_to_name.get(&ppid) {
                            info.parent_name = Some(parent_name.clone());
                        }
                    }
                    if let Some(children) = parent_to_children.get(&info.pid) {
                        info.child_pids = children.clone();
                    }
                }

                // Convert to results
                for info in pid_to_info.values() {
                    let val = if fields.is_empty() {
                        serde_json::to_value(info)?
                    } else {
                        let mut map = serde_json::Map::new();
                        let full = serde_json::to_value(info)?;
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
                        session_id: None,
                        terminal: None,
                        cgroup: None,
                        container_id: None,
                        integrity_level: None,
                        parent_name: None,
                        child_pids: Vec::new(),
                        modules: Vec::new(),
                        deleted_executable: false,
                        command_line_full: None,
                        environment: Vec::new(),
                        working_directory: None,
                        priority: None,
                        nice: None,
                        threads: None,
                        handles: None,
                        gdi_handles: None,
                        user_handles: None,
                        io_read_bytes: None,
                        io_write_bytes: None,
                        io_other_bytes: None,
                        page_faults: None,
                        context_switches: None,
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

/// Build process tree from flat process list
pub fn detect_process_hollowing(processes: &[ProcessInfo]) -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    for proc in processes {
        let executable = proc.executable_path.as_deref().unwrap_or("");
        let deleted = proc.deleted_executable;
        let has_memory_only_module = proc.modules.iter().any(|module| {
            module.path.starts_with('[')
                || module.path.contains("memfd")
                || module.path.contains("anon")
                || module.path.is_empty()
        });
        let name_lower = proc.name.to_ascii_lowercase();
        let suspicious = deleted
            || has_memory_only_module
            || (name_lower.contains("rundll32")
                && !executable.is_empty()
                && !executable.contains("rundll32"));

        if suspicious {
            findings.push(serde_json::json!({
                "indicator": "process.hollowing",
                "pid": proc.pid,
                "process": proc.name,
                "executable_path": executable,
                "deleted_executable": deleted,
                "memory_only_modules": has_memory_only_module,
                "reason": if deleted {
                    "process executable is deleted while still mapped"
                } else if has_memory_only_module {
                    "process contains executable memory regions without a stable file-backed mapping"
                } else {
                    "process image path does not align with its observed execution behavior"
                },
                "confidence": if deleted { 0.9 } else { 0.74 },
            }));
        }
    }
    findings
}

pub fn build_process_tree(processes: &[ProcessInfo]) -> Vec<ProcessTreeNode> {
    let mut pid_to_node: std::collections::HashMap<i32, ProcessTreeNode> =
        std::collections::HashMap::new();
    let mut children_map: std::collections::HashMap<i32, Vec<i32>> =
        std::collections::HashMap::new();
    let mut root_pids = Vec::new();

    // Create nodes for all processes
    for proc in processes {
        pid_to_node.insert(
            proc.pid,
            ProcessTreeNode {
                process: proc.clone(),
                children: Vec::new(),
            },
        );
    }

    // Build parent-child relationships
    for proc in processes {
        if let Some(ppid) = proc.ppid {
            children_map.entry(ppid).or_default().push(proc.pid);
        } else {
            root_pids.push(proc.pid);
        }
    }

    // Build tree by attaching children to parents
    // Collect children first to avoid borrow issues
    let mut children_to_move: Vec<(i32, ProcessTreeNode)> = Vec::new();
    for (ppid, child_pids) in children_map {
        for child_pid in child_pids {
            if let Some(child) = pid_to_node.remove(&child_pid) {
                children_to_move.push((ppid, child));
            }
        }
    }
    // Now attach children to parents
    for (ppid, child) in children_to_move {
        if let Some(parent) = pid_to_node.get_mut(&ppid) {
            parent.children.push(child);
        }
    }

    // Collect roots
    root_pids
        .into_iter()
        .filter_map(|pid| pid_to_node.remove(&pid))
        .collect()
}

/// Collect loaded modules (DLLs/shared libraries) for a process - Linux
#[cfg(target_os = "linux")]
fn collect_modules_linux(pid: i32) -> Vec<ProcessModule> {
    use std::fs;
    let mut modules = Vec::new();

    if let Ok(maps) = fs::read_to_string(format!("/proc/{}/maps", pid)) {
        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let path = parts[5].to_string();
                if path.starts_with('/') || path.starts_with('[') {
                    let addr_parts: Vec<&str> = parts[0].split('-').collect();
                    if addr_parts.len() == 2 {
                        let perms = parts[1];
                        // Only include executable mappings (likely code)
                        if perms.contains('x') {
                            modules.push(ProcessModule {
                                name: path.split('/').last().unwrap_or(&path).to_string(),
                                path: path.clone(),
                                base_address: addr_parts[0].to_string(),
                                size_bytes: u64::from_str_radix(addr_parts[1], 16).unwrap_or(0)
                                    - u64::from_str_radix(addr_parts[0], 16).unwrap_or(0),
                                version: None,
                                description: None,
                                company: None,
                                signed: None,
                                signature_date: None,
                            });
                        }
                    }
                }
            }
        }
    }
    modules
}

/// Collect loaded modules (DLLs) for a process - Windows
#[cfg(target_os = "windows")]
fn collect_modules_windows(pid: i32) -> Vec<ProcessModule> {
    use std::process::Command;
    let mut modules = Vec::new();

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"Get-Process -Id {} | Select-Object -ExpandProperty Modules | ForEach-Object {{{{ [PSCustomObject]@{{ ModuleName=$_.ModuleName; FileName=$_.FileName; BaseAddress=$_.BaseAddress.ToString('X'); ModuleMemorySize=$_.ModuleMemorySize; FileVersionInfo=if($_.FileVersionInfo){{{{@{{FileVersion=$_.FileVersionInfo.FileVersion; FileDescription=$_.FileVersionInfo.FileDescription; CompanyName=$_.FileVersionInfo.CompanyName}}}} else {{{{$null}}}} }} }} }} | ConvertTo-Json -Compress"#,
                pid
            ),
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
                let fvi = item.get("FileVersionInfo");
                modules.push(ProcessModule {
                    name: item
                        .get("ModuleName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    path: item
                        .get("FileName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    base_address: item
                        .get("BaseAddress")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size_bytes: item
                        .get("ModuleMemorySize")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    version: fvi
                        .and_then(|v| v.get("FileVersion"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    description: fvi
                        .and_then(|v| v.get("FileDescription"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    company: fvi
                        .and_then(|v| v.get("CompanyName"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    signed: None, // Would need authenticode verification
                    signature_date: None,
                });
            }
        }
    }
    modules
}

/// Check if process executable has been deleted (Linux)
#[cfg(target_os = "linux")]
fn is_executable_deleted(pid: i32) -> bool {
    use std::fs;
    // Check if /proc/<pid>/exe is a broken symlink
    if let Ok(target) = fs::read_link(format!("/proc/{}/exe", pid)) {
        let target_str = target.to_string_lossy();
        // If the target contains "(deleted)" or the file doesn't exist
        target_str.contains(" (deleted)") || !target.exists()
    } else {
        false
    }
}

/// Get process integrity level (Windows)
#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn get_integrity_level(pid: i32) -> Option<String> {
    use std::process::Command;
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(r#"(Get-Process -Id {}).IntegrityLevel"#, pid),
        ])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() && stdout != " " {
            return Some(stdout);
        }
    }
    None
}

/// Collect environment variables for a process - Linux
#[cfg(target_os = "linux")]
fn collect_environment_linux(pid: i32) -> Vec<String> {
    use std::fs;
    if let Ok(content) = fs::read_to_string(format!("/proc/{}/environ", pid)) {
        content
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

/// Collect environment variables for a process - Windows
#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn collect_environment_windows(_pid: i32) -> Vec<String> {
    // Would require WMI or process hacking - returning empty for now
    Vec::new()
}

/// Get working directory for a process - Windows
#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn get_working_directory_windows(pid: i32) -> Option<String> {
    use std::process::Command;
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"(Get-CimInstance Win32_Process -Filter "ProcessId={}" | Select-Object ExecutablePath).ExecutablePath | Split-Path"#, pid
            ),
        ])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return Some(stdout);
        }
    }
    None
}

/// Detect container ID for a process (Linux)
#[cfg(target_os = "linux")]
fn detect_container_id(pid: i32) -> Option<String> {
    use std::fs;
    if let Ok(cgroup) = fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        // Look for container IDs in cgroup path
        for line in cgroup.lines() {
            if line.contains("docker") || line.contains("containerd") || line.contains("kubepods") {
                // Extract container ID from path like /docker/abc123... or /kubepods/.../abc123...
                let parts: Vec<&str> = line.split('/').collect();
                for part in parts {
                    if part.len() >= 12 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(part.to_string());
                    }
                }
            }
        }
    }
    None
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

/// Collector functions matching capability registry
pub fn collect_process_tree() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let processes = enumerate_processes(&[])?;
    let process_infos: Vec<ProcessInfo> = processes
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();
    let tree = build_process_tree(&process_infos);
    Ok(serde_json::to_value(tree)?
        .as_array()
        .unwrap_or(&Vec::new())
        .to_vec())
}

pub fn collect_process_modules(
    pid: Option<i32>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        if let Some(pid) = pid {
            let modules = collect_modules_linux(pid);
            Ok(modules
                .into_iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?)
        } else {
            Ok(Vec::new())
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(pid) = pid {
            let modules = collect_modules_windows(pid);
            Ok(modules
                .into_iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?)
        } else {
            Ok(Vec::new())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

pub fn detect_deleted_executables() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let processes = enumerate_processes(&[])?;
        let deleted: Vec<_> = processes
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ProcessInfo>(v).ok())
            .filter(|p| p.deleted_executable)
            .map(|p| serde_json::to_value(p).unwrap())
            .collect();
        Ok(deleted)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}
