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
pub fn carve_prefetch(search_path: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
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
            for entry in std::fs::read_dir(&path).unwrap_or_else(|_| std::fs::read_dir("/").unwrap()) {
                let Some(entry) = entry.ok() else { continue };
                let p = entry.path();
                if p.is_file() {
                    let content = std::fs::read_to_string(&p).unwrap_or_default();
                    let suspicious = content.lines().any(|line| {
                        let lower = line.to_lowercase();
                        suspicious_patterns.iter().any(|pattern| lower.contains(pattern))
                    });
                    results.push(serde_json::json!({
                        "collector": "autostart",
                        "artifact_type": "autostart_entry",
                        "path": p.display().to_string(),
                        "suspicious": suspicious,
                        "content_sample": content.lines().take(20).collect::<Vec<_>>(),
                    }));
                }
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let suspicious = content.lines().any(|line| {
            let lower = line.to_lowercase();
            suspicious_patterns.iter().any(|pattern| lower.contains(pattern))
        });
        results.push(serde_json::json!({
            "collector": "autostart",
            "artifact_type": "autostart_entry",
            "path": path.display().to_string(),
            "suspicious": suspicious,
            "content_sample": content.lines().take(20).collect::<Vec<_>>(),
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

/// Windows Amcache.hve parser
pub fn carve_amcache(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "amcache",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Amcache.hve is typically at C:\Windows\AppCompat\Programs\Amcache.hve
        let amcache_path = Path::new(r"C:\Windows\AppCompat\Programs\Amcache.hve");
        if amcache_path.exists() {
            // TODO: Implement actual Amcache parsing
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "amcache",
                "status": "not_implemented",
                "note": "Amcache parsing not yet implemented",
                "path": amcache_path.display().to_string(),
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "amcache",
        "status": "platform_note",
        "note": "Amcache is Windows-specific",
    })])
}

/// Windows SRUM database parser
pub fn carve_srum(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "srum",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // SRUM is typically at C:\Windows\System32\sru\SRUDB.dat
        let srum_path = Path::new(r"C:\Windows\System32\sru\SRUDB.dat");
        if srum_path.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "srum",
                "status": "not_implemented",
                "note": "SRUM parsing not yet implemented",
                "path": srum_path.display().to_string(),
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "srum",
        "status": "platform_note",
        "note": "SRUM is Windows-specific",
    })])
}

/// Windows Jump Lists parser
pub fn carve_jumplists(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "jumplists",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Jump Lists are typically at C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
        let jumplist_dir = Path::new(r"C:\Users");
        if jumplist_dir.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "jumplists",
                "status": "not_implemented",
                "note": "Jump Lists parsing not yet implemented",
                "path": jumplist_dir.display().to_string(),
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "jumplists",
        "status": "platform_note",
        "note": "Jump Lists are Windows-specific",
    })])
}

/// Windows Shellbags parser
pub fn carve_shellbags(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "shellbags",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Shellbags are in registry: HKCU\Software\Microsoft\Windows\Shell\Bags
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "shellbags",
            "status": "not_implemented",
            "note": "Shellbags parsing not yet implemented (requires registry access)",
        })]);
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "shellbags",
        "status": "platform_note",
        "note": "Shellbags are Windows-specific",
    })])
}

/// Windows ETW logs collector
pub fn collect_etw_logs(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "etw",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "etw",
            "status": "not_implemented",
            "note": "ETW log collection not yet implemented",
        })]);
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "etw",
        "status": "platform_note",
        "note": "ETW is Windows-specific",
    })])
}

/// Windows Event Logs collector
pub fn carve_event_logs(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "event_logs",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Event logs are typically at C:\Windows\System32\winevt\Logs\
        let evt_dir = Path::new(r"C:\Windows\System32\winevt\Logs");
        if evt_dir.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "event_logs",
                "status": "not_implemented",
                "note": "Event log parsing not yet implemented",
                "path": evt_dir.display().to_string(),
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "event_logs",
        "status": "platform_note",
        "note": "Event logs are Windows-specific",
    })])
}

/// Windows Recent Files collector
pub fn carve_recent_files(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "recent_files",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Recent files are in C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
        let recent_dir = Path::new(r"C:\Users");
        if recent_dir.exists() {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "recent_files",
                "status": "not_implemented",
                "note": "Recent files parsing not yet implemented",
                "path": recent_dir.display().to_string(),
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "recent_files",
        "status": "platform_note",
        "note": "Recent files are Windows-specific",
    })])
}

/// Linux Container artifacts collector
pub fn carve_container_artifacts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "container",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "linux")]
    {
        // Check for Docker, containerd, podman artifacts
        let docker_path = Path::new("/var/lib/docker");
        let containerd_path = Path::new("/var/lib/containerd");
        let podman_path = Path::new("/var/lib/containers");
        
        let mut found = false;
        if docker_path.exists() || containerd_path.exists() || podman_path.exists() {
            found = true;
        }
        
        if found {
            return Ok(vec![serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "container",
                "status": "not_implemented",
                "note": "Container artifact parsing not yet implemented",
                "paths": vec![
                    docker_path.display().to_string(),
                    containerd_path.display().to_string(),
                    podman_path.display().to_string(),
                ],
            })]);
        }
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "container",
        "status": "platform_note",
        "note": "Container artifacts are Linux-specific",
    })])
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
            for entry in std::fs::read_dir(home_dir).unwrap_or_else(|_| std::fs::read_dir("/").unwrap()) {
                if let Ok(entry) = entry {
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
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "ssh_config",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
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
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "powershell_script",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Find .ps1 files
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.extension().and_then(|e| e.to_str()) == Some("ps1") {
                let content = std::fs::read_to_string(&entry).unwrap_or_default();
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                
                // Simple analysis
                let suspicious = content.to_lowercase().contains("invoke-expression")
                    || content.to_lowercase().contains("iex")
                    || content.to_lowercase().contains("downloadstring")
                    || content.to_lowercase().contains("bypass")
                    || content.to_lowercase().contains("encodedcommand")
                    || content.to_lowercase().contains("amsi");
                
                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "powershell_script".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "suspicious_patterns": if suspicious { vec!["potential_obfuscation", "amsi_bypass", "download_execute"] } else { vec![] },
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("PowerShell script contains suspicious patterns".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "powershell_script",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "powershell_script",
        "status": "platform_note",
        "note": "PowerShell script analysis is Windows-specific",
    })])
}

/// WMI/VBScript analyzer
pub fn analyze_wmi_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "wmi_script",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "windows")]
    {
        // Find .vbs files
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.extension().and_then(|e| e.to_str()) == Some("vbs") {
                let content = std::fs::read_to_string(&entry).unwrap_or_default();
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                
                let suspicious = content.to_lowercase().contains("wscript.shell")
                    || content.to_lowercase().contains("wmi")
                    || content.to_lowercase().contains("execquery")
                    || content.to_lowercase().contains("createobject");
                
                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "wmi_script".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "suspicious_patterns": if suspicious { vec!["wmi_query", "shell_execution"] } else { vec![] },
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("VBScript contains suspicious WMI/shell patterns".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "wmi_script",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "wmi_script",
        "status": "platform_note",
        "note": "WMI/VBScript analysis is Windows-specific",
    })])
}

/// Shell script analyzer
pub fn analyze_shell_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "shell_script",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    #[cfg(target_os = "linux")]
    {
        // Find .sh files
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.extension().and_then(|e| e.to_str()) == Some("sh") {
                let content = std::fs::read_to_string(&entry).unwrap_or_default();
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                
                let suspicious = content.to_lowercase().contains("base64")
                    || content.to_lowercase().contains("wget")
                    || content.to_lowercase().contains("curl")
                    || content.to_lowercase().contains("nc ")
                    || content.to_lowercase().contains("/dev/tcp")
                    || content.to_lowercase().contains("chmod +x")
                    || content.to_lowercase().contains("python -c")
                    || content.to_lowercase().contains("perl -e")
                    || content.to_lowercase().contains("bash -i");
                
                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "shell_script".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "suspicious_patterns": if suspicious { vec!["obfuscation", "download_execute", "reverse_shell"] } else { vec![] },
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("Shell script contains suspicious patterns".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "shell_script",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "shell_script",
            "status": "platform_note",
            "note": "Shell script analysis is Linux-specific",
        })])
    }
}

/// Python script analyzer
pub fn analyze_python_scripts(
    search_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(search_path);
    if !path.exists() {
        return Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "python_script",
            "status": "path_not_found",
            "search_path": search_path,
        })]);
    }
    {
        // Find .py files
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            if entry.extension().and_then(|e| e.to_str()) == Some("py") {
                let content = std::fs::read_to_string(&entry).unwrap_or_default();
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                
                let suspicious = content.to_lowercase().contains("base64")
                    || content.to_lowercase().contains("exec(")
                    || content.to_lowercase().contains("eval(")
                    || content.to_lowercase().contains("subprocess")
                    || content.to_lowercase().contains("os.system")
                    || content.to_lowercase().contains("socket")
                    || content.to_lowercase().contains("requests")
                    || content.to_lowercase().contains("urllib");
                
                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "python_script".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "suspicious_patterns": if suspicious { vec!["code_execution", "network_access", "obfuscation"] } else { vec![] },
                    }),
                    suspicious,
                    suspicious_reason: if suspicious {
                        Some("Python script contains suspicious patterns".to_string())
                    } else {
                        None
                    },
                })?);
            }
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "python_script",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
    }
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
    #[cfg(target_os = "windows")]
    {
        // Find .exe, .dll files
        let mut results = Vec::new();
        for entry in walkdir_max_depth(path, 3) {
            let ext = entry.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "exe" || ext == "dll" || ext == "sys" {
                let sha256 = sha256_file(&entry);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                
                results.push(serde_json::to_value(CarvedArtifact {
                    artifact_type: "pe_metadata".to_string(),
                    path: entry.display().to_string(),
                    size_bytes: size,
                    sha256,
                    modified_at: modified_at(&entry),
                    metadata: serde_json::json!({
                        "file_type": ext,
                        "note": "PE parsing not fully implemented",
                    }),
                    suspicious: false,
                    suspicious_reason: None,
                })?);
            }
        }
        
        if results.is_empty() {
            results.push(serde_json::json!({
                "collector": "artifacts",
                "artifact_type": "pe_metadata",
                "status": "no_artifacts_found",
            }));
        }
        
        return Ok(results);
    }
    Ok(vec![serde_json::json!({
        "collector": "artifacts",
        "artifact_type": "pe_metadata",
        "status": "platform_note",
        "note": "PE metadata parsing is Windows-specific",
    })])
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
    #[cfg(target_os = "linux")]
    {
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
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "artifacts",
            "artifact_type": "elf_metadata",
            "status": "platform_note",
            "note": "ELF metadata parsing is Linux-specific",
        })])
    }
}

fn read_elf_uint(bytes: &[u8], offset: usize, width: usize, little_endian: bool) -> Result<u64, String> {
    let end = offset.checked_add(width).ok_or_else(|| "ELF field offset overflow".to_string())?;
    let field = bytes.get(offset..end).ok_or_else(|| format!("truncated ELF field at offset {}", offset))?;
    let value = if little_endian {
        field.iter().enumerate().fold(0u64, |value, (index, byte)| value | ((*byte as u64) << (index * 8)))
    } else {
        field.iter().fold(0u64, |value, byte| (value << 8) | *byte as u64)
    };
    Ok(value)
}

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
        return Err(format!("unsupported ELF identification version {}", bytes[6]));
    }

    let header_size = if class == 32 { 52 } else { 64 };
    if bytes.len() < header_size {
        return Err(format!("truncated ELF{} header", class));
    }
    let file_type = read_elf_uint(bytes, 16, 2, little_endian)? as u16;
    let machine = read_elf_uint(bytes, 18, 2, little_endian)? as u16;
    let (entry, program_offset, section_offset, flags_offset, header_size_offset,
        program_entry_size_offset, program_count_offset, section_entry_size_offset,
        section_count_offset, section_names_index_offset) = if class == 32 {
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
    let program_entry_size = read_elf_uint(bytes, program_entry_size_offset, 2, little_endian)? as usize;
    let program_count = read_elf_uint(bytes, program_count_offset, 2, little_endian)? as usize;
    let section_entry_size = read_elf_uint(bytes, section_entry_size_offset, 2, little_endian)? as usize;
    let section_count = read_elf_uint(bytes, section_count_offset, 2, little_endian)? as usize;
    let section_names_index = read_elf_uint(bytes, section_names_index_offset, 2, little_endian)? as usize;

    if declared_header_size < header_size as u64 {
        return Err(format!("invalid ELF header size {}", declared_header_size));
    }
    if program_count > 0 && program_entry_size < if class == 32 { 32 } else { 56 } {
        return Err(format!("invalid program header entry size {}", program_entry_size));
    }
    if section_count > 0 && section_entry_size < if class == 32 { 40 } else { 64 } {
        return Err(format!("invalid section header entry size {}", section_entry_size));
    }
    if program_count > 65_536 || section_count > 65_536 {
        return Err("ELF header table entry count exceeds parser limit".to_string());
    }

    let table_end = |offset: usize, count: usize, stride: usize| -> Result<usize, String> {
        let length = count.checked_mul(stride).ok_or_else(|| "ELF table size overflow".to_string())?;
        let end = offset.checked_add(length).ok_or_else(|| "ELF table offset overflow".to_string())?;
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
            (read_elf_uint(bytes, base + 4, 4, little_endian)?, read_elf_uint(bytes, base + 16, 4, little_endian)?)
        } else {
            (read_elf_uint(bytes, base + 8, 8, little_endian)?, read_elf_uint(bytes, base + 32, 8, little_endian)?)
        };
        let segment_name = match segment_type {
            0 => "NULL", 1 => "LOAD", 2 => "DYNAMIC", 3 => "INTERP", 4 => "NOTE",
            5 => "SHLIB", 6 => "PHDR", 7 => "TLS", _ => "OTHER",
        };
        if segment_type == 3 {
            let start = usize::try_from(file_offset).map_err(|_| "ELF interpreter offset is too large")?;
            let length = usize::try_from(file_size).map_err(|_| "ELF interpreter size is too large")?;
            let end = start.checked_add(length).ok_or_else(|| "ELF interpreter range overflow".to_string())?;
            let value = bytes.get(start..end).ok_or_else(|| "truncated ELF interpreter segment".to_string())?;
            interpreter = Some(String::from_utf8_lossy(value).trim_end_matches('\0').to_string());
        }
        program_headers.push(serde_json::json!({
            "type": segment_name,
            "type_id": segment_type,
            "offset": file_offset,
            "file_size": file_size,
        }));
    }

    let section_name_offset = if class == 32 { 0 } else { 0 };
    let section_type_offset = 4;
    let section_file_offset = if class == 32 { 16 } else { 24 };
    let section_size_offset = if class == 32 { 20 } else { 32 };
    let section_word_width = if class == 32 { 4 } else { 8 };
    let section_names = if section_count > 0 && section_names_index < section_count {
        let names_header = section_offset + section_names_index * section_entry_size;
        let names_file_offset = read_elf_uint(bytes, names_header + section_file_offset, section_word_width, little_endian)? as usize;
        let names_size = read_elf_uint(bytes, names_header + section_size_offset, section_word_width, little_endian)? as usize;
        let names_end = names_file_offset.checked_add(names_size).ok_or_else(|| "ELF section-name table range overflow".to_string())?;
        Some(bytes.get(names_file_offset..names_end).ok_or_else(|| "truncated ELF section-name string table".to_string())?)
    } else {
        None
    };

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = section_offset + index * section_entry_size;
        let name_index = read_elf_uint(bytes, base + section_name_offset, 4, little_endian)? as usize;
        let section_type = read_elf_uint(bytes, base + section_type_offset, 4, little_endian)? as u32;
        let file_offset = read_elf_uint(bytes, base + section_file_offset, section_word_width, little_endian)?;
        let size = read_elf_uint(bytes, base + section_size_offset, section_word_width, little_endian)?;
        let name = section_names.and_then(|table| table.get(name_index..)).map(|remaining| {
            let end = remaining.iter().position(|byte| *byte == 0).unwrap_or(remaining.len());
            String::from_utf8_lossy(&remaining[..end]).into_owned()
        }).unwrap_or_default();
        let type_name = match section_type {
            0 => "NULL", 1 => "PROGBITS", 2 => "SYMTAB", 3 => "STRTAB", 4 => "RELA",
            5 => "HASH", 6 => "DYNAMIC", 7 => "NOTE", 8 => "NOBITS", 9 => "REL",
            11 => "DYNSYM", _ => "OTHER",
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
        0 => "none", 1 => "relocatable", 2 => "executable", 3 => "shared_object", 4 => "core", _ => "processor_specific",
    };
    let machine_name = match machine {
        3 => "x86", 40 => "ARM", 62 => "x86_64", 183 => "AArch64", 243 => "RISC-V", _ => "unknown",
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
        
        return Ok(results);
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
                        Some(format!("High entropy ({:.2}) suggests packing or encryption", entropy))
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
        
        return Ok(results);
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
        
        return Ok(results);
    }
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
                if ext == "exe" || ext == "dll" || ext == "so" || ext == "bin" {
                    let bytes = std::fs::read(&entry).unwrap_or_default();
                    if bytes.is_empty() {
                        continue;
                    }
                    
                    // Calculate entropy
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
                    
                    let suspicious = entropy > 7.0;
                    
                    results.push(serde_json::to_value(CarvedArtifact {
                        artifact_type: "binary_anomalies".to_string(),
                        path: entry.display().to_string(),
                        size_bytes: size,
                        sha256,
                        modified_at: modified_at(&entry),
                        metadata: serde_json::json!({
                            "entropy": entropy,
                            "file_type": ext,
                            "anomalies": if suspicious { vec!["high_entropy"] } else { vec![] },
                        }),
                        suspicious,
                        suspicious_reason: if suspicious {
                            Some(format!("Binary has high entropy ({:.2})", entropy))
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
        
        return Ok(results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_elf_metadata_reads_real_executable() {
        let executable = std::env::current_exe().unwrap();
        let records = parse_elf_metadata(executable.to_str().unwrap()).unwrap();
        let metadata = records[0].get("metadata").expect("ELF metadata record");

        assert_eq!(metadata["file_type"], "elf");
        assert!(metadata["class"].as_u64().is_some());
        assert!(metadata["machine"].as_str().is_some());
        assert!(metadata["sections"].as_array().is_some_and(|sections| !sections.is_empty()));
    }

    #[test]
    fn test_parse_elf_metadata_rejects_truncated_input() {
        let error = parse_elf_bytes(b"\x7fELF").unwrap_err();
        assert!(error.contains("truncated"));
    }

    #[test]
    fn test_collect_autostart_entries_reads_real_paths() {
        let tmp = std::env::temp_dir().join("jockey-autostart-tests");
        let _ = std::fs::create_dir_all(&tmp);
        let startup = tmp.join(".bashrc");
        std::fs::write(&startup, "export PATH=$PATH:/tmp\n").unwrap();

        let result = collect_autostart_entries(Some(tmp.to_str().unwrap()));
        assert!(result.is_ok(), "autostart collection should succeed");
        let records = result.unwrap();
        assert!(!records.is_empty());
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

