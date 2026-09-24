//! TraceForge Runtime — Forensic artifact carver
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
fn carve_prefetch(search_path: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
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
fn carve_lnk_files(
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
fn carve_recycle_bin(
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
fn carve_shell_history(
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

/// Collect cron job entries from system and user crontabs
fn carve_cron_entries(
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
fn carve_systemd_units(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_artifacts_all() {
        // Should return without panicking even with no files
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
        // Each entry should have artifact_type field
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
