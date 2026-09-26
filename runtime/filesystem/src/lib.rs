//! jockey Runtime - Filesystem enumeration and hashing

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub is_directory: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub permissions: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub modified_time: chrono::DateTime<chrono::Utc>,
    pub accessed_time: chrono::DateTime<chrono::Utc>,
    pub created_time: Option<chrono::DateTime<chrono::Utc>>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

pub fn enumerate_files(
    root_path: &str,
    recursive: bool,
    hash_algorithm: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = Path::new(root_path);
    let mut results = Vec::new();

    let walker = if recursive {
        WalkDir::new(path).into_iter()
    } else {
        WalkDir::new(path).max_depth(1).into_iter()
    };

    for entry in walker.filter_map(|e| e.ok()) {
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let file_type = metadata.file_type();
        let is_dir = file_type.is_dir();
        let is_symlink = file_type.is_symlink();

        let symlink_target = if is_symlink {
            fs::read_link(entry.path())
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let mut info = FileInfo {
            path: entry.path().to_string_lossy().to_string(),
            name: entry.file_name().to_string_lossy().to_string(),
            size_bytes: metadata.len(),
            is_directory: is_dir,
            is_symlink,
            symlink_target,
            permissions: file_permissions(&metadata),
            owner_uid: file_owner_uid(&metadata),
            owner_gid: file_owner_gid(&metadata),
            modified_time: chrono::DateTime::from(metadata.modified()?),
            accessed_time: chrono::DateTime::from(metadata.accessed()?),
            created_time: metadata.created().ok().map(chrono::DateTime::from),
            sha256: None,
            sha1: None,
            md5: None,
        };

        // Calculate hashes for files (not directories)
        if !is_dir && hash_algorithm != "none" {
            match hash_algorithm {
                "sha256" => {
                    if let Ok(hash) = calculate_file_hash(entry.path(), "sha256") {
                        info.sha256 = Some(hash);
                    }
                }
                "sha1" => {
                    if let Ok(hash) = calculate_file_hash(entry.path(), "sha1") {
                        info.sha1 = Some(hash);
                    }
                }
                "md5" => {
                    if let Ok(hash) = calculate_file_hash(entry.path(), "md5") {
                        info.md5 = Some(hash);
                    }
                }
                _ => {}
            }
        }

        results.push(serde_json::to_value(info)?);
    }

    Ok(results)
}

fn calculate_file_hash(path: &Path, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hasher = match algorithm {
        "sha256" => HashState::Sha256(Sha256::new()),
        "sha1" => HashState::Sha1(Sha1::new()),
        "md5" => HashState::Md5(Md5::new()),
        _ => return Err(format!("Unsupported hash algorithm: {algorithm}").into()),
    };
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize())
}

enum HashState {
    Sha256(Sha256),
    Sha1(Sha1),
    Md5(Md5),
}

impl HashState {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha1(hasher) => hasher.update(bytes),
            Self::Md5(hasher) => hasher.update(bytes),
        }
    }

    fn finalize(self) -> String {
        match self {
            Self::Sha256(hasher) => format!("{:x}", hasher.finalize()),
            Self::Sha1(hasher) => format!("{:x}", hasher.finalize()),
            Self::Md5(hasher) => format!("{:x}", hasher.finalize()),
        }
    }
}

pub fn calculate_hash(path: &str, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(path);
    match algorithm {
        "sha256" | "sha1" | "md5" => calculate_file_hash(path, algorithm),
        _ => Err("Unsupported hash algorithm".into()),
    }
}

#[cfg(unix)]
fn file_permissions(metadata: &fs::Metadata) -> String {
    format!("{:o}", metadata.mode() & 0o777)
}

#[cfg(not(unix))]
fn file_permissions(metadata: &fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "readonly".to_string()
    } else {
        "writable".to_string()
    }
}

#[cfg(unix)]
fn file_owner_uid(metadata: &fs::Metadata) -> u32 {
    metadata.uid()
}

#[cfg(not(unix))]
fn file_owner_uid(_: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn file_owner_gid(metadata: &fs::Metadata) -> u32 {
    metadata.gid()
}

#[cfg(not(unix))]
fn file_owner_gid(_: &fs::Metadata) -> u32 {
    0
}

/// Alternate Data Streams (ADS) detector
pub fn detect_alternate_data_streams(
    target_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let p = if target_path == "." || target_path.is_empty() {
        std::env::current_dir()?.display().to_string()
    } else {
        target_path.to_string()
    };

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    r#"Get-Item -LiteralPath '{}' -Stream * -ErrorAction SilentlyContinue | Select-Object Stream, Length | ConvertTo-Json -Compress"#,
                    p.replace('\'', "''")
                ),
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
                        let stream_name = item.get("Stream").and_then(|v| v.as_str()).unwrap_or("");
                        let length = item.get("Length").and_then(|v| v.as_u64()).unwrap_or(0);
                        if stream_name != ":$DATA" {
                            results.push(serde_json::json!({
                                "collector": "filesystem",
                                "artifact_type": "alternate_data_stream",
                                "target_path": p,
                                "stream_name": stream_name,
                                "size_bytes": length,
                                "is_zone_identifier": stream_name.contains("Zone.Identifier"),
                                "status": "success",
                            }));
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("getfattr").args(["-d", "-m", "-", &p]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some((attr, val)) = line.split_once('=') {
                        results.push(serde_json::json!({
                            "collector": "filesystem",
                            "artifact_type": "extended_attribute",
                            "target_path": p,
                            "attribute": attr.trim(),
                            "value": val.trim(),
                            "status": "success",
                        }));
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "filesystem",
            "artifact_type": "alternate_data_stream",
            "target_path": p,
            "status": "no_artifacts_found",
            "note": "No alternate data streams or extended attributes detected on target path",
        }));
    }

    Ok(results)
}

/// Enumerate mount points / mounted filesystems
pub fn enumerate_mounts() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                r#"Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining, DriveType | ConvertTo-Json -Compress"#,
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
                        let drive = item.get("DriveLetter").and_then(|v| v.as_str()).unwrap_or("");
                        let label = item.get("FileSystemLabel").and_then(|v| v.as_str()).unwrap_or("");
                        let fs_type = item.get("FileSystem").and_then(|v| v.as_str()).unwrap_or("");
                        let size = item.get("Size").and_then(|v| v.as_u64()).unwrap_or(0);
                        let free = item.get("SizeRemaining").and_then(|v| v.as_u64()).unwrap_or(0);
                        results.push(serde_json::json!({
                            "collector": "filesystem",
                            "artifact_type": "mount_point",
                            "mount_point": if drive.is_empty() { String::new() } else { format!("{}:\\", drive) },
                            "device": drive,
                            "filesystem": fs_type,
                            "label": label,
                            "size_bytes": size,
                            "free_bytes": free,
                            "status": "success",
                        }));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    results.push(serde_json::json!({
                        "collector": "filesystem",
                        "artifact_type": "mount_point",
                        "device": parts[0],
                        "mount_point": parts[1],
                        "filesystem": parts[2],
                        "options": parts[3],
                        "status": "success",
                    }));
                }
            }
        }
    }

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "filesystem",
            "artifact_type": "mount_point",
            "status": "no_artifacts_found",
        }));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::calculate_hash;
    use std::fs;

    #[test]
    fn calculates_supported_hash_algorithms() {
        let path = std::env::temp_dir().join(format!("jockey-hash-{}.txt", std::process::id()));
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            calculate_hash(path.to_str().unwrap(), "sha256").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            calculate_hash(path.to_str().unwrap(), "sha1").unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            calculate_hash(path.to_str().unwrap(), "md5").unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );

        fs::remove_file(path).unwrap();
    }
}
