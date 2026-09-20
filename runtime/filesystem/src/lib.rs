//! TraceForge Runtime - Filesystem enumeration and hashing

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
            fs::read_link(entry.path()).ok().map(|p| p.to_string_lossy().to_string())
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
            permissions: format!("{:o}", metadata.mode() & 0o777),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            modified_time: chrono::DateTime::from(std::time::SystemTime::from(metadata.modified()?)),
            accessed_time: chrono::DateTime::from(std::time::SystemTime::from(metadata.accessed()?)),
            created_time: metadata.created().ok().map(|t| chrono::DateTime::from(std::time::SystemTime::from(t))),
            sha256: None,
            sha1: None,
            md5: None,
        };

        // Calculate hashes for files (not directories)
        if !is_dir && hash_algorithm != "none" {
            match hash_algorithm {
                "sha256" => {
                    if let Ok(hash) = calculate_file_hash(entry.path(), &Sha256::new()) {
                        info.sha256 = Some(hash);
                    }
                }
                "sha1" => {
                    // Would need sha1 crate
                }
                "md5" => {
                    // Would need md5 crate
                }
                _ => {}
            }
        }

        results.push(serde_json::to_value(info)?);
    }

    Ok(results)
}

fn calculate_file_hash<D: Digest + Default>(path: &Path, _hasher: &D) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut hasher = D::default();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn calculate_hash(path: &str, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(path);
    match algorithm {
        "sha256" => calculate_file_hash(path, &Sha256::new()),
        _ => Err("Unsupported hash algorithm".into()),
    }
}