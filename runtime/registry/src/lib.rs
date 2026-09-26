//! jockey Runtime — Registry / sysctl forensic collector
//!
//! On Windows: reads real registry hives via `winreg`.
//! On Linux: enumerates `/proc/sys/**` kernel parameters and loaded modules
//!           as a structural equivalent (Linux has no registry, but sysctl
//!           parameters carry equivalent configuration evidence).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Hive / root path (e.g. "HKLM\\SOFTWARE\\..." on Windows, "/proc/sys/kernel" on Linux)
    pub hive: String,
    /// Full key path
    pub key_path: String,
    /// Value name
    pub value_name: String,
    /// Value data as string representation
    pub value_data: String,
    /// Value type (REG_SZ, REG_DWORD, sysctl_string, sysctl_int, module, etc.)
    pub value_type: String,
    /// Whether this key/value is commonly abused for persistence
    pub persistence_risk: bool,
}

/// Known Windows autorun key paths (for persistence_risk detection)
#[allow(dead_code)]
static PERSISTENCE_KEYS: &[&str] = &[
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "SYSTEM\\CurrentControlSet\\Services",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
];

/// Enumerate registry entries under the given hive and key path.
///
/// - On Windows: reads real registry using `winreg`.
/// - On Linux: enumerates `/proc/sys/<mapped_path>` kernel parameters.
///
/// `hive_or_root`: e.g. `"HKLM"`, `"HKCU"`, or Linux sysctl root like `"kernel"`
/// `key_path`: subpath under the hive, e.g. `"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"`
pub fn enumerate_registry(
    hive_or_root: &str,
    key_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        enumerate_windows_registry(hive_or_root, key_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        enumerate_linux_sysctl(hive_or_root, key_path)
    }
}

/// Enumerate loaded kernel modules (Linux `lsmod` equivalent via `/proc/modules`)
pub fn enumerate_modules() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        enumerate_linux_modules()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![serde_json::json!({
            "collector": "modules",
            "status": "unavailable",
            "platform": std::env::consts::OS,
        })])
    }
}

#[cfg(target_os = "linux")]
fn enumerate_linux_modules() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open("/proc/modules")?;
    let reader = BufReader::new(file);
    let mut results = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let name = parts[0].to_string();
        let size = parts
            .get(1)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let used_by = parts
            .get(3)
            .map(|s| s.trim_end_matches(',').to_string())
            .unwrap_or_default();
        let state = parts.get(4).map(|s| s.to_string()).unwrap_or_default();
        let load_addr = parts
            .get(5)
            .map(|s| s.trim_start_matches("0x").to_string())
            .unwrap_or_default();

        results.push(serde_json::json!({
            "collector": "modules",
            "name": name,
            "size_bytes": size,
            "used_by": used_by,
            "state": state,
            "load_address": load_addr,
        }));
    }

    Ok(results)
}

#[cfg(not(target_os = "windows"))]
fn enumerate_linux_sysctl(
    _hive: &str,
    key_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    // Map the key_path to a /proc/sys directory.
    // Replace backslashes (Windows-style) and dots with forward slashes.
    let sysctl_path = format!(
        "/proc/sys/{}",
        key_path.replace(['\\', '.'], "/").to_lowercase()
    );

    let path = std::path::Path::new(&sysctl_path);
    let mut results = Vec::new();

    walk_sysctl(path, _hive, &mut results, 0)?;

    if results.is_empty() {
        results.push(serde_json::json!({
            "collector": "registry",
            "hive": _hive,
            "key_path": key_path,
            "sysctl_path": sysctl_path,
            "status": "no_entries",
            "note": "Path not found or no readable entries under this sysctl path",
        }));
    }

    Ok(results)
}

#[cfg(not(target_os = "windows"))]
fn walk_sysctl(
    dir: &std::path::Path,
    hive: &str,
    results: &mut Vec<serde_json::Value>,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if depth > 5 {
        return Ok(());
    } // Prevent infinite descent

    if !dir.exists() {
        return Ok(());
    }

    if dir.is_file() {
        // Read value
        let val = std::fs::read_to_string(dir).unwrap_or_default();
        let val = val.trim().to_string();
        let key_path = dir.to_string_lossy().to_string();

        results.push(serde_json::to_value(RegistryEntry {
            hive: hive.to_string(),
            key_path: key_path.clone(),
            value_name: dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            value_data: val,
            value_type: "sysctl_string".to_string(),
            persistence_risk: false,
        })?);
        return Ok(());
    }

    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            walk_sysctl(&entry.path(), hive, results, depth + 1)?;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn enumerate_windows_registry(
    hive: &str,
    key_path: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    use winreg::enums::*;
    use winreg::RegKey;

    let root = match hive.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => RegKey::predef(HKEY_LOCAL_MACHINE),
        "HKCU" | "HKEY_CURRENT_USER" => RegKey::predef(HKEY_CURRENT_USER),
        "HKCR" | "HKEY_CLASSES_ROOT" => RegKey::predef(HKEY_CLASSES_ROOT),
        "HKU" | "HKEY_USERS" => RegKey::predef(HKEY_USERS),
        _ => return Err(format!("Unknown hive: {}", hive).into()),
    };

    let key = root.open_subkey(key_path)?;
    let mut results = Vec::new();
    let is_persistence = PERSISTENCE_KEYS.iter().any(|p| key_path.contains(p));

    for (name, val) in key.enum_values().filter_map(|r| r.ok()) {
        let (data_str, type_str) = winreg_value_to_string(&val);
        results.push(serde_json::to_value(RegistryEntry {
            hive: hive.to_string(),
            key_path: key_path.to_string(),
            value_name: name,
            value_data: data_str,
            value_type: type_str,
            persistence_risk: is_persistence,
        })?);
    }

    // Recurse into subkeys (one level)
    for subkey_name in key.enum_keys().filter_map(|r| r.ok()) {
        let sub_path = format!("{}\\{}", key_path, subkey_name);
        if let Ok(subkey) = root.open_subkey(&sub_path) {
            let sub_is_persistence = PERSISTENCE_KEYS.iter().any(|p| sub_path.contains(p));
            for (name, val) in subkey.enum_values().filter_map(|r| r.ok()) {
                let (data_str, type_str) = winreg_value_to_string(&val);
                results.push(serde_json::to_value(RegistryEntry {
                    hive: hive.to_string(),
                    key_path: sub_path.clone(),
                    value_name: name,
                    value_data: data_str,
                    value_type: type_str,
                    persistence_risk: sub_is_persistence,
                })?);
            }
        }
    }

    Ok(results)
}

#[cfg(target_os = "windows")]
fn winreg_value_to_string(val: &winreg::RegValue) -> (String, String) {
    use winreg::enums::*;
    match val.vtype {
        REG_SZ | REG_EXPAND_SZ => {
            let s: String = val.to_string();
            (s, "REG_SZ".to_string())
        }
        REG_DWORD => {
            let bytes = &val.bytes;
            if bytes.len() >= 4 {
                let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                (n.to_string(), "REG_DWORD".to_string())
            } else {
                (format!("{:?}", bytes), "REG_DWORD".to_string())
            }
        }
        REG_QWORD => {
            let bytes = &val.bytes;
            if bytes.len() >= 8 {
                let n = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]));
                (n.to_string(), "REG_QWORD".to_string())
            } else {
                (format!("{:?}", bytes), "REG_QWORD".to_string())
            }
        }
        REG_BINARY => (format!("{:02x?}", val.bytes), "REG_BINARY".to_string()),
        REG_MULTI_SZ => (format!("{:?}", val.bytes), "REG_MULTI_SZ".to_string()),
        _ => (format!("{:?}", val.bytes), format!("{:?}", val.vtype)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_registry_does_not_panic() {
        #[cfg(target_os = "windows")]
        let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        #[cfg(not(target_os = "windows"))]
        let key = "kernel";

        let result = enumerate_registry("HKLM", key);
        assert!(
            result.is_ok(),
            "enumerate_registry failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_enumerate_modules() {
        let result = enumerate_modules();
        assert!(result.is_ok());
        let modules = result.unwrap();
        assert!(!modules.is_empty());
    }
}
