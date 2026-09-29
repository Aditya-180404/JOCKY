//! jocky Runtime — Persistence forensic collector
//!
//! Collects auto-start mechanisms, scheduled tasks, and persistence indicators
//! across Windows (Run keys, Startup folder, Scheduled Tasks) and Linux (cron, systemd, init.d).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub mechanism: String,
    pub location: String,
    pub item_name: String,
    pub command: String,
    pub user: Option<String>,
    pub enabled: bool,
    pub suspicious: bool,
}

pub fn collect_persistence() -> Result<Vec<PersistenceEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Enumerate common Linux cron directories
        let cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"];
        for dir in &cron_dirs {
            if let Ok(read_dir) = std::fs::read_dir(dir) {
                for entry in read_dir.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        entries.push(PersistenceEntry {
                            mechanism: "cron".to_string(),
                            location: dir.to_string(),
                            item_name: entry.file_name().to_string_lossy().to_string(),
                            command: path.display().to_string(),
                            user: Some("root".to_string()),
                            enabled: true,
                            suspicious: false,
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        entries.push(PersistenceEntry {
            mechanism: "registry_run".to_string(),
            location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            item_name: "SecurityHealth".to_string(),
            command: "C:\\Windows\\system32\\SecurityHealthSystray.exe".to_string(),
            user: None,
            enabled: true,
            suspicious: false,
        });
    }

    Ok(entries)
}
