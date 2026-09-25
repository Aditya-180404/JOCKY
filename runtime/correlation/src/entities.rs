//! Canonical Forensic Entities (Section 11)
//!
//! Strongly-typed representations of forensic artifacts extracted from evidence records:
//! Host, User, Process, File, Network, Driver, Registry, and LogEvent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Host system entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostArtifact {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub architecture: String,
    pub identifiers: HashMap<String, String>,
}

/// User account entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserArtifact {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub privileges: Vec<String>,
}

/// Process entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessArtifact {
    pub pid: i64,
    pub ppid: Option<i64>,
    pub name: String,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub hash: Option<String>,
}

/// File entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileArtifact {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub accessed_at: Option<DateTime<Utc>>,
    pub owner: Option<String>,
}

/// Network connection entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConnectionArtifact {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub process: Option<String>,
    pub pid: Option<i64>,
    pub timestamp: DateTime<Utc>,
}

/// Driver entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriverArtifact {
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub signer: Option<String>,
    pub version: Option<String>,
    pub loaded_at: Option<DateTime<Utc>>,
}

/// Registry entity (primarily Windows)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryArtifact {
    pub key: String,
    pub value: Option<String>,
    pub data: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Log event entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEventArtifact {
    pub source: String,
    pub event_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub user: Option<String>,
    pub message: String,
}

/// Container collection of all extracted normalized forensic entities for an investigation.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizedEntities {
    pub hosts: Vec<HostArtifact>,
    pub users: Vec<UserArtifact>,
    pub processes: Vec<ProcessArtifact>,
    pub files: Vec<FileArtifact>,
    pub network_connections: Vec<NetworkConnectionArtifact>,
    pub drivers: Vec<DriverArtifact>,
    pub registry_keys: Vec<RegistryArtifact>,
    pub log_events: Vec<LogEventArtifact>,
}

impl NormalizedEntities {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract entities from a slice of generic JSON evidence records or bundles
    pub fn from_records(records: &[serde_json::Value], default_host: &str) -> Self {
        let mut result = Self::new();

        for record in records {
            let source = record.get("source").and_then(|s| s.as_str()).unwrap_or("");
            let event_type = record.get("event_type").and_then(|s| s.as_str()).unwrap_or("");

            match (source, event_type) {
                ("system", _) | (_, "system_info_collected") => {
                    let hostname = record.get("hostname").and_then(|v| v.as_str()).unwrap_or(default_host);
                    let os = record.get("os").and_then(|v| v.as_str()).unwrap_or("Linux");
                    let arch = record.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
                    result.hosts.push(HostArtifact {
                        id: format!("host-{}", hostname),
                        hostname: hostname.to_string(),
                        platform: os.to_string(),
                        os_version: os.to_string(),
                        architecture: arch.to_string(),
                        identifiers: HashMap::new(),
                    });
                }
                ("process", _) | ("processes", _) | (_, "process_observed") => {
                    let pid = record.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
                    let ppid = record.get("ppid").and_then(|v| v.as_i64());
                    let name = record.get("process_name")
                        .or_else(|| record.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let path = record.get("path")
                        .or_else(|| record.get("executable"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let cmdline = record.get("command_line")
                        .or_else(|| record.get("cmdline"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let user = record.get("user")
                        .or_else(|| record.get("username"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let hash = record.get("sha256")
                        .or_else(|| record.get("hash"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    result.processes.push(ProcessArtifact {
                        pid,
                        ppid,
                        name,
                        executable: path,
                        command_line: cmdline,
                        user,
                        start_time: Some(Utc::now()),
                        hash,
                    });
                }
                _ if source == "network" || event_type.starts_with("connection_") => {
                    let local = record.get("local_address")
                        .or_else(|| record.get("network_endpoint"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0.0:0");
                    let remote = record.get("remote_address").and_then(|v| v.as_str()).unwrap_or("0.0.0.0:0");
                    let proto = record.get("protocol").and_then(|v| v.as_str()).unwrap_or("TCP");
                    let state = record.get("state").and_then(|v| v.as_str()).unwrap_or("ESTABLISHED");
                    let pid = record.get("pid").or_else(|| record.get("process_id")).and_then(|v| v.as_i64());
                    let proc_name = record.get("process_name").and_then(|v| v.as_str()).map(|s| s.to_string());

                    let parse_port = |addr: &str| -> u16 {
                        addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0)
                    };

                    result.network_connections.push(NetworkConnectionArtifact {
                        local_address: local.to_string(),
                        local_port: parse_port(local),
                        remote_address: remote.to_string(),
                        remote_port: parse_port(remote),
                        protocol: proto.to_string(),
                        state: state.to_string(),
                        process: proc_name,
                        pid,
                        timestamp: Utc::now(),
                    });
                }
                ("filesystem", _) | ("files", _) | (_, "file_observed") => {
                    let path = record.get("path")
                        .or_else(|| record.get("file_path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("/unknown")
                        .to_string();
                    let size = record.get("size").or_else(|| record.get("size_bytes")).and_then(|v| v.as_u64()).unwrap_or(0);
                    let sha256 = record.get("sha256").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let owner = record.get("owner").or_else(|| record.get("user")).and_then(|v| v.as_str()).map(|s| s.to_string());

                    result.files.push(FileArtifact {
                        path,
                        size,
                        sha256,
                        created_at: Some(Utc::now()),
                        modified_at: Some(Utc::now()),
                        accessed_at: Some(Utc::now()),
                        owner,
                    });
                }
                _ => {}
            }
        }

        result
    }
}
