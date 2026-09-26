//! jockey Runtime - Cross-Source Correlation Engine
//!
//! Provides correlation of forensic observations across multiple evidence sources.
//! Builds relationships between entities (processes, files, network connections, etc.)
//! based on shared attributes like PIDs, paths, hashes, IP addresses, and timestamps.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use jockey_runtime_evidence::EvidenceCollector;
use jockey_runtime_timeline::{ForensicTimeline, TimelineEvent};

pub mod entities;
pub mod ioc;
pub mod rules;

pub use entities::{
    DriverArtifact, FileArtifact, HostArtifact, LogEventArtifact, NetworkConnectionArtifact,
    NormalizedEntities, ProcessArtifact, RegistryArtifact, UserArtifact,
};
pub use ioc::{Indicator, IndicatorMatch, IndicatorType, IocEngine, MatchType};
pub use rules::{JockeyRule, RuleCondition, RuleEngine, RuleFinding, RuleSeverity};

/// Represents a forensic entity that can be correlated across sources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Entity {
    Process { pid: i32, name: String },
    File { path: String, hash: Option<String> },
    NetworkConnection { local: String, remote: String },
    User { name: String },
    Host { name: String },
    Driver { name: String },
    RegistryKey { hive: String, path: String },
    MemoryRegion { base: u64, size: u64 },
    Artifact { artifact_type: String, path: String },
    LogEvent { source: String, message: String },
}

impl Entity {
    pub fn entity_type(&self) -> &'static str {
        match self {
            Entity::Process { .. } => "process",
            Entity::File { .. } => "file",
            Entity::NetworkConnection { .. } => "network_connection",
            Entity::User { .. } => "user",
            Entity::Host { .. } => "host",
            Entity::Driver { .. } => "driver",
            Entity::RegistryKey { .. } => "registry_key",
            Entity::MemoryRegion { .. } => "memory_region",
            Entity::Artifact { .. } => "artifact",
            Entity::LogEvent { .. } => "log_event",
        }
    }

    pub fn display(&self) -> String {
        match self {
            Entity::Process { pid, name } => format!("process:{}({})", name, pid),
            Entity::File { path, hash } => {
                if let Some(h) = hash {
                    format!("file:{}#{}", path, &h[..16.min(h.len())])
                } else {
                    format!("file:{}", path)
                }
            }
            Entity::NetworkConnection { local, remote } => format!("net:{}→{}", local, remote),
            Entity::User { name } => format!("user:{}", name),
            Entity::Host { name } => format!("host:{}", name),
            Entity::Driver { name } => format!("driver:{}", name),
            Entity::RegistryKey { hive, path } => format!("reg:{}@{}", hive, path),
            Entity::MemoryRegion { base, size } => format!("mem:0x{:x}+{}", base, size),
            Entity::Artifact {
                artifact_type,
                path,
            } => format!("artifact:{}:{}", artifact_type, path),
            Entity::LogEvent { source, .. } => format!("log:{}", source),
        }
    }
}

/// A relationship between two entities with evidence backing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: String,
    pub source_entity: Entity,
    pub target_entity: Entity,
    pub relationship_type: RelationshipType,
    pub evidence_refs: Vec<String>,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    ParentOf,
    ChildOf,
    Executed,
    ConnectedTo,
    Created,
    Modified,
    Deleted,
    Loaded,
    BelongsTo,
    ResolvedTo,
    ObservedOn,
    Matched,
    CommunicatedWith,
    InjectedInto,
    Spawned,
    WroteTo,
    ReadFrom,
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::ParentOf => write!(f, "PARENT_OF"),
            RelationshipType::ChildOf => write!(f, "CHILD_OF"),
            RelationshipType::Executed => write!(f, "EXECUTED"),
            RelationshipType::ConnectedTo => write!(f, "CONNECTED_TO"),
            RelationshipType::Created => write!(f, "CREATED"),
            RelationshipType::Modified => write!(f, "MODIFIED"),
            RelationshipType::Deleted => write!(f, "DELETED"),
            RelationshipType::Loaded => write!(f, "LOADED"),
            RelationshipType::BelongsTo => write!(f, "BELONGS_TO"),
            RelationshipType::ResolvedTo => write!(f, "RESOLVED_TO"),
            RelationshipType::ObservedOn => write!(f, "OBSERVED_ON"),
            RelationshipType::Matched => write!(f, "MATCHED"),
            RelationshipType::CommunicatedWith => write!(f, "COMMUNICATED_WITH"),
            RelationshipType::InjectedInto => write!(f, "INJECTED_INTO"),
            RelationshipType::Spawned => write!(f, "SPAWNED"),
            RelationshipType::WroteTo => write!(f, "WROTE_TO"),
            RelationshipType::ReadFrom => write!(f, "READ_FROM"),
        }
    }
}

/// A correlation finding linking multiple entities through relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub entities: Vec<Entity>,
    pub relationships: Vec<Relationship>,
    pub evidence_refs: Vec<String>,
    pub severity: CorrelationSeverity,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub mitre_attack_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CorrelationSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Complete correlation graph for an investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationGraph {
    pub investigation_id: String,
    pub host: String,
    pub generated_at: DateTime<Utc>,
    pub entities: IndexMap<String, EntityNode>,
    pub relationships: Vec<Relationship>,
    pub findings: Vec<CorrelationFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityNode {
    pub entity: Entity,
    pub evidence_refs: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: usize,
}

impl CorrelationGraph {
    pub fn new(investigation_id: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            investigation_id: investigation_id.into(),
            host: host.into(),
            generated_at: Utc::now(),
            entities: IndexMap::new(),
            relationships: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn add_entity(&mut self, entity: Entity, evidence_ref: String, timestamp: DateTime<Utc>) {
        let key = entity.display();
        self.entities
            .entry(key.clone())
            .and_modify(|node| {
                node.evidence_refs.push(evidence_ref.clone());
                node.last_seen = timestamp;
                node.event_count += 1;
            })
            .or_insert(EntityNode {
                entity: entity.clone(),
                evidence_refs: vec![evidence_ref],
                first_seen: timestamp,
                last_seen: timestamp,
                event_count: 1,
            });
    }

    pub fn add_relationship(&mut self, rel: Relationship) {
        self.relationships.push(rel);
    }

    pub fn add_finding(&mut self, finding: CorrelationFinding) {
        self.findings.push(finding);
    }

    pub fn get_entity(&self, key: &str) -> Option<&EntityNode> {
        self.entities.get(key)
    }

    pub fn get_related_entities(&self, entity_key: &str) -> Vec<&EntityNode> {
        self.relationships
            .iter()
            .filter_map(|rel| {
                if rel.source_entity.display() == entity_key {
                    self.entities.get(&rel.target_entity.display())
                } else if rel.target_entity.display() == entity_key {
                    self.entities.get(&rel.source_entity.display())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Correlation engine that builds relationships from forensic evidence
pub struct CorrelationEngine {
    graph: CorrelationGraph,
    timeline: Option<ForensicTimeline>,
    process_tree: HashMap<i32, ProcessNode>,
    file_by_hash: HashMap<String, Vec<String>>, // hash -> evidence_refs
    network_by_endpoint: HashMap<String, Vec<String>>, // endpoint -> evidence_refs
}

#[derive(Debug, Clone)]
struct ProcessNode {
    pid: i32,
    ppid: Option<i32>,
    name: String,
    _command_line: Option<String>,
    executable_path: Option<String>,
    _user: Option<String>,
    start_time: Option<DateTime<Utc>>,
    evidence_ref: String,
}

impl CorrelationEngine {
    pub fn new(investigation_id: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            graph: CorrelationGraph::new(investigation_id, host),
            timeline: None,
            process_tree: HashMap::new(),
            file_by_hash: HashMap::new(),
            network_by_endpoint: HashMap::new(),
        }
    }

    /// Ingest evidence records directly and build correlations
    pub fn ingest_records(&mut self, records: &[serde_json::Value], host: &str) {
        // First pass: build timeline
        self.timeline = Some(jockey_runtime_timeline::build_timeline(records, host, None));

        // Second pass: extract entities and build indices
        self.extract_entities(records, host);

        // Third pass: correlate relationships
        self.correlate_process_tree();
        self.correlate_file_hashes();
        self.correlate_network_endpoints();
        self.correlate_timeline_proximity();

        // Fourth pass: generate findings
        self.generate_findings();
    }

    /// Ingest evidence records from collector and build correlations
    pub fn ingest(
        &mut self,
        collector: &EvidenceCollector,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let records = collector.records();
        let host = collector.host_identifier().to_string();
        self.ingest_records(records, &host);
        Ok(())
    }

    pub fn into_graph(self) -> CorrelationGraph {
        self.graph
    }

    fn extract_entities(&mut self, records: &[serde_json::Value], host: &str) {
        for (index, record) in records.iter().enumerate() {
            let evidence_ref = format!("record-{}", index);
            let obj = match record.as_object() {
                Some(o) => o,
                None => continue,
            };

            // Extract timestamp
            let timestamp = [
                "timestamp",
                "start_time",
                "created_at",
                "time",
                "event_time",
            ]
            .iter()
            .find_map(|field| {
                obj.get(*field)
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            })
            .unwrap_or_else(Utc::now);

            // Process entity
            if let (Some(pid), Some(name)) = (
                obj.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32),
                obj.get("name").and_then(|v| v.as_str()),
            ) {
                let ppid = obj.get("ppid").and_then(|v| v.as_i64()).map(|v| v as i32);
                let cmdline = obj.get("command_line").and_then(|v| {
                    if let Some(arr) = v.as_array() {
                        Some(
                            arr.iter()
                                .filter_map(|e| e.as_str())
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    } else {
                        v.as_str().map(|s| s.to_string())
                    }
                });
                let exe_path = obj
                    .get("executable_path")
                    .or_else(|| obj.get("path"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let user = obj
                    .get("username")
                    .or_else(|| obj.get("user"))
                    .or_else(|| obj.get("owner"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let entity = Entity::Process {
                    pid,
                    name: name.to_string(),
                };
                self.graph
                    .add_entity(entity.clone(), evidence_ref.clone(), timestamp);

                self.process_tree.insert(
                    pid,
                    ProcessNode {
                        pid,
                        ppid,
                        name: name.to_string(),
                        _command_line: cmdline,
                        executable_path: exe_path,
                        _user: user,
                        start_time: Some(timestamp),
                        evidence_ref: evidence_ref.clone(),
                    },
                );
            }

            // File entity
            if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                let hash = obj
                    .get("sha256")
                    .or_else(|| obj.get("hash"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let entity = Entity::File {
                    path: path.to_string(),
                    hash: hash.clone(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);

                if let Some(h) = hash {
                    self.file_by_hash
                        .entry(h)
                        .or_default()
                        .push(evidence_ref.clone());
                }
            }

            // Network entity
            if let (Some(local), Some(remote)) = (
                obj.get("local_address")
                    .or_else(|| obj.get("local_addr"))
                    .and_then(|v| v.as_str()),
                obj.get("remote_address")
                    .or_else(|| obj.get("remote_addr"))
                    .and_then(|v| v.as_str()),
            ) {
                let local_port = obj
                    .get("local_port")
                    .and_then(|v| v.as_u64())
                    .map(|p| format!(":{}", p))
                    .unwrap_or_default();
                let remote_port = obj
                    .get("remote_port")
                    .and_then(|v| v.as_u64())
                    .map(|p| format!(":{}", p))
                    .unwrap_or_default();
                let local = format!("{}{}", local, local_port);
                let remote = format!("{}{}", remote, remote_port);

                let entity = Entity::NetworkConnection {
                    local: local.clone(),
                    remote: remote.clone(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);

                self.network_by_endpoint
                    .entry(remote.clone())
                    .or_default()
                    .push(evidence_ref.clone());
            }

            // User entity
            if let Some(user) = obj
                .get("username")
                .or_else(|| obj.get("user"))
                .or_else(|| obj.get("owner"))
                .and_then(|v| v.as_str())
            {
                let entity = Entity::User {
                    name: user.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Host entity
            if let Some(hostname) = obj.get("hostname").and_then(|v| v.as_str()) {
                let entity = Entity::Host {
                    name: hostname.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            } else {
                let entity = Entity::Host {
                    name: host.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Driver entity
            if let Some(driver_name) = obj
                .get("module_name")
                .or_else(|| obj.get("driver_name"))
                .and_then(|v| v.as_str())
            {
                let entity = Entity::Driver {
                    name: driver_name.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Registry entity
            if let (Some(hive), Some(key_path)) = (
                obj.get("hive").and_then(|v| v.as_str()),
                obj.get("key_path").and_then(|v| v.as_str()),
            ) {
                let entity = Entity::RegistryKey {
                    hive: hive.to_string(),
                    path: key_path.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Memory region entity
            if let (Some(base), Some(size)) = (
                obj.get("start_address").and_then(|v| v.as_u64()),
                obj.get("end_address").and_then(|v| v.as_u64()),
            ) {
                let entity = Entity::MemoryRegion {
                    base,
                    size: size.saturating_sub(base),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Artifact entity
            if let (Some(artifact_type), Some(path)) = (
                obj.get("artifact_type").and_then(|v| v.as_str()),
                obj.get("path").and_then(|v| v.as_str()),
            ) {
                let entity = Entity::Artifact {
                    artifact_type: artifact_type.to_string(),
                    path: path.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }

            // Log event entity
            if let Some(message) = obj.get("message").and_then(|v| v.as_str()) {
                let source = obj
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let entity = Entity::LogEvent {
                    source: source.to_string(),
                    message: message.to_string(),
                };
                self.graph
                    .add_entity(entity, evidence_ref.clone(), timestamp);
            }
        }
    }

    fn correlate_process_tree(&mut self) {
        // Build parent-child relationships
        let pids: Vec<i32> = self.process_tree.keys().copied().collect();
        for pid in pids {
            if let Some(node) = self.process_tree.get(&pid) {
                if let Some(ppid) = node.ppid {
                    if let Some(parent) = self.process_tree.get(&ppid) {
                        let child_entity = Entity::Process {
                            pid: node.pid,
                            name: node.name.clone(),
                        };
                        let parent_entity = Entity::Process {
                            pid: parent.pid,
                            name: parent.name.clone(),
                        };

                        self.graph.add_relationship(Relationship {
                            id: Uuid::new_v4().to_string(),
                            source_entity: parent_entity.clone(),
                            target_entity: child_entity.clone(),
                            relationship_type: RelationshipType::ParentOf,
                            evidence_refs: vec![
                                parent.evidence_ref.clone(),
                                node.evidence_ref.clone(),
                            ],
                            confidence: 0.95,
                            timestamp: node.start_time.unwrap_or_else(Utc::now),
                            details: {
                                let mut m = serde_json::Map::new();
                                m.insert(
                                    "parent_pid".to_string(),
                                    serde_json::Value::Number(parent.pid.into()),
                                );
                                m.insert(
                                    "child_pid".to_string(),
                                    serde_json::Value::Number(node.pid.into()),
                                );
                                m
                            },
                        });

                        self.graph.add_relationship(Relationship {
                            id: Uuid::new_v4().to_string(),
                            source_entity: child_entity,
                            target_entity: parent_entity,
                            relationship_type: RelationshipType::ChildOf,
                            evidence_refs: vec![
                                node.evidence_ref.clone(),
                                parent.evidence_ref.clone(),
                            ],
                            confidence: 0.95,
                            timestamp: node.start_time.unwrap_or_else(Utc::now),
                            details: {
                                let mut m = serde_json::Map::new();
                                m.insert(
                                    "parent_pid".to_string(),
                                    serde_json::Value::Number(parent.pid.into()),
                                );
                                m.insert(
                                    "child_pid".to_string(),
                                    serde_json::Value::Number(node.pid.into()),
                                );
                                m
                            },
                        });
                    }
                }
            }
        }

        // Executable -> Process relationships
        for node in self.process_tree.values() {
            if let Some(exe_path) = &node.executable_path {
                let file_entity = Entity::File {
                    path: exe_path.clone(),
                    hash: None,
                };
                let proc_entity = Entity::Process {
                    pid: node.pid,
                    name: node.name.clone(),
                };

                self.graph.add_relationship(Relationship {
                    id: Uuid::new_v4().to_string(),
                    source_entity: file_entity,
                    target_entity: proc_entity,
                    relationship_type: RelationshipType::Executed,
                    evidence_refs: vec![node.evidence_ref.clone()],
                    confidence: 0.9,
                    timestamp: node.start_time.unwrap_or_else(Utc::now),
                    details: serde_json::Map::new(),
                });
            }
        }
    }

    fn correlate_file_hashes(&mut self) {
        // Find files with matching hashes (potential duplicates or same file)
        for refs in self.file_by_hash.values() {
            if refs.len() > 1 {
                // Multiple files with same hash - could indicate duplication or same file
                // We'd need actual file records to link them properly
                // For now, create a MATCHED relationship between evidence references
                for i in 0..refs.len() {
                    for _j in i + 1..refs.len() {
                        // This is a simplified correlation - in practice you'd link actual file entities
                    }
                }
            }
        }
    }

    fn correlate_network_endpoints(&mut self) {
        // Find processes that communicated with same remote endpoint
        for refs in self.network_by_endpoint.values() {
            if refs.len() > 1 {
                // Multiple connections to same endpoint - correlate the processes
                // This would need process info from network records
            }
        }
    }

    fn correlate_timeline_proximity(&mut self) {
        if let Some(timeline) = &self.timeline {
            // Find events that happened close in time and involve same process
            let mut process_events: HashMap<String, Vec<&TimelineEvent>> = HashMap::new();

            for event in &timeline.events {
                if let Some(proc_name) = &event.process_name {
                    let key = format!("{}:{}", event.host, proc_name);
                    process_events.entry(key).or_default().push(event);
                }
            }

            for (_, events) in process_events {
                if events.len() > 1 {
                    // Sort by time
                    let mut sorted = events;
                    sorted.sort_by_key(|e| e.timestamp);

                    // Look for chains: process -> network -> file -> etc.
                    for window in sorted.windows(2) {
                        let e1 = window[0];
                        let e2 = window[1];

                        let time_diff = (e2.timestamp - e1.timestamp).num_seconds();
                        if (0..=300).contains(&time_diff) {
                            // Within 5 minutes
                            let rel_type = infer_relationship_type(e1, e2);
                            if let Some(rt) = rel_type {
                                let src = Entity::Process {
                                    pid: e1.process_id.unwrap_or(0) as i32,
                                    name: e1.process_name.clone().unwrap_or_default(),
                                };
                                let dst = Entity::Process {
                                    pid: e2.process_id.unwrap_or(0) as i32,
                                    name: e2.process_name.clone().unwrap_or_default(),
                                };

                                if src != dst {
                                    self.graph.add_relationship(Relationship {
                                        id: Uuid::new_v4().to_string(),
                                        source_entity: src,
                                        target_entity: dst,
                                        relationship_type: rt,
                                        evidence_refs: vec![
                                            e1.evidence_ref.clone().unwrap_or_default(),
                                            e2.evidence_ref.clone().unwrap_or_default(),
                                        ],
                                        confidence: 0.7,
                                        timestamp: e1.timestamp,
                                        details: {
                                            let mut m = serde_json::Map::new();
                                            m.insert(
                                                "time_delta_seconds".to_string(),
                                                serde_json::Value::Number(time_diff.into()),
                                            );
                                            m.insert(
                                                "source_event_type".to_string(),
                                                serde_json::Value::String(e1.event_type.clone()),
                                            );
                                            m.insert(
                                                "target_event_type".to_string(),
                                                serde_json::Value::String(e2.event_type.clone()),
                                            );
                                            m
                                        },
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn generate_findings(&mut self) {
        // Find suspicious process chains (e.g., winword -> powershell -> network)
        self.find_process_chains();
        self.find_suspicious_network_behavior();
        self.find_file_drop_chains();
    }

    fn find_process_chains(&mut self) {
        // Look for suspicious parent-child chains
        for node in self.process_tree.values() {
            if let Some(ppid) = node.ppid {
                if let Some(parent) = self.process_tree.get(&ppid) {
                    let parent_lower = parent.name.to_lowercase();
                    let child_lower = node.name.to_lowercase();

                    // Office app spawning shell
                    let is_suspicious = matches!(
                        (parent_lower.as_str(), child_lower.as_str()),
                        ("winword.exe", "cmd.exe")
                            | ("winword.exe", "powershell.exe")
                            | ("excel.exe", "cmd.exe")
                            | ("excel.exe", "powershell.exe")
                            | ("outlook.exe", "cmd.exe")
                            | ("outlook.exe", "powershell.exe")
                            | ("svchost.exe", "cmd.exe")
                            | ("services.exe", "cmd.exe")
                            | ("explorer.exe", "mshta.exe")
                            | ("wmiprvse.exe", "powershell.exe")
                            | ("w3wp.exe", "cmd.exe")
                            | ("w3wp.exe", "powershell.exe")
                    );

                    if is_suspicious {
                        let parent_entity = Entity::Process {
                            pid: parent.pid,
                            name: parent.name.clone(),
                        };
                        let child_entity = Entity::Process {
                            pid: node.pid,
                            name: node.name.clone(),
                        };

                        self.graph.add_finding(CorrelationFinding {
                            id: Uuid::new_v4().to_string(),
                            title: "Suspicious Process Chain".to_string(),
                            description: format!("{} spawned {}, which is a common indicator of malicious macro or exploit activity", parent.name, node.name),
                            entities: vec![parent_entity.clone(), child_entity.clone()],
                            relationships: vec![Relationship {
                                id: Uuid::new_v4().to_string(),
                                source_entity: parent_entity,
                                target_entity: child_entity,
                                relationship_type: RelationshipType::Spawned,
                                evidence_refs: vec![parent.evidence_ref.clone(), node.evidence_ref.clone()],
                                confidence: 0.85,
                                timestamp: node.start_time.unwrap_or_else(Utc::now),
                                details: serde_json::Map::new(),
                            }],
                            evidence_refs: vec![parent.evidence_ref.clone(), node.evidence_ref.clone()],
                            severity: CorrelationSeverity::High,
                            confidence: 0.85,
                            timestamp: node.start_time.unwrap_or_else(Utc::now),
                            mitre_attack_ids: vec!["T1059".to_string(), "T1055".to_string()],
                        });
                    }
                }
            }
        }
    }

    fn find_suspicious_network_behavior(&mut self) {
        // Look for processes making connections to suspicious ports
        let suspicious_ports = [4444, 5555, 1337, 31337, 12345, 6666, 6667, 9001, 9050, 8443];

        if let Some(timeline) = &self.timeline {
            for event in &timeline.events {
                if event.source == "network" {
                    if let Some(endpoint) = &event.network_endpoint {
                        if let Some(port_str) = endpoint.split(':').next_back() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                if suspicious_ports.contains(&port)
                                    && event.event_type.contains("established")
                                {
                                    if let Some(proc_name) = &event.process_name {
                                        let pid = event.process_id.unwrap_or(0) as i32;
                                        let proc_entity = Entity::Process {
                                            pid,
                                            name: proc_name.clone(),
                                        };
                                        let net_entity = Entity::NetworkConnection {
                                            local: event.target.clone().unwrap_or_default(),
                                            remote: endpoint.clone(),
                                        };

                                        self.graph.add_finding(CorrelationFinding {
                                            id: Uuid::new_v4().to_string(),
                                            title: "Suspicious Network Connection".to_string(),
                                            description: format!(
                                                "{} connected to suspicious port {}",
                                                proc_name, port
                                            ),
                                            entities: vec![proc_entity.clone(), net_entity.clone()],
                                            relationships: vec![Relationship {
                                                id: Uuid::new_v4().to_string(),
                                                source_entity: proc_entity,
                                                target_entity: net_entity,
                                                relationship_type: RelationshipType::ConnectedTo,
                                                evidence_refs: event
                                                    .evidence_ref
                                                    .as_ref()
                                                    .map(|r| vec![r.clone()])
                                                    .unwrap_or_default(),
                                                confidence: 0.7,
                                                timestamp: event.timestamp,
                                                details: serde_json::Map::new(),
                                            }],
                                            evidence_refs: event
                                                .evidence_ref
                                                .as_ref()
                                                .map(|r| vec![r.clone()])
                                                .unwrap_or_default(),
                                            severity: CorrelationSeverity::High,
                                            confidence: 0.7,
                                            timestamp: event.timestamp,
                                            mitre_attack_ids: vec!["T1571".to_string()],
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn find_file_drop_chains(&mut self) {
        // Look for processes creating files shortly after network connections
        if let Some(timeline) = &self.timeline {
            let mut process_file_events: HashMap<String, Vec<&TimelineEvent>> = HashMap::new();

            for event in &timeline.events {
                if event.source == "filesystem" && event.event_type.contains("created") {
                    if let Some(proc_name) = &event.process_name {
                        let key = format!("{}:{}", event.host, proc_name);
                        process_file_events.entry(key).or_default().push(event);
                    }
                }
            }

            for (_, file_events) in process_file_events {
                for file_event in file_events {
                    // Look for prior network activity by same process
                    if let Some(net_events) = timeline
                        .events
                        .iter()
                        .filter(|e| {
                            e.process_name == file_event.process_name && e.source == "network"
                        })
                        .filter(|e| {
                            (file_event.timestamp - e.timestamp).num_seconds() >= 0
                                && (file_event.timestamp - e.timestamp).num_seconds() <= 300
                        })
                        .collect::<Vec<_>>()
                        .first()
                    {
                        let proc_entity = Entity::Process {
                            pid: file_event.process_id.unwrap_or(0) as i32,
                            name: file_event.process_name.clone().unwrap_or_default(),
                        };
                        let file_entity = Entity::File {
                            path: file_event.path.clone().unwrap_or_default(),
                            hash: None,
                        };
                        let net_entity = Entity::NetworkConnection {
                            local: net_events.target.clone().unwrap_or_default(),
                            remote: net_events.network_endpoint.clone().unwrap_or_default(),
                        };

                        self.graph.add_finding(CorrelationFinding {
                            id: Uuid::new_v4().to_string(),
                            title: "Potential File Drop After Network Activity".to_string(),
                            description: format!(
                                "Process created file {} after network connection to {}",
                                file_event.path.clone().unwrap_or("unknown".to_string()),
                                net_events
                                    .network_endpoint
                                    .clone()
                                    .unwrap_or("unknown".to_string())
                            ),
                            entities: vec![
                                proc_entity.clone(),
                                file_entity.clone(),
                                net_entity.clone(),
                            ],
                            relationships: vec![
                                Relationship {
                                    id: Uuid::new_v4().to_string(),
                                    source_entity: proc_entity.clone(),
                                    target_entity: file_entity.clone(),
                                    relationship_type: RelationshipType::Created,
                                    evidence_refs: vec![file_event
                                        .evidence_ref
                                        .clone()
                                        .unwrap_or_default()],
                                    confidence: 0.75,
                                    timestamp: file_event.timestamp,
                                    details: serde_json::Map::new(),
                                },
                                Relationship {
                                    id: Uuid::new_v4().to_string(),
                                    source_entity: proc_entity,
                                    target_entity: net_entity.clone(),
                                    relationship_type: RelationshipType::ConnectedTo,
                                    evidence_refs: vec![net_events
                                        .evidence_ref
                                        .clone()
                                        .unwrap_or_default()],
                                    confidence: 0.75,
                                    timestamp: net_events.timestamp,
                                    details: serde_json::Map::new(),
                                },
                            ],
                            evidence_refs: vec![
                                file_event.evidence_ref.clone().unwrap_or_default(),
                                net_events.evidence_ref.clone().unwrap_or_default(),
                            ],
                            severity: CorrelationSeverity::Medium,
                            confidence: 0.75,
                            timestamp: file_event.timestamp,
                            mitre_attack_ids: vec!["T1105".to_string(), "T1571".to_string()],
                        });
                    }
                }
            }
        }
    }

    pub fn graph(&self) -> &CorrelationGraph {
        &self.graph
    }

    pub fn timeline(&self) -> Option<&ForensicTimeline> {
        self.timeline.as_ref()
    }
}

fn infer_relationship_type(e1: &TimelineEvent, e2: &TimelineEvent) -> Option<RelationshipType> {
    match (
        e1.source.as_str(),
        e1.event_type.as_str(),
        e2.source.as_str(),
        e2.event_type.as_str(),
    ) {
        ("process", "process_observed", "network", _) => Some(RelationshipType::ConnectedTo),
        ("process", "process_observed", "filesystem", "file_created") => {
            Some(RelationshipType::Created)
        }
        ("network", _, "filesystem", "file_created") => Some(RelationshipType::Created),
        ("process", "process_observed", "process", "process_observed") => {
            Some(RelationshipType::Spawned)
        }
        ("process", "process_observed", "log", "log_entry") => Some(RelationshipType::ObservedOn),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_display() {
        let proc = Entity::Process {
            pid: 1234,
            name: "powershell.exe".to_string(),
        };
        assert_eq!(proc.display(), "process:powershell.exe(1234)");

        let file = Entity::File {
            path: "/tmp/test.exe".to_string(),
            hash: Some("abc123".to_string()),
        };
        assert!(file.display().contains("/tmp/test.exe"));
    }

    #[test]
    fn test_correlation_engine_creation() {
        let engine = CorrelationEngine::new("test-investigation", "test-host");
        assert_eq!(engine.graph.investigation_id, "test-investigation");
        assert_eq!(engine.graph.host, "test-host");
    }

    #[test]
    fn test_relationship_type_display() {
        assert_eq!(RelationshipType::ParentOf.to_string(), "PARENT_OF");
        assert_eq!(RelationshipType::ConnectedTo.to_string(), "CONNECTED_TO");
        assert_eq!(RelationshipType::Created.to_string(), "CREATED");
    }
}
