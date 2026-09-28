//! jockey Runtime - Evidence collection, integrity, and verification

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;

pub mod bundle;
pub use bundle::{
    BundleVerificationResult, EvidenceBundle, EvidenceManifest, EvidenceProvenance, EvidenceRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollectionStatus {
    Success,
    Partial,
    Failed,
    NotFound,
    Unsupported,
    PermissionDenied,
    RequiresElevation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EvidenceOrigin {
    Real,
    Simulated,
    Imported,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectorResult {
    pub collector: String,
    pub status: CollectionStatus,
    pub records_count: usize,
    pub error: Option<String>,
    pub warning: Option<String>,
    pub timestamp: DateTime<Utc>,
}

fn default_evidence_origin() -> EvidenceOrigin {
    EvidenceOrigin::Real
}

fn default_collection_status() -> CollectionStatus {
    CollectionStatus::Success
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceMetadata {
    pub investigation_name: String,
    pub tool_name: String,
    pub tool_version: String,
    pub host_identifier: String,
    pub collection_time: DateTime<Utc>,
    pub evidence_hash: String,
    pub evidence_size: u64,
    pub merkle_root: Option<String>,
    pub merkle_proof: Option<Vec<MerkleProofNode>>,
    pub blockchain_anchor: Option<BlockchainAnchor>,
    #[serde(default = "default_evidence_origin")]
    pub evidence_origin: EvidenceOrigin,
    #[serde(default = "default_collection_status")]
    pub overall_status: CollectionStatus,
    #[serde(default)]
    pub collector_results: Vec<CollectorResult>,
    pub compiler_version: Option<String>,
    pub source_hash: Option<String>,
    pub artifact_hash: Option<String>,
    pub collection_started_at: Option<DateTime<Utc>>,
    pub collection_finished_at: Option<DateTime<Utc>>,
}

/// A single node in a Merkle inclusion proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofNode {
    /// SHA-256 hash of the sibling node
    pub sibling_hash: String,
    /// Which side the sibling is on
    pub position: MerkleNodePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MerkleNodePosition {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    pub transaction_id: String,
    pub block_height: u64,
    pub timestamp: DateTime<Utc>,
    pub network: String,
}

/// Result of verifying evidence integrity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    Verified,
    Tampered { reason: String },
    Missing { detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub evidence_path: String,
    pub metadata_path: String,
    pub calculated_hash: Option<String>,
    pub stored_hash: Option<String>,
    pub merkle_root_valid: Option<bool>,
    pub verified_at: DateTime<Utc>,
}

/// Detailed per-item verification result for deep evidence audits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepVerificationResult {
    pub base_result: VerificationResult,
    pub total_items: usize,
    pub verified_items: usize,
    pub failed_items: Vec<(usize, String)>,
    pub per_item_proofs_valid: bool,
    pub merkle_leaf_hashes: Vec<String>,
}

pub struct EvidenceCollector {
    investigation_name: String,
    tool_name: String,
    tool_version: String,
    compiler_version: String,
    source_hash: Option<String>,
    artifact_hash: Option<String>,
    host_identifier: String,
    output_format: String,
    output_path: String,
    data: Vec<serde_json::Value>,
    filters: Vec<serde_json::Value>,
    where_conditions: Vec<serde_json::Value>,
    limit: Option<usize>,
    metadata: HashMap<String, serde_json::Value>,
    collector_results: Vec<CollectorResult>,
    evidence_origin: EvidenceOrigin,
    started_at: DateTime<Utc>,
}

impl EvidenceCollector {
    pub fn new(investigation_name: &str) -> Self {
        Self {
            investigation_name: investigation_name.to_string(),
            tool_name: "jockey-tool".to_string(),
            tool_version: "0.1.0".to_string(),
            compiler_version: "0.1.0".to_string(),
            source_hash: None,
            artifact_hash: None,
            host_identifier: whoami::devicename(),
            output_format: "json".to_string(),
            output_path: format!("{}.json", investigation_name),
            data: Vec::new(),
            filters: Vec::new(),
            where_conditions: Vec::new(),
            limit: None,
            metadata: HashMap::new(),
            collector_results: Vec::new(),
            evidence_origin: EvidenceOrigin::Real,
            started_at: Utc::now(),
        }
    }

    pub fn set_evidence_origin(&mut self, origin: EvidenceOrigin) {
        self.evidence_origin = origin;
    }

    pub fn set_build_provenance(
        &mut self,
        source_hash: Option<String>,
        artifact_hash: Option<String>,
    ) {
        self.source_hash = source_hash;
        self.artifact_hash = artifact_hash;
    }

    pub fn record_collector_result(
        &mut self,
        collector: &str,
        status: CollectionStatus,
        records_count: usize,
        error: Option<String>,
        warning: Option<String>,
    ) {
        self.collector_results.push(CollectorResult {
            collector: collector.to_string(),
            status,
            records_count,
            error,
            warning,
            timestamp: Utc::now(),
        });
    }

    pub fn collector_results(&self) -> &[CollectorResult] {
        &self.collector_results
    }

    /// Get the collected evidence data
    pub fn data(&self) -> &[serde_json::Value] {
        &self.data
    }

    /// Get mutable reference to collected evidence data
    pub fn data_mut(&mut self) -> &mut Vec<serde_json::Value> {
        &mut self.data
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn overall_status(&self) -> CollectionStatus {
        if self.collector_results.is_empty() {
            return CollectionStatus::Success;
        }
        let has_success = self
            .collector_results
            .iter()
            .any(|r| r.status == CollectionStatus::Success);
        let has_failure = self.collector_results.iter().any(|r| {
            matches!(
                r.status,
                CollectionStatus::Failed
                    | CollectionStatus::NotFound
                    | CollectionStatus::Unsupported
                    | CollectionStatus::PermissionDenied
                    | CollectionStatus::RequiresElevation
            )
        });
        let has_partial = self
            .collector_results
            .iter()
            .any(|r| r.status == CollectionStatus::Partial);
        if has_failure && !has_success {
            if self
                .collector_results
                .iter()
                .all(|r| r.status == CollectionStatus::NotFound)
            {
                CollectionStatus::NotFound
            } else if self
                .collector_results
                .iter()
                .all(|r| r.status == CollectionStatus::Unsupported)
            {
                CollectionStatus::Unsupported
            } else if self
                .collector_results
                .iter()
                .all(|r| r.status == CollectionStatus::PermissionDenied)
            {
                CollectionStatus::PermissionDenied
            } else if self
                .collector_results
                .iter()
                .all(|r| r.status == CollectionStatus::RequiresElevation)
            {
                CollectionStatus::RequiresElevation
            } else {
                CollectionStatus::Failed
            }
        } else if has_failure || has_partial {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Success
        }
    }

    pub fn collect_system_info(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_system::collect_system_info() {
            Ok(info) => {
                self.data.push(info);
                self.record_collector_result(
                    "system_info",
                    CollectionStatus::Success,
                    1,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "system_info",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_processes(
        &mut self,
        fields: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_process::enumerate_processes(&fields) {
            Ok(processes) => {
                let count = processes.len();
                for proc in processes {
                    self.data.push(proc);
                }
                self.record_collector_result(
                    "processes",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "processes",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_network_connections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_network::enumerate_connections() {
            Ok(connections) => {
                let count = connections.len();
                for conn in connections {
                    self.data.push(conn);
                }
                self.record_collector_result(
                    "network",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "network",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_firewall(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_network::enumerate_firewall_policy() {
            Ok(records) => {
                let count = records.len();
                let mut status = CollectionStatus::Success;
                for rec in records {
                    if let Some(s) = rec.get("status").and_then(|v| v.as_str()) {
                        if s == "requires_elevation" {
                            status = CollectionStatus::RequiresElevation;
                        } else if (s == "not_available" || s == "unsupported")
                            && status != CollectionStatus::RequiresElevation
                        {
                            status = CollectionStatus::Unsupported;
                        }
                    }
                    self.data.push(rec);
                }
                self.record_collector_result("firewall", status, count, None, None);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "firewall",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_proxy(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_network::enumerate_proxy() {
            Ok(records) => {
                let count = records.len();
                for rec in records {
                    self.data.push(rec);
                }
                self.record_collector_result("proxy", CollectionStatus::Success, count, None, None);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "proxy",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_files(
        &mut self,
        path: &str,
        recursive: bool,
        hash: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_filesystem::enumerate_files(path, recursive, hash) {
            Ok(files) => {
                let count = files.len();
                for file in files {
                    self.data.push(file);
                }
                self.record_collector_result("files", CollectionStatus::Success, count, None, None);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "files",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_logs(&mut self, source: &str) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_logs::collect_logs(source) {
            Ok(logs) => {
                let count = logs.len();
                for log in logs {
                    self.data.push(log);
                }
                self.record_collector_result("logs", CollectionStatus::Success, count, None, None);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "logs",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_drivers(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_drivers::enumerate_drivers() {
            Ok(drivers) => {
                let count = drivers.len();
                for d in drivers {
                    self.data.push(d);
                }
                self.record_collector_result(
                    "drivers",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "drivers",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_memory_regions(
        &mut self,
        pid_filter: Option<i32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_memory::enumerate_memory_regions(pid_filter) {
            Ok(regions) => {
                let count = regions.len();
                for region in regions {
                    self.data.push(region);
                }
                self.record_collector_result(
                    "memory_regions",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "memory_regions",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_registry(
        &mut self,
        hive: &str,
        key_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_registry::enumerate_registry(hive, key_path) {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    self.data.push(entry);
                }
                self.record_collector_result(
                    "registry",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "registry",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn collect_artifacts(
        &mut self,
        artifact_type: &str,
        search_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match jockey_runtime_artifacts::carve_artifacts(artifact_type, search_path) {
            Ok(artifacts) => {
                let count = artifacts.len();
                for artifact in artifacts {
                    self.data.push(artifact);
                }
                self.record_collector_result(
                    "artifacts",
                    CollectionStatus::Success,
                    count,
                    None,
                    None,
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                self.record_collector_result(
                    "artifacts",
                    CollectionStatus::Failed,
                    0,
                    Some(err_str),
                    None,
                );
                Err(e)
            }
        }
    }

    pub fn generate_timeline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let host = self.host_identifier.clone();
        let records = self.data.clone();
        let mut timeline_records = Vec::with_capacity(records.len());
        for (i, rec) in records.iter().enumerate() {
            let ref_str = format!("ref-{}", i + 1);
            if let Some(event) =
                jockey_runtime_timeline::normalize_record(rec, &host, Some(&ref_str))
            {
                if let Ok(v) = serde_json::to_value(&event) {
                    timeline_records.push(v);
                    continue;
                }
            }
            timeline_records.push(rec.clone());
        }
        self.data = timeline_records;
        self.metadata
            .insert("timeline_generated".to_string(), serde_json::json!(true));
        Ok(())
    }

    pub fn generate_chain_of_custody(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let host = self.host_identifier.clone();
        let inv = self.investigation_name.clone();
        let hash = self.compute_hash("sha256")?;
        let merkle = self
            .metadata
            .get("merkle_root")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let coc = generate_chain_of_custody(&inv, &host, &hash, merkle.as_deref());
        self.data.push(serde_json::to_value(&coc)?);
        self.record_collector_result("chain_of_custody", CollectionStatus::Success, 1, None, None);
        Ok(())
    }

    pub fn export_evidence(&mut self, format: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.output_format = format.to_string();
        Ok(())
    }

    pub fn set_output_format(&mut self, format: &str, path: &str) {
        self.output_format = format.to_string();
        self.output_path = path.to_string();
    }

    pub fn add_filter(&mut self, condition: serde_json::Value) {
        self.filters.push(condition);
    }

    pub fn add_where(&mut self, condition: serde_json::Value) {
        self.where_conditions.push(condition);
    }

    pub fn set_limit(&mut self, limit: serde_json::Value) {
        if let Some(n) = limit.as_u64() {
            self.limit = Some(n as usize);
        }
    }

    pub fn add_metadata(&mut self, key: &str, value: serde_json::Value) {
        self.metadata.insert(key.to_string(), value);
    }

    pub fn add_record(&mut self, record: serde_json::Value) {
        self.data.push(record);
    }

    pub fn host_identifier(&self) -> &str {
        &self.host_identifier
    }

    pub fn records(&self) -> &[serde_json::Value] {
        &self.data
    }

    pub fn set_records(&mut self, records: Vec<serde_json::Value>) {
        self.data = records;
    }

    pub fn compute_hash(&mut self, algo: &str) -> Result<String, Box<dyn std::error::Error>> {
        let evidence_json = serde_json::to_vec(&self.data)?;
        let hash_str = match algo.to_lowercase().as_str() {
            "sha256" | "" => {
                let mut hasher = Sha256::new();
                hasher.update(&evidence_json);
                format!("{:x}", hasher.finalize())
            }
            "sha512" => {
                use sha2::Sha512;
                let mut hasher = Sha512::new();
                hasher.update(&evidence_json);
                format!("{:x}", hasher.finalize())
            }
            _ => {
                let mut hasher = Sha256::new();
                hasher.update(&evidence_json);
                format!("{:x}", hasher.finalize())
            }
        };
        self.metadata
            .insert("hash_algorithm".to_string(), serde_json::json!(algo));
        self.metadata
            .insert("evidence_hash".to_string(), serde_json::json!(&hash_str));
        Ok(hash_str)
    }

    /// Construct a canonical EvidenceBundle representation of the gathered evidence.
    pub fn to_bundle(&self) -> EvidenceBundle {
        let records: Vec<EvidenceRecord> = self
            .data
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let source = item
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("collector");
                let record_type = item
                    .get("event_type")
                    .or_else(|| item.get("collector"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("record");
                let mut provenance = EvidenceProvenance::new(
                    self.evidence_origin,
                    &self.host_identifier,
                    record_type,
                    &self.tool_version,
                    "native",
                );
                provenance.compiler_version = Some(self.compiler_version.clone());
                provenance.source_hash = self.source_hash.clone();
                provenance.artifact_hash = self.artifact_hash.clone();
                EvidenceRecord::new(
                    Some(format!("rec-{:04}-{}", i, uuid::Uuid::new_v4().simple())),
                    &self.host_identifier,
                    Some(Utc::now()),
                    source,
                    record_type,
                    record_type,
                    item.clone(),
                    provenance,
                )
            })
            .collect();

        EvidenceBundle::from_records(
            &self.investigation_name,
            &self.host_identifier,
            "native",
            &self.tool_version,
            &self.compiler_version,
            self.started_at,
            Utc::now(),
            self.collector_results.clone(),
            self.source_hash.clone(),
            self.artifact_hash.clone(),
            records,
        )
    }

    pub fn finalize(&mut self) -> Result<EvidenceMetadata, Box<dyn std::error::Error>> {
        // Apply filters
        self.apply_filters()?;

        // Apply where conditions
        self.apply_where()?;

        // Apply limit
        if let Some(limit) = self.limit {
            self.data.truncate(limit);
        }

        // Serialize evidence
        let evidence_json = serde_json::to_vec_pretty(&self.data)?;

        // Calculate SHA-256 of entire evidence array
        let mut hasher = Sha256::new();
        hasher.update(&evidence_json);
        let evidence_hash = format!("{:x}", hasher.finalize());
        let evidence_size = evidence_json.len() as u64;

        // Build Merkle tree from individual evidence items
        let item_hashes: Vec<String> = self
            .data
            .iter()
            .map(|item| {
                let bytes = serde_json::to_vec(item).unwrap_or_default();
                let mut h = Sha256::new();
                h.update(&bytes);
                format!("{:x}", h.finalize())
            })
            .collect();

        let merkle_root = if item_hashes.is_empty() {
            None
        } else {
            Some(compute_merkle_root(&item_hashes))
        };

        // Write evidence file
        let mut file = fs::File::create(&self.output_path)?;
        file.write_all(&evidence_json)?;

        // Create metadata
        let overall_status = self.overall_status();
        let metadata = EvidenceMetadata {
            investigation_name: self.investigation_name.clone(),
            tool_name: self.tool_name.clone(),
            tool_version: self.tool_version.clone(),
            host_identifier: self.host_identifier.clone(),
            collection_time: Utc::now(),
            evidence_hash,
            evidence_size,
            merkle_root,
            merkle_proof: None,
            blockchain_anchor: None,
            evidence_origin: self.evidence_origin,
            overall_status,
            collector_results: self.collector_results.clone(),
            compiler_version: Some(self.compiler_version.clone()),
            source_hash: self.source_hash.clone(),
            artifact_hash: self.artifact_hash.clone(),
            collection_started_at: Some(self.started_at),
            collection_finished_at: Some(Utc::now()),
        };

        // Write metadata sidecar
        let meta_path = format!("{}.meta.json", self.output_path);
        let meta_json = serde_json::to_vec_pretty(&metadata)?;
        fs::write(meta_path, meta_json)?;

        // Write canonical EvidenceBundle
        let bundle = self.to_bundle();
        let bundle_path = format!("{}.bundle.json", self.output_path);
        let bundle_json = serde_json::to_vec_pretty(&bundle)?;
        fs::write(&bundle_path, bundle_json)?;

        println!("Evidence written to: {}", self.output_path);
        println!("SHA-256: {}", metadata.evidence_hash);
        println!(
            "Merkle root: {}",
            metadata.merkle_root.as_deref().unwrap_or("(empty)")
        );
        println!("Size: {} bytes", metadata.evidence_size);

        Ok(metadata)
    }

    /// Collect variable: returns a clone of current data (for pipeline variable assignment)
    pub fn collect_variable(
        &self,
        _expr: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        Ok(self.data.clone())
    }

    /// Process a pipeline stage count (for evidence pipeline IR operations)
    pub fn process_pipeline(
        &mut self,
        _variable: &str,
        _stage_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // In the full implementation, this would apply pipeline stages to the named variable
        Ok(())
    }

    fn apply_filters(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conditions = self.filters.clone();
        self.apply_conditions(&conditions)
    }

    fn apply_where(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conditions = self.where_conditions.clone();
        self.apply_conditions(&conditions)
    }

    fn apply_conditions(
        &mut self,
        conditions: &[serde_json::Value],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for condition in conditions {
            self.data = self
                .data
                .drain(..)
                .filter_map(|record| match evaluate(condition, &record) {
                    Ok(true) => Some(Ok(record)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFinding {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub evidence_refs: Vec<String>,
    pub detection_reason: String,
    pub recommendation: String,
}

pub fn analyze_evidence(evidence: &[serde_json::Value]) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();
    let mut evidence_refs = Vec::new();

    for (index, item) in evidence.iter().enumerate() {
        let id = format!("evidence-{}", index + 1);
        evidence_refs.push(id.clone());

        if let Some(map) = item.as_object() {
            let mut suspicious = false;
            let mut reason = String::new();

            if map
                .get("state")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|state| {
                    state.eq_ignore_ascii_case("LISTEN")
                        || state.eq_ignore_ascii_case("ESTABLISHED")
                })
            {
                suspicious = true;
                reason.push_str("network endpoint is active");
            }

            if map
                .get("pid")
                .and_then(serde_json::Value::as_i64)
                .is_some_and(|pid| pid > 0)
            {
                if !reason.is_empty() {
                    reason.push_str("; ");
                }
                reason.push_str("process id is present");
            }

            if suspicious {
                findings.push(SecurityFinding {
                    id: format!("finding-{}", findings.len() + 1),
                    category: "network-state".to_string(),
                    severity: "medium".to_string(),
                    description: "Active network state observed in evidence collection.".to_string(),
                    evidence_refs: vec![id],
                    detection_reason: reason,
                    recommendation: "Review the process and destination endpoint for expected baseline activity.".to_string(),
                });
            }
        }
    }

    if evidence
        .iter()
        .any(|item| item.to_string().contains("powershell") || item.to_string().contains("cmd.exe"))
    {
        findings.push(SecurityFinding {
            id: format!("finding-{}", findings.len() + 1),
            category: "execution".to_string(),
            severity: "high".to_string(),
            description: "Command shell execution was captured in forensic evidence.".to_string(),
            evidence_refs: evidence_refs.clone(),
            detection_reason: "Evidence records contain command-shell invocation strings.".to_string(),
            recommendation: "Validate whether the command was expected administrative activity and preserve the related process metadata.".to_string(),
        });
    }

    findings
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockchainAnchorRecord {
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
}

pub trait BlockchainAdapter {
    fn anchor(&self, hash: &str, source: &str) -> Result<String, Box<dyn std::error::Error>>;
    fn verify(&self, hash: &str, transaction_id: &str) -> Result<bool, Box<dyn std::error::Error>>;
    fn get_status(&self) -> Result<String, Box<dyn std::error::Error>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelopmentBlockchainAdapter {
    pub network_name: String,
    pub manifest_path: std::path::PathBuf,
}

impl Default for DevelopmentBlockchainAdapter {
    fn default() -> Self {
        Self {
            network_name: "dev-local".to_string(),
            manifest_path: std::env::temp_dir().join("jockey-blockchain-manifest.json"),
        }
    }
}

impl DevelopmentBlockchainAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockchainAdapter for DevelopmentBlockchainAdapter {
    fn anchor(&self, hash: &str, source: &str) -> Result<String, Box<dyn std::error::Error>> {
        let manifest = BlockchainAnchorRecord {
            hash: hash.to_string(),
            created_at: chrono::Utc::now(),
            source: source.to_string(),
        };
        let slice_len = std::cmp::min(12, hash.len());
        let tx_id = format!("dev-{}", &hash[..slice_len]);
        let existing = if self.manifest_path.exists() {
            let bytes = std::fs::read(&self.manifest_path)?;
            let mut items: Vec<BlockchainAnchorRecord> =
                serde_json::from_slice(&bytes).unwrap_or_default();
            items.push(manifest.clone());
            items
        } else {
            vec![manifest]
        };
        std::fs::write(
            self.manifest_path.clone(),
            serde_json::to_vec_pretty(&existing)?,
        )?;
        Ok(tx_id)
    }

    fn verify(&self, hash: &str, transaction_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if !self.manifest_path.exists() {
            return Ok(false);
        }
        let bytes = std::fs::read(&self.manifest_path)?;
        let items: Vec<BlockchainAnchorRecord> = serde_json::from_slice(&bytes).unwrap_or_default();
        let slice_len = std::cmp::min(12, hash.len());
        let expected_prefix = format!("dev-{}", &hash[..slice_len]);
        Ok(items.iter().any(|entry| entry.hash == hash) && transaction_id == expected_prefix)
    }

    fn get_status(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(format!(
            "development adapter active on {}",
            self.network_name
        ))
    }
}

#[test]
fn test_security_analysis_returns_evidence_backed_findings() {
    let evidence = vec![
        serde_json::json!({ "state": "ESTABLISHED", "pid": 1337, "process_name": "powershell.exe" }),
        serde_json::json!({ "state": "LISTEN", "pid": 42, "process_name": "python" }),
    ];

    let findings = analyze_evidence(&evidence);
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.category == "network-state"));
}

#[test]
fn test_bundle_preserves_partial_and_unsupported_collection_status() {
    let mut partial = EvidenceCollector::new("partial-status-test");
    partial.record_collector_result(
        "parser",
        CollectionStatus::Partial,
        1,
        None,
        Some("malformed record".into()),
    );
    assert_eq!(
        partial.to_bundle().evidence_status,
        CollectionStatus::Partial
    );

    let mut unsupported = EvidenceCollector::new("unsupported-status-test");
    unsupported.record_collector_result("collector", CollectionStatus::Unsupported, 0, None, None);
    assert_eq!(
        unsupported.to_bundle().evidence_status,
        CollectionStatus::Unsupported
    );
}

#[test]
fn test_development_blockchain_adapter_round_trip() {
    let adapter = DevelopmentBlockchainAdapter::new();
    let hash = "aaabbbccdd";
    let tx_id = adapter.anchor(hash, "unit-test").unwrap();
    assert!(adapter.verify(hash, &tx_id).unwrap());
    assert!(adapter.get_status().unwrap().contains("development"));
}

fn evaluate(
    expression: &serde_json::Value,
    record: &serde_json::Value,
) -> Result<bool, Box<dyn std::error::Error>> {
    truthy(&evaluate_value(expression, record)?)
}

fn evaluate_value(
    expression: &serde_json::Value,
    record: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match expression {
        serde_json::Value::String(name) if name.starts_with('$') => record
            .get(name.trim_start_matches('$'))
            .cloned()
            .ok_or_else(|| format!("Unknown evidence field: {}", name).into()),
        serde_json::Value::Object(object) if object.contains_key("field_access") => {
            let access = object
                .get("field_access")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| "Invalid field access expression".to_string())?;
            let field = access
                .get("field")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "Field access is missing a field name".to_string())?;
            let target = evaluate_value(
                access
                    .get("object")
                    .ok_or_else(|| "Field access is missing an object".to_string())?,
                record,
            )?;
            target
                .get(field)
                .cloned()
                .ok_or_else(|| format!("Unknown evidence field: {}", field).into())
        }
        serde_json::Value::Object(object) if object.contains_key("op") => {
            let op = object
                .get("op")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "Expression operator is missing".to_string())?;
            let left = object
                .get("left")
                .map(|value| evaluate_value(value, record))
                .transpose()?;
            let right = object
                .get("right")
                .map(|value| evaluate_value(value, record))
                .transpose()?;
            let operand = object
                .get("expr")
                .map(|value| evaluate_value(value, record))
                .transpose()?;
            evaluate_operator(op, left.as_ref(), right.as_ref(), operand.as_ref())
        }
        value => Ok(value.clone()),
    }
}

fn evaluate_operator(
    op: &str,
    left: Option<&serde_json::Value>,
    right: Option<&serde_json::Value>,
    operand: Option<&serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let comparison = |predicate: fn(std::cmp::Ordering) -> bool| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let left = left.ok_or_else(|| "Binary expression is missing its left operand".to_string())?;
        let right = right.ok_or_else(|| "Binary expression is missing its right operand".to_string())?;
        Ok(serde_json::Value::Bool(predicate(compare_values(left, right)?)))
    };

    match op {
        "equal" => Ok(serde_json::Value::Bool(left == right)),
        "not_equal" => Ok(serde_json::Value::Bool(left != right)),
        "less" => comparison(|ordering| ordering == std::cmp::Ordering::Less),
        "less_equal" => comparison(|ordering| ordering != std::cmp::Ordering::Greater),
        "greater" => comparison(|ordering| ordering == std::cmp::Ordering::Greater),
        "greater_equal" => comparison(|ordering| ordering != std::cmp::Ordering::Less),
        "and" => Ok(serde_json::Value::Bool(
            truthy(left.ok_or_else(|| "Missing left operand".to_string())?)?
                && truthy(right.ok_or_else(|| "Missing right operand".to_string())?)?,
        )),
        "or" => Ok(serde_json::Value::Bool(
            truthy(left.ok_or_else(|| "Missing left operand".to_string())?)?
                || truthy(right.ok_or_else(|| "Missing right operand".to_string())?)?,
        )),
        "add" | "subtract" | "multiply" | "divide" => arithmetic(op, left, right),
        "not" => Ok(serde_json::Value::Bool(!truthy(
            operand.ok_or_else(|| "Missing unary operand".to_string())?,
        )?)),
        "minus" => match operand.ok_or_else(|| "Missing unary operand".to_string())? {
            serde_json::Value::Number(number) => Ok(serde_json::json!(-number
                .as_f64()
                .ok_or_else(|| "Invalid numeric operand".to_string())?)),
            _ => Err("Unary minus requires a number".into()),
        },
        _ => Err(format!("Unsupported expression operator: {}", op).into()),
    }
}

fn arithmetic(
    op: &str,
    left: Option<&serde_json::Value>,
    right: Option<&serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let left = left
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "Arithmetic requires numeric operands".to_string())?;
    let right = right
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| "Arithmetic requires numeric operands".to_string())?;
    let result = match op {
        "add" => left + right,
        "subtract" => left - right,
        "multiply" => left * right,
        "divide" if right != 0.0 => left / right,
        "divide" => return Err("Division by zero".into()),
        _ => unreachable!(),
    };
    Ok(serde_json::json!(result))
}

fn truthy(value: &serde_json::Value) -> Result<bool, Box<dyn std::error::Error>> {
    match value {
        serde_json::Value::Bool(value) => Ok(*value),
        serde_json::Value::Null => Ok(false),
        serde_json::Value::Number(value) => Ok(value.as_f64().unwrap_or(0.0) != 0.0),
        serde_json::Value::String(value) => Ok(!value.is_empty()),
        _ => Err("Expected a scalar boolean value".into()),
    }
}

fn compare_values(
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> Result<std::cmp::Ordering, Box<dyn std::error::Error>> {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        return left
            .partial_cmp(&right)
            .ok_or_else(|| "Cannot compare non-finite numbers".into());
    }
    if let (Some(left), Some(right)) = (left.as_str(), right.as_str()) {
        return Ok(left.cmp(right));
    }
    Err("Values are not comparable".into())
}

/// Calculate SHA-256 hash of a file
pub fn hash_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify evidence integrity with detailed result
pub fn verify_evidence(
    evidence_path: &str,
    metadata_path: &str,
) -> Result<VerificationResult, Box<dyn std::error::Error>> {
    let evidence_path_str = evidence_path.to_string();
    let metadata_path_str = metadata_path.to_string();

    // Read evidence file
    let evidence_bytes = match fs::read(evidence_path) {
        Ok(b) => b,
        Err(e) => {
            return Ok(VerificationResult {
                status: VerificationStatus::Missing {
                    detail: format!("Evidence file not readable: {}", e),
                },
                evidence_path: evidence_path_str,
                metadata_path: metadata_path_str,
                calculated_hash: None,
                stored_hash: None,
                merkle_root_valid: None,
                verified_at: Utc::now(),
            });
        }
    };

    // Calculate hash of evidence file
    let mut hasher = Sha256::new();
    hasher.update(&evidence_bytes);
    let calculated_hash = format!("{:x}", hasher.finalize());

    // Read metadata
    let meta_bytes = match fs::read(metadata_path) {
        Ok(b) => b,
        Err(e) => {
            return Ok(VerificationResult {
                status: VerificationStatus::Missing {
                    detail: format!("Metadata file not readable: {}", e),
                },
                evidence_path: evidence_path_str,
                metadata_path: metadata_path_str,
                calculated_hash: Some(calculated_hash),
                stored_hash: None,
                merkle_root_valid: None,
                verified_at: Utc::now(),
            });
        }
    };

    let metadata: EvidenceMetadata = serde_json::from_slice(&meta_bytes)?;
    let stored_hash = metadata.evidence_hash.clone();

    // Check hash match
    if calculated_hash != stored_hash {
        return Ok(VerificationResult {
            status: VerificationStatus::Tampered {
                reason: format!(
                    "SHA-256 mismatch: calculated={} stored={}",
                    &calculated_hash[..16],
                    &stored_hash[..16]
                ),
            },
            evidence_path: evidence_path_str,
            metadata_path: metadata_path_str,
            calculated_hash: Some(calculated_hash),
            stored_hash: Some(stored_hash),
            merkle_root_valid: None,
            verified_at: Utc::now(),
        });
    }

    // Verify Merkle root if present
    let merkle_root_valid = if let Some(stored_root) = &metadata.merkle_root {
        // Re-compute Merkle root from evidence items
        let evidence_items: Vec<serde_json::Value> = serde_json::from_slice(&evidence_bytes)?;
        let item_hashes: Vec<String> = evidence_items
            .iter()
            .map(|item| {
                let bytes = serde_json::to_vec(item).unwrap_or_default();
                let mut h = Sha256::new();
                h.update(&bytes);
                format!("{:x}", h.finalize())
            })
            .collect();
        let computed_root = compute_merkle_root(&item_hashes);
        Some(computed_root == *stored_root)
    } else {
        None
    };

    // Check Merkle root validity
    if merkle_root_valid == Some(false) {
        return Ok(VerificationResult {
            status: VerificationStatus::Tampered {
                reason: "Merkle root mismatch: individual evidence items have been modified"
                    .to_string(),
            },
            evidence_path: evidence_path_str,
            metadata_path: metadata_path_str,
            calculated_hash: Some(calculated_hash),
            stored_hash: Some(stored_hash),
            merkle_root_valid,
            verified_at: Utc::now(),
        });
    }

    Ok(VerificationResult {
        status: VerificationStatus::Verified,
        evidence_path: evidence_path_str,
        metadata_path: metadata_path_str,
        calculated_hash: Some(calculated_hash),
        stored_hash: Some(stored_hash),
        merkle_root_valid,
        verified_at: Utc::now(),
    })
}

/// Perform deep verification of evidence: base integrity check + per-item Merkle proof checks
pub fn verify_evidence_deep(
    evidence_path: &str,
    metadata_path: &str,
) -> Result<DeepVerificationResult, Box<dyn std::error::Error>> {
    let base = verify_evidence(evidence_path, metadata_path)?;
    if !matches!(base.status, VerificationStatus::Verified) {
        return Ok(DeepVerificationResult {
            base_result: base,
            total_items: 0,
            verified_items: 0,
            failed_items: vec![],
            per_item_proofs_valid: false,
            merkle_leaf_hashes: vec![],
        });
    }

    let evidence_bytes = fs::read(evidence_path)?;
    let evidence_items: Vec<serde_json::Value> = serde_json::from_slice(&evidence_bytes)?;
    let meta_bytes = fs::read(metadata_path)?;
    let metadata: EvidenceMetadata = serde_json::from_slice(&meta_bytes)?;

    let item_hashes: Vec<String> = evidence_items
        .iter()
        .map(|item| {
            let bytes = serde_json::to_vec(item).unwrap_or_default();
            let mut h = Sha256::new();
            h.update(&bytes);
            format!("{:x}", h.finalize())
        })
        .collect();

    let expected_root = metadata.merkle_root.as_deref().unwrap_or("");
    let mut verified_count = 0;
    let mut failed_items = Vec::new();

    if !expected_root.is_empty() && !item_hashes.is_empty() {
        for (idx, hash) in item_hashes.iter().enumerate() {
            if let Some(proof) = generate_merkle_proof(&item_hashes, idx) {
                if verify_merkle_proof_for_item(hash, &proof, expected_root) {
                    verified_count += 1;
                } else {
                    failed_items
                        .push((idx, format!("Proof verification failed for leaf {}", hash)));
                }
            } else {
                failed_items.push((idx, format!("Could not generate proof for index {}", idx)));
            }
        }
    } else {
        verified_count = item_hashes.len();
    }

    let all_valid = failed_items.is_empty();
    let mut final_base = base;
    if !all_valid {
        final_base.status = VerificationStatus::Tampered {
            reason: format!(
                "Deep verification failed: {} item proof(s) invalid",
                failed_items.len()
            ),
        };
    }

    Ok(DeepVerificationResult {
        base_result: final_base,
        total_items: item_hashes.len(),
        verified_items: verified_count,
        failed_items,
        per_item_proofs_valid: all_valid,
        merkle_leaf_hashes: item_hashes,
    })
}

/// Generate a Merkle inclusion proof for the item at leaf_index
pub fn generate_merkle_proof(
    item_hashes: &[String],
    leaf_index: usize,
) -> Option<Vec<MerkleProofNode>> {
    if item_hashes.is_empty() || leaf_index >= item_hashes.len() {
        return None;
    }

    let mut level = item_hashes.to_vec();
    let mut proof = Vec::new();
    let mut index = leaf_index;

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        let sibling = if sibling_index < level.len() {
            level[sibling_index].clone()
        } else {
            // Duplicate last node (standard Merkle tree padding)
            level[index].clone()
        };

        proof.push(MerkleProofNode {
            sibling_hash: sibling,
            position: if index.is_multiple_of(2) {
                MerkleNodePosition::Right
            } else {
                MerkleNodePosition::Left
            },
        });

        // Build next level
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next_level.push(format_hash(format!("{}{}", pair[0], right).as_bytes()));
        }
        level = next_level;
        index /= 2;
    }

    Some(proof)
}

/// Verify a Merkle inclusion proof
pub fn verify_merkle_proof_for_item(
    leaf_hash: &str,
    proof: &[MerkleProofNode],
    expected_root: &str,
) -> bool {
    let mut current = leaf_hash.to_string();

    for node in proof {
        let combined = match node.position {
            MerkleNodePosition::Right => format!("{}{}", current, node.sibling_hash),
            MerkleNodePosition::Left => format!("{}{}", node.sibling_hash, current),
        };
        current = format_hash(combined.as_bytes());
    }

    current == expected_root
}

/// Build Merkle tree from evidence files (file-level hash tree)
pub fn build_merkle_tree(evidence_paths: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut hashes = Vec::new();
    for path in evidence_paths {
        let hash = hash_file(path)?;
        hashes.push(hash);
    }

    if hashes.is_empty() {
        return Ok(String::new());
    }
    Ok(compute_merkle_root(&hashes))
}

/// Verify a simple Merkle proof (for backward compatibility)
pub fn verify_merkle_proof(
    leaf_hash: &str,
    proof: &[String],
    root_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Convert simple string proof to MerkleProofNode (assumes right-sibling)
    let nodes: Vec<MerkleProofNode> = proof
        .iter()
        .map(|h| MerkleProofNode {
            sibling_hash: h.clone(),
            position: MerkleNodePosition::Right,
        })
        .collect();
    Ok(verify_merkle_proof_for_item(leaf_hash, &nodes, root_hash))
}

pub fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return format_hash(&[]);
    }

    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next_level.push(format_hash(format!("{}{}", pair[0], right).as_bytes()));
        }
        level = next_level;
    }

    level.remove(0)
}

// Keep old name for backward compatibility with existing call sites
#[allow(dead_code)]
fn merkle_root(hashes: &[String]) -> String {
    compute_merkle_root(hashes)
}

fn format_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub host_id: String,
    pub details: String,
    pub integrity_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub investigation_id: String,
    pub evidence_id: String,
    pub acquired_at: DateTime<Utc>,
    pub acquired_by: String,
    pub host_identifier: String,
    pub evidence_hash: String,
    pub merkle_root: Option<String>,
    pub events: Vec<CustodyEvent>,
}

pub fn generate_chain_of_custody(
    investigation_id: &str,
    host_id: &str,
    evidence_hash: &str,
    merkle_root: Option<&str>,
) -> ChainOfCustody {
    let now = Utc::now();
    let current_user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "forensic_analyst".to_string());

    let initial_event = CustodyEvent {
        timestamp: now,
        action: "ACQUISITION".to_string(),
        actor: current_user.clone(),
        host_id: host_id.to_string(),
        details: format!(
            "Initial forensic acquisition sealed under investigation '{}'",
            investigation_id
        ),
        integrity_hash: evidence_hash.to_string(),
    };

    ChainOfCustody {
        investigation_id: investigation_id.to_string(),
        evidence_id: format!("coc-{}", uuid::Uuid::new_v4().simple()),
        acquired_at: now,
        acquired_by: current_user,
        host_identifier: host_id.to_string(),
        evidence_hash: evidence_hash.to_string(),
        merkle_root: merkle_root.map(|s| s.to_string()),
        events: vec![initial_event],
    }
}

/// Development blockchain adapter (local JSON ledger, NOT a real blockchain)
/// This is a development-only adapter that records anchors locally.
/// In production, replace with a real blockchain adapter implementation.
pub fn anchor_to_blockchain(hash: &str) -> Result<BlockchainAnchor, Box<dyn std::error::Error>> {
    // Development-only: records to local manifest file
    // A real production adapter would submit to a verifiable public ledger
    let dev_adapter = DevelopmentBlockchainAdapter::new();
    let tx_id = dev_adapter.anchor(hash, "jockey-evidence")?;
    Ok(BlockchainAnchor {
        transaction_id: tx_id,
        block_height: 0, // Not applicable for development adapter
        timestamp: Utc::now(),
        network: "dev-local".to_string(),
    })
}

/// Verify blockchain anchor (development adapter)
pub fn verify_blockchain_anchor(
    anchor: &BlockchainAnchor,
    hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let dev_adapter = DevelopmentBlockchainAdapter::new();
    dev_adapter.verify(hash, &anchor.transaction_id)
}

#[test]
fn evaluates_field_comparison() {
    let expression = serde_json::json!({
        "op": "greater_equal",
        "left": "$pid",
        "right": 100
    });
    let record = serde_json::json!({ "pid": 101 });

    assert!(evaluate(&expression, &record).unwrap());
}

#[test]
fn evaluates_boolean_composition() {
    let expression = serde_json::json!({
        "op": "and",
        "left": { "op": "equal", "left": "$name", "right": "sshd" },
        "right": { "op": "greater", "left": "$pid", "right": 1 }
    });
    let record = serde_json::json!({ "name": "sshd", "pid": 42 });

    assert!(evaluate(&expression, &record).unwrap());
}

#[test]
fn unknown_field_is_an_error() {
    let expression = serde_json::json!({ "op": "equal", "left": "$missing", "right": true });
    let record = serde_json::json!({ "pid": 42 });

    assert!(evaluate(&expression, &record).is_err());
}
