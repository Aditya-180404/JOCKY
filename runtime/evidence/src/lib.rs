//! TraceForge Runtime - Evidence collection, integrity, and verification

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use chrono::{DateTime, Utc};

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
    pub merkle_proof: Option<Vec<String>>,
    pub blockchain_anchor: Option<BlockchainAnchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    pub transaction_id: String,
    pub block_height: u64,
    pub timestamp: DateTime<Utc>,
    pub network: String,
}

pub struct EvidenceCollector {
    investigation_name: String,
    tool_name: String,
    tool_version: String,
    host_identifier: String,
    output_format: String,
    output_path: String,
    data: Vec<serde_json::Value>,
    filters: Vec<serde_json::Value>,
    where_conditions: Vec<serde_json::Value>,
    limit: Option<usize>,
    metadata: HashMap<String, serde_json::Value>,
}

impl EvidenceCollector {
    pub fn new(investigation_name: &str) -> Self {
        Self {
            investigation_name: investigation_name.to_string(),
            tool_name: "traceforge-tool".to_string(),
            tool_version: "0.1.0".to_string(),
            host_identifier: whoami::devicename(),
            output_format: "json".to_string(),
            output_path: format!("{}.json", investigation_name),
            data: Vec::new(),
            filters: Vec::new(),
            where_conditions: Vec::new(),
            limit: None,
            metadata: HashMap::new(),
        }
    }

    pub fn collect_system_info(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let info = traceforge_runtime_system::collect_system_info()?;
        self.data.push(info);
        Ok(())
    }

    pub fn collect_processes(&mut self, fields: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let processes = traceforge_runtime_process::enumerate_processes(&fields)?;
        for proc in processes {
            self.data.push(proc);
        }
        Ok(())
    }

    pub fn collect_network_connections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let connections = traceforge_runtime_network::enumerate_connections()?;
        for conn in connections {
            self.data.push(conn);
        }
        Ok(())
    }

    pub fn collect_files(&mut self, path: &str, recursive: bool, hash: &str) -> Result<(), Box<dyn std::error::Error>> {
        let files = traceforge_runtime_filesystem::enumerate_files(path, recursive, hash)?;
        for file in files {
            self.data.push(file);
        }
        Ok(())
    }

    pub fn collect_logs(&mut self, source: &str) -> Result<(), Box<dyn std::error::Error>> {
        let logs = traceforge_runtime_logs::collect_logs(source)?;
        for log in logs {
            self.data.push(log);
        }
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

    pub fn finalize(&mut self) -> Result<EvidenceMetadata, Box<dyn std::error::Error>> {
        // Apply filters
        self.apply_filters();

        // Apply where conditions
        self.apply_where();

        // Apply limit
        if let Some(limit) = self.limit {
            self.data.truncate(limit);
        }

        // Serialize evidence
        let evidence_json = serde_json::to_vec_pretty(&self.data)?;

        // Calculate SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&evidence_json);
        let evidence_hash = format!("{:x}", hasher.finalize());
        let evidence_size = evidence_json.len() as u64;

        // Write evidence file
        let mut file = fs::File::create(&self.output_path)?;
        file.write_all(&evidence_json)?;

        // Create metadata
        let metadata = EvidenceMetadata {
            investigation_name: self.investigation_name.clone(),
            tool_name: self.tool_name.clone(),
            tool_version: self.tool_version.clone(),
            host_identifier: self.host_identifier.clone(),
            collection_time: Utc::now(),
            evidence_hash,
            evidence_size,
            merkle_root: None,
            merkle_proof: None,
            blockchain_anchor: None,
        };

        // Write metadata sidecar
        let meta_path = format!("{}.meta.json", self.output_path);
        let meta_json = serde_json::to_vec_pretty(&metadata)?;
        fs::write(meta_path, meta_json)?;

        println!("Evidence written to: {}", self.output_path);
        println!("SHA-256: {}", metadata.evidence_hash);
        println!("Size: {} bytes", metadata.evidence_size);

        Ok(metadata)
    }

    fn apply_filters(&mut self) {
        // Filter implementation would go here
        // For now, just a placeholder
    }

    fn apply_where(&mut self) {
        // Where implementation would go here
    }
}

/// Calculate SHA-256 hash of a file
pub fn hash_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify evidence integrity
pub fn verify_evidence(evidence_path: &str, metadata_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // Read evidence file
    let evidence_bytes = fs::read(evidence_path)?;

    // Calculate hash
    let mut hasher = Sha256::new();
    hasher.update(&evidence_bytes);
    let calculated_hash = format!("{:x}", hasher.finalize());

    // Read metadata
    let meta_bytes = fs::read(metadata_path)?;
    let metadata: EvidenceMetadata = serde_json::from_slice(&meta_bytes)?;

    // Compare
    Ok(calculated_hash == metadata.evidence_hash)
}

/// Build Merkle tree from evidence files
pub fn build_merkle_tree(evidence_paths: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut hashes = Vec::new();
    for path in evidence_paths {
        let hash = hash_file(path)?;
        hashes.push(hash);
    }

    Ok(merkle_root(&hashes))
}

/// Verify Merkle proof
pub fn verify_merkle_proof(
    leaf_hash: &str,
    proof: &[String],
    root_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut hashes = Vec::with_capacity(proof.len() + 1);
    hashes.push(leaf_hash.to_string());
    hashes.extend_from_slice(proof);
    Ok(merkle_root(&hashes) == root_hash)
}

fn merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return format_hash(&[]);
    }

    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next_level.push(format_hash(format!("{}{}", pair[0], right).as_bytes()));
        }
        level = next_level;
    }

    level.remove(0)
}

fn format_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Mock blockchain anchor (for demonstration)
pub fn anchor_to_blockchain(hash: &str) -> Result<BlockchainAnchor, Box<dyn std::error::Error>> {
    // In production, this would submit to a real blockchain
    // For MVP, we create a mock anchor
    Ok(BlockchainAnchor {
        transaction_id: format!("mock_tx_{}", &hash[..16]),
        block_height: 12345,
        timestamp: Utc::now(),
        network: "mock".to_string(),
    })
}

/// Verify blockchain anchor
pub fn verify_blockchain_anchor(anchor: &BlockchainAnchor, hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // In production, this would verify against the blockchain
    // For MVP, we just check the mock format
    Ok(anchor.transaction_id == format!("mock_tx_{}", &hash[..16]))
}