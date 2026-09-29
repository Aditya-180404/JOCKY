//! Canonical Evidence Bundle Architecture for JOCKY
//!
//! Provides the primary forensic data contracts:
//! - EvidenceRecord (with cryptographically sealed item hash and provenance)
//! - EvidenceProvenance (immutable chain-of-custody tracking)
//! - EvidenceManifest (Merkle root, leaf hashes, collector telemetry)
//! - EvidenceBundle (canonical exchange artifact across compiler, runtime, API, and workspace)
//! - Cryptographic verification with strict tamper detection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{compute_merkle_root, CollectionStatus, CollectorResult, EvidenceOrigin};

/// Immutable provenance metadata tracking source, compiler, and host identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceProvenance {
    pub origin: EvidenceOrigin,
    pub host_id: String,
    pub collector: String,
    pub collector_version: String,
    pub compiler_version: Option<String>,
    pub source_hash: Option<String>,
    pub artifact_hash: Option<String>,
    pub execution_mode: String,
    pub captured_at: DateTime<Utc>,
}

impl EvidenceProvenance {
    pub fn new(
        origin: EvidenceOrigin,
        host_id: &str,
        collector: &str,
        collector_version: &str,
        execution_mode: &str,
    ) -> Self {
        Self {
            origin,
            host_id: host_id.to_string(),
            collector: collector.to_string(),
            collector_version: collector_version.to_string(),
            compiler_version: Some("0.1.0".to_string()),
            source_hash: None,
            artifact_hash: None,
            execution_mode: execution_mode.to_string(),
            captured_at: Utc::now(),
        }
    }
}

/// A single atomic forensic record with an individual cryptographic digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub host_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub collector: String,
    pub record_type: String,
    pub payload: serde_json::Value,
    pub hash: String,
    pub provenance: EvidenceProvenance,
}

impl EvidenceRecord {
    /// Compute deterministic canonical record hash.
    pub fn compute_hash(
        evidence_id: &str,
        host_id: &str,
        timestamp: &DateTime<Utc>,
        source: &str,
        collector: &str,
        record_type: &str,
        payload: &serde_json::Value,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(evidence_id.as_bytes());
        hasher.update(b"|");
        hasher.update(host_id.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(b"|");
        hasher.update(source.as_bytes());
        hasher.update(b"|");
        hasher.update(collector.as_bytes());
        hasher.update(b"|");
        hasher.update(record_type.as_bytes());
        hasher.update(b"|");
        let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
        hasher.update(&payload_bytes);
        format!("{:x}", hasher.finalize())
    }

    /// Construct a new sealed EvidenceRecord with computed hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: Option<String>,
        host_id: &str,
        timestamp: Option<DateTime<Utc>>,
        source: &str,
        collector: &str,
        record_type: &str,
        payload: serde_json::Value,
        provenance: EvidenceProvenance,
    ) -> Self {
        let eid = evidence_id.unwrap_or_else(|| format!("ev-{}", Uuid::new_v4().simple()));
        let ts = timestamp.unwrap_or_else(Utc::now);
        let hash = Self::compute_hash(&eid, host_id, &ts, source, collector, record_type, &payload);

        Self {
            evidence_id: eid,
            host_id: host_id.to_string(),
            timestamp: ts,
            source: source.to_string(),
            collector: collector.to_string(),
            record_type: record_type.to_string(),
            payload,
            hash,
            provenance,
        }
    }

    /// Verify if this record's stored hash matches its current payload content.
    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_hash(
            &self.evidence_id,
            &self.host_id,
            &self.timestamp,
            &self.source,
            &self.collector,
            &self.record_type,
            &self.payload,
        );
        expected == self.hash
    }
}

/// Cryptographic manifest summarizing the evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceManifest {
    pub bundle_id: String,
    pub total_records: usize,
    pub record_hashes: Vec<String>,
    pub collector_results: Vec<CollectorResult>,
    pub created_at: DateTime<Utc>,
    pub sha256: String,
    pub merkle_root: String,
}

/// Canonical Evidence Bundle representing a completed forensic collection session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceBundle {
    pub bundle_id: String,
    pub investigation_id: String,
    pub host_id: String,
    pub collector_version: String,
    pub compiler_version: String,
    pub source_hash: Option<String>,
    pub artifact_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub collection_started_at: DateTime<Utc>,
    pub collection_finished_at: DateTime<Utc>,
    pub execution_mode: String,
    pub evidence_status: CollectionStatus,
    pub records: Vec<EvidenceRecord>,
    pub manifest: EvidenceManifest,
    pub sha256: String,
    pub merkle_root: String,
}

/// Result of complete evidence bundle verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerificationResult {
    pub valid: bool,
    pub status: String,
    pub total_records: usize,
    pub verified_records: usize,
    pub mismatched_records: Vec<(usize, String)>,
    pub merkle_root_matches: bool,
    pub sha256_matches: bool,
    pub manifest_valid: bool,
    pub expected_merkle_root: String,
    pub recomputed_merkle_root: String,
    pub expected_sha256: String,
    pub recomputed_sha256: String,
    pub failure_reason: Option<String>,
}

impl EvidenceBundle {
    /// Construct a canonical EvidenceBundle from raw records and collector telemetry.
    #[allow(clippy::too_many_arguments)]
    pub fn from_records(
        investigation_id: &str,
        host_id: &str,
        execution_mode: &str,
        collector_version: &str,
        compiler_version: &str,
        collection_started_at: DateTime<Utc>,
        collection_finished_at: DateTime<Utc>,
        collector_results: Vec<CollectorResult>,
        source_hash: Option<String>,
        artifact_hash: Option<String>,
        records: Vec<EvidenceRecord>,
    ) -> Self {
        let bundle_id = format!("bundle-{}", Uuid::new_v4().simple());
        let now = Utc::now();

        // Calculate record leaf hashes for Merkle tree
        let record_hashes: Vec<String> = records.iter().map(|r| r.hash.clone()).collect();
        let merkle_root = if record_hashes.is_empty() {
            String::new()
        } else {
            compute_merkle_root(&record_hashes)
        };

        // Determine collection status
        let has_failed = collector_results.iter().any(|c| {
            matches!(
                c.status,
                CollectionStatus::Failed
                    | CollectionStatus::NotFound
                    | CollectionStatus::Unsupported
                    | CollectionStatus::PermissionDenied
                    | CollectionStatus::RequiresElevation
            )
        });
        let has_success = collector_results
            .iter()
            .any(|c| c.status == CollectionStatus::Success);
        let has_partial = collector_results
            .iter()
            .any(|c| c.status == CollectionStatus::Partial);
        let evidence_status = if has_partial || (has_failed && has_success) {
            CollectionStatus::Partial
        } else if has_failed && !has_success {
            if collector_results
                .iter()
                .all(|c| c.status == CollectionStatus::NotFound)
            {
                CollectionStatus::NotFound
            } else if collector_results
                .iter()
                .all(|c| c.status == CollectionStatus::Unsupported)
            {
                CollectionStatus::Unsupported
            } else if collector_results
                .iter()
                .all(|c| c.status == CollectionStatus::PermissionDenied)
            {
                CollectionStatus::PermissionDenied
            } else if collector_results
                .iter()
                .all(|c| c.status == CollectionStatus::RequiresElevation)
            {
                CollectionStatus::RequiresElevation
            } else {
                CollectionStatus::Failed
            }
        } else {
            CollectionStatus::Success
        };

        // Compute overall payload hash over records JSON
        let records_bytes = serde_json::to_vec(&records).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&records_bytes);
        let sha256 = format!("{:x}", hasher.finalize());

        let manifest = EvidenceManifest {
            bundle_id: bundle_id.clone(),
            total_records: records.len(),
            record_hashes: record_hashes.clone(),
            collector_results,
            created_at: now,
            sha256: sha256.clone(),
            merkle_root: merkle_root.clone(),
        };

        Self {
            bundle_id,
            investigation_id: investigation_id.to_string(),
            host_id: host_id.to_string(),
            collector_version: collector_version.to_string(),
            compiler_version: compiler_version.to_string(),
            source_hash,
            artifact_hash,
            created_at: now,
            collection_started_at,
            collection_finished_at,
            execution_mode: execution_mode.to_string(),
            evidence_status,
            records,
            manifest,
            sha256,
            merkle_root,
        }
    }

    /// Deep cryptographic verification of the bundle, including manifest,
    /// record-level hash checks, Merkle root tree reconstruction, and bundle payload digest.
    pub fn verify(&self) -> BundleVerificationResult {
        let mut mismatched = Vec::new();
        let mut recomputed_leaf_hashes = Vec::new();

        // 1. Verify individual record hashes
        for (idx, record) in self.records.iter().enumerate() {
            if !record.verify_hash() {
                mismatched.push((
                    idx,
                    format!(
                        "Record {} ({}) has invalid cryptographic hash",
                        idx, record.evidence_id
                    ),
                ));
            }
            recomputed_leaf_hashes.push(record.hash.clone());
        }

        // 2. Recompute Merkle root
        let recomputed_merkle = if recomputed_leaf_hashes.is_empty() {
            String::new()
        } else {
            compute_merkle_root(&recomputed_leaf_hashes)
        };
        let merkle_root_matches =
            recomputed_merkle == self.merkle_root && self.merkle_root == self.manifest.merkle_root;

        // 3. Recompute bundle payload SHA-256
        let records_bytes = serde_json::to_vec(&self.records).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&records_bytes);
        let recomputed_sha256 = format!("{:x}", hasher.finalize());
        let sha256_matches =
            recomputed_sha256 == self.sha256 && self.sha256 == self.manifest.sha256;

        // 4. Verify manifest integrity
        let manifest_valid = self.manifest.bundle_id == self.bundle_id
            && self.manifest.total_records == self.records.len()
            && self.manifest.record_hashes == recomputed_leaf_hashes;

        let verified_records = self.records.len().saturating_sub(mismatched.len());
        let valid =
            mismatched.is_empty() && merkle_root_matches && sha256_matches && manifest_valid;

        let failure_reason = if !valid {
            if !mismatched.is_empty() {
                Some(format!(
                    "Tamper detected: {} records have altered content",
                    mismatched.len()
                ))
            } else if !merkle_root_matches {
                Some("Tamper detected: Merkle root mismatch".to_string())
            } else if !sha256_matches {
                Some("Tamper detected: Bundle SHA-256 digest mismatch".to_string())
            } else {
                Some("Tamper detected: Manifest inconsistencies detected".to_string())
            }
        } else {
            None
        };

        let status = if valid {
            "VALID".to_string()
        } else {
            "TAMPERED".to_string()
        };

        BundleVerificationResult {
            valid,
            status,
            total_records: self.records.len(),
            verified_records,
            mismatched_records: mismatched,
            merkle_root_matches,
            sha256_matches,
            manifest_valid,
            expected_merkle_root: self.merkle_root.clone(),
            recomputed_merkle_root: recomputed_merkle,
            expected_sha256: self.sha256.clone(),
            recomputed_sha256,
            failure_reason,
        }
    }

    /// Parse and verify a JSON-encoded bundle string.
    pub fn verify_json(json_str: &str) -> Result<BundleVerificationResult, serde_json::Error> {
        let bundle: EvidenceBundle = serde_json::from_str(json_str)?;
        Ok(bundle.verify())
    }
}
