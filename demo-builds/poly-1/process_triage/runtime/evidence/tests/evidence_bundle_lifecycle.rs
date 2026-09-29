use chrono::Utc;
use jocky_runtime_evidence::{
    bundle::{EvidenceBundle, EvidenceProvenance, EvidenceRecord},
    CollectionStatus, EvidenceCollector, EvidenceOrigin,
};
use serde_json::json;

#[test]
fn test_canonical_evidence_bundle_generation_and_tamper_detection() {
    // 1. Generate evidence
    let mut collector = EvidenceCollector::new("investigation-alpha");
    collector.set_evidence_origin(EvidenceOrigin::Real);

    collector.add_record(json!({
        "source": "process",
        "event_type": "process_observed",
        "pid": 412,
        "name": "sshd",
        "path": "/usr/sbin/sshd",
        "user": "root"
    }));

    collector.add_record(json!({
        "source": "network",
        "event_type": "connection_listen",
        "protocol": "TCP",
        "local_address": "0.0.0.0:22",
        "state": "LISTEN",
        "pid": 412
    }));

    collector.record_collector_result("process", CollectionStatus::Success, 1, None, None);
    collector.record_collector_result("network", CollectionStatus::Success, 1, None, None);

    // 2. Build canonical EvidenceBundle
    let bundle = collector.to_bundle();

    // Verify bundle metadata
    assert_eq!(bundle.investigation_id, "investigation-alpha");
    assert_eq!(bundle.records.len(), 2);
    assert_eq!(bundle.manifest.total_records, 2);
    assert_eq!(bundle.evidence_status, CollectionStatus::Success);
    assert!(
        !bundle.merkle_root.is_empty(),
        "Merkle root must be computed"
    );
    assert!(
        !bundle.sha256.is_empty(),
        "Bundle payload SHA-256 must be computed"
    );

    // 3. Verify untouched bundle
    let res = bundle.verify();
    assert!(res.valid, "Untouched bundle must pass verification");
    assert_eq!(res.status, "VALID");
    assert_eq!(res.verified_records, 2);
    assert!(res.mismatched_records.is_empty());
    assert!(res.merkle_root_matches);
    assert!(res.sha256_matches);
    assert!(res.manifest_valid);

    // 4. Test serialization / deserialization round-trip (e.g. transfer/upload)
    let json_bytes = serde_json::to_vec_pretty(&bundle).expect("Serialization failed");
    let restored_res = EvidenceBundle::verify_json(std::str::from_utf8(&json_bytes).unwrap())
        .expect("Verification of restored bundle failed");
    assert!(
        restored_res.valid,
        "Restored bundle from JSON must pass verification"
    );

    // 5. Mutate one byte in a record's payload (Tamper test)
    let mut tampered_bundle = bundle.clone();
    tampered_bundle.records[0].payload["path"] = json!("/usr/sbin/sshd_backdoored");

    let tampered_res = tampered_bundle.verify();
    assert!(
        !tampered_res.valid,
        "Tampered payload MUST fail verification"
    );
    assert_eq!(tampered_res.status, "TAMPERED");
    assert_eq!(tampered_res.mismatched_records.len(), 1);
    assert!(tampered_res.failure_reason.is_some());

    // 6. Mutate Merkle root in bundle
    let mut tampered_merkle = bundle.clone();
    tampered_merkle.merkle_root =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let merkle_res = tampered_merkle.verify();
    assert!(
        !merkle_res.valid,
        "Tampered Merkle root MUST fail verification"
    );
    assert!(!merkle_res.merkle_root_matches);

    // 7. Mutate bundle SHA-256
    let mut tampered_sha = bundle.clone();
    tampered_sha.sha256 =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string();
    let sha_res = tampered_sha.verify();
    assert!(
        !sha_res.valid,
        "Tampered bundle SHA-256 MUST fail verification"
    );
    assert!(!sha_res.sha256_matches);
}

#[test]
fn test_provenance_immutability() {
    let prov = EvidenceProvenance::new(
        EvidenceOrigin::Real,
        "victim-workstation-01",
        "memory_inspector",
        "1.0.0",
        "native",
    );
    assert_eq!(prov.origin, EvidenceOrigin::Real);
    assert_eq!(prov.host_id, "victim-workstation-01");
    assert_eq!(prov.execution_mode, "native");

    let record = EvidenceRecord::new(
        Some("rec-test-01".to_string()),
        "victim-workstation-01",
        Some(Utc::now()),
        "kernel",
        "driver_audit",
        "driver_info",
        json!({"driver_name": "procmon.sys", "signed": true}),
        prov,
    );

    assert!(record.verify_hash());
}
