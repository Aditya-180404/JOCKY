use jockey_runtime_evidence::{verify_evidence_deep, EvidenceCollector, VerificationStatus};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("jockey_test_{}_{}.json", name, nonce))
}

#[test]
fn test_deep_verification_clean_evidence() {
    let path = temp_path("clean");
    let path_str = path.to_str().unwrap();
    let meta_path_str = format!("{}.meta.json", path_str);

    let mut collector = EvidenceCollector::new("Triage_Deep_Test");
    collector.set_output_format("json", path_str);
    collector.add_record(serde_json::json!({
        "collector": "system_info",
        "hostname": "forensic-host-01",
        "os": "linux"
    }));
    collector.add_record(serde_json::json!({
        "collector": "processes",
        "pid": 1337,
        "name": "suspicious_daemon"
    }));
    collector.add_record(serde_json::json!({
        "collector": "network_connections",
        "proto": "tcp",
        "local": "127.0.0.1:4444",
        "state": "LISTEN"
    }));

    let meta = collector.finalize().expect("finalize must succeed");
    assert!(meta.merkle_root.is_some());

    let result =
        verify_evidence_deep(path_str, &meta_path_str).expect("verify_evidence_deep must execute");

    assert_eq!(result.total_items, 3);
    assert_eq!(result.verified_items, 3);
    assert!(result.per_item_proofs_valid);
    assert!(result.failed_items.is_empty());
    assert!(matches!(
        result.base_result.status,
        VerificationStatus::Verified
    ));
    assert_eq!(
        result.base_result.calculated_hash,
        result.base_result.stored_hash
    );
    assert_eq!(result.base_result.merkle_root_valid, Some(true));

    // Clean up
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&meta_path_str);
}

#[test]
fn test_deep_verification_detects_tampered_record() {
    let path = temp_path("tamper_rec");
    let path_str = path.to_str().unwrap();
    let meta_path_str = format!("{}.meta.json", path_str);

    let mut collector = EvidenceCollector::new("Tamper_Test");
    collector.set_output_format("json", path_str);
    collector.add_record(serde_json::json!({ "record": 1 }));
    collector.add_record(serde_json::json!({ "record": 2 }));
    collector.finalize().expect("finalize must succeed");

    // Tamper with the evidence file: replace "record": 1 with "record": 999
    let content = fs::read_to_string(&path).unwrap();
    let tampered = content.replace("\"record\": 1", "\"record\": 999");
    fs::write(&path, tampered).unwrap();

    let result =
        verify_evidence_deep(path_str, &meta_path_str).expect("verify_evidence_deep must execute");

    // Base verification should catch that SHA-256 does not match
    assert!(matches!(
        result.base_result.status,
        VerificationStatus::Tampered { .. }
    ));
    assert_ne!(
        result.base_result.calculated_hash,
        result.base_result.stored_hash
    );

    // Clean up
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&meta_path_str);
}

#[test]
fn test_deep_verification_single_item() {
    let path = temp_path("single");
    let path_str = path.to_str().unwrap();
    let meta_path_str = format!("{}.meta.json", path_str);

    let mut collector = EvidenceCollector::new("Single_Leaf_Test");
    collector.set_output_format("json", path_str);
    collector.add_record(serde_json::json!({
        "event": "rootkit_detected",
        "module": "hidden_driver.ko"
    }));
    collector.finalize().expect("finalize must succeed");

    let result =
        verify_evidence_deep(path_str, &meta_path_str).expect("verify_evidence_deep must execute");

    assert_eq!(result.total_items, 1);
    assert_eq!(result.verified_items, 1);
    assert!(result.per_item_proofs_valid);
    assert!(matches!(
        result.base_result.status,
        VerificationStatus::Verified
    ));

    // Clean up
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&meta_path_str);
}
