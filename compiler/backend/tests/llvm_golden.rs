use jockey_backend::llvm::LlvmBackend;
use jockey_ir::BuildConfig;
use jockey_mir::{
    MirBasicBlock, MirFunction, MirInstruction, MirLocal, MirProgram, MirProvenance, MirTerminator,
    MirType,
};
use std::collections::HashSet;
use std::process::Command;

#[test]
fn test_llvm_golden_process_triage_ir() {
    let locals = vec![
        MirLocal {
            id: 0,
            name: "ctx".to_string(),
            ty: MirType::EvidenceContext,
        },
        MirLocal {
            id: 1,
            name: "proc_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 2,
            name: "ret".to_string(),
            ty: MirType::Int32,
        },
    ];

    let instructions = vec![
        MirInstruction::EvidenceInit {
            dest: 0,
            investigation_name: "process_triage_golden".to_string(),
            source_hash: "golden_src".to_string(),
        },
        MirInstruction::CollectProcesses {
            dest: 1,
            ctx: 0,
            fields_json: "[\"pid\",\"name\",\"cmdline\",\"status\"]".to_string(),
            hash_algo: None,
        },
        MirInstruction::EvidenceAddFilter {
            ctx: 0,
            condition_json: "{\"status\": \"running\"}".to_string(),
        },
        MirInstruction::EvidenceSetLimit { ctx: 0, limit: 50 },
        MirInstruction::EvidenceExport {
            ctx: 0,
            format: "json".to_string(),
            path: "process_triage_evidence.json".to_string(),
        },
        MirInstruction::ConstInt { dest: 2, value: 0 },
    ];

    let mir = MirProgram {
        name: "golden_triage".to_string(),
        target: Some("linux".to_string()),
        functions: vec![MirFunction {
            name: "main".to_string(),
            return_type: MirType::Int32,
            locals,
            blocks: vec![MirBasicBlock {
                id: 0,
                name: "entry".to_string(),
                instructions,
                terminator: MirTerminator::Return { value: Some(2) },
            }],
        }],
        capabilities: HashSet::new(),
        provenance: MirProvenance {
            source_hash: "golden_src".to_string(),
            hir_hash: "golden_hir".to_string(),
            mir_hash: "golden_mir".to_string(),
            compiler_version: "0.1.0".to_string(),
            created_at: "2026-09-24".to_string(),
        },
    };

    let backend = LlvmBackend::new(BuildConfig::default());
    let ir = backend
        .generate_llvm_ir(&mir)
        .expect("Failed to generate IR");

    // Golden verification
    assert!(ir.contains("; ModuleID = 'golden_triage'"));
    assert!(ir.contains("target datalayout = \"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128\""));
    assert!(ir.contains("target triple = \"x86_64-pc-linux-gnu\""));
    assert!(ir.contains("declare ptr @jockey_rt_evidence_init(ptr, ptr)"));
    assert!(ir.contains("declare i32 @jockey_rt_collect_processes(ptr, ptr, ptr)"));
    assert!(ir.contains("declare i32 @jockey_rt_evidence_filter(ptr, ptr)"));
    assert!(ir.contains("declare i32 @jockey_rt_evidence_limit(ptr, i64)"));
    assert!(ir.contains("declare i32 @jockey_rt_evidence_export(ptr, ptr, ptr)"));
    assert!(ir.contains("declare void @jockey_rt_evidence_free(ptr)"));
    assert!(ir.contains("call ptr @jockey_rt_evidence_init"));
    assert!(ir.contains("call i32 @jockey_rt_collect_processes"));
    assert!(ir.contains("call i32 @jockey_rt_evidence_filter"));
    assert!(ir.contains("call i32 @jockey_rt_evidence_limit"));
    assert!(ir.contains("call i32 @jockey_rt_evidence_export"));
    assert!(ir.contains("call void @jockey_rt_evidence_free"));
    assert!(ir.contains("ret i32"));

    // Verify clang parses and compiles this IR to an object file with zero errors
    let clang_res = Command::new("clang")
        .args(["-x", "ir", "-", "-c", "-o", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut child) = clang_res {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(ir.as_bytes());
        }
        let status = child.wait().expect("Clang process failed");
        assert!(
            status.success(),
            "Clang must successfully validate generated LLVM IR"
        );
    }
}
