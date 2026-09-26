#![cfg(feature = "llvm")]

use jockey_backend::llvm::LlvmBackend;
use jockey_ir::BuildConfig;
use jockey_mir::{
    MirBasicBlock, MirCompareOp, MirFunction, MirInstruction, MirLocal, MirProgram, MirProvenance,
    MirTerminator, MirType,
};
use std::collections::HashSet;

/// Verifies that every MIR instruction variant — including the three new
/// collectors (MemoryRegions, Registry, Artifacts) — produces valid LLVM IR.
#[test]
fn test_every_mir_instruction_has_explicit_llvm_lowering() {
    let locals = vec![
        MirLocal {
            id: 0,
            name: "c_int".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 1,
            name: "c_bool".to_string(),
            ty: MirType::Bool,
        },
        MirLocal {
            id: 2,
            name: "c_str".to_string(),
            ty: MirType::String,
        },
        MirLocal {
            id: 3,
            name: "ptr_slot".to_string(),
            ty: MirType::Pointer,
        },
        MirLocal {
            id: 4,
            name: "loaded_val".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 5,
            name: "ctx".to_string(),
            ty: MirType::EvidenceContext,
        },
        MirLocal {
            id: 6,
            name: "sys_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 7,
            name: "proc_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 8,
            name: "net_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 9,
            name: "files_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 10,
            name: "logs_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 11,
            name: "drv_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 12,
            name: "hash_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 13,
            name: "timeline_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 14,
            name: "cmp_res".to_string(),
            ty: MirType::Bool,
        },
        MirLocal {
            id: 15,
            name: "call_res".to_string(),
            ty: MirType::Int32,
        },
        // New collector result locals
        MirLocal {
            id: 16,
            name: "mem_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 17,
            name: "reg_res".to_string(),
            ty: MirType::Int32,
        },
        MirLocal {
            id: 18,
            name: "art_res".to_string(),
            ty: MirType::Int32,
        },
    ];

    let instructions = vec![
        // 1. ConstInt
        MirInstruction::ConstInt { dest: 0, value: 42 },
        // 2. ConstBool
        MirInstruction::ConstBool {
            dest: 1,
            value: true,
        },
        // 3. ConstString
        MirInstruction::ConstString {
            dest: 2,
            value: "sample_str".to_string(),
        },
        // 4. Alloc
        MirInstruction::Alloc {
            dest: 3,
            ty: MirType::Int32,
        },
        // 5. Store
        MirInstruction::Store { dest: 3, src: 0 },
        // 6. Load
        MirInstruction::Load { dest: 4, src: 3 },
        // 7. EvidenceInit
        MirInstruction::EvidenceInit {
            dest: 5,
            investigation_name: "completeness_test".to_string(),
            source_hash: "completeness_source".to_string(),
        },
        // 8. CollectSystemInfo
        MirInstruction::CollectSystemInfo { dest: 6, ctx: 5 },
        // 9. CollectProcesses
        MirInstruction::CollectProcesses {
            dest: 7,
            ctx: 5,
            fields_json: "[\"name\"]".to_string(),
            hash_algo: None,
        },
        // 10. CollectNetwork
        MirInstruction::CollectNetwork { dest: 8, ctx: 5 },
        // 11. CollectFiles
        MirInstruction::CollectFiles {
            dest: 9,
            ctx: 5,
            path: "/tmp".to_string(),
            recursive: false,
            hash_algo: "sha256".to_string(),
        },
        // 12. CollectLogs
        MirInstruction::CollectLogs {
            dest: 10,
            ctx: 5,
            source: "system".to_string(),
        },
        // 13. CollectDrivers
        MirInstruction::CollectDrivers { dest: 11, ctx: 5 },
        // 14. EvidenceAddFilter
        MirInstruction::EvidenceAddFilter {
            ctx: 5,
            condition_json: "{\"status\": 0}".to_string(),
        },
        // 15. EvidenceAddWhere
        MirInstruction::EvidenceAddWhere {
            ctx: 5,
            condition_json: "{\"pid\": 1}".to_string(),
        },
        // 16. EvidenceSetLimit
        MirInstruction::EvidenceSetLimit { ctx: 5, limit: 100 },
        // 17. EvidenceComputeHash
        MirInstruction::EvidenceComputeHash {
            dest: 12,
            ctx: 5,
            algorithm: "sha256".to_string(),
        },
        // 18. EvidenceGenerateTimeline
        MirInstruction::EvidenceGenerateTimeline { dest: 13, ctx: 5 },
        // 19. EvidenceExport
        MirInstruction::EvidenceExport {
            ctx: 5,
            format: "json".to_string(),
            path: "complete.json".to_string(),
        },
        // 20. Compare
        MirInstruction::Compare {
            dest: 14,
            op: MirCompareOp::Eq,
            left: 0,
            right: 4,
        },
        // 21. CallRuntime
        MirInstruction::CallRuntime {
            dest: Some(15),
            function_name: "jockey_rt_collect_system".to_string(),
            args: vec![5],
        },
        // 22. CollectMemoryRegions (NEW)
        MirInstruction::CollectMemoryRegions {
            dest: 16,
            ctx: 5,
            pid: 1234,
        },
        // 23. CollectRegistry (NEW)
        MirInstruction::CollectRegistry {
            dest: 17,
            ctx: 5,
            hive: "HKLM".to_string(),
            key_path: "SOFTWARE\\Test".to_string(),
        },
        // 24. CollectArtifacts (NEW)
        MirInstruction::CollectArtifacts {
            dest: 18,
            ctx: 5,
            artifact_type: "prefetch".to_string(),
            path: "C:\\Windows\\Prefetch".to_string(),
        },
    ];

    let mir = MirProgram {
        name: "mir_completeness".to_string(),
        target: Some("linux".to_string()),
        functions: vec![MirFunction {
            name: "main".to_string(),
            return_type: MirType::Int32,
            locals,
            blocks: vec![MirBasicBlock {
                id: 0,
                name: "entry".to_string(),
                instructions,
                terminator: MirTerminator::Return { value: Some(0) },
            }],
        }],
        capabilities: HashSet::new(),
        provenance: MirProvenance {
            source_hash: "src_sha".to_string(),
            hir_hash: "hir_sha".to_string(),
            mir_hash: "mir_sha".to_string(),
            compiler_version: "0.1.0".to_string(),
            created_at: "2026-09-24".to_string(),
        },
    };

    let backend = LlvmBackend::new(BuildConfig::default());
    let ir = backend
        .generate_llvm_ir(&mir)
        .expect("LLVM IR generation failed");

    // ── Programmatic LLVM lowering assertions ─────────────────────────────────────────────
    assert!(
        ir.contains("store i32 42, ptr %loc_0_c_int"),
        "ConstInt lowering missing"
    );
    assert!(
        ir.contains("store i1 true, ptr %loc_1_c_bool"),
        "ConstBool lowering missing"
    );
    assert!(
        ir.contains("store ptr") && ir.contains(".str."),
        "ConstString lowering missing"
    );
    assert!(
        ir.contains("%loc_3_ptr_slot = alloca ptr"),
        "Alloc lowering missing"
    );
    assert!(ir.contains("store ptr"), "Store lowering missing");
    assert!(ir.contains("load i32"), "Load lowering missing");
    assert!(
        ir.contains("call ptr @jockey_rt_evidence_init"),
        "EvidenceInit lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_system"),
        "CollectSystemInfo lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_processes"),
        "CollectProcesses lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_network"),
        "CollectNetwork lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_files"),
        "CollectFiles lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_logs"),
        "CollectLogs lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_drivers"),
        "CollectDrivers lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_filter"),
        "EvidenceAddFilter lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_where"),
        "EvidenceAddWhere lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_limit"),
        "EvidenceSetLimit lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_compute_hash"),
        "EvidenceComputeHash lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_generate_timeline"),
        "EvidenceGenerateTimeline lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_evidence_export"),
        "EvidenceExport lowering missing"
    );
    assert!(ir.contains("icmp eq i32"), "Compare lowering missing");
    assert!(
        ir.contains("call void @jockey_rt_evidence_free"),
        "EvidenceFree on return missing"
    );
    assert!(ir.contains("ret i32"), "Return value lowering missing");

    // ── Forensic collector lowering assertions ──────────────────────
    assert!(
        ir.contains("call i32 @jockey_rt_collect_memory_regions"),
        "CollectMemoryRegions lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_registry"),
        "CollectRegistry lowering missing"
    );
    assert!(
        ir.contains("call i32 @jockey_rt_collect_artifacts"),
        "CollectArtifacts lowering missing"
    );

    // ── Assembler validation via Clang ────────────────────────────────
    let mut cmd = std::process::Command::new("clang");
    cmd.args(["-x", "ir", "-", "-c", "-o", "/dev/null"]);
    cmd.stdin(std::process::Stdio::piped());
    if let Ok(mut child) = cmd.spawn() {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(ir.as_bytes());
        }
        let status = child.wait().expect("Clang process wait failed");
        assert!(
            status.success(),
            "Clang must successfully validate generated programmatic LLVM IR"
        );
    }
}

/// Exhaustive compile-time test ensuring every MirInstruction variant has an explicit arm
#[test]
fn test_instruction_enum_exhaustive_match() {
    fn check_exhaustive(inst: &MirInstruction) {
        match inst {
            MirInstruction::ConstInt { .. } => {}
            MirInstruction::ConstString { .. } => {}
            MirInstruction::ConstBool { .. } => {}
            MirInstruction::Alloc { .. } => {}
            MirInstruction::Load { .. } => {}
            MirInstruction::Store { .. } => {}
            MirInstruction::EvidenceInit { .. } => {}
            MirInstruction::EvidenceAddFilter { .. } => {}
            MirInstruction::EvidenceAddWhere { .. } => {}
            MirInstruction::EvidenceSetLimit { .. } => {}
            MirInstruction::EvidenceComputeHash { .. } => {}
            MirInstruction::EvidenceGenerateTimeline { .. } => {}
            MirInstruction::EvidenceExport { .. } => {}
            MirInstruction::CollectSystemInfo { .. } => {}
            MirInstruction::CollectProcesses { .. } => {}
            MirInstruction::CollectProcessTree { .. } => {}
            MirInstruction::CollectProcessModules { .. } => {}
            MirInstruction::CollectProcessHandles { .. } => {}
            MirInstruction::CollectDeletedExecutables { .. } => {}
            MirInstruction::CollectNetwork { .. } => {}
            MirInstruction::CollectFiles { .. } => {}
            MirInstruction::CollectLogs { .. } => {}
            MirInstruction::CollectDrivers { .. } => {}
            MirInstruction::CollectMemoryRegions { .. } => {}
            MirInstruction::CollectRegistry { .. } => {}
            MirInstruction::CollectArtifacts { .. } => {}
            MirInstruction::InvokeCapability { .. } => {}
            MirInstruction::Compare { .. } => {}
            MirInstruction::CallRuntime { .. } => {}
        }
    }

    let dummy = MirInstruction::ConstInt { dest: 0, value: 0 };
    check_exhaustive(&dummy);
}
