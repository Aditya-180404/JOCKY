use std::collections::HashSet;
use traceforge_backend::llvm::LlvmBackend;
use traceforge_ir::BuildConfig;
use traceforge_mir::{
    MirBasicBlock, MirCompareOp, MirFunction, MirInstruction, MirLocal, MirProgram,
    MirProvenance, MirTerminator, MirType,
};

#[test]
fn test_every_mir_instruction_has_explicit_llvm_lowering() {
    let locals = vec![
        MirLocal { id: 0, name: "c_int".to_string(), ty: MirType::Int32 },
        MirLocal { id: 1, name: "c_bool".to_string(), ty: MirType::Bool },
        MirLocal { id: 2, name: "c_str".to_string(), ty: MirType::String },
        MirLocal { id: 3, name: "ptr_slot".to_string(), ty: MirType::Pointer },
        MirLocal { id: 4, name: "loaded_val".to_string(), ty: MirType::Int32 },
        MirLocal { id: 5, name: "ctx".to_string(), ty: MirType::EvidenceContext },
        MirLocal { id: 6, name: "sys_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 7, name: "proc_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 8, name: "net_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 9, name: "files_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 10, name: "logs_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 11, name: "drv_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 12, name: "hash_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 13, name: "timeline_res".to_string(), ty: MirType::Int32 },
        MirLocal { id: 14, name: "cmp_res".to_string(), ty: MirType::Bool },
        MirLocal { id: 15, name: "call_res".to_string(), ty: MirType::Int32 },
    ];

    let instructions = vec![
        // 1. ConstInt
        MirInstruction::ConstInt { dest: 0, value: 42 },
        // 2. ConstBool
        MirInstruction::ConstBool { dest: 1, value: true },
        // 3. ConstString
        MirInstruction::ConstString { dest: 2, value: "sample_str".to_string() },
        // 4. Alloc
        MirInstruction::Alloc { dest: 3, ty: MirType::Int32 },
        // 5. Store
        MirInstruction::Store { dest: 3, src: 0 },
        // 6. Load
        MirInstruction::Load { dest: 4, src: 3 },
        // 7. EvidenceInit
        MirInstruction::EvidenceInit { dest: 5, investigation_name: "completeness_test".to_string() },
        // 8. CollectSystemInfo
        MirInstruction::CollectSystemInfo { dest: 6, ctx: 5 },
        // 9. CollectProcesses
        MirInstruction::CollectProcesses { dest: 7, ctx: 5, fields_json: "[\"name\"]".to_string(), hash_algo: None },
        // 10. CollectNetwork
        MirInstruction::CollectNetwork { dest: 8, ctx: 5 },
        // 11. CollectFiles
        MirInstruction::CollectFiles { dest: 9, ctx: 5, path: "/tmp".to_string(), recursive: false, hash_algo: "sha256".to_string() },
        // 12. CollectLogs
        MirInstruction::CollectLogs { dest: 10, ctx: 5, source: "system".to_string() },
        // 13. CollectDrivers
        MirInstruction::CollectDrivers { dest: 11, ctx: 5 },
        // 14. EvidenceAddFilter
        MirInstruction::EvidenceAddFilter { ctx: 5, condition_json: "{\"status\": 0}".to_string() },
        // 15. EvidenceAddWhere
        MirInstruction::EvidenceAddWhere { ctx: 5, condition_json: "{\"pid\": 1}".to_string() },
        // 16. EvidenceSetLimit
        MirInstruction::EvidenceSetLimit { ctx: 5, limit: 100 },
        // 17. EvidenceComputeHash
        MirInstruction::EvidenceComputeHash { dest: 12, ctx: 5, algorithm: "sha256".to_string() },
        // 18. EvidenceGenerateTimeline
        MirInstruction::EvidenceGenerateTimeline { dest: 13, ctx: 5 },
        // 19. EvidenceExport
        MirInstruction::EvidenceExport { ctx: 5, format: "json".to_string(), path: "complete.json".to_string() },
        // 20. Compare
        MirInstruction::Compare { dest: 14, op: MirCompareOp::Eq, left: 0, right: 4 },
        // 21. CallRuntime
        MirInstruction::CallRuntime { dest: Some(15), function_name: "traceforge_rt_collect_system".to_string(), args: vec![5] },
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
    let ir = backend.generate_llvm_ir(&mir).expect("LLVM IR generation failed");

    // Verify all 21 MIR instruction lowering outcomes are present in LLVM IR
    assert!(ir.contains("add i32 0, 42"), "ConstInt lowering missing");
    assert!(ir.contains("icmp eq i32 1, 1"), "ConstBool lowering missing");
    assert!(ir.contains("getelementptr inbounds [11 x i8]"), "ConstString lowering missing");
    assert!(ir.contains("%l3 = alloca i32"), "Alloc lowering missing");
    assert!(ir.contains("store i32 %l0, ptr %l3"), "Store lowering missing");
    assert!(ir.contains("%l4 = load i32, ptr %l3"), "Load lowering missing");
    assert!(ir.contains("call ptr @traceforge_rt_evidence_init"), "EvidenceInit lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_system"), "CollectSystemInfo lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_processes"), "CollectProcesses lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_network"), "CollectNetwork lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_files"), "CollectFiles lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_logs"), "CollectLogs lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_collect_drivers"), "CollectDrivers lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_filter"), "EvidenceAddFilter lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_where"), "EvidenceAddWhere lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_limit"), "EvidenceSetLimit lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_compute_hash"), "EvidenceComputeHash lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_generate_timeline"), "EvidenceGenerateTimeline lowering missing");
    assert!(ir.contains("call i32 @traceforge_rt_evidence_export"), "EvidenceExport lowering missing");
    assert!(ir.contains("icmp eq i32 %l0, %l4"), "Compare lowering missing");
    assert!(ir.contains("call void @traceforge_rt_evidence_free"), "EvidenceFree on return missing");
    assert!(ir.contains("ret i32 %l0"), "Return value lowering missing");
}
