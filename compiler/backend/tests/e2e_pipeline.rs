//! End-to-end pipeline test: `.tfg` source → Lexer → Parser → AST →
//! Semantic → IrInvestigation → HIR → MIR → LLVM IR text.
//!
//! These tests drive the **full** compilation stack at the IR-generation level
//! without the runtime linker step, making them fast and suitable for CI.

use std::process::Command;
use jockey_backend::llvm::LlvmBackend;
use jockey_ir::BuildConfig;
use jockey_lexer::Lexer;
use jockey_parser::Parser;
use jockey_semantic::SemanticAnalyzer;

/// Run the full compiler stack from source text, stopping just before the
/// linker, and return the LLVM IR string.
fn compile_to_llvm_ir(source: &str, test_name: &str) -> String {
    // Lexer
    let mut lexer = Lexer::new(source);
    let tokens = lexer
        .tokenize()
        .unwrap_or_else(|e| panic!("[{}] Lexer error: {}", test_name, e));

    // Parser
    let mut parser = Parser::new(tokens);
    let (ast, parse_diags) = parser.parse_with_diagnostics();
    if !parse_diags.is_empty() {
        panic!("[{}] Parse errors: {:?}", test_name, parse_diags);
    }
    let ast = ast.unwrap_or_else(|| panic!("[{}] No AST produced", test_name));

    // Semantic analysis → IrInvestigation
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);
    if !sem_diags.is_empty() {
        panic!("[{}] Semantic errors: {:?}", test_name, sem_diags);
    }
    let ir = ir.unwrap_or_else(|| panic!("[{}] No IR produced", test_name));

    // Lower IR → HIR → MIR
    let hir: jockey_hir::HirInvestigation = (&ir).into();
    let mir = jockey_mir::MirLowering::lower(&hir)
        .unwrap_or_else(|e| panic!("[{}] MIR lowering error: {}", test_name, e));

    // Generate LLVM IR text
    let llvm = LlvmBackend::new(BuildConfig::default());
    llvm.generate_llvm_ir(&mir)
        .unwrap_or_else(|e| panic!("[{}] LLVM IR generation error: {}", test_name, e))
}

/// If `clang` is available, validate the IR with the assembler frontend.
fn validate_with_clang(ir: &str, test_name: &str) {
    use std::io::Write;
    let mut child = match Command::new("clang")
        .args(["-x", "ir", "-", "-c", "-o", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return, // clang not available – skip
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(ir.as_bytes());
    }
    let status = child.wait().expect("clang process failed");
    assert!(
        status.success(),
        "[{}] Clang rejected the generated LLVM IR",
        test_name
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual collector tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_basic_system_triage() {
    let source = r#"investigation "e2e_sys" {
    collect system_info
    collect processes
    export evidence "sys.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_basic_system_triage");
    assert!(
        ir.contains("jockey_rt_evidence_init"),
        "missing evidence_init"
    );
    assert!(
        ir.contains("jockey_rt_collect_system"),
        "missing collect_system"
    );
    assert!(
        ir.contains("jockey_rt_collect_processes"),
        "missing collect_processes"
    );
    assert!(
        ir.contains("jockey_rt_evidence_export"),
        "missing evidence_export"
    );
    validate_with_clang(&ir, "e2e_basic_system_triage");
}

#[test]
fn e2e_network_investigation() {
    let source = r#"investigation "e2e_net" {
    collect system_info
    collect network_connections
    export evidence "net.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_network_investigation");
    assert!(
        ir.contains("jockey_rt_collect_network"),
        "missing collect_network"
    );
    validate_with_clang(&ir, "e2e_network_investigation");
}

#[test]
fn e2e_filesystem_integrity() {
    let source = r#"investigation "e2e_fs" {
    collect files "/etc" { recursive hash.sha256 } limit 50
    export evidence "fs.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_filesystem_integrity");
    assert!(
        ir.contains("jockey_rt_collect_files"),
        "missing collect_files"
    );
    validate_with_clang(&ir, "e2e_filesystem_integrity");
}

#[test]
fn e2e_memory_regions() {
    let source = r#"investigation "e2e_mem" {
    collect memory_regions pid=1234
    export evidence "mem.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_memory_regions");
    assert!(
        ir.contains("jockey_rt_collect_memory_regions"),
        "missing collect_memory_regions"
    );
    validate_with_clang(&ir, "e2e_memory_regions");
}

#[test]
fn e2e_registry_audit() {
    let source = r#"investigation "e2e_reg" {
    collect registry hive="HKLM" key="SOFTWARE\\Test"
    export evidence "reg.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_registry_audit");
    assert!(
        ir.contains("jockey_rt_collect_registry"),
        "missing collect_registry"
    );
    validate_with_clang(&ir, "e2e_registry_audit");
}

#[test]
fn e2e_artifact_carving() {
    let source = r#"investigation "e2e_art" {
    collect artifacts type="prefetch"
    export evidence "art.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_artifact_carving");
    assert!(
        ir.contains("jockey_rt_collect_artifacts"),
        "missing collect_artifacts"
    );
    validate_with_clang(&ir, "e2e_artifact_carving");
}

#[test]
fn e2e_driver_hunt() {
    let source = r#"investigation "e2e_drv" {
    collect system_info
    collect drivers
    export evidence "drv.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_driver_hunt");
    assert!(
        ir.contains("jockey_rt_collect_drivers"),
        "missing collect_drivers"
    );
    validate_with_clang(&ir, "e2e_driver_hunt");
}

#[test]
fn e2e_full_triage_all_collectors() {
    let source = r#"investigation "e2e_full" {
    metadata { author = "DFIR Team" priority = "High" }
    collect system_info
    collect processes { pid name hash.sha256 }
    collect network_connections
    collect files "/tmp" { recursive hash.sha256 } limit 25
    collect logs source="auth"
    collect drivers
    collect memory_regions pid=1
    collect registry hive="HKLM" key="SOFTWARE"
    collect artifacts type="prefetch"
    export evidence "full_triage.json"
}"#;
    let ir = compile_to_llvm_ir(source, "e2e_full_triage_all_collectors");
    for symbol in &[
        "jockey_rt_collect_system",
        "jockey_rt_collect_processes",
        "jockey_rt_collect_network",
        "jockey_rt_collect_files",
        "jockey_rt_collect_logs",
        "jockey_rt_collect_drivers",
        "jockey_rt_collect_memory_regions",
        "jockey_rt_collect_registry",
        "jockey_rt_collect_artifacts",
        "jockey_rt_evidence_export",
    ] {
        assert!(ir.contains(symbol), "missing runtime symbol: {}", symbol);
    }
    validate_with_clang(&ir, "e2e_full_triage_all_collectors");
}
