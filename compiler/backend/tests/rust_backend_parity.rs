#![cfg(feature = "llvm")]

use jockey_ast::Capability;
use jockey_backend::llvm::LlvmBackend;
use jockey_backend::{Backend, BackendKind};
use jockey_ir::{BuildConfig, IrInvestigation};
use jockey_lexer::Lexer;
use jockey_parser::Parser;
use jockey_semantic::SemanticAnalyzer;
use std::collections::HashSet;

fn parse_to_ir(source: &str, test_name: &str) -> IrInvestigation {
    let mut lexer = Lexer::new(source);
    let tokens = lexer
        .tokenize()
        .unwrap_or_else(|e| panic!("[{}] Lexer error: {}", test_name, e));

    let mut parser = Parser::new(tokens);
    let (ast, parse_diags) = parser.parse_with_diagnostics();
    if !parse_diags.is_empty() {
        panic!("[{}] Parse errors: {:?}", test_name, parse_diags);
    }
    let ast = ast.unwrap_or_else(|| panic!("[{}] No AST produced", test_name));

    let mut analyzer = SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);
    if !sem_diags.is_empty() {
        panic!("[{}] Semantic errors: {:?}", test_name, sem_diags);
    }
    ir.unwrap_or_else(|| panic!("[{}] No IR produced", test_name))
}

#[test]
fn test_rust_and_llvm_backend_parity_all_collectors() {
    let source = r#"investigation "full_parity_triage" {
    collect system_info
    collect processes { pid name }
    collect network_connections
    collect memory_regions pid=4321
    collect registry hive="HKLM" key="SOFTWARE\\Microsoft\\Windows"
    collect artifacts type="shimcache" path="/windows/appcompat"
    collect drivers
    collect logs source="syslog"
    export evidence "triage_evidence.json"
}"#;

    let ir = parse_to_ir(source, "full_parity_triage");
    let build_config = BuildConfig::default();

    // 1. Rust backend codegen verification
    let rust_backend = Backend::new_with_kind(build_config.clone(), BackendKind::Rust);
    let rust_source = rust_backend
        .generate_rust_code(&ir)
        .expect("Rust codegen must succeed");

    assert!(
        rust_source.contains("evidence.collect_system_info()?;"),
        "Missing system_info in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_processes("),
        "Missing collect_processes in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_network_connections()?;"),
        "Missing network_connections in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_memory_regions("),
        "Missing memory_regions in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_registry("),
        "Missing registry in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_artifacts("),
        "Missing artifacts in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_drivers()?;"),
        "Missing drivers in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.collect_logs("),
        "Missing logs in Rust backend:\n{}",
        rust_source
    );
    assert!(
        rust_source.contains("evidence.finalize()?;"),
        "Missing finalize in Rust backend:\n{}",
        rust_source
    );

    // Verify Cargo.toml generation for Rust backend
    let cargo_toml = rust_backend
        .generate_cargo_toml(&ir)
        .expect("Cargo.toml generation must succeed");
    let runtime_line = cargo_toml
        .lines()
        .find(|line| line.contains("jockey-runtime"))
        .expect("Cargo.toml must declare jockey-runtime");
    assert!(cargo_toml.contains("jockey-runtime"));
    assert!(cargo_toml.contains("name = \"full_parity_triage\""));
    assert!(
        !runtime_line.contains(":"),
        "Generated Cargo.toml must not embed an absolute runtime path: {}",
        runtime_line
    );

    // 2. LLVM backend verification
    let hir: jockey_hir::HirInvestigation = (&ir).into();
    let mir = jockey_mir::MirLowering::lower(&hir).expect("MIR lowering must succeed");
    let llvm_backend = LlvmBackend::new(build_config);
    let llvm_ir = llvm_backend
        .generate_llvm_ir(&mir)
        .expect("LLVM IR codegen must succeed");

    assert!(
        llvm_ir.contains("jockey_rt_collect_system"),
        "Missing jockey_rt_collect_system in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_processes"),
        "Missing jockey_rt_collect_processes in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_network"),
        "Missing jockey_rt_collect_network in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_memory_regions"),
        "Missing jockey_rt_collect_memory_regions in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_registry"),
        "Missing jockey_rt_collect_registry in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_artifacts"),
        "Missing jockey_rt_collect_artifacts in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_drivers"),
        "Missing jockey_rt_collect_drivers in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_collect_logs"),
        "Missing jockey_rt_collect_logs in LLVM backend"
    );
    assert!(
        llvm_ir.contains("jockey_rt_evidence_export"),
        "Missing jockey_rt_evidence_export in LLVM backend"
    );

    // 3. Parity checks: both backends target identical required capabilities
    let ir_caps: HashSet<Capability> = ir.required_capabilities.into_iter().collect();
    assert_eq!(
        ir_caps, mir.capabilities,
        "IR and MIR capability requirements must match"
    );
}

#[test]
fn test_rust_backend_pipeline_stage_parity() {
    let source = r#"investigation "pipeline_parity_test" {
    collect processes
    where name == "malware.exe"
    filter pid > 100
    limit 10
    export evidence "proc_evidence.json"
}"#;

    let ir = parse_to_ir(source, "pipeline_parity_test");
    let backend = Backend::new_with_kind(BuildConfig::default(), BackendKind::Rust);

    let rust_code = backend.generate_rust_code(&ir).expect("Codegen failed");
    assert!(rust_code.contains("evidence.add_where("));
    assert!(rust_code.contains("evidence.add_filter("));
    assert!(rust_code.contains("evidence.set_limit("));
    assert!(rust_code.contains(r#"evidence.set_output_format("json", "proc_evidence.json");"#));
}
