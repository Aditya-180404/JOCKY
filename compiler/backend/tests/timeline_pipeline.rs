#![cfg(feature = "llvm")]

use jocky_backend::llvm::LlvmBackend;
use jocky_hir::{HirLowering, HirOperation};
use jocky_ir::BuildConfig;
use jocky_lexer::Lexer;
use jocky_mir::{MirInstruction, MirLowering};
use jocky_parser::Parser;
use jocky_semantic::SemanticAnalyzer;

#[test]
fn test_timeline_lowering_pipeline_integrity() {
    let source = r#"
investigation "timeline_verification" {
    collect processes
    collect timeline
    export evidence "timeline.json"
}
"#;

    // 1. Lexer & Parser
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize().expect("Lexing failed");
    let mut parser = Parser::new(tokens);
    let ast = parser.parse().expect("Parsing failed");

    // Verify AST has Timeline target
    let has_ast_timeline = ast.statements.iter().any(|stmt| {
        if let jocky_ast::Stmt::Collect { target, .. } = stmt {
            matches!(target, jocky_ast::CollectTarget::Timeline { .. })
        } else {
            false
        }
    });
    assert!(has_ast_timeline, "AST must contain CollectTarget::Timeline");

    // 2. Semantic Analysis
    let mut analyzer = SemanticAnalyzer::new();
    let ir = analyzer.analyze(&ast).expect("Semantic analysis failed");

    let has_ir_timeline = ir.operations.iter().any(|op| {
        if let jocky_ir::IrOperation::Collect(c) = op {
            c.operation == "timeline.build" || c.operation == "timeline"
        } else {
            false
        }
    });
    assert!(has_ir_timeline, "IR must contain timeline.build operation");

    // 3. HIR Lowering
    let hir =
        HirLowering::lower(&ast, &ir.required_capabilities, source).expect("HIR lowering failed");

    let has_hir_timeline = hir
        .operations
        .iter()
        .any(|op| matches!(op, HirOperation::CollectTimeline { .. }));
    assert!(
        has_hir_timeline,
        "HIR must contain HirOperation::CollectTimeline, NOT CollectSystemInfo"
    );

    // Also verify from_ir roundtrip
    let hir_from_ir = jocky_hir::HirInvestigation::from(&ir);
    let has_hir_from_ir_timeline = hir_from_ir
        .operations
        .iter()
        .any(|op| matches!(op, HirOperation::CollectTimeline { .. }));
    assert!(
        has_hir_from_ir_timeline,
        "HIR from IR must contain HirOperation::CollectTimeline"
    );

    // 4. MIR Lowering
    let mir = MirLowering::lower(&hir).expect("MIR lowering failed");

    let mut has_mir_timeline = false;
    for func in &mir.functions {
        for block in &func.blocks {
            for inst in &block.instructions {
                if matches!(inst, MirInstruction::EvidenceGenerateTimeline { .. }) {
                    has_mir_timeline = true;
                }
            }
        }
    }
    assert!(
        has_mir_timeline,
        "MIR must contain MirInstruction::EvidenceGenerateTimeline"
    );

    // 5. LLVM IR Generation
    let backend = LlvmBackend::new(BuildConfig::default());
    let llvm_ir = backend
        .generate_llvm_ir(&mir)
        .expect("LLVM generation failed");

    assert!(
        llvm_ir.contains("call i32 @jocky_rt_evidence_generate_timeline"),
        "LLVM IR must explicitly invoke @jocky_rt_evidence_generate_timeline"
    );
}
