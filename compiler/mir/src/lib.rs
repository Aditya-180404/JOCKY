//! jockey MIR - Mid-Level Intermediate Representation
//!
//! A strongly-typed, control-flow-graph (CFG) representation with basic blocks,
//! explicit instructions, temporaries/locals, typed values, and terminators.
//! MIR bridges the gap between high-level forensic intent and low-level LLVM codegen.

use jockey_ast::Capability;
use jockey_hir::{HirExpr, HirInvestigation, HirOperation, HirPipelineStage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub type LocalId = usize;
pub type BasicBlockId = usize;

/// Complete MIR program for a compilation unit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MirProgram {
    pub name: String,
    pub target: Option<String>,
    pub functions: Vec<MirFunction>,
    pub capabilities: HashSet<Capability>,
    pub provenance: MirProvenance,
}

/// Cryptographic provenance tracking through the MIR stage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MirProvenance {
    pub source_hash: String,
    pub hir_hash: String,
    pub mir_hash: String,
    pub compiler_version: String,
    pub created_at: String,
}

/// A function in MIR (e.g. `main` or investigation subroutines)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MirFunction {
    pub name: String,
    pub return_type: MirType,
    pub locals: Vec<MirLocal>,
    pub blocks: Vec<MirBasicBlock>,
}

/// Strongly-typed local variable or temporary register in MIR
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MirLocal {
    pub id: LocalId,
    pub name: String,
    pub ty: MirType,
}

/// MIR type system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MirType {
    Void,
    Int32,
    Int64,
    Bool,
    String,
    Pointer,
    EvidenceContext,
    RecordSet,
    JsonValue,
}

/// A basic block with a single entry and terminating control-flow transfer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MirBasicBlock {
    pub id: BasicBlockId,
    pub name: String,
    pub instructions: Vec<MirInstruction>,
    pub terminator: MirTerminator,
}

/// Strongly-typed MIR instructions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum MirInstruction {
    // Constant literals
    ConstInt {
        dest: LocalId,
        value: i64,
    },
    ConstString {
        dest: LocalId,
        value: String,
    },
    ConstBool {
        dest: LocalId,
        value: bool,
    },

    // Memory operations
    Alloc {
        dest: LocalId,
        ty: MirType,
    },
    Load {
        dest: LocalId,
        src: LocalId,
    },
    Store {
        dest: LocalId,
        src: LocalId,
    },

    // Evidence & runtime context lifecycle
    EvidenceInit {
        dest: LocalId,
        investigation_name: String,
        source_hash: String,
    },
    EvidenceAddFilter {
        ctx: LocalId,
        condition_json: String,
    },
    EvidenceAddWhere {
        ctx: LocalId,
        condition_json: String,
    },
    EvidenceSetLimit {
        ctx: LocalId,
        limit: usize,
    },
    EvidenceComputeHash {
        dest: LocalId,
        ctx: LocalId,
        algorithm: String,
    },
    EvidenceGenerateTimeline {
        dest: LocalId,
        ctx: LocalId,
    },
    EvidenceExport {
        ctx: LocalId,
        format: String,
        path: String,
    },

    // Forensic collectors
    CollectSystemInfo {
        dest: LocalId,
        ctx: LocalId,
    },
    CollectProcesses {
        dest: LocalId,
        ctx: LocalId,
        fields_json: String,
        hash_algo: Option<String>,
    },
    CollectProcessTree {
        dest: LocalId,
        ctx: LocalId,
    },
    CollectProcessModules {
        dest: LocalId,
        ctx: LocalId,
        pid: i32,
    },
    CollectProcessHandles {
        dest: LocalId,
        ctx: LocalId,
        pid: i32,
    },
    CollectDeletedExecutables {
        dest: LocalId,
        ctx: LocalId,
    },
    CollectNetwork {
        dest: LocalId,
        ctx: LocalId,
    },
    CollectFiles {
        dest: LocalId,
        ctx: LocalId,
        path: String,
        recursive: bool,
        hash_algo: String,
    },
    CollectLogs {
        dest: LocalId,
        ctx: LocalId,
        source: String,
    },
    CollectDrivers {
        dest: LocalId,
        ctx: LocalId,
    },
    CollectMemoryRegions {
        dest: LocalId,
        ctx: LocalId,
        pid: i32,
    },
    CollectRegistry {
        dest: LocalId,
        ctx: LocalId,
        hive: String,
        key_path: String,
    },
    CollectArtifacts {
        dest: LocalId,
        ctx: LocalId,
        artifact_type: String,
        path: String,
    },
    InvokeCapability {
        dest: LocalId,
        ctx: LocalId,
        capability_id: String,
        options_json: String,
    },

    // Comparison and call
    Compare {
        dest: LocalId,
        op: MirCompareOp,
        left: LocalId,
        right: LocalId,
    },
    CallRuntime {
        dest: Option<LocalId>,
        function_name: String,
        args: Vec<LocalId>,
    },

    // ── Obfuscation-only instructions ────────────────────────────────────────
    // These instructions are only emitted by obfuscation passes and are
    // understood by the LLVM backend. They are never generated by the MIR
    // lowering pass from user-written JOCKEY source code.

    /// Dead arithmetic XOR of two integer locals — result is never used.
    /// Emitted by JunkInsertionPass to break byte-pattern signatures.
    JunkBitwiseXor {
        dest: LocalId,
        lhs: LocalId,
        rhs: LocalId,
    },

    /// Dead integer addition — result is never used.
    JunkAdd {
        dest: LocalId,
        lhs: LocalId,
        rhs: LocalId,
    },

    /// Stores an XOR-encrypted string payload. The `ciphertext` bytes are the
    /// original string XOR'd with `xor_key`. Emitted by StringEncryptionPass.
    EncryptedString {
        raw_dest: LocalId,
        ciphertext: Vec<u8>,
        xor_key: [u8; 16],
    },

    /// Decrypts an EncryptedString into a usable String local.
    /// At codegen time, this emits an inline XOR loop in LLVM IR that runs at
    /// runtime, so the plaintext is never present in the binary as a static
    /// byte sequence.
    InlineDecrypt {
        dest: LocalId,
        src: LocalId,
        ciphertext: Vec<u8>,
        xor_key: [u8; 16],
    },

    /// Opaque predicate marker. The `value` local always satisfies
    /// `value != 0` (always-true) or `value == 0` (always-false) at runtime.
    /// Emitted by OpaquePredicatePass. The LLVM backend emits a conditional
    /// branch that looks real to a static analyser.
    OpaqueCheck {
        value: LocalId,
        expected_true: bool,
    },

    /// Unique per-build watermark blob embedded in a named binary section.
    /// The `bytes` are random, the `seed` is the build seed, and `tag` is a
    /// human-readable label. Emitted by PolymorphicWatermarkPass.
    WatermarkBlob {
        bytes: Vec<u8>,
        tag: String,
        seed: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MirCompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

/// Control-flow terminator for basic blocks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "terminator")]
pub enum MirTerminator {
    Return {
        value: Option<LocalId>,
    },
    /// Unconditional jump to another basic block
    Jump {
        target: BasicBlockId,
    },
    /// Backwards-compatible alias kept for HIR-lowered programs
    Branch {
        target: BasicBlockId,
    },
    CondBranch {
        cond: LocalId,
        /// Target when cond is true
        true_block: BasicBlockId,
        /// Target when cond is false
        false_block: BasicBlockId,
    },
    /// State-machine dispatch switch: jumps to the arm whose value matches
    /// the `discriminant` local. Used by CfgFlatteningPass.
    DispatchSwitch {
        discriminant: LocalId,
        /// (state_value, target_basic_block_id)
        arms: Vec<(i64, BasicBlockId)>,
        default_target: BasicBlockId,
    },
    Unreachable,
}

/// Lowers HIR into typed MIR
pub struct MirLowering {
    locals: Vec<MirLocal>,
    instructions: Vec<MirInstruction>,
    blocks: Vec<MirBasicBlock>,
    next_local: LocalId,
    next_bb: BasicBlockId,
}

impl Default for MirLowering {
    fn default() -> Self {
        Self::new()
    }
}

impl MirLowering {
    pub fn new() -> Self {
        Self {
            locals: Vec::new(),
            instructions: Vec::new(),
            blocks: Vec::new(),
            next_local: 0,
            next_bb: 0,
        }
    }

    fn new_basic_block(&mut self) -> BasicBlockId {
        let id = self.next_bb;
        self.next_bb += 1;
        id
    }

    fn new_local(&mut self, name: &str, ty: MirType) -> LocalId {
        let id = self.next_local;
        self.next_local += 1;
        self.locals.push(MirLocal {
            id,
            name: name.to_string(),
            ty,
        });
        id
    }

    pub fn lower(hir: &HirInvestigation) -> Result<MirProgram, String> {
        let mut lowering = Self::new();
        let main_fn = lowering.lower_investigation(hir)?;

        // Calculate deterministic cryptographic hashes for MIR provenance
        let hir_hash = hir.calculate_deterministic_hash();

        let mut mir_hasher = Sha256::new();
        let fn_json = serde_json::to_string(&main_fn).map_err(|e| e.to_string())?;
        mir_hasher.update(fn_json.as_bytes());
        let mir_hash = format!("{:x}", mir_hasher.finalize());

        let provenance = MirProvenance {
            source_hash: hir.provenance.source_hash.clone(),
            hir_hash,
            mir_hash,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let program = MirProgram {
            name: hir.name.clone(),
            target: hir.target.clone(),
            functions: vec![main_fn],
            capabilities: hir.capabilities.clone(),
            provenance,
        };

        // Validate generated MIR
        MirValidator::validate(&program)?;

        Ok(program)
    }

    fn lower_investigation(&mut self, hir: &HirInvestigation) -> Result<MirFunction, String> {
        let ctx = self.new_local("ctx", MirType::EvidenceContext);
        let ret_code = self.new_local("ret_code", MirType::Int32);

        // Initialize evidence collector context
        self.instructions.push(MirInstruction::EvidenceInit {
            dest: ctx,
            investigation_name: hir.name.clone(),
            source_hash: hir.provenance.source_hash.clone(),
        });

        // Lower each operation in HIR
        for op in &hir.operations {
            self.lower_operation(op, ctx)?;
        }

        // Default exit code 0
        self.instructions.push(MirInstruction::ConstInt {
            dest: ret_code,
            value: 0,
        });

        let entry_id = self.new_basic_block();
        let entry_block = MirBasicBlock {
            id: entry_id,
            name: "entry".to_string(),
            instructions: std::mem::take(&mut self.instructions),
            terminator: MirTerminator::Return {
                value: Some(ret_code),
            },
        };
        self.blocks.push(entry_block);

        Ok(MirFunction {
            name: "main".to_string(),
            return_type: MirType::Int32,
            locals: std::mem::take(&mut self.locals),
            blocks: std::mem::take(&mut self.blocks),
        })
    }

    fn lower_operation(&mut self, op: &HirOperation, ctx: LocalId) -> Result<(), String> {
        let res_id = self.new_local("res", MirType::Int32);

        match op {
            HirOperation::InvokeCapability {
                capability_id,
                fields,
                options,
                ..
            } => {
                let mut args = options.clone();
                args.insert("fields".to_string(), serde_json::json!(fields));
                self.instructions.push(MirInstruction::InvokeCapability {
                    dest: res_id,
                    ctx,
                    capability_id: capability_id.clone(),
                    options_json: serde_json::Value::Object(args).to_string(),
                });
            }
            HirOperation::CollectSystemInfo { .. } => {
                self.instructions
                    .push(MirInstruction::CollectSystemInfo { dest: res_id, ctx });
            }
            HirOperation::CollectProcesses {
                fields,
                hash_algorithm,
                ..
            } => {
                let fields_json =
                    serde_json::to_string(fields).unwrap_or_else(|_| "[]".to_string());
                self.instructions.push(MirInstruction::CollectProcesses {
                    dest: res_id,
                    ctx,
                    fields_json,
                    hash_algo: hash_algorithm.clone(),
                });
            }
            HirOperation::CollectNetworkConnections { .. } => {
                self.instructions
                    .push(MirInstruction::CollectNetwork { dest: res_id, ctx });
            }
            HirOperation::CollectFiles {
                path,
                recursive,
                hash_algorithm,
                ..
            } => {
                self.instructions.push(MirInstruction::CollectFiles {
                    dest: res_id,
                    ctx,
                    path: path.clone(),
                    recursive: *recursive,
                    hash_algo: hash_algorithm.clone(),
                });
            }
            HirOperation::CollectLogs { source, .. } => {
                self.instructions.push(MirInstruction::CollectLogs {
                    dest: res_id,
                    ctx,
                    source: source.clone(),
                });
            }
            HirOperation::CollectDrivers { .. } => {
                self.instructions
                    .push(MirInstruction::CollectDrivers { dest: res_id, ctx });
            }
            HirOperation::CollectMemoryRegions { pid, .. } => {
                self.instructions
                    .push(MirInstruction::CollectMemoryRegions {
                        dest: res_id,
                        ctx,
                        pid: *pid,
                    });
            }
            HirOperation::CollectRegistry { hive, key_path, .. } => {
                self.instructions.push(MirInstruction::CollectRegistry {
                    dest: res_id,
                    ctx,
                    hive: hive.clone(),
                    key_path: key_path.clone(),
                });
            }
            HirOperation::CollectArtifacts {
                artifact_type,
                path,
                ..
            } => {
                self.instructions.push(MirInstruction::CollectArtifacts {
                    dest: res_id,
                    ctx,
                    artifact_type: artifact_type.clone(),
                    path: path.clone(),
                });
            }
            HirOperation::CollectTimeline { .. } => {
                self.instructions
                    .push(MirInstruction::EvidenceGenerateTimeline { dest: res_id, ctx });
            }
            HirOperation::CollectEvidence { .. } => {
                self.instructions
                    .push(MirInstruction::CollectSystemInfo { dest: res_id, ctx });
            }
            HirOperation::CollectProcessTree { .. } => {
                self.instructions
                    .push(MirInstruction::CollectProcessTree { dest: res_id, ctx });
            }
            HirOperation::CollectProcessModules { pid, .. } => {
                self.instructions
                    .push(MirInstruction::CollectProcessModules {
                        dest: res_id,
                        ctx,
                        pid: *pid,
                    });
            }
            HirOperation::CollectProcessHandles { pid, .. } => {
                self.instructions
                    .push(MirInstruction::CollectProcessHandles {
                        dest: res_id,
                        ctx,
                        pid: *pid,
                    });
            }
            HirOperation::CollectDeletedExecutables { .. } => {
                self.instructions
                    .push(MirInstruction::CollectDeletedExecutables { dest: res_id, ctx });
            }
            HirOperation::Filter { condition, .. } => {
                self.instructions.push(MirInstruction::EvidenceAddFilter {
                    ctx,
                    condition_json: serde_json::to_string(condition).unwrap_or_default(),
                });
            }
            HirOperation::Where { condition, .. } => {
                self.instructions.push(MirInstruction::EvidenceAddWhere {
                    ctx,
                    condition_json: serde_json::to_string(condition).unwrap_or_default(),
                });
            }
            HirOperation::Limit { count, .. } => {
                self.instructions
                    .push(MirInstruction::EvidenceSetLimit { ctx, limit: *count });
            }
            HirOperation::Assign { variable, expr, .. } => {
                self.lower_assign(variable, expr, ctx)?;
            }
            HirOperation::EvidencePipeline { stages, .. } => {
                for stage in stages {
                    match stage {
                        HirPipelineStage::Where { condition, .. } => {
                            self.instructions.push(MirInstruction::EvidenceAddWhere {
                                ctx,
                                condition_json: serde_json::to_string(condition)
                                    .unwrap_or_default(),
                            });
                        }
                        HirPipelineStage::Filter { condition, .. } => {
                            self.instructions.push(MirInstruction::EvidenceAddFilter {
                                ctx,
                                condition_json: serde_json::to_string(condition)
                                    .unwrap_or_default(),
                            });
                        }
                        HirPipelineStage::Limit { count, .. } => {
                            self.instructions
                                .push(MirInstruction::EvidenceSetLimit { ctx, limit: *count });
                        }
                        HirPipelineStage::Hash { algorithm, .. } => {
                            let hash_id = self.new_local("hash", MirType::String);
                            self.instructions.push(MirInstruction::EvidenceComputeHash {
                                dest: hash_id,
                                ctx,
                                algorithm: algorithm.clone(),
                            });
                        }
                        HirPipelineStage::Timeline { .. } => {
                            let timeline_id = self.new_local("timeline", MirType::RecordSet);
                            self.instructions
                                .push(MirInstruction::EvidenceGenerateTimeline {
                                    dest: timeline_id,
                                    ctx,
                                });
                        }
                        HirPipelineStage::Export { format, path, .. } => {
                            self.instructions.push(MirInstruction::EvidenceExport {
                                ctx,
                                format: format.clone(),
                                path: path.clone(),
                            });
                        }
                    }
                }
            }
            HirOperation::Export { format, path, .. } => {
                self.instructions.push(MirInstruction::EvidenceExport {
                    ctx,
                    format: format.clone(),
                    path: path.clone(),
                });
            }
        }

        Ok(())
    }

    fn lower_assign(
        &mut self,
        _variable: &str,
        expr: &HirExpr,
        ctx: LocalId,
    ) -> Result<(), String> {
        match expr {
            HirExpr::Collect {
                target,
                fields,
                options,
            } => {
                let res_id = self.new_local("assign_collect", MirType::RecordSet);
                match target.as_str() {
                    "processes" => {
                        let hash_algo = options
                            .get("hash")
                            .and_then(|h| h.as_str())
                            .map(|s| s.to_string());
                        self.instructions.push(MirInstruction::CollectProcesses {
                            dest: res_id,
                            ctx,
                            fields_json: serde_json::to_string(fields).unwrap_or_default(),
                            hash_algo,
                        });
                    }
                    "network" | "network_connections" => {
                        self.instructions
                            .push(MirInstruction::CollectNetwork { dest: res_id, ctx });
                    }
                    "system" | "system_info" => {
                        self.instructions
                            .push(MirInstruction::CollectSystemInfo { dest: res_id, ctx });
                    }
                    _ => {}
                }
            }
            HirExpr::Pipeline { source, stages } => {
                self.lower_assign(_variable, source, ctx)?;
                for stage in stages {
                    match stage {
                        HirPipelineStage::Where { condition, .. } => {
                            self.instructions.push(MirInstruction::EvidenceAddWhere {
                                ctx,
                                condition_json: serde_json::to_string(condition)
                                    .unwrap_or_default(),
                            });
                        }
                        HirPipelineStage::Filter { condition, .. } => {
                            self.instructions.push(MirInstruction::EvidenceAddFilter {
                                ctx,
                                condition_json: serde_json::to_string(condition)
                                    .unwrap_or_default(),
                            });
                        }
                        HirPipelineStage::Limit { count, .. } => {
                            self.instructions
                                .push(MirInstruction::EvidenceSetLimit { ctx, limit: *count });
                        }
                        HirPipelineStage::Hash { algorithm, .. } => {
                            let hash_id = self.new_local("hash", MirType::String);
                            self.instructions.push(MirInstruction::EvidenceComputeHash {
                                dest: hash_id,
                                ctx,
                                algorithm: algorithm.clone(),
                            });
                        }
                        HirPipelineStage::Timeline { .. } => {
                            let timeline_id = self.new_local("timeline", MirType::RecordSet);
                            self.instructions
                                .push(MirInstruction::EvidenceGenerateTimeline {
                                    dest: timeline_id,
                                    ctx,
                                });
                        }
                        HirPipelineStage::Export { format, path, .. } => {
                            self.instructions.push(MirInstruction::EvidenceExport {
                                ctx,
                                format: format.clone(),
                                path: path.clone(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Validates structural invariants of MIR
pub struct MirValidator;

impl MirValidator {
    pub fn validate(program: &MirProgram) -> Result<(), String> {
        if program.functions.is_empty() {
            return Err("MIR program has no functions".to_string());
        }

        for func in &program.functions {
            if func.blocks.is_empty() {
                return Err(format!("MIR function '{}' has no basic blocks", func.name));
            }

            let valid_local_ids: HashSet<LocalId> = func.locals.iter().map(|l| l.id).collect();

            for block in &func.blocks {
                for inst in &block.instructions {
                    match inst {
                        MirInstruction::ConstInt { dest, .. }
                        | MirInstruction::ConstString { dest, .. }
                        | MirInstruction::ConstBool { dest, .. }
                        | MirInstruction::Alloc { dest, .. }
                        | MirInstruction::EvidenceInit { dest, .. }
                        | MirInstruction::CollectSystemInfo { dest, .. }
                        | MirInstruction::CollectNetwork { dest, .. }
                        | MirInstruction::CollectDrivers { dest, .. }
                        | MirInstruction::CollectMemoryRegions { dest, .. }
                        | MirInstruction::CollectRegistry { dest, .. }
                        | MirInstruction::CollectArtifacts { dest, .. }
                        | MirInstruction::InvokeCapability { dest, .. } => {
                            if !valid_local_ids.contains(dest) {
                                return Err(format!("Undefined destination local {}", dest));
                            }
                        }
                        MirInstruction::EvidenceAddFilter { ctx, .. }
                        | MirInstruction::EvidenceAddWhere { ctx, .. }
                        | MirInstruction::EvidenceSetLimit { ctx, .. }
                        | MirInstruction::EvidenceExport { ctx, .. }
                            if !valid_local_ids.contains(ctx) =>
                        {
                            return Err(format!("Undefined context local {}", ctx));
                        }
                        MirInstruction::EvidenceAddFilter { .. }
                        | MirInstruction::EvidenceAddWhere { .. }
                        | MirInstruction::EvidenceSetLimit { .. }
                        | MirInstruction::EvidenceExport { .. } => {}
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

/// Basic optimization passes on MIR
pub struct MirOptimizer;

impl MirOptimizer {
    pub fn optimize(program: &mut MirProgram) {
        for func in &mut program.functions {
            for block in &mut func.blocks {
                // Pass 1: Deduplicate consecutive redundant instructions if any
                block.instructions.dedup_by(|a, b| match (a, b) {
                    (
                        MirInstruction::ConstInt {
                            dest: d1,
                            value: v1,
                        },
                        MirInstruction::ConstInt {
                            dest: d2,
                            value: v2,
                        },
                    ) => d1 == d2 && v1 == v2,
                    _ => false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jockey_ast::Span;
    use jockey_hir::HirProvenance;

    #[test]
    fn test_mir_lowering_and_validation() {
        let hir = HirInvestigation {
            name: "mir_test".to_string(),
            target: Some("linux".to_string()),
            metadata: vec![],
            operations: vec![
                HirOperation::CollectSystemInfo {
                    span: Span::new(1, 1, 1, 10),
                },
                HirOperation::Export {
                    format: "json".to_string(),
                    path: "evidence.json".to_string(),
                    span: Span::new(2, 1, 2, 20),
                },
            ],
            capabilities: HashSet::new(),
            provenance: HirProvenance {
                source_hash: "abcd".to_string(),
                ast_hash: "1234".to_string(),
                compiler_version: "0.1.0".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
            },
            span: Span::new(1, 1, 2, 20),
        };

        let mir = MirLowering::lower(&hir).expect("MIR lowering failed");
        assert_eq!(mir.name, "mir_test");
        assert_eq!(mir.functions.len(), 1);
        assert!(!mir.functions[0].blocks.is_empty());
        assert!(!mir.provenance.mir_hash.is_empty());

        let validation_res = MirValidator::validate(&mir);
        assert!(validation_res.is_ok());
    }

    #[test]
    fn test_mir_preserves_generic_capability_id_and_options() {
        let mut options = serde_json::Map::new();
        options.insert("path".to_string(), serde_json::json!("/var/log"));
        let hir = HirInvestigation {
            name: "generic_capability".to_string(),
            target: Some("linux".to_string()),
            metadata: vec![],
            operations: vec![HirOperation::InvokeCapability {
                capability_id: "network.routes".to_string(),
                fields: vec!["destination".to_string()],
                options,
                span: Span::new(1, 1, 1, 20),
            }],
            capabilities: HashSet::new(),
            provenance: HirProvenance {
                source_hash: "abcd".to_string(),
                ast_hash: "1234".to_string(),
                compiler_version: "0.1.0".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
            },
            span: Span::new(1, 1, 1, 20),
        };

        let mir = MirLowering::lower(&hir).expect("MIR lowering failed");
        let instruction = &mir.functions[0].blocks[0].instructions;
        assert!(instruction.iter().any(|instruction| matches!(
            instruction,
            MirInstruction::InvokeCapability { capability_id, options_json, .. }
                if capability_id == "network.routes"
                    && options_json.contains("/var/log")
                    && options_json.contains("destination")
        )));
    }

    #[test]
    fn test_mir_optimizer_pass() {
        let mut mir = MirProgram {
            name: "opt_test".to_string(),
            target: None,
            functions: vec![MirFunction {
                name: "main".to_string(),
                return_type: MirType::Int32,
                locals: vec![MirLocal {
                    id: 0,
                    name: "x".to_string(),
                    ty: MirType::Int32,
                }],
                blocks: vec![MirBasicBlock {
                    id: 0,
                    name: "entry".to_string(),
                    instructions: vec![
                        MirInstruction::ConstInt { dest: 0, value: 42 },
                        MirInstruction::ConstInt { dest: 0, value: 42 }, // duplicate
                    ],
                    terminator: MirTerminator::Return { value: Some(0) },
                }],
            }],
            capabilities: HashSet::new(),
            provenance: MirProvenance {
                source_hash: "a".to_string(),
                hir_hash: "b".to_string(),
                mir_hash: "c".to_string(),
                compiler_version: "0.1.0".to_string(),
                created_at: "now".to_string(),
            },
        };

        MirOptimizer::optimize(&mut mir);
        assert_eq!(mir.functions[0].blocks[0].instructions.len(), 1);
    }
}
