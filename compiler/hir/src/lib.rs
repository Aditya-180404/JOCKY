//! jockey HIR - High-Level Intermediate Representation
//!
//! HIR captures semantic meaning, resolved capabilities, evidence requirements,
//! and provenance, separating syntax structure from semantic operations.

use jockey_ast::{
    BinaryOp, Capability, CollectOptions, CollectTarget, Diagnostic, ExportFormat, Expr,
    HashAlgorithm, Investigation, PipelineStage, Span, Stmt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// High-Level Intermediate Representation of a jockey Investigation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HirInvestigation {
    pub name: String,
    pub target: Option<String>,
    pub metadata: Vec<(String, serde_json::Value)>,
    pub operations: Vec<HirOperation>,
    pub capabilities: HashSet<Capability>,
    pub provenance: HirProvenance,
    pub span: Span,
}

impl HirInvestigation {
    /// Compute a deterministic hash of HIR semantic content independent of wall-clock timestamps
    pub fn calculate_deterministic_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let val = serde_json::json!({
            "name": self.name,
            "target": self.target,
            "operations": self.operations,
            "capabilities": self.capabilities,
            "source_hash": self.provenance.source_hash,
            "ast_hash": self.provenance.ast_hash,
        });
        hasher.update(val.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Provenance metadata tracking compilation lineage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HirProvenance {
    pub source_hash: String,
    pub ast_hash: String,
    pub compiler_version: String,
    pub created_at: String,
}

/// Semantic operations at the HIR level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum HirOperation {
    InvokeCapability {
        capability_id: String,
        fields: Vec<String>,
        options: serde_json::Map<String, serde_json::Value>,
        span: Span,
    },
    CollectSystemInfo {
        span: Span,
    },
    CollectProcesses {
        fields: Vec<String>,
        hash_algorithm: Option<String>,
        span: Span,
    },
    CollectNetworkConnections {
        span: Span,
    },
    CollectFiles {
        path: String,
        recursive: bool,
        hash_algorithm: String,
        span: Span,
    },
    CollectLogs {
        source: String,
        span: Span,
    },
    CollectDrivers {
        span: Span,
    },
    CollectMemoryRegions {
        pid: i32,
        span: Span,
    },
    CollectRegistry {
        hive: String,
        key_path: String,
        span: Span,
    },
    CollectArtifacts {
        artifact_type: String,
        path: String,
        span: Span,
    },
    CollectTimeline {
        sources: Vec<String>,
        span: Span,
    },
    CollectEvidence {
        format: String,
        span: Span,
    },
    CollectProcessTree {
        span: Span,
    },
    CollectProcessModules {
        pid: i32,
        span: Span,
    },
    CollectProcessHandles {
        pid: i32,
        span: Span,
    },
    CollectDeletedExecutables {
        span: Span,
    },
    Filter {
        condition: serde_json::Value,
        span: Span,
    },
    Where {
        condition: serde_json::Value,
        span: Span,
    },
    Limit {
        count: usize,
        span: Span,
    },
    Assign {
        variable: String,
        expr: HirExpr,
        span: Span,
    },
    EvidencePipeline {
        variable: String,
        stages: Vec<HirPipelineStage>,
        span: Span,
    },
    Export {
        format: String,
        path: String,
        span: Span,
    },
}

/// Expressions at HIR level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum HirExpr {
    Collect {
        target: String,
        fields: Vec<String>,
        options: serde_json::Map<String, serde_json::Value>,
    },
    Variable {
        name: String,
    },
    Pipeline {
        source: Box<HirExpr>,
        stages: Vec<HirPipelineStage>,
    },
    Literal {
        value: serde_json::Value,
    },
}

/// Linear pipeline stages for evidence transformations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "stage")]
pub enum HirPipelineStage {
    Where {
        condition: serde_json::Value,
        span: Span,
    },
    Filter {
        condition: serde_json::Value,
        span: Span,
    },
    Limit {
        count: usize,
        span: Span,
    },
    Hash {
        algorithm: String,
        span: Span,
    },
    Timeline {
        span: Span,
    },
    Export {
        format: String,
        path: String,
        span: Span,
    },
}

/// Lowers AST to HIR
pub struct HirLowering;

impl HirLowering {
    pub fn lower(
        ast: &Investigation,
        capabilities: &HashSet<Capability>,
        source_code: &str,
    ) -> Result<HirInvestigation, Vec<Diagnostic>> {
        let mut operations = Vec::new();
        let mut metadata = Vec::new();

        // Calculate cryptographic hashes for provenance
        let mut source_hasher = Sha256::new();
        source_hasher.update(source_code.as_bytes());
        let source_hash = format!("{:x}", source_hasher.finalize());

        let ast_json = serde_json::to_string(ast).unwrap_or_default();
        let mut ast_hasher = Sha256::new();
        ast_hasher.update(ast_json.as_bytes());
        let ast_hash = format!("{:x}", ast_hasher.finalize());

        for stmt in &ast.statements {
            match stmt {
                Stmt::Target(..) => {}
                Stmt::Collect {
                    target,
                    options,
                    span,
                } => {
                    let op = Self::lower_collect(target, options, *span)?;
                    operations.push(op);
                }
                Stmt::Export { format, path, span } => {
                    operations.push(HirOperation::Export {
                        format: match format {
                            ExportFormat::Json => "json".to_string(),
                            ExportFormat::Csv => "csv".to_string(),
                            ExportFormat::Xml => "xml".to_string(),
                        },
                        path: path.clone(),
                        span: *span,
                    });
                }
                Stmt::Filter { condition, span } => {
                    let val = Self::expr_to_json(condition);
                    operations.push(HirOperation::Filter {
                        condition: val,
                        span: *span,
                    });
                }
                Stmt::Where { condition, span } => {
                    let val = Self::expr_to_json(condition);
                    operations.push(HirOperation::Where {
                        condition: val,
                        span: *span,
                    });
                }
                Stmt::Limit { count, span } => {
                    let limit_val = Self::expr_as_usize(count).unwrap_or(0);
                    operations.push(HirOperation::Limit {
                        count: limit_val,
                        span: *span,
                    });
                }
                Stmt::Metadata(meta_list, _) => {
                    for (k, v) in meta_list {
                        let json_val = Self::expr_to_json(v);
                        metadata.push((k.clone(), json_val));
                    }
                }
                Stmt::Assign {
                    variable,
                    expression,
                    span,
                } => {
                    let hir_expr = Self::lower_expr(expression)?;
                    operations.push(HirOperation::Assign {
                        variable: variable.clone(),
                        expr: hir_expr,
                        span: *span,
                    });
                }
                Stmt::EvidencePipeline {
                    variable,
                    stages,
                    span,
                } => {
                    let mut hir_stages = Vec::new();
                    for stage in stages {
                        match stage {
                            PipelineStage::Where(expr, s) => {
                                hir_stages.push(HirPipelineStage::Where {
                                    condition: Self::expr_to_json(expr),
                                    span: *s,
                                });
                            }
                            PipelineStage::Filter(expr, s) => {
                                hir_stages.push(HirPipelineStage::Filter {
                                    condition: Self::expr_to_json(expr),
                                    span: *s,
                                });
                            }
                            PipelineStage::Limit(expr, s) => {
                                let limit_val = Self::expr_as_usize(expr).unwrap_or(0);
                                hir_stages.push(HirPipelineStage::Limit {
                                    count: limit_val,
                                    span: *s,
                                });
                            }
                            PipelineStage::Hash(algo, s) => {
                                hir_stages.push(HirPipelineStage::Hash {
                                    algorithm: match algo {
                                        HashAlgorithm::Sha256 => "sha256".to_string(),
                                        HashAlgorithm::Sha1 => "sha1".to_string(),
                                        HashAlgorithm::Md5 => "md5".to_string(),
                                    },
                                    span: *s,
                                });
                            }
                            PipelineStage::Timeline(s) => {
                                hir_stages.push(HirPipelineStage::Timeline { span: *s });
                            }
                            PipelineStage::Export(path, s) => {
                                hir_stages.push(HirPipelineStage::Export {
                                    format: "json".to_string(),
                                    path: path.clone(),
                                    span: *s,
                                });
                            }
                        }
                    }
                    operations.push(HirOperation::EvidencePipeline {
                        variable: variable.clone(),
                        stages: hir_stages,
                        span: *span,
                    });
                }
            }
        }

        let provenance = HirProvenance {
            source_hash,
            ast_hash,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok(HirInvestigation {
            name: ast.name.clone(),
            target: ast.target.clone(),
            metadata,
            operations,
            capabilities: capabilities.clone(),
            provenance,
            span: ast.span,
        })
    }

    fn lower_collect(
        target: &CollectTarget,
        options: &CollectOptions,
        span: Span,
    ) -> Result<HirOperation, Vec<Diagnostic>> {
        match target {
            CollectTarget::SystemInfo => Ok(HirOperation::CollectSystemInfo { span }),
            CollectTarget::Processes => {
                let fields = options.fields.clone();
                let hash_algo = options.hash_algorithm.as_ref().map(|h| match h {
                    HashAlgorithm::Sha256 => "sha256".to_string(),
                    HashAlgorithm::Sha1 => "sha1".to_string(),
                    HashAlgorithm::Md5 => "md5".to_string(),
                });
                Ok(HirOperation::CollectProcesses {
                    fields,
                    hash_algorithm: hash_algo,
                    span,
                })
            }
            CollectTarget::ProcessTree => Ok(HirOperation::CollectProcessTree { span }),
            CollectTarget::ProcessModules { pid } => {
                Ok(HirOperation::CollectProcessModules { pid: *pid, span })
            }
            CollectTarget::ProcessHandles { pid } => {
                Ok(HirOperation::CollectProcessHandles { pid: *pid, span })
            }
            CollectTarget::DeletedExecutables => {
                Ok(HirOperation::CollectDeletedExecutables { span })
            }
            CollectTarget::NetworkConnections => {
                Ok(HirOperation::CollectNetworkConnections { span })
            }
            CollectTarget::Files { path } => {
                let recursive = options.recursive;
                let hash_algo = options
                    .hash_algorithm
                    .as_ref()
                    .map(|h| match h {
                        HashAlgorithm::Sha256 => "sha256".to_string(),
                        HashAlgorithm::Sha1 => "sha1".to_string(),
                        HashAlgorithm::Md5 => "md5".to_string(),
                    })
                    .unwrap_or_else(|| "none".to_string());

                Ok(HirOperation::CollectFiles {
                    path: path.clone(),
                    recursive,
                    hash_algorithm: hash_algo,
                    span,
                })
            }
            CollectTarget::Logs { source } => Ok(HirOperation::CollectLogs {
                source: source.clone(),
                span,
            }),
            CollectTarget::Drivers => Ok(HirOperation::CollectDrivers { span }),
            CollectTarget::MemoryRegions => Ok(HirOperation::CollectMemoryRegions { pid: 0, span }),
            CollectTarget::Registry { hive, key_path } => Ok(HirOperation::CollectRegistry {
                hive: hive.clone(),
                key_path: key_path.clone(),
                span,
            }),
            CollectTarget::Artifacts {
                artifact_type,
                path,
            } => Ok(HirOperation::CollectArtifacts {
                artifact_type: artifact_type.clone(),
                path: path.clone(),
                span,
            }),
            CollectTarget::Timeline { sources } => Ok(HirOperation::CollectTimeline {
                sources: sources.clone(),
                span,
            }),
            CollectTarget::Evidence { format } => Ok(HirOperation::CollectEvidence {
                format: format.clone(),
                span,
            }),
        }
    }

    fn lower_expr(expr: &Expr) -> Result<HirExpr, Vec<Diagnostic>> {
        match expr {
            Expr::Identifier(name, _) => Ok(HirExpr::Variable { name: name.clone() }),
            Expr::Pipeline { source, stages, .. } => {
                let source_hir = Self::lower_expr(source)?;
                let mut hir_stages = Vec::new();
                for stage in stages {
                    match stage {
                        PipelineStage::Where(e, s) => {
                            hir_stages.push(HirPipelineStage::Where {
                                condition: Self::expr_to_json(e),
                                span: *s,
                            });
                        }
                        PipelineStage::Filter(e, s) => {
                            hir_stages.push(HirPipelineStage::Filter {
                                condition: Self::expr_to_json(e),
                                span: *s,
                            });
                        }
                        PipelineStage::Limit(e, s) => {
                            let limit_val = Self::expr_as_usize(e).unwrap_or(0);
                            hir_stages.push(HirPipelineStage::Limit {
                                count: limit_val,
                                span: *s,
                            });
                        }
                        PipelineStage::Hash(algo, s) => {
                            hir_stages.push(HirPipelineStage::Hash {
                                algorithm: match algo {
                                    HashAlgorithm::Sha256 => "sha256".to_string(),
                                    HashAlgorithm::Sha1 => "sha1".to_string(),
                                    HashAlgorithm::Md5 => "md5".to_string(),
                                },
                                span: *s,
                            });
                        }
                        PipelineStage::Timeline(s) => {
                            hir_stages.push(HirPipelineStage::Timeline { span: *s });
                        }
                        PipelineStage::Export(path, s) => {
                            hir_stages.push(HirPipelineStage::Export {
                                format: "json".to_string(),
                                path: path.clone(),
                                span: *s,
                            });
                        }
                    }
                }
                Ok(HirExpr::Pipeline {
                    source: Box::new(source_hir),
                    stages: hir_stages,
                })
            }
            Expr::StringLiteral(s, _) => Ok(HirExpr::Literal {
                value: serde_json::Value::String(s.clone()),
            }),
            Expr::IntegerLiteral(i, _) => Ok(HirExpr::Literal {
                value: serde_json::json!(i),
            }),
            Expr::FloatLiteral(f, _) => Ok(HirExpr::Literal {
                value: serde_json::json!(f),
            }),
            Expr::BooleanLiteral(b, _) => Ok(HirExpr::Literal {
                value: serde_json::Value::Bool(*b),
            }),
            _ => Ok(HirExpr::Literal {
                value: Self::expr_to_json(expr),
            }),
        }
    }

    fn expr_as_usize(expr: &Expr) -> Option<usize> {
        match expr {
            Expr::IntegerLiteral(i, _) => Some(*i as usize),
            _ => None,
        }
    }

    fn expr_to_json(expr: &Expr) -> serde_json::Value {
        match expr {
            Expr::Identifier(s, _) => serde_json::json!({ "field": s }),
            Expr::StringLiteral(s, _) => serde_json::Value::String(s.clone()),
            Expr::IntegerLiteral(i, _) => serde_json::json!(i),
            Expr::FloatLiteral(f, _) => serde_json::json!(f),
            Expr::BooleanLiteral(b, _) => serde_json::Value::Bool(*b),
            Expr::BinaryOp {
                left, op, right, ..
            } => {
                let op_str = match op {
                    BinaryOp::Equal => "==",
                    BinaryOp::NotEqual => "!=",
                    BinaryOp::Less => "<",
                    BinaryOp::LessEqual => "<=",
                    BinaryOp::Greater => ">",
                    BinaryOp::GreaterEqual => ">=",
                    BinaryOp::And => "and",
                    BinaryOp::Or => "or",
                    BinaryOp::Contains => "contains",
                    BinaryOp::Add => "+",
                    BinaryOp::Subtract => "-",
                    BinaryOp::Multiply => "*",
                    BinaryOp::Divide => "/",
                };
                serde_json::json!({
                    "left": Self::expr_to_json(left),
                    "op": op_str,
                    "right": Self::expr_to_json(right),
                })
            }
            Expr::ArrayLiteral(items, _) => {
                let arr: Vec<serde_json::Value> = items.iter().map(Self::expr_to_json).collect();
                serde_json::Value::Array(arr)
            }
            Expr::ObjectLiteral(entries, _) => {
                let mut map = serde_json::Map::new();
                for (k, v) in entries {
                    map.insert(k.clone(), Self::expr_to_json(v));
                }
                serde_json::Value::Object(map)
            }
            _ => serde_json::Value::Null,
        }
    }
}

impl From<&jockey_ir::IrInvestigation> for HirInvestigation {
    fn from(ir: &jockey_ir::IrInvestigation) -> Self {
        let mut operations = Vec::new();
        for op in &ir.operations {
            match op {
                jockey_ir::IrOperation::Collect(c) => match c.operation.as_str() {
                    "system.info" => {
                        operations.push(invoke_capability_from_ir(c, "system.info.basic"));
                    }
                    "process.enumerate" => {
                        operations.push(invoke_capability_from_ir(c, "process.enumerate"));
                    }
                    "network.connections" => {
                        operations.push(invoke_capability_from_ir(c, "network.connections"));
                    }
                    "filesystem.enumerate" => {
                        operations.push(invoke_capability_from_ir(c, "filesystem.enumerate"));
                    }
                    "logs.collect" => {
                        let source = c
                            .options
                            .get("source")
                            .and_then(|v| v.as_str())
                            .unwrap_or("system")
                            .to_string();
                        operations.push(HirOperation::CollectLogs {
                            source,
                            span: c.span,
                        });
                    }
                    "drivers.enumerate" => {
                        operations.push(invoke_capability_from_ir(c, "service.drivers"));
                    }
                    "memory.regions" => {
                        operations.push(invoke_capability_from_ir(c, "process.memory"));
                    }
                    "registry.enumerate" => {
                        let hive = c
                            .options
                            .get("hive")
                            .and_then(|v| v.as_str())
                            .unwrap_or("HKLM")
                            .to_string();
                        let key_path = c
                            .options
                            .get("key_path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("SOFTWARE")
                            .to_string();
                        operations.push(HirOperation::CollectRegistry {
                            hive,
                            key_path,
                            span: c.span,
                        });
                    }
                    "artifacts.carve" => {
                        let artifact_type = c
                            .options
                            .get("artifact_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("all")
                            .to_string();
                        let path = c
                            .options
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        operations.push(HirOperation::CollectArtifacts {
                            artifact_type,
                            path,
                            span: c.span,
                        });
                    }
                    "timeline.build" | "timeline" => {
                        let sources = c
                            .options
                            .get("sources")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        operations.push(HirOperation::CollectTimeline {
                            sources,
                            span: c.span,
                        });
                    }
                    "evidence" => {
                        let format = c
                            .options
                            .get("format")
                            .and_then(|v| v.as_str())
                            .unwrap_or("json")
                            .to_string();
                        operations.push(HirOperation::CollectEvidence {
                            format,
                            span: c.span,
                        });
                    }
                    _ => operations.push(HirOperation::InvokeCapability {
                        capability_id: c.operation.clone(),
                        fields: c.fields.clone(),
                        options: c.options.clone(),
                        span: c.span,
                    }),
                },
                jockey_ir::IrOperation::Export(e) => {
                    operations.push(HirOperation::Export {
                        format: e.format.clone(),
                        path: e.path.clone(),
                        span: e.span,
                    });
                }
                jockey_ir::IrOperation::Filter(f) => {
                    operations.push(HirOperation::Filter {
                        condition: f.condition.clone(),
                        span: f.span,
                    });
                }
                jockey_ir::IrOperation::Where(w) => {
                    operations.push(HirOperation::Where {
                        condition: w.condition.clone(),
                        span: w.span,
                    });
                }
                jockey_ir::IrOperation::Limit(l) => {
                    let count = l.count.as_u64().unwrap_or(0) as usize;
                    operations.push(HirOperation::Limit {
                        count,
                        span: l.span,
                    });
                }
                jockey_ir::IrOperation::Assign(a) => {
                    operations.push(HirOperation::Assign {
                        variable: a.variable.clone(),
                        expr: HirExpr::Literal {
                            value: a.expression.clone(),
                        },
                        span: a.span,
                    });
                }
                jockey_ir::IrOperation::EvidencePipeline(ep) => {
                    let stages = ep
                        .stages
                        .iter()
                        .map(|s| match s {
                            jockey_ir::IrPipelineStage::Where { condition, span } => {
                                HirPipelineStage::Where {
                                    condition: condition.clone(),
                                    span: *span,
                                }
                            }
                            jockey_ir::IrPipelineStage::Filter { condition, span } => {
                                HirPipelineStage::Filter {
                                    condition: condition.clone(),
                                    span: *span,
                                }
                            }
                            jockey_ir::IrPipelineStage::Limit { count, span } => {
                                let lim = count.as_u64().unwrap_or(0) as usize;
                                HirPipelineStage::Limit {
                                    count: lim,
                                    span: *span,
                                }
                            }
                            jockey_ir::IrPipelineStage::Hash { algorithm, span } => {
                                HirPipelineStage::Hash {
                                    algorithm: algorithm.clone(),
                                    span: *span,
                                }
                            }
                            jockey_ir::IrPipelineStage::Timeline { span } => {
                                HirPipelineStage::Timeline { span: *span }
                            }
                            jockey_ir::IrPipelineStage::Export { path, span } => {
                                HirPipelineStage::Export {
                                    format: "json".to_string(),
                                    path: path.clone(),
                                    span: *span,
                                }
                            }
                        })
                        .collect();
                    operations.push(HirOperation::EvidencePipeline {
                        variable: ep.variable.clone(),
                        stages,
                        span: ep.span,
                    });
                }
                jockey_ir::IrOperation::Metadata(..) => {}
            }
        }

        let ir_json = serde_json::to_string(ir).unwrap_or_default();
        let mut hasher = sha2::Sha256::new();
        hasher.update(ir_json.as_bytes());
        let ir_hash = format!("{:x}", hasher.finalize());

        HirInvestigation {
            name: ir.name.clone(),
            target: ir.target.clone(),
            metadata: ir.metadata.clone(),
            operations,
            capabilities: ir.required_capabilities.clone(),
            provenance: HirProvenance {
                source_hash: ir_hash.clone(),
                ast_hash: ir_hash,
                compiler_version: env!("CARGO_PKG_VERSION").to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            span: ir.span,
        }
    }
}

fn invoke_capability_from_ir(
    operation: &jockey_ir::IrCollectOperation,
    capability_id: &str,
) -> HirOperation {
    let mut options = operation.options.clone();
    options.insert("fields".to_string(), serde_json::json!(operation.fields));
    HirOperation::InvokeCapability {
        capability_id: capability_id.to_string(),
        fields: operation.fields.clone(),
        options,
        span: operation.span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jockey_ast::{CollectOptions, CollectTarget, ExportFormat, Investigation, Stmt};

    #[test]
    fn test_hir_lowering_basic() {
        let ast = Investigation {
            name: "test_investigation".to_string(),
            target: Some("linux".to_string()),
            metadata: vec![],
            statements: vec![
                Stmt::Collect {
                    target: CollectTarget::SystemInfo,
                    options: CollectOptions::default(),
                    span: Span::new(1, 1, 1, 20),
                },
                Stmt::Export {
                    format: ExportFormat::Json,
                    path: "out.json".to_string(),
                    span: Span::new(2, 1, 2, 20),
                },
            ],
            span: Span::new(1, 1, 2, 20),
        };

        let mut caps = HashSet::new();
        caps.insert(Capability::SystemInfoRead);

        let hir = HirLowering::lower(&ast, &caps, "source code test").expect("HIR lowering failed");
        assert_eq!(hir.name, "test_investigation");
        assert_eq!(hir.operations.len(), 2);
        assert!(hir.capabilities.contains(&Capability::SystemInfoRead));
        assert!(!hir.provenance.source_hash.is_empty());
        assert!(!hir.provenance.ast_hash.is_empty());
    }

    #[test]
    fn test_hir_provenance_determinism() {
        let ast = Investigation {
            name: "det_test".to_string(),
            target: None,
            metadata: vec![],
            statements: vec![],
            span: Span::new(1, 1, 1, 10),
        };
        let caps = HashSet::new();

        let hir1 = HirLowering::lower(&ast, &caps, "const source").unwrap();
        let hir2 = HirLowering::lower(&ast, &caps, "const source").unwrap();

        assert_eq!(hir1.provenance.source_hash, hir2.provenance.source_hash);
        assert_eq!(hir1.provenance.ast_hash, hir2.provenance.ast_hash);
    }

    #[test]
    fn test_hir_lowering_all_collectors() {
        use jockey_ast::HashAlgorithm;

        let ast = Investigation {
            name: "all_collectors".to_string(),
            target: Some("linux".to_string()),
            metadata: vec![],
            statements: vec![
                Stmt::Collect {
                    target: CollectTarget::SystemInfo,
                    options: CollectOptions::default(),
                    span: Span::new(1, 1, 1, 10),
                },
                Stmt::Collect {
                    target: CollectTarget::Processes,
                    options: CollectOptions {
                        fields: vec!["pid".to_string(), "name".to_string()],
                        ..Default::default()
                    },
                    span: Span::new(2, 1, 2, 10),
                },
                Stmt::Collect {
                    target: CollectTarget::NetworkConnections,
                    options: CollectOptions::default(),
                    span: Span::new(3, 1, 3, 10),
                },
                Stmt::Collect {
                    target: CollectTarget::Files {
                        path: "/var/log".to_string(),
                    },
                    options: CollectOptions {
                        recursive: true,
                        hash_algorithm: Some(HashAlgorithm::Sha256),
                        ..Default::default()
                    },
                    span: Span::new(4, 1, 4, 10),
                },
                Stmt::Collect {
                    target: CollectTarget::Logs {
                        source: "auth".to_string(),
                    },
                    options: CollectOptions::default(),
                    span: Span::new(5, 1, 5, 10),
                },
                Stmt::Collect {
                    target: CollectTarget::Drivers,
                    options: CollectOptions::default(),
                    span: Span::new(6, 1, 6, 10),
                },
                Stmt::Export {
                    format: ExportFormat::Json,
                    path: "evidence.json".to_string(),
                    span: Span::new(7, 1, 7, 10),
                },
            ],
            span: Span::new(1, 1, 7, 10),
        };

        let mut caps = HashSet::new();
        caps.insert(Capability::SystemInfoRead);
        caps.insert(Capability::ProcessRead);
        caps.insert(Capability::NetworkRead);
        caps.insert(Capability::FilesystemRead);
        caps.insert(Capability::LogRead);
        caps.insert(Capability::DriverRead);

        let hir = HirLowering::lower(&ast, &caps, "source").expect("Hir lowering failed");
        assert_eq!(hir.operations.len(), 7);

        // Verify each operation variant exists in order
        assert!(matches!(
            hir.operations[0],
            HirOperation::CollectSystemInfo { .. }
        ));
        assert!(matches!(
            hir.operations[1],
            HirOperation::CollectProcesses { .. }
        ));
        assert!(matches!(
            hir.operations[2],
            HirOperation::CollectNetworkConnections { .. }
        ));
        assert!(matches!(
            hir.operations[3],
            HirOperation::CollectFiles { .. }
        ));
        assert!(matches!(
            hir.operations[4],
            HirOperation::CollectLogs { .. }
        ));
        assert!(matches!(
            hir.operations[5],
            HirOperation::CollectDrivers { .. }
        ));
        assert!(matches!(hir.operations[6], HirOperation::Export { .. }));
    }

    #[test]
    fn test_hir_lowering_pipelines_and_filters() {
        use jockey_ast::{Expr, HashAlgorithm, PipelineStage};

        let ast = Investigation {
            name: "pipeline_test".to_string(),
            target: Some("linux".to_string()),
            metadata: vec![],
            statements: vec![
                Stmt::Filter {
                    condition: Expr::Identifier("status".to_string(), Span::new(1, 1, 1, 10)),
                    span: Span::new(1, 1, 1, 10),
                },
                Stmt::Where {
                    condition: Expr::Identifier("active".to_string(), Span::new(2, 1, 2, 10)),
                    span: Span::new(2, 1, 2, 10),
                },
                Stmt::Limit {
                    count: Expr::IntegerLiteral(25, Span::new(3, 1, 3, 10)),
                    span: Span::new(3, 1, 3, 10),
                },
                Stmt::EvidencePipeline {
                    variable: "procs".to_string(),
                    stages: vec![
                        PipelineStage::Hash(HashAlgorithm::Sha256, Span::new(4, 1, 4, 10)),
                        PipelineStage::Timeline(Span::new(4, 11, 4, 20)),
                        PipelineStage::Export("out.json".to_string(), Span::new(4, 21, 4, 30)),
                    ],
                    span: Span::new(4, 1, 4, 30),
                },
            ],
            span: Span::new(1, 1, 4, 30),
        };

        let hir = HirLowering::lower(&ast, &HashSet::new(), "source").expect("HIR lowering failed");
        assert_eq!(hir.operations.len(), 4);
        assert!(matches!(hir.operations[0], HirOperation::Filter { .. }));
        assert!(matches!(hir.operations[1], HirOperation::Where { .. }));
        assert!(matches!(
            hir.operations[2],
            HirOperation::Limit { count: 25, .. }
        ));
        if let HirOperation::EvidencePipeline { stages, .. } = &hir.operations[3] {
            assert_eq!(stages.len(), 3);
            assert!(
                matches!(stages[0], HirPipelineStage::Hash { ref algorithm, .. } if algorithm == "sha256")
            );
            assert!(matches!(stages[1], HirPipelineStage::Timeline { .. }));
            assert!(
                matches!(stages[2], HirPipelineStage::Export { ref path, .. } if path == "out.json")
            );
        } else {
            panic!("Expected EvidencePipeline operation");
        }
    }

    #[test]
    fn test_hir_from_ir_roundtrip() {
        use jockey_ir::{IrCollectOperation, IrExportOperation, IrInvestigation, IrOperation};

        let ir = IrInvestigation {
            name: "from_ir_test".to_string(),
            target: Some("windows".to_string()),
            metadata: vec![],
            operations: vec![
                IrOperation::Collect(IrCollectOperation {
                    operation: "system.info".to_string(),
                    fields: vec![],
                    options: serde_json::Map::new(),
                    span: Span::new(1, 1, 1, 10),
                }),
                IrOperation::Export(IrExportOperation {
                    format: "json".to_string(),
                    path: "ir_out.json".to_string(),
                    span: Span::new(2, 1, 2, 20),
                }),
            ],
            required_capabilities: HashSet::new(),
            span: Span::new(1, 1, 2, 20),
        };

        let hir = HirInvestigation::from(&ir);
        assert_eq!(hir.name, "from_ir_test");
        assert_eq!(hir.target, Some("windows".to_string()));
        assert_eq!(hir.operations.len(), 2);
        assert!(!hir.provenance.source_hash.is_empty());
    }

    #[test]
    fn test_hir_preserves_unknown_capability_identity_and_options() {
        use jockey_ir::{IrCollectOperation, IrInvestigation, IrOperation};

        let mut options = serde_json::Map::new();
        options.insert("path".to_string(), serde_json::json!("/var/log"));
        let ir = IrInvestigation {
            name: "capability_dispatch".to_string(),
            target: None,
            metadata: vec![],
            operations: vec![IrOperation::Collect(IrCollectOperation {
                operation: "network.routes".to_string(),
                fields: vec!["destination".to_string()],
                options,
                span: Span::new(1, 1, 1, 20),
            })],
            required_capabilities: HashSet::new(),
            span: Span::new(1, 1, 1, 20),
        };

        let hir = HirInvestigation::from(&ir);
        assert!(matches!(
            &hir.operations[0],
            HirOperation::InvokeCapability { capability_id, fields, options, .. }
                if capability_id == "network.routes"
                    && fields == &["destination"]
                    && options.get("path").and_then(serde_json::Value::as_str) == Some("/var/log")
        ));
    }

    #[test]
    fn test_hir_maps_core_collectors_to_runtime_capability_ids() {
        use jockey_ir::{IrCollectOperation, IrInvestigation, IrOperation};

        let operations = [
            "system.info",
            "process.enumerate",
            "network.connections",
            "filesystem.enumerate",
        ]
        .into_iter()
        .map(|operation| {
            IrOperation::Collect(IrCollectOperation {
                operation: operation.to_string(),
                fields: vec![],
                options: serde_json::Map::new(),
                span: Span::new(1, 1, 1, 20),
            })
        })
        .collect();
        let ir = IrInvestigation {
            name: "core_capabilities".to_string(),
            target: None,
            metadata: vec![],
            operations,
            required_capabilities: HashSet::new(),
            span: Span::new(1, 1, 1, 20),
        };

        let hir = HirInvestigation::from(&ir);
        let ids = hir
            .operations
            .iter()
            .filter_map(|operation| match operation {
                HirOperation::InvokeCapability { capability_id, .. } => {
                    Some(capability_id.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "system.info.basic",
                "process.enumerate",
                "network.connections",
                "filesystem.enumerate"
            ]
        );
    }
}
