//! TraceForge HIR - High-Level Intermediate Representation
//!
//! HIR captures semantic meaning, resolved capabilities, evidence requirements,
//! and provenance, separating syntax structure from semantic operations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use traceforge_ast::{
    BinaryOp, Capability, CollectOptions, CollectTarget, Diagnostic, ExportFormat, Expr,
    HashAlgorithm, Investigation, PipelineStage, Span, Stmt,
};

/// High-Level Intermediate Representation of a TraceForge Investigation
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
                Stmt::Export {
                    format,
                    path,
                    span,
                } => {
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
            CollectTarget::Evidence { .. } | CollectTarget::Timeline { .. } => {
                Ok(HirOperation::CollectSystemInfo { span })
            }
        }
    }

    fn lower_expr(expr: &Expr) -> Result<HirExpr, Vec<Diagnostic>> {
        match expr {
            Expr::Identifier(name, _) => Ok(HirExpr::Variable { name: name.clone() }),
            Expr::Pipeline {
                source,
                stages,
                ..
            } => {
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
                left,
                op,
                right,
                ..
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

impl From<&traceforge_ir::IrInvestigation> for HirInvestigation {
    fn from(ir: &traceforge_ir::IrInvestigation) -> Self {
        let mut operations = Vec::new();
        for op in &ir.operations {
            match op {
                traceforge_ir::IrOperation::Collect(c) => match c.operation.as_str() {
                    "system.info" => {
                        operations.push(HirOperation::CollectSystemInfo { span: c.span });
                    }
                    "process.enumerate" => {
                        let hash_algo = c
                            .options
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        operations.push(HirOperation::CollectProcesses {
                            fields: c.fields.clone(),
                            hash_algorithm: hash_algo,
                            span: c.span,
                        });
                    }
                    "network.connections" => {
                        operations.push(HirOperation::CollectNetworkConnections { span: c.span });
                    }
                    "filesystem.enumerate" => {
                        let path = c
                            .options
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("/")
                            .to_string();
                        let recursive = c
                            .options
                            .get("recursive")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let hash_algo = c
                            .options
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("none")
                            .to_string();
                        operations.push(HirOperation::CollectFiles {
                            path,
                            recursive,
                            hash_algorithm: hash_algo,
                            span: c.span,
                        });
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
                        operations.push(HirOperation::CollectDrivers { span: c.span });
                    }
                    _ => {}
                },
                traceforge_ir::IrOperation::Export(e) => {
                    operations.push(HirOperation::Export {
                        format: e.format.clone(),
                        path: e.path.clone(),
                        span: e.span,
                    });
                }
                traceforge_ir::IrOperation::Filter(f) => {
                    operations.push(HirOperation::Filter {
                        condition: f.condition.clone(),
                        span: f.span,
                    });
                }
                traceforge_ir::IrOperation::Where(w) => {
                    operations.push(HirOperation::Where {
                        condition: w.condition.clone(),
                        span: w.span,
                    });
                }
                traceforge_ir::IrOperation::Limit(l) => {
                    let count = l.count.as_u64().unwrap_or(0) as usize;
                    operations.push(HirOperation::Limit {
                        count,
                        span: l.span,
                    });
                }
                traceforge_ir::IrOperation::Assign(a) => {
                    operations.push(HirOperation::Assign {
                        variable: a.variable.clone(),
                        expr: HirExpr::Literal {
                            value: a.expression.clone(),
                        },
                        span: a.span,
                    });
                }
                traceforge_ir::IrOperation::EvidencePipeline(ep) => {
                    let stages = ep
                        .stages
                        .iter()
                        .map(|s| match s {
                            traceforge_ir::IrPipelineStage::Where { condition, span } => {
                                HirPipelineStage::Where {
                                    condition: condition.clone(),
                                    span: *span,
                                }
                            }
                            traceforge_ir::IrPipelineStage::Filter { condition, span } => {
                                HirPipelineStage::Filter {
                                    condition: condition.clone(),
                                    span: *span,
                                }
                            }
                            traceforge_ir::IrPipelineStage::Limit { count, span } => {
                                let lim = count.as_u64().unwrap_or(0) as usize;
                                HirPipelineStage::Limit {
                                    count: lim,
                                    span: *span,
                                }
                            }
                            traceforge_ir::IrPipelineStage::Hash { algorithm, span } => {
                                HirPipelineStage::Hash {
                                    algorithm: algorithm.clone(),
                                    span: *span,
                                }
                            }
                            traceforge_ir::IrPipelineStage::Timeline { span } => {
                                HirPipelineStage::Timeline { span: *span }
                            }
                            traceforge_ir::IrPipelineStage::Export {
                                path,
                                span,
                            } => HirPipelineStage::Export {
                                format: "json".to_string(),
                                path: path.clone(),
                                span: *span,
                            },
                        })
                        .collect();
                    operations.push(HirOperation::EvidencePipeline {
                        variable: ep.variable.clone(),
                        stages,
                        span: ep.span,
                    });
                }
                traceforge_ir::IrOperation::Metadata(..) => {}
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

#[cfg(test)]
mod tests {
    use super::*;
    use traceforge_ast::{CollectOptions, CollectTarget, ExportFormat, Investigation, Stmt};

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
}
