//! jockey IR - Intermediate Representation

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use jockey_ast::{Capability, Span};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInvestigation {
    pub name: String,
    pub target: Option<String>,
    pub metadata: Vec<(String, serde_json::Value)>,
    pub operations: Vec<IrOperation>,
    pub required_capabilities: HashSet<Capability>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IrOperation {
    Collect(IrCollectOperation),
    Export(IrExportOperation),
    Filter(IrFilterOperation),
    Where(IrWhereOperation),
    Limit(IrLimitOperation),
    Metadata(IrMetadataOperation),
    /// Variable assignment: `var = collect ...` or `var = expr | where ...`
    Assign(IrAssignOperation),
    /// Evidence pipeline statement: `evidence var | hash sha256 | timeline | export "out.json"`
    EvidencePipeline(IrEvidencePipelineOperation),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrCollectOperation {
    pub operation: String,
    pub fields: Vec<String>,
    pub options: serde_json::Map<String, serde_json::Value>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrExportOperation {
    pub format: String,
    pub path: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFilterOperation {
    pub condition: serde_json::Value,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrWhereOperation {
    pub condition: serde_json::Value,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrLimitOperation {
    pub count: serde_json::Value,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrMetadataOperation {
    pub metadata: Vec<(String, serde_json::Value)>,
    pub span: Span,
}

/// Assignment: variable_name = pipeline-expression (collect + optional filters)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrAssignOperation {
    /// Target variable name
    pub variable: String,
    /// The RHS expression in JSON form (for pipeline/collect expressions)
    pub expression: serde_json::Value,
    pub span: Span,
}

/// Evidence pipeline: `evidence varname | hash sha256 | timeline | export "path"`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrEvidencePipelineOperation {
    pub variable: String,
    pub stages: Vec<IrPipelineStage>,
    pub span: Span,
}

/// A single pipeline stage in evidence pipelines
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "stage")]
pub enum IrPipelineStage {
    Where {
        condition: serde_json::Value,
        span: Span,
    },
    Filter {
        condition: serde_json::Value,
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
        path: String,
        span: Span,
    },
    Limit {
        count: serde_json::Value,
        span: Span,
    },
}

/// IR Version for compatibility checking
pub const IR_VERSION: &str = "0.1";

/// Serialize IR to JSON
pub fn serialize_ir(investigation: &IrInvestigation) -> Result<String, serde_json::Error> {
    let wrapper = IrWrapper {
        version: IR_VERSION.to_string(),
        investigation: investigation.clone(),
    };
    serde_json::to_string_pretty(&wrapper)
}

/// Deserialize IR from JSON
pub fn deserialize_ir(json: &str) -> Result<IrInvestigation, serde_json::Error> {
    let wrapper: IrWrapper = serde_json::from_str(json)?;
    if wrapper.version != IR_VERSION {
        // Could handle version migration here
    }
    Ok(wrapper.investigation)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IrWrapper {
    version: String,
    investigation: IrInvestigation,
}

/// Target platform for compilation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetPlatform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetArch {
    X64,
    Arm64,
}

/// Build configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub target_platform: TargetPlatform,
    pub target_arch: TargetArch,
    pub optimization_level: OptimizationLevel,
    pub debug_symbols: bool,
    pub strip_symbols: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationLevel {
    None,
    Size,
    Speed,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            target_platform: TargetPlatform::Linux,
            target_arch: TargetArch::X64,
            optimization_level: OptimizationLevel::Speed,
            debug_symbols: false,
            strip_symbols: true,
        }
    }
}

/// Build artifact metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub investigation_name: String,
    pub source_hash: String,
    pub compiler_version: String,
    pub compiler_hash: String,
    pub target_platform: TargetPlatform,
    pub target_arch: TargetArch,
    pub build_timestamp: String,
    pub artifact_hash: String,
    pub required_capabilities: Vec<String>,
    pub ir_version: String,
}
