//! jockey IR - Intermediate Representation

use jockey_ast::{Capability, Span};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Canonical file extension for JOCKEY DSL source files (without dot).
pub const JOCKEY_SOURCE_EXTENSION: &str = "jy";

/// Canonical file extension for JOCKEY DSL source files (with dot).
pub const JOCKEY_SOURCE_EXTENSION_DOT: &str = ".jy";

/// Check if a path has the official `.jy` JOCKEY source extension.
pub fn is_jockey_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case(JOCKEY_SOURCE_EXTENSION))
        .unwrap_or(false)
}

/// Validate that a path has the official `.jy` JOCKEY source extension,
/// returning a clear diagnostic error message if not.
pub fn validate_source_extension(path: &Path) -> Result<(), String> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case(JOCKEY_SOURCE_EXTENSION) => Ok(()),
        Some(ext) => Err(format!(
            "Unsupported JOCKEY source extension '.{}'.\nExpected a '.jy' source file.\n\nExample:\n  jockey check examples/complete_forensic_triage.jy",
            ext
        )),
        None => Err(format!(
            "Missing file extension on '{}'.\nExpected a '.jy' source file.\n\nExample:\n  jockey check examples/complete_forensic_triage.jy",
            path.display()
        )),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_canonical_extension_constants() {
        assert_eq!(JOCKEY_SOURCE_EXTENSION, "jy");
        assert_eq!(JOCKEY_SOURCE_EXTENSION_DOT, ".jy");
    }

    #[test]
    fn test_is_jockey_source_file() {
        assert!(is_jockey_source_file(Path::new("test.jy")));
        assert!(is_jockey_source_file(Path::new(
            "examples/complete_forensic_triage.jy"
        )));
        assert!(is_jockey_source_file(Path::new("TEST.JY")));
        assert!(!is_jockey_source_file(Path::new("test.tfg")));
        assert!(!is_jockey_source_file(Path::new("test.rs")));
        assert!(!is_jockey_source_file(Path::new("test")));
    }

    #[test]
    fn test_validate_source_extension_accepted() {
        assert!(validate_source_extension(Path::new("investigation.jy")).is_ok());
        assert!(validate_source_extension(Path::new("path/to/my_tool.jy")).is_ok());
    }

    #[test]
    fn test_validate_source_extension_rejected_tfg() {
        let result = validate_source_extension(Path::new("legacy.tfg"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unsupported JOCKEY source extension '.tfg'"));
        assert!(err.contains("Expected a '.jy' source file"));
    }

    #[test]
    fn test_validate_source_extension_rejected_no_ext() {
        let result = validate_source_extension(Path::new("no_extension"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Missing file extension"));
        assert!(err.contains("Expected a '.jy' source file"));
    }
}
