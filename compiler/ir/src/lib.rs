//! jocky IR - Intermediate Representation

use jocky_ast::{Capability, Span};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Canonical file extension for JOCKY DSL source files (without dot).
pub const JOCKY_SOURCE_EXTENSION: &str = "jy";

/// Canonical file extension for JOCKY DSL source files (with dot).
pub const JOCKY_SOURCE_EXTENSION_DOT: &str = ".jy";

/// Check if a path has the official `.jy` JOCKY source extension.
pub fn is_jocky_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case(JOCKY_SOURCE_EXTENSION))
        .unwrap_or(false)
}

/// Validate that a path has the official `.jy` JOCKY source extension,
/// returning a clear diagnostic error message if not.
pub fn validate_source_extension(path: &Path) -> Result<(), String> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case(JOCKY_SOURCE_EXTENSION) => Ok(()),
        Some(ext) => Err(format!(
            "Unsupported JOCKY source extension '.{}'.\nExpected a '.jy' source file.\n\nExample:\n  jocky check examples/complete_forensic_triage.jy",
            ext
        )),
        None => Err(format!(
            "Missing file extension on '{}'.\nExpected a '.jy' source file.\n\nExample:\n  jocky check examples/complete_forensic_triage.jy",
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

/// Obfuscation configuration for polymorphic binary generation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscationConfig {
    /// Enable CFG flattening: converts linear control flow into a state-machine dispatcher
    pub cfg_flattening: bool,
    /// Encrypt string/constant literals with a per-build XOR key
    pub string_encryption: bool,
    /// Insert junk (dead) instructions to defeat signature matching
    pub junk_insertion: bool,
    /// Insert opaque predicate branches that always evaluate the same way
    pub opaque_predicates: bool,
    /// Append a unique random watermark section so each build has a unique hash
    pub polymorphic_watermark: bool,
    /// Per-build random seed (generated at compile time; ensures unique binaries)
    pub build_seed: u64,
}

impl ObfuscationConfig {
    /// Return true if any obfuscation pass is enabled
    pub fn is_any_enabled(&self) -> bool {
        self.cfg_flattening
            || self.string_encryption
            || self.junk_insertion
            || self.opaque_predicates
            || self.polymorphic_watermark
    }

    /// Create a fully-enabled polymorphic config with a freshly generated random seed
    pub fn full_polymorphic() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEADBEEFCAFEBABE);
        Self {
            cfg_flattening: true,
            string_encryption: true,
            junk_insertion: true,
            opaque_predicates: true,
            polymorphic_watermark: true,
            build_seed: seed,
        }
    }
}

/// Build configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub target_platform: TargetPlatform,
    pub target_arch: TargetArch,
    pub optimization_level: OptimizationLevel,
    pub debug_symbols: bool,
    pub strip_symbols: bool,
    /// Obfuscation and polymorphism options (default: all disabled)
    pub obfuscation: ObfuscationConfig,
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
            obfuscation: ObfuscationConfig::default(),
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
    /// SHA-256 hash of the emitted binary (set after compilation)
    pub build_hash: Option<String>,
    /// Whether this binary was produced with polymorphic obfuscation
    pub unique_binary: bool,
    /// The per-build seed used for obfuscation (0 if not obfuscated)
    pub obfuscation_seed: u64,
    /// Byte offset of the polymorphic watermark section in the binary (None if not present)
    pub watermark_section_offset: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_canonical_extension_constants() {
        assert_eq!(JOCKY_SOURCE_EXTENSION, "jy");
        assert_eq!(JOCKY_SOURCE_EXTENSION_DOT, ".jy");
    }

    #[test]
    fn test_is_jocky_source_file() {
        assert!(is_jocky_source_file(Path::new("test.jy")));
        assert!(is_jocky_source_file(Path::new(
            "examples/complete_forensic_triage.jy"
        )));
        assert!(is_jocky_source_file(Path::new("TEST.JY")));
        assert!(!is_jocky_source_file(Path::new("test.tfg")));
        assert!(!is_jocky_source_file(Path::new("test.rs")));
        assert!(!is_jocky_source_file(Path::new("test")));
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
        assert!(err.contains("Unsupported JOCKY source extension '.tfg'"));
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
