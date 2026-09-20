//! TraceForge Backend - Code generation for target platforms

use std::path::Path;
use traceforge_ir::{ArtifactMetadata, BuildConfig, IrInvestigation, TargetArch, TargetPlatform};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Code generation failed: {0}")]
    CodeGenError(String),
    #[error("Compilation failed: {0}")]
    CompilationError(String),
    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Template error: {0}")]
    TemplateError(String),
}

pub struct Backend {
    config: BuildConfig,
}

impl Backend {
    pub fn new(config: BuildConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self, ir: &IrInvestigation, output_dir: &Path) -> Result<ArtifactMetadata, BackendError> {
        match self.config.target_platform {
            TargetPlatform::Linux => self.generate_linux(ir, output_dir),
            TargetPlatform::Windows => self.generate_windows(ir, output_dir),
        }
    }

    fn generate_linux(&self, ir: &IrInvestigation, output_dir: &Path) -> Result<ArtifactMetadata, BackendError> {
        std::fs::create_dir_all(output_dir)?;

        // Generate Rust source code
        let rust_code = self.generate_rust_code(ir)?;
        let src_path = output_dir.join("main.rs");
        std::fs::write(&src_path, rust_code)?;

        // Generate Cargo.toml
        let cargo_toml = self.generate_cargo_toml(ir)?;
        std::fs::write(output_dir.join("Cargo.toml"), cargo_toml)?;

        // Compile with cargo
        let artifact_name = format!("{}-linux-{}", ir.name, self.arch_suffix());
        let output_path = output_dir.join(&artifact_name);

        let status = std::process::Command::new("cargo")
            .args(["build", "--release", "--target-dir", output_dir.to_str().unwrap()])
            .current_dir(output_dir)
            .status()?;

        if !status.success() {
            return Err(BackendError::CompilationError("Cargo build failed".to_string()));
        }

        // Find the compiled binary
        let binary_path = output_dir.join("release").join(&artifact_name);
        if !binary_path.exists() {
            // Try alternative location
            let alt_path = output_dir.join(&artifact_name);
            if alt_path.exists() {
                std::fs::rename(&alt_path, &binary_path)?;
            } else {
                return Err(BackendError::CompilationError("Binary not found after build".to_string()));
            }
        }

        // Calculate artifact hash
        let artifact_hash = self.calculate_sha256(&binary_path)?;

        // Generate metadata
        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash: "TODO".to_string(), // Will be filled by caller
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash: "TODO".to_string(),
            target_platform: TargetPlatform::Linux,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: ir.required_capabilities.iter().map(|c| c.as_str().to_string()).collect(),
            ir_version: traceforge_ir::IR_VERSION.to_string(),
        };

        Ok(metadata)
    }

    fn generate_windows(&self, ir: &IrInvestigation, output_dir: &Path) -> Result<ArtifactMetadata, BackendError> {
        // For cross-compilation to Windows, we'd need mingw-w64
        // For now, generate the same Rust code but note it's for Windows
        std::fs::create_dir_all(output_dir)?;

        let rust_code = self.generate_rust_code(ir)?;
        let src_path = output_dir.join("main.rs");
        std::fs::write(&src_path, rust_code)?;

        let cargo_toml = self.generate_cargo_toml(ir)?;
        std::fs::write(output_dir.join("Cargo.toml"), cargo_toml)?;

        // Note: Actual Windows cross-compilation requires additional setup
        // For MVP, we'll generate the source and mark it as Windows-targeted
        let artifact_name = format!("{}-windows-{}.exe", ir.name, self.arch_suffix());

        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash: "TODO".to_string(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash: "TODO".to_string(),
            target_platform: TargetPlatform::Windows,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash: "PENDING_CROSS_COMPILE".to_string(),
            required_capabilities: ir.required_capabilities.iter().map(|c| c.as_str().to_string()).collect(),
            ir_version: traceforge_ir::IR_VERSION.to_string(),
        };

        Ok(metadata)
    }

    fn generate_rust_code(&self, ir: &IrInvestigation) -> Result<String, BackendError> {
        let mut code = String::new();

        // Header
        code.push_str(&format!(
            r#"//! Generated by TraceForge Compiler v{}
//! Investigation: {}
//! Target: {:?}-{:?}
//! Required capabilities: {:?}

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use traceforge_runtime::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let mut evidence = EvidenceCollector::new("{}");
"#,
            env!("CARGO_PKG_VERSION"),
            ir.name,
            self.config.target_platform,
            self.config.target_arch,
            ir.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            ir.name
        ));

        // Generate operations
        for op in &ir.operations {
            code.push_str(&self.generate_operation(op)?);
        }

        // Finalize and write evidence
        code.push_str(r#"
    evidence.finalize()?;
    println!("Evidence collection complete");
    Ok(())
}
"#);

        Ok(code)
    }

    fn generate_operation(&self, op: &traceforge_ir::IrOperation) -> Result<String, BackendError> {
        use traceforge_ir::IrOperation;

        match op {
            IrOperation::Collect(collect) => self.generate_collect(collect),
            IrOperation::Export(export) => self.generate_export(export),
            IrOperation::Filter(filter) => self.generate_filter(filter),
            IrOperation::Where(where_op) => self.generate_where(where_op),
            IrOperation::Limit(limit) => self.generate_limit(limit),
            IrOperation::Metadata(meta) => self.generate_metadata(meta),
        }
    }

    fn generate_collect(&self, collect: &traceforge_ir::IrCollectOperation) -> Result<String, BackendError> {
        let mut code = String::new();

        match collect.operation.as_str() {
            "system.info" => {
                code.push_str("    evidence.collect_system_info();\n");
            }
            "process.enumerate" => {
                let fields: Vec<String> = collect.fields.iter().map(|f| format!("\"{}\"", f)).collect();
                let fields_str = if fields.is_empty() {
                    "vec![]".to_string()
                } else {
                    format!("vec![{}]", fields.join(", "))
                };
                code.push_str(&format!("    evidence.collect_processes({});\n", fields_str));
            }
            "network.connections" => {
                code.push_str("    evidence.collect_network_connections();\n");
            }
            "filesystem.enumerate" => {
                let path = collect.options.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                let recursive = collect.options.get("recursive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let hash = collect.options.get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none");

                code.push_str(&format!(
                    "    evidence.collect_files(\"{}\", {}, \"{}\");\n",
                    path, recursive, hash
                ));
            }
            "logs.collect" => {
                let source = collect.options.get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system");
                code.push_str(&format!("    evidence.collect_logs(\"{}\");\n", source));
            }
            "evidence.export" => {
                let format = collect.options.get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("json");
                code.push_str(&format!("    evidence.export_evidence(\"{}\");\n", format));
            }
            _ => {
                code.push_str(&format!("    // Unknown collect operation: {}\n", collect.operation));
            }
        }

        Ok(code)
    }

    fn generate_export(&self, export: &traceforge_ir::IrExportOperation) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.set_output_format(\"{}\", \"{}\");\n",
            export.format, export.path
        ))
    }

    fn generate_filter(&self, filter: &traceforge_ir::IrFilterOperation) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.add_filter({:?});\n",
            filter.condition
        ))
    }

    fn generate_where(&self, where_op: &traceforge_ir::IrWhereOperation) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.add_where({:?});\n",
            where_op.condition
        ))
    }

    fn generate_limit(&self, limit: &traceforge_ir::IrLimitOperation) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.set_limit({:?});\n",
            limit.count
        ))
    }

    fn generate_metadata(&self, meta: &traceforge_ir::IrMetadataOperation) -> Result<String, BackendError> {
        let mut code = String::new();
        for (key, value) in &meta.metadata {
            code.push_str(&format!(
                "    evidence.add_metadata(\"{}\", {:?});\n",
                key, value
            ));
        }
        Ok(code)
    }

    fn generate_cargo_toml(&self, ir: &IrInvestigation) -> Result<String, BackendError> {
        let deps = self.required_dependencies(ir);

        Ok(format!(
            r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
traceforge-runtime = {{ path = "../../../../runtime" }}
{}
"#,
            ir.name.replace('-', "_"),
            deps
        ))
    }

    fn required_dependencies(&self, ir: &IrInvestigation) -> String {
        let mut deps = Vec::new();

        for cap in &ir.required_capabilities {
            match cap {
                traceforge_ast::Capability::ProcessRead => {
                    deps.push("procfs = \"0.15\"".to_string());
                }
                traceforge_ast::Capability::NetworkRead => {
                    deps.push("netstat2 = \"0.3\"".to_string());
                }
                traceforge_ast::Capability::FilesystemRead => {
                    deps.push("walkdir = \"2.4\"".to_string());
                }
                traceforge_ast::Capability::FileHash => {
                    deps.push("sha2 = \"0.10\"".to_string());
                }
                _ => {}
            }
        }

        deps.sort();
        deps.dedup();
        deps.join("\n")
    }

    fn arch_suffix(&self) -> &'static str {
        match self.config.target_arch {
            TargetArch::X64 => "x64",
            TargetArch::Arm64 => "arm64",
        }
    }

    fn calculate_sha256(&self, path: &Path) -> Result<String, BackendError> {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finalize();
        Ok(format!("{:x}", hash))
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self::new(BuildConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traceforge_ir::{IrInvestigation, TargetPlatform, TargetArch};
    use traceforge_ast::{Capability, Span};
    use std::collections::HashSet;

    #[test]
    fn test_backend_generates_rust_code() {
        let config = BuildConfig {
            target_platform: TargetPlatform::Linux,
            target_arch: TargetArch::X64,
            ..Default::default()
        };
        let backend = Backend::new(config);

        let ir = IrInvestigation {
            name: "test_investigation".to_string(),
            metadata: vec![],
            operations: vec![],
            required_capabilities: HashSet::from([Capability::SystemInfoRead]),
            span: Span::new(1, 1, 1, 1),
        };

        let code = backend.generate_rust_code(&ir).unwrap();
        assert!(code.contains("test_investigation"));
        assert!(code.contains("EvidenceCollector"));
    }
}