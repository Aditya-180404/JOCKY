//! TraceForge Backend - Code generation for target platforms

use std::path::Path;
use thiserror::Error;
use traceforge_ir::{ArtifactMetadata, BuildConfig, IrInvestigation, TargetArch, TargetPlatform};

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

    pub fn validate_target(&self) -> Result<(), BackendError> {
        let spec = TargetSpec::from_build_config(self.config.clone());
        if !spec.is_supported() {
            return Err(BackendError::CompilationError(format!(
                "Unsupported target: {:?} {:?}. Supported targets: {}",
                self.config.target_platform,
                self.config.target_arch,
                TargetSpec::supported_targets()
                    .iter()
                    .map(|t| format!("{:?}-{:?}", t.platform, t.arch))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        match self.config.target_platform {
            TargetPlatform::Linux => {
                #[cfg(target_os = "linux")]
                {
                    if !std::process::Command::new("cargo")
                        .arg("--version")
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                    {
                        return Err(BackendError::CompilationError(
                            "Linux native compilation requires the Rust toolchain (cargo) to be installed and on PATH.".to_string(),
                        ));
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let cross_available = std::process::Command::new("cross")
                        .arg("--version")
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if !cross_available {
                        return Err(BackendError::CompilationError(
                            "Linux native artifacts cannot be built directly on a Windows host without a Linux cross-compilation toolchain. To build Linux targets on Windows, use WSL ('wsl cargo build'), Docker ('docker compose run api cargo build'), or install 'cross' ('cargo install cross').".to_string(),
                        ));
                    }
                    Ok(())
                }
            }
            TargetPlatform::Windows => {
                #[cfg(target_os = "windows")]
                {
                    if !std::process::Command::new("cargo")
                        .arg("--version")
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                    {
                        return Err(BackendError::CompilationError(
                            "Windows native compilation requires the Rust toolchain (cargo) to be installed and on PATH.".to_string(),
                        ));
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "windows"))]
                {
                    return Err(BackendError::CompilationError(
                        "Windows native compilation on non-Windows hosts requires a configured cross-compilation toolchain (e.g. x86_64-pc-windows-gnu or cargo-xwin).".to_string(),
                    ));
                }
            }
        }
    }

    pub fn generate(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        self.validate_target()?;
        match self.config.target_platform {
            TargetPlatform::Linux => self.generate_linux(ir, output_dir),
            TargetPlatform::Windows => self.generate_windows(ir, output_dir),
        }
    }

    fn generate_linux(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        #[cfg(target_os = "windows")]
        {
            let _ = (ir, output_dir);
            return Err(BackendError::CompilationError(
                "Linux native artifacts require a Linux host or configured cross-compilation toolchain (e.g. cross or x86_64-unknown-linux-gnu)".to_string(),
            ));
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.generate_linux_native(ir, output_dir)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn generate_linux_native(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        // Create a temporary project directory inside output_dir
        let project_dir = output_dir.join(&ir.name);
        let src_dir = project_dir.join("src");
        std::fs::create_dir_all(&src_dir)?;

        // Generate Rust source code
        let rust_code = self.generate_rust_code(ir)?;
        let src_path = src_dir.join("main.rs");
        std::fs::write(&src_path, rust_code)?;

        // Generate Cargo.toml
        let cargo_toml = self.generate_cargo_toml(ir)?;
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)?;

        // Compile with cargo
        let artifact_name = format!("{}-linux-{}", ir.name, self.arch_suffix());
        let output_path = output_dir.join(&artifact_name);

        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target-dir",
                "target",
            ])
            .current_dir(&project_dir)
            .status()?;

        if !status.success() {
            return Err(BackendError::CompilationError(
                "Cargo build failed".to_string(),
            ));
        }

        // Find the compiled binary
        let binary_path = project_dir
            .join("target")
            .join("release")
            .join(&artifact_name);
        if !binary_path.exists() {
            return Err(BackendError::CompilationError(
                "Binary not found after build".to_string(),
            ));
        }

        // Copy binary to output directory
        std::fs::copy(&binary_path, &output_path)?;

        // Calculate artifact hash
        let artifact_hash = self.calculate_sha256(&output_path)?;

        // Generate metadata
        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash: String::new(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash: String::new(),
            target_platform: TargetPlatform::Linux,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: ir
                .required_capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            ir_version: traceforge_ir::IR_VERSION.to_string(),
        };

        Ok(metadata)
    }

    fn generate_windows(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (ir, output_dir);
            return Err(BackendError::CompilationError(
                "Windows native compilation on non-Windows hosts requires a configured cross-compilation toolchain (e.g. x86_64-pc-windows-gnu or cargo-xwin).".to_string(),
            ));
        }

        #[cfg(target_os = "windows")]
        {
            self.generate_windows_native(ir, output_dir)
        }
    }

    #[cfg(target_os = "windows")]
    fn generate_windows_native(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        let project_dir = output_dir.join(&ir.name);
        let src_dir = project_dir.join("src");
        std::fs::create_dir_all(&src_dir)?;

        let rust_code = self.generate_rust_code(ir)?;
        let src_path = src_dir.join("main.rs");
        std::fs::write(&src_path, rust_code)?;

        let cargo_toml = self.generate_cargo_toml(ir)?;
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)?;

        let artifact_name = format!("{}-windows-{}.exe", ir.name, self.arch_suffix());
        let output_path = output_dir.join(&artifact_name);

        let target_dir = project_dir.join("target");
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target-dir",
                "target",
            ])
            .current_dir(&project_dir)
            .status()?;

        if !status.success() {
            return Err(BackendError::CompilationError(
                "Cargo build failed for Windows native target".to_string(),
            ));
        }

        let pkg_binary_name = format!("{}.exe", ir.name.replace('-', "_"));
        let binary_path = target_dir
            .join("release")
            .join(&pkg_binary_name);
        if !binary_path.exists() {
            return Err(BackendError::CompilationError(format!(
                "Binary not found after build: {}",
                binary_path.display()
            )));
        }

        std::fs::copy(&binary_path, &output_path)?;

        let default_exe = output_dir.join(format!("{}.exe", ir.name));
        let _ = std::fs::copy(&binary_path, &default_exe);

        let artifact_hash = self.calculate_sha256(&output_path)?;

        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash: String::new(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash: String::new(),
            target_platform: TargetPlatform::Windows,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: ir
                .required_capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
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

#![allow(unused_imports, unused_variables)]
use traceforge_runtime::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let mut evidence = EvidenceCollector::new("{}");
"#,
            env!("CARGO_PKG_VERSION"),
            ir.name,
            self.config.target_platform,
            self.config.target_arch,
            ir.required_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            ir.name
        ));

        // Generate operations
        for op in &ir.operations {
            code.push_str(&self.generate_operation(op)?);
        }

        // Finalize and write evidence
        code.push_str(
            r#"
    evidence.finalize()?;
    println!("Evidence collection complete");
    Ok(())
}
"#,
        );

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

    fn generate_collect(
        &self,
        collect: &traceforge_ir::IrCollectOperation,
    ) -> Result<String, BackendError> {
        let mut code = String::new();

        match collect.operation.as_str() {
            "system.info" => {
                code.push_str("    evidence.collect_system_info()?;\n");
            }
            "process.enumerate" => {
                let fields: Vec<String> = collect
                    .fields
                    .iter()
                    .map(|f| format!("\"{}\".to_string()", f))
                    .collect();
                let fields_str = if fields.is_empty() {
                    "vec![]".to_string()
                } else {
                    format!("vec![{}]", fields.join(", "))
                };
                code.push_str(&format!(
                    "    evidence.collect_processes({})?;\n",
                    fields_str
                ));
            }
            "network.connections" => {
                code.push_str("    evidence.collect_network_connections()?;\n");
            }
            "filesystem.enumerate" => {
                let path = collect
                    .options
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                let recursive = collect
                    .options
                    .get("recursive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let hash = collect
                    .options
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none");

                code.push_str(&format!(
                    "    evidence.collect_files(\"{}\", {}, \"{}\")?;\n",
                    path, recursive, hash
                ));
            }
            "logs.collect" => {
                let source = collect
                    .options
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system");
                code.push_str(&format!("    evidence.collect_logs(\"{}\")?;\n", source));
            }
            "evidence.export" => {
                let format = collect
                    .options
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("json");
                code.push_str(&format!("    evidence.export_evidence(\"{}\")?;\n", format));
            }
            _ => {
                code.push_str(&format!(
                    "    // Unknown collect operation: {}\n",
                    collect.operation
                ));
            }
        }

        Ok(code)
    }

    fn generate_export(
        &self,
        export: &traceforge_ir::IrExportOperation,
    ) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.set_output_format(\"{}\", \"{}\");\n",
            export.format, export.path
        ))
    }

    fn generate_filter(
        &self,
        filter: &traceforge_ir::IrFilterOperation,
    ) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.add_filter({:?});\n",
            filter.condition
        ))
    }

    fn generate_where(
        &self,
        where_op: &traceforge_ir::IrWhereOperation,
    ) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.add_where({:?});\n",
            where_op.condition
        ))
    }

    fn generate_limit(
        &self,
        limit: &traceforge_ir::IrLimitOperation,
    ) -> Result<String, BackendError> {
        Ok(format!("    evidence.set_limit({:?});\n", limit.count))
    }

    fn generate_metadata(
        &self,
        meta: &traceforge_ir::IrMetadataOperation,
    ) -> Result<String, BackendError> {
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
        let runtime_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../runtime")
            .canonicalize()
            .map_err(|error| {
                BackendError::TemplateError(format!("Unable to locate runtime crate: {}", error))
            })?;
        let mut runtime_path_str = runtime_path.to_string_lossy().to_string();
        if let Some(stripped) = runtime_path_str.strip_prefix(r"\\?\") {
            runtime_path_str = stripped.to_string();
        }
        let runtime_path = runtime_path_str.replace('\\', "/");

        Ok(format!(
            r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
traceforge-runtime = {{ path = "{}" }}
{}
"#,
            ir.name.replace('-', "_"),
            runtime_path,
            deps
        ))
    }

    fn required_dependencies(&self, ir: &IrInvestigation) -> String {
        let mut deps = Vec::new();

        for cap in &ir.required_capabilities {
            match cap {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    pub platform: TargetPlatform,
    pub arch: TargetArch,
    pub host_compatible: bool,
    pub toolchain_required: Option<&'static str>,
}

impl TargetSpec {
    pub fn from_build_config(config: BuildConfig) -> Self {
        Self {
            platform: config.target_platform,
            arch: config.target_arch,
            host_compatible: match config.target_platform {
                TargetPlatform::Linux => cfg!(target_os = "linux"),
                TargetPlatform::Windows => cfg!(target_os = "windows"),
            },
            toolchain_required: match config.target_platform {
                TargetPlatform::Linux => {
                    if cfg!(target_os = "linux") {
                        None
                    } else {
                        Some("Linux host or 'cross' required for Linux builds")
                    }
                }
                TargetPlatform::Windows => {
                    if cfg!(target_os = "windows") {
                        None
                    } else {
                        Some("Windows host or MinGW/cargo-xwin required for Windows builds")
                    }
                }
            },
        }
    }

    pub fn supported_targets() -> Vec<Self> {
        vec![
            Self {
                platform: TargetPlatform::Linux,
                arch: TargetArch::X64,
                host_compatible: cfg!(target_os = "linux"),
                toolchain_required: if cfg!(target_os = "linux") {
                    None
                } else {
                    Some("Linux host or 'cross' required for Linux builds")
                },
            },
            Self {
                platform: TargetPlatform::Windows,
                arch: TargetArch::X64,
                host_compatible: cfg!(target_os = "windows"),
                toolchain_required: if cfg!(target_os = "windows") {
                    None
                } else {
                    Some("Windows host or MinGW/cargo-xwin required for Windows builds")
                },
            },
        ]
    }

    pub fn is_supported(&self) -> bool {
        match (self.platform, self.arch) {
            (TargetPlatform::Linux, TargetArch::X64) => true,
            (TargetPlatform::Linux, TargetArch::Arm64) => false,
            (TargetPlatform::Windows, TargetArch::X64) => true,
            (TargetPlatform::Windows, TargetArch::Arm64) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use traceforge_ast::{Capability, Span};
    use traceforge_ir::{IrInvestigation, TargetArch, TargetPlatform};

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

    #[test]
    fn test_supported_targets_include_linux_x64_and_windows_x64() {
        let targets = TargetSpec::supported_targets();
        assert!(targets.iter().any(|t| t.platform == TargetPlatform::Linux && t.arch == TargetArch::X64));
        assert!(targets.iter().any(|t| t.platform == TargetPlatform::Windows && t.arch == TargetArch::X64));
    }

    #[test]
    fn test_unrecognized_target_is_rejected() {
        let spec = TargetSpec {
            platform: TargetPlatform::Linux,
            arch: TargetArch::Arm64,
            host_compatible: false,
            toolchain_required: Some("cross-compiler toolchain required"),
        };
        assert!(!spec.is_supported());
    }
}
