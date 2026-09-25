//! jockey Backend - Code generation for target platforms

use jockey_ir::{ArtifactMetadata, BuildConfig, IrInvestigation, TargetArch, TargetPlatform};
use sha2::Digest;
use std::path::Path;
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
    #[error("LLVM lowering error: {0}")]
    LlvmLoweringError(String),
    #[error("LLVM verification error: {0}")]
    LlvmVerificationError(String),
    #[error("Target error: {0}")]
    TargetError(String),
}

pub mod llvm;
pub mod llvm_codegen;
pub mod llvm_core;
pub mod llvm_types;
pub use llvm::LlvmBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum BackendKind {
    Rust,
    #[default]
    Llvm,
}

impl std::str::FromStr for BackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "llvm" => Ok(BackendKind::Llvm),
            "rust" => Ok(BackendKind::Rust),
            _ => Err(format!("Unknown backend kind: {}", s)),
        }
    }
}

pub struct Backend {
    config: BuildConfig,
    kind: BackendKind,
}

fn command_exists(executable: &str) -> bool {
    std::process::Command::new(executable)
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn rustup_target_installed(target: &str) -> bool {
    let output = match std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .any(|installed_target| installed_target == target)
}

fn windows_cross_compile_requirement_message(
    mingw_available: bool,
    target_installed: bool,
) -> String {
    let missing = {
        let mut missing = Vec::new();
        if !mingw_available {
            missing.push("x86_64-w64-mingw32-gcc");
        }
        if !target_installed {
            missing.push("rustup target x86_64-pc-windows-gnu");
        }
        missing
    };

    format!(
        "Windows cross-compilation on non-Windows hosts requires {}.",
        missing.join(" and ")
    )
}

impl Backend {
    pub fn new(config: BuildConfig) -> Self {
        Self {
            config,
            kind: BackendKind::Llvm,
        }
    }

    pub fn new_with_kind(config: BuildConfig, kind: BackendKind) -> Self {
        Self { config, kind }
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
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
                    let mingw_available = command_exists("x86_64-w64-mingw32-gcc");
                    let target_installed = rustup_target_installed("x86_64-pc-windows-gnu");
                    if !(mingw_available && target_installed) {
                        return Err(BackendError::CompilationError(
                            windows_cross_compile_requirement_message(
                                mingw_available,
                                target_installed,
                            ),
                        ));
                    }
                    Ok(())
                }
            }
        }
    }

    pub fn generate_from_mir(
        &self,
        mir: &jockey_mir::MirProgram,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        let llvm_backend = LlvmBackend::new(self.config.clone());
        llvm_backend.compile(mir, output_dir)
    }

    pub fn generate(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        match self.kind {
            BackendKind::Llvm => {
                let hir: jockey_hir::HirInvestigation = ir.into();
                let mir =
                    jockey_mir::MirLowering::lower(&hir).map_err(BackendError::CodeGenError)?;
                let llvm_backend = LlvmBackend::new(self.config.clone());
                llvm_backend.compile(&mir, output_dir)
            }
            BackendKind::Rust => self.generate_rust(ir, output_dir),
        }
    }

    pub fn generate_rust(
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
            Err(BackendError::CompilationError(
                "Linux native artifacts require a Linux host or configured cross-compilation toolchain (e.g. cross or x86_64-unknown-linux-gnu)".to_string(),
            ))
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
        if project_dir.is_file() {
            let _ = std::fs::remove_file(&project_dir);
        }
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
            .args(["build", "--release", "--target-dir", "target"])
            .current_dir(&project_dir)
            .status()?;

        if !status.success() {
            return Err(BackendError::CompilationError(
                "Cargo build failed".to_string(),
            ));
        }

        // Find the compiled binary
        let pkg_binary_name = ir.name.replace('-', "_");
        let release_dir = project_dir.join("target").join("release");
        let binary_path = if release_dir.join(&pkg_binary_name).exists() {
            release_dir.join(&pkg_binary_name)
        } else if release_dir.join(&ir.name).exists() {
            release_dir.join(&ir.name)
        } else {
            release_dir.join(&artifact_name)
        };

        if !binary_path.exists() {
            return Err(BackendError::CompilationError(format!(
                "Binary not found after build: {}",
                binary_path.display()
            )));
        }

        // Copy binary to output directory
        std::fs::copy(&binary_path, &output_path)?;
        let default_bin = output_dir.join(&ir.name);
        let _ = std::fs::copy(&binary_path, &default_bin);

        // Calculate artifact hash
        let artifact_hash = self.calculate_sha256(&output_path)?;

        let source_json = jockey_ir::serialize_ir(ir).unwrap_or_default();
        let mut source_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut source_hasher, source_json.as_bytes());
        let source_hash = format!("{:x}", sha2::Digest::finalize(source_hasher));

        let mut compiler_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut compiler_hasher, env!("CARGO_PKG_VERSION").as_bytes());
        sha2::Digest::update(
            &mut compiler_hasher,
            format!("{:?}-{:?}", TargetPlatform::Linux, self.config.target_arch).as_bytes(),
        );
        let compiler_hash = format!("{:x}", sha2::Digest::finalize(compiler_hasher));

        // Generate metadata
        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash,
            target_platform: TargetPlatform::Linux,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: ir
                .required_capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            ir_version: jockey_ir::IR_VERSION.to_string(),
        };

        let manifest_path = output_dir.join(format!("{}.manifest.json", ir.name));
        let _ = self.generate_manifest(&metadata, &manifest_path);

        Ok(metadata)
    }

    fn generate_windows(
        &self,
        ir: &IrInvestigation,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, BackendError> {
        let project_dir = output_dir.join(&ir.name);
        if project_dir.is_file() {
            let _ = std::fs::remove_file(&project_dir);
        }
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
        let mut cmd = std::process::Command::new("cargo");
        cmd.args(["build", "--release", "--target-dir", "target"]);

        #[cfg(not(target_os = "windows"))]
        {
            cmd.args(["--target", "x86_64-pc-windows-gnu"]);
            cmd.env(
                "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER",
                "x86_64-w64-mingw32-gcc",
            );
        }

        let status = cmd.current_dir(&project_dir).status()?;

        if !status.success() {
            return Err(BackendError::CompilationError(
                "Cargo build failed for Windows target".to_string(),
            ));
        }

        let pkg_binary_name = format!("{}.exe", ir.name.replace('-', "_"));
        #[cfg(target_os = "windows")]
        let binary_path = target_dir.join("release").join(&pkg_binary_name);
        #[cfg(not(target_os = "windows"))]
        let binary_path = target_dir
            .join("x86_64-pc-windows-gnu")
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

        let source_json = jockey_ir::serialize_ir(ir).unwrap_or_default();
        let mut source_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut source_hasher, source_json.as_bytes());
        let source_hash = format!("{:x}", sha2::Digest::finalize(source_hasher));

        let mut compiler_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut compiler_hasher, env!("CARGO_PKG_VERSION").as_bytes());
        sha2::Digest::update(
            &mut compiler_hasher,
            format!(
                "{:?}-{:?}",
                TargetPlatform::Windows,
                self.config.target_arch
            )
            .as_bytes(),
        );
        let compiler_hash = format!("{:x}", sha2::Digest::finalize(compiler_hasher));

        let metadata = ArtifactMetadata {
            investigation_name: ir.name.clone(),
            source_hash,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash,
            target_platform: TargetPlatform::Windows,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: ir
                .required_capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            ir_version: jockey_ir::IR_VERSION.to_string(),
        };

        let manifest_path = output_dir.join(format!("{}.manifest.json", ir.name));
        let _ = self.generate_manifest(&metadata, &manifest_path);

        Ok(metadata)
    }

    pub fn generate_rust_code(&self, ir: &IrInvestigation) -> Result<String, BackendError> {
        let mut code = String::new();

        // Header
        code.push_str(&format!(
            r#"//! Generated by jockey Compiler v{}
//! Investigation: {}
//! Target: {:?}-{:?}
//! Required capabilities: {:?}

#![allow(unused_imports, unused_variables)]
use jockey_runtime::*;

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

    fn generate_operation(&self, op: &jockey_ir::IrOperation) -> Result<String, BackendError> {
        use jockey_ir::IrOperation;

        match op {
            IrOperation::Collect(collect) => self.generate_collect(collect),
            IrOperation::Export(export) => self.generate_export(export),
            IrOperation::Filter(filter) => self.generate_filter(filter),
            IrOperation::Where(where_op) => self.generate_where(where_op),
            IrOperation::Limit(limit) => self.generate_limit(limit),
            IrOperation::Metadata(meta) => self.generate_metadata(meta),
            IrOperation::Assign(assign) => Ok(format!(
                "    // Assignment: {} = ...\n    let _{} = evidence.collect_variable({:?})?;\n",
                assign.variable, assign.variable, assign.expression
            )),
            IrOperation::EvidencePipeline(ep) => {
                let mut pipeline_code =
                    format!("    // Evidence pipeline for variable: {}\n", ep.variable);
                for stage in &ep.stages {
                    match stage {
                        jockey_ir::IrPipelineStage::Where { condition, .. } => {
                            let json_str = serde_json::to_string(condition).unwrap_or_default();
                            pipeline_code.push_str(&format!(
                                "    evidence.add_where(serde_json::from_str({:?}).unwrap_or_default());\n",
                                json_str
                            ));
                        }
                        jockey_ir::IrPipelineStage::Filter { condition, .. } => {
                            let json_str = serde_json::to_string(condition).unwrap_or_default();
                            pipeline_code.push_str(&format!(
                                "    evidence.add_filter(serde_json::from_str({:?}).unwrap_or_default());\n",
                                json_str
                            ));
                        }
                        jockey_ir::IrPipelineStage::Hash { algorithm, .. } => {
                            pipeline_code.push_str(&format!(
                                "    evidence.compute_hash(\"{}\")?;\n",
                                algorithm
                            ));
                        }
                        jockey_ir::IrPipelineStage::Timeline { .. } => {
                            pipeline_code.push_str("    evidence.generate_timeline()?;\n");
                        }
                        jockey_ir::IrPipelineStage::Export { path, .. } => {
                            pipeline_code.push_str(&format!(
                                "    evidence.set_output_format(\"json\", \"{}\");\n",
                                path
                            ));
                        }
                        jockey_ir::IrPipelineStage::Limit { count, .. } => {
                            let json_str = serde_json::to_string(count).unwrap_or_default();
                            pipeline_code.push_str(&format!(
                                "    evidence.set_limit(serde_json::from_str({:?}).unwrap_or_default());\n",
                                json_str
                            ));
                        }
                    }
                }
                Ok(pipeline_code)
            }
        }
    }

    fn generate_collect(
        &self,
        collect: &jockey_ir::IrCollectOperation,
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
            "drivers.enumerate" => {
                code.push_str("    evidence.collect_drivers()?;\n");
            }
            "timeline.build" => {
                code.push_str("    evidence.generate_timeline()?;\n");
            }
            "memory.regions" => {
                let pid = collect
                    .options
                    .get("pid")
                    .and_then(|v| v.as_i64())
                    .map(|p| p as i32);
                let pid_str = match pid {
                    Some(p) => format!("Some({})", p),
                    None => "None".to_string(),
                };
                code.push_str(&format!(
                    "    evidence.collect_memory_regions({})?;\n",
                    pid_str
                ));
            }
            "registry.enumerate" => {
                let hive = collect
                    .options
                    .get("hive")
                    .and_then(|v| v.as_str())
                    .unwrap_or("HKLM");
                let key_path = collect
                    .options
                    .get("key_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SOFTWARE");
                code.push_str(&format!(
                    "    evidence.collect_registry(\"{}\", \"{}\")?;\n",
                    hive, key_path
                ));
            }
            "artifacts.carve" => {
                let artifact_type = collect
                    .options
                    .get("artifact_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let path = collect
                    .options
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                code.push_str(&format!(
                    "    evidence.collect_artifacts(\"{}\", \"{}\")?;\n",
                    artifact_type, path
                ));
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
        export: &jockey_ir::IrExportOperation,
    ) -> Result<String, BackendError> {
        Ok(format!(
            "    evidence.set_output_format(\"{}\", \"{}\");\n",
            export.format, export.path
        ))
    }

    fn generate_filter(
        &self,
        filter: &jockey_ir::IrFilterOperation,
    ) -> Result<String, BackendError> {
        let json_str = serde_json::to_string(&filter.condition).unwrap_or_default();
        Ok(format!(
            "    evidence.add_filter(serde_json::from_str({:?}).unwrap_or_default());\n",
            json_str
        ))
    }

    fn generate_where(
        &self,
        where_op: &jockey_ir::IrWhereOperation,
    ) -> Result<String, BackendError> {
        let json_str = serde_json::to_string(&where_op.condition).unwrap_or_default();
        Ok(format!(
            "    evidence.add_where(serde_json::from_str({:?}).unwrap_or_default());\n",
            json_str
        ))
    }

    fn generate_limit(&self, limit: &jockey_ir::IrLimitOperation) -> Result<String, BackendError> {
        let json_str = serde_json::to_string(&limit.count).unwrap_or_default();
        Ok(format!(
            "    evidence.set_limit(serde_json::from_str({:?}).unwrap_or_default());\n",
            json_str
        ))
    }

    pub fn generate_manifest(
        &self,
        metadata: &ArtifactMetadata,
        output_path: &Path,
    ) -> Result<(), BackendError> {
        let manifest_json = serde_json::to_string_pretty(metadata).map_err(|e| {
            BackendError::TemplateError(format!("Failed to serialize manifest: {}", e))
        })?;
        std::fs::write(output_path, manifest_json)
            .map_err(|e| BackendError::TemplateError(format!("Failed to write manifest: {}", e)))?;
        Ok(())
    }

    fn generate_metadata(
        &self,
        meta: &jockey_ir::IrMetadataOperation,
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

    pub fn generate_cargo_toml(&self, ir: &IrInvestigation) -> Result<String, BackendError> {
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
jockey-runtime = {{ path = "{}" }}
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
                jockey_ast::Capability::FilesystemRead => {
                    deps.push("walkdir = \"2.4\"".to_string());
                }
                jockey_ast::Capability::FileHash => {
                    deps.push("sha2 = \"0.10\"".to_string());
                }
                _ => {}
            }
        }

        deps.push("serde_json = \"1.0\"".to_string());
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
    use jockey_ast::{Capability, Span};
    use jockey_ir::{IrInvestigation, TargetArch, TargetPlatform};
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
            target: None,
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
        assert!(targets
            .iter()
            .any(|t| t.platform == TargetPlatform::Linux && t.arch == TargetArch::X64));
        assert!(targets
            .iter()
            .any(|t| t.platform == TargetPlatform::Windows && t.arch == TargetArch::X64));
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
