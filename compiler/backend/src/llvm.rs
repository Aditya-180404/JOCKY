//! Real Programmatic LLVM Code Generation Backend
//!
//! Lowers TraceForge MIR into standard, valid LLVM 15-21 Intermediate Representation (`.ll`),
//! optimizes via LLVM passes, and links against the native TraceForge runtime staticlib
//! using `clang` to produce platform-native ELF and PE executables.

use std::path::{Path, PathBuf};
use traceforge_ir::{ArtifactMetadata, BuildConfig, TargetArch, TargetPlatform};
use traceforge_mir::MirProgram;

/// LLVM backend configuration and compilation driver
pub struct LlvmBackend {
    config: BuildConfig,
}

impl LlvmBackend {
    pub fn new(config: BuildConfig) -> Self {
        Self { config }
    }

    /// Generate valid LLVM IR string from programmatic LLVM module
    pub fn generate_llvm_ir(&self, mir: &MirProgram) -> Result<String, String> {
        let codegen = crate::llvm_codegen::ProgrammaticLlvmCodegen::new(
            self.config.target_platform,
            self.config.target_arch,
        );
        let res = codegen.emit_module(mir).map_err(|e| e.to_string())?;
        Ok(res.module.print_ir())
    }

    /// Compile MIR to native executable using programmatic LLVM module and Clang
    pub fn compile(
        &self,
        mir: &MirProgram,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, crate::BackendError> {
        if self.config.target_arch == TargetArch::Arm64 {
            return Err(crate::BackendError::TargetError(
                "ARM64 target code generation is not yet supported on this host toolchain. Supported targets: Linux x86_64, Windows x86_64".to_string()
            ));
        }

        std::fs::create_dir_all(output_dir)?;

        // 1. Generate and verify programmatic LLVM module
        let codegen = crate::llvm_codegen::ProgrammaticLlvmCodegen::new(
            self.config.target_platform,
            self.config.target_arch,
        );
        let res = codegen.emit_module(mir)?;
        let llvm_ir = res.module.print_ir();

        // 2. Write .ll file (debug representation serialized from real LLVM module)
        let ll_path = output_dir.join(format!("{}.ll", mir.name));
        std::fs::write(&ll_path, &llvm_ir)?;

        // 3. Determine artifact filename and target parameters
        let (artifact_name, target_triple, linker_flags) = match self.config.target_platform {
            TargetPlatform::Linux => (
                format!("{}-linux-{}", mir.name, self.arch_suffix()),
                "x86_64-pc-linux-gnu",
                vec!["-lpthread", "-ldl", "-lm"],
            ),
            TargetPlatform::Windows => (
                format!("{}-windows-{}.exe", mir.name, self.arch_suffix()),
                "x86_64-w64-windows-gnu",
                vec![
                    "-lws2_32",
                    "-luserenv",
                    "-lntdll",
                    "-ladvapi32",
                    "-lbcrypt",
                    "-lsecur32",
                ],
            ),
        };

        let output_path = output_dir.join(&artifact_name);

        // 4. Ensure runtime static archive exists
        let runtime_lib = self.ensure_runtime_lib(self.config.target_platform)?;

        // 5. Invoke clang to compile .ll to native binary
        let mut cmd = std::process::Command::new("clang");
        // Optimization level
        match self.config.optimization_level {
            traceforge_ir::OptimizationLevel::None => {
                cmd.arg("-O0");
            }
            traceforge_ir::OptimizationLevel::Size => {
                cmd.arg("-Os");
            }
            traceforge_ir::OptimizationLevel::Speed => {
                cmd.arg("-O2");
            }
        }

        cmd.arg("-target").arg(target_triple);
        // Input: LLVM IR source file – scope -x ir to just this file
        cmd.arg("-x").arg("ir").arg(&ll_path).arg("-x").arg("none");
        // Runtime static archive (plain archive, not IR)
        cmd.arg(&runtime_lib);

        for flag in linker_flags {
            cmd.arg(flag);
        }

        cmd.arg("-o").arg(&output_path);

        let output = cmd.output().map_err(|e| {
            crate::BackendError::CompilationError(format!("Failed to execute clang: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::BackendError::CompilationError(format!(
                "Clang compilation failed: {}",
                stderr
            )));
        }

        if !output_path.exists() {
            return Err(crate::BackendError::CompilationError(
                "Native executable not found after LLVM compilation".to_string(),
            ));
        }

        // Also copy default unversioned binary for convenience
        let default_bin = match self.config.target_platform {
            TargetPlatform::Linux => output_dir.join(&mir.name),
            TargetPlatform::Windows => output_dir.join(format!("{}.exe", mir.name)),
        };
        if !default_bin.is_dir() {
            let _ = std::fs::copy(&output_path, &default_bin);
        }

        // 6. Calculate artifact SHA-256 hash
        let artifact_hash = self.calculate_sha256(&output_path)?;

        let metadata = ArtifactMetadata {
            investigation_name: mir.name.clone(),
            source_hash: mir.provenance.source_hash.clone(),
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            compiler_hash: mir.provenance.mir_hash.clone(),
            target_platform: self.config.target_platform,
            target_arch: self.config.target_arch,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            artifact_hash,
            required_capabilities: mir
                .capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            ir_version: "2.0-llvm".to_string(),
        };

        Ok(metadata)
    }

    fn ensure_runtime_lib(&self, platform: TargetPlatform) -> Result<PathBuf, crate::BackendError> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_dir);

        let (target_arg, rel_path) = match platform {
            TargetPlatform::Linux => (
                None,
                workspace_root
                    .join("target")
                    .join("release")
                    .join("libtraceforge_runtime.a"),
            ),
            TargetPlatform::Windows => (
                Some("x86_64-pc-windows-gnu"),
                workspace_root
                    .join("target")
                    .join("x86_64-pc-windows-gnu")
                    .join("release")
                    .join("libtraceforge_runtime.a"),
            ),
        };

        if rel_path.exists() {
            return Ok(rel_path);
        }

        // Build runtime static library on demand
        let mut cmd = std::process::Command::new("cargo");
        cmd.args(["build", "-p", "traceforge-runtime", "--release"]);
        if let Some(target) = target_arg {
            cmd.args(["--target", target]);
        }
        cmd.current_dir(workspace_root);

        let status = cmd.status().map_err(|e| {
            crate::BackendError::CompilationError(format!(
                "Failed to build runtime staticlib: {}",
                e
            ))
        })?;

        if !status.success() || !rel_path.exists() {
            return Err(crate::BackendError::CompilationError(format!(
                "Failed to build required staticlib: {}",
                rel_path.display()
            )));
        }

        Ok(rel_path)
    }

    fn arch_suffix(&self) -> &'static str {
        match self.config.target_arch {
            TargetArch::X64 => "x64",
            TargetArch::Arm64 => "arm64",
        }
    }

    fn calculate_sha256(&self, path: &Path) -> Result<String, crate::BackendError> {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use traceforge_mir::{
        MirBasicBlock, MirFunction, MirInstruction, MirLocal, MirProgram, MirProvenance,
        MirTerminator, MirType,
    };

    #[test]
    fn test_llvm_ir_generation_validity() {
        let mir = MirProgram {
            name: "unit_test_llvm".to_string(),
            target: Some("linux".to_string()),
            functions: vec![MirFunction {
                name: "main".to_string(),
                return_type: MirType::Int32,
                locals: vec![
                    MirLocal {
                        id: 0,
                        name: "ctx".to_string(),
                        ty: MirType::EvidenceContext,
                    },
                    MirLocal {
                        id: 1,
                        name: "res".to_string(),
                        ty: MirType::Int32,
                    },
                ],
                blocks: vec![MirBasicBlock {
                    id: 0,
                    name: "entry".to_string(),
                    instructions: vec![
                        MirInstruction::EvidenceInit {
                            dest: 0,
                            investigation_name: "unit_test_llvm".to_string(),
                        },
                        MirInstruction::CollectSystemInfo { dest: 1, ctx: 0 },
                        MirInstruction::EvidenceExport {
                            ctx: 0,
                            format: "json".to_string(),
                            path: "unit_evidence.json".to_string(),
                        },
                    ],
                    terminator: MirTerminator::Return { value: Some(1) },
                }],
            }],
            capabilities: HashSet::new(),
            provenance: MirProvenance {
                source_hash: "aaa".to_string(),
                hir_hash: "bbb".to_string(),
                mir_hash: "ccc".to_string(),
                compiler_version: "0.1.0".to_string(),
                created_at: "now".to_string(),
            },
        };

        let backend = LlvmBackend::new(BuildConfig::default());
        let ir = backend
            .generate_llvm_ir(&mir)
            .expect("LLVM IR codegen failed");

        assert!(ir.contains("target triple = \"x86_64-pc-linux-gnu\""));
        assert!(ir.contains("declare ptr @traceforge_rt_evidence_init(ptr)"));
        assert!(ir.contains("call ptr @traceforge_rt_evidence_init"));
        assert!(ir.contains("call i32 @traceforge_rt_collect_system"));
        assert!(ir.contains("call i32 @traceforge_rt_evidence_export"));
        assert!(ir.contains("call void @traceforge_rt_evidence_free"));
        assert!(ir.contains("ret i32"));
    }
}
