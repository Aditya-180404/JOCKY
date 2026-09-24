//! Real Programmatic LLVM Code Generation Backend
//!
//! Lowers TraceForge MIR into standard, valid LLVM 15-21 Intermediate Representation (`.ll`),
//! optimizes via LLVM passes, and links against the native TraceForge runtime staticlib
//! using `clang` to produce platform-native ELF and PE executables.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use traceforge_ir::{ArtifactMetadata, BuildConfig, TargetArch, TargetPlatform};
use traceforge_mir::{MirInstruction, MirProgram, MirTerminator};

/// LLVM backend configuration and compilation driver
pub struct LlvmBackend {
    config: BuildConfig,
}

impl LlvmBackend {
    pub fn new(config: BuildConfig) -> Self {
        Self { config }
    }

    /// Generate valid LLVM IR string from MIR program
    pub fn generate_llvm_ir(&self, mir: &MirProgram) -> Result<String, String> {
        let mut codegen = LlvmCodegen::new(self.config.target_platform, self.config.target_arch);
        codegen.emit_program(mir)
    }

    /// Compile MIR to native executable using LLVM and Clang
    pub fn compile(
        &self,
        mir: &MirProgram,
        output_dir: &Path,
    ) -> Result<ArtifactMetadata, crate::BackendError> {
        std::fs::create_dir_all(output_dir)?;

        // 1. Generate programmatic LLVM IR
        let llvm_ir = self
            .generate_llvm_ir(mir)
            .map_err(crate::BackendError::CodeGenError)?;

        // 2. Write .ll file
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

/// Programmatic LLVM IR Generator
struct LlvmCodegen {
    platform: TargetPlatform,
    #[allow(dead_code)]
    arch: TargetArch,
    strings: Vec<String>,
    string_map: HashMap<String, usize>,
}

impl LlvmCodegen {
    fn new(platform: TargetPlatform, arch: TargetArch) -> Self {
        Self {
            platform,
            arch,
            strings: Vec::new(),
            string_map: HashMap::new(),
        }
    }

    fn get_or_intern_string(&mut self, s: &str) -> usize {
        if let Some(&id) = self.string_map.get(s) {
            id
        } else {
            let id = self.strings.len();
            self.strings.push(s.to_string());
            self.string_map.insert(s.to_string(), id);
            id
        }
    }

    fn emit_program(&mut self, mir: &MirProgram) -> Result<String, String> {
        let (datalayout, triple) = match self.platform {
            TargetPlatform::Linux => (
                "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
                "x86_64-pc-linux-gnu",
            ),
            TargetPlatform::Windows => (
                "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
                "x86_64-w64-windows-gnu",
            ),
        };

        // First pass: collect all strings so globals can be emitted before functions
        for func in &mir.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    match inst {
                        MirInstruction::ConstString { value, .. } => {
                            self.get_or_intern_string(value);
                        }
                        MirInstruction::EvidenceInit {
                            investigation_name, ..
                        } => {
                            self.get_or_intern_string(investigation_name);
                        }
                        MirInstruction::CollectProcesses { fields_json, .. } => {
                            self.get_or_intern_string(fields_json);
                        }
                        MirInstruction::CollectFiles {
                            path, hash_algo, ..
                        } => {
                            self.get_or_intern_string(path);
                            self.get_or_intern_string(hash_algo);
                        }
                        MirInstruction::CollectLogs { source, .. } => {
                            self.get_or_intern_string(source);
                        }
                        MirInstruction::EvidenceAddFilter { condition_json, .. }
                        | MirInstruction::EvidenceAddWhere { condition_json, .. } => {
                            self.get_or_intern_string(condition_json);
                        }
                        MirInstruction::EvidenceComputeHash { algorithm, .. } => {
                            self.get_or_intern_string(algorithm);
                        }
                        MirInstruction::EvidenceExport { format, path, .. } => {
                            self.get_or_intern_string(format);
                            self.get_or_intern_string(path);
                        }
                        MirInstruction::CollectRegistry { hive, key_path, .. } => {
                            self.get_or_intern_string(hive);
                            self.get_or_intern_string(key_path);
                        }
                        MirInstruction::CollectArtifacts {
                            artifact_type,
                            path,
                            ..
                        } => {
                            self.get_or_intern_string(artifact_type);
                            self.get_or_intern_string(path);
                        }
                        _ => {}
                    }
                }
            }
        }

        let mut out = String::new();

        // LLVM Header
        out.push_str(&format!("; ModuleID = \"{}\"\n", mir.name));
        out.push_str(&format!("source_filename = \"{}.tfg\"\n", mir.name));
        out.push_str(&format!("target datalayout = \"{}\"\n", datalayout));
        out.push_str(&format!("target triple = \"{}\"\n\n", triple));

        // String Constant Pool
        for (i, s) in self.strings.iter().enumerate() {
            let escaped = Self::escape_llvm_string(s);
            let byte_len = s.len() + 1; // including \00 null terminator
            out.push_str(&format!(
                "@.str.{} = private unnamed_addr constant [{} x i8] c\"{}\\00\", align 1\n",
                i, byte_len, escaped
            ));
        }
        out.push('\n');

        // External Runtime Declarations
        out.push_str("; --- TraceForge Forensic Runtime C-ABI Declarations ---\n");
        out.push_str("declare ptr @traceforge_rt_evidence_init(ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_system(ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_processes(ptr, ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_network(ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_files(ptr, ptr, i32, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_logs(ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_drivers(ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_memory_regions(ptr, i32)\n");
        out.push_str("declare i32 @traceforge_rt_collect_registry(ptr, ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_collect_artifacts(ptr, ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_filter(ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_where(ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_limit(ptr, i64)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_compute_hash(ptr, ptr)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_generate_timeline(ptr)\n");
        out.push_str("declare i32 @traceforge_rt_evidence_export(ptr, ptr, ptr)\n");
        out.push_str("declare void @traceforge_rt_evidence_free(ptr)\n\n");

        // Emit Functions
        for func in &mir.functions {
            self.emit_function(func, &mut out)?;
        }

        Ok(out)
    }

    fn mir_to_llvm_type(ty: &traceforge_mir::MirType) -> &'static str {
        match ty {
            traceforge_mir::MirType::Void => "void",
            traceforge_mir::MirType::Int32 => "i32",
            traceforge_mir::MirType::Int64 => "i64",
            traceforge_mir::MirType::Bool => "i1",
            traceforge_mir::MirType::String => "ptr",
            traceforge_mir::MirType::Pointer => "ptr",
            traceforge_mir::MirType::EvidenceContext => "ptr",
            traceforge_mir::MirType::RecordSet => "ptr",
            traceforge_mir::MirType::JsonValue => "ptr",
        }
    }

    fn emit_function(
        &self,
        func: &traceforge_mir::MirFunction,
        out: &mut String,
    ) -> Result<(), String> {
        let ret_ty = Self::mir_to_llvm_type(&func.return_type);

        out.push_str(&format!("define {} @{}() {{\n", ret_ty, func.name));

        let local_types: std::collections::HashMap<
            traceforge_mir::LocalId,
            traceforge_mir::MirType,
        > = func.locals.iter().map(|l| (l.id, l.ty.clone())).collect();

        let mut ssa_counter = 0usize;
        let mut ssa_name = || {
            let name = format!("%v{}", ssa_counter);
            ssa_counter += 1;
            name
        };

        let mut ctx_reg: Option<String> = None;

        for block in &func.blocks {
            out.push_str(&format!("{}:\n", block.name));

            for inst in &block.instructions {
                match inst {
                    MirInstruction::ConstInt { dest, value } => {
                        let ty = local_types
                            .get(dest)
                            .map(Self::mir_to_llvm_type)
                            .unwrap_or("i32");
                        out.push_str(&format!("  %l{} = add {} 0, {}\n", dest, ty, value));
                    }
                    MirInstruction::ConstBool { dest, value } => {
                        let b_val = if *value { 1 } else { 0 };
                        out.push_str(&format!("  %l{} = icmp eq i32 {}, 1\n", dest, b_val));
                    }
                    MirInstruction::ConstString { dest, value } => {
                        let str_id = self.string_map.get(value).copied().unwrap_or(0);
                        let byte_len = value.len() + 1;
                        out.push_str(&format!(
                            "  %l{} = getelementptr inbounds [{} x i8], ptr @.str.{}, i64 0, i64 0\n",
                            dest, byte_len, str_id
                        ));
                    }
                    MirInstruction::Alloc { dest, ty } => {
                        let llvm_ty = Self::mir_to_llvm_type(ty);
                        out.push_str(&format!("  %l{} = alloca {}\n", dest, llvm_ty));
                    }
                    MirInstruction::Load { dest, src } => {
                        let ty = local_types
                            .get(dest)
                            .map(Self::mir_to_llvm_type)
                            .unwrap_or("i64");
                        out.push_str(&format!("  %l{} = load {}, ptr %l{}\n", dest, ty, src));
                    }
                    MirInstruction::Store { dest, src } => {
                        let ty = local_types
                            .get(src)
                            .map(Self::mir_to_llvm_type)
                            .unwrap_or("i64");
                        out.push_str(&format!("  store {} %l{}, ptr %l{}\n", ty, src, dest));
                    }
                    MirInstruction::EvidenceInit {
                        dest,
                        investigation_name,
                    } => {
                        let str_id = self
                            .string_map
                            .get(investigation_name)
                            .copied()
                            .unwrap_or(0);
                        ctx_reg = Some(format!("%l{}", dest));
                        out.push_str(&format!(
                            "  %l{} = call ptr @traceforge_rt_evidence_init(ptr @.str.{})\n",
                            dest, str_id
                        ));
                    }
                    MirInstruction::CollectSystemInfo { dest, ctx } => {
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_system(ptr %l{})\n",
                            dest, ctx
                        ));
                    }
                    MirInstruction::CollectProcesses {
                        dest,
                        ctx,
                        fields_json,
                        ..
                    } => {
                        let str_id = self.string_map.get(fields_json).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_processes(ptr %l{}, ptr @.str.{}, ptr null)\n",
                            dest, ctx, str_id
                        ));
                    }
                    MirInstruction::CollectNetwork { dest, ctx } => {
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_network(ptr %l{})\n",
                            dest, ctx
                        ));
                    }
                    MirInstruction::CollectFiles {
                        dest,
                        ctx,
                        path,
                        recursive,
                        hash_algo,
                    } => {
                        let path_id = self.string_map.get(path).copied().unwrap_or(0);
                        let hash_id = self.string_map.get(hash_algo).copied().unwrap_or(0);
                        let rec_val = if *recursive { 1 } else { 0 };
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_files(ptr %l{}, ptr @.str.{}, i32 {}, ptr @.str.{})\n",
                            dest, ctx, path_id, rec_val, hash_id
                        ));
                    }
                    MirInstruction::CollectLogs { dest, ctx, source } => {
                        let src_id = self.string_map.get(source).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_logs(ptr %l{}, ptr @.str.{})\n",
                            dest, ctx, src_id
                        ));
                    }
                    MirInstruction::CollectDrivers { dest, ctx } => {
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_drivers(ptr %l{})\n",
                            dest, ctx
                        ));
                    }
                    MirInstruction::CollectMemoryRegions { dest, ctx, pid } => {
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_memory_regions(ptr %l{}, i32 {})\n",
                            dest, ctx, pid
                        ));
                    }
                    MirInstruction::CollectRegistry {
                        dest,
                        ctx,
                        hive,
                        key_path,
                    } => {
                        let hive_id = self.string_map.get(hive).copied().unwrap_or(0);
                        let key_id = self.string_map.get(key_path).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_registry(ptr %l{}, ptr @.str.{}, ptr @.str.{})\n",
                            dest, ctx, hive_id, key_id
                        ));
                    }
                    MirInstruction::CollectArtifacts {
                        dest,
                        ctx,
                        artifact_type,
                        path,
                    } => {
                        let type_id = self.string_map.get(artifact_type).copied().unwrap_or(0);
                        let path_id = self.string_map.get(path).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_collect_artifacts(ptr %l{}, ptr @.str.{}, ptr @.str.{})\n",
                            dest, ctx, type_id, path_id
                        ));
                    }
                    MirInstruction::EvidenceAddFilter {
                        ctx,
                        condition_json,
                    } => {
                        let cond_id = self.string_map.get(condition_json).copied().unwrap_or(0);
                        let reg = ssa_name();
                        out.push_str(&format!(
                            "  {} = call i32 @traceforge_rt_evidence_filter(ptr %l{}, ptr @.str.{})\n",
                            reg, ctx, cond_id
                        ));
                    }
                    MirInstruction::EvidenceAddWhere {
                        ctx,
                        condition_json,
                    } => {
                        let cond_id = self.string_map.get(condition_json).copied().unwrap_or(0);
                        let reg = ssa_name();
                        out.push_str(&format!(
                            "  {} = call i32 @traceforge_rt_evidence_where(ptr %l{}, ptr @.str.{})\n",
                            reg, ctx, cond_id
                        ));
                    }
                    MirInstruction::EvidenceSetLimit { ctx, limit } => {
                        let reg = ssa_name();
                        out.push_str(&format!(
                            "  {} = call i32 @traceforge_rt_evidence_limit(ptr %l{}, i64 {})\n",
                            reg, ctx, limit
                        ));
                    }
                    MirInstruction::EvidenceComputeHash {
                        dest,
                        ctx,
                        algorithm,
                    } => {
                        let algo_id = self.string_map.get(algorithm).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_evidence_compute_hash(ptr %l{}, ptr @.str.{})\n",
                            dest, ctx, algo_id
                        ));
                    }
                    MirInstruction::EvidenceGenerateTimeline { dest, ctx } => {
                        out.push_str(&format!(
                            "  %l{} = call i32 @traceforge_rt_evidence_generate_timeline(ptr %l{})\n",
                            dest, ctx
                        ));
                    }
                    MirInstruction::EvidenceExport { ctx, format, path } => {
                        let fmt_id = self.string_map.get(format).copied().unwrap_or(0);
                        let path_id = self.string_map.get(path).copied().unwrap_or(0);
                        let reg = ssa_name();
                        out.push_str(&format!(
                            "  {} = call i32 @traceforge_rt_evidence_export(ptr %l{}, ptr @.str.{}, ptr @.str.{})\n",
                            reg, ctx, fmt_id, path_id
                        ));
                    }
                    MirInstruction::Compare {
                        dest,
                        op,
                        left,
                        right,
                    } => {
                        let ty = local_types
                            .get(left)
                            .map(Self::mir_to_llvm_type)
                            .unwrap_or("i64");
                        let pred = match op {
                            traceforge_mir::MirCompareOp::Eq => "eq",
                            traceforge_mir::MirCompareOp::Ne => "ne",
                            traceforge_mir::MirCompareOp::Lt => "slt",
                            traceforge_mir::MirCompareOp::Le => "sle",
                            traceforge_mir::MirCompareOp::Gt => "sgt",
                            traceforge_mir::MirCompareOp::Ge => "sge",
                            traceforge_mir::MirCompareOp::Contains => "ne",
                        };
                        out.push_str(&format!(
                            "  %l{} = icmp {} {} %l{}, %l{}\n",
                            dest, pred, ty, left, right
                        ));
                    }
                    MirInstruction::CallRuntime {
                        dest,
                        function_name,
                        args,
                    } => {
                        let arg_strs: Vec<String> = args
                            .iter()
                            .map(|a| {
                                let ty = local_types
                                    .get(a)
                                    .map(Self::mir_to_llvm_type)
                                    .unwrap_or("ptr");
                                format!("{} %l{}", ty, a)
                            })
                            .collect();
                        let args_joined = arg_strs.join(", ");
                        if let Some(dest_id) = dest {
                            let ret_ty = local_types
                                .get(dest_id)
                                .map(Self::mir_to_llvm_type)
                                .unwrap_or("i32");
                            out.push_str(&format!(
                                "  %l{} = call {} @{}({})\n",
                                dest_id, ret_ty, function_name, args_joined
                            ));
                        } else {
                            out.push_str(&format!(
                                "  call void @{}({})\n",
                                function_name, args_joined
                            ));
                        }
                    }
                }
            }

            // Cleanup before return
            if let MirTerminator::Return { value } = &block.terminator {
                if let Some(ctx) = &ctx_reg {
                    out.push_str(&format!(
                        "  call void @traceforge_rt_evidence_free(ptr {})\n",
                        ctx
                    ));
                }
                match value {
                    Some(v) => {
                        let ty = local_types
                            .get(v)
                            .map(Self::mir_to_llvm_type)
                            .unwrap_or("i32");
                        out.push_str(&format!("  ret {} %l{}\n", ty, v));
                    }
                    None => {
                        if func.return_type == traceforge_mir::MirType::Void {
                            out.push_str("  ret void\n");
                        } else {
                            out.push_str("  ret i32 0\n");
                        }
                    }
                }
            } else if let MirTerminator::Branch { target } = &block.terminator {
                let target_name = func
                    .blocks
                    .iter()
                    .find(|b| b.id == *target)
                    .map(|b| b.name.as_str())
                    .unwrap_or("entry");
                out.push_str(&format!("  br label %{}\n", target_name));
            } else if let MirTerminator::CondBranch {
                cond,
                then_target,
                else_target,
            } = &block.terminator
            {
                let then_name = func
                    .blocks
                    .iter()
                    .find(|b| b.id == *then_target)
                    .map(|b| b.name.as_str())
                    .unwrap_or("entry");
                let else_name = func
                    .blocks
                    .iter()
                    .find(|b| b.id == *else_target)
                    .map(|b| b.name.as_str())
                    .unwrap_or("entry");
                out.push_str(&format!(
                    "  br i1 %l{}, label %{}, label %{}\n",
                    cond, then_name, else_name
                ));
            } else if let MirTerminator::Unreachable = &block.terminator {
                out.push_str("  unreachable\n");
            }
        }

        out.push_str("}\n\n");
        Ok(())
    }

    fn escape_llvm_string(s: &str) -> String {
        let mut res = String::new();
        for b in s.bytes() {
            match b {
                b'\\' => res.push_str("\\5C"),
                b'"' => res.push_str("\\22"),
                b'\n' => res.push_str("\\0A"),
                b'\r' => res.push_str("\\0D"),
                b'\t' => res.push_str("\\09"),
                0x20..=0x7E => res.push(b as char),
                _ => res.push_str(&format!("\\{:02X}", b)),
            }
        }
        res
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
        assert!(ir.contains("ret i32 %l1"));
    }
}
