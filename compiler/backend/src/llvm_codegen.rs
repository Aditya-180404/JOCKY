//! Programmatic LLVM Code Generation Engine
//!
//! Lowers JOCKY MIR directly into programmatic LLVM Context, Module, Functions,
//! BasicBlocks, Instructions, and Terminators using the LLVM C API.
//!
//! Note on Runtime ABI:
//! Runtime declarations use the `traceforge_rt_*` naming scheme as an intentional internal
//! ABI compatibility boundary with the native runtime static library.

use std::collections::HashMap;
use std::ffi::CString;

use llvm_sys::core::*;
use llvm_sys::prelude::*;
use llvm_sys::LLVMIntPredicate;

use traceforge_ir::{TargetArch, TargetPlatform};
use traceforge_mir::{
    BasicBlockId, LocalId, MirCompareOp, MirFunction, MirInstruction, MirProgram, MirTerminator,
    MirType,
};

use crate::llvm_core::{LlvmBuilder, LlvmContext, LlvmModule};
use crate::llvm_types::{mir_type_to_llvm, RuntimeSignatures};
use crate::BackendError;

/// Programmatic LLVM Code Generation Result
pub struct ProgrammaticCodegenResult {
    pub module: LlvmModule,
    pub context: LlvmContext,
}

pub struct ProgrammaticLlvmCodegen {
    platform: TargetPlatform,
    arch: TargetArch,
}

impl ProgrammaticLlvmCodegen {
    pub fn new(platform: TargetPlatform, arch: TargetArch) -> Self {
        Self { platform, arch }
    }

    /// Lower a MIR program into a fully verified programmatic LLVM module
    pub fn emit_module(&self, mir: &MirProgram) -> Result<ProgrammaticCodegenResult, BackendError> {
        // Enforce supported target architectures
        if self.arch == TargetArch::Arm64 {
            return Err(BackendError::TargetError(
                "ARM64 target code generation is not yet supported on this host toolchain. Supported targets: Linux x86_64, Windows x86_64".to_string()
            ));
        }

        let context = LlvmContext::new();
        let module = LlvmModule::new(&mir.name, &context);
        let builder = LlvmBuilder::new(&context);

        // Configure target triple and data layout
        let (target_triple, data_layout) = match self.platform {
            TargetPlatform::Linux => (
                "x86_64-pc-linux-gnu",
                "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
            ),
            TargetPlatform::Windows => (
                "x86_64-w64-windows-gnu",
                "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
            ),
        };

        module.set_target_triple(target_triple);
        module.set_data_layout(data_layout);

        unsafe {
            // Declare runtime C ABI functions
            let rt_sigs = RuntimeSignatures::new(context.as_raw());
            let mut rt_funcs: HashMap<&'static str, (LLVMValueRef, LLVMTypeRef)> = HashMap::new();

            let declare_rt = |module_ref: LLVMModuleRef,
                              funcs: &mut HashMap<&'static str, (LLVMValueRef, LLVMTypeRef)>,
                              name: &'static str,
                              fn_ty: LLVMTypeRef| {
                let c_name = CString::new(name).unwrap();
                let f = LLVMAddFunction(module_ref, c_name.as_ptr(), fn_ty);
                funcs.insert(name, (f, fn_ty));
            };

            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_init.1,
                rt_sigs.evidence_init.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_system.1,
                rt_sigs.collect_system.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_processes.1,
                rt_sigs.collect_processes.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_network.1,
                rt_sigs.collect_network.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_files.1,
                rt_sigs.collect_files.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_logs.1,
                rt_sigs.collect_logs.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_drivers.1,
                rt_sigs.collect_drivers.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_memory_regions.1,
                rt_sigs.collect_memory_regions.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_registry.1,
                rt_sigs.collect_registry.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.collect_artifacts.1,
                rt_sigs.collect_artifacts.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_filter.1,
                rt_sigs.evidence_filter.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_where.1,
                rt_sigs.evidence_where.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_limit.1,
                rt_sigs.evidence_limit.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_export.1,
                rt_sigs.evidence_export.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_compute_hash.1,
                rt_sigs.evidence_compute_hash.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_generate_timeline.1,
                rt_sigs.evidence_generate_timeline.0,
            );
            declare_rt(
                module.as_raw(),
                &mut rt_funcs,
                rt_sigs.evidence_free.1,
                rt_sigs.evidence_free.0,
            );

            // Global string literal pool to avoid duplicate allocations
            let mut string_constants: HashMap<String, LLVMValueRef> = HashMap::new();

            let get_or_create_string_ptr = |_ctx: LLVMContextRef,
                                            _mod_ref: LLVMModuleRef,
                                            builder_ref: LLVMBuilderRef,
                                            pool: &mut HashMap<String, LLVMValueRef>,
                                            val: &str|
             -> LLVMValueRef {
                if let Some(&ptr) = pool.get(val) {
                    return ptr;
                }
                let c_val = CString::new(val).unwrap_or_else(|_| CString::new("").unwrap());
                let var_name = format!(".str.{}", pool.len());
                let c_var_name = CString::new(var_name).unwrap();
                let ptr = LLVMBuildGlobalString(builder_ref, c_val.as_ptr(), c_var_name.as_ptr());
                pool.insert(val.to_string(), ptr);
                ptr
            };

            // Lower each MIR function
            for mir_fn in &mir.functions {
                self.lower_function(
                    mir_fn,
                    &context,
                    &module,
                    &builder,
                    &rt_funcs,
                    &mut string_constants,
                    get_or_create_string_ptr,
                )?;
            }
        }

        // Verify module integrity
        module
            .verify()
            .map_err(BackendError::LlvmVerificationError)?;

        Ok(ProgrammaticCodegenResult { module, context })
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn lower_function<F>(
        &self,
        mir_fn: &MirFunction,
        context: &LlvmContext,
        module: &LlvmModule,
        builder: &LlvmBuilder,
        rt_funcs: &HashMap<&'static str, (LLVMValueRef, LLVMTypeRef)>,
        string_pool: &mut HashMap<String, LLVMValueRef>,
        mut get_string_ptr: F,
    ) -> Result<(), BackendError>
    where
        F: FnMut(
            LLVMContextRef,
            LLVMModuleRef,
            LLVMBuilderRef,
            &mut HashMap<String, LLVMValueRef>,
            &str,
        ) -> LLVMValueRef,
    {
        let ctx = context.as_raw();
        let builder_ref = builder.as_raw();
        let mod_ref = module.as_raw();

        let ret_ty = if mir_fn.name == "main" {
            LLVMInt32TypeInContext(ctx)
        } else {
            mir_type_to_llvm(ctx, &mir_fn.return_type).map_err(BackendError::LlvmLoweringError)?
        };

        let mut param_types = Vec::new();
        let fn_ty = LLVMFunctionType(ret_ty, param_types.as_mut_ptr(), 0, 0);

        let fn_name_c = CString::new(mir_fn.name.as_str()).unwrap();
        let function = LLVMAddFunction(mod_ref, fn_name_c.as_ptr(), fn_ty);

        // Pre-create all basic blocks
        let mut bb_map: HashMap<BasicBlockId, LLVMBasicBlockRef> = HashMap::new();
        for bb in &mir_fn.blocks {
            let bb_name_c = CString::new(format!("bb_{}_{}", bb.id, bb.name)).unwrap();
            let llvm_bb = LLVMAppendBasicBlockInContext(ctx, function, bb_name_c.as_ptr());
            bb_map.insert(bb.id, llvm_bb);
        }

        // Entry block setup: allocate all locals
        let entry_bb = match mir_fn.blocks.first() {
            Some(first) => bb_map[&first.id],
            None => return Ok(()),
        };

        LLVMPositionBuilderAtEnd(builder_ref, entry_bb);

        let mut local_allocas: HashMap<LocalId, (LLVMTypeRef, LLVMValueRef)> = HashMap::new();
        for local in &mir_fn.locals {
            let local_ty =
                mir_type_to_llvm(ctx, &local.ty).map_err(BackendError::LlvmLoweringError)?;
            let local_name_c = CString::new(format!("loc_{}_{}", local.id, local.name)).unwrap();
            let alloca = LLVMBuildAlloca(builder_ref, local_ty, local_name_c.as_ptr());
            local_allocas.insert(local.id, (local_ty, alloca));
        }

        // Helper to load value from local
        let load_local = |builder_ref: LLVMBuilderRef,
                          allocas: &HashMap<LocalId, (LLVMTypeRef, LLVMValueRef)>,
                          id: LocalId,
                          name: &str|
         -> Result<LLVMValueRef, BackendError> {
            let &(ty, alloca) = allocas.get(&id).ok_or_else(|| {
                BackendError::LlvmLoweringError(format!("Unallocated local variable ID: {}", id))
            })?;
            let c_name = CString::new(name).unwrap();
            Ok(LLVMBuildLoad2(builder_ref, ty, alloca, c_name.as_ptr()))
        };

        // Helper to store value into local
        let store_local = |builder_ref: LLVMBuilderRef,
                           allocas: &HashMap<LocalId, (LLVMTypeRef, LLVMValueRef)>,
                           id: LocalId,
                           val: LLVMValueRef|
         -> Result<(), BackendError> {
            let &(_, alloca) = allocas.get(&id).ok_or_else(|| {
                BackendError::LlvmLoweringError(format!("Unallocated local variable ID: {}", id))
            })?;
            LLVMBuildStore(builder_ref, val, alloca);
            Ok(())
        };

        let i32_ty = LLVMInt32TypeInContext(ctx);
        let i64_ty = LLVMInt64TypeInContext(ctx);
        let i1_ty = LLVMInt1TypeInContext(ctx);

        // Lower instructions in each basic block
        for bb in &mir_fn.blocks {
            let llvm_bb = bb_map[&bb.id];
            LLVMPositionBuilderAtEnd(builder_ref, llvm_bb);

            for inst in &bb.instructions {
                match inst {
                    MirInstruction::ConstInt { dest, value } => {
                        let &(dest_ty, _) = local_allocas.get(dest).ok_or_else(|| {
                            BackendError::LlvmLoweringError(format!("Invalid dest local {}", dest))
                        })?;
                        let val = LLVMConstInt(dest_ty, *value as u64, 1);
                        store_local(builder_ref, &local_allocas, *dest, val)?;
                    }
                    MirInstruction::ConstString { dest, value } => {
                        let str_ptr = get_string_ptr(ctx, mod_ref, builder_ref, string_pool, value);
                        store_local(builder_ref, &local_allocas, *dest, str_ptr)?;
                    }
                    MirInstruction::ConstBool { dest, value } => {
                        let val = LLVMConstInt(i1_ty, if *value { 1 } else { 0 }, 0);
                        store_local(builder_ref, &local_allocas, *dest, val)?;
                    }
                    MirInstruction::Alloc { dest, ty: _ } => {
                        // Already allocated in entry block
                        let _ = dest;
                    }
                    MirInstruction::Load { dest, src } => {
                        let val = load_local(builder_ref, &local_allocas, *src, "load_tmp")?;
                        store_local(builder_ref, &local_allocas, *dest, val)?;
                    }
                    MirInstruction::Store { dest, src } => {
                        let val = load_local(builder_ref, &local_allocas, *src, "store_src")?;
                        store_local(builder_ref, &local_allocas, *dest, val)?;
                    }
                    MirInstruction::EvidenceInit {
                        dest,
                        investigation_name,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_init"];
                        let name_ptr = get_string_ptr(
                            ctx,
                            mod_ref,
                            builder_ref,
                            string_pool,
                            investigation_name,
                        );
                        let mut args = [name_ptr];
                        let c_call_name = CString::new("ev_ctx").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            1,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::EvidenceAddFilter {
                        ctx: ev_ctx,
                        condition_json,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_filter"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let filter_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, condition_json);
                        let mut args = [ctx_ptr, filter_ptr];
                        let c_call_name = CString::new("filter_res").unwrap();
                        LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                    }
                    MirInstruction::EvidenceAddWhere {
                        ctx: ev_ctx,
                        condition_json,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_where"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let where_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, condition_json);
                        let mut args = [ctx_ptr, where_ptr];
                        let c_call_name = CString::new("where_res").unwrap();
                        LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                    }
                    MirInstruction::EvidenceSetLimit { ctx: ev_ctx, limit } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_limit"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let limit_val = LLVMConstInt(i64_ty, *limit as u64, 0);
                        let mut args = [ctx_ptr, limit_val];
                        let c_call_name = CString::new("limit_res").unwrap();
                        LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                    }
                    MirInstruction::EvidenceComputeHash {
                        dest,
                        ctx: ev_ctx,
                        algorithm,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_compute_hash"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let algo_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, algorithm);
                        let mut args = [ctx_ptr, algo_ptr];
                        let c_call_name = CString::new("hash_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::EvidenceGenerateTimeline { dest, ctx: ev_ctx } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_generate_timeline"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let mut args = [ctx_ptr];
                        let c_call_name = CString::new("time_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            1,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::EvidenceExport {
                        ctx: ev_ctx,
                        format,
                        path,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_evidence_export"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let fmt_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, format);
                        let path_ptr = get_string_ptr(ctx, mod_ref, builder_ref, string_pool, path);
                        let mut args = [ctx_ptr, fmt_ptr, path_ptr];
                        let c_call_name = CString::new("export_res").unwrap();
                        LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            3,
                            c_call_name.as_ptr(),
                        );

                        // Also invoke evidence_free to release context
                        let (free_val, free_ty) = rt_funcs["traceforge_rt_evidence_free"];
                        let mut free_args = [ctx_ptr];
                        let c_free_name = CString::new("").unwrap();
                        LLVMBuildCall2(
                            builder_ref,
                            free_ty,
                            free_val,
                            free_args.as_mut_ptr(),
                            1,
                            c_free_name.as_ptr(),
                        );
                    }
                    MirInstruction::CollectSystemInfo { dest, ctx: ev_ctx } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_system"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let mut args = [ctx_ptr];
                        let c_call_name = CString::new("collect_sys_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            1,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectProcesses {
                        dest,
                        ctx: ev_ctx,
                        fields_json,
                        hash_algo,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_processes"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let fields_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, fields_json);
                        let algo_str = hash_algo.as_deref().unwrap_or("");
                        let algo_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, algo_str);
                        let mut args = [ctx_ptr, fields_ptr, algo_ptr];
                        let c_call_name = CString::new("collect_proc_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            3,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectNetwork { dest, ctx: ev_ctx } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_network"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let mut args = [ctx_ptr];
                        let c_call_name = CString::new("collect_net_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            1,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectFiles {
                        dest,
                        ctx: ev_ctx,
                        path,
                        recursive,
                        hash_algo,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_files"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let path_ptr = get_string_ptr(ctx, mod_ref, builder_ref, string_pool, path);
                        let rec_val = LLVMConstInt(i32_ty, if *recursive { 1 } else { 0 }, 0);
                        let algo_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, hash_algo);
                        let mut args = [ctx_ptr, path_ptr, rec_val, algo_ptr];
                        let c_call_name = CString::new("collect_files_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            4,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectLogs {
                        dest,
                        ctx: ev_ctx,
                        source,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_logs"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let src_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, source);
                        let mut args = [ctx_ptr, src_ptr];
                        let c_call_name = CString::new("collect_logs_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectDrivers { dest, ctx: ev_ctx } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_drivers"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let mut args = [ctx_ptr];
                        let c_call_name = CString::new("collect_drv_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            1,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectMemoryRegions {
                        dest,
                        ctx: ev_ctx,
                        pid,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_memory_regions"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let pid_val = LLVMConstInt(i32_ty, *pid as u64, 1);
                        let mut args = [ctx_ptr, pid_val];
                        let c_call_name = CString::new("collect_mem_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            2,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectRegistry {
                        dest,
                        ctx: ev_ctx,
                        hive,
                        key_path,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_registry"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let hive_ptr = get_string_ptr(ctx, mod_ref, builder_ref, string_pool, hive);
                        let key_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, key_path);
                        let mut args = [ctx_ptr, hive_ptr, key_ptr];
                        let c_call_name = CString::new("collect_reg_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            3,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CollectArtifacts {
                        dest,
                        ctx: ev_ctx,
                        artifact_type,
                        path,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs["traceforge_rt_collect_artifacts"];
                        let ctx_ptr = load_local(builder_ref, &local_allocas, *ev_ctx, "ctx_val")?;
                        let type_ptr =
                            get_string_ptr(ctx, mod_ref, builder_ref, string_pool, artifact_type);
                        let path_ptr = get_string_ptr(ctx, mod_ref, builder_ref, string_pool, path);
                        let mut args = [ctx_ptr, type_ptr, path_ptr];
                        let c_call_name = CString::new("collect_art_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            args.as_mut_ptr(),
                            3,
                            c_call_name.as_ptr(),
                        );
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::Compare {
                        dest,
                        op,
                        left,
                        right,
                    } => {
                        let lhs = load_local(builder_ref, &local_allocas, *left, "cmp_lhs")?;
                        let rhs = load_local(builder_ref, &local_allocas, *right, "cmp_rhs")?;
                        let predicate = match op {
                            MirCompareOp::Eq => LLVMIntPredicate::LLVMIntEQ,
                            MirCompareOp::Ne => LLVMIntPredicate::LLVMIntNE,
                            MirCompareOp::Lt => LLVMIntPredicate::LLVMIntSLT,
                            MirCompareOp::Le => LLVMIntPredicate::LLVMIntSLE,
                            MirCompareOp::Gt => LLVMIntPredicate::LLVMIntSGT,
                            MirCompareOp::Ge => LLVMIntPredicate::LLVMIntSGE,
                            MirCompareOp::Contains => LLVMIntPredicate::LLVMIntEQ,
                        };
                        let c_name = CString::new("cmp_res").unwrap();
                        let res = LLVMBuildICmp(builder_ref, predicate, lhs, rhs, c_name.as_ptr());
                        store_local(builder_ref, &local_allocas, *dest, res)?;
                    }
                    MirInstruction::CallRuntime {
                        dest,
                        function_name,
                        args,
                    } => {
                        let (fn_val, fn_ty) = rt_funcs
                            .get(function_name.as_str())
                            .copied()
                            .ok_or_else(|| {
                                BackendError::LlvmLoweringError(format!(
                                    "Unknown runtime function '{}'",
                                    function_name
                                ))
                            })?;
                        let mut llvm_args = Vec::with_capacity(args.len());
                        for arg_id in args {
                            let val = load_local(builder_ref, &local_allocas, *arg_id, "arg")?;
                            llvm_args.push(val);
                        }
                        let c_name = CString::new("call_res").unwrap();
                        let res = LLVMBuildCall2(
                            builder_ref,
                            fn_ty,
                            fn_val,
                            llvm_args.as_mut_ptr(),
                            llvm_args.len() as u32,
                            c_name.as_ptr(),
                        );
                        if let Some(dest_id) = dest {
                            store_local(builder_ref, &local_allocas, *dest_id, res)?;
                        }
                    }
                }
            }

            // Lower terminator
            match &bb.terminator {
                MirTerminator::Return { value } => {
                    if let Some(val_id) = value {
                        let ret_val = load_local(builder_ref, &local_allocas, *val_id, "ret_val")?;
                        LLVMBuildRet(builder_ref, ret_val);
                    } else if mir_fn.name == "main" {
                        let const_0 = LLVMConstInt(i32_ty, 0, 0);
                        LLVMBuildRet(builder_ref, const_0);
                    } else if mir_fn.return_type == MirType::Void {
                        LLVMBuildRetVoid(builder_ref);
                    } else {
                        let const_0 = LLVMConstInt(i32_ty, 0, 0);
                        LLVMBuildRet(builder_ref, const_0);
                    }
                }
                MirTerminator::Branch { target } => {
                    let target_bb = bb_map.get(target).copied().ok_or_else(|| {
                        BackendError::LlvmLoweringError(format!(
                            "Invalid branch target BB: {}",
                            target
                        ))
                    })?;
                    LLVMBuildBr(builder_ref, target_bb);
                }
                MirTerminator::CondBranch {
                    cond,
                    then_target,
                    else_target,
                } => {
                    let cond_val = load_local(builder_ref, &local_allocas, *cond, "cond_val")?;
                    let then_bb = bb_map.get(then_target).copied().ok_or_else(|| {
                        BackendError::LlvmLoweringError(format!(
                            "Invalid then branch target BB: {}",
                            then_target
                        ))
                    })?;
                    let else_bb = bb_map.get(else_target).copied().ok_or_else(|| {
                        BackendError::LlvmLoweringError(format!(
                            "Invalid else branch target BB: {}",
                            else_target
                        ))
                    })?;
                    LLVMBuildCondBr(builder_ref, cond_val, then_bb, else_bb);
                }
                MirTerminator::Unreachable => {
                    LLVMBuildUnreachable(builder_ref);
                }
            }
        }

        Ok(())
    }
}
