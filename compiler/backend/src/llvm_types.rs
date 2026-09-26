//! Centralized Type Lowering from jockey MIR to LLVM Types
//!
//! Provides authoritative translation of `MirType` and external C ABI function
//! prototypes to `LLVMTypeRef`.

use jockey_mir::MirType;
use llvm_sys::core::*;
use llvm_sys::prelude::*;

/// Translate a `MirType` into its corresponding `LLVMTypeRef`.
///
/// # Safety
/// The caller must provide a valid `LLVMContextRef` that remains alive for the duration
/// of the generated LLVM type handles.
pub unsafe fn mir_type_to_llvm(ctx: LLVMContextRef, ty: &MirType) -> Result<LLVMTypeRef, String> {
    match ty {
        MirType::Void => Ok(LLVMVoidTypeInContext(ctx)),
        MirType::Int32 => Ok(LLVMInt32TypeInContext(ctx)),
        MirType::Int64 => Ok(LLVMInt64TypeInContext(ctx)),
        MirType::Bool => Ok(LLVMInt1TypeInContext(ctx)),
        // In LLVM 15+, pointers are opaque ptr types
        MirType::String
        | MirType::Pointer
        | MirType::EvidenceContext
        | MirType::RecordSet
        | MirType::JsonValue => Ok(LLVMPointerTypeInContext(ctx, 0)),
    }
}

/// External runtime function signatures declared in the LLVM module
pub struct RuntimeSignatures {
    pub evidence_init: (LLVMTypeRef, &'static str),
    pub collect_system: (LLVMTypeRef, &'static str),
    pub collect_processes: (LLVMTypeRef, &'static str),
    pub collect_network: (LLVMTypeRef, &'static str),
    pub collect_files: (LLVMTypeRef, &'static str),
    pub collect_logs: (LLVMTypeRef, &'static str),
    pub collect_drivers: (LLVMTypeRef, &'static str),
    pub collect_memory_regions: (LLVMTypeRef, &'static str),
    pub collect_registry: (LLVMTypeRef, &'static str),
    pub collect_artifacts: (LLVMTypeRef, &'static str),
    pub invoke_capability: (LLVMTypeRef, &'static str),
    pub evidence_filter: (LLVMTypeRef, &'static str),
    pub evidence_where: (LLVMTypeRef, &'static str),
    pub evidence_limit: (LLVMTypeRef, &'static str),
    pub evidence_export: (LLVMTypeRef, &'static str),
    pub evidence_compute_hash: (LLVMTypeRef, &'static str),
    pub evidence_generate_timeline: (LLVMTypeRef, &'static str),
    pub evidence_free: (LLVMTypeRef, &'static str),
}

impl RuntimeSignatures {
    /// Constructs the runtime signature table for the provided LLVM context.
    ///
    /// # Safety
    /// The caller must ensure that `ctx` is a valid, live `LLVMContextRef` for the duration
    /// of the signature objects created here.
    pub unsafe fn new(ctx: LLVMContextRef) -> Self {
        let ptr_ty = LLVMPointerTypeInContext(ctx, 0);
        let i32_ty = LLVMInt32TypeInContext(ctx);
        let i64_ty = LLVMInt64TypeInContext(ctx);
        let void_ty = LLVMVoidTypeInContext(ctx);

        // jockey_rt_evidence_init(investigation_name, source_hash) -> *mut c_void
        let mut init_params = [ptr_ty, ptr_ty];
        let init_ty = LLVMFunctionType(ptr_ty, init_params.as_mut_ptr(), 2, 0);

        // jockey_rt_collect_system(ctx: *mut c_void) -> c_int
        let mut sys_params = [ptr_ty];
        let sys_ty = LLVMFunctionType(i32_ty, sys_params.as_mut_ptr(), 1, 0);

        // jockey_rt_collect_processes(ctx: *mut c_void, fields_json: *const c_char, hash_algo: *const c_char) -> c_int
        let mut proc_params = [ptr_ty, ptr_ty, ptr_ty];
        let proc_ty = LLVMFunctionType(i32_ty, proc_params.as_mut_ptr(), 3, 0);

        // jockey_rt_collect_network(ctx: *mut c_void) -> c_int
        let mut net_params = [ptr_ty];
        let net_ty = LLVMFunctionType(i32_ty, net_params.as_mut_ptr(), 1, 0);

        // jockey_rt_collect_files(ctx: *mut c_void, path: *const c_char, recursive: c_int, hash_algo: *const c_char) -> c_int
        let mut files_params = [ptr_ty, ptr_ty, i32_ty, ptr_ty];
        let files_ty = LLVMFunctionType(i32_ty, files_params.as_mut_ptr(), 4, 0);

        // jockey_rt_collect_logs(ctx: *mut c_void, source: *const c_char) -> c_int
        let mut logs_params = [ptr_ty, ptr_ty];
        let logs_ty = LLVMFunctionType(i32_ty, logs_params.as_mut_ptr(), 2, 0);

        // jockey_rt_collect_drivers(ctx: *mut c_void) -> c_int
        let mut drv_params = [ptr_ty];
        let drv_ty = LLVMFunctionType(i32_ty, drv_params.as_mut_ptr(), 1, 0);

        // jockey_rt_collect_memory_regions(ctx: *mut c_void, pid: c_int) -> c_int
        let mut mem_params = [ptr_ty, i32_ty];
        let mem_ty = LLVMFunctionType(i32_ty, mem_params.as_mut_ptr(), 2, 0);

        // jockey_rt_collect_registry(ctx: *mut c_void, hive: *const c_char, key_path: *const c_char) -> c_int
        let mut reg_params = [ptr_ty, ptr_ty, ptr_ty];
        let reg_ty = LLVMFunctionType(i32_ty, reg_params.as_mut_ptr(), 3, 0);

        // jockey_rt_collect_artifacts(ctx: *mut c_void, artifact_type: *const c_char, path: *const c_char) -> c_int
        let mut art_params = [ptr_ty, ptr_ty, ptr_ty];
        let art_ty = LLVMFunctionType(i32_ty, art_params.as_mut_ptr(), 3, 0);

        // jockey_rt_invoke_capability(ctx, capability_id, options_json) -> c_int
        let mut invoke_params = [ptr_ty, ptr_ty, ptr_ty];
        let invoke_ty = LLVMFunctionType(i32_ty, invoke_params.as_mut_ptr(), 3, 0);

        // jockey_rt_evidence_filter(ctx: *mut c_void, filter_json: *const c_char) -> c_int
        let mut filter_params = [ptr_ty, ptr_ty];
        let filter_ty = LLVMFunctionType(i32_ty, filter_params.as_mut_ptr(), 2, 0);

        // jockey_rt_evidence_where(ctx: *mut c_void, where_json: *const c_char) -> c_int
        let mut where_params = [ptr_ty, ptr_ty];
        let where_ty = LLVMFunctionType(i32_ty, where_params.as_mut_ptr(), 2, 0);

        // jockey_rt_evidence_limit(ctx: *mut c_void, limit: usize/i64) -> c_int
        let mut limit_params = [ptr_ty, i64_ty];
        let limit_ty = LLVMFunctionType(i32_ty, limit_params.as_mut_ptr(), 2, 0);

        // jockey_rt_evidence_export(ctx: *mut c_void, format: *const c_char, path: *const c_char) -> c_int
        let mut export_params = [ptr_ty, ptr_ty, ptr_ty];
        let export_ty = LLVMFunctionType(i32_ty, export_params.as_mut_ptr(), 3, 0);

        // jockey_rt_evidence_compute_hash(ctx: *mut c_void, algo: *const c_char) -> c_int
        let mut hash_params = [ptr_ty, ptr_ty];
        let hash_ty = LLVMFunctionType(i32_ty, hash_params.as_mut_ptr(), 2, 0);

        // jockey_rt_evidence_generate_timeline(ctx: *mut c_void) -> c_int
        let mut time_params = [ptr_ty];
        let time_ty = LLVMFunctionType(i32_ty, time_params.as_mut_ptr(), 1, 0);

        // jockey_rt_evidence_free(ctx: *mut c_void) -> void
        let mut free_params = [ptr_ty];
        let free_ty = LLVMFunctionType(void_ty, free_params.as_mut_ptr(), 1, 0);

        Self {
            evidence_init: (init_ty, "jockey_rt_evidence_init"),
            collect_system: (sys_ty, "jockey_rt_collect_system"),
            collect_processes: (proc_ty, "jockey_rt_collect_processes"),
            collect_network: (net_ty, "jockey_rt_collect_network"),
            collect_files: (files_ty, "jockey_rt_collect_files"),
            collect_logs: (logs_ty, "jockey_rt_collect_logs"),
            collect_drivers: (drv_ty, "jockey_rt_collect_drivers"),
            collect_memory_regions: (mem_ty, "jockey_rt_collect_memory_regions"),
            collect_registry: (reg_ty, "jockey_rt_collect_registry"),
            collect_artifacts: (art_ty, "jockey_rt_collect_artifacts"),
            invoke_capability: (invoke_ty, "jockey_rt_invoke_capability"),
            evidence_filter: (filter_ty, "jockey_rt_evidence_filter"),
            evidence_where: (where_ty, "jockey_rt_evidence_where"),
            evidence_limit: (limit_ty, "jockey_rt_evidence_limit"),
            evidence_export: (export_ty, "jockey_rt_evidence_export"),
            evidence_compute_hash: (hash_ty, "jockey_rt_evidence_compute_hash"),
            evidence_generate_timeline: (time_ty, "jockey_rt_evidence_generate_timeline"),
            evidence_free: (free_ty, "jockey_rt_evidence_free"),
        }
    }
}
