//! C-compatible ABI for jockey LLVM code generation
//!
//! Provides `extern "C"` endpoints called directly by the LLVM IR generated
//! by the jockey compiler.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use jockey_runtime_evidence::EvidenceCollector;

/// Context wrapper holding the collector
pub struct RuntimeContext {
    pub collector: EvidenceCollector,
}

#[no_mangle]
/// # Safety
/// Caller must ensure `investigation_name` is either a valid UTF-8 C string pointer or null.
pub unsafe extern "C" fn jockey_rt_evidence_init(
    investigation_name: *const c_char,
) -> *mut c_void {
    let name_str = if investigation_name.is_null() {
        "investigation".to_string()
    } else {
        CStr::from_ptr(investigation_name)
            .to_str()
            .unwrap_or("investigation")
            .to_string()
    };
    let collector = EvidenceCollector::new(&name_str);
    let ctx = Box::new(RuntimeContext { collector });
    Box::into_raw(ctx) as *mut c_void
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid pointer returned by `jockey_rt_evidence_init` and must not
/// dereference it after calling `jockey_rt_evidence_free`.
pub unsafe extern "C" fn jockey_rt_collect_system(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    match ctx.collector.collect_system_info() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] System info collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must ensure `ctx_ptr` is a valid runtime context pointer and that `fields_json` is a
/// valid UTF-8 C string pointer or null.
pub unsafe extern "C" fn jockey_rt_collect_processes(
    ctx_ptr: *mut c_void,
    fields_json: *const c_char,
    _hash_algo: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let fields: Vec<String> = if fields_json.is_null() {
        vec![]
    } else if let Ok(s) = CStr::from_ptr(fields_json).to_str() {
        serde_json::from_str(s).unwrap_or_default()
    } else {
        vec![]
    };

    match ctx.collector.collect_processes(fields) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Process collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer returned by `jockey_rt_evidence_init`.
pub unsafe extern "C" fn jockey_rt_collect_network(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    match ctx.collector.collect_network_connections() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Network collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and ensure `path_ptr` and `hash_algo_ptr`
/// are valid UTF-8 C strings or null.
pub unsafe extern "C" fn jockey_rt_collect_files(
    ctx_ptr: *mut c_void,
    path_ptr: *const c_char,
    recursive: c_int,
    hash_algo_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let path = if path_ptr.is_null() {
        "/"
    } else {
        CStr::from_ptr(path_ptr).to_str().unwrap_or("/")
    };
    let hash_algo = if hash_algo_ptr.is_null() {
        "sha256"
    } else {
        CStr::from_ptr(hash_algo_ptr).to_str().unwrap_or("sha256")
    };

    match ctx.collector.collect_files(path, recursive != 0, hash_algo) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Filesystem collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and a valid UTF-8 C string pointer for
/// `source_ptr`, or null.
pub unsafe extern "C" fn jockey_rt_collect_logs(
    ctx_ptr: *mut c_void,
    source_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let source = if source_ptr.is_null() {
        "system"
    } else {
        CStr::from_ptr(source_ptr).to_str().unwrap_or("system")
    };

    match ctx.collector.collect_logs(source) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Logs collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer returned by `jockey_rt_evidence_init`.
pub unsafe extern "C" fn jockey_rt_collect_drivers(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    match crate::drivers::enumerate_drivers() {
        Ok(driver_records) => {
            for rec in driver_records {
                ctx.collector.add_record(rec);
            }
            0
        }
        Err(e) => {
            eprintln!("[jockey Runtime] Drivers collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer returned by `jockey_rt_evidence_init`.
pub unsafe extern "C" fn jockey_rt_collect_memory_regions(
    ctx_ptr: *mut c_void,
    pid: c_int,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let pid_filter = if pid <= 0 { None } else { Some(pid) };
    match ctx.collector.collect_memory_regions(pid_filter) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[jockey Runtime] Memory regions collection error: {}",
                e
            );
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and valid UTF-8 strings or null.
pub unsafe extern "C" fn jockey_rt_collect_registry(
    ctx_ptr: *mut c_void,
    hive_ptr: *const c_char,
    key_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let hive = if hive_ptr.is_null() {
        "HKLM"
    } else {
        CStr::from_ptr(hive_ptr).to_str().unwrap_or("HKLM")
    };
    let key_path = if key_ptr.is_null() {
        "SOFTWARE"
    } else {
        CStr::from_ptr(key_ptr).to_str().unwrap_or("SOFTWARE")
    };

    match ctx.collector.collect_registry(hive, key_path) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Registry collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and valid UTF-8 strings or null.
pub unsafe extern "C" fn jockey_rt_collect_artifacts(
    ctx_ptr: *mut c_void,
    type_ptr: *const c_char,
    path_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let artifact_type = if type_ptr.is_null() {
        "all"
    } else {
        CStr::from_ptr(type_ptr).to_str().unwrap_or("all")
    };
    let path = if path_ptr.is_null() {
        ""
    } else {
        CStr::from_ptr(path_ptr).to_str().unwrap_or("")
    };

    match ctx.collector.collect_artifacts(artifact_type, path) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Artifacts collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must ensure `ctx_ptr` is valid and `filter_json` is a valid UTF-8 C string pointer.
pub unsafe extern "C" fn jockey_rt_evidence_filter(
    ctx_ptr: *mut c_void,
    filter_json: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() || filter_json.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    if let Ok(s) = CStr::from_ptr(filter_json).to_str() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
            ctx.collector.add_filter(val);
            return 0;
        }
    }
    -1
}

#[no_mangle]
/// # Safety
/// Caller must ensure `ctx_ptr` is valid and `where_json` is a valid UTF-8 C string pointer.
pub unsafe extern "C" fn jockey_rt_evidence_where(
    ctx_ptr: *mut c_void,
    where_json: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() || where_json.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    if let Ok(s) = CStr::from_ptr(where_json).to_str() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
            ctx.collector.add_where(val);
            return 0;
        }
    }
    -1
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer returned by `jockey_rt_evidence_init`.
pub unsafe extern "C" fn jockey_rt_evidence_limit(ctx_ptr: *mut c_void, limit: usize) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    ctx.collector.set_limit(serde_json::json!(limit));
    0
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and valid UTF-8 C string pointers for the
/// format and output path, or null.
pub unsafe extern "C" fn jockey_rt_evidence_export(
    ctx_ptr: *mut c_void,
    format_ptr: *const c_char,
    path_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let format = if format_ptr.is_null() {
        "json"
    } else {
        CStr::from_ptr(format_ptr).to_str().unwrap_or("json")
    };
    let path = if path_ptr.is_null() {
        "evidence.json"
    } else {
        CStr::from_ptr(path_ptr).to_str().unwrap_or("evidence.json")
    };

    ctx.collector.set_output_format(format, path);
    match ctx.collector.finalize() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Export error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer and a valid UTF-8 C string pointer for
/// `algo_ptr`, or null.
pub unsafe extern "C" fn jockey_rt_evidence_compute_hash(
    ctx_ptr: *mut c_void,
    algo_ptr: *const c_char,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let algo = if algo_ptr.is_null() {
        "sha256"
    } else {
        CStr::from_ptr(algo_ptr).to_str().unwrap_or("sha256")
    };
    match ctx.collector.compute_hash(algo) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[jockey Runtime] Compute hash error: {}", e);
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// Caller must provide a valid runtime context pointer returned by `jockey_rt_evidence_init`.
pub unsafe extern "C" fn jockey_rt_evidence_generate_timeline(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    let host = ctx.collector.host_identifier().to_string();
    let records = ctx.collector.records();
    let mut timeline_records = Vec::with_capacity(records.len());
    for (i, rec) in records.iter().enumerate() {
        let ref_str = format!("ref-{}", i + 1);
        if let Some(event) =
            jockey_runtime_timeline::normalize_record(rec, &host, Some(&ref_str))
        {
            if let Ok(v) = serde_json::to_value(&event) {
                timeline_records.push(v);
                continue;
            }
        }
        timeline_records.push(rec.clone());
    }
    ctx.collector.set_records(timeline_records);
    ctx.collector
        .add_metadata("timeline_generated", serde_json::json!(true));
    0
}

#[no_mangle]
/// # Safety
/// Caller must ensure `ctx_ptr` is either null or a pointer previously returned by
/// `jockey_rt_evidence_init` and not already freed.
pub unsafe extern "C" fn jockey_rt_evidence_free(ctx_ptr: *mut c_void) {
    if !ctx_ptr.is_null() {
        drop(Box::from_raw(ctx_ptr as *mut RuntimeContext));
    }
}
