//! C-compatible ABI for TraceForge LLVM code generation
//!
//! Provides `extern "C"` endpoints called directly by the LLVM IR generated
//! by the TraceForge compiler.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use traceforge_runtime_evidence::EvidenceCollector;

/// Context wrapper holding the collector
pub struct RuntimeContext {
    pub collector: EvidenceCollector,
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_evidence_init(investigation_name: *const c_char) -> *mut c_void {
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
pub unsafe extern "C" fn traceforge_rt_collect_system(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    match ctx.collector.collect_system_info() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[TraceForge Runtime] System info collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_collect_processes(
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
            eprintln!("[TraceForge Runtime] Process collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_collect_network(ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    match ctx.collector.collect_network_connections() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("[TraceForge Runtime] Network collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_collect_files(
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
            eprintln!("[TraceForge Runtime] Filesystem collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_collect_logs(
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
            eprintln!("[TraceForge Runtime] Logs collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_collect_drivers(ctx_ptr: *mut c_void) -> c_int {
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
            eprintln!("[TraceForge Runtime] Drivers collection error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_evidence_filter(
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
pub unsafe extern "C" fn traceforge_rt_evidence_where(
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
pub unsafe extern "C" fn traceforge_rt_evidence_limit(
    ctx_ptr: *mut c_void,
    limit: usize,
) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut RuntimeContext);
    ctx.collector.set_limit(serde_json::json!(limit));
    0
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_evidence_export(
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
            eprintln!("[TraceForge Runtime] Export error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn traceforge_rt_evidence_free(ctx_ptr: *mut c_void) {
    if !ctx_ptr.is_null() {
        drop(Box::from_raw(ctx_ptr as *mut RuntimeContext));
    }
}
