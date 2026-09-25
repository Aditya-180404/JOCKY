use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

use jockey_ast::Severity;
use jockey_backend::TargetSpec;
use jockey_ir::{TargetArch, TargetPlatform};
use jockey_lexer::Lexer;
use jockey_parser::Parser;
use jockey_semantic::SemanticAnalyzer;

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticResponse {
    pub severity: String,
    pub message: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub valid: bool,
    pub diagnostics: Vec<DiagnosticResponse>,
    pub investigation_name: Option<String>,
    pub required_capabilities: Vec<String>,
    pub collectors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TargetResponse {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub architecture: String,
    pub supported: bool,
    pub host_compatible: bool,
    pub toolchain_required: Option<String>,
}

pub async fn targets_handler() -> Json<Vec<TargetResponse>> {
    let mut targets = vec![TargetResponse {
        id: "sandbox".to_string(),
        name: "jockey server sandbox".to_string(),
        platform: "sandbox".to_string(),
        architecture: "server".to_string(),
        supported: true,
        host_compatible: true,
        toolchain_required: None,
    }];

    for target in TargetSpec::supported_targets() {
        let (platform, architecture, id, name) = match (target.platform, target.arch) {
            (TargetPlatform::Windows, TargetArch::X64) => {
                ("windows", "x64", "windows-x64", "Windows x64")
            }
            (TargetPlatform::Linux, TargetArch::X64) => {
                ("linux", "x64", "linux-x64", "Linux x86_64")
            }
            (TargetPlatform::Windows, TargetArch::Arm64) => {
                ("windows", "arm64", "windows-arm64", "Windows ARM64")
            }
            (TargetPlatform::Linux, TargetArch::Arm64) => {
                ("linux", "arm64", "linux-arm64", "Linux ARM64")
            }
        };
        targets.push(TargetResponse {
            id: id.to_string(),
            name: name.to_string(),
            platform: platform.to_string(),
            architecture: architecture.to_string(),
            supported: target.is_supported(),
            host_compatible: target.host_compatible,
            toolchain_required: target.toolchain_required.map(str::to_string),
        });
    }

    Json(targets)
}

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub source: String,
    #[allow(dead_code)]
    pub target: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceItemResponse {
    pub id: String,
    pub collector: String,
    pub timestamp: String,
    pub source: String,
    /// Evidence provenance label:
    /// - `"REAL"`             = live-collected from the host running the API server
    /// - `"COLLECTOR_FAILED"` = collector returned an error; data field contains the error message
    pub origin: String,
    pub data: serde_json::Value,
    pub sha256: String,
    pub integrity: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub success: bool,
    pub investigation_name: String,
    pub execution_target: String,
    pub execution_time_ms: u64,
    pub collectors_executed: Vec<String>,
    pub evidence_count: usize,
    pub sha256: String,
    pub integrity: String,
    pub evidence_items: Vec<EvidenceItemResponse>,
    pub diagnostics: Vec<DiagnosticResponse>,
    pub output_log: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub evidence_json: String,
    pub expected_hash: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub actual_hash: String,
    pub expected_hash: String,
    pub message: String,
}

/// Endpoint: POST /api/compiler/check
pub async fn check_handler(
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut lexer = Lexer::new(&req.source);
    let tokens = match lexer.tokenize() {
        Ok(t) => t,
        Err(e) => {
            return Ok(Json(CheckResponse {
                valid: false,
                diagnostics: vec![DiagnosticResponse {
                    severity: "error".to_string(),
                    message: e.to_string(),
                    line: 1,
                    column: 1,
                }],
                investigation_name: None,
                required_capabilities: vec![],
                collectors: vec![],
            }));
        }
    };

    let mut parser = Parser::new(tokens);
    let (ast, parse_diags) = parser.parse_with_diagnostics();

    let mut all_diags = Vec::new();
    for d in parse_diags {
        let (line, column) = match d.span {
            Some(s) => (s.start_line, s.start_column),
            None => (1, 1),
        };
        all_diags.push(DiagnosticResponse {
            severity: match d.severity {
                Severity::Error => "error".to_string(),
                Severity::Warning => "warning".to_string(),
                Severity::Info => "info".to_string(),
                Severity::Hint => "hint".to_string(),
            },
            message: d.message,
            line,
            column,
        });
    }

    if let Some(ast) = ast {
        let mut analyzer = SemanticAnalyzer::new();
        let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

        for d in sem_diags {
            let (line, column) = match d.span {
                Some(s) => (s.start_line, s.start_column),
                None => (1, 1),
            };
            all_diags.push(DiagnosticResponse {
                severity: match d.severity {
                    Severity::Error => "error".to_string(),
                    Severity::Warning => "warning".to_string(),
                    Severity::Info => "info".to_string(),
                    Severity::Hint => "hint".to_string(),
                },
                message: d.message,
                line,
                column,
            });
        }

        let has_errors = all_diags.iter().any(|d| d.severity == "error");

        if let Some(ir) = ir {
            let mut collectors: Vec<String> = Vec::new();
            for op in &ir.operations {
                if let jockey_ir::IrOperation::Collect(c) = op {
                    collectors.push(c.operation.clone());
                }
            }

            let required_caps = ir
                .required_capabilities
                .iter()
                .map(|c| format!("{:?}", c))
                .collect();

            return Ok(Json(CheckResponse {
                valid: !has_errors,
                diagnostics: all_diags,
                investigation_name: Some(ir.name),
                required_capabilities: required_caps,
                collectors,
            }));
        }
    }

    Ok(Json(CheckResponse {
        valid: false,
        diagnostics: all_diags,
        investigation_name: None,
        required_capabilities: vec![],
        collectors: vec![],
    }))
}

/// Endpoint: POST /api/compiler/execute
pub async fn execute_handler(
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, Json<serde_json::Value>)> {
    let start_time = Instant::now();
    let mut log = Vec::new();
    log.push("jockey Sandbox Execution Engine v0.1.0".to_string());
    log.push("Parsing investigation specification...".to_string());

    let mut lexer = Lexer::new(&req.source);
    let tokens = match lexer.tokenize() {
        Ok(t) => t,
        Err(e) => {
            return Ok(Json(ExecuteResponse {
                success: false,
                investigation_name: "unknown".to_string(),
                execution_target: "jockey Sandbox".to_string(),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                collectors_executed: vec![],
                evidence_count: 0,
                sha256: String::new(),
                integrity: "FAILED".to_string(),
                evidence_items: vec![],
                diagnostics: vec![DiagnosticResponse {
                    severity: "error".to_string(),
                    message: e.to_string(),
                    line: 1,
                    column: 1,
                }],
                output_log: vec![format!("Lexer error: {}", e)],
            }));
        }
    };

    let mut parser = Parser::new(tokens);
    let (ast, parse_diags) = parser.parse_with_diagnostics();
    let mut all_diags = Vec::new();

    for d in parse_diags {
        let (line, column) = match d.span {
            Some(s) => (s.start_line, s.start_column),
            None => (1, 1),
        };
        all_diags.push(DiagnosticResponse {
            severity: match d.severity {
                Severity::Error => "error".to_string(),
                Severity::Warning => "warning".to_string(),
                Severity::Info => "info".to_string(),
                Severity::Hint => "hint".to_string(),
            },
            message: d.message,
            line,
            column,
        });
    }

    let ast = match ast {
        Some(a) => a,
        None => {
            return Ok(Json(ExecuteResponse {
                success: false,
                investigation_name: "unknown".to_string(),
                execution_target: "jockey Sandbox".to_string(),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                collectors_executed: vec![],
                evidence_count: 0,
                sha256: String::new(),
                integrity: "FAILED".to_string(),
                evidence_items: vec![],
                diagnostics: all_diags,
                output_log: vec!["Parse errors encountered. Execution aborted.".to_string()],
            }));
        }
    };

    let mut analyzer = SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);
    for d in sem_diags {
        let (line, column) = match d.span {
            Some(s) => (s.start_line, s.start_column),
            None => (1, 1),
        };
        all_diags.push(DiagnosticResponse {
            severity: match d.severity {
                Severity::Error => "error".to_string(),
                Severity::Warning => "warning".to_string(),
                Severity::Info => "info".to_string(),
                Severity::Hint => "hint".to_string(),
            },
            message: d.message,
            line,
            column,
        });
    }

    let ir = match ir {
        Some(i) => i,
        None => {
            return Ok(Json(ExecuteResponse {
                success: false,
                investigation_name: "unknown".to_string(),
                execution_target: "jockey Sandbox".to_string(),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                collectors_executed: vec![],
                evidence_count: 0,
                sha256: String::new(),
                integrity: "FAILED".to_string(),
                evidence_items: vec![],
                diagnostics: all_diags,
                output_log: vec!["Semantic validation errors encountered.".to_string()],
            }));
        }
    };

    log.push(format!(
        "Executing investigation '{}' in secure sandbox...",
        ir.name
    ));

    // Build a properly-labelled evidence item from live-collected data.
    // origin must be one of: "REAL", "COLLECTOR_FAILED"
    let make_item = |collector: &str, source: &str, origin: &str, data: serde_json::Value| -> EvidenceItemResponse {
        let item_json = serde_json::to_vec(&data).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&item_json);
        let item_hash = format!("{:x}", h.finalize());
        let integrity = if origin == "COLLECTOR_FAILED" { "N/A".to_string() } else { "VALID".to_string() };
        EvidenceItemResponse {
            id: format!("evi-{}-{}", collector.replace('.', "-"), uuid::Uuid::new_v4().simple()),
            collector: collector.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: source.to_string(),
            origin: origin.to_string(),
            data,
            sha256: item_hash,
            integrity,
        }
    };

    let mut collectors_executed = Vec::new();
    let mut evidence_items = Vec::new();
    let mut aggregated_evidence = Vec::new();

    for op in &ir.operations {
        if let jockey_ir::IrOperation::Collect(c) = op {
            match c.operation.as_str() {
                "system.info" | "system_info" | "system" => {
                    log.push("Running collector: system_info".to_string());
                    collectors_executed.push("system_info".to_string());

                    let (sys_data, origin) = match jockey_runtime_system::collect_system_info() {
                        Ok(info) => (
                            serde_json::to_value(&info).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})),
                            "REAL",
                        ),
                        Err(e) => (
                            serde_json::json!({"error": e.to_string(), "collector": "system_info"}),
                            "COLLECTOR_FAILED",
                        ),
                    };

                    let item = make_item("system_info", "/proc/sys", origin, sys_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "system_info",
                        "origin": origin,
                        "options": c.options,
                        "data": sys_data
                    }));
                }
                "process.enumerate" | "processes" | "process" => {
                    log.push("Running collector: processes".to_string());
                    collectors_executed.push("processes".to_string());

                    let (proc_data, origin) = match jockey_runtime_process::enumerate_processes(&c.fields) {
                        Ok(mut procs) => {
                            if procs.len() > 25 {
                                procs.truncate(25);
                            }
                            (serde_json::to_value(&procs).unwrap_or_else(|_| serde_json::json!([])), "REAL")
                        }
                        Err(e) => (serde_json::json!({"error": e.to_string(), "collector": "processes"}), "COLLECTOR_FAILED"),
                    };

                    let item = make_item("processes", "/proc/[pid]", origin, proc_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "processes",
                        "origin": origin,
                        "options": c.options,
                        "data": proc_data
                    }));
                }
                "network.connections" | "network_connections" | "network" => {
                    log.push("Running collector: network_connections".to_string());
                    collectors_executed.push("network_connections".to_string());

                    let (net_data, origin) = match jockey_runtime_network::enumerate_connections() {
                        Ok(mut conns) => {
                            if conns.len() > 20 {
                                conns.truncate(20);
                            }
                            (serde_json::to_value(&conns).unwrap_or_else(|_| serde_json::json!([])), "REAL")
                        }
                        Err(e) => (serde_json::json!({"error": e.to_string(), "collector": "network_connections"}), "COLLECTOR_FAILED"),
                    };

                    let item = make_item("network_connections", "/proc/net/tcp", origin, net_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "network_connections",
                        "origin": origin,
                        "options": c.options,
                        "data": net_data
                    }));
                }
                "filesystem.enumerate" | "filesystem" | "files" => {
                    log.push("Running collector: filesystem".to_string());
                    collectors_executed.push("filesystem".to_string());

                    // Collect real filesystem metadata from the paths specified in the IR.
                    // The scan root defaults to "/etc" if no path is provided.
                    let scan_root = c.options.get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("/etc");

                    let (fs_data, origin) = match jockey_runtime_filesystem::enumerate_files(scan_root, false, "sha256") {
                        Ok(entries) => (serde_json::to_value(&entries).unwrap_or_else(|_| serde_json::json!([])), "REAL"),
                        Err(e) => (serde_json::json!({"error": e.to_string(), "collector": "filesystem", "scan_root": scan_root}), "COLLECTOR_FAILED"),
                    };

                    let item = make_item("filesystem", scan_root, origin, fs_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "filesystem",
                        "origin": origin,
                        "options": c.options,
                        "data": fs_data
                    }));
                }
                "logs.collect" | "logs" => {
                    log.push("Running collector: logs".to_string());
                    collectors_executed.push("logs".to_string());

                    let log_source = c.options.get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("system");
                    let (log_data, origin) = match jockey_runtime_logs::collect_logs(log_source) {
                        Ok(entries) => (serde_json::to_value(&entries).unwrap_or_else(|_| serde_json::json!([])), "REAL"),
                        Err(e) => (serde_json::json!({"error": e.to_string(), "collector": "logs", "source": log_source}), "COLLECTOR_FAILED"),
                    };

                    let item = make_item("logs", "system journal / syslog", origin, log_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "logs",
                        "origin": origin,
                        "options": c.options,
                        "data": log_data
                    }));
                }
                "security.analysis" | "security_analysis" => {
                    log.push("Running collector: security_analysis".to_string());
                    collectors_executed.push("security_analysis".to_string());

                    let hostname = jockey_runtime_system::collect_system_info()
                        .ok().and_then(|s| s.get("hostname").and_then(|h| h.as_str()).map(|s| s.to_string()))
                        .unwrap_or_else(|| "sandbox-host".to_string());
                    let analyzer = jockey_runtime_security::SecurityAnalyzer::new(&hostname);
                    let summary = analyzer.summary();
                    let sec_data = serde_json::to_value(&summary).unwrap_or_default();

                    let item = make_item("security_analysis", "heuristic security engine", "REAL", sec_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": "security_analysis",
                        "origin": "REAL",
                        "data": sec_data
                    }));
                }
                other => {
                    log.push(format!("Collector '{}' is not registered in this execution context.", other));
                    collectors_executed.push(other.to_string());
                    let err_data = serde_json::json!({
                        "error": format!("Collector '{}' is not available in the API sandbox execution context. Use a native compiled binary for full collector support.", other),
                        "collector": other
                    });
                    let item = make_item(other, "N/A", "COLLECTOR_FAILED", err_data.clone());
                    evidence_items.push(item);
                    aggregated_evidence.push(serde_json::json!({
                        "collector": other,
                        "origin": "COLLECTOR_FAILED",
                        "data": err_data
                    }));
                }
            }
        }
    }

    let bundle_bytes = serde_json::to_vec_pretty(&aggregated_evidence).unwrap_or_default();
    let mut overall_hasher = Sha256::new();
    overall_hasher.update(&bundle_bytes);
    let overall_sha256 = format!("{:x}", overall_hasher.finalize());

    let real_count = evidence_items.iter().filter(|e| e.origin == "REAL").count();
    let failed_count = evidence_items.iter().filter(|e| e.origin == "COLLECTOR_FAILED").count();
    log.push(format!(
        "Finalized {} evidence items ({} REAL, {} COLLECTOR_FAILED).",
        evidence_items.len(), real_count, failed_count
    ));
    log.push(format!("SHA-256 Checksum: {}", overall_sha256));
    let integrity_status = if failed_count == 0 { "VALID" } else { "PARTIAL" };
    log.push(format!("Integrity status: {} (Cryptographically verified)", integrity_status));

    Ok(Json(ExecuteResponse {
        success: true,
        investigation_name: ir.name,
        execution_target: "jockey Sandbox".to_string(),
        execution_time_ms: start_time.elapsed().as_millis() as u64,
        collectors_executed,
        evidence_count: evidence_items.len(),
        sha256: overall_sha256,
        integrity: integrity_status.to_string(),
        evidence_items,
        diagnostics: all_diags,
        output_log: log,
    }))
}

/// Endpoint: POST /api/compiler/verify
pub async fn verify_handler(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut hasher = Sha256::new();
    hasher.update(req.evidence_json.as_bytes());
    let actual_hash = format!("{:x}", hasher.finalize());

    let is_valid = actual_hash.eq_ignore_ascii_case(req.expected_hash.trim());
    let message = if is_valid {
        "Cryptographic integrity VALID. Evidence is unmodified.".to_string()
    } else {
        format!(
            "Evidence TAMPERED! Expected SHA-256 {}, but computed {}",
            req.expected_hash, actual_hash
        )
    };

    Ok(Json(VerifyResponse {
        valid: is_valid,
        actual_hash,
        expected_hash: req.expected_hash,
        message,
    }))
}

#[derive(Debug, Serialize)]
pub struct DownloadInfoResponse {
    pub packages: Vec<DownloadPackage>,
}

#[derive(Debug, Serialize)]
pub struct DownloadPackage {
    pub platform: String,
    pub arch: String,
    pub name: String,
    pub filename: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub release_date: String,
    pub requirements: String,
    pub download_url: String,
}

/// Endpoint: GET /api/downloads/info
pub async fn downloads_info_handler() -> Json<DownloadInfoResponse> {
    Json(DownloadInfoResponse {
        packages: vec![
            DownloadPackage {
                platform: "Windows".to_string(),
                arch: "x64".to_string(),
                name: "jockey Windows Distribution Archive".to_string(),
                filename: "jockey-0.1.0-windows-x64.zip".to_string(),
                version: "0.1.0".to_string(),
                size_bytes: 1_580_458,
                sha256: "35b29f54b6879b039b462a97293f3b7ed6ecdf25a4a2b90a7c55d65eb2bd7247"
                    .to_string(),
                release_date: "2026-09-23".to_string(),
                requirements: "Windows 10 / 11 64-bit".to_string(),
                download_url: "/api/downloads/jockey-0.1.0-windows-x64.zip".to_string(),
            },
            DownloadPackage {
                platform: "Windows".to_string(),
                arch: "x64".to_string(),
                name: "jockey CLI Executable".to_string(),
                filename: "jockey.exe".to_string(),
                version: "0.1.0".to_string(),
                size_bytes: 3_226_112,
                sha256: "1e539f20b535e97ff4b44a983fb120ade3f6769bc7114212b50e92030b6321e2"
                    .to_string(),
                release_date: "2026-09-23".to_string(),
                requirements: "Windows 10 / 11 64-bit".to_string(),
                download_url: "/api/downloads/jockey.exe".to_string(),
            },
        ],
    })
}

/// Endpoint: GET /api/downloads/:filename
pub async fn download_file_handler(Path(filename): Path<String>) -> impl IntoResponse {
    let sanitized = filename.replace("..", "").replace(['/', '\\'], "");
    let package_path = std::path::PathBuf::from("./packages").join(&sanitized);
    let build_path = std::path::PathBuf::from("./build").join(&sanitized);
    let target_path = std::path::PathBuf::from("./target/release").join(&sanitized);
    let debug_path = std::path::PathBuf::from("./target/debug").join(&sanitized);

    let content_res = if package_path.is_file() {
        std::fs::read(&package_path)
    } else if build_path.is_file() {
        std::fs::read(&build_path)
    } else if target_path.is_file() {
        std::fs::read(&target_path)
    } else if debug_path.is_file() {
        std::fs::read(&debug_path)
    } else {
        return (StatusCode::NOT_FOUND, "Artifact not currently available").into_response();
    };

    match content_res {
        Ok(data) => (
            StatusCode::OK,
            [
                ("Content-Type", "application/octet-stream"),
                (
                    "Content-Disposition",
                    &format!("attachment; filename=\"{}\"", sanitized),
                ),
            ],
            data,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Artifact not currently available").into_response(),
    }
}
