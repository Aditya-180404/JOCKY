use axum::{
    body::Body,
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jocky_ast::Severity;
use jocky_backend::TargetSpec;
use jocky_backend::{Backend, BackendKind};
use jocky_ir::BuildConfig;
use jocky_ir::{TargetArch, TargetPlatform};
use jocky_lexer::Lexer;
use jocky_parser::Parser;
use jocky_semantic::SemanticAnalyzer;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub source: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    pub source: String,
    pub target: Option<String>,
}

/// Compile defensive JOCKY source to a downloadable local artifact.
/// The hosted compiler intentionally supports Linux x86_64 only. Windows users download
/// the compiler and build on a Windows machine, where the runtime can inspect that host.
pub async fn compile_handler(Json(req): Json<CompileRequest>) -> Response {
    if req.source.len() > 256 * 1024 {
        return compiler_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Source exceeds the 256 KiB compile limit",
        );
    }

    let target = req.target.unwrap_or_else(|| "linux-x64".to_string());
    if target != "linux-x64" && target != "windows-x64" {
        return compiler_error(
            StatusCode::BAD_REQUEST,
            "Unsupported target platform. Supported targets: linux-x64, windows-x64.",
        );
    }

    let target_clone = target.clone();
    let result =
        tokio::task::spawn_blocking(move || compile_native_artifact(&req.source, &target_clone))
            .await;
    match result {
        Ok(Ok((filename, bytes))) => {
            let disposition = format!("attachment; filename=\"{}\"", filename);
            let mut response = Response::new(Body::from(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition)
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            let target_header = if target.contains("windows") {
                HeaderValue::from_static("windows-x86_64")
            } else {
                HeaderValue::from_static("linux-x86_64")
            };
            response
                .headers_mut()
                .insert("x-jocky-target", target_header);
            response
        }
        Ok(Err(message)) => compiler_error(StatusCode::UNPROCESSABLE_ENTITY, &message),
        Err(error) => compiler_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Compile task failed: {}", error),
        ),
    }
}

fn compile_native_artifact(source: &str, target_str: &str) -> Result<(String, Vec<u8>), String> {
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize().map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens);
    let (ast, diagnostics) = parser.parse_with_diagnostics();
    if !diagnostics.is_empty() {
        return Err(diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect::<Vec<_>>()
            .join("; "));
    }
    let ast = ast.ok_or_else(|| "Unable to parse investigation".to_string())?;
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, diagnostics) = analyzer.analyze_with_diagnostics(&ast);
    if !diagnostics.is_empty() {
        return Err(diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect::<Vec<_>>()
            .join("; "));
    }
    let ir = ir.ok_or_else(|| "Unable to analyze investigation".to_string())?;
    let output_dir =
        std::env::temp_dir().join(format!("jocky-public-build-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;

    let is_windows = target_str.contains("windows");
    let target_platform = if is_windows {
        TargetPlatform::Windows
    } else {
        TargetPlatform::Linux
    };
    let config = BuildConfig {
        target_platform,
        target_arch: TargetArch::X64,
        optimization_level: jocky_ir::OptimizationLevel::Speed,
        debug_symbols: false,
        strip_symbols: true,
        obfuscation: Default::default(),
    };
    let backend_kind = if std::env::var("JOCKY_BACKEND").unwrap_or_default() == "llvm" {
        BackendKind::Llvm
    } else {
        BackendKind::Rust
    };
    let build = Backend::new_with_kind(config, backend_kind).generate(&ir, &output_dir);
    let filename = if is_windows {
        format!("{}-windows-x64.exe", ir.name)
    } else {
        format!("{}-linux-x64", ir.name)
    };
    let path = PathBuf::from(&output_dir).join(&filename);
    let bytes = build
        .map_err(|e| e.to_string())
        .and_then(|_| std::fs::read(&path).map_err(|e| e.to_string()));
    let cleanup_dir = output_dir.clone();
    std::thread::spawn(move || {
        let _ = std::fs::remove_dir_all(&cleanup_dir);
    });
    bytes.map(|bytes| (filename, bytes))
}

fn compiler_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": "compile_failed", "message": message })),
    )
        .into_response()
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
    let mut targets = Vec::new();

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
        if !target.is_supported() {
            continue;
        }
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

#[derive(Debug, serde::Deserialize, Default)]
pub struct CapabilitiesQuery {
    pub status: Option<String>,
    pub platform: Option<String>,
}

pub async fn capabilities_handler(
    axum::extract::Query(query): axum::extract::Query<CapabilitiesQuery>,
) -> Json<serde_json::Value> {
    let reg = jocky_runtime_capabilities::CapabilityRegistry::new();
    let mut map = reg.to_json();
    let total = map.as_object().map_or(0, serde_json::Map::len);
    if let serde_json::Value::Object(ref mut payload) = map {
        if query.status.is_some() || query.platform.is_some() {
            let status_filter = query.status.as_ref().map(|s| s.to_lowercase());
            let platform_filter = query.platform.as_ref().map(|p| p.to_lowercase());
            payload.retain(|_k, v| {
                if let Some(ref sf) = status_filter {
                    let cap_status = v
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let is_impl = v
                        .get("is_implemented")
                        .and_then(|b| b.as_bool())
                        .unwrap_or(false);
                    let matches_status = if sf == "implemented" {
                        cap_status == "implemented"
                    } else if sf == "missing" || sf == "unsupported" {
                        cap_status == "unsupported" || !is_impl
                    } else {
                        cap_status == *sf
                            || cap_status.replace('_', " ") == *sf
                            || cap_status.replace('_', "") == *sf
                    };
                    if !matches_status {
                        return false;
                    }
                }
                if let Some(ref pf) = platform_filter {
                    let platforms = v
                        .get("platforms")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let matches_platform = if pf == "windows" {
                        platforms.contains("windows") || platforms.contains("both")
                    } else if pf == "linux" {
                        platforms.contains("linux") || platforms.contains("both")
                    } else {
                        platforms.contains(pf)
                    };
                    if !matches_platform {
                        return false;
                    }
                }
                true
            });
        }
    }

    let payload = match map {
        serde_json::Value::Object(payload) => payload,
        other => {
            return Json(serde_json::json!({
                "capabilities": other,
                "count": 0,
                "total": total,
                "implemented": 0,
                "partial": 0,
                "requires_elevation": 0,
                "unsupported": 0,
            }));
        }
    };

    let count = payload.len();
    let implemented = payload
        .values()
        .filter(|v| v.get("status") == Some(&serde_json::Value::String("IMPLEMENTED".into())))
        .count();
    let partial = payload
        .values()
        .filter(|v| v.get("status") == Some(&serde_json::Value::String("PARTIAL".into())))
        .count();
    let requires_elevation = payload
        .values()
        .filter(|v| {
            v.get("status") == Some(&serde_json::Value::String("REQUIRES_ELEVATION".into()))
        })
        .count();
    let unsupported = payload
        .values()
        .filter(|v| v.get("status") == Some(&serde_json::Value::String("UNSUPPORTED".into())))
        .count();

    Json(serde_json::json!({
        "capabilities": payload,
        "count": count,
        "total": total,
        "implemented": implemented,
        "partial": partial,
        "requires_elevation": requires_elevation,
        "unsupported": unsupported,
    }))
}

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

        if let Some(ir) = ir {
            let mut collectors: Vec<String> = Vec::new();
            for op in &ir.operations {
                if let jocky_ir::IrOperation::Collect(c) = op {
                    collectors.push(c.operation.clone());
                }
            }

            let reg = jocky_runtime_capabilities::CapabilityRegistry::new();
            if let Some(ref target) = req.target {
                let target_lower = target.to_lowercase();
                let is_windows = target_lower.contains("windows");
                let is_linux = target_lower.contains("linux");
                if !is_windows && !is_linux {
                    all_diags.push(DiagnosticResponse {
                        severity: "error".to_string(),
                        message: format!(
                            "Unsupported target platform '{}'. Supported targets: windows-x64, linux-x64",
                            target
                        ),
                        line: 1,
                        column: 1,
                    });
                }
                for cap_name in &ir.required_capabilities {
                    let cap_str = format!("{:?}", cap_name).to_lowercase();
                    if cap_str.contains("registry") && is_linux {
                        all_diags.push(DiagnosticResponse {
                            severity: "error".to_string(),
                            message: format!(
                                "Capability 'RegistryRead' is Windows-specific and not supported on target platform '{}'",
                                target
                            ),
                            line: 1,
                            column: 1,
                        });
                    }
                    if let Some(cap) = reg.capabilities.values().find(|c| {
                        let id_norm = c.id.replace('.', "").to_lowercase();
                        let name_norm = c.name.replace(' ', "").to_lowercase();
                        id_norm == cap_str
                            || name_norm == cap_str
                            || (cap_str.contains("registry") && c.id.starts_with("registry."))
                    }) {
                        use jocky_runtime_capabilities::Platform;
                        let compatible = match cap.platforms {
                            Platform::Both => true,
                            Platform::Windows => is_windows,
                            Platform::Linux => is_linux,
                        };
                        if !compatible && !cap_str.contains("registry") {
                            all_diags.push(DiagnosticResponse {
                                severity: "error".to_string(),
                                message: format!(
                                    "Capability '{}' is not supported on target platform '{}'",
                                    cap.name, target
                                ),
                                line: 1,
                                column: 1,
                            });
                        }
                    }
                }
            }

            let required_caps = ir
                .required_capabilities
                .iter()
                .map(|c| format!("{:?}", c))
                .collect();

            let has_errors = all_diags.iter().any(|d| d.severity == "error");

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

/// Compute SHA-256 of a file searching several candidate locations, return "unavailable" if file does not exist.
fn file_sha256_candidates(candidates: &[&str]) -> (String, u64) {
    use sha2::{Digest, Sha256};
    for path in candidates {
        if let Ok(mut f) = std::fs::File::open(path) {
            if let Ok(meta) = f.metadata() {
                let size = meta.len();
                let mut h = Sha256::new();
                if std::io::copy(&mut f, &mut h).is_ok() {
                    return (format!("{:x}", h.finalize()), size);
                }
            }
        }
    }
    ("unavailable".to_string(), 0)
}

/// Endpoint: GET /api/downloads/info
pub async fn downloads_info_handler() -> Json<DownloadInfoResponse> {
    // Compute real hashes from the actual files on disk
    let (win_zip_hash, win_zip_size) = file_sha256_candidates(&[
        "./jocky_0.1.0_windows_amd64.zip",
        "./packages/jocky_0.1.0_windows_amd64.zip",
        "./packages/jocky-0.1.0-windows-x64.zip",
    ]);
    let (deb_hash, deb_size) = file_sha256_candidates(&[
        "./jocky_0.1.0_amd64.deb",
        "./packages/jocky_0.1.0_amd64.deb",
    ]);
    let (win_exe_hash, win_exe_size) = file_sha256_candidates(&[
        "./target/release/jocky.exe",
        "./packaging/windows-stage/jocky.exe",
    ]);

    let release_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut packages = Vec::new();

    if win_zip_size > 0 && win_zip_hash != "unavailable" {
        packages.push(DownloadPackage {
            platform: "Windows".to_string(),
            arch: "x64".to_string(),
            name: "jocky Windows Distribution Archive (.zip)".to_string(),
            filename: "jocky_0.1.0_windows_amd64.zip".to_string(),
            version: "0.1.0".to_string(),
            size_bytes: win_zip_size,
            sha256: win_zip_hash,
            content_type: "application/zip".to_string(),
            release_date: release_date.clone(),
            requirements: "Windows 10 / 11 64-bit".to_string(),
            download_url: "/api/downloads/jocky_0.1.0_windows_amd64.zip".to_string(),
        });
    }

    if deb_size > 0 && deb_hash != "unavailable" {
        packages.push(DownloadPackage {
            platform: "Linux (Debian)".to_string(),
            arch: "x64".to_string(),
            name: "jocky Debian / Ubuntu Package (.deb)".to_string(),
            filename: "jocky_0.1.0_amd64.deb".to_string(),
            version: "0.1.0".to_string(),
            size_bytes: deb_size,
            sha256: deb_hash,
            content_type: "application/vnd.debian.binary-package".to_string(),
            release_date: release_date.clone(),
            requirements: "Debian 12+ / Ubuntu 22.04+ (x86_64)".to_string(),
            download_url: "/api/downloads/jocky_0.1.0_amd64.deb".to_string(),
        });
    }

    if win_exe_size > 0 && win_exe_hash != "unavailable" {
        packages.push(DownloadPackage {
            platform: "Windows".to_string(),
            arch: "x64".to_string(),
            name: "jocky Standalone CLI Executable".to_string(),
            filename: "jocky.exe".to_string(),
            version: "0.1.0".to_string(),
            size_bytes: win_exe_size,
            sha256: win_exe_hash,
            content_type: "application/vnd.microsoft.portable-executable".to_string(),
            release_date,
            requirements: "Windows 10 / 11 64-bit".to_string(),
            download_url: "/api/downloads/jocky.exe".to_string(),
        });
    }

    Json(DownloadInfoResponse { packages })
}

/// Endpoint: GET /api/downloads/:filename
pub async fn download_file_handler(Path(filename): Path<String>) -> impl IntoResponse {
    let (candidates, content_type): (&[&str], &str) = match filename.as_str() {
        "jocky_0.1.0_windows_amd64.zip" => (
            &[
                "./jocky_0.1.0_windows_amd64.zip",
                "./packages/jocky_0.1.0_windows_amd64.zip",
                "./build/jocky_0.1.0_windows_amd64.zip",
            ],
            "application/zip",
        ),
        "jocky_0.1.0_amd64.deb" => (
            &[
                "./jocky_0.1.0_amd64.deb",
                "./packages/jocky_0.1.0_amd64.deb",
            ],
            "application/vnd.debian.binary-package",
        ),
        "jocky.exe" => (
            &[
                "./target/release/jocky.exe",
                "./jocky.exe",
                "./packaging/windows-stage/jocky.exe",
            ],
            "application/vnd.microsoft.portable-executable",
        ),
        _ => return (StatusCode::NOT_FOUND, "Artifact not currently available").into_response(),
    };

    let content_res = candidates
        .iter()
        .map(std::path::Path::new)
        .find(|path| path.is_file())
        .map(std::fs::read);

    match content_res {
        Some(Ok(data)) => {
            let etag = format!("\"{}{}\"", data.len(), filename.len());
            let content_length = data.len().to_string();

            (
                StatusCode::OK,
                [
                    ("Content-Type", content_type),
                    (
                        "Content-Disposition",
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                    ("Content-Length", &content_length),
                    ("ETag", &etag),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                ],
                data,
            )
                .into_response()
        }
        Some(Err(_)) | None => {
            (StatusCode::NOT_FOUND, "Artifact not currently available").into_response()
        }
    }
}

#[cfg(test)]
mod download_tests {
    use super::{
        capabilities_handler, download_file_handler, download_windows_handler,
        downloads_info_handler, verify_handler, CapabilitiesQuery, VerifyRequest,
    };
    use axum::{body::to_bytes, response::IntoResponse, Json};

    #[tokio::test]
    async fn download_route_rejects_unapproved_names_and_traversal() {
        for filename in [
            "Cargo.toml",
            "../../Cargo.toml",
            "../../../etc/passwd",
            r"..\..\Cargo.toml",
            "foo.json",
        ] {
            let response = download_file_handler(axum::extract::Path(filename.to_string()))
                .await
                .into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::NOT_FOUND,
                "unexpectedly accepted {filename}"
            );
        }
    }

    #[tokio::test]
    async fn windows_download_route_returns_canonical_zip_headers() {
        let path =
            std::env::temp_dir().join(format!("jocky-download-test-{}.zip", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"PK\x03\x04test").unwrap();
        let previous = std::env::var_os("JOCKY_WINDOWS_ZIP");
        std::env::set_var("JOCKY_WINDOWS_ZIP", &path);

        let response = download_windows_handler().await.into_response();

        if let Some(value) = previous {
            std::env::set_var("JOCKY_WINDOWS_ZIP", value);
        } else {
            std::env::remove_var("JOCKY_WINDOWS_ZIP");
        }
        let _ = std::fs::remove_file(path);

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/zip"
        );
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_DISPOSITION],
            "attachment; filename=\"jocky_0.1.0_windows_amd64.zip\""
        );
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
    }

    #[tokio::test]
    async fn evidence_verification_accepts_original_and_rejects_tampered_json() {
        use sha2::{Digest, Sha256};

        let records = vec![serde_json::json!({ "hostname": "test-host" })];
        let evidence = serde_json::to_string(&records).unwrap();
        let evidence_hash = format!("{:x}", Sha256::digest(evidence.as_bytes()));
        let record_hashes = records
            .iter()
            .map(|record| format!("{:x}", Sha256::digest(serde_json::to_vec(record).unwrap())))
            .collect::<Vec<_>>();
        let merkle_root = jocky_runtime::compute_merkle_root(&record_hashes);
        let metadata = serde_json::json!({
            "evidence_hash": evidence_hash,
            "merkle_root": merkle_root,
        });

        let original = verify_handler(Json(VerifyRequest {
            evidence: evidence.clone(),
            metadata: metadata.clone(),
        }))
        .await;
        let original_body = to_bytes(original.into_body(), usize::MAX).await.unwrap();
        let original_result: serde_json::Value = serde_json::from_slice(&original_body).unwrap();
        assert_eq!(original_result["valid"], true);
        assert_eq!(original_result["status"], "VALID");

        let tampered = evidence.replace("test-host", "modified-host");
        let response = verify_handler(Json(VerifyRequest {
            evidence: tampered,
            metadata,
        }))
        .await;
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["valid"], false);
        assert_eq!(result["status"], "TAMPERED");
    }

    #[tokio::test]
    async fn capability_envelope_counts_and_filtered_total_match_registry() {
        let full = capabilities_handler(axum::extract::Query(CapabilitiesQuery::default()))
            .await
            .0;
        assert_eq!(full["count"], 247);
        assert_eq!(full["total"], 247);
        assert_eq!(full["implemented"], 241);
        assert_eq!(full["partial"], 1);
        assert_eq!(full["requires_elevation"], 4);
        assert_eq!(full["unsupported"], 1);
        assert_eq!(full["capabilities"].as_object().unwrap().len(), 247);

        let filtered = capabilities_handler(axum::extract::Query(CapabilitiesQuery {
            status: Some("implemented".to_string()),
            platform: None,
        }))
        .await
        .0;
        assert_eq!(filtered["count"], 241);
        assert_eq!(filtered["total"], 247);
        assert_eq!(filtered["implemented"], 241);
    }

    #[tokio::test]
    async fn download_metadata_only_describes_real_artifacts() {
        let response = downloads_info_handler().await.0;
        for package in response.packages {
            assert!(
                package.size_bytes > 0,
                "{} has no artifact bytes",
                package.filename
            );
            assert!(
                package.sha256.len() == 64
                    && package.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{} has no computed SHA-256 digest",
                package.filename
            );
            let expected_content_type = match package.filename.as_str() {
                "jocky_0.1.0_windows_amd64.zip" => "application/zip",
                "jocky_0.1.0_amd64.deb" => "application/vnd.debian.binary-package",
                "jocky.exe" => "application/vnd.microsoft.portable-executable",
                other => panic!("unapproved package filename advertised: {other}"),
            };
            assert_eq!(package.content_type, expected_content_type);
        }
    }
}

/// Endpoint: GET /api/downloads/windows — Direct Windows download
pub async fn download_windows_handler() -> impl IntoResponse {
    let candidates = [
        std::env::var("JOCKY_WINDOWS_ZIP").unwrap_or_default(),
        "./jocky_0.1.0_windows_amd64.zip".to_string(),
        "./packages/jocky_0.1.0_windows_amd64.zip".to_string(),
        "./build/jocky_0.1.0_windows_amd64.zip".to_string(),
    ];

    for path_str in candidates {
        if path_str.is_empty() {
            continue;
        }
        let p = std::path::PathBuf::from(&path_str);
        if p.is_file() {
            if let Ok(data) = std::fs::read(&p) {
                let filename = "jocky_0.1.0_windows_amd64.zip";
                let content_length = data.len().to_string();
                return (
                    StatusCode::OK,
                    [
                        ("Content-Type", "application/zip"),
                        (
                            "Content-Disposition",
                            &format!("attachment; filename=\"{}\"", filename),
                        ),
                        ("Content-Length", &content_length),
                        ("Cache-Control", "no-store"),
                    ],
                    data,
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "artifact_unavailable",
            "message": "Windows package is not currently available on the server"
        })),
    )
        .into_response()
}

/// Endpoint: GET /api/downloads/linux — Direct Linux download
pub async fn download_linux_handler() -> impl IntoResponse {
    let candidates = [
        std::env::var("JOCKY_LINUX_DEB").unwrap_or_default(),
        "./jocky_0.1.0_amd64.deb".to_string(),
        "./packages/jocky_0.1.0_amd64.deb".to_string(),
    ];

    for path_str in candidates {
        if path_str.is_empty() {
            continue;
        }
        let p = std::path::PathBuf::from(&path_str);
        if p.is_file() {
            if let Ok(data) = std::fs::read(&p) {
                let filename = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("jocky_0.1.0_amd64.deb");
                let content_length = data.len().to_string();
                return (
                    StatusCode::OK,
                    [
                        ("Content-Type", "application/vnd.debian.binary-package"),
                        (
                            "Content-Disposition",
                            &format!("attachment; filename=\"{}\"", filename),
                        ),
                        ("Content-Length", &content_length),
                        ("Cache-Control", "no-store"),
                    ],
                    data,
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "artifact_unavailable",
            "message": "Debian Linux package is not currently built on this host; download from GitHub Releases or build with packaging/build-deb.sh"
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RunRequest {
    pub source: String,
    pub target: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RunResponse {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub evidence: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub verification: Option<VerificationResponse>,
    pub artifact_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerificationResponse {
    pub valid: bool,
    pub status: String,
    pub sha256: String,
    pub merkle_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_raw: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub evidence: String,
    pub metadata: serde_json::Value,
}

pub async fn verify_handler(Json(req): Json<VerifyRequest>) -> Response {
    const MAX_EVIDENCE_SIZE: usize = 16 * 1024 * 1024;
    if req.evidence.len() > MAX_EVIDENCE_SIZE {
        return compiler_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Evidence exceeds the 16 MiB verification limit",
        );
    }

    let expected_hash = match req.metadata.get("evidence_hash").and_then(|v| v.as_str()) {
        Some(hash) => hash,
        None => return compiler_error(StatusCode::BAD_REQUEST, "Metadata has no evidence_hash"),
    };
    let records: Vec<serde_json::Value> = match serde_json::from_str(&req.evidence) {
        Ok(records) => records,
        Err(error) => {
            return compiler_error(
                StatusCode::BAD_REQUEST,
                &format!("Evidence is not a valid JSON record array: {error}"),
            )
        }
    };

    use sha2::{Digest, Sha256};
    let calculated_hash = format!("{:x}", Sha256::digest(req.evidence.as_bytes()));
    let merkle_root = req.metadata.get("merkle_root").and_then(|v| v.as_str());
    let calculated_merkle_root = if merkle_root.is_some() {
        let record_hashes = records
            .iter()
            .map(|record| {
                let bytes = serde_json::to_vec(record).unwrap_or_default();
                format!("{:x}", Sha256::digest(bytes))
            })
            .collect::<Vec<_>>();
        Some(jocky_runtime::compute_merkle_root(&record_hashes))
    } else {
        None
    };
    let hash_matches = calculated_hash == expected_hash;
    let merkle_matches = merkle_root
        .zip(calculated_merkle_root.as_deref())
        .map(|(expected, calculated)| expected == calculated)
        .unwrap_or(true);
    let valid = hash_matches && merkle_matches;

    Json(VerificationResponse {
        valid,
        status: if valid {
            "VALID".to_string()
        } else {
            "TAMPERED".to_string()
        },
        sha256: calculated_hash,
        merkle_root: calculated_merkle_root,
        evidence_raw: None,
    })
    .into_response()
}

/// Endpoint: POST /api/compiler/run — Execute JOCKY program in controlled sandbox and return structured evidence
pub async fn run_handler(Json(req): Json<RunRequest>) -> Response {
    if req.source.len() > 256 * 1024 {
        return compiler_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Source exceeds the 256 KiB execution limit",
        );
    }

    let target = req.target.unwrap_or_else(|| {
        if cfg!(target_os = "windows") {
            "windows-x64".to_string()
        } else {
            "linux-x64".to_string()
        }
    });

    let target_clone = target.clone();
    let result =
        tokio::task::spawn_blocking(move || execute_native_program(&req.source, &target_clone))
            .await;
    match result {
        Ok(res) => Json(res).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "exit_code": -1,
                "stdout": "",
                "stderr": format!("Server task execution failed: {}", e),
                "duration_ms": 0,
                "evidence": null,
                "metadata": null,
                "verification": null,
                "artifact_name": null,
            })),
        )
            .into_response(),
    }
}

fn execute_native_program(source: &str, target_str: &str) -> RunResponse {
    let start_time = std::time::Instant::now();

    // 1. Lex and tokenize
    let mut lexer = Lexer::new(source);
    let tokens = match lexer.tokenize() {
        Ok(t) => t,
        Err(e) => {
            return RunResponse {
                success: false,
                exit_code: 1,
                stdout: String::new(),
                stderr: format!("Lexer error: {}", e),
                duration_ms: start_time.elapsed().as_millis() as u64,
                evidence: None,
                metadata: None,
                verification: None,
                artifact_name: None,
            };
        }
    };

    // 2. Parse AST
    let mut parser = Parser::new(tokens);
    let (ast, diagnostics) = parser.parse_with_diagnostics();
    if !diagnostics.is_empty() && ast.is_none() {
        let errs = diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect::<Vec<_>>()
            .join("\n");
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Parser error:\n{}", errs),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: None,
        };
    }

    let ast = match ast {
        Some(a) => a,
        None => {
            return RunResponse {
                success: false,
                exit_code: 1,
                stdout: String::new(),
                stderr: "Unable to parse investigation source".to_string(),
                duration_ms: start_time.elapsed().as_millis() as u64,
                evidence: None,
                metadata: None,
                verification: None,
                artifact_name: None,
            };
        }
    };

    // 3. Semantic Analysis
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, diagnostics) = analyzer.analyze_with_diagnostics(&ast);
    if !diagnostics.is_empty() && ir.is_none() {
        let errs = diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect::<Vec<_>>()
            .join("\n");
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Semantic validation error:\n{}", errs),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: None,
        };
    }

    let ir = match ir {
        Some(i) => i,
        None => {
            return RunResponse {
                success: false,
                exit_code: 1,
                stdout: String::new(),
                stderr: "Unable to analyze investigation IR".to_string(),
                duration_ms: start_time.elapsed().as_millis() as u64,
                evidence: None,
                metadata: None,
                verification: None,
                artifact_name: None,
            };
        }
    };

    // Target checks
    let is_windows_target = target_str.contains("windows");
    let is_linux_target = target_str.contains("linux");
    let host_is_windows = cfg!(target_os = "windows");
    let host_is_linux = cfg!(target_os = "linux");

    if is_linux_target && !host_is_linux {
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: "Direct execution of Linux targets is only supported on a Linux host (or via Docker/WSL). Use 'windows-x64' target for live execution on this server, or click 'Compile' to download the artifact.".to_string(),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: Some(format!("{}-linux-x64", ir.name)),
        };
    }

    if is_windows_target && !host_is_windows {
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: "Direct execution of Windows targets is only supported on a Windows host. Click 'Compile' to download the standalone executable.".to_string(),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: Some(format!("{}-windows-x64.exe", ir.name)),
        };
    }

    let output_dir = std::env::temp_dir().join(format!("jocky-run-{}", uuid::Uuid::new_v4()));
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Failed to create temporary build directory: {}", e),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: None,
        };
    }

    let target_platform = if is_windows_target {
        TargetPlatform::Windows
    } else {
        TargetPlatform::Linux
    };

    let config = BuildConfig {
        target_platform,
        target_arch: TargetArch::X64,
        optimization_level: jocky_ir::OptimizationLevel::Speed,
        debug_symbols: false,
        strip_symbols: true,
        obfuscation: Default::default(),
    };
    let backend_kind = if std::env::var("JOCKY_BACKEND").unwrap_or_default() == "llvm" {
        BackendKind::Llvm
    } else {
        BackendKind::Rust
    };

    let build_res = Backend::new_with_kind(config, backend_kind).generate(&ir, &output_dir);
    if let Err(e) = build_res {
        let _ = std::fs::remove_dir_all(&output_dir);
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Compilation failed: {}", e),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: None,
        };
    }

    let artifact_name = if is_windows_target {
        format!("{}-windows-x64.exe", ir.name)
    } else {
        format!("{}-linux-x64", ir.name)
    };
    let executable_path = output_dir.join(&artifact_name);

    if !executable_path.is_file() {
        let _ = std::fs::remove_dir_all(&output_dir);
        return RunResponse {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: format!(
                "Generated executable artifact '{}' not found on disk",
                artifact_name
            ),
            duration_ms: start_time.elapsed().as_millis() as u64,
            evidence: None,
            metadata: None,
            verification: None,
            artifact_name: Some(artifact_name),
        };
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut cmd = std::process::Command::new(&executable_path);
    cmd.current_dir(&output_dir);
    cmd.stdin(std::process::Stdio::null());

    let _exec_thread = std::thread::spawn(move || {
        let res = cmd.output();
        let _ = tx.send(res);
    });

    let timeout_dur = std::time::Duration::from_secs(240);
    let output = match rx.recv_timeout(timeout_dur) {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            let _ = std::fs::remove_dir_all(&output_dir);
            return RunResponse {
                success: false,
                exit_code: 1,
                stdout: String::new(),
                stderr: format!("Process execution error: {}", e),
                duration_ms: start_time.elapsed().as_millis() as u64,
                evidence: None,
                metadata: None,
                verification: None,
                artifact_name: Some(artifact_name),
            };
        }
        Err(_) => {
            let _ = std::fs::remove_dir_all(&output_dir);
            return RunResponse {
                success: false,
                exit_code: 124,
                stdout: String::new(),
                stderr: "Execution timed out after 240 seconds".to_string(),
                duration_ms: start_time.elapsed().as_millis() as u64,
                evidence: None,
                metadata: None,
                verification: None,
                artifact_name: Some(artifact_name),
            };
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output
        .status
        .code()
        .unwrap_or(if output.status.success() { 0 } else { 1 });

    let mut evidence_val: Option<serde_json::Value> = None;
    let mut evidence_raw: Option<String> = None;
    let mut metadata_val: Option<serde_json::Value> = None;
    let mut verification_res: Option<VerificationResponse> = None;

    if let Ok(entries) = std::fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if fname.ends_with(".json")
                && !fname.ends_with(".meta.json")
                && !fname.ends_with(".manifest.json")
                && !fname.ends_with(".ast.json")
                && !fname.ends_with(".hir.json")
                && !fname.ends_with(".mir.json")
            {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    evidence_raw = Some(content.clone());
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        evidence_val = Some(val);
                    }
                }
                let meta_path = if path.with_extension("json.meta.json").exists() {
                    path.with_extension("json.meta.json")
                } else {
                    let mut p = path.clone();
                    p.set_extension("meta.json");
                    p
                };
                if meta_path.is_file() {
                    if let Ok(meta_content) = std::fs::read_to_string(&meta_path) {
                        if let Ok(meta_val) =
                            serde_json::from_str::<serde_json::Value>(&meta_content)
                        {
                            metadata_val = Some(meta_val);
                        }
                    }
                }
                if let Ok(result) = jocky_runtime::verify_evidence(
                    path.to_str().unwrap_or_default(),
                    meta_path.to_str().unwrap_or_default(),
                ) {
                    let valid =
                        matches!(result.status, jocky_runtime::VerificationStatus::Verified);
                    let status_str = match &result.status {
                        jocky_runtime::VerificationStatus::Verified => "VALID".to_string(),
                        jocky_runtime::VerificationStatus::Tampered { reason } => {
                            format!("TAMPERED: {}", reason)
                        }
                        jocky_runtime::VerificationStatus::Missing { detail } => {
                            format!("MISSING: {}", detail)
                        }
                    };
                    let hash_str = result.calculated_hash.unwrap_or_else(|| {
                        use sha2::{Digest, Sha256};
                        let raw_bytes = std::fs::read(&path).unwrap_or_default();
                        format!("{:x}", Sha256::digest(&raw_bytes))
                    });
                    let merkle_root = metadata_val.as_ref().and_then(|m| {
                        m.get("merkle_root")
                            .and_then(|r| r.as_str())
                            .map(str::to_string)
                    });
                    verification_res = Some(VerificationResponse {
                        valid,
                        status: status_str,
                        sha256: hash_str,
                        merkle_root,
                        evidence_raw: evidence_raw.clone(),
                    });
                }
                break;
            }
        }
    }

    let cleanup_dir = output_dir.clone();
    std::thread::spawn(move || {
        let _ = std::fs::remove_dir_all(&cleanup_dir);
    });

    let verification_succeeded = verification_res
        .as_ref()
        .is_some_and(|verification| verification.valid);
    let success = output.status.success() && verification_succeeded;
    let stderr_str = if output.status.success() && !verification_succeeded {
        format!(
            "{}{}Investigation did not produce evidence that passed integrity verification.",
            stderr_str,
            if stderr_str.is_empty() { "" } else { "\n" }
        )
    } else {
        stderr_str
    };

    RunResponse {
        success,
        exit_code: if success { exit_code } else { exit_code.max(1) },
        stdout: stdout_str,
        stderr: stderr_str,
        duration_ms: start_time.elapsed().as_millis() as u64,
        evidence: evidence_val,
        metadata: metadata_val,
        verification: verification_res,
        artifact_name: Some(artifact_name),
    }
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
    pub content_type: String,
    pub release_date: String,
    pub requirements: String,
    pub download_url: String,
}
