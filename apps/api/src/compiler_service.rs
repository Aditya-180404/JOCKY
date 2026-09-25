use axum::{
    body::Body,
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use jockey_ast::Severity;
use jockey_backend::TargetSpec;
use jockey_ir::{TargetArch, TargetPlatform};
use jockey_lexer::Lexer;
use jockey_parser::Parser;
use jockey_semantic::SemanticAnalyzer;
use jockey_backend::{Backend, BackendKind};
use jockey_ir::BuildConfig;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    pub source: String,
    pub target: Option<String>,
}

/// Compile defensive JOCKEY source to a downloadable local artifact.
/// The hosted compiler intentionally supports Linux x86_64 only. Windows users download
/// the compiler and build on a Windows machine, where the runtime can inspect that host.
pub async fn compile_handler(Json(req): Json<CompileRequest>) -> Response {
    if req.source.len() > 256 * 1024 {
        return compiler_error(StatusCode::PAYLOAD_TOO_LARGE, "Source exceeds the 256 KiB compile limit");
    }

    let target = req.target.unwrap_or_else(|| "linux-x64".to_string());
    if target != "linux-x64" {
        return compiler_error(
            StatusCode::BAD_REQUEST,
            "Hosted compilation currently produces Linux x86_64 artifacts only. Download the local compiler for Windows builds.",
        );
    }

    let result = tokio::task::spawn_blocking(move || compile_linux_artifact(&req.source)).await;
    match result {
        Ok(Ok((filename, bytes))) => {
            let disposition = format!("attachment; filename=\"{}\"", filename);
            let mut response = Response::new(Body::from(bytes));
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            response.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&disposition).unwrap_or_else(|_| HeaderValue::from_static("attachment")));
            response.headers_mut().insert("x-jockey-target", HeaderValue::from_static("linux-x86_64"));
            response
        }
        Ok(Err(message)) => compiler_error(StatusCode::UNPROCESSABLE_ENTITY, &message),
        Err(error) => compiler_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Compile task failed: {}", error)),
    }
}

fn compile_linux_artifact(source: &str) -> Result<(String, Vec<u8>), String> {
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize().map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens);
    let (ast, diagnostics) = parser.parse_with_diagnostics();
    if !diagnostics.is_empty() {
        return Err(diagnostics.into_iter().map(|d| d.message).collect::<Vec<_>>().join("; "));
    }
    let ast = ast.ok_or_else(|| "Unable to parse investigation".to_string())?;
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, diagnostics) = analyzer.analyze_with_diagnostics(&ast);
    if !diagnostics.is_empty() {
        return Err(diagnostics.into_iter().map(|d| d.message).collect::<Vec<_>>().join("; "));
    }
    let ir = ir.ok_or_else(|| "Unable to analyze investigation".to_string())?;
    let output_dir = std::env::temp_dir().join(format!("jockey-public-build-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let config = BuildConfig::default();
    let backend_kind = if std::env::var("JOCKEY_BACKEND").unwrap_or_default() == "rust" {
        BackendKind::Rust
    } else {
        BackendKind::Llvm
    };
    let build = Backend::new_with_kind(config, backend_kind).generate(&ir, &output_dir);
    let filename = format!("{}-linux-x64", ir.name);
    let path = PathBuf::from(&output_dir).join(&filename);
    let bytes = build
        .map_err(|e| e.to_string())
        .and_then(|_| std::fs::read(&path).map_err(|e| e.to_string()));
    let _ = std::fs::remove_dir_all(&output_dir);
    bytes.map(|bytes| (filename, bytes))
}

fn compiler_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": "compile_failed", "message": message }))).into_response()
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
        if !target.is_supported() || target.platform != TargetPlatform::Linux {
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
