//! Tools module

use std::sync::Arc;
use axum::{
    extract::{State, Path, Query, Json, Extension, Multipart},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use validator::Validate;
use tracing::{info, error};
use serde::{Deserialize, Serialize};
use redis::AsyncCommands;

use traceforge_shared_types::{Tool, ToolVersion, Build, BuildStatus, PaginatedResponse, Pagination, ErrorResponse};

use crate::{AppState, AuthUser};
use crate::middleware::sha256_hash;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateToolRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateToolVersionRequest {
    #[validate(length(min = 1))]
    pub version: String,
    #[validate(length(min = 1))]
    pub source: String,
    pub target_platform: String,
    pub target_arch: String,
}

#[derive(Debug, Deserialize)]
pub struct BuildToolRequest {
    pub target_platform: Option<String>,
    pub target_arch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ToolResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub author_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub versions: Vec<ToolVersionResponse>,
}

#[derive(Debug, Serialize)]
pub struct ToolVersionResponse {
    pub id: Uuid,
    pub version: String,
    pub source_hash: String,
    pub compiler_version: String,
    pub target_platform: String,
    pub target_arch: String,
    pub capabilities: Vec<String>,
    pub artifact_hash: Option<String>,
    pub artifact_size: Option<i64>,
    pub is_published: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_tools(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let tools = sqlx::query_as!(
        ToolRow,
        r#"
        SELECT id, organization_id, project_id, name, description, author_id, created_at, updated_at
        FROM tools WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
        auth.organization_id,
        pagination.per_page as i64,
        ((pagination.page - 1) * pagination.per_page) as i64
    )
    .fetch_all(&state.db)
    .await;

    let total = sqlx::query!(
        "SELECT COUNT(*) as count FROM tools WHERE organization_id = $1",
        auth.organization_id
    )
    .fetch_one(&state.db)
    .await;

    match (tools, total) {
        (Ok(tools), Ok(total)) => {
            let mut responses = Vec::new();
            for tool in tools {
                let versions = sqlx::query_as!(
                    ToolVersionRow,
                    "SELECT * FROM tool_versions WHERE tool_id = $1 ORDER BY created_at DESC",
                    tool.id
                )
                .fetch_all(&state.db)
                .await
                .unwrap_or_default();

                responses.push(ToolResponse {
                    id: tool.id,
                    name: tool.name,
                    description: tool.description,
                    author_id: tool.author_id,
                    created_at: tool.created_at,
                    updated_at: tool.updated_at,
                    versions: versions.into_iter().map(|v| ToolVersionResponse {
                        id: v.id,
                        version: v.version,
                        source_hash: v.source_hash,
                        compiler_version: v.compiler_version,
                        target_platform: v.target_platform,
                        target_arch: v.target_arch,
                        capabilities: v.capabilities,
                        artifact_hash: v.artifact_hash,
                        artifact_size: v.artifact_size,
                        is_published: v.is_published,
                        published_at: v.published_at,
                        created_at: v.created_at,
                    }).collect(),
                });
            }

            Json(PaginatedResponse {
                data: responses,
                pagination: Pagination {
                    page: pagination.page,
                    per_page: pagination.per_page,
                    total: total.count.unwrap_or(0) as u64,
                },
            })
            .into_response()
        }
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to list tools"),
    }
}

pub async fn create_tool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(payload): Json<CreateToolRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return error_response(StatusCode::BAD_REQUEST, "Validation error", &e.to_string());
    }

    let tool_id = Uuid::new_v4();
    let now = Utc::now();

    let result = sqlx::query!(
        r#"
        INSERT INTO tools (id, organization_id, project_id, name, description, author_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        tool_id,
        auth.organization_id,
        payload.project_id,
        payload.name,
        payload.description,
        auth.user_id,
        now,
        now
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!("Tool created: {} by user {}", tool_id, auth.user_id);
            Json(ToolResponse {
                id: tool_id,
                name: payload.name,
                description: payload.description,
                author_id: auth.user_id,
                created_at: now,
                updated_at: now,
                versions: vec![],
            })
            .into_response()
        }
        Err(e) => {
            error!("Failed to create tool: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create tool")
        }
    }
}

pub async fn get_tool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let tool = sqlx::query_as!(
        ToolRow,
        "SELECT * FROM tools WHERE id = $1 AND organization_id = $2",
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    match tool {
        Ok(Some(tool)) => {
            let versions = sqlx::query_as!(
                ToolVersionRow,
                "SELECT * FROM tool_versions WHERE tool_id = $1 ORDER BY created_at DESC",
                tool.id
            )
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

            Json(ToolResponse {
                id: tool.id,
                name: tool.name,
                description: tool.description,
                author_id: tool.author_id,
                created_at: tool.created_at,
                updated_at: tool.updated_at,
                versions: versions.into_iter().map(|v| ToolVersionResponse {
                    id: v.id,
                    version: v.version,
                    source_hash: v.source_hash,
                    compiler_version: v.compiler_version,
                    target_platform: v.target_platform,
                    target_arch: v.target_arch,
                    capabilities: v.capabilities,
                    artifact_hash: v.artifact_hash,
                    artifact_size: v.artifact_size,
                    is_published: v.is_published,
                    published_at: v.published_at,
                    created_at: v.created_at,
                }).collect(),
            })
            .into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Not found", "Tool not found"),
        Err(e) => {
            error!("Database error: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get tool")
        }
    }
}

pub async fn create_tool_version(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateToolVersionRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return error_response(StatusCode::BAD_REQUEST, "Validation error", &e.to_string());
    }

    // Verify tool exists and belongs to organization
    let tool = sqlx::query!(
        "SELECT id FROM tools WHERE id = $1 AND organization_id = $2",
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    if tool.is_err() || tool.unwrap().is_none() {
        return error_response(StatusCode::NOT_FOUND, "Not found", "Tool not found");
    }

    // Validate source code
    let mut lexer = traceforge_lexer::Lexer::new(&payload.source);
    let tokens = match lexer.tokenize() {
        Ok(t) => t,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "Invalid source", &e.to_string()),
    };

    let mut parser = traceforge_parser::Parser::new(tokens);
    let (ast, diags) = parser.parse_with_diagnostics();

    if !diags.is_empty() {
        let mut msg = String::new();
        for d in diags {
            msg.push_str(&format!("{} at {}; ", d.message, d.span.map(|s| s.to_string()).unwrap_or_default()));
        }
        return error_response(StatusCode::BAD_REQUEST, "Parse error", &msg);
    }

    let ast = match ast {
        Some(a) => a,
        None => return error_response(StatusCode::BAD_REQUEST, "Parse error", "Failed to parse source"),
    };

    let mut analyzer = traceforge_semantic::SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

    if !sem_diags.is_empty() {
        let mut msg = String::new();
        for d in sem_diags {
            msg.push_str(&format!("{}; ", d.message));
        }
        return error_response(StatusCode::BAD_REQUEST, "Semantic error", &msg);
    }

    let ir = match ir {
        Some(i) => i,
        None => return error_response(StatusCode::BAD_REQUEST, "Semantic error", "Failed to analyze source"),
    };

    let source_hash = sha256_hash(&payload.source);
    let compiler_version = env!("CARGO_PKG_VERSION").to_string();
    let compiler_hash = calculate_compiler_hash().unwrap_or_default();

    let version_id = Uuid::new_v4();
    let now = Utc::now();

    let result = sqlx::query!(
        r#"
        INSERT INTO tool_versions (id, tool_id, version, source_hash, compiler_version, compiler_hash, target_platform, target_arch, capabilities, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        version_id,
        id,
        payload.version,
        source_hash,
        compiler_version,
        compiler_hash,
        payload.target_platform,
        payload.target_arch,
        &ir.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        now
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!("Tool version created: {} for tool {}", version_id, id);
            Json(serde_json::json!({
                "id": version_id,
                "version": payload.version,
                "source_hash": source_hash,
                "compiler_version": compiler_version,
                "target_platform": payload.target_platform,
                "target_arch": payload.target_arch,
                "capabilities": ir.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "created_at": now
            }))
            .into_response()
        }
        Err(e) => {
            if e.to_string().contains("unique constraint") {
                error_response(StatusCode::CONFLICT, "Version exists", "This version already exists")
            } else {
                error!("Failed to create tool version: {}", e);
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create tool version")
            }
        }
    }
}

pub async fn build_tool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    Json(payload): Json<BuildToolRequest>,
) -> impl IntoResponse {
    // Get latest unpublished version or create build for specific version
    let version = sqlx::query_as!(
        ToolVersionRow,
        r#"
        SELECT * FROM tool_versions WHERE tool_id = $1 AND is_published = false
        ORDER BY created_at DESC LIMIT 1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await;

    let version = match version {
        Ok(Some(v)) => v,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "No version to build", "No unpublished version found"),
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get tool version");
        }
    };

    // Create build record
    let build_id = Uuid::new_v4();
    let now = Utc::now();

    if let Err(e) = sqlx::query!(
        "INSERT INTO builds (id, tool_version_id, status, started_at, created_at) VALUES ($1, $2, $3, $4, $5)",
        build_id,
        version.id,
        BuildStatus::Pending as i32,
        now,
        now
    )
    .execute(&state.db)
    .await {
        error!("Failed to create build: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create build");
    }

    // Queue build job
    let job = BuildJob {
        build_id,
        tool_version_id: version.id,
        tool_name: format!("{}-{}-{}", version.id, version.target_platform, version.target_arch),
        source: get_tool_source(&state.db, version.id).await.unwrap_or_default(),
        target_platform: payload.target_platform.unwrap_or(version.target_platform),
        target_arch: payload.target_arch.unwrap_or(version.target_arch),
    };

    let mut redis = match state.redis.get_async_connection().await {
        Ok(redis) => redis,
        Err(e) => {
            error!("Redis connection error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Queue error", "Failed to connect to queue");
        }
    };

    if let Err(e) = redis.rpush("build_queue", serde_json::to_string(&job).unwrap()).await {
        error!("Failed to queue build: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Queue error", "Failed to queue build");
    }

    // Update build status to running
    if let Err(e) = sqlx::query!(
        "UPDATE builds SET status = $1 WHERE id = $2",
        BuildStatus::Running as i32,
        build_id
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to update build status: {}", e);
    }

    info!("Build queued: {} for tool version {}", build_id, version.id);

    Json(serde_json::json!({
        "build_id": build_id,
        "status": "queued",
        "message": "Build queued successfully"
    }))
    .into_response()
}

pub async fn publish_tool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Check for successful build
    let version = sqlx::query_as!(
        ToolVersionRow,
        r#"
        SELECT tv.* FROM tool_versions tv
        JOIN builds b ON tv.id = b.tool_version_id
        WHERE tv.tool_id = $1 AND tv.is_published = false AND b.status = $2
        ORDER BY tv.created_at DESC LIMIT 1
        "#,
        id,
        BuildStatus::Success as i32
    )
    .fetch_optional(&state.db)
    .await;

    let version = match version {
        Ok(Some(v)) => v,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "Nothing to publish", "No successful build found"),
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get tool version");
        }
    };

    let now = Utc::now();
    if let Err(e) = sqlx::query!(
        "UPDATE tool_versions SET is_published = true, published_at = $1 WHERE id = $2",
        now,
        version.id
    )
    .execute(&state.db)
    .await {
        error!("Failed to publish tool: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to publish tool");
    }

    info!("Tool published: {} version {}", id, version.version);

    Json(serde_json::json!({
        "message": "Tool published successfully",
        "version_id": version.id,
        "version": version.version
    }))
    .into_response()
}

pub async fn download_tool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let version = sqlx::query_as!(
        ToolVersionRow,
        "SELECT * FROM tool_versions WHERE id = $1 AND is_published = true",
        id
    )
    .fetch_optional(&state.db)
    .await;

    let version = match version {
        Ok(Some(v)) => v,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "Not found", "Published tool version not found"),
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get tool version");
        }
    };

    let artifact_path = match version.artifact_path {
        Some(p) => p,
        None => return error_response(StatusCode::NOT_FOUND, "Not found", "Artifact not available"),
    };

    // Generate presigned URL for download
    let presigned = state.s3
        .get_object()
        .bucket(&state.bucket)
        .key(&artifact_path)
        .presigned(aws_sdk_s3::presigning::PresigningConfig::expires_in(std::time::Duration::from_secs(3600)).unwrap())
        .await;

    match presigned {
        Ok(url) => {
            Json(serde_json::json!({
                "download_url": url.uri().to_string(),
                "expires_in": 3600,
                "artifact_hash": version.artifact_hash,
                "artifact_size": version.artifact_size
            }))
            .into_response()
        }
        Err(e) => {
            error!("Failed to generate presigned URL: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Download error", "Failed to generate download URL")
        }
    }
}

async fn get_tool_source(db: &PgPool, version_id: Uuid) -> anyhow::Result<String> {
    // In a real implementation, this would fetch the source from storage
    // For now, we'll store it in the database or object storage
    Ok(String::new())
}

fn calculate_compiler_hash() -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let exe_path = std::env::current_exe()?;
    let mut file = std::fs::File::open(exe_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(ErrorResponse {
        error: error.to_string(),
        message: message.to_string(),
        code: None,
        request_id: None,
    })).into_response()
}

#[derive(sqlx::FromRow)]
struct ToolRow {
    id: Uuid,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    name: String,
    description: Option<String>,
    author_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ToolVersionRow {
    id: Uuid,
    tool_id: Uuid,
    version: String,
    source_hash: String,
    compiler_version: String,
    compiler_hash: String,
    target_platform: String,
    target_arch: String,
    capabilities: Vec<String>,
    artifact_path: Option<String>,
    artifact_hash: Option<String>,
    artifact_size: Option<i64>,
    changelog: Option<String>,
    is_published: bool,
    published_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BuildJob {
    build_id: Uuid,
    tool_version_id: Uuid,
    tool_name: String,
    source: String,
    target_platform: String,
    target_arch: String,
}