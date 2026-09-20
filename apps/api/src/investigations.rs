//! Investigations module

use std::sync::Arc;
use axum::{
    extract::{State, Path, Query, Json, Extension},
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use validator::Validate;
use tracing::{info, error};
use serde::{Deserialize, Serialize};

use traceforge_shared_types::{Investigation, InvestigationStatus, PaginatedResponse, Pagination, ErrorResponse};

use crate::{AppState, AuthUser};

#[derive(Debug, Deserialize, Validate)]
pub struct CreateInvestigationRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub project_id: Option<Uuid>,
    pub tool_version_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct InvestigationResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub tool_version_id: Option<Uuid>,
    pub status: InvestigationStatus,
    pub created_by: Uuid,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_investigations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Query(pagination): Query<Pagination>,
) -> impl IntoResponse {
    let investigations = sqlx::query_as!(
        InvestigationRow,
        r#"
        SELECT id, organization_id, project_id, name, description, tool_version_id, status as "status: InvestigationStatus", created_by, started_at, completed_at, created_at, updated_at
        FROM investigations WHERE organization_id = $1
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
        "SELECT COUNT(*) as count FROM investigations WHERE organization_id = $1",
        auth.organization_id
    )
    .fetch_one(&state.db)
    .await;

    match (investigations, total) {
        (Ok(investigations), Ok(total)) => {
            let responses: Vec<InvestigationResponse> = investigations.into_iter().map(|i| InvestigationResponse {
                id: i.id,
                name: i.name,
                description: i.description,
                tool_version_id: i.tool_version_id,
                status: i.status,
                created_by: i.created_by,
                started_at: i.started_at,
                completed_at: i.completed_at,
                created_at: i.created_at,
                updated_at: i.updated_at,
            }).collect();

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
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to list investigations"),
    }
}

pub async fn create_investigation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Json(payload): Json<CreateInvestigationRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return error_response(StatusCode::BAD_REQUEST, "Validation error", &e.to_string());
    }

    // Verify project exists if provided
    if let Some(project_id) = payload.project_id {
        let project = sqlx::query!(
            "SELECT id FROM projects WHERE id = $1 AND organization_id = $2",
            project_id,
            auth.organization_id
        )
        .fetch_optional(&state.db)
        .await;

        if project.is_err() || project.unwrap().is_none() {
            return error_response(StatusCode::BAD_REQUEST, "Invalid project", "Project not found");
        }
    }

    // Verify tool version exists if provided
    if let Some(tool_version_id) = payload.tool_version_id {
        let version = sqlx::query!(
            "SELECT id FROM tool_versions tv JOIN tools t ON tv.tool_id = t.id WHERE tv.id = $1 AND t.organization_id = $2",
            tool_version_id,
            auth.organization_id
        )
        .fetch_optional(&state.db)
        .await;

        if version.is_err() || version.unwrap().is_none() {
            return error_response(StatusCode::BAD_REQUEST, "Invalid tool version", "Tool version not found");
        }
    }

    let investigation_id = Uuid::new_v4();
    let now = Utc::now();

    let result = sqlx::query!(
        r#"
        INSERT INTO investigations (id, organization_id, project_id, name, description, tool_version_id, status, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9)
        "#,
        investigation_id,
        auth.organization_id,
        payload.project_id,
        payload.name,
        payload.description,
        payload.tool_version_id,
        auth.user_id,
        now,
        now
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!("Investigation created: {} by user {}", investigation_id, auth.user_id);
            Json(InvestigationResponse {
                id: investigation_id,
                name: payload.name,
                description: payload.description,
                tool_version_id: payload.tool_version_id,
                status: InvestigationStatus::Draft,
                created_by: auth.user_id,
                started_at: None,
                completed_at: None,
                created_at: now,
                updated_at: now,
            })
            .into_response()
        }
        Err(e) => {
            error!("Failed to create investigation: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create investigation")
        }
    }
}

pub async fn get_investigation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let investigation = sqlx::query_as!(
        InvestigationRow,
        r#"
        SELECT id, organization_id, project_id, name, description, tool_version_id, status as "status: InvestigationStatus", created_by, started_at, completed_at, created_at, updated_at
        FROM investigations WHERE id = $1 AND organization_id = $2
        "#,
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    match investigation {
        Ok(Some(i)) => {
            // Get associated evidence
            let evidence = sqlx::query_as!(
                EvidenceRow,
                "SELECT * FROM evidence WHERE investigation_id = $1 ORDER BY collection_time DESC",
                id
            )
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

            Json(serde_json::json!({
                "investigation": InvestigationResponse {
                    id: i.id,
                    name: i.name,
                    description: i.description,
                    tool_version_id: i.tool_version_id,
                    status: i.status,
                    created_by: i.created_by,
                    started_at: i.started_at,
                    completed_at: i.completed_at,
                    created_at: i.created_at,
                    updated_at: i.updated_at,
                },
                "evidence": evidence.into_iter().map(|e| EvidenceSummary {
                    id: e.id,
                    host_identifier: e.host_identifier,
                    collection_time: e.collection_time,
                    sha256_hash: e.sha256_hash,
                    size_bytes: e.size_bytes,
                }).collect::<Vec<_>>()
            }))
            .into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Not found", "Investigation not found"),
        Err(e) => {
            error!("Database error: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get investigation")
        }
    }
}

pub async fn run_investigation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let investigation = sqlx::query_as!(
        InvestigationRow,
        r#"
        SELECT id, organization_id, project_id, name, description, tool_version_id, status as "status: InvestigationStatus", created_by, started_at, completed_at, created_at, updated_at
        FROM investigations WHERE id = $1 AND organization_id = $2
        "#,
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    let investigation = match investigation {
        Ok(Some(i)) => i,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "Not found", "Investigation not found"),
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to get investigation");
        }
    };

    if investigation.tool_version_id.is_none() {
        return error_response(StatusCode::BAD_REQUEST, "No tool", "Investigation has no associated tool version");
    }

    // Update status to running
    let now = Utc::now();
    sqlx::query!(
        "UPDATE investigations SET status = 'running', started_at = $1 WHERE id = $2",
        now,
        id
    )
    .execute(&state.db)
    .await
    .ok();

    // In a real implementation, this would trigger the tool execution on an agent
    // For MVP, we'll return a message indicating the investigation was started
    info!("Investigation started: {}", id);

    Json(serde_json::json!({
        "message": "Investigation started",
        "investigation_id": id,
        "status": "running",
        "note": "In MVP, evidence collection is manual. Download the tool artifact and run it on the target machine, then upload evidence."
    }))
    .into_response()
}

#[derive(Debug, Serialize)]
struct EvidenceSummary {
    id: Uuid,
    host_identifier: Option<String>,
    collection_time: DateTime<Utc>,
    sha256_hash: String,
    size_bytes: i64,
}

#[derive(sqlx::FromRow)]
struct InvestigationRow {
    id: Uuid,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    name: String,
    description: Option<String>,
    tool_version_id: Option<Uuid>,
    status: InvestigationStatus,
    created_by: Uuid,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct EvidenceRow {
    id: Uuid,
    investigation_id: Uuid,
    tool_version_id: Option<Uuid>,
    host_identifier: Option<String>,
    collection_time: DateTime<Utc>,
    sha256_hash: String,
    size_bytes: i64,
    storage_path: String,
    metadata: Option<serde_json::Value>,
    merkle_proof: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

fn error_response(status: StatusCode, error: &str, message: &str) -> impl IntoResponse {
    (status, Json(ErrorResponse {
        error: error.to_string(),
        message: message.to_string(),
        code: None,
        request_id: None,
    }))
}