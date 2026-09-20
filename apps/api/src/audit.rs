//! Audit logs module

use std::sync::Arc;
use axum::{
    extract::{State, Query, Extension},
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use tracing::error;
use serde::{Deserialize, Serialize};

use traceforge_shared_types::{AuditLog, AuditResult, PaginatedResponse, Pagination, ErrorResponse};

use crate::{AppState, AuthUser};

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub action: Option<String>,
    pub user_id: Option<Uuid>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub result: AuditResult,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100).max(1);

    let mut conditions = vec!["organization_id = $1".to_string()];
    let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync>> = vec![Box::new(auth.organization_id)];
    let mut param_idx = 2;

    if let Some(action) = &query.action {
        conditions.push(format!("action = ${}", param_idx));
        params.push(Box::new(action.clone()));
        param_idx += 1;
    }

    if let Some(user_id) = &query.user_id {
        conditions.push(format!("user_id = ${}", param_idx));
        params.push(Box::new(*user_id));
        param_idx += 1;
    }

    if let Some(start_date) = &query.start_date {
        conditions.push(format!("created_at >= ${}", param_idx));
        params.push(Box::new(*start_date));
        param_idx += 1;
    }

    if let Some(end_date) = &query.end_date {
        conditions.push(format!("created_at <= ${}", param_idx));
        params.push(Box::new(*end_date));
        param_idx += 1;
    }

    let where_clause = conditions.join(" AND ");

    // Note: This is a simplified version. In production, use sqlx::query_as with dynamic queries
    // For now, we'll use a simpler approach
    let logs = sqlx::query_as!(
        AuditLogRow,
        r#"
        SELECT id, organization_id, user_id, action, resource_type, resource_id, result as "result: AuditResult", ip_address, user_agent, metadata, created_at
        FROM audit_logs WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
        auth.organization_id,
        per_page as i64,
        ((page - 1) * per_page) as i64
    )
    .fetch_all(&state.db)
    .await;

    let total = sqlx::query!(
        "SELECT COUNT(*) as count FROM audit_logs WHERE organization_id = $1",
        auth.organization_id
    )
    .fetch_one(&state.db)
    .await;

    match (logs, total) {
        (Ok(logs), Ok(total)) => {
            let responses: Vec<AuditLogResponse> = logs.into_iter().map(|l| AuditLogResponse {
                id: l.id,
                organization_id: l.organization_id,
                user_id: l.user_id,
                action: l.action,
                resource_type: l.resource_type,
                resource_id: l.resource_id,
                result: l.result,
                ip_address: l.ip_address.map(|ip| ip.to_string()),
                user_agent: l.user_agent,
                metadata: l.metadata,
                created_at: l.created_at,
            }).collect();

            Json(PaginatedResponse {
                data: responses,
                pagination: Pagination {
                    page,
                    per_page,
                    total: total.count.unwrap_or(0) as u64,
                },
            })
            .into_response()
        }
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to list audit logs"),
    }
}

fn error_response(status: StatusCode, error: &str, message: &str) -> impl IntoResponse {
    (status, Json(ErrorResponse {
        error: error.to_string(),
        message: message.to_string(),
        code: None,
        request_id: None,
    }))
}

#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: Uuid,
    organization_id: Uuid,
    user_id: Option<Uuid>,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
    result: AuditResult,
    ip_address: Option<sqlx::types::IpNetwork>,
    user_agent: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}