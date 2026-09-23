use aws_sdk_s3::primitives::ByteStream;
use axum::{
    extract::{Extension, Json, Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use traceforge_shared_types::ErrorResponse;

use crate::{AppState, AuthUser};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct UploadEvidenceRequest {
    pub investigation_id: Uuid,
    pub tool_version_id: Option<Uuid>,
    pub host_identifier: Option<String>,
    pub collection_time: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceResponse {
    pub id: Uuid,
    pub investigation_id: Uuid,
    pub tool_version_id: Option<Uuid>,
    pub host_identifier: Option<String>,
    pub collection_time: DateTime<Utc>,
    pub sha256_hash: String,
    pub size_bytes: i64,
    pub storage_path: String,
    pub metadata: Option<serde_json::Value>,
    pub merkle_proof: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub async fn upload_evidence(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // Parse multipart form
    let mut investigation_id: Option<Uuid> = None;
    let mut tool_version_id: Option<Uuid> = None;
    let mut host_identifier: Option<String> = None;
    let mut collection_time: Option<DateTime<Utc>> = None;
    let mut metadata: Option<serde_json::Value> = None;
    let mut file_data: Option<Vec<u8>> = None;
    let mut _filename: Option<String> = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "investigation_id" => {
                let text = field.text().await.unwrap_or_default();
                investigation_id = Uuid::parse_str(&text).ok();
            }
            "tool_version_id" => {
                let text = field.text().await.unwrap_or_default();
                tool_version_id = Uuid::parse_str(&text).ok();
            }
            "host_identifier" => {
                host_identifier = Some(field.text().await.unwrap_or_default());
            }
            "collection_time" => {
                let text = field.text().await.unwrap_or_default();
                collection_time = DateTime::parse_from_rfc3339(&text)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc));
            }
            "metadata" => {
                let text = field.text().await.unwrap_or_default();
                metadata = serde_json::from_str(&text).ok();
            }
            "file" => {
                _filename = field.file_name().map(|s| s.to_string());
                file_data = Some(field.bytes().await.unwrap_or_default().to_vec());
            }
            _ => {}
        }
    }

    let investigation_id = match investigation_id {
        Some(id) => id,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Missing field",
                "investigation_id is required",
            )
        }
    };

    let file_data = match file_data {
        Some(data) => data,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Missing file",
                "Evidence file is required",
            )
        }
    };

    // Verify investigation exists and belongs to organization
    let investigation = sqlx::query!(
        "SELECT id FROM investigations WHERE id = $1 AND organization_id = $2",
        investigation_id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    if investigation.is_err() || investigation.unwrap().is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            "Not found",
            "Investigation not found",
        );
    }

    // Calculate SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let sha256_hash = format!("{:x}", hasher.finalize());
    let size_bytes = file_data.len() as i64;

    // Generate storage path
    let storage_path = format!(
        "evidence/{}/{}/{}",
        auth.organization_id, investigation_id, sha256_hash
    );

    // Upload to S3
    let body = ByteStream::from(file_data);
    let upload_result = state
        .s3
        .put_object()
        .bucket(&state.bucket)
        .key(&storage_path)
        .body(body)
        .send()
        .await;

    if upload_result.is_err() {
        error!("Failed to upload evidence to S3");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Upload failed",
            "Failed to store evidence",
        );
    }

    // Store evidence record
    let evidence_id = Uuid::new_v4();
    let now = Utc::now();

    let result = sqlx::query!(
        r#"
        INSERT INTO evidence (id, investigation_id, tool_version_id, host_identifier, collection_time, sha256_hash, size_bytes, storage_path, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        evidence_id,
        investigation_id,
        tool_version_id,
        host_identifier,
        collection_time.unwrap_or(now),
        sha256_hash,
        size_bytes,
        storage_path,
        metadata,
        now
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!(
                "Evidence uploaded: {} for investigation {}",
                evidence_id, investigation_id
            );
            Json(EvidenceResponse {
                id: evidence_id,
                investigation_id,
                tool_version_id,
                host_identifier,
                collection_time: collection_time.unwrap_or(now),
                sha256_hash,
                size_bytes,
                storage_path,
                metadata,
                merkle_proof: None,
                created_at: now,
            })
            .into_response()
        }
        Err(e) => {
            error!("Failed to store evidence record: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error",
                "Failed to store evidence record",
            )
        }
    }
}

pub async fn get_evidence(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let evidence = sqlx::query_as!(
        EvidenceRow,
        r#"
        SELECT e.* FROM evidence e
        JOIN investigations i ON e.investigation_id = i.id
        WHERE e.id = $1 AND i.organization_id = $2
        "#,
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    match evidence {
        Ok(Some(e)) => {
            // Generate presigned URL for download
            let presigned = state
                .s3
                .get_object()
                .bucket(&state.bucket)
                .key(&e.storage_path)
                .presigned(
                    aws_sdk_s3::presigning::PresigningConfig::expires_in(
                        std::time::Duration::from_secs(3600),
                    )
                    .unwrap(),
                )
                .await;

            let download_url = presigned.ok().map(|u| u.uri().to_string());

            Json(serde_json::json!({
                "evidence": EvidenceResponse {
                    id: e.id,
                    investigation_id: e.investigation_id,
                    tool_version_id: e.tool_version_id,
                    host_identifier: e.host_identifier,
                    collection_time: e.collection_time,
                    sha256_hash: e.sha256_hash,
                    size_bytes: e.size_bytes,
                    storage_path: e.storage_path,
                    metadata: e.metadata,
                    merkle_proof: e.merkle_proof,
                    created_at: e.created_at,
                },
                "download_url": download_url
            }))
            .into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Not found", "Evidence not found"),
        Err(e) => {
            error!("Database error: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error",
                "Failed to get evidence",
            )
        }
    }
}

pub async fn verify_evidence(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let evidence = sqlx::query_as!(
        EvidenceRow,
        r#"
        SELECT e.* FROM evidence e
        JOIN investigations i ON e.investigation_id = i.id
        WHERE e.id = $1 AND i.organization_id = $2
        "#,
        id,
        auth.organization_id
    )
    .fetch_optional(&state.db)
    .await;

    let evidence = match evidence {
        Ok(Some(e)) => e,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "Not found", "Evidence not found")
        }
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error",
                "Failed to get evidence",
            );
        }
    };

    // Download evidence from S3 and verify hash
    let obj = state
        .s3
        .get_object()
        .bucket(&state.bucket)
        .key(&evidence.storage_path)
        .send()
        .await;

    let data = match obj {
        Ok(o) => match o.body.collect().await {
            Ok(body) => body.into_bytes(),
            Err(e) => {
                error!("Failed to read evidence from S3: {}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Verification failed",
                    "Failed to read evidence",
                );
            }
        },
        Err(e) => {
            error!("Failed to get evidence from S3: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed",
                "Failed to get evidence",
            );
        }
    };

    // Calculate hash
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let calculated_hash = format!("{:x}", hasher.finalize());

    let is_valid = calculated_hash == evidence.sha256_hash;

    // Log verification
    log_audit(
        &state.db,
        auth.user_id,
        auth.organization_id,
        "VERIFY_EVIDENCE",
        "evidence",
        Some(id),
        is_valid,
    )
    .await;

    Json(serde_json::json!({
        "valid": is_valid,
        "expected_hash": evidence.sha256_hash,
        "calculated_hash": calculated_hash,
        "size_bytes": data.len()
    }))
    .into_response()
}

async fn log_audit(
    db: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    success: bool,
) {
    sqlx::query!(
        r#"
        INSERT INTO audit_logs (id, organization_id, user_id, action, resource_type, resource_id, result, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        Uuid::new_v4(),
        org_id,
        user_id,
        action,
        resource_type,
        resource_id,
        if success { "success" } else { "failure" },
        Utc::now()
    )
    .execute(db)
    .await
    .ok();
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            message: message.to_string(),
            code: None,
            request_id: None,
        }),
    )
        .into_response()
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
