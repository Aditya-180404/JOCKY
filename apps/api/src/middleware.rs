//! Middleware module

use std::sync::Arc;
use axum::{
    extract::{State, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::decode;
use uuid::Uuid;
use tracing::warn;

use traceforge_shared_types::Role;

use crate::auth::Claims;

#[derive(Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub role: Role,
    pub token: String,
    pub db: Arc<sqlx::PgPool>,
}

pub async fn auth_middleware(
    State(state): State<Arc<crate::AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract authorization header
    let auth_header = request.headers().get("authorization");
    let token = match auth_header.and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_string(),
        _ => {
            return (StatusCode::UNAUTHORIZED, "Missing or invalid authorization header").into_response();
        }
    };

    // Decode and validate token
    let claims = match decode::<Claims>(&token, &state.auth.decoding_key, &state.auth.validation) {
        Ok(token) => token.claims,
        Err(e) => {
            warn!("Invalid token: {}", e);
            return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
        }
    };

    if claims.token_type != "access" {
        return (StatusCode::UNAUTHORIZED, "Invalid token type").into_response();
    }

    // Verify session exists
    let token_hash = sha256_hash(&token);
    let session = sqlx::query!(
        "SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > $2",
        token_hash,
        chrono::Utc::now()
    )
    .fetch_optional(&state.db)
    .await;

    if session.is_err() || session.unwrap().is_none() {
        return (StatusCode::UNAUTHORIZED, "Session expired or invalid").into_response();
    }

    // Parse user ID and organization ID
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    };

    let organization_id = match Uuid::parse_str(&claims.org) {
        Ok(id) => id,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    };

    let role = match claims.role.as_str() {
        "ADMIN" => Role::Admin,
        "INVESTIGATOR" => Role::Investigator,
        "DEVELOPER" => Role::Developer,
        _ => Role::Viewer,
    };

    // Update session last accessed
    sqlx::query!(
        "UPDATE sessions SET last_accessed_at = $1 WHERE token_hash = $2",
        chrono::Utc::now(),
        token_hash
    )
    .execute(&state.db)
    .await
    .ok();

    // Add auth user to request extensions
    let auth_user = AuthUser {
        user_id,
        organization_id,
        role,
        token,
        db: Arc::new(state.db.clone()),
    };

    request.extensions_mut().insert(auth_user);
    next.run(request).await
}

pub(crate) fn sha256_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}