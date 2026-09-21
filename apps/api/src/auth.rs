//! Authentication module

use std::sync::Arc;
use axum::{
    extract::{State, Json, Extension},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher, password_hash::SaltString};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use validator::Validate;
use tracing::{info, warn, error};

use traceforge_shared_types::{User, Role, Session, ErrorResponse};
use crate::{AppState, AuthUser};

#[derive(Clone)]
pub struct AuthState {
    encoding_key: EncodingKey,
    pub(crate) decoding_key: DecodingKey,
    pub(crate) validation: Validation,
}

impl AuthState {
    pub fn new(secret: String) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation: Validation::new(Algorithm::HS256),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // User ID
    pub org: String,        // Organization ID
    pub role: String,       // Role
    pub exp: i64,           // Expiration
    pub iat: i64,           // Issued at
    pub token_type: String, // "access" or "refresh"
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    pub full_name: Option<String>,
    pub organization_name: String,
    pub organization_slug: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: Option<String>,
    pub role: Role,
    pub organization_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: UserResponse,
    pub organization: OrganizationResponse,
}

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return error_response(StatusCode::BAD_REQUEST, "Validation error", &e.to_string());
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => { 
            error!("Database transaction error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to start transaction");
        }
    };

    // Check if organization exists
    let org = sqlx::query_as!(
        OrganizationRow,
        "SELECT id, name, slug, description, created_at, updated_at FROM organizations WHERE slug = $1",
        payload.organization_slug
    )
    .fetch_optional(&mut *tx)
    .await;

    let org_id = match org {
        Ok(Some(org)) => org.id,
        Ok(None) => {
            // Create organization
            let org_id = Uuid::new_v4();
            if let Err(e) = sqlx::query!(
                "INSERT INTO organizations (id, name, slug, description) VALUES ($1, $2, $3, $4)",
                org_id,
                payload.organization_name,
                payload.organization_slug,
                None::<String>
            )
            .execute(&mut *tx)
            .await {
                error!("Failed to create organization: {}", e);
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create organization");
            }
            org_id
        }
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to check organization");
        }
    };

    // Check if user exists
    let existing = sqlx::query!(
        "SELECT id FROM users WHERE email = $1 AND organization_id = $2",
        payload.email,
        org_id
    )
    .fetch_optional(&mut *tx)
    .await;

    if existing.is_ok_and(|u| u.is_some()) {
        return error_response(StatusCode::CONFLICT, "User exists", "User with this email already exists in organization");
    }

    // Hash password
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            error!("Password hashing error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "Failed to hash password");
        }
    };

    // Create user
    let user_id = Uuid::new_v4();
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO users (id, organization_id, email, password_hash, full_name, role)
        VALUES ($1, $2, $3, $4, $5, 'INVESTIGATOR')
        "#,
        user_id,
        org_id,
        payload.email,
        password_hash,
        payload.full_name
    )
    .execute(&mut *tx)
    .await {
        error!("Failed to create user: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create user");
    }

    // Create default project
    let project_id = Uuid::new_v4();
    if let Err(e) = sqlx::query!(
        "INSERT INTO projects (id, organization_id, name, description, created_by) VALUES ($1, $2, $3, $4, $5)",
        project_id,
        org_id,
        "Default Project",
        "Default project for investigations",
        user_id
    )
    .execute(&mut *tx)
    .await {
        error!("Failed to create default project: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create default project");
    }

    if let Err(e) = tx.commit().await {
        error!("Transaction commit error: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to commit transaction");
    }

    // Generate tokens
    let tokens = match generate_tokens(user_id, org_id, Role::Investigator, &state.auth) {
        Ok(tokens) => tokens,
        Err(e) => {
            error!("Token generation error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "Failed to generate tokens");
        }
    };

    info!("User registered: {} (org: {})", payload.email, org_id);

    Json(AuthResponse {
        access_token: tokens.0,
        refresh_token: tokens.1,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        user: UserResponse {
            id: user_id,
            email: payload.email,
            full_name: payload.full_name,
            role: Role::Investigator,
            organization_id: org_id,
        },
    })
    .into_response()
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return error_response(StatusCode::BAD_REQUEST, "Validation error", &e.to_string());
    }

    // Find user
    let user = sqlx::query_as!(
        UserRow,
        r#"
        SELECT id, organization_id, email, password_hash, full_name, role as "role: Role", is_active, last_login_at, created_at, updated_at
        FROM users WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            warn!("Login attempt for non-existent user: {}", payload.email);
            return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials", "Invalid email or password");
        }
        Err(e) => {
            error!("Database error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to find user");
        }
    };

    if !user.is_active {
        return error_response(StatusCode::FORBIDDEN, "Account disabled", "This account has been disabled");
    }

    // Verify password
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Password hash parse error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "Invalid password hash");
        }
    };

    let argon2 = Argon2::default();
    if argon2.verify_password(payload.password.as_bytes(), &parsed_hash).is_err() {
        warn!("Invalid password for user: {}", payload.email);
        return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials", "Invalid email or password");
    }

    // Generate tokens
    let role = user.role;
    let tokens = match generate_tokens(user.id, user.organization_id, role, &state.auth) {
        Ok(tokens) => tokens,
        Err(e) => {
            error!("Token generation error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "Failed to generate tokens");
        }
    };

    // Create session
    let access_token_hash = sha256_hash(&tokens.0);
    let session_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(1);
    if let Err(e) = sqlx::query!(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        session_id,
        user.id,
        access_token_hash,
        expires_at
    )
    .execute(&state.db)
    .await {
        error!("Failed to create session: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error", "Failed to create session");
    }

    // Update last login
    sqlx::query!("UPDATE users SET last_login_at = $1 WHERE id = $2", Utc::now(), user.id)
        .execute(&state.db)
        .await
        .ok();

    info!("User logged in: {}", payload.email);

    Json(AuthResponse {
        access_token: tokens.0,
        refresh_token: tokens.1,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        user: UserResponse {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            role,
            organization_id: user.organization_id,
        },
    })
    .into_response()
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Delete session
    let access_token_hash = sha256_hash(&auth_user.token);
    sqlx::query!("DELETE FROM sessions WHERE token_hash = $1", access_token_hash)
        .execute(&state.db)
        .await
        .ok();

    info!("User logged out: {}", auth_user.user_id);

    Json(serde_json::json!({ "message": "Logged out successfully" })).into_response()
}

pub async fn me(
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    let user = sqlx::query_as!(
        UserRow,
        r#"
        SELECT id, organization_id, email, password_hash, full_name, role as "role: Role", is_active, last_login_at, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        auth_user.user_id
    )
    .fetch_one(&auth_user.db)
    .await;

    let org = sqlx::query_as!(
        OrganizationRow,
        "SELECT id, name, slug, description, created_at, updated_at FROM organizations WHERE id = $1",
        auth_user.organization_id
    )
    .fetch_one(&auth_user.db)
    .await;

    match (user, org) {
        (Ok(user), Ok(org)) => {
            Json(MeResponse {
                user: UserResponse {
                    id: user.id,
                    email: user.email,
                    full_name: user.full_name,
                    role: user.role,
                    organization_id: user.organization_id,
                },
                organization: OrganizationResponse {
                    id: org.id,
                    name: org.name,
                    slug: org.slug,
                },
            })
            .into_response()
        }
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Not found", "User or organization not found"),
    }
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> impl IntoResponse {
    let claims = match decode::<Claims>(&payload.refresh_token, &state.auth.decoding_key, &state.auth.validation) {
        Ok(token) => token.claims,
        Err(e) => {
            warn!("Invalid refresh token: {}", e);
            return error_response(StatusCode::UNAUTHORIZED, "Invalid token", "Invalid or expired refresh token");
        }
    };

    if claims.token_type != "refresh" {
        return error_response(StatusCode::UNAUTHORIZED, "Invalid token", "Token is not a refresh token");
    }

    // Verify user still exists and is active
    let user = sqlx::query_as!(
        UserRow,
        r#"
        SELECT id, organization_id, email, password_hash, full_name, role as "role: Role", is_active, last_login_at, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        Uuid::parse_str(&claims.sub).unwrap()
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        _ => return error_response(StatusCode::UNAUTHORIZED, "Invalid token", "User not found"),
    };

    if !user.is_active {
        return error_response(StatusCode::FORBIDDEN, "Account disabled", "This account has been disabled");
    }

    let role = user.role;
    let tokens = match generate_tokens(user.id, user.organization_id, role, &state.auth) {
        Ok(tokens) => tokens,
        Err(e) => {
            error!("Token generation error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "Failed to generate tokens");
        }
    };

    // Update session
    let access_token_hash = sha256_hash(&tokens.0);
    sqlx::query!(
        "UPDATE sessions SET token_hash = $1, last_accessed_at = $2 WHERE user_id = $3",
        access_token_hash,
        Utc::now(),
        user.id
    )
    .execute(&state.db)
    .await
    .ok();

    Json(AuthResponse {
        access_token: tokens.0,
        refresh_token: tokens.1,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        user: UserResponse {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            role,
            organization_id: user.organization_id,
        },
    })
    .into_response()
}

fn generate_tokens(user_id: Uuid, org_id: Uuid, role: Role, auth: &AuthState) -> anyhow::Result<(String, String)> {
    let now = Utc::now();
    let access_exp = now + Duration::hours(1);
    let refresh_exp = now + Duration::days(30);

    let access_claims = Claims {
        sub: user_id.to_string(),
        org: org_id.to_string(),
        role: role.as_str().to_string(),
        exp: access_exp.timestamp(),
        iat: now.timestamp(),
        token_type: "access".to_string(),
    };

    let refresh_claims = Claims {
        sub: user_id.to_string(),
        org: org_id.to_string(),
        role: role.as_str().to_string(),
        exp: refresh_exp.timestamp(),
        iat: now.timestamp(),
        token_type: "refresh".to_string(),
    };

    let access_token = encode(&Header::default(), &access_claims, &auth.encoding_key)?;
    let refresh_token = encode(&Header::default(), &refresh_claims, &auth.encoding_key)?;

    Ok((access_token, refresh_token))
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

fn sha256_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
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
struct UserRow {
    id: Uuid,
    organization_id: Uuid,
    email: String,
    password_hash: String,
    full_name: Option<String>,
    role: Role,
    is_active: bool,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct OrganizationRow {
    id: Uuid,
    name: String,
    slug: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}