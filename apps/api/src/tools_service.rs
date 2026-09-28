//! tools_service — In-process auth + tool repository for local development.
//!
//! All state is held in process memory via OnceLock<Arc<Mutex<HashMap>>>.
//! No database required. Swap with a DB-backed implementation for production.

use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};
use uuid::Uuid;

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTool {
    pub id: String,
    pub name: String,
    pub description: String,
    pub owner_email: String,
    pub created_at: String,
    pub versions: Vec<StoredVersion>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredVersion {
    pub id: String,
    pub version: String,
    pub source: String,
    pub target_platform: String,
    pub target_arch: String,
    pub artifact_hash: String,
    pub created_at: String,
}

static USERS: OnceLock<Arc<Mutex<HashMap<String, StoredUser>>>> = OnceLock::new();
static TOOLS: OnceLock<Arc<Mutex<HashMap<String, StoredTool>>>> = OnceLock::new();

fn users() -> &'static Arc<Mutex<HashMap<String, StoredUser>>> {
    USERS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

fn tools() -> &'static Arc<Mutex<HashMap<String, StoredTool>>> {
    TOOLS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

// ─── JWT (HS256) ──────────────────────────────────────────────────────────────

const JWT_SECRET: &[u8] = b"jocky-local-dev-secret-DO-NOT-USE-IN-PRODUCTION";

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn generate_token(email: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let exp = (Utc::now().timestamp() as usize) + 86_400;
    encode(
        &Header::default(),
        &Claims {
            sub: email.to_string(),
            exp,
        },
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .unwrap_or_else(|_| "token-error".to_string())
}

fn verify_token(token: &str) -> Option<String> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims.sub)
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    format!("{:x}", h.finalize())
}

fn api_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

// ─── Auth endpoints ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

/// POST /api/auth/register
pub async fn auth_register_handler(Json(req): Json<AuthRequest>) -> Response {
    if req.email.is_empty() || req.password.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "email and password are required");
    }
    let mut store = users().lock().unwrap();
    if store.contains_key(&req.email) {
        return api_error(StatusCode::CONFLICT, "email already registered");
    }
    let id = Uuid::new_v4().to_string();
    store.insert(
        req.email.clone(),
        StoredUser {
            id: id.clone(),
            email: req.email.clone(),
            password_hash: sha256_hex(&req.password),
            created_at: Utc::now().to_rfc3339(),
        },
    );
    let token = generate_token(&req.email);
    Json(serde_json::json!({
        "access_token": token,
        "token": token,
        "user_id": id,
        "email": req.email,
    }))
    .into_response()
}

/// POST /api/auth/login
pub async fn auth_login_handler(Json(req): Json<AuthRequest>) -> Response {
    let store = users().lock().unwrap();
    match store.get(&req.email) {
        Some(u) if u.password_hash == sha256_hex(&req.password) => {
            let token = generate_token(&req.email);
            Json(serde_json::json!({
                "access_token": token,
                "token": token,
                "user_id": u.id,
                "email": u.email,
            }))
            .into_response()
        }
        _ => api_error(StatusCode::UNAUTHORIZED, "invalid credentials"),
    }
}

// ─── Tool repository ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateToolRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateVersionRequest {
    pub version: String,
    pub source: String,
    pub target_platform: Option<String>,
    pub target_arch: Option<String>,
}

/// GET /api/tools — public
pub async fn tools_list_handler() -> Response {
    let store = tools().lock().unwrap();
    let items: Vec<_> = store
        .values()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "owner": t.owner_email,
                "version_count": t.versions.len(),
                "created_at": t.created_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "data": items, "total": items.len() })).into_response()
}

/// POST /api/tools — auth required
pub async fn tools_create_handler(
    headers: HeaderMap,
    Json(payload): Json<CreateToolRequest>,
) -> Response {
    let email = match bearer_from_headers(&headers).and_then(|t| verify_token(&t)) {
        Some(e) => e,
        None => return api_error(StatusCode::UNAUTHORIZED, "authentication required"),
    };
    if payload.name.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "name is required");
    }
    let id = Uuid::new_v4().to_string();
    let tool = StoredTool {
        id: id.clone(),
        name: payload.name.clone(),
        description: payload.description.unwrap_or_default(),
        owner_email: email,
        created_at: Utc::now().to_rfc3339(),
        versions: vec![],
    };
    tools().lock().unwrap().insert(id.clone(), tool.clone());
    Json(serde_json::json!({
        "id": tool.id,
        "name": tool.name,
        "description": tool.description,
        "created_at": tool.created_at,
    }))
    .into_response()
}

/// GET /api/tools/:id — public
pub async fn tools_get_handler(Path(id): Path<String>) -> Response {
    let store = tools().lock().unwrap();
    match store.get(&id) {
        Some(t) => Json(serde_json::json!({
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "owner": t.owner_email,
            "versions": t.versions.iter().map(|v| serde_json::json!({
                "id": v.id,
                "version": v.version,
                "target_platform": v.target_platform,
                "target_arch": v.target_arch,
                "artifact_hash": v.artifact_hash,
                "created_at": v.created_at,
            })).collect::<Vec<_>>(),
            "created_at": t.created_at,
        }))
        .into_response(),
        None => api_error(StatusCode::NOT_FOUND, "tool not found"),
    }
}

/// POST /api/tools/:id/versions — auth required
pub async fn tools_create_version_handler(
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateVersionRequest>,
) -> Response {
    if bearer_from_headers(&headers)
        .and_then(|t| verify_token(&t))
        .is_none()
    {
        return api_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let artifact_hash = sha256_hex(&payload.source);
    let version_id = Uuid::new_v4().to_string();
    let ver = StoredVersion {
        id: version_id.clone(),
        version: payload.version.clone(),
        source: payload.source,
        target_platform: payload
            .target_platform
            .unwrap_or_else(|| "windows".to_string()),
        target_arch: payload.target_arch.unwrap_or_else(|| "x64".to_string()),
        artifact_hash: artifact_hash.clone(),
        created_at: Utc::now().to_rfc3339(),
    };
    let mut store = tools().lock().unwrap();
    match store.get_mut(&id) {
        Some(tool) => {
            tool.versions.push(ver);
            Json(serde_json::json!({
                "id": version_id,
                "version": payload.version,
                "artifact_hash": artifact_hash,
                "status": "published",
            }))
            .into_response()
        }
        None => api_error(StatusCode::NOT_FOUND, "tool not found"),
    }
}

/// GET /api/tools/:id/download — auth required
pub async fn tools_download_handler(headers: HeaderMap, Path(id): Path<String>) -> Response {
    if bearer_from_headers(&headers)
        .and_then(|t| verify_token(&t))
        .is_none()
    {
        return api_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let store = tools().lock().unwrap();
    match store.get(&id) {
        Some(t) => match t.versions.last() {
            Some(v) => (
                StatusCode::OK,
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    (
                        "Content-Disposition",
                        &format!("attachment; filename=\"{}.jy\"", t.name),
                    ),
                ],
                v.source.clone(),
            )
                .into_response(),
            None => api_error(StatusCode::NOT_FOUND, "no published versions"),
        },
        None => api_error(StatusCode::NOT_FOUND, "tool not found"),
    }
}
