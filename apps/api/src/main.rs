//! TraceForge API - REST API for the TraceForge platform

use std::sync::Arc;
use axum::{
    routing::{get, post, put, delete},
    Router, Json, extract::{State, Path, Query, Extension},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use sqlx::PgPool;
use redis::Client as RedisClient;
use aws_sdk_s3::Client as S3Client;
use tracing::{info, error};
use validator::Validate;

use traceforge_shared_types::*;

mod auth;
mod tools;
mod investigations;
mod evidence;
mod audit;
mod middleware;

use auth::{AuthState, register, login, logout, me, refresh_token};
use tools::{create_tool, list_tools, get_tool, create_tool_version, build_tool, publish_tool, download_tool};
use investigations::{create_investigation, list_investigations, get_investigation, run_investigation};
use evidence::{upload_evidence, get_evidence, verify_evidence};
use audit::list_audit_logs;
use middleware::auth_middleware;
pub(crate) use middleware::AuthUser;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    redis: RedisClient,
    s3: S3Client,
    bucket: String,
    auth: AuthState,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting TraceForge API");

    // Load configuration
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://traceforge:traceforge_dev@localhost:5432/traceforge".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let minio_endpoint = std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let minio_access_key = std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "traceforge".to_string());
    let minio_secret_key = std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "traceforge_dev".to_string());
    let minio_bucket = std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "traceforge-artifacts".to_string());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev_secret_change_in_production_at_least_32_chars_long".to_string());

    // Connect to PostgreSQL
    let db_pool = PgPool::connect(&database_url).await?;
    info!("Connected to PostgreSQL");

    // Run migrations
    sqlx::migrate!("../../migrations").run(&db_pool).await?;
    info!("Database migrations applied");

    // Connect to Redis
    let redis_client = RedisClient::open(redis_url)?;
    info!("Connected to Redis");

    // Configure S3 client for MinIO
    let s3_config = aws_config::from_env()
        .endpoint_url(&minio_endpoint)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            minio_access_key,
            minio_secret_key,
            None,
            None,
            "static",
        ))
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .load()
        .await;
    let s3_client = S3Client::new(&s3_config);
    info!("Configured S3 client for MinIO");

    // Auth state
    let auth_state = AuthState::new(jwt_secret);

    let state = Arc::new(AppState {
        db: db_pool,
        redis: redis_client,
        s3: s3_client,
        bucket: minio_bucket,
        auth: auth_state,
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Auth routes
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/refresh", post(refresh_token))
        // Tool routes
        .route("/api/tools", get(list_tools).post(create_tool))
        .route("/api/tools/:id", get(get_tool))
        .route("/api/tools/:id/versions", post(create_tool_version))
        .route("/api/tools/:id/build", post(build_tool))
        .route("/api/tools/:id/publish", post(publish_tool))
        .route("/api/tools/:id/download", get(download_tool))
        // Investigation routes
        .route("/api/investigations", get(list_investigations).post(create_investigation))
        .route("/api/investigations/:id", get(get_investigation))
        .route("/api/investigations/:id/run", post(run_investigation))
        // Evidence routes
        .route("/api/evidence", post(upload_evidence))
        .route("/api/evidence/:id", get(get_evidence))
        .route("/api/evidence/:id/verify", post(verify_evidence))
        // Audit routes
        .route("/api/audit-logs", get(list_audit_logs))
        // Shared state
        .layer(Extension(state.clone()))
        // CORS
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        // Tracing
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("API server listening on http://0.0.0.0:8080");

    axum::serve(listener, app.with_state(state.clone())).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "traceforge-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}