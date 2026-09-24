//! jockey API - REST API for the jockey platform

use aws_sdk_s3::Client as S3Client;
use axum::{
    extract::Extension,
    http::HeaderValue,
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use redis::Client as RedisClient;
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod audit;
mod auth;
mod compiler_service;
mod evidence;
mod investigations;
mod middleware;
mod tools;

use audit::list_audit_logs;
use auth::{login, logout, me, refresh_token, register, AuthState};
use compiler_service::{
    check_handler, download_file_handler, downloads_info_handler, execute_handler, targets_handler,
    verify_handler,
};
use evidence::{get_evidence, upload_evidence, verify_evidence};
use investigations::{
    create_investigation, get_investigation, list_investigations, run_investigation,
};
use middleware::auth_middleware;
pub(crate) use middleware::AuthUser;
use tools::{
    build_tool, create_tool, create_tool_version, download_tool, get_tool, list_tools, publish_tool,
};

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

    info!("Starting jockey API");

    // Load configuration - default PostgreSQL port 5433 for local docker container mapping
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://jockey:jockey_dev@localhost:5433/jockey".to_string()
    });
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let minio_endpoint =
        std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let minio_access_key =
        std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "jockey".to_string());
    let minio_secret_key =
        std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "jockey_dev".to_string());
    let minio_bucket =
        std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "jockey-artifacts".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "dev_secret_change_in_production_at_least_32_chars_long".to_string());

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
    let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
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
    let s3_client_config = aws_sdk_s3::config::Builder::from(&s3_config)
        .force_path_style(true)
        .build();
    let s3_client = S3Client::from_conf(s3_client_config);
    let buckets = s3_client.list_buckets().send().await?;
    let bucket_exists = buckets
        .buckets()
        .iter()
        .any(|bucket| bucket.name() == Some(minio_bucket.as_str()));
    if !bucket_exists {
        s3_client
            .create_bucket()
            .bucket(&minio_bucket)
            .send()
            .await?;
        info!("Created object storage bucket: {}", minio_bucket);
    }
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

    // Public routes do not require a session.
    let public_routes = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Auth routes
        .route("/api/auth/register", post(register))
        .route("/api/auth/login", post(login))
        .route("/api/auth/refresh", post(refresh_token))
        // Compiler & Sandbox Execution routes
        .route("/api/compiler/check", post(check_handler))
        .route("/api/compiler/execute", post(execute_handler))
        .route("/api/compiler/targets", get(targets_handler))
        .route("/api/compiler/verify", post(verify_handler))
        // Download package routes
        .route("/api/downloads/info", get(downloads_info_handler))
        .route("/api/downloads/:filename", get(download_file_handler));

    let protected_routes = Router::new()
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        // Tool routes
        .route("/api/tools", get(list_tools).post(create_tool))
        .route("/api/tools/:id", get(get_tool))
        .route("/api/tools/:id/versions", post(create_tool_version))
        .route("/api/tools/:id/build", post(build_tool))
        .route("/api/tools/:id/publish", post(publish_tool))
        .route("/api/tools/:id/download", get(download_tool))
        // Investigation routes
        .route(
            "/api/investigations",
            get(list_investigations).post(create_investigation),
        )
        .route("/api/investigations/:id", get(get_investigation))
        .route("/api/investigations/:id/run", post(run_investigation))
        // Evidence routes
        .route("/api/evidence", post(upload_evidence))
        .route("/api/evidence/:id", get(get_evidence))
        .route("/api/evidence/:id/verify", post(verify_evidence))
        // Audit routes
        .route("/api/audit-logs", get(list_audit_logs))
        .layer(from_fn_with_state(state.clone(), auth_middleware));

    let allowed_origins = [
        "http://localhost:3000".parse::<HeaderValue>().unwrap(),
        "http://localhost:5173".parse::<HeaderValue>().unwrap(),
        "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
        "http://127.0.0.1:5173".parse::<HeaderValue>().unwrap(),
    ];

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    // Build router
    let app = public_routes
        .merge(protected_routes)
        // Shared state
        .layer(Extension(state.clone()))
        // CORS
        .layer(cors)
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
        "service": "jockey-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
