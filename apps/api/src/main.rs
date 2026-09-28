//! jocky API - REST API for the jocky platform

use axum::{
    extract::DefaultBodyLimit,
    http::HeaderValue,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod compiler_service;
mod tools_service;

use compiler_service::{
    capabilities_handler, check_handler, compile_handler, download_file_handler,
    download_linux_handler, download_windows_handler, downloads_info_handler, run_handler,
    targets_handler, verify_handler,
};
use tools_service::{
    auth_login_handler, auth_register_handler, tools_create_handler, tools_create_version_handler,
    tools_download_handler, tools_get_handler, tools_list_handler,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting jocky API");

    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Stateless compiler routes
        .route("/api/compiler/check", post(check_handler))
        .route("/api/compiler/compile", post(compile_handler))
        .route("/api/compiler/run", post(run_handler))
        .route(
            "/api/compiler/verify",
            post(verify_handler).layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/api/compiler/targets", get(targets_handler))
        .route("/api/compiler/capabilities", get(capabilities_handler))
        // Download package routes
        .route("/api/downloads/info", get(downloads_info_handler))
        .route("/api/downloads/windows", get(download_windows_handler))
        .route("/api/downloads/linux", get(download_linux_handler))
        .route("/api/downloads/:filename", get(download_file_handler))
        // Auth routes (stateless JWT, no database required)
        .route("/api/auth/register", post(auth_register_handler))
        .route("/api/auth/login", post(auth_login_handler))
        // Tool repository routes (in-memory for local dev; swap with DB-backed in production)
        .route(
            "/api/tools",
            get(tools_list_handler).post(tools_create_handler),
        )
        .route("/api/tools/:id", get(tools_get_handler))
        .route(
            "/api/tools/:id/versions",
            post(tools_create_version_handler),
        )
        .route("/api/tools/:id/download", get(tools_download_handler));

    let allowed_origins = [
        "http://localhost:3000".parse::<HeaderValue>().unwrap(),
        "http://localhost:5173".parse::<HeaderValue>().unwrap(),
        "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
        "http://127.0.0.1:5173".parse::<HeaderValue>().unwrap(),
    ];

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_credentials(true)
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
            axum::http::header::ACCEPT,
        ])
        .expose_headers([
            axum::http::header::CONTENT_DISPOSITION,
            axum::http::header::CONTENT_LENGTH,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ETAG,
        ]);

    let app = app.layer(cors).layer(TraceLayer::new_for_http());

    let bind_address =
        std::env::var("JOCKY_API_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    info!("API server listening on http://{}", bind_address);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "jocky-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
