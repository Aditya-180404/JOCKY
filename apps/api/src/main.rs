//! jockey API - REST API for the jockey platform

use axum::{http::HeaderValue, response::IntoResponse, routing::{get, post}, Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod compiler_service;
use compiler_service::{
    check_handler, compile_handler, download_file_handler, downloads_info_handler, targets_handler,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting jockey API");

    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Stateless compiler routes. No account, evidence upload, or remote host execution.
        .route("/api/compiler/check", post(check_handler))
        .route("/api/compiler/compile", post(compile_handler))
        .route("/api/compiler/targets", get(targets_handler))
        // Download package routes
        .route("/api/downloads/info", get(downloads_info_handler))
        .route("/api/downloads/:filename", get(download_file_handler));

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
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    // Build router
    let app = app
        .layer(cors)
        // Tracing
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("API server listening on http://0.0.0.0:8080");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "jockey-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
