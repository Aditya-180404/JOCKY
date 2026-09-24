//! TraceForge Compiler Worker — Background job processor with:
//!   • Priority queue via Redis BZPOPMIN on sorted set `build_queue_priority`
//!   • Fallback to RPOP on legacy `build_queue` list
//!   • Source-hash artifact caching (skip recompile if identical source)
//!   • Real-time log streaming via Redis XADD on `build_log:<build_id>`
//!   • /health HTTP endpoint on port 9100

use aws_sdk_s3::{primitives::ByteStream, Client as S3Client};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::signal;
use tokio::time::interval;
use tracing::{error, info, warn};

use traceforge_backend::Backend;
use traceforge_ir::{serialize_ir, BuildConfig, TargetArch, TargetPlatform};
use traceforge_lexer::Lexer;
use traceforge_parser::Parser;
use traceforge_semantic::SemanticAnalyzer;
use traceforge_shared_types::BuildStatus;

// ──────────────────────────────────────────────────────────────────────────────
// Config constants
// ──────────────────────────────────────────────────────────────────────────────

/// Redis sorted-set key used for the priority queue.
const PRIORITY_QUEUE_KEY: &str = "build_queue_priority";
/// Legacy list key (kept for backward-compat).
const LEGACY_QUEUE_KEY: &str = "build_queue";
/// Key prefix for log streams.
const LOG_STREAM_PREFIX: &str = "build_log";
/// Key prefix for source-hash → artifact-s3-key cache.
const CACHE_PREFIX: &str = "artifact_cache";
/// TTL for cached artifact entries (7 days in seconds).
const CACHE_TTL_SECS: u64 = 7 * 24 * 3600;
/// HTTP port for /health endpoint.
const HEALTH_PORT: u16 = 9100;

// ──────────────────────────────────────────────────────────────────────────────
// App state
// ──────────────────────────────────────────────────────────────────────────────

struct AppState {
    redis: redis::Client,
    s3: S3Client,
    bucket: String,
    db: PgPool,
    work_dir: TempDir,
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting TraceForge Compiler Worker");

    // Load configuration
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://traceforge:traceforge_dev@localhost:5432/traceforge".to_string()
    });
    let minio_endpoint =
        std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let minio_access_key =
        std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "traceforge".to_string());
    let minio_secret_key =
        std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "traceforge_dev".to_string());
    let minio_bucket =
        std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "traceforge-artifacts".to_string());

    // Connect to Redis
    let redis_client = redis::Client::open(redis_url)?;
    let _redis_conn = redis_client.get_async_connection().await?;
    info!("Connected to Redis");

    // Connect to PostgreSQL
    let db_pool = PgPool::connect(&database_url).await?;
    info!("Connected to PostgreSQL");

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

    // Ensure bucket exists
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

    let work_dir = TempDir::new()?;
    info!("Work directory: {}", work_dir.path().display());

    let state = Arc::new(AppState {
        redis: redis_client,
        s3: s3_client,
        bucket: minio_bucket,
        db: db_pool,
        work_dir,
    });

    // Spawn health endpoint on port 9100
    let health_state = Arc::clone(&state);
    tokio::spawn(run_health_server(health_state));

    // Start worker loop
    let worker = Worker::new(state);
    worker.run().await?;

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Health HTTP server (port 9100)
// ──────────────────────────────────────────────────────────────────────────────

async fn run_health_server(_state: Arc<AppState>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(format!("0.0.0.0:{}", HEALTH_PORT)).await {
        Ok(l) => {
            info!("Health endpoint listening on :{}", HEALTH_PORT);
            l
        }
        Err(e) => {
            warn!("Failed to bind health endpoint: {}", e);
            return;
        }
    };

    loop {
        if let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let response = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Type: application/json\r\n",
                    "Content-Length: 15\r\n",
                    "\r\n",
                    r#"{"status":"ok"}"#
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Worker
// ──────────────────────────────────────────────────────────────────────────────

struct Worker {
    state: Arc<AppState>,
}

impl Worker {
    fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    async fn run(&self) -> anyhow::Result<()> {
        // Use a short-poll interval; BZPOPMIN handles blocking for priority queue.
        let mut tick = interval(Duration::from_millis(500));
        let shutdown = signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.process_queue().await {
                        error!("Error processing queue: {}", e);
                    }
                }
                _ = &mut shutdown => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        info!("Worker stopped");
        Ok(())
    }

    /// Try BZPOPMIN on the priority sorted-set first, then fall back to RPOP on
    /// the legacy list. Returns `Ok(None)` if no job is immediately available.
    async fn process_queue(&self) -> anyhow::Result<()> {
        let mut conn = self.state.redis.get_async_connection().await?;

        // BZPOPMIN with a 0.4 s timeout — returns (key, member, score) on success.
        let priority_result: Option<(String, String, f64)> =
            conn.bzpopmin(PRIORITY_QUEUE_KEY, 0.4).await.ok().flatten();

        let job_json = if let Some((_key, member, _score)) = priority_result {
            Some(member)
        } else {
            // Fallback: legacy FIFO list
            conn.rpop::<_, Option<String>>(LEGACY_QUEUE_KEY, None).await?
        };

        if let Some(json) = job_json {
            info!("Dequeued build job");
            if let Err(e) = self.process_job(&json).await {
                error!("Failed to process job: {}", e);
            }
        }

        Ok(())
    }

    async fn process_job(&self, job_json: &str) -> anyhow::Result<()> {
        let job: BuildJob = serde_json::from_str(job_json)?;
        info!(
            "Processing build for tool_version_id: {}",
            job.tool_version_id
        );

        // ── Source-hash cache lookup ──────────────────────────────────────────
        let source_hash = calculate_sha256(&job.source);
        let cache_key = format!("{}:{}", CACHE_PREFIX, source_hash);

        let mut conn = self.state.redis.get_async_connection().await?;
        let cached_s3_key: Option<String> = conn.get(&cache_key).await.unwrap_or(None);

        if let Some(s3_key) = cached_s3_key {
            info!(
                "Cache HIT for source hash {} → s3://{}/{}",
                &source_hash[..12],
                self.state.bucket,
                s3_key
            );
            self.stream_log(job.build_id, "cache_hit", &format!("Reusing cached artifact: {}", s3_key)).await;
            self.update_build_status(job.build_id, BuildStatus::Success, Some(source_hash))
                .await?;
            return Ok(());
        }

        // ── Fresh compilation ─────────────────────────────────────────────────
        self.update_build_status(job.build_id, BuildStatus::Running, None)
            .await?;
        self.stream_log(job.build_id, "start", "Build started").await;

        let build_dir = self.state.work_dir.path().join(job.build_id.to_string());
        std::fs::create_dir_all(&build_dir)?;

        let source_path = build_dir.join("investigation.tfg");
        std::fs::write(&source_path, &job.source)?;

        self.stream_log(job.build_id, "compile", "Compiling source...").await;
        let result = self.compile_investigation(&job, &build_dir).await;

        match result {
            Ok(metadata) => {
                let artifact_name = format!(
                    "{}-{}-{}{}",
                    metadata.investigation_name,
                    target_platform_name(&metadata.target_platform),
                    target_arch_name(&metadata.target_arch),
                    if matches!(metadata.target_platform, TargetPlatform::Windows) {
                        ".exe"
                    } else {
                        ""
                    }
                );
                let artifact_path = build_dir.join(&artifact_name);
                if !artifact_path.is_file() {
                    anyhow::bail!(
                        "Compiler reported success but artifact is missing: {}",
                        artifact_path.display()
                    );
                }
                let artifact_size = std::fs::metadata(&artifact_path)?.len();
                let s3_key = format!("artifacts/{}/{}", job.tool_version_id, artifact_name);

                self.stream_log(job.build_id, "upload", &format!("Uploading artifact: {}", s3_key)).await;
                self.upload_artifact(&artifact_path, &s3_key).await?;

                // Cache the result
                let mut cache_conn = self.state.redis.get_async_connection().await?;
                let _: () = cache_conn
                    .set_ex(&cache_key, &s3_key, CACHE_TTL_SECS)
                    .await
                    .unwrap_or(());
                info!("Cached artifact for source hash {}", &source_hash[..12]);

                self.update_build_status(
                    job.build_id,
                    BuildStatus::Success,
                    Some(metadata.artifact_hash.clone()),
                )
                .await?;

                self.update_tool_version(&job, &metadata, artifact_size, &s3_key)
                    .await?;

                self.stream_log(job.build_id, "done", "Build completed successfully").await;
                info!("Build completed successfully: {}", job.tool_version_id);
            }
            Err(e) => {
                error!("Build failed: {}", e);
                let msg = e.to_string();
                self.stream_log(job.build_id, "error", &msg).await;
                self.update_build_status(job.build_id, BuildStatus::Failed, None)
                    .await?;
                self.update_build_log(job.build_id, &msg).await?;
            }
        }

        Ok(())
    }

    /// Append a structured log entry to the Redis stream `build_log:<build_id>`.
    async fn stream_log(&self, build_id: uuid::Uuid, event: &str, message: &str) {
        let stream_key = format!("{}:{}", LOG_STREAM_PREFIX, build_id);
        if let Ok(mut conn) = self.state.redis.get_async_connection().await {
            let ts = chrono::Utc::now().to_rfc3339();
            let fields = &[("ts", ts.as_str()), ("event", event), ("msg", message)];
            let _: redis::RedisResult<String> = conn.xadd(&stream_key, "*", fields).await;
        }
    }

    async fn compile_investigation(
        &self,
        job: &BuildJob,
        build_dir: &std::path::Path,
    ) -> anyhow::Result<traceforge_ir::ArtifactMetadata> {
        // Parse and analyze
        let mut lexer = Lexer::new(&job.source);
        let tokens = lexer.tokenize()?;

        let mut parser = Parser::new(tokens);
        let (ast, diags) = parser.parse_with_diagnostics();

        if !diags.is_empty() {
            anyhow::bail!("Parse errors: {:?}", diags);
        }

        let ast = ast.ok_or_else(|| anyhow::anyhow!("No AST produced"))?;

        let mut analyzer = SemanticAnalyzer::new();
        let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

        if !sem_diags.is_empty() {
            anyhow::bail!("Semantic errors: {:?}", sem_diags);
        }

        let ir = ir.ok_or_else(|| anyhow::anyhow!("No IR produced"))?;

        // Write IR JSON for storage
        let ir_json = serialize_ir(&ir)?;
        let ir_path = build_dir.join("ir.json");
        std::fs::write(&ir_path, ir_json)?;

        // Compile to target
        let target_platform = match job.target_platform.as_str() {
            "linux" => TargetPlatform::Linux,
            "windows" => TargetPlatform::Windows,
            value => anyhow::bail!("Unsupported target platform: {}", value),
        };

        let target_arch = match job.target_arch.as_str() {
            "x64" | "x86_64" => TargetArch::X64,
            "arm64" | "aarch64" => TargetArch::Arm64,
            value => anyhow::bail!("Unsupported target architecture: {}", value),
        };

        let config = BuildConfig {
            target_platform,
            target_arch,
            optimization_level: traceforge_ir::OptimizationLevel::Speed,
            debug_symbols: false,
            strip_symbols: true,
        };

        let backend = Backend::new(config);
        let mut metadata = backend.generate(&ir, build_dir)?;

        // Fill provenance
        metadata.source_hash = calculate_sha256(&job.source);
        metadata.compiler_version = env!("CARGO_PKG_VERSION").to_string();
        metadata.compiler_hash = calculate_compiler_hash()?;

        // Calculate artifact hash
        let artifact_name = format!(
            "{}-{}-{}{}",
            metadata.investigation_name,
            target_platform_name(&metadata.target_platform),
            target_arch_name(&metadata.target_arch),
            if matches!(metadata.target_platform, TargetPlatform::Windows) {
                ".exe"
            } else {
                ""
            }
        );
        let artifact_path = build_dir.join(artifact_name);
        if !artifact_path.is_file() {
            anyhow::bail!(
                "Compiler did not produce an artifact: {}",
                artifact_path.display()
            );
        }
        metadata.artifact_hash = calculate_file_sha256(&artifact_path)?;

        Ok(metadata)
    }

    async fn upload_artifact(
        &self,
        local_path: &std::path::Path,
        s3_key: &str,
    ) -> anyhow::Result<()> {
        let body = ByteStream::from_path(local_path).await?;
        self.state
            .s3
            .put_object()
            .bucket(&self.state.bucket)
            .key(s3_key)
            .body(body)
            .send()
            .await?;
        Ok(())
    }

    async fn update_build_status(
        &self,
        build_id: uuid::Uuid,
        status: BuildStatus,
        _artifact_hash: Option<String>,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        let completed_at = if matches!(status, BuildStatus::Success | BuildStatus::Failed) {
            Some(now)
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE builds SET status = $1, completed_at = $2
            WHERE id = $3
            "#,
        )
        .bind(status.as_str())
        .bind(completed_at)
        .bind(build_id)
        .execute(&self.state.db)
        .await?;

        Ok(())
    }

    async fn update_build_log(&self, build_id: uuid::Uuid, log: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE builds SET build_log = $1 WHERE id = $2")
            .bind(log)
            .bind(build_id)
            .execute(&self.state.db)
            .await?;
        Ok(())
    }

    async fn update_tool_version(
        &self,
        job: &BuildJob,
        metadata: &traceforge_ir::ArtifactMetadata,
        artifact_size: u64,
        s3_key: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE tool_versions
            SET artifact_path = $1, artifact_hash = $2, artifact_size = $3
            WHERE id = $4
            "#,
        )
        .bind(s3_key)
        .bind(&metadata.artifact_hash)
        .bind(artifact_size as i64)
        .bind(job.tool_version_id)
        .execute(&self.state.db)
        .await?;
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn target_platform_name(platform: &TargetPlatform) -> &'static str {
    match platform {
        TargetPlatform::Linux => "linux",
        TargetPlatform::Windows => "windows",
    }
}

fn target_arch_name(arch: &TargetArch) -> &'static str {
    match arch {
        TargetArch::X64 => "x64",
        TargetArch::Arm64 => "arm64",
    }
}

#[derive(serde::Deserialize)]
struct BuildJob {
    build_id: uuid::Uuid,
    tool_version_id: uuid::Uuid,
    tool_name: String,
    source: String,
    target_platform: String,
    target_arch: String,
    /// Optional priority score (lower = higher priority). Used when enqueuing
    /// via ZADD on `build_queue_priority`. Not needed for legacy RPOP path.
    #[serde(default)]
    #[allow(dead_code)]
    priority: Option<f64>,
}

fn calculate_sha256(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn calculate_file_sha256(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn calculate_compiler_hash() -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let exe_path = std::env::current_exe()?;
    let mut file = std::fs::File::open(exe_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}
