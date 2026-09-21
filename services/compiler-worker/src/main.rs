//! TraceForge Compiler Worker - Background job processor for compilation

use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;
use tracing::{info, error, warn, debug};
use redis::AsyncCommands;
use aws_sdk_s3::{Client as S3Client, primitives::ByteStream};
use sqlx::PgPool;
use tempfile::TempDir;

use traceforge_lexer::Lexer;
use traceforge_parser::Parser;
use traceforge_semantic::SemanticAnalyzer;
use traceforge_ir::{BuildConfig, TargetArch, TargetPlatform, serialize_ir};
use traceforge_backend::Backend;
use traceforge_shared_types::{Build, BuildStatus};

struct AppState {
    redis: redis::Client,
    s3: S3Client,
    bucket: String,
    db: PgPool,
    work_dir: TempDir,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    info!("Starting TraceForge Compiler Worker");

    // Load configuration
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://traceforge:traceforge_dev@localhost:5432/traceforge".to_string());
    let minio_endpoint = std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let minio_access_key = std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "traceforge".to_string());
    let minio_secret_key = std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "traceforge_dev".to_string());
    let minio_bucket = std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "traceforge-artifacts".to_string());

    // Connect to Redis
    let redis_client = redis::Client::open(redis_url)?;
    let mut redis_conn = redis_client.get_async_connection().await?;
    info!("Connected to Redis");

    // Connect to PostgreSQL
    let db_pool = PgPool::connect(&database_url).await?;
    info!("Connected to PostgreSQL");

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

    // Create temp directory for builds
    let work_dir = TempDir::new()?;
    info!("Work directory: {}", work_dir.path().display());

    let state = Arc::new(AppState {
        redis: redis_client,
        s3: s3_client,
        bucket: minio_bucket,
        db: db_pool,
        work_dir,
    });

    // Start worker loop
    let worker = Worker::new(state);
    worker.run().await?;

    Ok(())
}

struct Worker {
    state: Arc<AppState>,
}

impl Worker {
    fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    async fn run(&self) -> anyhow::Result<()> {
        let mut interval = interval(Duration::from_secs(5));
        let mut shutdown = signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                _ = interval.tick() => {
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

    async fn process_queue(&self) -> anyhow::Result<()> {
        let mut conn = self.state.redis.get_async_connection().await?;

        // Pop a build job from the queue
        let job_data: Option<String> = conn.rpop("build_queue", None).await?;

        if let Some(job_json) = job_data {
            info!("Processing build job");
            if let Err(e) = self.process_job(&job_json).await {
                error!("Failed to process job: {}", e);
            }
        }

        Ok(())
    }

    async fn process_job(&self, job_json: &str) -> anyhow::Result<()> {
        let job: BuildJob = serde_json::from_str(job_json)?;
        info!("Processing build for tool_version_id: {}", job.tool_version_id);

        // Update build status to running
        self.update_build_status(job.build_id, BuildStatus::Running, None).await?;

        // Create build directory
        let build_dir = self.state.work_dir.path().join(job.build_id.to_string());
        std::fs::create_dir_all(&build_dir)?;

        // Write source file
        let source_path = build_dir.join("investigation.tfg");
        std::fs::write(&source_path, &job.source)?;

        // Compile
        let result = self.compile_investigation(&job, &build_dir).await;

        match result {
            Ok(metadata) => {
                // Upload artifact to S3
                let artifact_path = build_dir.join(&job.tool_name);
                let artifact_size = std::fs::metadata(&artifact_path)?.len();
                let s3_key = format!("artifacts/{}/{}", job.tool_version_id, job.tool_name);
                self.upload_artifact(&artifact_path, &s3_key).await?;

                // Update build status to success
                self.update_build_status(job.build_id, BuildStatus::Success, Some(metadata.artifact_hash.clone())).await?;

                // Update tool version with artifact info
                self.update_tool_version(&job, &metadata, artifact_size, &s3_key).await?;

                info!("Build completed successfully: {}", job.tool_version_id);
            }
            Err(e) => {
                error!("Build failed: {}", e);
                self.update_build_status(job.build_id, BuildStatus::Failed, None).await?;
                self.update_build_log(job.build_id, &e.to_string()).await?;
            }
        }

        Ok(())
    }

    async fn compile_investigation(&self, job: &BuildJob, build_dir: &std::path::Path) -> anyhow::Result<traceforge_ir::ArtifactMetadata> {
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

        // Generate IR JSON for storage
        let ir_json = serialize_ir(&ir)?;
        let ir_path = build_dir.join("ir.json");
        std::fs::write(&ir_path, ir_json)?;

        // Compile to target
        let target_platform = match job.target_platform.as_str() {
            "linux" => TargetPlatform::Linux,
            "windows" => TargetPlatform::Windows,
            _ => TargetPlatform::Linux,
        };

        let target_arch = match job.target_arch.as_str() {
            "x64" | "x86_64" => TargetArch::X64,
            "arm64" | "aarch64" => TargetArch::Arm64,
            _ => TargetArch::X64,
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

        // Calculate source hash
        metadata.source_hash = calculate_sha256(&job.source);
        metadata.compiler_version = env!("CARGO_PKG_VERSION").to_string();
        metadata.compiler_hash = calculate_compiler_hash()?;

        // Calculate artifact hash
        let artifact_path = build_dir.join(&job.tool_name);
        if artifact_path.exists() {
            metadata.artifact_hash = calculate_file_sha256(&artifact_path)?;
        }

        Ok(metadata)
    }

    async fn upload_artifact(&self, local_path: &std::path::Path, s3_key: &str) -> anyhow::Result<()> {
        let body = ByteStream::from_path(local_path).await?;
        self.state.s3
            .put_object()
            .bucket(&self.state.bucket)
            .key(s3_key)
            .body(body)
            .send()
            .await?;
        Ok(())
    }

    async fn update_build_status(&self, build_id: uuid::Uuid, status: BuildStatus, artifact_hash: Option<String>) -> anyhow::Result<()> {
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
        .bind(status as i32)
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

    async fn update_tool_version(&self, job: &BuildJob, metadata: &traceforge_ir::ArtifactMetadata, artifact_size: u64, s3_key: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE tool_versions
            SET artifact_path = $1, artifact_hash = $2, artifact_size = $3, is_published = true, published_at = $4
            WHERE id = $5
            "#,
        )
        .bind(s3_key)
        .bind(&metadata.artifact_hash)
        .bind(artifact_size as i64)
        .bind(chrono::Utc::now())
        .bind(job.tool_version_id)
        .execute(&self.state.db)
        .await?;
        Ok(())
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