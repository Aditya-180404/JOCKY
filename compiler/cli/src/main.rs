//! TraceForge CLI - Command-line interface for the TraceForge compiler

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use traceforge_backend::{Backend, BackendKind};
use traceforge_ir::{BuildConfig, TargetArch, TargetPlatform};
use traceforge_lexer::Lexer;
use traceforge_parser::Parser as TfParser;
use traceforge_runtime::{verify_evidence, VerificationStatus};
use traceforge_semantic::SemanticAnalyzer;

#[derive(Parser)]
#[command(
    name = "traceforge",
    version,
    about = "TraceForge Forensic Investigation Compiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a TraceForge source file
    #[command(alias = "check")]
    Validate {
        /// Source file to validate
        file: PathBuf,
    },
    /// Compile a TraceForge source file
    Compile {
        /// Source file to compile
        file: PathBuf,
        /// Target platform (linux, windows, native)
        #[arg(short, long, default_value = "native")]
        target: String,
        /// Target architecture (x64, arm64)
        #[arg(short, long, default_value = "x64")]
        arch: String,
        /// Output directory
        #[arg(short, long, default_value = "./build")]
        output: PathBuf,
        /// Optimization level (none, size, speed)
        #[arg(long, default_value = "speed")]
        opt: String,
        /// Compilation backend (llvm, rust)
        #[arg(short, long, default_value = "llvm")]
        backend: String,
        /// Emit HIR representation (.hir.json)
        #[arg(long)]
        emit_hir: bool,
        /// Emit MIR representation (.mir.json)
        #[arg(long)]
        emit_mir: bool,
        /// Emit LLVM IR (.ll)
        #[arg(long)]
        emit_llvm: bool,
        /// Emit all intermediate artifacts (.tokens, .ast.json, .hir.json, .mir.json, .ll, .manifest.json)
        #[arg(long)]
        emit_all: bool,
        /// Verbose compiler pipeline output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Build a TraceForge source file (alias for compile)
    Build {
        /// Source file to build
        file: PathBuf,
        /// Target platform (linux, windows, native)
        #[arg(short, long, default_value = "native")]
        target: String,
        /// Target architecture (x64, arm64)
        #[arg(short, long, default_value = "x64")]
        arch: String,
        /// Output directory
        #[arg(short, long, default_value = "./build")]
        output: PathBuf,
        /// Compilation backend (llvm, rust)
        #[arg(short, long, default_value = "llvm")]
        backend: String,
        /// Emit HIR representation (.hir.json)
        #[arg(long)]
        emit_hir: bool,
        /// Emit MIR representation (.mir.json)
        #[arg(long)]
        emit_mir: bool,
        /// Emit LLVM IR (.ll)
        #[arg(long)]
        emit_llvm: bool,
        /// Emit all intermediate artifacts (.tokens, .ast.json, .hir.json, .mir.json, .ll, .manifest.json)
        #[arg(long)]
        emit_all: bool,
        /// Verbose compiler pipeline output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Inspect a TraceForge source file (show AST/IR)
    Inspect {
        /// Source file to inspect
        file: PathBuf,
        /// Output format (ast, ir, json)
        #[arg(short, long, default_value = "ir")]
        format: String,
    },
    /// Calculate SHA-256 hash of a file
    Hash {
        /// File to hash
        file: PathBuf,
    },
    /// Verify an artifact against its generated metadata
    Verify {
        /// Artifact to verify
        artifact: PathBuf,
    },
    /// Evidence operations (verify integrity, inspect metadata)
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },
    /// Initialize a new TraceForge project
    Init {
        /// Project name
        name: String,
    },
    /// Compile and execute a TraceForge source file
    Run {
        /// Source file to run
        file: PathBuf,
        /// Target platform (linux, windows, native)
        #[arg(short, long, default_value = "native")]
        target: String,
        /// Target architecture (x64, arm64)
        #[arg(short, long, default_value = "x64")]
        arch: String,
        /// Build output directory
        #[arg(short, long, default_value = "./build")]
        output: PathBuf,
    },
    /// Validate and normalize a TraceForge source file
    Fmt {
        /// Source file to format
        file: PathBuf,
        /// Write the normalized source back to the file
        #[arg(long)]
        write: bool,
    },
    /// List supported compilation targets
    Target {
        #[command(subcommand)]
        command: TargetCommands,
    },
    /// Log in to the TraceForge tool repository
    Login {
        /// User email
        #[arg(short, long)]
        email: Option<String>,
        /// User password
        #[arg(short, long)]
        password: Option<String>,
        /// API server URL
        #[arg(long, default_value = "http://localhost:8080")]
        url: String,
    },
    /// Search for tools in the repository
    Search {
        /// Search query
        #[arg(default_value = "")]
        query: String,
    },
    /// Install a tool from the repository
    Install {
        /// Tool name or ID
        tool: String,
        /// Specific version to install
        #[arg(short, long)]
        version: Option<String>,
    },
    /// List installed or available tools
    List,
    /// View detailed tool information
    Info {
        /// Tool name or ID
        tool: String,
    },
    /// Update installed tools
    Update {
        /// Specific tool to update (or all if omitted)
        tool: Option<String>,
    },
    /// Publish a tool to the repository
    Publish {
        /// Source file to publish
        file: PathBuf,
        /// Semantic version (e.g. 1.0.0)
        #[arg(short, long, default_value = "0.1.0")]
        version: String,
        /// Release changelog / description
        #[arg(short, long, default_value = "Initial release")]
        description: String,
    },
    /// Launch the TraceForge Desktop / Web IDE
    Ide {
        /// Port to launch on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}

#[derive(Subcommand)]
enum TargetCommands {
    /// List supported platform and architecture combinations
    List,
}

#[derive(Subcommand)]
enum EvidenceCommands {
    /// Verify evidence integrity (SHA-256 + Merkle root)
    Verify {
        /// Evidence JSON file to verify
        evidence: PathBuf,
        /// Metadata sidecar file (default: <evidence>.meta.json)
        #[arg(long)]
        meta: Option<PathBuf>,
    },
    /// Inspect evidence metadata sidecar
    Inspect {
        /// Evidence JSON or metadata file
        file: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { file } => validate(&file),
        Commands::Compile {
            file,
            target,
            arch,
            output,
            opt,
            backend,
            emit_hir,
            emit_mir,
            emit_llvm,
            emit_all,
            verbose,
        } => compile(
            &file,
            &target,
            &arch,
            &output,
            &opt,
            &backend,
            emit_hir,
            emit_mir,
            emit_llvm,
            emit_all,
            verbose,
        ),
        Commands::Build {
            file,
            target,
            arch,
            output,
            backend,
            emit_hir,
            emit_mir,
            emit_llvm,
            emit_all,
            verbose,
        } => compile(
            &file,
            &target,
            &arch,
            &output,
            "speed",
            &backend,
            emit_hir,
            emit_mir,
            emit_llvm,
            emit_all,
            verbose,
        ),
        Commands::Inspect { file, format } => inspect(&file, &format),
        Commands::Hash { file } => hash_file(&file),
        Commands::Verify { artifact } => verify_artifact(&artifact),
        Commands::Evidence { command } => match command {
            EvidenceCommands::Verify { evidence, meta } => {
                let meta_path = meta
                    .unwrap_or_else(|| PathBuf::from(format!("{}.meta.json", evidence.display())));
                evidence_verify(&evidence, &meta_path)
            }
            EvidenceCommands::Inspect { file } => evidence_inspect(&file),
        },
        Commands::Init { name } => init_project(&name),
        Commands::Run {
            file,
            target,
            arch,
            output,
        } => run(&file, &target, &arch, &output),
        Commands::Fmt { file, write } => fmt(&file, write),
        Commands::Target {
            command: TargetCommands::List,
        } => list_targets(),
        Commands::Login {
            email,
            password,
            url,
        } => repo_login(email, password, &url),
        Commands::Search { query } => repo_search(&query),
        Commands::Install { tool, version } => repo_install(&tool, version.as_deref()),
        Commands::List => repo_list(),
        Commands::Info { tool } => repo_info(&tool),
        Commands::Update { tool } => repo_update(tool.as_deref()),
        Commands::Publish {
            file,
            version,
            description,
        } => repo_publish(&file, &version, &description),
        Commands::Ide { port } => launch_ide(port),
    }
}

fn run(file: &Path, target: &str, arch: &str, output: &Path) -> anyhow::Result<()> {
    compile(file, target, arch, output, "speed", "llvm", false, false, false, false, false)?;

    let target_platform = match target.to_lowercase().as_str() {
        "linux" => TargetPlatform::Linux,
        "windows" => TargetPlatform::Windows,
        "native" => {
            if cfg!(target_os = "windows") {
                TargetPlatform::Windows
            } else {
                TargetPlatform::Linux
            }
        }
        _ => anyhow::bail!("Unknown target platform: {}", target),
    };

    match target_platform {
        TargetPlatform::Linux if !cfg!(target_os = "linux") => {
            anyhow::bail!(
                "Running Linux artifacts directly is only supported on a Linux host (or via WSL)."
            );
        }
        TargetPlatform::Windows if !cfg!(target_os = "windows") => {
            anyhow::bail!("Running Windows artifacts directly is only supported on a Windows host (or via Wine).");
        }
        _ => {}
    }

    let source = std::fs::read_to_string(file)?;
    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;
    let mut parser = TfParser::new(tokens);
    let (ast, diagnostics) = parser.parse_with_diagnostics();
    if !diagnostics.is_empty() {
        print_diagnostics(&diagnostics);
    }
    let ast = ast.ok_or_else(|| anyhow::anyhow!("Unable to determine investigation name"))?;
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, semantic_diagnostics) = analyzer.analyze_with_diagnostics(&ast);
    if !semantic_diagnostics.is_empty() {
        print_diagnostics(&semantic_diagnostics);
    }
    let investigation =
        ir.ok_or_else(|| anyhow::anyhow!("Unable to determine investigation name"))?;
    let artifact = match target_platform {
        TargetPlatform::Linux => output.join(format!(
            "{}-linux-{}",
            investigation.name,
            arch_suffix(arch)?
        )),
        TargetPlatform::Windows => output.join(format!(
            "{}-windows-{}.exe",
            investigation.name,
            arch_suffix(arch)?
        )),
    };

    println!("Running {}", artifact.display());
    let status = std::process::Command::new(&artifact)
        .current_dir(output)
        .status()?;
    if !status.success() {
        anyhow::bail!("Investigation exited with status {}", status);
    }
    Ok(())
}

fn arch_suffix(arch: &str) -> anyhow::Result<&'static str> {
    match arch.to_lowercase().as_str() {
        "x64" | "x86_64" => Ok("x64"),
        "arm64" | "aarch64" => Ok("arm64"),
        _ => anyhow::bail!("Unknown target architecture: {}", arch),
    }
}

fn fmt(file: &Path, write: bool) -> anyhow::Result<()> {
    let source = std::fs::read_to_string(file)?;
    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;
    let mut parser = TfParser::new(tokens);
    let (ast, diagnostics) = parser.parse_with_diagnostics();
    if !diagnostics.is_empty() {
        print_diagnostics(&diagnostics);
    }
    if ast.is_none() {
        anyhow::bail!("Formatting failed: source does not parse");
    }

    let formatted = source
        .replace("\r\n", "\n")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    if write {
        std::fs::write(file, formatted)?;
    } else {
        print!("{}", formatted);
    }
    Ok(())
}

fn list_targets() -> anyhow::Result<()> {
    println!("linux x64");
    println!("windows x64");
    Ok(())
}

fn validate(file: &Path) -> anyhow::Result<()> {
    println!("Validating {}", file.display());

    let source = std::fs::read_to_string(file)?;

    // Debug: print tokens
    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;
    println!("Tokens:");
    for (i, token) in tokens.iter().enumerate() {
        println!("  [{}] {:?}", i, token.kind);
    }

    let mut parser = TfParser::new(tokens);
    let (ast, diags) = parser.parse_with_diagnostics();

    if !diags.is_empty() {
        print_diagnostics(&diags);
        if ast.is_none() {
            anyhow::bail!("Validation failed");
        }
    }

    if let Some(ast) = ast {
        let mut analyzer = SemanticAnalyzer::new();
        let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

        if !sem_diags.is_empty() {
            print_diagnostics(&sem_diags);
            anyhow::bail!("Semantic validation failed");
        }

        println!("✓ Validation successful");
        println!(
            "  Investigation: {}",
            ir.as_ref().map(|i| i.name.as_str()).unwrap_or("unknown")
        );
        println!(
            "  Required capabilities: {:?}",
            ir.map(|i| i
                .required_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>())
                .unwrap_or_default()
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile(
    file: &Path,
    target: &str,
    arch: &str,
    output: &Path,
    opt: &str,
    backend_name: &str,
    emit_hir: bool,
    emit_mir: bool,
    emit_llvm: bool,
    emit_all: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    println!("Compiling {}", file.display());

    let source = std::fs::read_to_string(file)?;
    let source_hash = calculate_sha256(&source);

    // --- Lex ---
    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;

    if emit_all {
        std::fs::create_dir_all(output)?;
        let tok_path = output.join(format!("{}.tokens", file.file_stem().and_then(|s| s.to_str()).unwrap_or("output")));
        let mut tok_str = String::new();
        for t in &tokens { tok_str.push_str(&format!("{:?}\n", t)); }
        std::fs::write(&tok_path, tok_str)?;
        println!("  Tokens → {}", tok_path.display());
    }

    // --- Parse ---
    let mut parser = TfParser::new(tokens);
    let (ast, diags) = parser.parse_with_diagnostics();

    if !diags.is_empty() {
        print_diagnostics(&diags);
        if ast.is_none() {
            anyhow::bail!("Compilation failed during parsing");
        }
    }

    let ast = ast.unwrap();

    if emit_all {
        let ast_path = output.join(format!("{}.ast.json", file.file_stem().and_then(|s| s.to_str()).unwrap_or("output")));
        std::fs::write(&ast_path, serde_json::to_string_pretty(&ast)?)?;
        println!("  AST   → {}", ast_path.display());
    }

    // --- Semantic Analysis ---
    let mut analyzer = SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

    if !sem_diags.is_empty() {
        print_diagnostics(&sem_diags);
        anyhow::bail!("Compilation failed during semantic analysis");
    }

    let ir = ir.unwrap();

    // --- Target resolution ---
    let target_platform = match target.to_lowercase().as_str() {
        "linux" => TargetPlatform::Linux,
        "windows" => TargetPlatform::Windows,
        "native" => {
            if cfg!(target_os = "windows") {
                TargetPlatform::Windows
            } else {
                TargetPlatform::Linux
            }
        }
        _ => anyhow::bail!("Unknown target platform: {}", target),
    };

    let target_arch = match arch.to_lowercase().as_str() {
        "x64" | "x86_64" => TargetArch::X64,
        "arm64" | "aarch64" => TargetArch::Arm64,
        _ => anyhow::bail!("Unknown target architecture: {}", arch),
    };

    let optimization_level = match opt.to_lowercase().as_str() {
        "none" => traceforge_ir::OptimizationLevel::None,
        "size" => traceforge_ir::OptimizationLevel::Size,
        "speed" => traceforge_ir::OptimizationLevel::Speed,
        _ => traceforge_ir::OptimizationLevel::Speed,
    };

    let config = BuildConfig {
        target_platform,
        target_arch,
        optimization_level,
        debug_symbols: false,
        strip_symbols: true,
    };

    // --- Resolve backend kind ---
    let backend_kind: BackendKind = backend_name.parse().unwrap_or(BackendKind::Llvm);
    if verbose {
        println!("  Backend:          {:?}", backend_kind);
        println!("  Target:           {:?}-{:?}", target_platform, target_arch);
        println!("  Optimization:     {:?}", optimization_level);
    }

    std::fs::create_dir_all(output)?;
    println!("  Output directory: {}", output.display());
    println!("  Investigation:    {}", ir.name);

    // --- HIR lowering (for LLVM path and emit flags) ---
    let maybe_hir = if backend_kind == BackendKind::Llvm || emit_hir || emit_all {
        let hir: traceforge_hir::HirInvestigation = (&ir).into();
        Some(hir)
    } else {
        None
    };

    if emit_hir || emit_all {
        if let Some(hir) = &maybe_hir {
            let hir_path = output.join(format!("{}.hir.json", ir.name));
            std::fs::write(&hir_path, serde_json::to_string_pretty(hir)?)?;
            println!("  HIR   → {}", hir_path.display());
        }
    }

    // --- MIR lowering (for LLVM path and emit flags) ---
    let maybe_mir = if backend_kind == BackendKind::Llvm || emit_mir || emit_llvm || emit_all {
        if let Some(hir) = &maybe_hir {
            let mir = traceforge_mir::MirLowering::lower(hir)
                .map_err(|e| anyhow::anyhow!("MIR lowering failed: {}", e))?;
            Some(mir)
        } else {
            None
        }
    } else {
        None
    };

    if emit_mir || emit_all {
        if let Some(mir) = &maybe_mir {
            let mir_path = output.join(format!("{}.mir.json", ir.name));
            std::fs::write(&mir_path, serde_json::to_string_pretty(mir)?)?;
            println!("  MIR   → {}", mir_path.display());
        }
    }

    // --- LLVM IR emission (optional, before actual compilation) ---
    if emit_llvm || emit_all {
        if let Some(mir) = &maybe_mir {
            let llvm_backend = traceforge_backend::LlvmBackend::new(config.clone());
            let llvm_ir = llvm_backend
                .generate_llvm_ir(mir)
                .map_err(|e| anyhow::anyhow!("LLVM IR generation failed: {}", e))?;
            let ll_path = output.join(format!("{}.ll", ir.name));
            std::fs::write(&ll_path, &llvm_ir)?;
            println!("  LLVM  → {}", ll_path.display());
        }
    }

    // --- Code generation ---
    let backend = Backend::new_with_kind(config, backend_kind);
    let mut metadata = backend.generate(&ir, output)?;

    // Update metadata with actual values
    metadata.source_hash = source_hash;
    metadata.compiler_version = env!("CARGO_PKG_VERSION").to_string();
    metadata.compiler_hash = calculate_compiler_hash()?;

    // Write compile metadata sidecar
    let meta_path = output.join(format!("{}.meta.json", ir.name));
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)?;

    if emit_all {
        let cap_manifest = serde_json::json!({
            "investigation": ir.name,
            "required_capabilities": ir.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "operations_count": ir.operations.len(),
        });
        let manifest_path = output.join(format!("{}.manifest.json", ir.name));
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&cap_manifest)?)?;
        println!("  Manifest → {}", manifest_path.display());
    }

    let artifact_file = match target_platform {
        TargetPlatform::Linux => output.join(format!("{}-linux-{}", ir.name, arch_suffix(arch)?)),
        TargetPlatform::Windows => {
            output.join(format!("{}-windows-{}.exe", ir.name, arch_suffix(arch)?))
        }
    };

    println!("✓ Compilation successful");
    println!("  Artifact: {}", artifact_file.display());
    println!("  SHA-256:  {}", metadata.artifact_hash);
    println!("  Metadata: {}", meta_path.display());

    Ok(())
}

fn inspect(file: &Path, format: &str) -> anyhow::Result<()> {
    let source = std::fs::read_to_string(file)?;

    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;

    match format {
        "tokens" => {
            for token in tokens {
                println!("{:?} @ {}", token.kind, token.span);
            }
        }
        "ast" => {
            let mut parser = TfParser::new(tokens);
            let (ast, diags) = parser.parse_with_diagnostics();
            if !diags.is_empty() {
                print_diagnostics(&diags);
            }
            if let Some(ast) = ast {
                println!("{}", serde_json::to_string_pretty(&ast)?);
            }
        }
        "ir" | "json" => {
            let mut parser = TfParser::new(tokens);
            let (ast, diags) = parser.parse_with_diagnostics();
            if !diags.is_empty() {
                print_diagnostics(&diags);
            }
            if let Some(ast) = ast {
                let mut analyzer = SemanticAnalyzer::new();
                let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);
                if !sem_diags.is_empty() {
                    print_diagnostics(&sem_diags);
                }
                if let Some(ir) = ir {
                    println!("{}", traceforge_ir::serialize_ir(&ir)?);
                }
            }
        }
        _ => anyhow::bail!("Unknown format: {}", format),
    }

    Ok(())
}

fn hash_file(file: &Path) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(file)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();

    println!("SHA-256: {:x}", hash);
    Ok(())
}

fn verify_artifact(artifact: &Path) -> anyhow::Result<()> {
    if !artifact.is_file() {
        anyhow::bail!("Artifact does not exist: {}", artifact.display());
    }

    let actual_hash = calculate_file_hash(artifact)?;
    let parent = artifact
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let metadata_dir = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };

    // Check direct sidecar first (e.g. file.meta.json)
    let sidecar = metadata_dir.join(format!(
        "{}.meta.json",
        artifact
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    ));

    if sidecar.is_file() {
        let content = std::fs::read(&sidecar)?;
        if let Ok(evidence_meta) = serde_json::from_slice::<serde_json::Value>(&content) {
            if let Some(expected_hash) = evidence_meta.get("evidence_hash").and_then(|h| h.as_str())
            {
                if expected_hash == actual_hash {
                    println!("Integrity: VALID");
                    println!("SHA-256: {}", actual_hash);
                    println!("Metadata: {}", sidecar.display());
                    if let Some(name) = evidence_meta
                        .get("investigation_name")
                        .and_then(|n| n.as_str())
                    {
                        println!("Investigation: {}", name);
                    }
                    if let Some(host) = evidence_meta
                        .get("host_identifier")
                        .and_then(|h| h.as_str())
                    {
                        println!("Host: {}", host);
                    }
                    if let Some(time) = evidence_meta
                        .get("collection_time")
                        .and_then(|t| t.as_str())
                    {
                        println!("Collected: {}", time);
                    }
                    return Ok(());
                } else {
                    anyhow::bail!(
                        "Evidence TAMPERED! Hash mismatch: expected {}, got {}",
                        expected_hash,
                        actual_hash
                    );
                }
            }
        }
    }

    let mut matching_metadata = None;
    for entry in std::fs::read_dir(metadata_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json")
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .ends_with(".meta.json")
        {
            continue;
        }
        let content = std::fs::read(&path)?;
        if let Ok(metadata) = serde_json::from_slice::<traceforge_ir::ArtifactMetadata>(&content) {
            if metadata.artifact_hash == actual_hash {
                matching_metadata = Some((path, metadata));
                break;
            }
        } else if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&content) {
            if let Some(h) = v.get("evidence_hash").and_then(|h| h.as_str()) {
                if h == actual_hash {
                    println!("Integrity: VALID");
                    println!("SHA-256: {}", actual_hash);
                    println!("Metadata: {}", path.display());
                    return Ok(());
                }
            }
        }
    }

    match matching_metadata {
        Some((path, metadata)) => {
            println!("Signature: NOT PRESENT");
            println!("Artifact hash: VALID");
            println!("SHA-256: {}", actual_hash);
            println!("Metadata: {}", path.display());
            println!(
                "Target: {:?}-{:?}",
                metadata.target_platform, metadata.target_arch
            );
            Ok(())
        }
        None => anyhow::bail!(
            "Artifact hash does not match any metadata file: {}",
            actual_hash
        ),
    }
}

fn calculate_file_hash(file: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let mut input = std::fs::File::open(file)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut input, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}


fn evidence_verify(evidence: &Path, meta: &Path) -> anyhow::Result<()> {
    println!("Verifying evidence: {}", evidence.display());
    println!("Using metadata:    {}", meta.display());

    let result = verify_evidence(
        evidence.to_str().unwrap_or_default(),
        meta.to_str().unwrap_or_default(),
    )
    .map_err(|e| anyhow::anyhow!("Verification error: {}", e))?;

    match &result.status {
        VerificationStatus::Verified => {
            println!("✓ Evidence verification SUCCESSFUL (Integrity Intact)");
            if let Some(hash) = &result.calculated_hash {
                println!("  SHA-256 Hash: {}", hash);
            }
            if let Some(valid) = result.merkle_root_valid {
                println!(
                    "  Merkle Tree:  {}",
                    if valid { "Valid" } else { "Invalid" }
                );
            }
            println!("  Verified at:  {}", result.verified_at);
            Ok(())
        }
        VerificationStatus::Tampered { reason } => {
            eprintln!("✗ Evidence TAMPERED / INTEGRITY FAILED");
            eprintln!("  Reason: {}", reason);
            if let Some(calc) = &result.calculated_hash {
                eprintln!("  Calculated SHA-256: {}", calc);
            }
            if let Some(stored) = &result.stored_hash {
                eprintln!("  Expected SHA-256:   {}", stored);
            }
            anyhow::bail!("Evidence failed integrity check: {}", reason);
        }
        VerificationStatus::Missing { detail } => {
            eprintln!("✗ Evidence verification file missing");
            eprintln!("  Detail: {}", detail);
            anyhow::bail!("Verification missing file: {}", detail);
        }
    }
}

fn evidence_inspect(file: &Path) -> anyhow::Result<()> {
    println!("Inspecting evidence: {}", file.display());
    let content = std::fs::read_to_string(file)?;
    let val: serde_json::Value = serde_json::from_str(&content)?;

    println!("------------------------------------------------------------");
    if let Some(meta) = val.get("metadata") {
        println!("Metadata:");
        if let Some(inv) = meta.get("investigation_name").and_then(|v| v.as_str()) {
            println!("  Investigation: {}", inv);
        }
        if let Some(host) = meta.get("host_identifier").and_then(|v| v.as_str()) {
            println!("  Host:          {}", host);
        }
        if let Some(dt) = meta.get("collected_at").and_then(|v| v.as_str()) {
            println!("  Collected At:  {}", dt);
        }
        if let Some(h) = meta.get("evidence_hash").and_then(|v| v.as_str()) {
            println!("  Evidence Hash: {}", h);
        }
        if let Some(m) = meta.get("merkle_root").and_then(|v| v.as_str()) {
            println!("  Merkle Root:   {}", m);
        }
    }

    if let Some(records) = val.get("records").and_then(|r| r.as_array()) {
        println!("Records Count: {}", records.len());
        if !records.is_empty() {
            println!("\nSample Record [0]:");
            println!("{}", serde_json::to_string_pretty(&records[0])?);
        }
    } else if let Some(arr) = val.as_array() {
        println!("Array Items: {}", arr.len());
        if !arr.is_empty() {
            println!("\nSample Item [0]:");
            println!("{}", serde_json::to_string_pretty(&arr[0])?);
        }
    } else {
        println!("Payload Structure: Object");
        println!("{}", serde_json::to_string_pretty(&val)?);
    }
    println!("------------------------------------------------------------");
    Ok(())
}

fn init_project(name: &str) -> anyhow::Result<()> {
    let dir = PathBuf::from(name);
    std::fs::create_dir_all(&dir)?;

    // Create example investigation
    let example = format!(
        r#"investigation "{}" {{
    collect system_info

    collect processes {{
        pid
        name
        parent
        command_line
        start_time
        hash.sha256
    }}

    collect network_connections

    export evidence "{}_evidence.json"
}}"#,
        name, name
    );

    std::fs::write(dir.join(format!("{}.tfg", name)), example)?;

    // Create README
    let readme = format!(
        r#"# {} - TraceForge Investigation

This investigation collects system information, process details, and network connections.

## Building

```bash
traceforge build {}.tfg --target linux --arch x64
```

## Running

```bash
./build/{}-linux-x64
```

## Output

Evidence will be written to `{}_evidence.json` with a SHA-256 hash for integrity verification.
"#,
        name, name, name, name
    );

    std::fs::write(dir.join("README.md"), readme)?;

    println!("Created project: {}", dir.display());
    println!("  Edit {}.tfg to customize your investigation", name);
    println!("  Run `traceforge build {}.tfg` to compile", name);

    Ok(())
}

fn calculate_sha256(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn calculate_compiler_hash() -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let exe_path = std::env::current_exe()?;
    let mut file = std::fs::File::open(exe_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn print_diagnostics(diags: &[traceforge_ast::Diagnostic]) {
    for diag in diags {
        let prefix = match diag.severity {
            traceforge_ast::Severity::Error => "ERROR",
            traceforge_ast::Severity::Warning => "WARNING",
            traceforge_ast::Severity::Info => "INFO",
            traceforge_ast::Severity::Hint => "HINT",
        };
        if let Some(span) = diag.span {
            eprintln!("{}: {} at {}", prefix, diag.message, span);
        } else {
            eprintln!("{}: {}", prefix, diag.message);
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
struct CliConfig {
    api_url: Option<String>,
    token: Option<String>,
    user_email: Option<String>,
}

fn get_config_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(home).join(".traceforge");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn load_config() -> CliConfig {
    let path = get_config_dir().join("config.json");
    if let Ok(data) = std::fs::read(&path) {
        if let Ok(cfg) = serde_json::from_slice::<CliConfig>(&data) {
            return cfg;
        }
    }
    CliConfig {
        api_url: Some("http://localhost:8080".to_string()),
        ..Default::default()
    }
}

fn save_config(cfg: &CliConfig) -> anyhow::Result<()> {
    let path = get_config_dir().join("config.json");
    std::fs::write(path, serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}

fn repo_login(
    email: Option<String>,
    password: Option<String>,
    api_url: &str,
) -> anyhow::Result<()> {
    let email = match email {
        Some(e) => e,
        None => {
            println!("Email: ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };

    let password = match password {
        Some(p) => p,
        None => {
            println!("Password: ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };

    let login_url = format!("{}/api/auth/login", api_url);
    println!("Connecting to {}...", login_url);

    let body = serde_json::json!({
        "email": email,
        "password": password
    });

    let resp: serde_json::Value = match ureq::post(&login_url)
        .set("Content-Type", "application/json")
        .send_json(body)
    {
        Ok(r) => r.into_json()?,
        Err(e) => anyhow::bail!("Login failed: {}", e),
    };

    let token = resp
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("No access token returned"))?;

    let mut cfg = load_config();
    cfg.api_url = Some(api_url.to_string());
    cfg.token = Some(token.to_string());
    cfg.user_email = Some(email.clone());
    save_config(&cfg)?;

    println!("✓ Successfully logged in as {}", email);
    println!(
        "  Auth token stored in {}",
        get_config_dir().join("config.json").display()
    );

    Ok(())
}

fn repo_search(query: &str) -> anyhow::Result<()> {
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let url = if query.is_empty() {
        format!("{}/api/tools", api_url)
    } else {
        format!("{}/api/tools?query={}", api_url, query)
    };

    println!("Searching tools repository (query: '{}')...", query);

    let mut req = ureq::get(&url);
    if let Some(token) = &cfg.token {
        req = req.set("Authorization", &format!("Bearer {}", token));
    }

    let resp: serde_json::Value = req
        .call()
        .map_err(|e| anyhow::anyhow!("Repository search failed: {e}"))?
        .into_json()?;

    println!("{:<28} {:<10} {:<40}", "NAME", "VERSION", "DESCRIPTION");
    println!("{}", "-".repeat(80));

    if let Some(items) = resp.get("data").and_then(|i| i.as_array()) {
        for item in items {
            let name = item
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let version = item
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.1.0");
            let desc = item
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            println!("{:<28} {:<10} {:<40}", name, version, desc);
        }
    }

    Ok(())
}

fn repo_install(tool_name: &str, version: Option<&str>) -> anyhow::Result<()> {
    if version.is_some() {
        anyhow::bail!(
            "Installing a specific repository version is not supported by the current API"
        );
    }
    let tool_id = uuid::Uuid::parse_str(tool_name).map_err(|_| {
        anyhow::anyhow!("Install requires a repository tool UUID, not a local example name")
    })?;
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let token = cfg
        .token
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run traceforge login first"))?;
    println!("Installing '{}'...", tool_id);
    let target_dir = PathBuf::from(".").join("tools");
    std::fs::create_dir_all(&target_dir)?;
    let target_file = target_dir.join(format!("{}.artifact", tool_id));
    let response = ureq::get(&format!("{}/api/tools/{}/download", api_url, tool_id))
        .set("Authorization", &format!("Bearer {}", token))
        .call()
        .map_err(|e| anyhow::anyhow!("Tool download failed: {e}"))?;
    let mut reader = response.into_reader();
    let mut file = std::fs::File::create(&target_file)?;
    std::io::copy(&mut reader, &mut file)?;
    println!("✓ Downloaded tool artifact to {}", target_file.display());

    Ok(())
}

fn repo_list() -> anyhow::Result<()> {
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let token = cfg
        .token
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run traceforge login first"))?;
    let response: serde_json::Value = ureq::get(&format!("{}/api/tools", api_url))
        .set("Authorization", &format!("Bearer {}", token))
        .call()
        .map_err(|e| anyhow::anyhow!("Repository list failed: {e}"))?
        .into_json()?;
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}

fn repo_info(tool: &str) -> anyhow::Result<()> {
    let tool_id = uuid::Uuid::parse_str(tool)
        .map_err(|_| anyhow::anyhow!("Info requires a repository tool UUID"))?;
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let token = cfg
        .token
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run traceforge login first"))?;
    let response: serde_json::Value = ureq::get(&format!("{}/api/tools/{}", api_url, tool_id))
        .set("Authorization", &format!("Bearer {}", token))
        .call()
        .map_err(|e| anyhow::anyhow!("Repository info failed: {e}"))?
        .into_json()?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn repo_update(tool: Option<&str>) -> anyhow::Result<()> {
    let _ = tool;
    anyhow::bail!("Repository update is not implemented by the current API")
}

fn repo_publish(file: &Path, version: &str, description: &str) -> anyhow::Result<()> {
    if !file.is_file() {
        anyhow::bail!("Source file not found: {}", file.display());
    }

    // Step 1: Validate file first
    validate(file)?;

    let source = std::fs::read_to_string(file)?;
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    println!(
        "Publishing {} (version {}) to {}...",
        file.display(),
        version,
        api_url
    );
    println!("Description: {}", description);

    let token = cfg
        .token
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run traceforge login first"))?;
    let tool_name = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("traceforge-tool");
    let tool_response: serde_json::Value = ureq::post(&format!("{}/api/tools", api_url))
        .set("Authorization", &format!("Bearer {}", token))
        .send_json(serde_json::json!({ "name": tool_name, "description": description }))
        .map_err(|e| anyhow::anyhow!("Tool creation failed: {e}"))?
        .into_json()?;
    let tool_id = tool_response
        .get("id")
        .and_then(|id| id.as_str())
        .ok_or_else(|| anyhow::anyhow!("API did not return a tool id"))?;
    let version_response = ureq::post(&format!("{}/api/tools/{}/versions", api_url, tool_id))
        .set("Authorization", &format!("Bearer {}", token))
        .send_json(serde_json::json!({
            "version": version,
            "source": source,
            "target_platform": "windows",
            "target_arch": "x64"
        }))
        .map_err(|e| anyhow::anyhow!("Tool version creation failed: {e}"))?;
    println!(
        "✓ Tool version published to repository (HTTP {})",
        version_response.status()
    );
    println!("  Artifact Hash: {}", calculate_sha256(&source));

    Ok(())
}

fn launch_ide(port: u16) -> anyhow::Result<()> {
    println!("============================================================");
    println!("  TRACEFORGE Forensic Programming Environment");
    println!("============================================================");
    println!("  Opening Web & Desktop Forensic IDE...");
    println!("  Local Web URL: http://localhost:{}", port);
    println!("  API Engine:    http://localhost:8080");
    println!(
        "  Runtime Host:  Local Windows Host ({})",
        whoami::devicename()
    );
    println!("============================================================");

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", &format!("http://localhost:{}", port)])
            .spawn();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(format!("http://localhost:{}", port))
            .spawn();
    }

    Ok(())
}
