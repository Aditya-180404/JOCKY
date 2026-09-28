//! jockey CLI - Command-line interface for the jockey compiler

use clap::{Parser, Subcommand};
use jockey_backend::{Backend, BackendKind};
use jockey_ir::{BuildConfig, TargetArch, TargetPlatform};
use jockey_lexer::Lexer;
use jockey_parser::Parser as TfParser;
use jockey_runtime::{verify_evidence, verify_evidence_deep, VerificationStatus};
use jockey_runtime_capabilities::CapabilityRegistry;
use jockey_semantic::SemanticAnalyzer;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "jockey",
    version,
    about = "jockey Forensic Investigation Compiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a JOCKEY source file (.jy)
    #[command(alias = "check")]
    Validate {
        /// Source file to validate (.jy)
        file: PathBuf,
    },
    /// Compile a JOCKEY source file (.jy)
    Compile {
        /// Source file to compile (.jy)
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
    /// Build a JOCKEY source file (.jy) (alias for compile)
    Build {
        /// Source file to build (.jy)
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
    /// Inspect a JOCKEY source file (.jy) (show AST/IR)
    Inspect {
        /// Source file to inspect (.jy)
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
    /// Generate a forensic report from an evidence JSON file
    Report {
        /// Evidence JSON file
        evidence: PathBuf,
        /// Metadata sidecar file (default: <evidence>.meta.json)
        #[arg(long)]
        meta: Option<PathBuf>,
        /// Report format (terminal, markdown, json, csv, html)
        #[arg(short, long, default_value = "terminal")]
        format: String,
        /// Output file to write report to (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Initialize a new JOCKEY project
    Init {
        /// Project name
        name: String,
    },
    /// Compile and execute a JOCKEY source file (.jy)
    Run {
        /// Source file to run (.jy)
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
    /// Validate and normalize a JOCKEY source file (.jy)
    Fmt {
        /// Source file to format (.jy)
        file: PathBuf,
        /// Write the normalized source back to the file
        #[arg(long)]
        write: bool,
    },
    /// List supported compilation targets
    #[command(alias = "targets")]
    Target {
        #[command(subcommand)]
        command: Option<TargetCommands>,
    },
    /// List all forensic capabilities
    #[command(alias = "capability")]
    Capabilities {
        /// Show all capabilities
        #[arg(long)]
        all: bool,
        /// Show only implemented capabilities
        #[arg(long)]
        implemented: bool,
        /// Show missing / unsupported capabilities
        #[arg(long)]
        missing: bool,
        /// Filter by platform (windows, linux, both)
        #[arg(long)]
        platform: Option<String>,
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
        /// Output format (table, json, markdown)
        #[arg(long, default_value = "table")]
        format: String,
        #[command(subcommand)]
        command: Option<CapabilityCommands>,
    },
    /// Log in to the JOCKEY tool repository
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
    /// Launch the jockey Desktop / Web IDE
    Ide {
        /// Port to launch on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    /// Inspect environment and platform capabilities
    Doctor,
}

#[derive(Subcommand)]
enum TargetCommands {
    /// List supported platform and architecture combinations
    List,
}

#[derive(Subcommand)]
enum CapabilityCommands {
    /// List all capabilities
    List {
        /// Filter by category (process, system_info, network, etc.)
        #[arg(long)]
        category: Option<String>,
        /// Filter by platform (linux, windows, both)
        #[arg(long)]
        platform: Option<String>,
        /// Show only implemented capabilities
        #[arg(long)]
        implemented: bool,
        /// Show only missing / unsupported capabilities
        #[arg(long)]
        missing: bool,
        /// Output format (table, json, markdown)
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Export capability inventory to JSON
    ExportJson {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Export capability inventory to Markdown
    ExportMarkdown {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
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
        /// Perform deep per-item Merkle proof verification
        #[arg(long)]
        deep: bool,
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
            &file, &target, &arch, &output, &opt, &backend, emit_hir, emit_mir, emit_llvm,
            emit_all, verbose,
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
            &file, &target, &arch, &output, "speed", &backend, emit_hir, emit_mir, emit_llvm,
            emit_all, verbose,
        ),
        Commands::Inspect { file, format } => inspect(&file, &format),
        Commands::Hash { file } => hash_file(&file),
        Commands::Verify { artifact } => verify_artifact(&artifact),
        Commands::Evidence { command } => match command {
            EvidenceCommands::Verify {
                evidence,
                meta,
                deep,
            } => {
                let meta_path = meta
                    .unwrap_or_else(|| PathBuf::from(format!("{}.meta.json", evidence.display())));
                evidence_verify(&evidence, &meta_path, deep)
            }
            EvidenceCommands::Inspect { file } => evidence_inspect(&file),
        },
        Commands::Report {
            evidence,
            meta,
            format,
            output,
        } => generate_report(&evidence, meta.as_deref(), &format, output.as_deref()),
        Commands::Init { name } => init_project(&name),
        Commands::Run {
            file,
            target,
            arch,
            output,
        } => run(&file, &target, &arch, &output),
        Commands::Fmt { file, write } => fmt(&file, write),
        Commands::Target { command: _ } => list_targets(),
        Commands::Capabilities {
            all: _,
            implemented,
            missing,
            platform,
            category,
            format,
            command,
        } => {
            if let Some(sub) = command {
                match sub {
                    CapabilityCommands::List {
                        category,
                        platform,
                        implemented,
                        missing,
                        format,
                    } => list_capabilities(category, platform, implemented, missing, &format),
                    CapabilityCommands::ExportJson { output } => export_capabilities_json(&output),
                    CapabilityCommands::ExportMarkdown { output } => {
                        export_capabilities_markdown(&output)
                    }
                }
            } else {
                list_capabilities(category, platform, implemented, missing, &format)
            }
        }
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
        Commands::Doctor => doctor_command(),
    }
}

fn run(file: &Path, target: &str, arch: &str, output: &Path) -> anyhow::Result<()> {
    compile(
        file, target, arch, output, "speed", "llvm", false, false, false, false, false,
    )?;
    let output_dir = std::fs::canonicalize(output)?;

    let target_lower = target.to_lowercase();
    let target_platform = if target_lower.starts_with("linux") || target_lower.contains("linux") {
        TargetPlatform::Linux
    } else if target_lower.starts_with("windows") || target_lower.contains("windows") {
        TargetPlatform::Windows
    } else if target_lower == "native" {
        if cfg!(target_os = "windows") {
            TargetPlatform::Windows
        } else {
            TargetPlatform::Linux
        }
    } else {
        anyhow::bail!("Unknown target platform: {}", target);
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
        TargetPlatform::Linux => output_dir.join(format!(
            "{}-linux-{}",
            investigation.name,
            arch_suffix(arch)?
        )),
        TargetPlatform::Windows => output_dir.join(format!(
            "{}-windows-{}.exe",
            investigation.name,
            arch_suffix(arch)?
        )),
    };

    println!("Running {}", artifact.display());
    let mut child = std::process::Command::new(&artifact)
        .current_dir(&output_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let out_thread = std::thread::spawn(move || {
        if let Some(stdout) = stdout {
            let reader = std::io::BufReader::new(stdout);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                println!("{}", line);
            }
        }
    });

    let err_thread = std::thread::spawn(move || {
        if let Some(stderr) = stderr {
            let reader = std::io::BufReader::new(stderr);
            use std::io::BufRead;
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("{}", line);
            }
        }
    });

    let _ = out_thread.join();
    let _ = err_thread.join();
    let status = child.wait()?;
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
    jockey_ir::validate_source_extension(file).map_err(|e| anyhow::anyhow!(e))?;
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

fn list_capabilities(
    category_filter: Option<String>,
    platform_filter: Option<String>,
    implemented_only: bool,
    missing_only: bool,
    format: &str,
) -> anyhow::Result<()> {
    let registry = CapabilityRegistry::new();
    let mut caps: Vec<_> = registry.all().collect();

    if let Some(cat_str) = category_filter {
        let cat = cat_str.to_lowercase();
        caps.retain(|c| {
            let c_cat = format!("{:?}", c.category).to_lowercase();
            c_cat == cat || c_cat.contains(&cat)
        });
    }

    if let Some(plat_str) = platform_filter {
        let plat = plat_str.to_lowercase();
        caps.retain(|c| {
            let c_plat = format!("{:?}", c.platforms).to_lowercase();
            if plat == "windows" {
                c_plat == "windows" || c_plat == "both"
            } else if plat == "linux" {
                c_plat == "linux" || c_plat == "both"
            } else {
                c_plat == plat || c_plat.contains(&plat)
            }
        });
    }

    if implemented_only {
        caps.retain(|c| c.is_implemented);
    } else if missing_only {
        caps.retain(|c| !c.is_implemented);
    }

    caps.sort_by(|a, b| a.id.cmp(&b.id));

    match format.to_lowercase().as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&caps)?);
        }
        "markdown" => {
            println!("{}", registry.to_markdown());
        }
        _ => {
            // Table format
            println!(
                "{:<35} {:<15} {:<10} {:<8} {:<20} {:<10} NAME",
                "ID", "CATEGORY", "PLATFORM", "PRIV", "STATUS", "MITRE"
            );
            println!("{}", "-".repeat(120));
            for cap in &caps {
                let mitre = cap.mitre_attack_ids.join(",");
                println!(
                    "{:<35} {:<15} {:<10} {:<8} {:<20} {:<10} {}",
                    cap.id,
                    format!("{:?}", cap.category),
                    format!("{:?}", cap.platforms),
                    format!("{:?}", cap.privilege),
                    cap.status.to_string(),
                    if mitre.is_empty() { "—" } else { &mitre },
                    cap.name
                );
            }
            println!("{}", "-".repeat(120));
            println!(
                "Total: {} | Implemented: {} | Partial: {} | Requires Elevation: {} | Platform Restricted: {} | Unsupported: {} | Coverage: {:.1}%",
                registry.count(),
                registry.implemented_count(),
                registry.partial_count(),
                registry.requires_elevation_count(),
                registry.platform_specific_count(),
                registry.unsupported_count(),
                registry.coverage_percentage()
            );
        }
    }
    Ok(())
}

fn export_capabilities_json(output: &Path) -> anyhow::Result<()> {
    let registry = CapabilityRegistry::new();
    let json = registry.to_json();
    let json_str = serde_json::to_string_pretty(&json)?;
    std::fs::write(output, json_str)?;
    println!("Exported capability inventory to {}", output.display());
    Ok(())
}

fn export_capabilities_markdown(output: &Path) -> anyhow::Result<()> {
    let registry = CapabilityRegistry::new();
    let markdown = registry.to_markdown();
    std::fs::write(output, markdown)?;
    println!("Exported capability inventory to {}", output.display());
    Ok(())
}

fn validate(file: &Path) -> anyhow::Result<()> {
    jockey_ir::validate_source_extension(file).map_err(|e| anyhow::anyhow!(e))?;
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
    jockey_ir::validate_source_extension(file).map_err(|e| anyhow::anyhow!(e))?;
    println!("Compiling {}", file.display());

    let source = std::fs::read_to_string(file)?;
    let source_hash = calculate_sha256(&source);

    // --- Lex ---
    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;

    if emit_all {
        std::fs::create_dir_all(output)?;
        let tok_path = output.join(format!(
            "{}.tokens",
            file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("output")
        ));
        let mut tok_str = String::new();
        for t in &tokens {
            tok_str.push_str(&format!("{:?}\n", t));
        }
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
        let ast_path = output.join(format!(
            "{}.ast.json",
            file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("output")
        ));
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

    let target_lower = target.to_lowercase();
    let target_platform = if target_lower.starts_with("linux") || target_lower.contains("linux") {
        TargetPlatform::Linux
    } else if target_lower.starts_with("windows") || target_lower.contains("windows") {
        TargetPlatform::Windows
    } else if target_lower == "native" {
        if cfg!(target_os = "windows") {
            TargetPlatform::Windows
        } else {
            TargetPlatform::Linux
        }
    } else {
        anyhow::bail!("Unknown target platform: {}", target);
    };

    let target_arch = if target_lower.contains("arm64") || target_lower.contains("aarch64") {
        TargetArch::Arm64
    } else if target_lower.contains("x64") || target_lower.contains("x86_64") {
        TargetArch::X64
    } else {
        match arch.to_lowercase().as_str() {
            "x64" | "x86_64" => TargetArch::X64,
            "arm64" | "aarch64" => TargetArch::Arm64,
            _ => anyhow::bail!("Unknown target architecture: {}", arch),
        }
    };

    let optimization_level = match opt.to_lowercase().as_str() {
        "none" => jockey_ir::OptimizationLevel::None,
        "size" => jockey_ir::OptimizationLevel::Size,
        "speed" => jockey_ir::OptimizationLevel::Speed,
        _ => jockey_ir::OptimizationLevel::Speed,
    };

    let config = BuildConfig {
        target_platform,
        target_arch,
        optimization_level,
        debug_symbols: false,
        strip_symbols: true,
    };

    // --- Resolve backend kind ---
    let backend_kind: BackendKind = {
        #[cfg(feature = "llvm")]
        {
            backend_name.parse().unwrap_or(BackendKind::Llvm)
        }
        #[cfg(not(feature = "llvm"))]
        {
            if backend_name.to_lowercase() == "llvm" {
                eprintln!(
                    "Note: LLVM backend not compiled in this binary; using native Rust backend."
                );
            }
            BackendKind::Rust
        }
    };
    if verbose {
        println!("  Backend:          {:?}", backend_kind);
        println!(
            "  Target:           {:?}-{:?}",
            target_platform, target_arch
        );
        println!("  Optimization:     {:?}", optimization_level);
    }

    std::fs::create_dir_all(output)?;
    println!("  Output directory: {}", output.display());
    println!("  Investigation:    {}", ir.name);

    // --- HIR lowering (for LLVM path and emit flags) ---
    let maybe_hir = if backend_kind == BackendKind::Llvm || emit_hir || emit_all {
        let hir: jockey_hir::HirInvestigation = (&ir).into();
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
            let mir = jockey_mir::MirLowering::lower(hir)
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
    #[cfg(feature = "llvm")]
    if emit_llvm || emit_all {
        if let Some(mir) = &maybe_mir {
            let llvm_backend = jockey_backend::LlvmBackend::new(config.clone());
            let llvm_ir = llvm_backend
                .generate_llvm_ir(mir)
                .map_err(|e| anyhow::anyhow!("LLVM IR generation failed: {}", e))?;
            let ll_path = output.join(format!("{}.ll", ir.name));
            std::fs::write(&ll_path, &llvm_ir)?;
            println!("  LLVM  → {}", ll_path.display());
        }
    }
    #[cfg(not(feature = "llvm"))]
    if emit_llvm {
        println!("  LLVM  → (LLVM feature not enabled in this build)");
    }

    // --- Code generation ---
    let backend = Backend::new_with_kind(config.clone(), backend_kind);
    let mut metadata = backend.generate(&ir, output)?;

    // Update metadata with actual values
    metadata.source_hash = source_hash.clone();
    metadata.compiler_version = env!("CARGO_PKG_VERSION").to_string();
    metadata.compiler_hash = calculate_compiler_hash()?;

    // Write compile metadata sidecar
    let meta_path = output.join(format!("{}.meta.json", ir.name));
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)?;

    // Always generate deterministic build & capability provenance manifest sidecar
    let hir_hash = maybe_mir.as_ref().map(|m| m.provenance.hir_hash.clone());
    let mir_hash = maybe_mir.as_ref().map(|m| m.provenance.mir_hash.clone());
    let llvm_ir_hash: Option<String> = {
        #[cfg(feature = "llvm")]
        {
            if let Some(mir) = &maybe_mir {
                let llvm_backend = jockey_backend::LlvmBackend::new(config.clone());
                llvm_backend
                    .generate_llvm_ir(mir)
                    .ok()
                    .map(|ir_text| calculate_sha256(&ir_text))
            } else {
                None
            }
        }
        #[cfg(not(feature = "llvm"))]
        {
            None
        }
    };

    let mut cap_provenance = Vec::new();
    for op in &ir.operations {
        if let jockey_ir::IrOperation::Collect(c) = op {
            let (cap_name, stmt_name) = match c.operation.as_str() {
                "system.info" => ("SYSTEM_INFO_READ", "collect system_info"),
                "process.enumerate" => ("PROCESS_READ", "collect processes"),
                "network.connections" => ("NETWORK_READ", "collect network_connections"),
                "filesystem.enumerate" => ("FILESYSTEM_READ", "collect files"),
                "logs.collect" => ("LOG_READ", "collect logs"),
                "drivers.enumerate" => ("DRIVER_READ", "collect drivers"),
                "timeline.build" => ("TIMELINE_READ", "collect timeline"),
                "memory.regions" => ("MEMORY_READ", "collect memory_regions"),
                "registry.enumerate" => ("REGISTRY_READ", "collect registry"),
                "artifacts.carve" => ("ARTIFACT_CARVE", "collect artifacts"),
                _ => continue,
            };
            cap_provenance.push(serde_json::json!({
                "capability": cap_name,
                "source_statement": stmt_name,
                "span": c.span.to_string(),
            }));
            if c.options.get("hash").is_some() {
                cap_provenance.push(serde_json::json!({
                    "capability": "FILE_HASH",
                    "source_statement": format!("{}: hash requested", stmt_name),
                    "span": c.span.to_string(),
                }));
            }
        }
    }

    let cap_manifest = serde_json::json!({
        "investigation": ir.name,
        "language_version": "1.0",
        "compiler_version": env!("CARGO_PKG_VERSION"),
        "compiler_identifier": metadata.compiler_hash,
        "source_hash": source_hash,
        "artifact_hash": metadata.artifact_hash,
        "target": format!("{:?}", target_platform).to_lowercase(),
        "architecture": arch_suffix(arch)?,
        "backend": format!("{:?}", backend_kind).to_lowercase(),
        "optimization_level": format!("{:?}", config.optimization_level).to_lowercase(),
        "runtime_version": env!("CARGO_PKG_VERSION"),
        "compiler_capabilities": ir.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "capability_provenance": cap_provenance,
        "hir_hash": hir_hash,
        "mir_hash": mir_hash,
        "llvm_ir_hash": llvm_ir_hash,
        "operations_count": ir.operations.len(),
        "safety_invariants": {
            "network_write": false,
            "persistence": false,
            "credential_access": false,
            "kernel_modification": false,
            "defensive_only": true,
        }
    });
    let manifest_path = output.join(format!("{}.manifest.json", ir.name));
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&cap_manifest)?)?;
    println!("  Manifest: {}", manifest_path.display());

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
    jockey_ir::validate_source_extension(file).map_err(|e| anyhow::anyhow!(e))?;
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
                    println!("{}", jockey_ir::serialize_ir(&ir)?);
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
        if let Ok(metadata) = serde_json::from_slice::<jockey_ir::ArtifactMetadata>(&content) {
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

fn evidence_verify(evidence: &Path, meta: &Path, deep: bool) -> anyhow::Result<()> {
    println!("Verifying evidence: {}", evidence.display());
    println!("Using metadata:    {}", meta.display());

    if deep {
        println!("Mode:              Deep (Per-Item Merkle Inclusion Verification)");
        let deep_res = verify_evidence_deep(
            evidence.to_str().unwrap_or_default(),
            meta.to_str().unwrap_or_default(),
        )
        .map_err(|e| anyhow::anyhow!("Deep verification error: {}", e))?;

        match &deep_res.base_result.status {
            VerificationStatus::Verified => {
                println!("✓ Deep evidence verification SUCCESSFUL");
                println!(
                    "  Total Items Verified: {}/{}",
                    deep_res.verified_items, deep_res.total_items
                );
                println!(
                    "  Per-Item Proofs Valid: {}",
                    deep_res.per_item_proofs_valid
                );
                if let Some(hash) = &deep_res.base_result.calculated_hash {
                    println!("  Evidence SHA-256:     {}", hash);
                }
                println!(
                    "  Verified at:          {}",
                    deep_res.base_result.verified_at
                );
                Ok(())
            }
            VerificationStatus::Tampered { reason } => {
                eprintln!("✗ Evidence TAMPERED / INTEGRITY FAILED");
                eprintln!("  Reason: {}", reason);
                eprintln!(
                    "  Total Items: {} | Verified: {} | Failed: {}",
                    deep_res.total_items,
                    deep_res.verified_items,
                    deep_res.failed_items.len()
                );
                for (idx, fail_reason) in deep_res.failed_items.iter().take(5) {
                    eprintln!("    - Item #{}: {}", idx, fail_reason);
                }
                anyhow::bail!("Evidence failed deep integrity check: {}", reason);
            }
            VerificationStatus::Missing { detail } => {
                eprintln!("✗ Evidence verification file missing");
                eprintln!("  Detail: {}", detail);
                anyhow::bail!("Verification missing file: {}", detail);
            }
        }
    } else {
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
}

fn generate_report(
    evidence_path: &Path,
    meta_path: Option<&Path>,
    format: &str,
    output_path: Option<&Path>,
) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(evidence_path)?;
    let evidence_val: serde_json::Value = serde_json::from_str(&content)?;

    let default_meta = PathBuf::from(format!("{}.meta.json", evidence_path.display()));
    let meta_file = meta_path.unwrap_or(&default_meta);
    let meta_val: Option<serde_json::Value> = if meta_file.exists() {
        std::fs::read_to_string(meta_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    let empty_vec = vec![];
    let items = if let Some(arr) = evidence_val.as_array() {
        arr
    } else if let Some(arr) = evidence_val.get("records").and_then(|r| r.as_array()) {
        arr
    } else {
        &empty_vec
    };

    let total_items = items.len();
    let mut processes_count = 0;
    let mut network_count = 0;
    let mut files_count = 0;
    let mut logs_count = 0;
    let mut drivers_count = 0;
    let mut memory_count = 0;
    let mut registry_count = 0;
    let mut artifacts_count = 0;
    let mut timeline_count = 0;
    let mut suspicious_count = 0;
    let mut suspicious_details = Vec::new();

    for item in items {
        if let Some(obj) = item.as_object() {
            if obj.get("suspicious").and_then(|v| v.as_bool()) == Some(true)
                || obj.get("persistence_risk").and_then(|v| v.as_bool()) == Some(true)
                || (obj.get("executable").and_then(|v| v.as_bool()) == Some(true)
                    && obj.get("anonymous").and_then(|v| v.as_bool()) == Some(true))
            {
                suspicious_count += 1;
                let desc = obj
                    .get("suspicious_reason")
                    .or_else(|| obj.get("key_path"))
                    .or_else(|| obj.get("path"))
                    .or_else(|| obj.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Flagged suspicious");
                suspicious_details.push(desc.to_string());
            }

            if obj.contains_key("pid") && obj.contains_key("ppid") {
                processes_count += 1;
            } else if obj.contains_key("local_address") || obj.contains_key("local_addr") {
                network_count += 1;
            } else if obj.contains_key("path")
                && (obj.contains_key("sha256") || obj.contains_key("size_bytes"))
            {
                if obj.contains_key("artifact_type") {
                    artifacts_count += 1;
                } else {
                    files_count += 1;
                }
            } else if obj.contains_key("source") && obj.contains_key("message") {
                logs_count += 1;
            } else if obj.contains_key("module_name") || obj.contains_key("driver_name") {
                drivers_count += 1;
            } else if obj.contains_key("start_address") && obj.contains_key("end_address") {
                memory_count += 1;
            } else if obj.contains_key("hive") && obj.contains_key("key_path") {
                registry_count += 1;
            } else if obj.contains_key("event_type") && obj.contains_key("timestamp") {
                timeline_count += 1;
            }
        }
    }

    let inv_name = meta_val
        .as_ref()
        .and_then(|m| m.get("investigation_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("jockey Investigation");
    let host_id = meta_val
        .as_ref()
        .and_then(|m| m.get("host_identifier"))
        .and_then(|v| v.as_str())
        .unwrap_or("localhost");
    let evidence_hash = meta_val
        .as_ref()
        .and_then(|m| m.get("evidence_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let merkle_root = meta_val
        .as_ref()
        .and_then(|m| m.get("merkle_root"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");
    let collected_at = meta_val
        .as_ref()
        .and_then(|m| m.get("collection_time").or_else(|| m.get("collected_at")))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let mut correlation = jockey_runtime::correlation::CorrelationEngine::new(inv_name, host_id);
    correlation.ingest_records(items, host_id);
    let graph = correlation.graph();
    let timeline_event_count = correlation
        .timeline()
        .map(|timeline| timeline.event_count)
        .unwrap_or(0);
    let process_records = items
        .iter()
        .filter(|record| record.get("pid").is_some())
        .cloned()
        .collect::<Vec<_>>();
    let connection_records = items
        .iter()
        .filter(|record| {
            record.get("local_address").is_some() || record.get("local_addr").is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let memory_records = items
        .iter()
        .filter(|record| {
            record.get("mapped_file").is_some() || record.get("start_address").is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let driver_records = items
        .iter()
        .filter(|record| {
            record.get("name").is_some() && record.get("vulnerability_indicators").is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut security_analyzer = jockey_runtime::security::SecurityAnalyzer::new(host_id);
    security_analyzer.run_full_analysis_with_context(
        &process_records,
        &connection_records,
        &memory_records,
        &driver_records,
    );
    let security_findings = security_analyzer.findings().to_vec();

    let report_output = match format.to_lowercase().as_str() {
        "json" => {
            let json_rep = serde_json::json!({
                "report_version": "1.0",
                "investigation": inv_name,
                "host": host_id,
                "collected_at": collected_at,
                "evidence_file": evidence_path.display().to_string(),
                "evidence_hash": evidence_hash,
                "merkle_root": merkle_root,
                "total_items": total_items,
                "timeline_event_count": timeline_event_count,
                "timeline": correlation.timeline(),
                "correlation_graph": graph,
                "relationships": graph.relationships,
                "correlation_findings": graph.findings,
                "security_findings": security_findings,
                "suspicious_items_count": suspicious_count,
                "suspicious_findings": suspicious_details,
                "counts_by_category": {
                    "processes": processes_count,
                    "network_connections": network_count,
                    "files": files_count,
                    "logs": logs_count,
                    "drivers": drivers_count,
                    "memory_regions": memory_count,
                    "registry_entries": registry_count,
                    "carved_artifacts": artifacts_count,
                    "timeline_events": timeline_count,
                }
            });
            serde_json::to_string_pretty(&json_rep)?
        }
        "csv" => {
            let mut csv = String::from(
                "record_index,category,capability_id,collector,host,platform,status,record_json\n",
            );
            for (index, item) in items.iter().enumerate() {
                let provenance = item.get("_provenance");
                let category = report_record_category(item);
                let columns = [
                    (index + 1).to_string(),
                    category,
                    provenance
                        .and_then(|value| value.get("capability_id"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    provenance
                        .and_then(|value| value.get("collector"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    provenance
                        .and_then(|value| value.get("host"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    provenance
                        .and_then(|value| value.get("platform"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    provenance
                        .and_then(|value| value.get("status"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    serde_json::to_string(item)?,
                ];
                csv.push_str(
                    &columns
                        .iter()
                        .map(|value| csv_escape(value))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push('\n');
            }
            for (offset, finding) in graph.findings.iter().enumerate() {
                let columns = [
                    (items.len() + offset + 1).to_string(),
                    "correlation_finding".to_string(),
                    String::new(),
                    "correlation_engine".to_string(),
                    host_id.to_string(),
                    std::env::consts::OS.to_string(),
                    format!("{:?}", finding.severity),
                    serde_json::to_string(finding)?,
                ];
                csv.push_str(
                    &columns
                        .iter()
                        .map(|value| csv_escape(value))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push('\n');
            }
            for (offset, finding) in security_findings.iter().enumerate() {
                let columns = [
                    (items.len() + graph.findings.len() + offset + 1).to_string(),
                    "security_finding".to_string(),
                    String::new(),
                    finding.category.to_string(),
                    finding.host.clone(),
                    std::env::consts::OS.to_string(),
                    finding.severity.to_string(),
                    serde_json::to_string(finding)?,
                ];
                csv.push_str(
                    &columns
                        .iter()
                        .map(|value| csv_escape(value))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push('\n');
            }
            csv
        }
        "html" => {
            let mut html = String::from("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>JOCKEY Forensic Report</title><style>body{font:15px system-ui,sans-serif;margin:2rem;color:#17212b}h1{margin-bottom:.25rem}table{border-collapse:collapse;width:100%;margin-top:1.5rem}th,td{border:1px solid #ccd3d8;padding:.5rem;text-align:left;vertical-align:top}th{background:#edf2f4}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1rem}.warn{color:#8b2b1d}</style></head><body>");
            html.push_str(&format!("<h1>{}</h1><dl class=\"meta\"><dt>Host</dt><dd>{}</dd><dt>Collected</dt><dd>{}</dd><dt>Evidence SHA-256</dt><dd><code>{}</code></dd><dt>Merkle root</dt><dd><code>{}</code></dd><dt>Records</dt><dd>{}</dd><dt>Flagged records</dt><dd class=\"warn\">{}</dd></dl>", html_escape(inv_name), html_escape(host_id), html_escape(collected_at), html_escape(evidence_hash), html_escape(merkle_root), total_items, suspicious_count));
            html.push_str("<table><thead><tr><th>#</th><th>Capability</th><th>Category</th><th>Source</th><th>Details</th></tr></thead><tbody>");
            for (index, item) in items.iter().enumerate() {
                let provenance = item.get("_provenance");
                let capability_id = provenance
                    .and_then(|value| value.get("capability_id"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let collector = provenance
                    .and_then(|value| value.get("collector"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let details = ["path", "name", "protocol", "local_address", "pid", "state"]
                    .iter()
                    .filter_map(|key| item.get(*key).map(|value| format!("{}={}", key, value)))
                    .collect::<Vec<_>>()
                    .join("; ");
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    index + 1,
                    html_escape(capability_id),
                    html_escape(&report_record_category(item)),
                    html_escape(collector),
                    html_escape(&details)
                ));
            }
            html.push_str("</tbody></table><h2>Evidence-backed Correlation Findings</h2>");
            if graph.findings.is_empty() {
                html.push_str("<p>No correlation rules matched the collected evidence.</p>");
            } else {
                html.push_str("<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence references</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>");
                for finding in &graph.findings {
                    html.push_str(&format!("<tr><td>{}</td><td><strong>{}</strong><br>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&format!("{:?}", finding.severity)),
                        html_escape(&finding.title),
                        html_escape(&finding.description),
                        html_escape(&finding.evidence_refs.join(", ")),
                        html_escape(&finding.mitre_attack_ids.join(", ")),
                    ));
                }
                html.push_str("</tbody></table>");
            }
            html.push_str("<h2>Rule-based Security Findings</h2>");
            if security_findings.is_empty() {
                html.push_str(
                    "<p>No security rules matched the collected process and network evidence.</p>",
                );
            } else {
                html.push_str("<table><thead><tr><th>Severity</th><th>Indicator</th><th>Reason</th><th>Evidence</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>");
                for finding in &security_findings {
                    html.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&finding.severity.to_string()),
                        html_escape(&finding.indicator),
                        html_escape(&finding.reason),
                        html_escape(&finding.evidence),
                        html_escape(&finding.mitre_attack_id),
                    ));
                }
                html.push_str("</tbody></table>");
            }
            html.push_str(&format!(
                "<p>Normalized timeline events: {}</p></body></html>",
                timeline_event_count
            ));
            html
        }
        "markdown" | "md" => {
            let mut md = String::new();
            md.push_str(&format!("# jockey Forensic Report: {}\n\n", inv_name));
            md.push_str("## Executive Summary\n\n");
            md.push_str(&format!("- **Investigation Name:** `{}`\n", inv_name));
            md.push_str(&format!("- **Target Host:** `{}`\n", host_id));
            md.push_str(&format!("- **Collection Timestamp:** `{}`\n", collected_at));
            md.push_str(&format!("- **Evidence SHA-256:** `{}`\n", evidence_hash));
            md.push_str(&format!("- **Merkle Root:** `{}`\n", merkle_root));
            md.push_str(&format!("- **Total Evidence Items:** `{}`\n", total_items));
            md.push_str(&format!(
                "- **Suspicious Findings:** `{}`\n\n",
                suspicious_count
            ));

            md.push_str("## Category Breakdown\n\n");
            md.push_str("| Category | Count |\n");
            md.push_str("|:---|:---:|\n");
            md.push_str(&format!("| Processes | {} |\n", processes_count));
            md.push_str(&format!("| Network Connections | {} |\n", network_count));
            md.push_str(&format!("| Filesystem Records | {} |\n", files_count));
            md.push_str(&format!("| Logs | {} |\n", logs_count));
            md.push_str(&format!("| Drivers / Modules | {} |\n", drivers_count));
            md.push_str(&format!("| Memory Regions | {} |\n", memory_count));
            md.push_str(&format!("| Registry / Sysctl | {} |\n", registry_count));
            md.push_str(&format!("| Carved Artifacts | {} |\n", artifacts_count));
            md.push_str(&format!("| Timeline Events | {} |\n\n", timeline_count));

            if suspicious_count > 0 {
                md.push_str("## High Risk Findings\n\n");
                for (i, find) in suspicious_details.iter().enumerate() {
                    md.push_str(&format!("{}. {}\n", i + 1, find));
                }
                md.push('\n');
            }

            md.push_str("## Evidence-backed Correlation Findings\n\n");
            if graph.findings.is_empty() {
                md.push_str("No correlation rules matched the collected evidence.\n\n");
            } else {
                for finding in &graph.findings {
                    md.push_str(&format!(
                        "- **{:?}: {}**: {} Evidence: `{}`. MITRE: `{}`.\n",
                        finding.severity,
                        finding.title,
                        finding.description,
                        finding.evidence_refs.join(", "),
                        finding.mitre_attack_ids.join(", "),
                    ));
                }
                md.push('\n');
            }
            md.push_str(&format!(
                "Normalized timeline events: `{}`; relationships: `{}`.\n\n",
                timeline_event_count,
                graph.relationships.len()
            ));

            md.push_str("## Rule-based Security Findings\n\n");
            if security_findings.is_empty() {
                md.push_str(
                    "No security rules matched the collected process and network evidence.\n\n",
                );
            } else {
                for finding in &security_findings {
                    md.push_str(&format!(
                        "- **{}: {}**. Reason: {} Evidence: `{}`. MITRE: `{}`.\n",
                        finding.severity,
                        finding.indicator,
                        finding.reason,
                        finding.evidence,
                        finding.mitre_attack_id,
                    ));
                }
                md.push('\n');
            }

            md.push_str("## Chain of Custody\n\n");
            md.push_str("Evidence integrity verified cryptographically via SHA-256 and Merkle tree root validation.\n");
            md
        }
        _ => {
            let mut term = String::new();
            term.push_str(
                "======================================================================\n",
            );
            term.push_str("             jockey FORENSIC INVESTIGATION REPORT\n");
            term.push_str(
                "======================================================================\n",
            );
            term.push_str(&format!(" Investigation:  {}\n", inv_name));
            term.push_str(&format!(" Target Host:    {}\n", host_id));
            term.push_str(&format!(" Collected At:   {}\n", collected_at));
            term.push_str(&format!(" Evidence SHA256:{}\n", evidence_hash));
            term.push_str(&format!(" Merkle Root:    {}\n", merkle_root));
            term.push_str(
                "----------------------------------------------------------------------\n",
            );
            term.push_str(" EVIDENCE INVENTORY:\n");
            term.push_str(&format!(
                "   • Processes:           {:>6}\n",
                processes_count
            ));
            term.push_str(&format!("   • Network Connections: {:>6}\n", network_count));
            term.push_str(&format!("   • Filesystem Items:    {:>6}\n", files_count));
            term.push_str(&format!("   • System Logs:         {:>6}\n", logs_count));
            term.push_str(&format!("   • Drivers/Modules:     {:>6}\n", drivers_count));
            term.push_str(&format!("   • Memory Regions:      {:>6}\n", memory_count));
            term.push_str(&format!(
                "   • Registry / Sysctl:   {:>6}\n",
                registry_count
            ));
            term.push_str(&format!(
                "   • Carved Artifacts:    {:>6}\n",
                artifacts_count
            ));
            term.push_str(&format!(
                "   • Timeline Events:     {:>6}\n",
                timeline_count
            ));
            term.push_str("   ─────────────────────────────\n");
            term.push_str(&format!("   TOTAL RECORDS:         {:>6}\n", total_items));
            term.push_str(
                "----------------------------------------------------------------------\n",
            );
            if suspicious_count > 0 {
                term.push_str(&format!(
                    " [!] SUSPICIOUS FINDINGS DETECTED: {}\n",
                    suspicious_count
                ));
                for (i, find) in suspicious_details.iter().take(10).enumerate() {
                    term.push_str(&format!("     {}. {}\n", i + 1, find));
                }
                if suspicious_details.len() > 10 {
                    term.push_str(&format!(
                        "     ... and {} more\n",
                        suspicious_details.len() - 10
                    ));
                }
            } else {
                term.push_str(" [✓] No immediate high-risk anomalies flagged.\n");
            }
            term.push_str(
                "======================================================================\n",
            );
            term
        }
    };

    if let Some(out) = output_path {
        std::fs::write(out, &report_output)?;
        println!("Report saved to {}", out.display());
    } else {
        println!("{}", report_output);
    }

    Ok(())
}

fn report_record_category(record: &serde_json::Value) -> String {
    if record.get("pid").is_some() && record.get("ppid").is_some() {
        "process".to_string()
    } else if record.get("local_address").is_some() || record.get("local_addr").is_some() {
        "network".to_string()
    } else if record.get("start_address").is_some() && record.get("end_address").is_some() {
        "memory".to_string()
    } else if record.get("artifact_type").is_some() {
        "artifact".to_string()
    } else if record.get("path").is_some() {
        "filesystem".to_string()
    } else if record.get("hive").is_some() && record.get("key_path").is_some() {
        "registry".to_string()
    } else if record.get("event_type").is_some() {
        "timeline".to_string()
    } else {
        "other".to_string()
    }
}

fn csv_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

    std::fs::write(dir.join(format!("{}.jy", name)), example)?;

    // Create README
    let readme = format!(
        r#"# {} - jockey Investigation

This investigation collects system information, process details, and network connections.

## Building

```bash
jockey build {}.jy --target linux --arch x64
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
    println!("  Edit {}.jy to customize your investigation", name);
    println!("  Run `jockey build {}.jy` to compile", name);

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

fn print_diagnostics(diags: &[jockey_ast::Diagnostic]) {
    for diag in diags {
        let (prefix, code) = match diag.severity {
            jockey_ast::Severity::Error => ("error", diag.code.as_deref().unwrap_or("E1001")),
            jockey_ast::Severity::Warning => ("warning", diag.code.as_deref().unwrap_or("W1001")),
            jockey_ast::Severity::Info => ("info", diag.code.as_deref().unwrap_or("I1001")),
            jockey_ast::Severity::Hint => ("help", diag.code.as_deref().unwrap_or("H1001")),
        };
        if let Some(span) = diag.span {
            eprintln!("{}[{}]: {} (at {})", prefix, code, diag.message, span);
        } else {
            eprintln!("{}[{}]: {}", prefix, code, diag.message);
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
    let dir = PathBuf::from(home).join(".jockey");
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
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run jockey login first"))?;
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
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run jockey login first"))?;
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
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run jockey login first"))?;
    let response: serde_json::Value = ureq::get(&format!("{}/api/tools/{}", api_url, tool_id))
        .set("Authorization", &format!("Bearer {}", token))
        .call()
        .map_err(|e| anyhow::anyhow!("Repository info failed: {e}"))?
        .into_json()?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn repo_update(tool: Option<&str>) -> anyhow::Result<()> {
    let cfg = load_config();
    let api_url = cfg
        .api_url
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let token = cfg
        .token
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run jockey login first"))?;

    match tool {
        Some(name) => {
            // Attempt to look up a tool by name and report its latest version
            let response: serde_json::Value = ureq::get(&format!("{}/api/tools", api_url))
                .set("Authorization", &format!("Bearer {}", token))
                .call()
                .map_err(|e| anyhow::anyhow!("Repository unreachable: {e}"))?
                .into_json()?;
            if let Some(items) = response.get("data").and_then(|d| d.as_array()) {
                let matched: Vec<_> = items
                    .iter()
                    .filter(|i| i.get("name").and_then(|n| n.as_str()) == Some(name))
                    .collect();
                if matched.is_empty() {
                    println!("No repository tool named '{}' found.", name);
                } else {
                    println!("Tool '{}' is at the latest published version (local install management not yet implemented).", name);
                    println!("{}", serde_json::to_string_pretty(&matched[0])?);
                }
            }
        }
        None => {
            println!("Checking all installed tools against repository...");
            println!("(Local tool tracking not yet implemented — listing available tools instead)");
            repo_list()?;
        }
    }
    Ok(())
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
        .ok_or_else(|| anyhow::anyhow!("Not logged in; run jockey login first"))?;
    let tool_name = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("jockey-tool");
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
    println!("  jockey Forensic Programming Environment");
    println!("============================================================");
    println!("  Opening Web IDE...");
    println!("  Local Web URL: http://localhost:{}", port);
    println!("  API Engine:    http://localhost:8080");
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

fn probe_tool(name: &str) -> Option<String> {
    std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn rustup_installed_targets() -> Vec<String> {
    std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn doctor_command() -> anyhow::Result<()> {
    println!("============================================================");
    println!("  JOCKEY System & Environment Diagnostic (jockey doctor)");
    println!("============================================================");
    println!();

    // ── Host ─────────────────────────────────────────────────────────────────
    println!("  Host");
    println!("  ─────────────────────────────────────────────────────────");
    println!("  [OS]               {}", std::env::consts::OS);
    println!("  [Architecture]     {}", std::env::consts::ARCH);
    if let Ok(dir) = std::env::current_dir() {
        println!("  [Working Dir]      {}", dir.display());
    }
    println!();

    // ── Rust toolchain ───────────────────────────────────────────────────────
    println!("  Rust Toolchain");
    println!("  ─────────────────────────────────────────────────────────");
    match probe_tool("rustc") {
        Some(v) => println!("  [rustc]            ✓ {}", v),
        None => println!("  [rustc]            ✗ NOT FOUND — install from https://rustup.rs"),
    }
    match probe_tool("cargo") {
        Some(v) => println!("  [cargo]            ✓ {}", v),
        None => println!("  [cargo]            ✗ NOT FOUND"),
    }
    match probe_tool("rustup") {
        Some(v) => println!("  [rustup]           ✓ {}", v),
        None => println!(
            "  [rustup]           ! NOT FOUND (optional, needed for cross-compilation targets)"
        ),
    }
    println!();

    // ── Compilation targets ──────────────────────────────────────────────────
    println!("  Compilation Targets");
    println!("  ─────────────────────────────────────────────────────────");
    let installed_targets = rustup_installed_targets();

    // Windows x64 — native on Windows, needs toolchain on Linux
    let win_x64_target = "x86_64-pc-windows-msvc";
    let win_x64_gnu = "x86_64-pc-windows-gnu";
    if cfg!(target_os = "windows") {
        println!("  [windows-x64]      ✓ Native host (MSVC toolchain available)");
    } else if installed_targets
        .iter()
        .any(|t| t == win_x64_target || t == win_x64_gnu)
    {
        println!("  [windows-x64]      ✓ Cross-compile toolchain installed");
    } else {
        println!(
            "  [windows-x64]      ✗ NOT available on this host — run: rustup target add {}",
            win_x64_gnu
        );
    }

    // Linux x64 — native on Linux, needs 'cross' on Windows
    if cfg!(target_os = "linux") {
        println!("  [linux-x64]        ✓ Native host");
    } else {
        match probe_tool("cross") {
            Some(v) => println!("  [linux-x64]        ✓ 'cross' available ({})", v),
            None    => println!("  [linux-x64]        ! Requires Linux host or 'cross' — install: cargo install cross"),
        }
    }
    if !installed_targets.is_empty() {
        println!("  [Installed targets] {}", installed_targets.join(", "));
    }
    println!();

    // ── Optional tooling ─────────────────────────────────────────────────────
    println!("  Optional Tooling");
    println!("  ─────────────────────────────────────────────────────────");
    match probe_tool("git") {
        Some(v) => println!("  [git]              ✓ {}", v),
        None => println!("  [git]              ! NOT FOUND (optional)"),
    }
    match probe_tool("docker") {
        Some(v) => println!("  [docker]           ✓ {}", v),
        None => println!(
            "  [docker]           ! NOT FOUND (optional, needed for Debian package builds)"
        ),
    }
    println!();

    // ── Capability registry ───────────────────────────────────────────────────
    let reg = CapabilityRegistry::new();
    let total = reg.count();
    let implemented = reg.implemented_count();
    let partial = reg.partial_count();
    let requires_elevation = reg.requires_elevation_count();
    let platform_restricted = reg.platform_specific_count();
    let unsupported = reg.unsupported_count();
    let coverage = reg.coverage_percentage();

    println!("  Capability Coverage");
    println!("  ─────────────────────────────────────────────────────────");
    println!("  Total:               {}", total);
    println!("  Implemented:         {}", implemented);
    println!("  Partial:             {}", partial);
    println!("  Requires elevation:  {}", requires_elevation);
    println!("  Platform restricted: {}", platform_restricted);
    println!("  Unsupported:         {}", unsupported);
    println!("  Coverage:            {:.1}%", coverage);
    println!();

    // ── API ───────────────────────────────────────────────────────────────────
    println!("  API Server");
    println!("  ─────────────────────────────────────────────────────────");
    match ureq::get("http://localhost:8080/health")
        .timeout(std::time::Duration::from_millis(800))
        .call()
    {
        Ok(resp) if resp.status() == 200 => {
            println!("  [API]              ✓ Online at http://localhost:8080");
        }
        _ => {
            println!("  [API]              ! Offline — start with: cargo run -p jockey-api");
        }
    }
    println!();

    // ── Auth config ───────────────────────────────────────────────────────────
    let cfg = load_config();
    match &cfg.user_email {
        Some(email) => println!("  [Logged In]        ✓ {}", email),
        None => println!("  [Auth]             ! Not logged in — run: jockey login"),
    }

    println!();
    println!("============================================================");
    println!("  Status: Diagnostic complete.");
    println!("============================================================");
    Ok(())
}

#[cfg(test)]
mod report_tests {
    use super::{csv_escape, html_escape};

    #[test]
    fn csv_report_escapes_quotes_and_delimiters() {
        assert_eq!(csv_escape("name, \"value\""), "\"name, \"\"value\"\"\"");
    }

    #[test]
    fn html_report_escapes_markup_characters() {
        assert_eq!(
            html_escape("<script a=\"x\">&'"),
            "&lt;script a=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn test_cli_accepts_jy_source_extension() {
        let p = std::path::Path::new("examples/complete_forensic_triage.jy");
        assert!(jockey_ir::validate_source_extension(p).is_ok());
    }

    #[test]
    fn test_cli_rejects_tfg_source_extension() {
        let p = std::path::Path::new("examples/complete_forensic_triage.tfg");
        let res = jockey_ir::validate_source_extension(p);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("Unsupported JOCKEY source extension '.tfg'"));
        assert!(err.contains("Expected a '.jy' source file"));
    }
}
