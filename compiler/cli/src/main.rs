//! TraceForge CLI - Command-line interface for the TraceForge compiler

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use traceforge_ir::{BuildConfig, TargetArch, TargetPlatform};
use traceforge_lexer::Lexer;
use traceforge_parser::Parser as TfParser;
use traceforge_semantic::SemanticAnalyzer;
use traceforge_backend::Backend;

#[derive(Parser)]
#[command(name = "traceforge", version, about = "TraceForge Forensic Investigation Compiler")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a TraceForge source file
    Validate {
        /// Source file to validate
        file: PathBuf,
    },
    /// Compile a TraceForge source file
    Compile {
        /// Source file to compile
        file: PathBuf,
        /// Target platform (linux, windows)
        #[arg(short, long, default_value = "linux")]
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
    },
    /// Build a TraceForge source file (alias for compile)
    Build {
        /// Source file to build
        file: PathBuf,
        /// Target platform (linux, windows)
        #[arg(short, long, default_value = "linux")]
        target: String,
        /// Target architecture (x64, arm64)
        #[arg(short, long, default_value = "x64")]
        arch: String,
        /// Output directory
        #[arg(short, long, default_value = "./build")]
        output: PathBuf,
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
    /// Initialize a new TraceForge project
    Init {
        /// Project name
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { file } => validate(&file),
        Commands::Compile { file, target, arch, output, opt } => compile(&file, &target, &arch, &output, &opt),
        Commands::Build { file, target, arch, output } => compile(&file, &target, &arch, &output, "speed"),
        Commands::Inspect { file, format } => inspect(&file, &format),
        Commands::Hash { file } => hash_file(&file),
        Commands::Init { name } => init_project(&name),
    }
}

fn validate(file: &PathBuf) -> anyhow::Result<()> {
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
        println!("  Investigation: {}", ir.as_ref().map(|i| i.name.as_str()).unwrap_or("unknown"));
        println!("  Required capabilities: {:?}", ir.map(|i| i.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>()).unwrap_or_default());
    }

    Ok(())
}

fn compile(file: &PathBuf, target: &str, arch: &str, output: &PathBuf, opt: &str) -> anyhow::Result<()> {
    println!("Compiling {}", file.display());

    let source = std::fs::read_to_string(file)?;
    let source_hash = calculate_sha256(&source);

    let mut lexer = Lexer::new(&source);
    let tokens = lexer.tokenize()?;

    let mut parser = TfParser::new(tokens);
    let (ast, diags) = parser.parse_with_diagnostics();

    if !diags.is_empty() {
        print_diagnostics(&diags);
        if ast.is_none() {
            anyhow::bail!("Compilation failed during parsing");
        }
    }

    let ast = ast.unwrap();

    let mut analyzer = SemanticAnalyzer::new();
    let (ir, sem_diags) = analyzer.analyze_with_diagnostics(&ast);

    if !sem_diags.is_empty() {
        print_diagnostics(&sem_diags);
        anyhow::bail!("Compilation failed during semantic analysis");
    }

    let ir = ir.unwrap();

    // Parse target platform
    let target_platform = match target.to_lowercase().as_str() {
        "linux" => TargetPlatform::Linux,
        "windows" => TargetPlatform::Windows,
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

    println!("  Output directory: {}", output.display());
    println!("  Investigation name: {}", ir.name);

    let backend = Backend::new(config);
    let mut metadata = backend.generate(&ir, output)?;

    // Update metadata with actual values
    metadata.source_hash = source_hash;
    metadata.compiler_version = env!("CARGO_PKG_VERSION").to_string();
    metadata.compiler_hash = calculate_compiler_hash()?;

    // Write metadata
    let meta_path = output.join(format!("{}.meta.json", ir.name));
    std::fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)?;

    println!("✓ Compilation successful");
    println!("  Artifact: {}", output.join(&ir.name).display());
    println!("  SHA-256: {}", metadata.artifact_hash);
    println!("  Metadata: {}", meta_path.display());

    Ok(())
}

fn inspect(file: &PathBuf, format: &str) -> anyhow::Result<()> {
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

fn hash_file(file: &PathBuf) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(file)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();

    println!("SHA-256: {:x}", hash);
    Ok(())
}

fn init_project(name: &str) -> anyhow::Result<()> {
    let dir = PathBuf::from(name);
    std::fs::create_dir_all(&dir)?;

    // Create example investigation
    let example = format!(r#"investigation "{}" {{
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
}}"#, name, name);

    std::fs::write(dir.join(format!("{}.tfg", name)), example)?;

    // Create README
    let readme = format!(r#"# {} - TraceForge Investigation

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
"#, name, name, name, name);

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