//! Source-independence and relocatability regression test suite for JOCKEY
//!
//! Validates:
//! 1. Generated projects NEVER contain developer machine absolute paths (G:\JOCKEY, developer C:\Users, /home, etc.)
//! 2. Generated Cargo manifests use relative runtime paths: `jockey-runtime = { path = "runtime" }`
//! 3. Generated projects can be moved to an entirely independent directory and compiled cleanly by Cargo.

use jockey_backend::Backend;
use jockey_ir::{BuildConfig, TargetArch, TargetPlatform};
use jockey_lexer::Lexer;
use jockey_parser::Parser;
use jockey_semantic::SemanticAnalyzer;
use std::fs;
use std::path::Path;

fn assert_no_machine_paths(text: &str, context: &str) {
    let lower = text.to_lowercase();
    assert!(
        !lower.contains("g:\\jockey") && !lower.contains("g:/jockey"),
        "Machine path 'G:/JOCKEY' detected in {}:\n{}",
        context,
        text
    );
    assert!(
        !lower.contains("/home/runner")
            && !lower.contains("/home/aditya")
            && !lower.contains("/home/samaresh"),
        "Developer home directory detected in {}:\n{}",
        context,
        text
    );
    assert!(
        !lower.contains("/workspace/jockey"),
        "Developer workspace directory detected in {}:\n{}",
        context,
        text
    );

    // Ensure no developer user profiles in C:\Users (excluding Windows system C:\Users\Default)
    if let Some(pos) = lower.find("c:\\users\\") {
        let remainder = &lower[pos + 9..];
        let user = remainder.split('\\').next().unwrap_or("");
        assert!(
            user == "default" || user.is_empty(),
            "Developer user profile 'C:\\Users\\{}' detected in {}:\n{}",
            user,
            context,
            text
        );
    }
}

fn scan_manifests_for_absolute_paths(dir: &Path) {
    for entry in fs::read_dir(dir).expect("Failed to read dir") {
        let entry = entry.expect("Valid entry");
        let path = entry.path();
        if path.is_file() {
            let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if filename == "Cargo.toml" || filename == "main.rs" {
                if let Ok(content) = fs::read_to_string(&path) {
                    assert_no_machine_paths(&content, &path.display().to_string());
                    if filename == "Cargo.toml" {
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("jockey-runtime")
                                || trimmed.starts_with("jockey-runtime-")
                            {
                                assert!(
                                    !trimmed.contains(":\\") && !trimmed.contains(":/"),
                                    "Cargo.toml must not contain absolute Windows path dependency: {}",
                                    trimmed
                                );
                            }
                        }
                    }
                }
            }
        } else if path.is_dir() && entry.file_name() != "target" && entry.file_name() != ".git" {
            scan_manifests_for_absolute_paths(&path);
        }
    }
}

#[test]
fn test_generated_project_source_independence_and_relocatability() {
    let dsl_source = r#"
investigation "relocatable_triage" {
    metadata {
        classification = "RESTRICTED"
        case_id = "CASE-RELOC-2026"
    }

    collect system_info
    collect processes
    collect network_connections
    collect files "C:\\Windows\\System32\\drivers\\etc" {
        recursive
    }

    export evidence "evidence.json"
}
"#;

    let mut lexer = Lexer::new(dsl_source);
    let tokens = lexer.tokenize().expect("Lexing must succeed");
    let mut parser = Parser::new(tokens);
    let ast = parser.parse().expect("Parsing must succeed");
    let mut semantic = SemanticAnalyzer::new();
    let ir = semantic
        .analyze(&ast)
        .expect("Semantic analysis must succeed");

    let build_config = BuildConfig {
        target_platform: if cfg!(target_os = "windows") {
            TargetPlatform::Windows
        } else {
            TargetPlatform::Linux
        },
        target_arch: TargetArch::X64,
        ..Default::default()
    };

    let backend = Backend::new(build_config);

    // 1. Verify Cargo.toml generation has no machine paths
    let cargo_toml = backend
        .generate_cargo_toml(&ir)
        .expect("Cargo.toml generation must succeed");
    assert_no_machine_paths(&cargo_toml, "Generated Cargo.toml");
    assert!(cargo_toml.contains("jockey-runtime = { path = \"runtime\" }"));

    // 2. Generate Rust main.rs and check for absolute path leaks
    let main_rs = backend
        .generate_rust_code(&ir)
        .expect("main.rs generation must succeed");
    assert_no_machine_paths(&main_rs, "Generated main.rs");

    // 3. Create a temporary project directory and verify complete project tree
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!("jockey_reloc_test_{}", nanos));
    let project_dir = temp_root.join("initial_project");
    fs::create_dir_all(&project_dir).expect("Create project dir");

    let cargo_path = project_dir.join("Cargo.toml");
    fs::write(&cargo_path, &cargo_toml).expect("Write Cargo.toml");

    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir).expect("Create src dir");
    fs::write(src_dir.join("main.rs"), &main_rs).expect("Write main.rs");
    backend
        .copy_runtime_bundle(&project_dir)
        .expect("Bundle runtime into project");

    // 4. Scan the initial generated files (manifests, source, and bundled runtime manifests)
    scan_manifests_for_absolute_paths(&project_dir);

    // 5. Relocate project to a completely different temporary directory
    let relocated_dir = temp_root.join("relocated_project");
    fs::create_dir_all(&relocated_dir).expect("Create relocated dir");
    fs::write(relocated_dir.join("Cargo.toml"), &cargo_toml).expect("Write relocated Cargo.toml");
    let relocated_src = relocated_dir.join("src");
    fs::create_dir_all(&relocated_src).expect("Create relocated src dir");
    fs::write(relocated_src.join("main.rs"), &main_rs).expect("Write relocated main.rs");
    backend
        .copy_runtime_bundle(&relocated_dir)
        .expect("Bundle runtime into relocated project");

    // Scan relocated files
    scan_manifests_for_absolute_paths(&relocated_dir);

    // 6. Verify that cargo check succeeds on the relocated project
    let check_status = std::process::Command::new("cargo")
        .args([
            "check",
            "--manifest-path",
            relocated_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .status()
        .expect("Run cargo check on relocated project");
    assert!(
        check_status.success(),
        "Relocated project must compile cleanly with Cargo"
    );

    // Clean up
    let _ = fs::remove_dir_all(&temp_root);
}
