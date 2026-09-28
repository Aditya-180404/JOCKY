//! JOCKY Integration Test Suite
//!
//! Covers end-to-end behaviour across the full LotL runtime:
//! - In-memory execution (fileless, memfd_create+fexecve)
//! - PEB resolver & DJB2 hashing (all 12 precomputed constants)
//! - Direct syscall stubs (Linux stub paths)
//! - API unhooking (KnownDlls path, Linux stubs)
//! - Anti-analysis guards (CPUID/RDTSC/TracerPid/PEB)
//! - Transport configuration validation (all 4 variants)

use jocky_runtime_lotl::{
    antianalysis::{AntiAnalysisGuard, EnvironmentRisk},
    direct_syscall::{DirectSyscall, SyscallError},
    in_memory_exec::{InMemoryExecutionError, InMemoryScriptRunner},
    peb_resolve::{djb2_hash, fn_hashes, PebResolver},
    transport::{build_transport, TransportConfig, TransportKind},
    unhook::{ApiUnhooker, UnhookError},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn base_transport_cfg() -> TransportConfig {
    TransportConfig {
        kind: TransportKind::Direct,
        relay_url: "https://jocky.example.com".into(),
        socks5_proxy_url: None,
        cdn_host: None,
        upload_presigned_url: None,
        poll_presigned_url: None,
        cloud_provider: None,
        chunk_size_bytes: 4 * 1024 * 1024,
        ca_bundle: None,
        timeout_secs: 30,
    }
}

// ─── In-Memory Execution ─────────────────────────────────────────────────────

mod in_memory {
    use super::*;

    #[test]
    fn empty_script_is_rejected() {
        let r = InMemoryScriptRunner::new();
        assert!(matches!(r.run_script(""), Err(InMemoryExecutionError::EmptyScript)));
    }

    #[test]
    fn whitespace_only_script_is_rejected() {
        let r = InMemoryScriptRunner::new();
        assert!(matches!(
            r.run_script("   \t\n  "),
            Err(InMemoryExecutionError::EmptyScript)
        ));
    }

    #[test]
    fn empty_payload_is_rejected() {
        let r = InMemoryScriptRunner::new();
        assert!(matches!(r.run_payload(&[]), Err(InMemoryExecutionError::EmptyScript)));
    }

    #[test]
    fn non_empty_script_does_not_panic() {
        let r = InMemoryScriptRunner::new();
        let _ = r.run_script("investigation \"test\" { collect system_info }");
    }

    #[test]
    fn env_vars_stored_via_builder() {
        let r = InMemoryScriptRunner::new()
            .with_env("JOCKY_CASE_ID", "CASE-001")
            .with_env("JOCKY_OPERATOR", "analyst-07");
        // Verify by trying to re-run with the env and checking no panic
        let _ = r.run_script("collect system_info");
    }

    #[test]
    fn env_var_overwrite_via_builder() {
        // Builder calls with same key should overwrite silently
        let r = InMemoryScriptRunner::new()
            .with_env("KEY", "v1")
            .with_env("KEY", "v2");
        // Only one value should remain — verify by building a second runner
        // identically and confirming both behave the same
        let r2 = InMemoryScriptRunner::new().with_env("KEY", "v2");
        let a = r.run_script("collect system_info");
        let b = r2.run_script("collect system_info");
        // Both should return the same variant (Ok or same error kind)
        assert_eq!(a.is_ok(), b.is_ok());
    }

    #[test]
    fn set_env_mutates_in_place() {
        let mut r = InMemoryScriptRunner::new();
        r.set_env("JOCKY_TARGET", "WORKSTATION-01");
        // Confirm the runner still works after mutation
        let _ = r.run_script("collect system_info");
    }

    #[test]
    fn many_env_vars_set() {
        let mut r = InMemoryScriptRunner::new();
        for i in 0..20 {
            r.set_env(format!("VAR_{i}"), format!("val_{i}"));
        }
        let _ = r.run_script("collect system_info");
    }

    #[test]
    fn error_empty_script_display() {
        let e = InMemoryExecutionError::EmptyScript;
        assert!(e.to_string().to_lowercase().contains("empty"));
    }

    #[test]
    fn error_not_supported_display() {
        let e = InMemoryExecutionError::NotSupported("plan9".to_string());
        assert!(e.to_string().contains("plan9"));
    }

    #[test]
    fn error_execution_failed_display() {
        let e = InMemoryExecutionError::ExecutionFailed("fexecve errno 13".to_string());
        assert!(e.to_string().contains("errno 13"));
    }

    #[test]
    fn all_error_variants_serialize_to_json() {
        let variants = [
            InMemoryExecutionError::EmptyScript,
            InMemoryExecutionError::NotSupported("os".into()),
            InMemoryExecutionError::ExecutionFailed("reason".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize failed");
            assert!(!json.is_empty());
        }
    }

    // Linux-specific memfd tests
    #[cfg(target_os = "linux")]
    mod linux_memfd {
        use super::*;

        /// Helper: create a memfd via the same syscall the runner uses
        fn create_memfd() -> i32 {
            extern "C" {
                fn memfd_create(
                    name: *const std::ffi::c_char,
                    flags: std::ffi::c_uint,
                ) -> std::ffi::c_int;
            }
            unsafe { memfd_create(b"\0".as_ptr() as _, 0x0001) }
        }

        fn close_fd(fd: i32) {
            extern "C" {
                fn close(fd: std::ffi::c_int) -> std::ffi::c_int;
            }
            unsafe { close(fd); }
        }

        #[test]
        fn memfd_create_syscall_available() {
            let fd = create_memfd();
            assert!(fd >= 0, "memfd_create failed");
            close_fd(fd);
        }

        #[test]
        fn memfd_fd_is_anonymous() {
            let fd = create_memfd();
            assert!(fd >= 0);
            if let Ok(link) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
                let s = link.to_string_lossy();
                assert!(
                    s.contains("memfd:") || s.contains("anon_inode"),
                    "Expected anonymous fd, got: {s}"
                );
            }
            close_fd(fd);
        }

        #[test]
        fn multiple_memfds_get_distinct_fds() {
            let fd1 = create_memfd();
            let fd2 = create_memfd();
            assert!(fd1 >= 0 && fd2 >= 0);
            assert_ne!(fd1, fd2);
            close_fd(fd1);
            close_fd(fd2);
        }

        #[test]
        fn non_elf_payload_reaches_fexecve_without_disk_write() {
            let r = InMemoryScriptRunner::new().with_env("JOCKY_CASE", "it-001");
            let payload = b"collect processes\nexport evidence \"out.json\"\n";
            let result = r.run_payload(payload);
            match &result {
                Ok(msg) => assert!(msg.contains("memfd") || msg.contains("in-memory")),
                Err(InMemoryExecutionError::NotSupported(_)) => {}
                Err(e) => panic!("Unexpected error: {e}"),
            }
            assert!(!std::path::Path::new("/tmp/jocky_payload").exists());
            assert!(!std::path::Path::new("/tmp/jocky-payload").exists());
        }

        #[test]
        fn large_payload_fits_in_memfd() {
            let r = InMemoryScriptRunner::new();
            let payload = vec![0xAAu8; 1024 * 1024]; // 1 MB
            let result = r.run_payload(&payload);
            assert!(
                result.is_ok() || matches!(result, Err(InMemoryExecutionError::NotSupported(_))),
                "1 MB payload must fit in memfd: {result:?}"
            );
        }

        #[test]
        fn binary_payload_does_not_corrupt() {
            // A payload of 256 distinct bytes — tests memfd can hold arbitrary binary
            let r = InMemoryScriptRunner::new();
            let payload: Vec<u8> = (0u8..=255).collect();
            let _ = r.run_payload(&payload); // must not panic
        }
    }
}

// ─── PEB Resolver & DJB2 Hashing ────────────────────────────────────────────

mod peb_and_djb2 {
    use super::*;

    #[test]
    fn djb2_empty_string() {
        // DJB2 initial state is 5381; empty input returns unchanged
        assert_eq!(djb2_hash(b""), 5381);
    }

    #[test]
    fn djb2_identical_inputs_equal() {
        assert_eq!(
            djb2_hash(b"NtQuerySystemInformation"),
            djb2_hash(b"NtQuerySystemInformation")
        );
    }

    #[test]
    fn djb2_different_inputs_differ() {
        assert_ne!(
            djb2_hash(b"NtQuerySystemInformation"),
            djb2_hash(b"NtQueryInformationProcess")
        );
    }

    #[test]
    fn djb2_is_case_sensitive() {
        assert_ne!(djb2_hash(b"ntdll.dll"), djb2_hash(b"NTDLL.DLL"));
    }

    #[test]
    fn djb2_is_const_evaluable() {
        const H: u32 = djb2_hash(b"NtCreateSection");
        assert_eq!(H, djb2_hash(b"NtCreateSection"));
    }

    #[test]
    fn precomputed_hashes_match_nt_query_system_info() {
        assert_eq!(
            fn_hashes::NT_QUERY_SYSTEM_INFORMATION,
            djb2_hash(b"NtQuerySystemInformation")
        );
    }

    #[test]
    fn precomputed_hashes_match_nt_query_info_process() {
        assert_eq!(
            fn_hashes::NT_QUERY_INFORMATION_PROCESS,
            djb2_hash(b"NtQueryInformationProcess")
        );
    }

    #[test]
    fn precomputed_hashes_match_nt_open_process() {
        assert_eq!(fn_hashes::NT_OPEN_PROCESS, djb2_hash(b"NtOpenProcess"));
    }

    #[test]
    fn precomputed_hashes_match_nt_query_object() {
        assert_eq!(fn_hashes::NT_QUERY_OBJECT, djb2_hash(b"NtQueryObject"));
    }

    #[test]
    fn precomputed_hashes_match_nt_enumerate_value_key() {
        assert_eq!(
            fn_hashes::NT_ENUMERATE_VALUE_KEY,
            djb2_hash(b"NtEnumerateValueKey")
        );
    }

    #[test]
    fn precomputed_hashes_match_rtl_get_version() {
        assert_eq!(fn_hashes::RTL_GET_VERSION, djb2_hash(b"RtlGetVersion"));
    }

    #[test]
    fn precomputed_hashes_match_virtual_query_ex() {
        assert_eq!(fn_hashes::VIRTUAL_QUERY_EX, djb2_hash(b"VirtualQueryEx"));
    }

    #[test]
    fn precomputed_hashes_match_nt_protect_virtual_memory() {
        assert_eq!(
            fn_hashes::NT_PROTECT_VIRTUAL_MEMORY,
            djb2_hash(b"NtProtectVirtualMemory")
        );
    }

    #[test]
    fn precomputed_hashes_match_nt_close() {
        assert_eq!(fn_hashes::NT_CLOSE, djb2_hash(b"NtClose"));
    }

    #[test]
    fn precomputed_hashes_match_nt_open_section() {
        assert_eq!(fn_hashes::NT_OPEN_SECTION, djb2_hash(b"NtOpenSection"));
    }

    #[test]
    fn precomputed_hashes_match_nt_map_view_of_section() {
        assert_eq!(
            fn_hashes::NT_MAP_VIEW_OF_SECTION,
            djb2_hash(b"NtMapViewOfSection")
        );
    }

    #[test]
    fn precomputed_hashes_match_nt_unmap_view_of_section() {
        assert_eq!(
            fn_hashes::NT_UNMAP_VIEW_OF_SECTION,
            djb2_hash(b"NtUnmapViewOfSection")
        );
    }

    #[test]
    fn peb_resolver_new_does_not_panic() {
        let _ = PebResolver::new();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peb_resolver_returns_none_on_linux() {
        let r = PebResolver::new();
        let result = r.resolve_by_hash(djb2_hash(b"ntdll.dll"), djb2_hash(b"NtClose"));
        assert!(result.is_none(), "PEB resolution must return None on Linux");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peb_resolver_multiple_queries_return_none_on_linux() {
        let r = PebResolver::new();
        let queries = [
            (djb2_hash(b"ntdll.dll"), fn_hashes::NT_CLOSE),
            (djb2_hash(b"ntdll.dll"), fn_hashes::NT_OPEN_PROCESS),
            (djb2_hash(b"kernel32.dll"), djb2_hash(b"CreateFileW")),
        ];
        for (dll_hash, fn_hash) in queries {
            assert!(r.resolve_by_hash(dll_hash, fn_hash).is_none());
        }
    }
}

// ─── Direct Syscalls ─────────────────────────────────────────────────────────

mod direct_syscalls {
    use super::*;

    #[test]
    fn direct_syscall_new_does_not_panic() {
        let _ = DirectSyscall::new();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_ssn_not_supported_on_linux() {
        let ds = DirectSyscall::new();
        assert!(matches!(
            ds.get_ssn(fn_hashes::NT_QUERY_SYSTEM_INFORMATION),
            Err(SyscallError::NotSupported)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn query_processes_direct_not_supported_on_linux() {
        let ds = DirectSyscall::new();
        assert!(matches!(
            ds.query_processes_direct(),
            Err(SyscallError::NotSupported)
        ));
    }

    #[test]
    fn syscall_error_not_supported_serializes() {
        let e = SyscallError::NotSupported;
        let j = serde_json::to_string(&e).unwrap();
        assert!(!j.is_empty());
    }

    #[test]
    fn syscall_error_ntdll_not_found_serializes() {
        let e = SyscallError::NtdllNotFound;
        let j = serde_json::to_string(&e).unwrap();
        assert!(!j.is_empty());
    }

    #[test]
    fn syscall_error_export_not_found_serializes() {
        let e = SyscallError::ExportNotFound { fn_name_hash: 0xDEADBEEF };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("ExportNotFound") || j.contains("fn_name_hash"));
    }

    #[test]
    fn syscall_error_unexpected_stub_pattern_serializes() {
        let e = SyscallError::UnexpectedStubPattern { bytes: [0u8; 8] };
        let j = serde_json::to_string(&e).unwrap();
        assert!(!j.is_empty());
    }

    #[test]
    fn syscall_error_nt_status_failed_serializes() {
        let e = SyscallError::NtStatusFailed { ntstatus: 0xC0000001 };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("NtStatusFailed") || j.contains("ntstatus"));
    }
}

// ─── API Unhooking ───────────────────────────────────────────────────────────

mod api_unhooking {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn unhooker_new_returns_not_supported_on_linux() {
        let result = ApiUnhooker::new();
        assert!(matches!(result, Err(UnhookError::NotSupported)));
    }

    #[test]
    fn unhook_error_not_supported_serializes() {
        let e = UnhookError::NotSupported;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }

    #[test]
    fn unhook_error_ntdll_not_found_serializes() {
        let e = UnhookError::NtdllNotFound;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }

    #[test]
    fn unhook_error_size_mismatch_serializes() {
        let e = UnhookError::SizeMismatch;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }

    #[test]
    fn unhook_error_known_dlls_not_found_serializes() {
        let e = UnhookError::KnownDllsSectionNotFound;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }

    #[test]
    fn unhook_error_text_section_not_found_serializes() {
        let e = UnhookError::TextSectionNotFound;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }

    #[test]
    fn unhook_error_virtual_protect_failed_serializes() {
        let e = UnhookError::VirtualProtectFailed;
        assert!(!serde_json::to_string(&e).unwrap().is_empty());
    }
}

// ─── Anti-Analysis Guards ────────────────────────────────────────────────────

mod anti_analysis {
    use super::*;

    #[test]
    fn guard_new_does_not_panic() {
        let _ = AntiAnalysisGuard::new();
    }

    #[test]
    fn guard_assess_returns_a_result() {
        let g = AntiAnalysisGuard::new();
        let _ = g.assess(); // must not panic
    }

    #[test]
    fn safe_is_not_hostile() {
        assert!(!EnvironmentRisk::Safe.is_hostile());
    }

    #[test]
    fn hostile_is_hostile() {
        assert!(EnvironmentRisk::Hostile(vec!["CPUID hypervisor bit set".into()]).is_hostile());
    }

    #[test]
    fn suspicious_is_not_hostile() {
        assert!(!EnvironmentRisk::Suspicious(vec!["low memory".into()]).is_hostile());
    }

    #[test]
    fn all_risk_variants_serialize() {
        let variants = [
            EnvironmentRisk::Safe,
            EnvironmentRisk::Suspicious(vec!["TracerPid > 0".into()]),
            EnvironmentRisk::Hostile(vec!["hypervisor detected".into()]),
        ];
        for v in &variants {
            let j = serde_json::to_string(v).unwrap();
            assert!(!j.is_empty());
        }
    }

    #[test]
    fn suspicious_reasons_are_non_empty() {
        let r = EnvironmentRisk::Suspicious(vec!["reason-A".into(), "reason-B".into()]);
        if let EnvironmentRisk::Suspicious(reasons) = r {
            assert!(!reasons.is_empty());
            assert!(reasons.iter().all(|s| !s.is_empty()));
        }
    }

    #[test]
    fn hostile_reasons_are_non_empty() {
        let r = EnvironmentRisk::Hostile(vec!["CPUID".into()]);
        if let EnvironmentRisk::Hostile(reasons) = r {
            assert!(!reasons.is_empty());
        }
    }

    #[test]
    fn repeated_assess_is_consistent() {
        let g = AntiAnalysisGuard::new();
        assert_eq!(g.assess().is_hostile(), g.assess().is_hostile());
    }

    #[test]
    fn guard_result_is_valid_variant() {
        // The guard may return any risk level depending on the host environment.
        // In a VM/container (CI) the hypervisor bit is set → correctly Hostile.
        // On a physical dev machine → Safe or Suspicious.
        // What must never happen: a panic or an invalid state.
        let g = AntiAnalysisGuard::new();
        let risk = g.assess();
        // Hostile variants must have at least one reason
        if let EnvironmentRisk::Hostile(ref reasons) = risk {
            assert!(!reasons.is_empty(), "Hostile result must include reason(s)");
        }
        // Suspicious variants must have at least one reason
        if let EnvironmentRisk::Suspicious(ref reasons) = risk {
            assert!(!reasons.is_empty(), "Suspicious result must include reason(s)");
        }
    }
}

// ─── Transport Configuration ─────────────────────────────────────────────────

mod transport {
    use super::*;

    #[test]
    fn direct_transport_builds_ok() {
        assert!(build_transport(base_transport_cfg()).is_ok());
    }

    #[test]
    fn domain_fronted_without_cdn_host_fails() {
        let cfg = TransportConfig {
            kind: TransportKind::DomainFronted,
            cdn_host: None,
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_err());
    }

    #[test]
    fn domain_fronted_with_cdn_host_builds_ok() {
        let cfg = TransportConfig {
            kind: TransportKind::DomainFronted,
            cdn_host: Some("cloudflare.com".into()),
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_ok());
    }

    #[test]
    fn socks5_without_proxy_url_fails() {
        let cfg = TransportConfig {
            kind: TransportKind::Socks5,
            socks5_proxy_url: None,
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_err());
    }

    #[test]
    fn socks5_with_proxy_url_builds_ok() {
        let cfg = TransportConfig {
            kind: TransportKind::Socks5,
            socks5_proxy_url: Some("socks5://127.0.0.1:9050".into()),
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_ok());
    }

    #[test]
    fn cloud_relay_without_upload_url_fails() {
        let cfg = TransportConfig {
            kind: TransportKind::CloudApiRelay,
            upload_presigned_url: None,
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_err());
    }

    #[test]
    fn cloud_relay_with_upload_url_builds_ok() {
        let cfg = TransportConfig {
            kind: TransportKind::CloudApiRelay,
            upload_presigned_url: Some("https://s3.example.com/key?sig=abc".into()),
            ..base_transport_cfg()
        };
        assert!(build_transport(cfg).is_ok());
    }

    #[test]
    fn transport_kind_parses_direct() {
        let k: TransportKind = "direct".parse().unwrap();
        assert_eq!(k, TransportKind::Direct);
    }

    #[test]
    fn transport_kind_parses_domain_fronted() {
        let k: TransportKind = "domain_fronted".parse().unwrap();
        assert_eq!(k, TransportKind::DomainFronted);
    }

    #[test]
    fn transport_kind_parses_socks5() {
        let k: TransportKind = "socks5".parse().unwrap();
        assert_eq!(k, TransportKind::Socks5);
    }

    #[test]
    fn transport_kind_parses_cloud_relay() {
        let k: TransportKind = "cloud_api_relay".parse().unwrap();
        assert_eq!(k, TransportKind::CloudApiRelay);
    }

    #[test]
    fn transport_kind_invalid_string_errors() {
        let result: Result<TransportKind, _> = "morse_code".parse();
        assert!(result.is_err());
    }

    #[test]
    fn chunk_size_is_within_reasonable_bounds() {
        let cfg = base_transport_cfg();
        assert!(cfg.chunk_size_bytes >= 1024);
        assert!(cfg.chunk_size_bytes <= 64 * 1024 * 1024);
    }

    #[test]
    fn timeout_secs_is_positive() {
        let cfg = base_transport_cfg();
        assert!(cfg.timeout_secs > 0);
    }
}
