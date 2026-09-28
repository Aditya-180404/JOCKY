//! PEB-Based Dynamic API Resolution
//!
//! Resolves Win32/NTAPI functions at runtime by walking the Process Environment
//! Block (PEB) instead of using `LoadLibraryA` + `GetProcAddress`, which are
//! both heavily hooked by EDR products.
//!
//! ## How It Works (Windows x64)
//!
//! 1. `gs:[0x60]` points to the `PEB` structure.
//! 2. `PEB.Ldr` (offset 0x18) points to `PEB_LDR_DATA`.
//! 3. `PEB_LDR_DATA.InMemoryOrderModuleList` (offset 0x20) is a doubly-linked
//!    list of `LDR_DATA_TABLE_ENTRY` structures, one per loaded DLL.
//! 4. Each entry has `DllBase` (the module's load address).
//! 5. From `DllBase` we parse the PE `IMAGE_EXPORT_DIRECTORY` to locate
//!    function RVAs by hashed name, without ever calling `GetProcAddress`.
//!
//! Function names are compared by DJB2 hash (compile-time constant) so no
//! plaintext function name strings are needed at resolution time.
//!
//! ## Platform Support
//!
//! - Windows x64: Full implementation via inline ASM to read `gs:[0x60]`.
//! - Linux / other: Stub returning `None` (resolution is not applicable).

/// DJB2 hash of a byte string — evaluated at compile time for zero-cost
/// function name hiding.
///
/// Usage: `let hash = djb2_hash(b"NtQuerySystemInformation");`
pub const fn djb2_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < name.len() {
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(name[i] as u32);
        i += 1;
    }
    hash
}

/// Pre-computed hashes for commonly-needed NTAPI functions.
/// These constants are evaluated at compile time so no plaintext strings appear
/// in the binary (after string encryption pass, even these disappear).
pub mod fn_hashes {
    use super::djb2_hash;

    pub const NT_QUERY_SYSTEM_INFORMATION: u32 =
        djb2_hash(b"NtQuerySystemInformation");
    pub const NT_QUERY_INFORMATION_PROCESS: u32 =
        djb2_hash(b"NtQueryInformationProcess");
    pub const NT_OPEN_PROCESS: u32 = djb2_hash(b"NtOpenProcess");
    pub const NT_QUERY_OBJECT: u32 = djb2_hash(b"NtQueryObject");
    pub const NT_ENUMERATE_VALUE_KEY: u32 = djb2_hash(b"NtEnumerateValueKey");
    pub const RTL_GET_VERSION: u32 = djb2_hash(b"RtlGetVersion");
    pub const VIRTUAL_QUERY_EX: u32 = djb2_hash(b"VirtualQueryEx");
}

/// A resolved function pointer (raw address).
pub struct ResolvedFn(pub usize);

impl ResolvedFn {
    /// Safety: Caller must ensure the resolved address points to a compatible
    /// function with the correct calling convention and argument types.
    pub unsafe fn as_fn_ptr<F: Copy>(&self) -> F {
        assert_eq!(
            std::mem::size_of::<F>(),
            std::mem::size_of::<usize>(),
            "ResolvedFn::as_fn_ptr: target type size mismatch"
        );
        *(&self.0 as *const usize as *const F)
    }
}

/// PEB-based runtime resolver.
///
/// On Windows x64, walks the PEB in-memory module list and parses PE export
/// directories to resolve functions by DJB2 hash without importing
/// `LoadLibraryA` or `GetProcAddress`.
///
/// On Linux, all resolve calls return `None` (not applicable).
pub struct PebResolver;

impl PebResolver {
    pub fn new() -> Self {
        Self
    }

    /// Resolve a function by DLL base name DJB2 hash and export name DJB2 hash.
    ///
    /// Returns `Some(ResolvedFn)` on successful resolution, `None` if the DLL
    /// or export is not found, or if running on a non-Windows platform.
    pub fn resolve_by_hash(
        &self,
        dll_name_hash: u32,
        fn_name_hash: u32,
    ) -> Option<ResolvedFn> {
        #[cfg(target_os = "windows")]
        {
            unsafe { self.resolve_windows(dll_name_hash, fn_name_hash) }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (dll_name_hash, fn_name_hash);
            None
        }
    }

    /// Convenience: resolve a function by plaintext names.
    ///
    /// **Note:** This method includes the names as string literals. Use
    /// `resolve_by_hash` with compile-time `djb2_hash` constants in production
    /// to avoid plaintext function names in the binary.
    pub fn resolve(&self, dll_name: &str, fn_name: &str) -> Option<ResolvedFn> {
        self.resolve_by_hash(
            djb2_hash(dll_name.as_bytes()),
            djb2_hash(fn_name.as_bytes()),
        )
    }

    #[cfg(target_os = "windows")]
    unsafe fn resolve_windows(
        &self,
        dll_name_hash: u32,
        fn_name_hash: u32,
    ) -> Option<ResolvedFn> {
        // ── Step 1: Get PEB address from gs:[0x60] ────────────────────────────
        let peb: *const u8;
        std::arch::asm!(
            "mov {peb}, gs:[0x60]",
            peb = out(reg) peb,
            options(nostack, preserves_flags)
        );

        if peb.is_null() {
            return None;
        }

        // ── Step 2: PEB.Ldr at offset 0x18 ───────────────────────────────────
        let ldr = *(peb.add(0x18) as *const *const u8);
        if ldr.is_null() {
            return None;
        }

        // ── Step 3: PEB_LDR_DATA.InMemoryOrderModuleList at offset 0x20 ──────
        // The list head Flink points to the first LDR_DATA_TABLE_ENTRY.
        // LDR_DATA_TABLE_ENTRY layout (x64):
        //   0x00: InLoadOrderLinks   (LIST_ENTRY: Flink/Blink)
        //   0x10: InMemoryOrderLinks (LIST_ENTRY)
        //   0x20: InInitOrderLinks   (LIST_ENTRY)
        //   0x30: DllBase            (*void)
        //   0x38: EntryPoint         (*void)
        //   0x40: SizeOfImage        (u32)
        //   0x48: FullDllName        (UNICODE_STRING)
        //   0x58: BaseDllName        (UNICODE_STRING)
        //     UNICODE_STRING: Length(u16), MaxLength(u16), pad(u32), Buffer(*u16)
        let list_head = ldr.add(0x20) as *const *const u8;
        let mut flink = *list_head;

        // Walk list (sentinel: flink returns to list_head)
        loop {
            if flink.is_null() || flink == list_head as *const u8 {
                break;
            }

            // InMemoryOrderLinks are at offset 0x10 inside the entry, so the
            // entry base is flink - 0x10
            let entry = flink.sub(0x10);

            // DllBase at offset 0x30 from entry
            let dll_base = *(entry.add(0x30) as *const usize);

            // BaseDllName at offset 0x58: UNICODE_STRING { len(u16), max(u16), pad(u32), buf(*u16) }
            let base_name_len = *(entry.add(0x58) as *const u16) as usize;
            let base_name_buf = *(entry.add(0x60) as *const *const u16);

            // Compute DJB2 hash of the DLL base name (Unicode → lowercase ASCII)
            if !base_name_buf.is_null() && base_name_len > 0 {
                let char_count = base_name_len / 2;
                let mut computed_hash: u32 = 5381;
                for i in 0..char_count {
                    let wc = *base_name_buf.add(i) as u8;
                    let lc = if wc >= b'A' && wc <= b'Z' { wc + 32 } else { wc };
                    computed_hash = computed_hash
                        .wrapping_shl(5)
                        .wrapping_add(computed_hash)
                        .wrapping_add(lc as u32);
                }

                if computed_hash == dll_name_hash && dll_base != 0 {
                    // ── Step 4: Parse PE export directory ────────────────────
                    if let Some(resolved) =
                        self.resolve_export(dll_base as *const u8, fn_name_hash)
                    {
                        return Some(resolved);
                    }
                }
            }

            // Advance: Flink is the first field of InMemoryOrderLinks
            flink = *(flink as *const *const u8);
        }

        None
    }

    #[cfg(target_os = "windows")]
    unsafe fn resolve_export(
        &self,
        dll_base: *const u8,
        fn_name_hash: u32,
    ) -> Option<ResolvedFn> {
        // MZ/PE header navigation
        // IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
        let e_lfanew = *(dll_base.add(0x3C) as *const u32) as usize;
        let pe_header = dll_base.add(e_lfanew);

        // IMAGE_NT_HEADERS: Signature(4) + FileHeader(20) + OptionalHeader
        // IMAGE_OPTIONAL_HEADER64.DataDirectory[0] = Export at offset 0x70 from OptHdr start
        // OptHdr start = pe_header + 4 (sig) + 20 (file hdr) = pe_header + 24
        let opt_hdr = pe_header.add(24);
        let export_dir_rva = *(opt_hdr.add(0x70) as *const u32) as usize;
        if export_dir_rva == 0 {
            return None;
        }

        let exp_dir = dll_base.add(export_dir_rva);

        // IMAGE_EXPORT_DIRECTORY layout:
        //   0x00 Characteristics
        //   0x04 TimeDateStamp
        //   0x08 MajorVersion / MinorVersion
        //   0x0C Name (RVA)
        //   0x10 Base
        //   0x14 NumberOfFunctions
        //   0x18 NumberOfNames
        //   0x1C AddressOfFunctions (RVA to array of u32 RVAs)
        //   0x20 AddressOfNames     (RVA to array of u32 RVAs)
        //   0x24 AddressOfNameOrdinals (RVA to array of u16)
        let num_names = *(exp_dir.add(0x18) as *const u32) as usize;
        let addr_of_functions = *(exp_dir.add(0x1C) as *const u32) as usize;
        let addr_of_names = *(exp_dir.add(0x20) as *const u32) as usize;
        let addr_of_ordinals = *(exp_dir.add(0x24) as *const u32) as usize;

        let names_table = dll_base.add(addr_of_names) as *const u32;
        let ordinals_table = dll_base.add(addr_of_ordinals) as *const u16;
        let functions_table = dll_base.add(addr_of_functions) as *const u32;

        for i in 0..num_names {
            let name_rva = *names_table.add(i) as usize;
            let name_ptr = dll_base.add(name_rva);

            // Compute DJB2 of this export name
            let mut hash: u32 = 5381;
            let mut c = name_ptr;
            loop {
                let byte = *c;
                if byte == 0 {
                    break;
                }
                hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(byte as u32);
                c = c.add(1);
            }

            if hash == fn_name_hash {
                let ordinal = *ordinals_table.add(i) as usize;
                let fn_rva = *functions_table.add(ordinal) as usize;
                let fn_addr = dll_base.add(fn_rva) as usize;
                return Some(ResolvedFn(fn_addr));
            }
        }

        None
    }
}

impl Default for PebResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2_hash_is_deterministic() {
        let h1 = djb2_hash(b"NtQuerySystemInformation");
        let h2 = djb2_hash(b"NtQuerySystemInformation");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_djb2_hash_different_strings() {
        let h1 = djb2_hash(b"ntdll.dll");
        let h2 = djb2_hash(b"kernel32.dll");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_precomputed_hashes_are_stable() {
        // These values must not change — they are embedded in compiled binaries
        assert_eq!(
            fn_hashes::NT_QUERY_SYSTEM_INFORMATION,
            djb2_hash(b"NtQuerySystemInformation")
        );
        assert_eq!(
            fn_hashes::NT_QUERY_INFORMATION_PROCESS,
            djb2_hash(b"NtQueryInformationProcess")
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_peb_resolver_returns_none_on_linux() {
        let resolver = PebResolver::new();
        let result = resolver.resolve("ntdll.dll", "NtQuerySystemInformation");
        assert!(result.is_none(), "PEB resolver must return None on Linux");
    }
}
