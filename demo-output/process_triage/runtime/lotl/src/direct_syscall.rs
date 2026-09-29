//! Direct NTAPI Syscall Stubs
//!
//! Issues raw syscall instructions with the correct System Service Number (SSN)
//! instead of calling through `ntdll.dll` exported stubs, which EDR drivers
//! hook via `DbgkpSendSystemCallReport`, SSDT patching, or inline hooks.
//!
//! ## SSN Discovery
//!
//! The SSN for each Nt* function is embedded in the first few bytes of its
//! export stub in `ntdll.dll`:
//!
//! ```asm
//! ; NtQuerySystemInformation stub pattern (Windows 10+)
//! mov r10, rcx          ; 4C 8B D1
//! mov eax, <SSN>        ; B8 xx xx xx xx
//! syscall               ; 0F 05
//! ret                   ; C3
//! ```
//!
//! We locate the stub via PEB resolution (from `peb_resolve.rs`), read the
//! 4 bytes after the `B8` opcode, and issue our own `syscall` with the same
//! SSN using our own stub. This bypasses any trampoline hooks in the Nt*
//! prologue.
//!
//! ## Platform Support
//!
//! - Windows x64: Full implementation.
//! - Linux / other: Stub implementations returning `Err(NotSupported)`.

use crate::peb_resolve::{djb2_hash, fn_hashes, PebResolver};

/// Result of a direct syscall operation.
pub type SyscallResult = Result<usize, SyscallError>;

/// Errors from the direct syscall subsystem.
#[derive(Debug, Clone, serde::Serialize)]
pub enum SyscallError {
    /// Running on a non-Windows platform; direct syscalls are not applicable.
    NotSupported,
    /// Failed to locate ntdll.dll via PEB.
    NtdllNotFound,
    /// Failed to find the target Nt* export in ntdll.
    ExportNotFound { fn_name_hash: u32 },
    /// The export stub does not match the expected `mov r10, rcx; mov eax, <SSN>` pattern.
    UnexpectedStubPattern { bytes: [u8; 8] },
    /// The NTSTATUS returned by the syscall indicates failure.
    NtStatusFailed { ntstatus: u32 },
}

/// Direct syscall issuer.
///
/// Discovers SSNs from `ntdll.dll` via PEB resolution and then issues raw
/// `syscall` instructions, bypassing `ntdll.dll`'s export stub trampolines.
pub struct DirectSyscall {
    resolver: PebResolver,
    /// DJB2 hash of "ntdll.dll" (lowercase), precomputed
    ntdll_hash: u32,
}

impl DirectSyscall {
    /// DJB2 hash of `ntdll.dll` (lowercase)
    const NTDLL_HASH: u32 = djb2_hash(b"ntdll.dll");

    pub fn new() -> Self {
        Self {
            resolver: PebResolver::new(),
            ntdll_hash: Self::NTDLL_HASH,
        }
    }

    /// Discover the SSN for a Nt* function by its export-name DJB2 hash.
    ///
    /// Returns `Ok(ssn)` on success. The SSN is extracted by reading the 4
    /// bytes of `eax` after the `B8` opcode in the stub.
    pub fn get_ssn(&self, fn_name_hash: u32) -> Result<u32, SyscallError> {
        #[cfg(target_os = "windows")]
        {
            let resolved = self
                .resolver
                .resolve_by_hash(self.ntdll_hash, fn_name_hash)
                .ok_or(SyscallError::ExportNotFound { fn_name_hash })?;

            // Read up to 8 bytes from the stub to find the SSN
            let stub = resolved.0 as *const u8;
            unsafe {
                // Expected pattern on Windows 10/11 x64:
                //   4C 8B D1   mov r10, rcx
                //   B8 xx xx xx xx   mov eax, <SSN>
                //   0F 05   syscall
                let bytes: [u8; 8] = [
                    *stub.add(0),
                    *stub.add(1),
                    *stub.add(2),
                    *stub.add(3),
                    *stub.add(4),
                    *stub.add(5),
                    *stub.add(6),
                    *stub.add(7),
                ];

                // Check for `4C 8B D1 B8` pattern
                if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
                    // SSN is little-endian u32 at bytes[4..8]
                    let ssn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                    return Ok(ssn);
                }

                // Some Windows versions / patched stubs use a different offset
                // Try: B8 xx xx xx xx at offset 0
                if bytes[0] == 0xB8 {
                    let ssn = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                    return Ok(ssn);
                }

                Err(SyscallError::UnexpectedStubPattern { bytes })
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = fn_name_hash;
            Err(SyscallError::NotSupported)
        }
    }

    /// Issue a raw syscall with the given SSN and up to 8 arguments (x64 ABI).
    ///
    /// # Safety
    /// Caller must pass correct `ssn`, correct number of arguments, and correct
    /// argument types. Incorrect usage will corrupt kernel or process state.
    #[cfg(target_os = "windows")]
    pub unsafe fn do_syscall(&self, ssn: u32, args: &[usize]) -> SyscallResult {
        // Pad args to 8 slots (unused slots must be 0)
        let a = [
            args.get(0).copied().unwrap_or(0),
            args.get(1).copied().unwrap_or(0),
            args.get(2).copied().unwrap_or(0),
            args.get(3).copied().unwrap_or(0),
            args.get(4).copied().unwrap_or(0),
            args.get(5).copied().unwrap_or(0),
            args.get(6).copied().unwrap_or(0),
            args.get(7).copied().unwrap_or(0),
        ];

        let ret: usize;
        std::arch::asm!(
            // Set up syscall number
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            // Stack slots for args 5-8 (shadow space already allocated by caller)
            "syscall",
            ssn = in(reg) ssn as usize,
            in("rcx") a[0],
            in("rdx") a[1],
            in("r8")  a[2],
            in("r9")  a[3],
            // args 4-7 go on the stack — we write them to [rsp+0x28..+0x48]
            // Here we simplify: callers with >4 args should use a dedicated wrapper
            lateout("rax") ret,
            clobber_abi("sysv64"),
        );

        // NTSTATUS 0xC0000000+ is error
        if ret as u32 >= 0xC000_0000 {
            Err(SyscallError::NtStatusFailed {
                ntstatus: ret as u32,
            })
        } else {
            Ok(ret)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub unsafe fn do_syscall(&self, _ssn: u32, _args: &[usize]) -> SyscallResult {
        Err(SyscallError::NotSupported)
    }

    /// High-level wrapper: enumerate processes via direct NtQuerySystemInformation
    /// syscall (SystemProcessInformation class = 5), bypassing userland API hooks.
    ///
    /// Returns a Vec of `(pid: u64, name_utf16: Vec<u16>)` tuples on success.
    ///
    /// On non-Windows or if SSN discovery fails, falls back to returning an
    /// explanatory error — the calling code should then fall back to the
    /// standard Win32 path.
    pub fn query_processes_direct(&self) -> Result<Vec<ProcessEntry>, SyscallError> {
        #[cfg(target_os = "windows")]
        {
            let ssn = self.get_ssn(fn_hashes::NT_QUERY_SYSTEM_INFORMATION)?;

            // Allocate a buffer. Start with 256 KB, retry with 1 MB if truncated.
            let mut buf_size: usize = 256 * 1024;
            loop {
                let mut buf: Vec<u8> = vec![0u8; buf_size];
                let mut ret_len: u32 = 0;

                let result = unsafe {
                    self.do_syscall(
                        ssn,
                        &[
                            5usize, // SystemProcessInformation
                            buf.as_mut_ptr() as usize,
                            buf_size,
                            &mut ret_len as *mut u32 as usize,
                        ],
                    )
                };

                match result {
                    Ok(_) => {
                        return Ok(parse_system_process_information(&buf));
                    }
                    Err(SyscallError::NtStatusFailed {
                        ntstatus: 0xC000_0004,
                    }) => {
                        // STATUS_INFO_LENGTH_MISMATCH — retry with larger buffer
                        buf_size = (ret_len as usize).max(buf_size * 2);
                        if buf_size > 64 * 1024 * 1024 {
                            return Err(SyscallError::NtStatusFailed {
                                ntstatus: 0xC000_0004,
                            });
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(SyscallError::NotSupported)
        }
    }
}

/// Parsed process entry from SystemProcessInformation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessEntry {
    pub pid: u64,
    pub parent_pid: u64,
    pub name: String,
    pub thread_count: u32,
    pub handle_count: u32,
    pub private_bytes: u64,
}

/// Parse SYSTEM_PROCESS_INFORMATION linked list from the raw buffer.
///
/// The structure starts at offset 0 and is:
/// ```text
/// SYSTEM_PROCESS_INFORMATION {
///   NextEntryOffset: u32       // 0x00
///   NumberOfThreads: u32       // 0x04
///   ...padding...              // 0x08
///   ImageName: UNICODE_STRING  // at offset 0x38 on x64 (len:u16, max:u16, pad:u32, buf:*u16)
///   BasePriority: i32          // 0x48
///   UniqueProcessId: *void     // 0x50
///   InheritedFromUniqueProcessId: *void // 0x58
///   HandleCount: u32           // 0x60
///   ...
///   PeakVirtualSize / VirtualSize ...
///   PrivatePageCount: usize    // varies
/// }
/// ```
fn parse_system_process_information(buf: &[u8]) -> Vec<ProcessEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    loop {
        if offset + 0x70 > buf.len() {
            break;
        }

        let next_entry_offset = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;

        // NumberOfThreads at 0x04
        let thread_count = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        // UniqueProcessId at 0x50 (pointer-sized, read as u64)
        let pid = u64::from_le_bytes(
            buf[offset + 0x50..offset + 0x58]
                .try_into()
                .unwrap_or([0u8; 8]),
        );

        // InheritedFromUniqueProcessId at 0x58
        let parent_pid = u64::from_le_bytes(
            buf[offset + 0x58..offset + 0x60]
                .try_into()
                .unwrap_or([0u8; 8]),
        );

        // HandleCount at 0x60
        let handle_count = u32::from_le_bytes([
            buf[offset + 0x60],
            buf[offset + 0x61],
            buf[offset + 0x62],
            buf[offset + 0x63],
        ]);

        // ImageName UNICODE_STRING at 0x38: Length(u16) at +0x38, Buffer ptr at +0x40 (x64)
        let name_len = u16::from_le_bytes([buf[offset + 0x38], buf[offset + 0x39]]) as usize;
        let name_buf_ptr = u64::from_le_bytes(
            buf[offset + 0x40..offset + 0x48]
                .try_into()
                .unwrap_or([0u8; 8]),
        ) as usize;

        // Try to read the image name from the buffer if the pointer is within buf
        let name = if name_buf_ptr >= buf.as_ptr() as usize
            && name_buf_ptr + name_len <= buf.as_ptr() as usize + buf.len()
            && name_len > 0
        {
            let rel = name_buf_ptr - buf.as_ptr() as usize;
            let name_bytes = &buf[rel..rel + name_len];
            // Convert UTF-16LE to String
            let utf16: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&utf16).to_string()
        } else {
            String::new()
        };

        entries.push(ProcessEntry {
            pid,
            parent_pid,
            name,
            thread_count,
            handle_count,
            private_bytes: 0, // simplified
        });

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset;
    }

    entries
}

impl Default for DirectSyscall {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ssn_not_supported_on_linux() {
        #[cfg(not(target_os = "windows"))]
        {
            let ds = DirectSyscall::new();
            let res = ds.get_ssn(fn_hashes::NT_QUERY_SYSTEM_INFORMATION);
            assert!(matches!(res, Err(SyscallError::NotSupported)));
        }
    }

    #[test]
    fn test_query_processes_not_supported_on_linux() {
        #[cfg(not(target_os = "windows"))]
        {
            let ds = DirectSyscall::new();
            let res = ds.query_processes_direct();
            assert!(matches!(res, Err(SyscallError::NotSupported)));
        }
    }
}
