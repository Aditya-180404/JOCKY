//! Safe programmatic wrappers around LLVM C API constructs
//!
//! Provides RAII management for `LLVMContextRef`, `LLVMModuleRef`, and `LLVMBuilderRef`,
//! preventing memory leaks and simplifying LLVM IR generation and verification.

use llvm_sys::analysis::{LLVMVerifierFailureAction, LLVMVerifyModule};
use llvm_sys::core::*;
use llvm_sys::prelude::*;
use std::ffi::{CStr, CString};

/// Safe wrapper around `LLVMContextRef`
pub struct LlvmContext {
    raw: LLVMContextRef,
}

impl LlvmContext {
    pub fn new() -> Self {
        unsafe {
            let raw = LLVMContextCreate();
            Self { raw }
        }
    }

    #[inline]
    pub fn as_raw(&self) -> LLVMContextRef {
        self.raw
    }
}

impl Default for LlvmContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LlvmContext {
    fn drop(&mut self) {
        unsafe {
            LLVMContextDispose(self.raw);
        }
    }
}

/// Safe wrapper around `LLVMModuleRef`
pub struct LlvmModule {
    raw: LLVMModuleRef,
}

impl LlvmModule {
    pub fn new(name: &str, ctx: &LlvmContext) -> Self {
        let c_name = CString::new(name).unwrap_or_else(|_| CString::new("module").unwrap());
        unsafe {
            let raw = LLVMModuleCreateWithNameInContext(c_name.as_ptr(), ctx.as_raw());
            Self { raw }
        }
    }

    #[inline]
    pub fn as_raw(&self) -> LLVMModuleRef {
        self.raw
    }

    pub fn set_target_triple(&self, triple: &str) {
        let c_triple = CString::new(triple).unwrap();
        unsafe {
            LLVMSetTarget(self.raw, c_triple.as_ptr());
        }
    }

    pub fn set_data_layout(&self, layout: &str) {
        let c_layout = CString::new(layout).unwrap();
        unsafe {
            LLVMSetDataLayout(self.raw, c_layout.as_ptr());
        }
    }

    /// Verifies the module using LLVM's internal module verifier.
    /// Returns Ok(()) if the module is well-formed, or Err(String) with the verifier diagnostics.
    pub fn verify(&self) -> Result<(), String> {
        unsafe {
            let mut err_msg: *mut std::os::raw::c_char = std::ptr::null_mut();
            let failed = LLVMVerifyModule(
                self.raw,
                LLVMVerifierFailureAction::LLVMReturnStatusAction,
                &mut err_msg,
            );
            if failed != 0 {
                let msg = if !err_msg.is_null() {
                    let s = CStr::from_ptr(err_msg).to_string_lossy().into_owned();
                    LLVMDisposeMessage(err_msg);
                    s
                } else {
                    "Unknown LLVM module verification error".to_string()
                };
                Err(msg)
            } else {
                if !err_msg.is_null() {
                    LLVMDisposeMessage(err_msg);
                }
                Ok(())
            }
        }
    }

    /// Print LLVM IR representation directly from the programmatic module
    pub fn print_ir(&self) -> String {
        unsafe {
            let str_ptr = LLVMPrintModuleToString(self.raw);
            if str_ptr.is_null() {
                return String::new();
            }
            let ir = CStr::from_ptr(str_ptr).to_string_lossy().into_owned();
            LLVMDisposeMessage(str_ptr);
            ir
        }
    }
}

impl Drop for LlvmModule {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeModule(self.raw);
        }
    }
}

/// Safe wrapper around `LLVMBuilderRef`
pub struct LlvmBuilder {
    raw: LLVMBuilderRef,
}

impl LlvmBuilder {
    pub fn new(ctx: &LlvmContext) -> Self {
        unsafe {
            let raw = LLVMCreateBuilderInContext(ctx.as_raw());
            Self { raw }
        }
    }

    #[inline]
    pub fn as_raw(&self) -> LLVMBuilderRef {
        self.raw
    }

    /// Positions the builder at the end of the provided basic block.
    ///
    /// # Safety
    /// The caller must ensure that `block` is a valid `LLVMBasicBlockRef` associated with
    /// the same context as this builder.
    #[inline]
    pub unsafe fn position_at_end(&self, block: LLVMBasicBlockRef) {
        LLVMPositionBuilderAtEnd(self.raw, block);
    }
}

impl Drop for LlvmBuilder {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeBuilder(self.raw);
        }
    }
}
