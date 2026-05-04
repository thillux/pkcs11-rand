//! Shared helpers for the p11rand CLI tools: dlopen the module, resolve
//! `C_GetFunctionList`, install a two-strikes signal handler.

#![allow(non_snake_case, non_camel_case_types)]

use std::sync::atomic::{AtomicI32, Ordering};

use cryptoki_sys::{CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_RV, CKR_OK};
use libloading::{Library, Symbol};

pub use cryptoki_sys;

pub struct Module {
    // Drop order matters: `funcs` references memory inside `_lib`, so the
    // library must outlive the function pointers we hold.
    pub funcs: &'static CK_FUNCTION_LIST,
    _lib: Library,
}

pub fn load_module(path: &str) -> Result<Module, String> {
    let lib = unsafe { Library::new(path) }
        .map_err(|e| format!("dlopen {path}: {e}"))?;
    let get_fn: Symbol<unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV> =
        unsafe { lib.get(b"C_GetFunctionList\0") }
            .map_err(|e| format!("dlsym C_GetFunctionList: {e}"))?;

    let mut fl: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
    let rv = unsafe { get_fn(&mut fl) };
    if rv != CKR_OK || fl.is_null() {
        return Err(format!("C_GetFunctionList failed: 0x{rv:x}"));
    }
    // Convert to a 'static reference: the function-list table lives in the
    // .so for the lifetime of the module mapping (i.e., until `lib` drops).
    let funcs: &'static CK_FUNCTION_LIST = unsafe { &*(fl as *const CK_FUNCTION_LIST) };
    Ok(Module { funcs, _lib: lib })
}

/// PKCS#11 strings are space-padded, not NUL-terminated. Trim trailing
/// spaces and decode as UTF-8 (lossy).
pub fn trim_pkcs11(field: &[u8]) -> String {
    let end = field
        .iter()
        .rposition(|&b| b != b' ')
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Two-strikes signal counter (SIGINT / SIGTERM). The first signal sets the
/// counter to 1 (callers should drain in-flight work and exit cleanly). A
/// second signal is the caller's cue to short-circuit with `_exit(130)`.
pub static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// Reset the counter (call before installing the handler).
pub fn signal_reset() {
    SIGNAL_COUNT.store(0, Ordering::SeqCst);
}

pub fn signal_count() -> i32 {
    SIGNAL_COUNT.load(Ordering::SeqCst)
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    let prev = SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
    if prev >= 1 {
        unsafe { libc::_exit(130) };
    }
}

/// Install a SIGINT/SIGTERM handler. Optionally, also `signal(SIGPIPE, SIG_IGN)`
/// when we expect to write to stdout (so EPIPE bubbles up as a write error).
pub fn install_signals(ignore_sigpipe: bool) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        if ignore_sigpipe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
    }
}
