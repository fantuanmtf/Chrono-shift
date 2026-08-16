//! FFI bridge — Rust to C ABI (v7.6 — Phase 1.1: AtomicPtr proxy to AppState)
//!
//! C callers must call ffi_set_app_state() once during initialization.
//! All F2F operations are forwarded to AppState via raw pointer indirection.
//!
//! SAFETY CONTRACT (audit fixes):
//!   - every extern function that dereferences a C pointer is marked
//!     `unsafe fn`: the CALLER must guarantee valid, correctly-sized,
//!     correctly-aligned buffers for the stated lifetimes;
//!   - every panic-prone extern function routes through ffi_guard! so a
//!     Rust panic never unwinds across the extern "C" boundary;
//!   - rust_encrypt_e2e / rust_decrypt_e2e return buffers allocated by
//!     Rust; the C side MUST free them with rust_free_bytes(p, len) using
//!     exactly the length reported in out_len;
//!   - rust_parse_json / rust_escape_json / rust_f2f_**
//!     string results MUST be freed with rust_free_string.
use crate::app::AppState;
use crate::crypto;
use crate::parser;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;
use zeroize::Zeroize;

/// Maximum length (bytes) accepted by length-taking FFI entry points.
const MAX_FFI_BUF: u32 = 1024 * 1024; // 1 MiB
/// Maximum length (bytes) of a C string read by rust_parse_json.
const MAX_JSON_CSTR_BYTES: usize = 64 * 1024; // 64 KiB

// ---- AppState proxy ----
static APP_STATE_PTR: AtomicPtr<Mutex<AppState>> = AtomicPtr::new(std::ptr::null_mut());

/// C callers must call this once during initialization to inject AppState.
/// After calling, all other FFI functions can operate on the F2F bridge.
///
/// # Safety
/// the pointer must be a valid, aligned Box<Mutex<AppState>> (or
/// similar heap allocation) that is not freed while the process lives and
/// is never replaced with a dangling pointer.
#[no_mangle]
pub unsafe extern "C" fn ffi_set_app_state(state: *mut Mutex<AppState>) {
    APP_STATE_PTR.store(state, Ordering::SeqCst);
}

/// Helper: access the F2fDcNetBridge through AppState proxy.
/// Returns None if ffi_set_app_state has not been called yet.
fn with_bridge<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut crate::dcnet::f2f::F2fDcNetBridge) -> R,
{
    let ptr = APP_STATE_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: C caller guarantees the pointer is valid for the process
    // lifetime (see ffi_set_app_state). We only create a SHARED reference —
    // Mutex::lock takes &self, so no &mut alias is ever formed here.
    let state: &Mutex<AppState> = unsafe { &*ptr };
    let mut guard = state.lock().ok()?;
    Some(f(&mut guard.bridge))
}

/// Run a closure, converting any panic into the given default value so a
/// panic never unwinds across the extern "C" boundary (UB).
macro_rules! ffi_guard {
    ($call:expr, $default:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $call)) {
            Ok(v) => v,
            Err(_) => {
                log::error!("FFI call panicked; returning default");
                $default
            }
        }
    };
}

/// Read a NUL-terminated C string, scanning at most `max` bytes. Returns
/// None if the pointer is null, no NUL is found within `max` bytes, or the
/// bytes are not valid UTF-8.
unsafe fn bounded_c_str(p: *const c_char, max: usize) -> Option<String> {
    if p.is_null() {
        return None;
    }
    for i in 0..max {
        if *p.add(i) == 0 {
            let with_nul = std::slice::from_raw_parts(p as *const u8, i + 1);
            return CStr::from_bytes_with_nul(with_nul)
                .ok()
                .and_then(|c| c.to_str().ok())
                .map(|s| s.to_string());
        }
    }
    None
}

// === Crypto FFI ===

/// # Safety
/// plaintext/key must point to buffers of at least
/// plaintext_len/32 bytes; out_len must be writable. The returned buffer
/// must be freed with rust_free_bytes(p, *out_len).
#[no_mangle]
pub unsafe extern "C" fn rust_encrypt_e2e(
    plaintext: *const u8,
    plaintext_len: u32,
    key: *const u8,
    out_len: *mut u32,
) -> *mut u8 {
    ffi_guard!(
        {
            if plaintext.is_null() || key.is_null() || out_len.is_null() {
                return std::ptr::null_mut();
            }
            // CRIT-5 (v8.0 audit): reject absurd lengths before unsafe ops.
            if plaintext_len == 0 || plaintext_len > 65536 {
                return std::ptr::null_mut();
            }
            let pt = std::slice::from_raw_parts(plaintext, plaintext_len as usize);
            let mut karr = [0u8; 32];
            karr.copy_from_slice(std::slice::from_raw_parts(key, 32));
            let result = match crypto::encrypt_e2e(pt, &karr) {
                Some(r) => {
                    *out_len = r.len() as u32;
                    let mut v = r.into_boxed_slice();
                    let p = v.as_mut_ptr();
                    std::mem::forget(v);
                    p
                }
                None => std::ptr::null_mut(),
            };
            karr.zeroize(); // S1 fix: clear key from stack
            result
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// enc/key must point to buffers of at least enc_len/32 bytes;
/// out_len must be writable. The returned buffer must be freed with
/// rust_free_bytes(p, *out_len).
#[no_mangle]
pub unsafe extern "C" fn rust_decrypt_e2e(
    enc: *const u8,
    enc_len: u32,
    key: *const u8,
    out_len: *mut u32,
) -> *mut u8 {
    ffi_guard!(
        {
            if enc.is_null() || key.is_null() || out_len.is_null() {
                return std::ptr::null_mut();
            }
            // CRIT-5 (v8.0 audit): reject absurd lengths before unsafe ops.
            if enc_len == 0 || enc_len > 65536 {
                return std::ptr::null_mut();
            }
            let e = std::slice::from_raw_parts(enc, enc_len as usize);
            let mut karr = [0u8; 32];
            karr.copy_from_slice(std::slice::from_raw_parts(key, 32));
            let result = match crypto::decrypt_e2e(e, &karr) {
                Some(r) => {
                    *out_len = r.len() as u32;
                    let mut v = r.into_boxed_slice();
                    let p = v.as_mut_ptr();
                    std::mem::forget(v);
                    p
                }
                None => std::ptr::null_mut(),
            };
            karr.zeroize(); // S1 fix: clear key from stack
            result
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// buf must be writable for at least len bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_secure_random(buf: *mut u8, len: u32) -> i32 {
    ffi_guard!(
        {
            if buf.is_null() || len > MAX_FFI_BUF {
                -1
            } else {
                let b = std::slice::from_raw_parts_mut(buf, len as usize);
                b.copy_from_slice(&crypto::secure_random_bytes(len as usize));
                0
            }
        },
        -1
    )
}

/// # Safety
/// a/b must point to buffers of at least al/bl bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_constant_time_eq(
    a: *const u8,
    al: u32,
    b: *const u8,
    bl: u32,
) -> i32 {
    ffi_guard!(
        {
            if a.is_null() || b.is_null() {
                0
            } else {
                crypto::constant_time_eq(
                    std::slice::from_raw_parts(a, al as usize),
                    std::slice::from_raw_parts(b, bl as usize),
                ) as i32
            }
        },
        0
    )
}

/// # Safety
/// i must be a valid NUL-terminated C string. Result must be freed
/// with rust_free_string.
#[no_mangle]
pub unsafe extern "C" fn rust_parse_json(i: *const c_char) -> *mut c_char {
    ffi_guard!(
        {
            if i.is_null() {
                std::ptr::null_mut()
            } else {
                // Cap the C string at 64 KiB before trusting the NUL
                // terminator — an unterminated/gigantic buffer must not be
                // scanned without bound.
                match bounded_c_str(i, MAX_JSON_CSTR_BYTES) {
                    Some(s) => match parser::parse_json(&s) {
                        Some(_) => CString::new("ok").unwrap().into_raw(),
                        None => std::ptr::null_mut(),
                    },
                    None => std::ptr::null_mut(),
                }
            }
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// i must be a valid NUL-terminated C string. Result must be freed
/// with rust_free_string.
#[no_mangle]
pub unsafe extern "C" fn rust_escape_json(i: *const c_char) -> *mut c_char {
    ffi_guard!(
        {
            if i.is_null() {
                std::ptr::null_mut()
            } else {
                let s = CStr::from_ptr(i).to_str().unwrap_or("");
                CString::new(parser::escape_json(s))
                    .unwrap_or_default()
                    .into_raw()
            }
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// d must point to at least l bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_utf8(d: *const u8, l: u32) -> i32 {
    ffi_guard!(
        {
            if d.is_null() {
                0
            } else if simdutf8::basic::from_utf8(std::slice::from_raw_parts(d, l as usize)).is_ok()
            {
                1
            } else {
                0
            }
        },
        0
    )
}

/// # Safety
/// p must be a pointer previously returned by rust_encrypt_e2e /
/// rust_decrypt_e2e and l must be exactly the length that was reported in
/// out_len for that allocation.
#[no_mangle]
pub unsafe extern "C" fn rust_free_bytes(p: *mut u8, l: u32) {
    if !p.is_null() {
        // The allocation side uses Box<[u8]> (into_boxed_slice + forget), so
        // reconstruct the matching Box here. Vec::from_raw_parts would hand
        // the allocator a mismatched (layout/drop-glue) pointer — UB.
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            p, l as usize,
        )));
    }
}

/// # Safety
/// p must be a pointer previously returned by a string-returning FFI
/// function (rust_parse_json / rust_escape_json / rust_f2f_*), and must not
/// have been freed already or passed twice.
#[no_mangle]
pub unsafe extern "C" fn rust_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

/// # Safety
/// p must be writable for at least l bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_secure_clear(p: *mut u8, l: u32) {
    ffi_guard!(
        {
            // Refuse to touch oversized buffers (no return value, so the
            // "error" is a no-op that leaves the buffer untouched).
            if !p.is_null() && l <= MAX_FFI_BUF {
                crypto::secure_clear(std::slice::from_raw_parts_mut(p, l as usize));
            }
        },
        ()
    )
}

// === F2F Bridge FFI ===
// Phase 1.1: All bridge access goes through APP_STATE_PTR → AppState.bridge.
// with_bridge() and f2f_or!() are defined at the top of this file.

/// # Safety
/// p must be null or point to a valid NUL-terminated C string.
unsafe fn safe_c_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(|s| s.to_string())
}

macro_rules! c_str {
    ($p:expr) => {{
        unsafe { safe_c_str($p).unwrap_or_default() }
    }};
}

// Phase 1.1: rust_f2f_init is a no-op — bridge is always initialized in AppState.
// C callers should call ffi_set_app_state() instead.
#[no_mangle]
pub extern "C" fn rust_f2f_init(_my_uid: *const c_char) -> i32 {
    0
}

// F2F helpers: bridge access without panic (HIGH-6 fix)
macro_rules! f2f_or {
    ($call:expr, $default:expr) => {
        with_bridge($call).unwrap_or($default)
    };
}

/// # Safety
/// uid/addr must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_add_friend(
    uid: *const c_char,
    addr: *const c_char,
    tl: u8,
) -> i32 {
    ffi_guard!(
        {
            if uid.is_null() || addr.is_null() {
                -1
            } else {
                f2f_or!(
                    |b| {
                        b.add_friend(&c_str!(uid), &c_str!(addr), tl);
                        0
                    },
                    -1
                )
            }
        },
        -1
    )
}

/// # Safety
/// uid must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_remove_friend(uid: *const c_char) -> i32 {
    ffi_guard!(
        {
            if uid.is_null() {
                -1
            } else {
                f2f_or!(
                    |b| {
                        b.remove_friend(&c_str!(uid));
                        0
                    },
                    -1
                )
            }
        },
        -1
    )
}

/// # Safety
/// uid must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_update_trust(uid: *const c_char, tl: u8) -> i32 {
    ffi_guard!(
        {
            if uid.is_null() {
                -1
            } else {
                f2f_or!(
                    |b| {
                        b.update_trust(&c_str!(uid), tl);
                        0
                    },
                    -1
                )
            }
        },
        -1
    )
}

/// Result must be freed with rust_free_string.
#[no_mangle]
pub extern "C" fn rust_f2f_form_group() -> *mut c_char {
    ffi_guard!(
        f2f_or!(
            |b| {
                b.create_channel("#main");
                CString::new(
                    serde_json::to_string(&b.list_channels()).unwrap_or_else(|_| "[]".into()),
                )
                .unwrap_or_default()
                .into_raw()
            },
            std::ptr::null_mut()
        ),
        std::ptr::null_mut()
    )
}

/// # Safety
/// uid must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_is_trusted(uid: *const c_char) -> i32 {
    ffi_guard!(
        {
            if uid.is_null() {
                0
            } else {
                f2f_or!(|b| b.is_trusted(&c_str!(uid)) as i32, 0)
            }
        },
        0
    )
}

/// # Safety
/// uid must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_get_trust(uid: *const c_char) -> u8 {
    ffi_guard!(
        {
            if uid.is_null() {
                0
            } else {
                f2f_or!(|b| b.get_trust(&c_str!(uid)), 0)
            }
        },
        0
    )
}

/// Result must be freed with rust_free_string.
#[no_mangle]
pub extern "C" fn rust_f2f_sync_reputation() -> *mut c_char {
    ffi_guard!(
        f2f_or!(
            |b| {
                let c = b.sync_reputation_to_trust();
                CString::new(serde_json::to_string(&c).unwrap_or_else(|_| "[]".into()))
                    .unwrap_or_default()
                    .into_raw()
            },
            std::ptr::null_mut()
        ),
        std::ptr::null_mut()
    )
}

/// Result must be freed with rust_free_string.
#[no_mangle]
pub extern "C" fn rust_f2f_group_status() -> *mut c_char {
    ffi_guard!(
        {
            let status = f2f_or!(
                |b| b.group_status(),
                r#"{"error":"not_initialized"}"#.to_string()
            );
            CString::new(status).unwrap_or_default().into_raw()
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// name must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_create_channel(name: *const c_char) -> i32 {
    ffi_guard!(
        {
            if name.is_null() {
                -1
            } else {
                f2f_or!(|b| b.create_channel(&c_str!(name)) as i32, -1)
            }
        },
        -1
    )
}

/// # Safety
/// ch/uids_json must be valid NUL-terminated C strings.
/// Result must be freed with rust_free_string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_join_channel(
    ch: *const c_char,
    uids_json: *const c_char,
) -> *mut c_char {
    ffi_guard!(
        {
            if ch.is_null() || uids_json.is_null() {
                return std::ptr::null_mut();
            }
            let uids: Vec<String> = serde_json::from_str(&c_str!(uids_json)).unwrap_or_default();
            f2f_or!(
                |b| {
                    let j = b.join_channel(&c_str!(ch), &uids);
                    CString::new(serde_json::to_string(&j).unwrap_or_else(|_| "[]".into()))
                        .unwrap_or_default()
                        .into_raw()
                },
                std::ptr::null_mut()
            )
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// name must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_leave_channel(name: *const c_char) -> i32 {
    ffi_guard!(
        {
            if name.is_null() {
                -1
            } else {
                f2f_or!(
                    |b| {
                        b.leave_channel(&c_str!(name));
                        0
                    },
                    -1
                )
            }
        },
        -1
    )
}

/// Result must be freed with rust_free_string.
#[no_mangle]
pub extern "C" fn rust_f2f_list_channels() -> *mut c_char {
    ffi_guard!(
        {
            let channels = f2f_or!(|b| b.list_channels(), Vec::new());
            CString::new(serde_json::to_string(&channels).unwrap_or_else(|_| "[]".into()))
                .unwrap_or_default()
                .into_raw()
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// name must be a valid NUL-terminated C string.
/// Result must be freed with rust_free_string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_channel_status(name: *const c_char) -> *mut c_char {
    ffi_guard!(
        {
            if name.is_null() {
                std::ptr::null_mut()
            } else {
                f2f_or!(
                    |b| CString::new(b.channel_status(&c_str!(name)))
                        .unwrap_or_default()
                        .into_raw(),
                    std::ptr::null_mut()
                )
            }
        },
        std::ptr::null_mut()
    )
}

/// # Safety
/// name must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_f2f_switch_channel(name: *const c_char) -> i32 {
    ffi_guard!(
        {
            if name.is_null() {
                -1
            } else {
                f2f_or!(|b| b.switch_channel(&c_str!(name)) as i32, -1)
            }
        },
        -1
    )
}

#[cfg(test)]
mod tests {
    use super::{rust_free_string, rust_parse_json};
    use std::ffi::CString;

    #[test]
    fn test_parse_json_ok_and_free_string() {
        let input = CString::new(r#"{"uid":"alice"}"#).unwrap();
        let p = unsafe { rust_parse_json(input.as_ptr()) };
        assert!(!p.is_null());
        // Free the returned C string exactly once (regression: must not leak).
        unsafe { rust_free_string(p) };
    }

    #[test]
    fn test_parse_json_rejects_invalid() {
        let input = CString::new("{invalid").unwrap();
        let p = unsafe { rust_parse_json(input.as_ptr()) };
        assert!(p.is_null());
    }

    #[test]
    fn test_free_string_null_is_noop() {
        unsafe { rust_free_string(std::ptr::null_mut()) };
    }
}
