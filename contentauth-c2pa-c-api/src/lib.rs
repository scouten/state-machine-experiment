// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! Tracked C ABI for synchronous, sans-I/O reading and signing.
//!
//! The host owns I/O, scheduling, keys and networking. Drive a session with
//! advance/request/fulfill, then consume it with finish. Reader finish consumes
//! a valid session on every outcome, including a null output or an early finish;
//! build finish has the same contract. Invalid or busy handles are not consumed.
//! Error objects are owned values, independent of their originating session.
//!
//! All opaque objects and returned strings are cimpl-tracked. Stale, null and
//! wrong-type handles are rejected without dereferencing caller-owned memory.
//! Borrowed request/report/error views still require the host to keep their
//! owner alive and serialize mutations with use of those views. Registry
//! bookkeeping briefly locks; no call performs host I/O, spawns or calls back.
//!
//! The generated header declares both workflows even when one is disabled.
//! Disabled workflows fail at link time. Common errors/strings need neither
//! feature; both `read` and `build` are enabled by default.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn, missing_docs)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[cfg(any(feature = "read", feature = "build"))]
use std::ffi::CStr;
use std::{
    collections::HashSet,
    ffi::{c_char, c_int, CString},
    sync::{Mutex, OnceLock},
};
#[cfg(any(feature = "read", feature = "build", test))]
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

#[cfg(feature = "read")]
mod reading;
#[cfg(feature = "read")]
pub use reading::*;
#[cfg(feature = "build")]
mod signing;
#[cfg(feature = "build")]
pub use signing::*;

/// Success.
pub const C2PA_SM_OK: c_int = 0;
/// Invalid argument, settings, handle, request ID or reply kind.
pub const C2PA_SM_ERR_INVALID_ARGUMENT: c_int = 1;
/// Unsupported container format.
pub const C2PA_SM_ERR_UNSUPPORTED_TYPE: c_int = 2;
/// No manifest store was found.
pub const C2PA_SM_ERR_NOT_FOUND: c_int = 3;
/// Reading or validation could not complete.
pub const C2PA_SM_ERR_READ: c_int = 4;
/// A Rust panic was caught at the boundary.
pub const C2PA_SM_ERR_PANIC: c_int = 5;

/// An independently owned, tracked error; free with [`c2pa_sm_error_free`].
pub struct C2paSmError {
    code: c_int,
    message: CString,
    name: CString,
}

#[derive(Debug)]
#[cfg(any(feature = "read", feature = "build", test))]
struct Failure {
    code: c_int,
    message: String,
    name: String,
}

#[cfg(any(feature = "read", feature = "build", test))]
impl Failure {
    fn invalid(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code: C2PA_SM_ERR_INVALID_ARGUMENT,
            name: format!("C2pa(BadParam({message:?}))"),
            message,
        }
    }
}

#[cfg(any(feature = "read", feature = "build", test))]
fn handle_error(error: cimpl::Error) -> Failure {
    Failure::invalid(error.to_string())
}

#[cfg(any(feature = "read", feature = "build", test))]
fn tracked<T: 'static + Send>(value: T) -> Result<*mut T, Failure> {
    cimpl::ensure_trackable().map_err(handle_error)?;
    let handle = cimpl::track_box(Box::into_raw(Box::new(value)));
    if handle.is_null() {
        return Err(Failure::invalid("could not track allocation"));
    }
    Ok(handle)
}

#[cfg(any(feature = "read", feature = "build", test))]
fn c_string(s: &str) -> CString {
    CString::new(s.replace('\0', "\u{fffd}")).unwrap_or_default()
}

// cimpl's public string free is intentionally untyped. Limit it to our strings
// so passing a different tracked object to string_free cannot destroy it.
fn strings() -> &'static Mutex<HashSet<usize>> {
    static STRINGS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    STRINGS.get_or_init(Mutex::default)
}

#[cfg(feature = "read")]
fn owned_string(s: &str) -> *mut c_char {
    let Ok(mut strings) = strings().lock() else {
        return ptr::null_mut();
    };
    let string = cimpl::to_c_string(s.replace('\0', "\u{fffd}"));
    if !string.is_null() {
        strings.insert(string as usize);
    }
    string
}

#[cfg(any(feature = "read", feature = "build", test))]
unsafe fn guard(
    out_error: *mut *mut C2paSmError,
    f: impl FnOnce() -> Result<(), Failure>,
) -> c_int {
    let failure = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => return C2PA_SM_OK,
        Ok(Err(failure)) => failure,
        Err(_) => Failure {
            code: C2PA_SM_ERR_PANIC,
            message: "internal error: panic in contentauth-c2pa-c-api".into(),
            name: "Panic".into(),
        },
    };
    let code = failure.code;
    if !out_error.is_null() {
        let error = C2paSmError {
            code,
            message: c_string(&failure.message),
            name: c_string(&failure.name),
        };
        if let Ok(error) = tracked(error) {
            unsafe { *out_error = error };
        }
    }
    code
}

#[cfg(any(feature = "read", feature = "build"))]
unsafe fn clear<T>(out: *mut *mut T) {
    if !out.is_null() {
        unsafe { *out = ptr::null_mut() };
    }
}

#[cfg(any(feature = "read", feature = "build"))]
unsafe fn utf8<'a>(s: *const c_char, what: &str) -> Result<&'a str, Failure> {
    if s.is_null() {
        return Err(Failure::invalid(format!("{what} is null")));
    }
    unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| Failure::invalid(format!("{what} is not valid UTF-8")))
}

/// Library version, NUL-terminated and static.
#[no_mangle]
pub extern "C" fn c2pa_sm_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Frees a returned string. Null, stale and non-string handles are no-ops.
///
/// # Safety
/// No host may access the string during or after its successful destruction.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_string_free(s: *mut c_char) {
    if let Ok(mut strings) = strings().lock() {
        if strings.remove(&(s as usize)) {
            let _ = cimpl::cimpl_free(s.cast());
        }
    }
}

/// Error code; INVALID_ARGUMENT for null, stale or wrong-type handles.
///
/// # Safety
/// Serialize destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_code(error: *const C2paSmError) -> c_int {
    cimpl::checkout_shared(error.cast_mut()).map_or(C2PA_SM_ERR_INVALID_ARGUMENT, |e| e.code)
}

/// Borrowed NUL-terminated message; empty for invalid handles.
///
/// # Safety
/// Keep the error alive until use of the returned borrow ends.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_message(error: *const C2paSmError) -> *const c_char {
    cimpl::checkout_shared(error.cast_mut()).map_or(c"".as_ptr(), |e| e.message.as_ptr())
}

/// Borrowed c2pa-rs Debug-spelled name; empty for invalid handles.
///
/// # Safety
/// Keep the error alive until use of the returned borrow ends.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_name(error: *const C2paSmError) -> *const c_char {
    cimpl::checkout_shared(error.cast_mut()).map_or(c"".as_ptr(), |e| e.name.as_ptr())
}

/// Frees an owned error. Null, stale, wrong-type and busy handles are no-ops.
///
/// # Safety
/// No borrowed error string may remain in use when destruction succeeds.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_free(error: *mut C2paSmError) {
    let _ = cimpl::untrack_owned(error);
}

#[cfg(test)]
mod common_tests;
