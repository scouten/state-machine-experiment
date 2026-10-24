// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Read-session C exports.

use std::{
    ffi::{c_char, c_void},
    ptr,
};

use super::{ffi_call, ffi_call_without_error_output};
use crate::{
    read::{C2paSmReadRequest, ReadSession},
    C2PA_SM_STEP_ERROR,
};

/// Opaque read-session handle exposed to C.
pub struct C2paSmReadSession {
    inner: ReadSession,
}

/// Creates a new sans-I/O read session.
///
/// # Safety
/// `format` and non-null `settings_json` must be valid null-terminated C strings.
/// A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_new(
    format: *const c_char,
    settings_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut C2paSmReadSession {
    ffi_call(err_out, ptr::null_mut(), || {
        let format = cimpl::cstr_or_return_null!(format);
        let settings = if settings_json.is_null() {
            None
        } else {
            Some(cimpl::cstr_or_return_null!(settings_json))
        };
        let session = cimpl::ok_or_return_null!(ReadSession::new(&format, settings.as_deref()));
        cimpl::box_tracked!(C2paSmReadSession { inner: session })
    })
}

/// Advances the read session.
///
/// The returned array and all nested pointers borrow session-owned buffers and are
/// valid until the next `c2pa_sm_read_advance`, `c2pa_sm_read_finish`, or
/// `c2pa_sm_read_free` call. Fulfillment calls do not invalidate them.
/// Each request is returned only once; its ID remains outstanding until a reply is
/// accepted. Async hosts must copy request details and payloads before advancing again.
///
/// # Safety
/// `session`, `out_requests`, and `out_count` must be valid pointers; a non-null
/// `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_advance(
    session: *mut C2paSmReadSession,
    out_requests: *mut *const C2paSmReadRequest,
    out_count: *mut usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, C2PA_SM_STEP_ERROR, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        cimpl::ptr_or_return_int!(out_requests);
        cimpl::ptr_or_return_int!(out_count);

        let step = cimpl::ok_or_return_int!(session.inner.advance());
        let requests = session.inner.current_requests();
        // SAFETY: both output pointers were checked above.
        unsafe {
            *out_requests = requests.as_ptr();
            *out_count = requests.len();
        }
        step
    })
}

/// Fulfills a read request with bytes.
///
/// # Safety
/// `session` must be a live session. For nonzero `len`, `bytes` must be valid
/// for reads of `len` bytes. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_fulfill_bytes(
    session: *mut C2paSmReadSession,
    id: u64,
    bytes: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        let bytes = cimpl::bytes_or_return_int!(bytes, len, "bytes");
        cimpl::ok_or_return_int!(session.inner.fulfill_bytes(id, bytes));
        0
    })
}

/// Fulfills a length request.
///
/// # Safety
/// `session` must be a live session. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_fulfill_length(
    session: *mut C2paSmReadSession,
    id: u64,
    length: u64,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        cimpl::ok_or_return_int!(session.inner.fulfill_length(id, length));
        0
    })
}

/// Fulfills a current-time request with UTC epoch seconds.
///
/// # Safety
/// `session` must be a live session. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_fulfill_time(
    session: *mut C2paSmReadSession,
    id: u64,
    epoch_secs: i64,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        cimpl::ok_or_return_int!(session.inner.fulfill_time(id, epoch_secs));
        0
    })
}

/// Fulfills an OCSP request with response DER bytes.
///
/// # Safety
/// `session` must be live. For nonzero `len`, `bytes` must be valid for reads
/// of `len` bytes. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_fulfill_ocsp(
    session: *mut C2paSmReadSession,
    id: u64,
    bytes: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        let bytes = cimpl::bytes_or_return_int!(bytes, len, "bytes");
        cimpl::ok_or_return_int!(session.inner.fulfill_ocsp(id, bytes));
        0
    })
}

/// Fulfills a read request with a host failure.
///
/// # Safety
/// `session` must be live and `msg` a valid null-terminated C string. A
/// non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_fulfill_failed(
    session: *mut C2paSmReadSession,
    id: u64,
    msg: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        let msg = cimpl::cstr_or_return_int!(msg);
        cimpl::ok_or_return_int!(session.inner.fulfill_failed(id, &msg));
        0
    })
}

/// Finishes a read session and retrieves its JSON report.
///
/// Call only after `advance` returns `C2PA_SM_STEP_COMPLETE`. Once valid arguments
/// reach the engine, finishing consumes the workflow even if it returns an error.
///
/// # Safety
/// `session`, `out_json`, and `out_has_manifest` must be valid pointers. A
/// non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_finish(
    session: *mut C2paSmReadSession,
    out_json: *mut *mut c_char,
    out_has_manifest: *mut bool,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmReadSession);
        cimpl::ptr_or_return_int!(out_json);
        cimpl::ptr_or_return_int!(out_has_manifest);

        let (json, found) = cimpl::ok_or_return_int!(session.inner.finish());
        let json_ptr = match json {
            Some(json) => {
                let ptr = cimpl::to_c_string(json);
                if ptr.is_null() {
                    return -1;
                }
                ptr
            }
            None => ptr::null_mut(),
        };
        // SAFETY: both output pointers were checked above.
        unsafe {
            *out_json = json_ptr;
            *out_has_manifest = found;
        }
        0
    })
}

/// Describes where the read session is: the phase it is waiting in, or
/// the one it failed in. Meant for logs and error reports, not for control
/// flow — the wording is not a stable interface. Returns `"Finished"` once
/// `c2pa_sm_read_finish` has been called.
///
/// The caller owns the returned string and must free it with
/// `c2pa_sm_string_free`. Returns null on error.
///
/// # Safety
/// `session` must be a live session. A non-null `err_out` must point to
/// writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_phase(
    session: *mut C2paSmReadSession,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    ffi_call(err_out, ptr::null_mut(), || {
        let session = cimpl::deref_mut_or_return_null!(session, C2paSmReadSession);
        cimpl::to_c_string(session.inner.phase())
    })
}

/// Frees a read session, including a partially driven or cancelled session.
///
/// # Safety
/// `session` must be null or a live pointer returned by [`c2pa_sm_read_new`].
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_free(session: *mut C2paSmReadSession) {
    ffi_call_without_error_output(|| {
        if !session.is_null() {
            let _ = cimpl::cimpl_free(session.cast::<c_void>());
        }
    });
}
