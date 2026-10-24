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

//! Build-session C exports and build-result allocation cleanup.

use std::{
    ffi::{c_char, c_void},
    ptr, slice,
};

use super::{ffi_call, ffi_call_without_error_output};
use crate::{
    build::{BuildSession, C2paSmBuildRequest, C2paSmExclusion},
    error::Error,
    C2PA_SM_STEP_ERROR,
};

/// Opaque build-session handle exposed to C.
pub struct C2paSmBuildSession {
    inner: BuildSession,
}

/// Opaque owner for a finished build's exclusion ranges.
///
/// Obtain the borrowed range pointer with [`c2pa_sm_exclusions_data`] and
/// release this owner with [`c2pa_sm_exclusions_free`].
pub struct C2paSmExclusionList {
    entries: Vec<C2paSmExclusion>,
}

fn certificate_array_bytes(count: usize, entry_size: usize) -> Result<usize, Error> {
    count
        .checked_mul(entry_size)
        .ok_or_else(|| Error::BadParam("certificate count is too large".to_owned()))
}

/// Creates a new sans-I/O build session.
///
/// # Safety
/// String arguments must be valid null-terminated C strings. For nonzero
/// `cert_count`, the certificate pointer and length arrays and each
/// certificate buffer must be valid. A non-null `err_out` must point to
/// writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_new(
    format: *const c_char,
    definition_json: *const c_char,
    alg: *const c_char,
    certs_der: *const *const u8,
    cert_lens: *const usize,
    cert_count: usize,
    err_out: *mut *mut c_char,
) -> *mut C2paSmBuildSession {
    ffi_call(err_out, ptr::null_mut(), || {
        let format = cimpl::cstr_or_return_null!(format);
        let definition_json = cimpl::cstr_or_return_null!(definition_json);
        let alg = cimpl::cstr_or_return_null!(alg);
        if cert_count == 0 {
            cimpl::Error::other("at least one certificate is required").set_last();
            return ptr::null_mut();
        }
        cimpl::ptr_or_return_null!(certs_der);
        cimpl::ptr_or_return_null!(cert_lens);

        let cert_ptrs_len = cimpl::ok_or_return_null!(certificate_array_bytes(
            cert_count,
            std::mem::size_of::<*const u8>()
        ));
        let cert_lens_len = cimpl::ok_or_return_null!(certificate_array_bytes(
            cert_count,
            std::mem::size_of::<usize>()
        ));
        let _ = cimpl::bytes_or_return_null!(certs_der.cast::<u8>(), cert_ptrs_len, "certs_der");
        let _ = cimpl::bytes_or_return_null!(cert_lens.cast::<u8>(), cert_lens_len, "cert_lens");
        let cert_ptrs = unsafe { slice::from_raw_parts(certs_der, cert_count) };
        let cert_lengths = unsafe { slice::from_raw_parts(cert_lens, cert_count) };
        let mut certs = Vec::with_capacity(cert_count);
        for (index, (&cert_ptr, &cert_len)) in cert_ptrs.iter().zip(cert_lengths).enumerate() {
            if cert_ptr.is_null() || cert_len == 0 {
                cimpl::Error::other(format!("certificate {index} is invalid")).set_last();
                return ptr::null_mut();
            }
            let cert = cimpl::bytes_or_return_null!(cert_ptr, cert_len, "certificate");
            certs.push(cert.to_vec());
        }

        let session =
            cimpl::ok_or_return_null!(BuildSession::new(&format, &definition_json, &alg, certs));
        cimpl::box_tracked!(C2paSmBuildSession { inner: session })
    })
}

/// Advances the build session.
///
/// The returned array and all nested pointers borrow session-owned buffers and are
/// valid until the next `c2pa_sm_build_advance`, `c2pa_sm_build_finish`, or
/// `c2pa_sm_build_free` call. Fulfillment calls do not invalidate them.
/// Each request is returned only once; its ID remains outstanding until a reply is
/// accepted. Async hosts must copy request details and payloads before advancing again.
///
/// # Safety
/// `session`, `out_requests`, and `out_count` must be valid pointers. A
/// non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_advance(
    session: *mut C2paSmBuildSession,
    out_requests: *mut *const C2paSmBuildRequest,
    out_count: *mut usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, C2PA_SM_STEP_ERROR, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
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

/// Fulfills a build read request with bytes.
///
/// # Safety
/// `session` must be live. For nonzero `len`, `bytes` must be valid for reads
/// of `len` bytes. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_bytes(
    session: *mut C2paSmBuildSession,
    id: u64,
    bytes: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        let bytes = cimpl::bytes_or_return_int!(bytes, len, "bytes");
        cimpl::ok_or_return_int!(session.inner.fulfill_bytes(id, bytes));
        0
    })
}

/// Fulfills a build length request.
///
/// # Safety
/// `session` must be live. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_length(
    session: *mut C2paSmBuildSession,
    id: u64,
    length: u64,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        cimpl::ok_or_return_int!(session.inner.fulfill_length(id, length));
        0
    })
}

/// Fulfills a build write request once the host has written the requested bytes.
///
/// # Safety
/// `session` must be live. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_written(
    session: *mut C2paSmBuildSession,
    id: u64,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        cimpl::ok_or_return_int!(session.inner.fulfill_written(id));
        0
    })
}

/// Fulfills a signing request with a COSE-format signature over the full message
/// bytes in the request's `data`. ECDSA uses fixed-width `r || s`, not DER.
///
/// # Safety
/// `session` must be live. For nonzero `sig_len`, `sig` must be valid for reads
/// of `sig_len` bytes. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_signature(
    session: *mut C2paSmBuildSession,
    id: u64,
    sig: *const u8,
    sig_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        let sig = cimpl::bytes_or_return_int!(sig, sig_len, "sig");
        cimpl::ok_or_return_int!(session.inner.fulfill_signature(id, sig));
        0
    })
}

/// Fulfills a timestamp request with DER `TimeStampResp` bytes.
///
/// # Safety
/// `session` must be live. For nonzero `resp_len`, `resp` must be valid for
/// reads of `resp_len` bytes. A non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_timestamp(
    session: *mut C2paSmBuildSession,
    id: u64,
    resp: *const u8,
    resp_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        let resp = cimpl::bytes_or_return_int!(resp, resp_len, "resp");
        cimpl::ok_or_return_int!(session.inner.fulfill_timestamp(id, resp));
        0
    })
}

/// Fulfills a build request with a host failure.
///
/// # Safety
/// `session` must be live and `msg` a valid null-terminated C string. A
/// non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_failed(
    session: *mut C2paSmBuildSession,
    id: u64,
    msg: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        let msg = cimpl::cstr_or_return_int!(msg);
        cimpl::ok_or_return_int!(session.inner.fulfill_failed(id, &msg));
        0
    })
}

/// Finishes the build and returns tracked manifest bytes and an exclusion-list handle.
///
/// Call only after `advance` returns `C2PA_SM_STEP_COMPLETE`. Once valid arguments
/// reach the engine, finishing consumes the workflow even if it returns an error.
///
/// # Safety
/// All output pointers and `session` must be valid. A non-null `err_out` must
/// point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_finish(
    session: *mut C2paSmBuildSession,
    out_manifest_ptr: *mut *mut u8,
    out_manifest_len: *mut usize,
    out_exclusions_ptr: *mut *mut C2paSmExclusionList,
    out_exclusions_count: *mut usize,
    err_out: *mut *mut c_char,
) -> i32 {
    ffi_call(err_out, -1, || {
        let mut session = cimpl::deref_mut_or_return_int!(session, C2paSmBuildSession);
        cimpl::ptr_or_return_int!(out_manifest_ptr);
        cimpl::ptr_or_return_int!(out_manifest_len);
        cimpl::ptr_or_return_int!(out_exclusions_ptr);
        cimpl::ptr_or_return_int!(out_exclusions_count);

        let (manifest, exclusions) = cimpl::ok_or_return_int!(session.inner.finish());
        let manifest_len = manifest.len();
        if manifest_len == 0 {
            cimpl::Error::other("build returned an empty manifest").set_last();
            return -1;
        }
        let manifest_ptr = cimpl::to_c_bytes(manifest);
        if manifest_ptr.is_null() {
            return -1;
        }
        let exclusions_count = exclusions.len();
        let exclusions_ptr = cimpl::box_tracked!(C2paSmExclusionList {
            entries: exclusions
        });
        // SAFETY: output pointers were checked above.
        unsafe {
            *out_manifest_ptr = manifest_ptr.cast_mut();
            *out_manifest_len = manifest_len;
            *out_exclusions_ptr = exclusions_ptr;
            *out_exclusions_count = exclusions_count;
        }
        0
    })
}

/// Returns a borrowed pointer to an exclusion list's entries.
///
/// The pointer is valid until the list is released by [`c2pa_sm_exclusions_free`].
///
/// # Safety
/// `exclusions` must be a live list returned by [`c2pa_sm_build_finish`]. A
/// non-null `err_out` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_exclusions_data(
    exclusions: *mut C2paSmExclusionList,
    err_out: *mut *mut c_char,
) -> *const C2paSmExclusion {
    ffi_call(err_out, ptr::null(), || {
        let exclusions = cimpl::deref_or_return_null!(exclusions, C2paSmExclusionList);
        exclusions.entries.as_ptr()
    })
}

/// Describes where the build session is: the phase it is waiting in, or
/// the one it failed in. Meant for logs and error reports, not for control
/// flow — the wording is not a stable interface. Returns `"Finished"` once
/// `c2pa_sm_build_finish` has been called.
///
/// The caller owns the returned string and must free it with
/// `c2pa_sm_string_free`. Returns null on error.
///
/// # Safety
/// `session` must be a live session. A non-null `err_out` must point to
/// writable storage.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_phase(
    session: *mut C2paSmBuildSession,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    ffi_call(err_out, ptr::null_mut(), || {
        let session = cimpl::deref_mut_or_return_null!(session, C2paSmBuildSession);
        cimpl::to_c_string(session.inner.phase())
    })
}

/// Frees a build session.
///
/// # Safety
/// `session` must be null or a live pointer returned by [`c2pa_sm_build_new`].
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_free(session: *mut C2paSmBuildSession) {
    ffi_call_without_error_output(|| {
        if !session.is_null() {
            let _ = cimpl::cimpl_free(session.cast::<c_void>());
        }
    });
}

/// Frees manifest bytes allocated by this library.
///
/// `len` is retained for ABI clarity; cimpl tracks the allocation's size.
///
/// # Safety
/// `bytes` must be null or an allocation returned by this library.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_bytes_free(bytes: *mut u8, _len: usize) {
    ffi_call_without_error_output(|| {
        if !bytes.is_null() {
            let _ = cimpl::cimpl_free(bytes.cast::<c_void>());
        }
    });
}

/// Frees an exclusion-list handle returned by [`c2pa_sm_build_finish`].
///
/// # Safety
/// `exclusions` must be null or a live handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_exclusions_free(exclusions: *mut C2paSmExclusionList) {
    ffi_call_without_error_output(|| {
        if !exclusions.is_null() {
            let _ = cimpl::cimpl_free(exclusions.cast::<c_void>());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_array_sizes_reject_overflow_before_reading_memory() {
        for width in [
            std::mem::size_of::<*const u8>(),
            std::mem::size_of::<usize>(),
        ] {
            assert!(matches!(certificate_array_bytes(0, width), Ok(0)));
            assert!(matches!(certificate_array_bytes(2, width), Ok(size) if size == 2 * width));
            let largest = usize::MAX / width;
            assert!(certificate_array_bytes(largest, width).is_ok());
            assert!(matches!(
                certificate_array_bytes(largest + 1, width),
                Err(Error::BadParam(message)) if message == "certificate count is too large"
            ));
        }
    }
}
