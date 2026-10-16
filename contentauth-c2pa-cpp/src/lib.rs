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

//! A C ABI over the sans-I/O reader session, and the foundation of the
//! header-only C++ binding in this crate's directory (see its README for
//! the design and how it differs from [c2pa-cpp]).
//!
//! The ABI is the engine's interaction contract, and nothing else:
//!
//! * [`c2pa_sm_session_new`] / [`c2pa_sm_session_free`] — a session is an
//!   opaque heap object with ordinary C++ value semantics (move it, destroy
//!   it; destroying it *is* cancelling it);
//! * [`c2pa_sm_session_advance`] — run the engine as far as it can go, then
//!   [`c2pa_sm_session_request`] each *new* [`C2paSmRequest`] it wants;
//! * [`c2pa_sm_session_fulfill`] — report one request's outcome;
//! * [`c2pa_sm_session_finish`] — consume the session, yielding a
//!   [`C2paSmReader`] to query.
//!
//! No function here blocks, spawns, takes a lock, or calls back into the
//! host, so a host may drive a session from any thread, on any executor,
//! in any order, and the library holds no state outside the objects it
//! returns — in particular none in thread-local storage. Errors are
//! therefore *values* ([`C2paSmError`], returned through an out-parameter)
//! rather than a "last error" the caller must fetch from the same thread.
//!
//! Every function is prefixed `c2pa_sm_` (types `C2paSm…`) so this library
//! can be linked into a process beside c2pa-c, whose symbols are `c2pa_…`.
//!
//! # Safety conventions
//!
//! Every pointer argument is either documented as nullable or must be
//! non-null; a null for the latter is reported as
//! [`C2PA_SM_ERR_INVALID_ARGUMENT`], not undefined behavior, wherever an
//! error out-parameter exists. Pointers into an object (a request's `url`
//! and `body`) are valid until the next call that takes that object
//! mutably (`advance`, `fulfill`, `finish`, `free`). A session is `Send`
//! but not `Sync`: move it between threads freely; do not call into one
//! session from two threads at the same time.
//!
//! Panics never unwind across the boundary: they become
//! [`C2PA_SM_ERR_PANIC`].
//!
//! [c2pa-cpp]: https://github.com/contentauth/c2pa-cpp

// The one crate in this workspace that must be `unsafe`: it *is* the FFI
// boundary.
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]

use std::{
    ffi::{c_char, c_int, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

use contentauth_c2pa_node_compat::{
    C2paError, Error, NodeSession, PendingRequest, Reader, Reply, Step,
};

/// Success.
pub const C2PA_SM_OK: c_int = 0;
/// A null or malformed argument, an unknown or already-answered request
/// id, a reply of the wrong kind, or bad settings JSON (c2pa-rs's
/// `BadParam`).
pub const C2PA_SM_ERR_INVALID_ARGUMENT: c_int = 1;
/// The asset's format is not one this build can read (c2pa-rs's
/// `UnsupportedType`).
pub const C2PA_SM_ERR_UNSUPPORTED_TYPE: c_int = 2;
/// The asset carries no manifest store (c2pa-rs's `JumbfNotFound`).
pub const C2PA_SM_ERR_NOT_FOUND: c_int = 3;
/// The read itself failed: a malformed asset or manifest store, or a host
/// that failed a request the engine cannot do without.
pub const C2PA_SM_ERR_READ: c_int = 4;
/// A Rust panic was caught at the boundary. Always a bug in this library.
pub const C2PA_SM_ERR_PANIC: c_int = 5;

/// Request kind: read `len` bytes of the asset at `start`. Answer with
/// [`C2PA_SM_REPLY_BYTES`].
pub const C2PA_SM_REQUEST_READ: c_int = 0;
/// Request kind: report the asset's length. Answer with
/// [`C2PA_SM_REPLY_LENGTH`].
pub const C2PA_SM_REQUEST_LENGTH: c_int = 1;
/// Request kind: report the wall clock. Answer with
/// [`C2PA_SM_REPLY_TIME`].
pub const C2PA_SM_REQUEST_TIME: c_int = 2;
/// Request kind: POST `body` to the OCSP responder at `url`. Answer with
/// [`C2PA_SM_REPLY_OCSP`].
pub const C2PA_SM_REQUEST_OCSP: c_int = 3;

/// Reply kind: the bytes of a read (`data`, `data_len`).
pub const C2PA_SM_REPLY_BYTES: c_int = 0;
/// Reply kind: the asset's length (`value`).
pub const C2PA_SM_REPLY_LENGTH: c_int = 1;
/// Reply kind: seconds since the Unix epoch, UTC (`value`).
pub const C2PA_SM_REPLY_TIME: c_int = 2;
/// Reply kind: an OCSP response body (`data`, `data_len`).
pub const C2PA_SM_REPLY_OCSP: c_int = 3;
/// Reply kind: the host could not do it; `data` is a UTF-8 message. Valid
/// for any request; the engine decides what that means (fail-open for
/// OCSP, an unevaluated validity window for the clock, an error for an
/// asset read).
pub const C2PA_SM_REPLY_FAILED: c_int = 4;

/// An error, returned by value through an out-parameter and freed with
/// [`c2pa_sm_error_free`]. Holds no reference to the session that
/// produced it, so it may outlive it and cross threads.
pub struct C2paSmError {
    code: c_int,
    message: CString,
    name: CString,
}

/// A read in progress. Opaque.
pub struct C2paSmSession {
    inner: NodeSession,
    /// The requests reported by the most recent `advance` — the ones
    /// [`c2pa_sm_session_request`] hands out borrows of.
    fresh: Vec<PendingRequest>,
}

/// A finished read. Opaque, immutable and `Send + Sync`: every accessor
/// takes `const` and may be called concurrently.
pub struct C2paSmReader {
    inner: Reader,
}

/// One thing a session needs its host to do. The pointer fields borrow
/// from the session and are valid until the next call that takes it
/// mutably.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C2paSmRequest {
    /// A `C2PA_SM_REQUEST_*` constant.
    pub kind: c_int,
    /// Quote this back in [`C2paSmReply::id`].
    pub id: u64,
    /// `READ`: offset of the first byte.
    pub start: u64,
    /// `READ`: number of bytes.
    pub len: u64,
    /// `OCSP`: the responder's URL, UTF-8, *not* NUL-terminated.
    pub url: *const c_char,
    /// `OCSP`: length of `url` in bytes.
    pub url_len: usize,
    /// `OCSP`: the DER `OCSPRequest` to send.
    pub body: *const u8,
    /// `OCSP`: length of `body` in bytes.
    pub body_len: usize,
}

/// The host's answer to one request. Everything is copied by
/// [`c2pa_sm_session_fulfill`]; the host may free `data` as soon as it
/// returns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C2paSmReply {
    /// A `C2PA_SM_REPLY_*` constant.
    pub kind: c_int,
    /// The `id` of the [`C2paSmRequest`] this answers.
    pub id: u64,
    /// `LENGTH`, `TIME`.
    pub value: i64,
    /// `BYTES`, `OCSP`, `FAILED`.
    pub data: *const u8,
    /// Length of `data` in bytes.
    pub data_len: usize,
}

/// What went wrong, before it is boxed for the caller.
struct Failure {
    code: c_int,
    message: String,
    name: String,
}

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

impl From<Error> for Failure {
    fn from(err: Error) -> Self {
        let code = match &err {
            Error::C2pa(C2paError::JumbfNotFound) => C2PA_SM_ERR_NOT_FOUND,
            Error::C2pa(C2paError::UnsupportedType) => C2PA_SM_ERR_UNSUPPORTED_TYPE,
            Error::C2pa(C2paError::BadParam(_)) => C2PA_SM_ERR_INVALID_ARGUMENT,
            _ => C2PA_SM_ERR_READ,
        };
        Self {
            code,
            message: err.to_string(),
            name: err.js_message(),
        }
    }
}

fn c_string(s: &str) -> CString {
    // Interior NULs cannot be represented; they are replaced, not dropped,
    // so a message is never silently empty.
    CString::new(s.replace('\0', "\u{fffd}")).unwrap_or_default()
}

/// Runs `f`, converting a failure or a panic into a status code and (if
/// the caller wants it) an error object.
///
/// # Safety
///
/// `out_error` must be null or valid for a pointer write.
unsafe fn guard(
    out_error: *mut *mut C2paSmError,
    f: impl FnOnce() -> Result<(), Failure>,
) -> c_int {
    let failure = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => return C2PA_SM_OK,
        Ok(Err(failure)) => failure,
        Err(_) => Failure {
            code: C2PA_SM_ERR_PANIC,
            message: "internal error: panic in contentauth-c2pa-cpp".to_string(),
            name: "Panic".to_string(),
        },
    };
    let code = failure.code;
    if !out_error.is_null() {
        let error = Box::new(C2paSmError {
            code,
            message: c_string(&failure.message),
            name: c_string(&failure.name),
        });
        // SAFETY: non-null, and the caller promises it is writable.
        unsafe { *out_error = Box::into_raw(error) };
    }
    code
}

/// Clears an out-parameter so a caller that ignores the status still sees
/// null rather than garbage.
///
/// # Safety
///
/// `out` must be null or valid for a pointer write.
unsafe fn clear<T>(out: *mut *mut T) {
    if !out.is_null() {
        // SAFETY: non-null, and the caller promises it is writable.
        unsafe { *out = ptr::null_mut() };
    }
}

/// The version of this library, NUL-terminated and static.
#[no_mangle]
pub extern "C" fn c2pa_sm_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Starts a read of an asset of type `format` (a MIME type or bare
/// extension), under c2pa-rs settings JSON `settings_json` (nullable:
/// c2pa-rs defaults). Both are NUL-terminated UTF-8.
///
/// Nothing is read until the session is advanced and its requests are
/// answered; the settings are copied, so neither argument need outlive
/// this call and no callback or context object can dangle later.
///
/// # Safety
///
/// `format` must be a valid C string; `settings_json` null or a valid C
/// string; `out_session` valid for a pointer write; `out_error` null or
/// valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_new(
    format: *const c_char,
    settings_json: *const c_char,
    out_session: *mut *mut C2paSmSession,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        clear(out_session);
        clear(out_error);
        guard(out_error, || {
            if out_session.is_null() {
                return Err(Failure::invalid("out_session is null"));
            }
            let format = utf8(format, "format")?;
            let settings = if settings_json.is_null() {
                None
            } else {
                Some(utf8(settings_json, "settings_json")?)
            };
            let inner = NodeSession::new(format, settings)?;
            *out_session = Box::into_raw(Box::new(C2paSmSession {
                inner,
                fresh: Vec::new(),
            }));
            Ok(())
        })
    }
}

/// Reads a required NUL-terminated UTF-8 argument.
///
/// # Safety
///
/// `s` must be null or a valid C string that outlives the returned borrow.
unsafe fn utf8<'a>(s: *const c_char, what: &str) -> Result<&'a str, Failure> {
    if s.is_null() {
        return Err(Failure::invalid(format!("{what} is null")));
    }
    // SAFETY: non-null, and the caller promises a valid C string.
    unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| Failure::invalid(format!("{what} is not valid UTF-8")))
}

/// Destroys a session, abandoning any read in flight. Null is a no-op.
///
/// This is the whole of cancellation: the session holds no thread and no
/// callback, so there is nothing to interrupt and nothing that can fire
/// afterward. Replies still en route from the host are simply never
/// delivered.
///
/// # Safety
///
/// `session` must be null or a pointer from [`c2pa_sm_session_new`] not
/// already freed or finished.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_free(session: *mut C2paSmSession) {
    if !session.is_null() {
        // SAFETY: from `session_new`, per the contract. A destructor that
        // panics would abort, which is acceptable for a bug.
        drop(unsafe { Box::from_raw(session) });
    }
}

/// Runs the engine as far as it can go without the host: one bounded
/// slice of parsing or hashing.
///
/// On success `*out_done` is nonzero if the read is finished (call
/// [`c2pa_sm_session_finish`]); otherwise the requests that are *new*
/// since the last call are available through [`c2pa_sm_session_request`]
/// — possibly none, if the session is still waiting on requests already
/// reported. Start them (concurrently if you like), fulfill each as it
/// settles, and advance again once at least one has.
///
/// # Safety
///
/// `session` must be a live session; `out_done` valid for an `int` write;
/// `out_error` null or valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_advance(
    session: *mut C2paSmSession,
    out_done: *mut c_int,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        clear(out_error);
        guard(out_error, || {
            let session = session
                .as_mut()
                .ok_or_else(|| Failure::invalid("session is null"))?;
            if out_done.is_null() {
                return Err(Failure::invalid("out_done is null"));
            }
            session.fresh.clear();
            match session.inner.advance()? {
                Step::Complete => *out_done = 1,
                Step::Pending(requests) => {
                    *out_done = 0;
                    session.fresh = requests;
                }
            }
            Ok(())
        })
    }
}

/// How many new requests the last [`c2pa_sm_session_advance`] reported.
/// Zero for a null session.
///
/// # Safety
///
/// `session` must be null or a live session.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_request_count(session: *const C2paSmSession) -> usize {
    // SAFETY: null or live, per the contract.
    unsafe { session.as_ref() }.map_or(0, |s| s.fresh.len())
}

/// Describes new request number `index` (`0 ..` the count) in `*out`.
/// Returns false, leaving `*out` untouched, if `index` is out of range or
/// an argument is null.
///
/// The pointers in `*out` are valid until the next call that takes the
/// session mutably.
///
/// # Safety
///
/// `session` must be null or a live session; `out` null or valid for a
/// [`C2paSmRequest`] write.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_request(
    session: *const C2paSmSession,
    index: usize,
    out: *mut C2paSmRequest,
) -> bool {
    // SAFETY: null or live / writable, per the contract.
    let (Some(session), false) = (unsafe { session.as_ref() }, out.is_null()) else {
        return false;
    };
    let Some(request) = session.fresh.get(index) else {
        return false;
    };
    let mut described = C2paSmRequest {
        kind: C2PA_SM_REQUEST_READ,
        id: request.id(),
        start: 0,
        len: 0,
        url: ptr::null(),
        url_len: 0,
        body: ptr::null(),
        body_len: 0,
    };
    match request {
        PendingRequest::Read { start, len, .. } => {
            described.start = *start;
            described.len = *len;
        }
        PendingRequest::Length { .. } => described.kind = C2PA_SM_REQUEST_LENGTH,
        PendingRequest::CurrentDateTime { .. } => described.kind = C2PA_SM_REQUEST_TIME,
        PendingRequest::Ocsp {
            url, request_der, ..
        } => {
            described.kind = C2PA_SM_REQUEST_OCSP;
            described.url = url.as_ptr().cast();
            described.url_len = url.len();
            described.body = request_der.as_ptr();
            described.body_len = request_der.len();
        }
        // `PendingRequest` is `#[non_exhaustive]`; `NodeSession` already
        // fails the read for a request it cannot describe, so none of
        // these can be reported to the host.
        _ => return false,
    }
    // SAFETY: non-null and writable, per the contract.
    unsafe { *out = described };
    true
}

/// Reports the outcome of one request. Replies may arrive in any order,
/// any subset, and from any thread (one at a time per session) between
/// calls to [`c2pa_sm_session_advance`].
///
/// Fails with `INVALID_ARGUMENT` if the id was never issued, was already
/// answered, or the reply is the wrong kind for it; the session stays
/// usable and the request stays outstanding.
///
/// # Safety
///
/// `session` must be a live session; `reply` a valid [`C2paSmReply`]
/// whose `data` points to `data_len` readable bytes (or may be null when
/// `data_len` is zero); `out_error` null or valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_fulfill(
    session: *mut C2paSmSession,
    reply: *const C2paSmReply,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        clear(out_error);
        guard(out_error, || {
            let session = session
                .as_mut()
                .ok_or_else(|| Failure::invalid("session is null"))?;
            let reply = reply
                .as_ref()
                .ok_or_else(|| Failure::invalid("reply is null"))?;
            let data = if reply.data.is_null() || reply.data_len == 0 {
                &[][..]
            } else {
                slice::from_raw_parts(reply.data, reply.data_len)
            };
            let converted = match reply.kind {
                C2PA_SM_REPLY_BYTES => Reply::Bytes(data.to_vec()),
                C2PA_SM_REPLY_LENGTH => Reply::Length(
                    u64::try_from(reply.value)
                        .map_err(|_| Failure::invalid("a length cannot be negative"))?,
                ),
                C2PA_SM_REPLY_TIME => Reply::Time(reply.value),
                C2PA_SM_REPLY_OCSP => Reply::Ocsp(data.to_vec()),
                C2PA_SM_REPLY_FAILED => Reply::Failed(String::from_utf8_lossy(data).into_owned()),
                other => return Err(Failure::invalid(format!("unknown reply kind {other}"))),
            };
            // Requests reported earlier are only ever borrowed until the
            // next call that takes the session mutably — this one.
            session.fresh.clear();
            session.inner.fulfill(reply.id, converted)?;
            Ok(())
        })
    }
}

/// Consumes a finished session — always, whether or not it succeeds —
/// and yields its reader in `*out_reader`.
///
/// `*out_reader` is null (with status `OK`) if the asset carries no
/// manifest store: the case c2pa-cpp's `Reader::from_asset` reports as
/// `std::nullopt`.
///
/// # Safety
///
/// `session` must be a live session, not used again afterward;
/// `out_reader` valid for a pointer write; `out_error` null or valid for
/// a pointer write.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_finish(
    session: *mut C2paSmSession,
    out_reader: *mut *mut C2paSmReader,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        clear(out_reader);
        clear(out_error);
        // Take ownership first so that the session is consumed even on the
        // error paths below, as documented.
        let session = if session.is_null() {
            None
        } else {
            Some(*Box::from_raw(session))
        };
        guard(out_error, || {
            let session = session.ok_or_else(|| Failure::invalid("session is null"))?;
            if out_reader.is_null() {
                return Err(Failure::invalid("out_reader is null"));
            }
            if let Some(reader) = session.inner.finish()? {
                *out_reader = Box::into_raw(Box::new(C2paSmReader { inner: reader }));
            }
            Ok(())
        })
    }
}

/// Destroys a reader. Null is a no-op.
///
/// # Safety
///
/// `reader` must be null or from [`c2pa_sm_session_finish`], not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_free(reader: *mut C2paSmReader) {
    if !reader.is_null() {
        // SAFETY: from `session_finish`, per the contract.
        drop(unsafe { Box::from_raw(reader) });
    }
}

/// The manifest store as c2pa-rs-shaped, pretty-printed JSON, in a new
/// string to free with [`c2pa_sm_string_free`]. Null for a null reader.
///
/// # Safety
///
/// `reader` must be null or a live reader.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_json(reader: *const C2paSmReader) -> *mut c_char {
    // SAFETY: null or live, per the contract.
    match unsafe { reader.as_ref() } {
        Some(reader) => CString::into_raw(c_string(&reader.inner.json())),
        None => ptr::null_mut(),
    }
}

/// The active manifest's label, in a new string to free with
/// [`c2pa_sm_string_free`]; null if there is none (or no reader).
///
/// # Safety
///
/// `reader` must be null or a live reader.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_active_label(reader: *const C2paSmReader) -> *mut c_char {
    // SAFETY: null or live, per the contract.
    unsafe { reader.as_ref() }
        .and_then(|reader| reader.inner.active_label())
        .map_or(ptr::null_mut(), |label| CString::into_raw(c_string(&label)))
}

/// Whether the manifest store was embedded in the asset. Always true
/// today; false for a null reader.
///
/// # Safety
///
/// `reader` must be null or a live reader.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_is_embedded(reader: *const C2paSmReader) -> bool {
    // SAFETY: null or live, per the contract.
    unsafe { reader.as_ref() }.is_some_and(|reader| reader.inner.is_embedded())
}

/// Frees a string returned by this library. Null is a no-op.
///
/// # Safety
///
/// `s` must be null or a string this library returned, not already freed.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: from `CString::into_raw` above, per the contract.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// The error's `C2PA_SM_ERR_*` code; `INVALID_ARGUMENT` for null.
///
/// # Safety
///
/// `error` must be null or a live error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_code(error: *const C2paSmError) -> c_int {
    // SAFETY: null or live, per the contract.
    unsafe { error.as_ref() }.map_or(C2PA_SM_ERR_INVALID_ARGUMENT, |e| e.code)
}

/// The error's human-readable message, NUL-terminated UTF-8, valid until
/// the error is freed. Empty for null.
///
/// # Safety
///
/// `error` must be null or a live error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_message(error: *const C2paSmError) -> *const c_char {
    // SAFETY: null or live, per the contract.
    unsafe { error.as_ref() }.map_or(c"".as_ptr(), |e| e.message.as_ptr())
}

/// The error in c2pa-rs's `Debug` spelling (e.g. `C2pa(JumbfNotFound)`),
/// the string c2pa-wasm and c2pa-node expose as an error's name,
/// NUL-terminated UTF-8, valid until the error is freed. Empty for null.
///
/// # Safety
///
/// `error` must be null or a live error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_name(error: *const C2paSmError) -> *const c_char {
    // SAFETY: null or live, per the contract.
    unsafe { error.as_ref() }.map_or(c"".as_ptr(), |e| e.name.as_ptr())
}

/// Destroys an error. Null is a no-op.
///
/// # Safety
///
/// `error` must be null or an error this library returned, not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_error_free(error: *mut C2paSmError) {
    if !error.is_null() {
        // SAFETY: from `guard`, per the contract.
        drop(unsafe { Box::from_raw(error) });
    }
}

#[cfg(test)]
mod tests;
