//! Reader session and immutable result ABI, shared-backend driven.

use std::ffi::{c_char, c_int};

use contentauth_c2pa_session_bridge::read::{
    C2paError, Error, PendingRequest, ReadSessionBridge, Reader, Reply, Step,
};

use super::*;

/// Read `len` bytes starting at `start`.
pub const C2PA_SM_REQUEST_READ: c_int = 0;
/// Report asset length.
pub const C2PA_SM_REQUEST_LENGTH: c_int = 1;
/// Report Unix seconds, UTC.
pub const C2PA_SM_REQUEST_TIME: c_int = 2;
/// POST body to the OCSP URL.
pub const C2PA_SM_REQUEST_OCSP: c_int = 3;
/// Read bytes reply.
pub const C2PA_SM_REPLY_BYTES: c_int = 0;
/// Asset length reply.
pub const C2PA_SM_REPLY_LENGTH: c_int = 1;
/// Unix seconds reply.
pub const C2PA_SM_REPLY_TIME: c_int = 2;
/// OCSP response body reply.
pub const C2PA_SM_REPLY_OCSP: c_int = 3;
/// Host failure, data contains a UTF-8 diagnostic.
pub const C2PA_SM_REPLY_FAILED: c_int = 4;

/// Overall validation outcome.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmValidationState {
    /// No reader.
    C2PA_SM_VALIDATION_UNAVAILABLE = -1,
    /// Failed or incomplete validation.
    C2PA_SM_VALIDATION_INVALID = 0,
    /// Valid but untrusted signer.
    C2PA_SM_VALIDATION_VALID = 1,
    /// Valid and trusted signer.
    C2PA_SM_VALIDATION_TRUSTED = 2,
}

/// Tracked read in progress; serialize its operations.
pub struct C2paSmSession {
    inner: ReadSessionBridge,
    fresh: Vec<PendingRequest>,
}

/// Tracked immutable result; accessors may run concurrently.
pub struct C2paSmReader {
    inner: Reader,
}

/// Request view, borrowed until the next mutable session operation.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C2paSmRequest {
    /// C2PA_SM_REQUEST_* value.
    pub kind: c_int,
    /// Outstanding request ID.
    pub id: u64,
    /// READ offset.
    pub start: u64,
    /// READ length.
    pub len: u64,
    /// OCSP URL; UTF-8, not NUL-terminated.
    pub url: *const c_char,
    /// URL length.
    pub url_len: usize,
    /// DER OCSP request.
    pub body: *const u8,
    /// Body length.
    pub body_len: usize,
}

/// Host reply, copied before fulfill returns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C2paSmReply {
    /// C2PA_SM_REPLY_* value.
    pub kind: c_int,
    /// Request ID.
    pub id: u64,
    /// LENGTH or TIME value.
    pub value: i64,
    /// BYTES, OCSP or FAILED payload.
    pub data: *const u8,
    /// Payload length.
    pub data_len: usize,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = match &error {
            Error::C2pa(C2paError::JumbfNotFound) => C2PA_SM_ERR_NOT_FOUND,
            Error::C2pa(C2paError::UnsupportedType) => C2PA_SM_ERR_UNSUPPORTED_TYPE,
            Error::C2pa(C2paError::BadParam(_)) => C2PA_SM_ERR_INVALID_ARGUMENT,
            _ => C2PA_SM_ERR_READ,
        };
        Self {
            code,
            message: error.to_string(),
            name: error.js_message(),
        }
    }
}

/// Starts a read. Null or whitespace-only settings select backend defaults
/// (including disabled online OCSP). Inputs are copied.
///
/// # Safety
/// Strings must be valid C strings; out_session writable; out_error null or writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_new(
    format: *const c_char,
    settings_json: *const c_char,
    out_session: *mut *mut C2paSmSession,
    out_error: *mut *mut C2paSmError,
) -> c_int {
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
                Some(utf8(settings_json, "settings_json")?).filter(|s| !s.trim().is_empty())
            };
            *out_session = tracked(C2paSmSession {
                inner: ReadSessionBridge::new(format, settings)?,
                fresh: Vec::new(),
            })?;
            Ok(())
        })
    }
}

/// Cancels a read; null, stale, wrong-type and busy handles are no-ops.
///
/// # Safety
/// End all borrowed request access before destruction succeeds.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_free(session: *mut C2paSmSession) {
    let _ = cimpl::untrack_owned(session);
}

/// Owned description of the current or failed phase, freed with
/// [`c2pa_sm_string_free`](crate::c2pa_sm_string_free); null for an invalid
/// or busy handle.
///
/// # Safety
/// Serialize session mutations and destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_phase(session: *const C2paSmSession) -> *mut c_char {
    cimpl::checkout_exclusive(session.cast_mut()).map_or(ptr::null_mut(), |session| {
        owned_string(&session.inner.phase())
    })
}

/// Advances bounded work; done is nonzero only when ready to finish.
/// New requests are exposed once, not repeated while outstanding.
///
/// # Safety
/// out_done must be writable; out_error null or writable. Serialize session calls
/// with use of any borrowed request view.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_advance(
    session: *mut C2paSmSession,
    out_done: *mut c_int,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if session.is_null() {
                return Err(Failure::invalid("session is null"));
            }
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
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

/// Number of newly issued requests; zero for invalid or busy handles.
///
/// # Safety
/// Serialize mutations with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_request_count(session: *const C2paSmSession) -> usize {
    cimpl::checkout_exclusive(session.cast_mut()).map_or(0, |s| s.fresh.len())
}

/// Describes a new request. Invalid handles, null output or an invalid index
/// return false without modifying out.
///
/// # Safety
/// out must be null or writable; keep the session alive and unmodified while
/// using any returned payload borrows.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_request(
    session: *const C2paSmSession,
    index: usize,
    out: *mut C2paSmRequest,
) -> bool {
    let Ok(session) = cimpl::checkout_exclusive(session.cast_mut()) else {
        return false;
    };
    if out.is_null() {
        return false;
    }
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
        _ => return false,
    }
    unsafe {
        *out = described;
    }
    true
}

/// Fulfills one request, in any order. Rejected IDs/kinds remain outstanding.
///
/// # Safety
/// reply must be null or initialized; nonempty data readable for data_len.
/// out_error null or writable. End request borrows before calling.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_fulfill(
    session: *mut C2paSmSession,
    reply: *const C2paSmReply,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if session.is_null() {
                return Err(Failure::invalid("session is null"));
            }
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            let reply = reply
                .as_ref()
                .ok_or_else(|| Failure::invalid("reply is null"))?;
            let data = if reply.data_len == 0 {
                &[][..]
            } else {
                cimpl::safe_slice_from_raw_parts(reply.data, reply.data_len, "data")
                    .map_err(handle_error)?
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
            session.fresh.clear();
            session.inner.fulfill(reply.id, converted)?;
            Ok(())
        })
    }
}

/// Consumes a valid session on success or failure, even with a null output.
/// An unsigned asset succeeds with a null reader. Busy/invalid handles remain
/// untouched. A caller must discard its session handle after consumption.
///
/// # Safety
/// out_reader writable; out_error null or writable. No request borrow may remain.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_session_finish(
    session: *mut C2paSmSession,
    out_reader: *mut *mut C2paSmReader,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_reader);
        clear(out_error);
        guard(out_error, || {
            if session.is_null() {
                return Err(Failure::invalid("session is null"));
            }
            let session = cimpl::untrack_owned(session).map_err(handle_error)?;
            if out_reader.is_null() {
                return Err(Failure::invalid("out_reader is null"));
            }
            if let Some(reader) = session.inner.finish()? {
                *out_reader = tracked(C2paSmReader { inner: reader })?;
            }
            Ok(())
        })
    }
}

/// Frees a reader; invalid/busy handles are no-ops.
///
/// # Safety
/// No view borrowed from this reader may remain in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_free(reader: *mut C2paSmReader) {
    let _ = cimpl::untrack_owned(reader);
}

/// Owned pretty JSON, freed with string_free; null for invalid/busy handles.
///
/// # Safety
/// Serialize reader destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_json(reader: *const C2paSmReader) -> *mut c_char {
    cimpl::checkout_shared(reader.cast_mut())
        .map_or(ptr::null_mut(), |r| owned_string(&r.inner.json()))
}

/// Overall outcome; unavailable for invalid/busy handles.
///
/// # Safety
/// Serialize reader destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_validation_state(
    reader: *const C2paSmReader,
) -> C2paSmValidationState {
    use contentauth_c2pa_session_bridge::compat::ValidationState;
    use C2paSmValidationState::*;
    match cimpl::checkout_shared(reader.cast_mut())
        .ok()
        .map(|r| r.inner.validation_state())
    {
        Some(ValidationState::Valid) => C2PA_SM_VALIDATION_VALID,
        Some(ValidationState::Trusted) => C2PA_SM_VALIDATION_TRUSTED,
        Some(_) => C2PA_SM_VALIDATION_INVALID,
        None => C2PA_SM_VALIDATION_UNAVAILABLE,
    }
}

/// Owned active label, freed with string_free; null if absent or invalid.
///
/// # Safety
/// Serialize reader destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_active_label(reader: *const C2paSmReader) -> *mut c_char {
    cimpl::checkout_shared(reader.cast_mut())
        .ok()
        .and_then(|r| r.inner.active_label())
        .map_or(ptr::null_mut(), |s| owned_string(&s))
}

/// True for an embedded manifest; false for invalid/busy handles.
///
/// # Safety
/// Serialize reader destruction with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_reader_is_embedded(reader: *const C2paSmReader) -> bool {
    cimpl::checkout_shared(reader.cast_mut()).is_ok_and(|r| r.inner.is_embedded())
}

#[cfg(test)]
pub(crate) mod tests;
