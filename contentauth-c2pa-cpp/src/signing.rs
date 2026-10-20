//! cimpl-tracked signing sessions and immutable reports.

use std::{ffi::c_char, os::raw::c_int};

use contentauth_c2pa_session_bridge::{
    build::{BuildSessionBridge, Error, PendingRequest, Reply, Step, Stream},
    Bytes,
};

use super::{clear, guard, utf8, C2paError, C2paSmError, Failure};

/// Signing-specific error codes, extending the common reader error codes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildErrorCode {
    /// Building or signing failed, including a host I/O, signer, or TSA failure.
    C2PA_SM_ERR_BUILD = 6,
}

/// Operations requested by a signing session.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildRequestKind {
    /// Read exactly the requested range; answer with bytes.
    C2PA_SM_BUILD_REQUEST_READ = 0,
    /// Report a stream's length.
    C2PA_SM_BUILD_REQUEST_LENGTH = 1,
    /// Write the entire payload and make it visible to subsequent reads.
    C2PA_SM_BUILD_REQUEST_WRITE = 2,
    /// Sign the complete COSE Sig_structure.
    C2PA_SM_BUILD_REQUEST_SIGN = 3,
    /// POST the encoded RFC 3161 request to the supplied URL.
    C2PA_SM_BUILD_REQUEST_TIMESTAMP = 4,
}

/// Host reply payload kinds; unknown incoming integers are rejected.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildReplyKind {
    /// Reply payload is the requested bytes.
    C2PA_SM_BUILD_REPLY_BYTES = 0,
    /// Reply value is the stream length.
    C2PA_SM_BUILD_REPLY_LENGTH = 1,
    /// The entire write is visible to subsequent reads.
    C2PA_SM_BUILD_REPLY_WRITTEN = 2,
    /// Reply payload is a signature; ES256 requires raw r || s, not DER.
    C2PA_SM_BUILD_REPLY_SIGNATURE = 3,
    /// Reply payload is the unmodified DER TimeStampResp.
    C2PA_SM_BUILD_REPLY_TIMESTAMP = 4,
    /// Reply payload is a UTF-8 host failure message.
    C2PA_SM_BUILD_REPLY_FAILED = 5,
}

/// Host-owned streams addressed by signing I/O requests.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildStream {
    /// The read-only source asset.
    C2PA_SM_BUILD_SOURCE = 0,
    /// The separate, initially empty, readable and writable output asset.
    C2PA_SM_BUILD_OUTPUT = 1,
}

impl TryFrom<c_int> for C2paSmBuildReplyKind {
    type Error = &'static str;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        [
            Self::C2PA_SM_BUILD_REPLY_BYTES,
            Self::C2PA_SM_BUILD_REPLY_LENGTH,
            Self::C2PA_SM_BUILD_REPLY_WRITTEN,
            Self::C2PA_SM_BUILD_REPLY_SIGNATURE,
            Self::C2PA_SM_BUILD_REPLY_TIMESTAMP,
            Self::C2PA_SM_BUILD_REPLY_FAILED,
        ]
        .into_iter()
        .find(|kind| *kind as c_int == value)
        .ok_or("unknown build reply kind")
    }
}

/// A borrowed byte range. Null is permitted only when len is zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuffer {
    /// First byte; strings are UTF-8 and not NUL-terminated.
    pub data: *const u8,
    /// Number of readable bytes.
    pub len: usize,
}

impl C2paSmBuffer {
    fn borrowed(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    unsafe fn bytes(&self) -> Result<&[u8], Failure> {
        if self.len == 0 {
            return Ok(&[]);
        }
        unsafe { cimpl::safe_slice_from_raw_parts(self.data, self.len, "buffer") }
            .map_err(handle_error)
    }
}

/// A cimpl-tracked, opaque signing session. Drive it from one thread at a time.
pub struct C2paSmBuildSession {
    inner: BuildSessionBridge,
    fresh: Vec<PendingRequest>,
    done: bool,
}

/// A request view, valid until the session's next advance, fulfill, finish, or free.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuildRequest {
    /// A C2paSmBuildRequestKind value, represented as an ABI integer.
    pub kind: c_int,
    /// Quote this ID in the reply.
    pub id: u64,
    /// A C2paSmBuildStream value for reads, lengths, and writes.
    pub stream: c_int,
    /// Read start or write offset.
    pub offset: u64,
    /// Read length.
    pub len: u64,
    /// Write bytes, signing input, or encoded TimeStampReq.
    pub data: C2paSmBuffer,
    /// Signing algorithm, UTF-8, not NUL-terminated.
    pub algorithm: C2paSmBuffer,
    /// Timestamp URL, UTF-8, not NUL-terminated.
    pub url: C2paSmBuffer,
}

/// A host reply; payload bytes are copied before fulfill returns.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuildReply {
    /// A C2paSmBuildReplyKind value; unknown integers are rejected.
    pub kind: c_int,
    /// The outstanding request ID.
    pub id: u64,
    /// Stream length for a length reply; otherwise ignored.
    pub value: u64,
    /// Payload for bytes, signature, timestamp, or failure replies.
    pub data: C2paSmBuffer,
}

/// One hard-binding exclusion in the completed output asset.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmExclusion {
    /// First excluded byte.
    pub start: u64,
    /// Number of excluded bytes.
    pub len: u64,
}

/// A cimpl-tracked, immutable report, independent of the consumed session.
pub struct C2paSmSignReport {
    manifest: Bytes,
    exclusions: Vec<C2paSmExclusion>,
}

/// Borrowed report storage, valid until the report is freed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmSignReportView {
    /// Embedded manifest bytes; the signed asset is already in the host output.
    pub manifest: C2paSmBuffer,
    /// Ascending exclusion ranges.
    pub exclusions: *const C2paSmExclusion,
    /// Number of exclusions.
    pub exclusion_count: usize,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let code = match &error {
            Error::C2pa(C2paError::BadParam(_)) | Error::Definition(_) => {
                super::C2PA_SM_ERR_INVALID_ARGUMENT
            }
            Error::C2pa(C2paError::UnsupportedType) => super::C2PA_SM_ERR_UNSUPPORTED_TYPE,
            _ => C2paSmBuildErrorCode::C2PA_SM_ERR_BUILD as c_int,
        };
        Self {
            code,
            message: error.to_string(),
            name: error.js_message(),
        }
    }
}

fn handle_error(error: cimpl::Error) -> Failure {
    Failure::invalid(error.to_string())
}

fn tracked<T: 'static + Send>(value: T) -> Result<*mut T, Failure> {
    cimpl::ensure_trackable().map_err(handle_error)?;
    let handle = cimpl::track_box(Box::into_raw(Box::new(value)));
    if handle.is_null() {
        return Err(Failure::invalid("could not track allocation"));
    }
    Ok(handle)
}

/// Starts a build; copies all inputs and never reads an asset or sees a key.
///
/// # Safety
/// Strings must be valid C strings. certs must address cert_count initialized
/// buffers, each readable for its length. Outputs must be writable; out_error
/// may be null. A null certificate array is accepted only with zero count.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_new(
    definition_json: *const c_char,
    format: *const c_char,
    algorithm: *const c_char,
    certs: *const C2paSmBuffer,
    cert_count: usize,
    out_session: *mut *mut C2paSmBuildSession,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_session);
        clear(out_error);
        guard(out_error, || {
            if out_session.is_null() {
                return Err(Failure::invalid("out_session is null"));
            }
            let definition = utf8(definition_json, "definition_json")?;
            let format = utf8(format, "format")?;
            let algorithm = utf8(algorithm, "algorithm")?;
            let certs = if cert_count == 0 {
                &[][..]
            } else {
                if certs.is_null()
                    || cert_count > isize::MAX as usize / std::mem::size_of::<C2paSmBuffer>()
                {
                    return Err(Failure::invalid("invalid certificate array"));
                }
                std::slice::from_raw_parts(certs, cert_count)
            };
            let certificates = certs
                .iter()
                .map(|cert| cert.bytes().map(<[u8]>::to_vec))
                .collect::<Result<Vec<_>, _>>()?;
            let inner = BuildSessionBridge::new(definition, format, algorithm, certificates)?;
            *out_session = tracked(C2paSmBuildSession {
                inner,
                fresh: Vec::new(),
                done: false,
            })?;
            Ok(())
        })
    }
}

/// Advances a build. out_count counts new requests, not all outstanding requests.
/// An empty batch with out_done == 0 still means waiting, not completion.
///
/// # Safety
/// out_done and out_count must be writable; out_error must be null or writable.
/// Session payload borrows must not be used concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_advance(
    session: *mut C2paSmBuildSession,
    out_done: *mut c_int,
    out_count: *mut usize,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        if !out_done.is_null() {
            *out_done = 0;
        }
        if !out_count.is_null() {
            *out_count = 0;
        }
        guard(out_error, || {
            if out_done.is_null() || out_count.is_null() {
                return Err(Failure::invalid("advance output is null"));
            }
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            session.fresh.clear();
            match session.inner.advance()? {
                Step::Complete => session.done = true,
                Step::Pending(requests) => session.fresh = requests,
            }
            *out_done = c_int::from(session.done);
            *out_count = session.fresh.len();
            Ok(())
        })
    }
}

fn describe(request: &PendingRequest) -> Result<C2paSmBuildRequest, Failure> {
    let mut view = C2paSmBuildRequest {
        id: request.id(),
        ..Default::default()
    };
    match request {
        PendingRequest::Read {
            stream, start, len, ..
        } => {
            view.kind = C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int;
            view.stream = stream_id(*stream);
            view.offset = *start;
            view.len = *len;
        }
        PendingRequest::Length { stream, .. } => {
            view.kind = C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int;
            view.stream = stream_id(*stream);
        }
        PendingRequest::Write {
            stream,
            offset,
            bytes,
            ..
        } => {
            view.kind = C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int;
            view.stream = stream_id(*stream);
            view.offset = *offset;
            view.data = C2paSmBuffer::borrowed(bytes);
        }
        PendingRequest::Sign { alg, data, .. } => {
            view.kind = C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_SIGN as c_int;
            view.algorithm = C2paSmBuffer::borrowed(alg.as_bytes());
            view.data = C2paSmBuffer::borrowed(data);
        }
        PendingRequest::Timestamp { url, request, .. } => {
            view.kind = C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_TIMESTAMP as c_int;
            view.url = C2paSmBuffer::borrowed(url.as_bytes());
            view.data = C2paSmBuffer::borrowed(request);
        }
        _ => return Err(Failure::invalid("unknown build request")),
    }
    Ok(view)
}

fn stream_id(stream: Stream) -> c_int {
    match stream {
        Stream::Source => C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int,
        Stream::Output => C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int,
    }
}

/// Copies a request descriptor. Copy its borrowed payloads before mutating the session.
///
/// # Safety
/// out must be writable; out_error null or writable. The session and its
/// payloads must not be mutated concurrently with this call or the returned borrows.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_request(
    session: *mut C2paSmBuildSession,
    index: usize,
    out: *mut C2paSmBuildRequest,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        if !out.is_null() {
            *out = C2paSmBuildRequest::default();
        }
        guard(out_error, || {
            if out.is_null() {
                return Err(Failure::invalid("request output is null"));
            }
            let session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            let request = session
                .fresh
                .get(index)
                .ok_or_else(|| Failure::invalid("request index is out of range"))?;
            *out = describe(request)?;
            Ok(())
        })
    }
}

unsafe fn reply_value(reply: &C2paSmBuildReply) -> Result<Reply, Failure> {
    use C2paSmBuildReplyKind::*;

    let kind = C2paSmBuildReplyKind::try_from(reply.kind).map_err(Failure::invalid)?;
    Ok(match kind {
        C2PA_SM_BUILD_REPLY_BYTES => Reply::Bytes(unsafe { reply.data.bytes()? }.to_vec()),
        C2PA_SM_BUILD_REPLY_LENGTH => Reply::Length(reply.value),
        C2PA_SM_BUILD_REPLY_WRITTEN => Reply::Written,
        C2PA_SM_BUILD_REPLY_SIGNATURE => Reply::Signature(unsafe { reply.data.bytes()? }.to_vec()),
        C2PA_SM_BUILD_REPLY_TIMESTAMP => {
            Reply::TimestampResponse(unsafe { reply.data.bytes()? }.to_vec())
        }
        C2PA_SM_BUILD_REPLY_FAILED => Reply::Failed(
            std::str::from_utf8(unsafe { reply.data.bytes()? })
                .map_err(|_| Failure::invalid("failure message is not UTF-8"))?
                .to_string(),
        ),
    })
}

/// Answers one outstanding request; replies can arrive in any order or subset.
/// Invalid IDs or reply kinds leave the request outstanding.
///
/// # Safety
/// reply must address an initialized reply with readable payload bytes;
/// out_error must be null or writable. No session payload borrow may be in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_fulfill(
    session: *mut C2paSmBuildSession,
    reply: *const C2paSmBuildReply,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            let reply = reply
                .as_ref()
                .ok_or_else(|| Failure::invalid("reply is null"))?;
            let converted = reply_value(reply)?;
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            session.fresh.clear();
            session
                .inner
                .fulfill(reply.id, converted)
                .map_err(|error| Failure::invalid(error.to_string()))?;
            Ok(())
        })
    }
}

/// Consumes a valid session on success or failure, returning an owned report.
/// Invalid or busy handles are rejected without consuming another operation's handle.
///
/// # Safety
/// out_report must be writable; out_error must be null or writable.
/// No session payload borrow may remain in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_finish(
    session: *mut C2paSmBuildSession,
    out_report: *mut *mut C2paSmSignReport,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_report);
        clear(out_error);
        guard(out_error, || {
            let session = cimpl::untrack_owned(session).map_err(handle_error)?;
            if out_report.is_null() {
                return Err(Failure::invalid("out_report is null"));
            }
            if !session.done {
                return Err(Failure::invalid("build is not complete"));
            }
            let report = session.inner.finish()?;
            *out_report = tracked(C2paSmSignReport {
                manifest: report.manifest,
                exclusions: report
                    .exclusions
                    .into_iter()
                    .map(|range| C2paSmExclusion {
                        start: range.start,
                        len: range.len,
                    })
                    .collect(),
            })?;
            Ok(())
        })
    }
}

/// Destroys a build session; null is a no-op, stale/wrong/busy handles are errors.
///
/// # Safety
/// out_error must be null or writable. No session payload borrow may remain in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_session_free(
    session: *mut C2paSmBuildSession,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if !session.is_null() {
                drop(cimpl::untrack_owned(session).map_err(handle_error)?);
            }
            Ok(())
        })
    }
}

/// Returns immutable report storage, valid until report_free. Reports may cross threads.
///
/// # Safety
/// out must be writable; out_error null or writable. Do not free the report
/// concurrently with this call or while any returned storage is still in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_sign_report_view(
    report: *const C2paSmSignReport,
    out: *mut C2paSmSignReportView,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        if !out.is_null() {
            *out = C2paSmSignReportView::default();
        }
        guard(out_error, || {
            if out.is_null() {
                return Err(Failure::invalid("report output is null"));
            }
            let report = cimpl::checkout_shared(report.cast_mut()).map_err(handle_error)?;
            *out = C2paSmSignReportView {
                manifest: C2paSmBuffer::borrowed(&report.manifest),
                exclusions: report.exclusions.as_ptr(),
                exclusion_count: report.exclusions.len(),
            };
            Ok(())
        })
    }
}

/// Frees an owned report; null is a no-op, stale/wrong/busy handles are errors.
///
/// # Safety
/// out_error must be null or writable; no report view may remain in use.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_sign_report_free(
    report: *mut C2paSmSignReport,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if !report.is_null() {
                drop(cimpl::untrack_owned(report).map_err(handle_error)?);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
