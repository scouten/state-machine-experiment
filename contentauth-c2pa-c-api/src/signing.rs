//! cimpl-tracked signing sessions, immutable reports and independent I/O leases.

use std::{collections::BTreeMap, ffi::c_char, os::raw::c_int, sync::Arc};

use contentauth_c2pa_session_bridge::{
    build::{BuildSessionBridge, Error, PendingRequest, Reply, Step, Stream},
    compat::C2paError,
    Bytes,
};

use super::{clear, guard, handle_error, tracked, utf8, C2paSmError, Failure};

/// Signing-specific error codes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildErrorCode {
    /// Host I/O, signing, timestamping or build failure.
    C2PA_SM_ERR_BUILD = 6,
}

/// Operations requested by a signing session.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildRequestKind {
    /// Read exactly the requested range.
    C2PA_SM_BUILD_REQUEST_READ = 0,
    /// Report a stream's length.
    C2PA_SM_BUILD_REQUEST_LENGTH = 1,
    /// Write the entire payload and make it visible to subsequent reads.
    C2PA_SM_BUILD_REQUEST_WRITE = 2,
    /// Sign the complete COSE Sig_structure.
    C2PA_SM_BUILD_REQUEST_SIGN = 3,
    /// POST the encoded RFC 3161 request.
    C2PA_SM_BUILD_REQUEST_TIMESTAMP = 4,
}

/// Host reply payload kinds; incoming unknown integers are rejected.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildReplyKind {
    /// Requested bytes.
    C2PA_SM_BUILD_REPLY_BYTES = 0,
    /// Stream length.
    C2PA_SM_BUILD_REPLY_LENGTH = 1,
    /// Entire write is visible to subsequent reads.
    C2PA_SM_BUILD_REPLY_WRITTEN = 2,
    /// Signature; ES256 requires raw r || s, not DER.
    C2PA_SM_BUILD_REPLY_SIGNATURE = 3,
    /// Unmodified DER TimeStampResp.
    C2PA_SM_BUILD_REPLY_TIMESTAMP = 4,
    /// UTF-8 failure message.
    C2PA_SM_BUILD_REPLY_FAILED = 5,
}

/// Streams addressed by signing I/O requests.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum C2paSmBuildStream {
    /// Read-only source.
    C2PA_SM_BUILD_SOURCE = 0,
    /// Separate, initially empty, readable and writable output.
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

/// Borrowed byte range. Null is permitted only with zero length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuffer {
    /// First byte; strings are UTF-8 and not NUL-terminated.
    pub data: *const u8,
    /// Readable byte count.
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

/// Tracked signing session; serialize calls.
pub struct C2paSmBuildSession {
    inner: BuildSessionBridge,
    fresh: Vec<PendingRequest>,
    done: bool,
    identity: Arc<()>,
    reads: BTreeMap<u64, (u64, Option<Arc<()>>)>,
    writes: BTreeMap<u64, Bytes>,
}

/// Immutable write storage retained independently of its session.
pub struct C2paSmWriteBuffer {
    _bytes: Bytes,
}
/// Writable read storage owned independently of its session.
pub struct C2paSmReadBuffer {
    identity: Arc<()>,
    id: u64,
    bytes: Vec<u8>,
    token: Arc<()>,
}
impl C2paSmReadBuffer {
    fn take_reply(&mut self) -> Reply {
        Reply::Bytes(std::mem::take(&mut self.bytes))
    }
}
/// Sealed read storage; writable pointers must no longer be used.
pub struct C2paSmCompletedRead {
    buffer: Option<C2paSmReadBuffer>,
}

/// Exclusive initialized storage; valid until seal or free.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmMutableBytes {
    /// Writable first byte. Never retain after sealing.
    pub data: *mut u8,
    /// Exact requested count.
    pub len: usize,
}

/// Request view, valid until the next session mutation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuildRequest {
    /// C2paSmBuildRequestKind ABI integer.
    pub kind: c_int,
    /// Request ID.
    pub id: u64,
    /// C2paSmBuildStream for I/O.
    pub stream: c_int,
    /// Read start or write offset.
    pub offset: u64,
    /// Read length.
    pub len: u64,
    /// Write bytes, signing input or encoded TimeStampReq.
    pub data: C2paSmBuffer,
    /// UTF-8 signing algorithm, not NUL-terminated.
    pub algorithm: C2paSmBuffer,
    /// UTF-8 timestamp URL, not NUL-terminated.
    pub url: C2paSmBuffer,
}

/// Host reply; payload copied before fulfill returns.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmBuildReply {
    /// C2paSmBuildReplyKind ABI integer.
    pub kind: c_int,
    /// Outstanding ID.
    pub id: u64,
    /// Length reply value.
    pub value: u64,
    /// Bytes, signature, timestamp or failure message.
    pub data: C2paSmBuffer,
}

/// Hard-binding exclusion in the completed asset.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmExclusion {
    /// First byte.
    pub start: u64,
    /// Byte count.
    pub len: u64,
}
/// Tracked immutable report, independent of its consumed session.
pub struct C2paSmSignReport {
    manifest: Bytes,
    exclusions: Vec<C2paSmExclusion>,
}
/// Borrowed report storage, valid until report free.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct C2paSmSignReportView {
    /// Embedded manifest. Signed asset is already in host output.
    pub manifest: C2paSmBuffer,
    /// Ascending exclusions.
    pub exclusions: *const C2paSmExclusion,
    /// Exclusion count.
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

/// Starts a build, copying inputs. Certificates must be a nonempty chain of
/// nonempty DER buffers. Unlike the experimental C++ boundary, empty chains
/// are rejected immediately, preserving the canonical constructor policy.
///
/// # Safety
/// Strings valid C strings; certs readable for cert_count initialized buffers,
/// each readable for len; out_session writable; out_error null or writable.
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
            if cert_count == 0
                || certs.is_null()
                || cert_count > isize::MAX as usize / std::mem::size_of::<C2paSmBuffer>()
            {
                return Err(Failure::invalid("invalid certificate array"));
            }
            let certificates = std::slice::from_raw_parts(certs, cert_count)
                .iter()
                .map(|cert| {
                    if cert.len == 0 {
                        return Err(Failure::invalid("empty certificate"));
                    }
                    cert.bytes().map(<[u8]>::to_vec)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let inner = BuildSessionBridge::new(definition, format, algorithm, certificates)?;
            *out_session = tracked(C2paSmBuildSession {
                inner,
                fresh: Vec::new(),
                done: false,
                identity: Arc::new(()),
                reads: BTreeMap::new(),
                writes: BTreeMap::new(),
            })?;
            Ok(())
        })
    }
}

/// Advances a build. Count is new requests, not all outstanding requests.
/// Zero count without done still means waiting.
///
/// # Safety
/// Outputs writable, out_error null or writable. End payload borrows and
/// serialize session operations.
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
            let reads: Vec<_> = session
                .fresh
                .iter()
                .filter_map(|request| {
                    if let PendingRequest::Read { id, len, .. } = request {
                        Some((*id, (*len, None)))
                    } else {
                        None
                    }
                })
                .collect();
            session.reads.extend(reads);
            let writes: Vec<_> = session
                .fresh
                .iter()
                .filter_map(|request| {
                    if let PendingRequest::Write { id, bytes, .. } = request {
                        Some((*id, bytes.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            session.writes.extend(writes);
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

/// Copies a descriptor. Copy borrowed payloads before mutating the session.
///
/// # Safety
/// out writable, out_error null or writable; serialize session mutations
/// with this call and use of its borrowed payloads.
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

/// Answers one outstanding request. Invalid IDs/kinds leave it outstanding.
///
/// # Safety
/// reply initialized with readable payload; out_error null or writable.
/// End all borrowed session payload accesses. Failed leased reads require
/// the host to stop accessing writable bytes; their leases still need free.
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
            if let Some((_, Some(_))) = session.reads.get(&reply.id) {
                if !matches!(converted, Reply::Failed(_)) {
                    return Err(Failure::invalid("read has an outstanding lease"));
                }
            }
            session.fresh.clear();
            session
                .inner
                .fulfill(reply.id, converted)
                .map_err(|e| Failure::invalid(e.to_string()))?;
            session.reads.remove(&reply.id);
            session.writes.remove(&reply.id);
            Ok(())
        })
    }
}

/// Retains immutable write bytes without copying. Multiple leases may share
/// storage; each survives acknowledgment and session destruction.
///
/// # Safety
/// Outputs writable and distinct; out_error null or writable. Serialize session
/// operations. Never mutate the bytes or use them after freeing the buffer.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_write_acquire(
    session: *mut C2paSmBuildSession,
    id: u64,
    out_buffer: *mut *mut C2paSmWriteBuffer,
    out_bytes: *mut C2paSmBuffer,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_buffer);
        clear(out_error);
        if !out_bytes.is_null() {
            *out_bytes = C2paSmBuffer::default();
        }
        guard(out_error, || {
            if out_buffer.is_null() || out_bytes.is_null() {
                return Err(Failure::invalid("write acquisition output is null"));
            }
            let session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            let bytes = session
                .writes
                .get(&id)
                .ok_or_else(|| Failure::invalid("not an outstanding write"))?
                .clone();
            let view = C2paSmBuffer::borrowed(&bytes);
            *out_buffer = tracked(C2paSmWriteBuffer { _bytes: bytes })?;
            *out_bytes = view;
            Ok(())
        })
    }
}

/// Frees retained write storage independently. Invalid/busy handles stay owned.
///
/// # Safety
/// buffer writable, out_error null or writable. Stop all I/O using the bytes.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_write_buffer_free(
    buffer: *mut *mut C2paSmWriteBuffer,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if buffer.is_null() {
                return Err(Failure::invalid("buffer is null"));
            }
            if !(*buffer).is_null() {
                drop(cimpl::untrack_owned(*buffer).map_err(handle_error)?);
                *buffer = std::ptr::null_mut();
            }
            Ok(())
        })
    }
}

/// Acquires fallibly allocated, initialized storage for an outstanding read.
/// Each request can acquire only one lease, even after abandonment.
///
/// # Safety
/// Outputs writable and distinct, out_error null or writable. Serialize session
/// operations. Only the host may access writable bytes until seal.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_read_acquire(
    session: *mut C2paSmBuildSession,
    id: u64,
    out_buffer: *mut *mut C2paSmReadBuffer,
    out_bytes: *mut C2paSmMutableBytes,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_buffer);
        clear(out_error);
        if !out_bytes.is_null() {
            *out_bytes = C2paSmMutableBytes::default();
        }
        guard(out_error, || {
            if out_buffer.is_null() || out_bytes.is_null() {
                return Err(Failure::invalid("read acquisition output is null"));
            }
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            let (len, leased) = session
                .reads
                .get(&id)
                .ok_or_else(|| Failure::invalid("not an outstanding read"))?;
            if leased.is_some() {
                return Err(Failure::invalid("read already leased"));
            }
            let len = usize::try_from(*len).map_err(|_| Failure::invalid("read too large"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| Failure::invalid("read allocation failed"))?;
            bytes.resize(len, 0);
            let view = C2paSmMutableBytes {
                data: bytes.as_mut_ptr(),
                len,
            };
            let token = Arc::new(());
            let buffer = tracked(C2paSmReadBuffer {
                identity: Arc::clone(&session.identity),
                id,
                bytes,
                token: Arc::clone(&token),
            })?;
            session.reads.insert(id, (len as u64, Some(token)));
            *out_buffer = buffer;
            *out_bytes = view;
            Ok(())
        })
    }
}

/// Seals storage once all I/O stops; consumes and nulls on success.
/// Wrong count or invalid/busy handle preserves ownership.
///
/// # Safety
/// Slots writable and distinct, out_error null or writable. No access to the
/// writable bytes, including from other threads, may remain.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_seal(
    buffer: *mut *mut C2paSmReadBuffer,
    bytes_read: usize,
    out_completed: *mut *mut C2paSmCompletedRead,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_completed);
        clear(out_error);
        guard(out_error, || {
            if buffer.is_null() || out_completed.is_null() {
                return Err(Failure::invalid("seal output is null"));
            }
            {
                let lease = cimpl::checkout_exclusive(*buffer).map_err(handle_error)?;
                if bytes_read != lease.bytes.len() {
                    return Err(Failure::invalid("short read"));
                }
            }
            let completed = tracked(C2paSmCompletedRead { buffer: None })?;
            let lease = match cimpl::untrack_owned(*buffer) {
                Ok(lease) => lease,
                Err(error) => {
                    drop(cimpl::untrack_owned(completed).map_err(handle_error)?);
                    return Err(handle_error(error));
                }
            };
            cimpl::checkout_exclusive(completed)
                .map_err(handle_error)?
                .buffer = Some(lease);
            *buffer = std::ptr::null_mut();
            *out_completed = completed;
            Ok(())
        })
    }
}

/// Moves sealed storage into its original request without copying.
/// Invalid sessions/requests preserve the completed handle.
///
/// # Safety
/// completed writable, out_error null or writable. Serialize session operations
/// and ownership transitions.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_build_fulfill_read(
    session: *mut C2paSmBuildSession,
    id: u64,
    completed: *mut *mut C2paSmCompletedRead,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if completed.is_null() {
                return Err(Failure::invalid("completed is null"));
            }
            let mut session = cimpl::checkout_exclusive(session).map_err(handle_error)?;
            let mut read = cimpl::checkout_exclusive(*completed).map_err(handle_error)?;
            let lease = read
                .buffer
                .as_mut()
                .ok_or_else(|| Failure::invalid("empty completion"))?;
            let (_, marker) = session
                .reads
                .get(&lease.id)
                .ok_or_else(|| Failure::invalid("read is no longer outstanding"))?;
            if id != lease.id
                || !Arc::ptr_eq(&session.identity, &lease.identity)
                || !marker
                    .as_ref()
                    .is_some_and(|state| Arc::ptr_eq(state, &lease.token))
            {
                return Err(Failure::invalid("read belongs to another session"));
            }
            session
                .inner
                .fulfill(lease.id, lease.take_reply())
                .map_err(|e| Failure::invalid(e.to_string()))?;
            session.reads.remove(&lease.id);
            session.fresh.clear();
            drop(read);
            drop(cimpl::untrack_owned(*completed).map_err(handle_error)?);
            *completed = std::ptr::null_mut();
            Ok(())
        })
    }
}

/// Frees abandoned writable storage independently and nulls on success.
///
/// # Safety
/// buffer writable, out_error null or writable. Stop all I/O using the bytes.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_read_buffer_free(
    buffer: *mut *mut C2paSmReadBuffer,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if buffer.is_null() {
                return Err(Failure::invalid("buffer is null"));
            }
            if !(*buffer).is_null() {
                drop(cimpl::untrack_owned(*buffer).map_err(handle_error)?);
                *buffer = std::ptr::null_mut();
            }
            Ok(())
        })
    }
}

/// Frees sealed storage independently and nulls on success.
///
/// # Safety
/// completed writable, out_error null or writable.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_completed_read_free(
    completed: *mut *mut C2paSmCompletedRead,
    out_error: *mut *mut C2paSmError,
) -> c_int {
    unsafe {
        clear(out_error);
        guard(out_error, || {
            if completed.is_null() {
                return Err(Failure::invalid("completed is null"));
            }
            if !(*completed).is_null() {
                drop(cimpl::untrack_owned(*completed).map_err(handle_error)?);
                *completed = std::ptr::null_mut();
            }
            Ok(())
        })
    }
}

/// Consumes a valid session on success or failure, including early finish or
/// null output. Invalid/busy handles are rejected without consuming them.
///
/// # Safety
/// out_report writable, out_error null or writable. End session payload borrows.
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
                    .map(|r| C2paSmExclusion {
                        start: r.start,
                        len: r.len,
                    })
                    .collect(),
            })?;
            Ok(())
        })
    }
}

/// Cancels a build. Null is a no-op; invalid/busy handles return an error.
///
/// # Safety
/// out_error null or writable; end session payload borrows.
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

/// Returns immutable report storage; report may cross threads.
///
/// # Safety
/// out writable, out_error null or writable. Do not free concurrently or while
/// any returned borrow remains in use.
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

/// Frees a report. Null is a no-op; invalid/busy handles return an error.
///
/// # Safety
/// out_error null or writable; end all report borrows.
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
pub(crate) mod tests;
