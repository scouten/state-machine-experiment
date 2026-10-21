#![allow(clippy::unwrap_used, clippy::panic)]

mod consolidation;

use std::{ffi::CString, ptr};

use base64::Engine;
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

use super::*;
use crate::{c2pa_sm_error_code, c2pa_sm_error_free, c2pa_sm_error_message, C2PA_SM_OK};

type AbiResult<T> = Result<T, (c_int, String)>;

fn result(code: c_int, error: *mut C2paSmError) -> AbiResult<()> {
    if code == C2PA_SM_OK {
        assert!(error.is_null());
        return Ok(());
    }
    unsafe {
        assert!(!error.is_null());
        assert_eq!(c2pa_sm_error_code(error), code);
        let message = std::ffi::CStr::from_ptr(c2pa_sm_error_message(error))
            .to_string_lossy()
            .into_owned();
        c2pa_sm_error_free(error);
        Err((code, message))
    }
}

struct Build(*mut C2paSmBuildSession);

impl Build {
    fn new(definition: &str) -> Self {
        let definition = CString::new(definition).unwrap();
        let certificate = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
        let mut session = ptr::null_mut();
        let mut error = ptr::null_mut();
        unsafe {
            let code = c2pa_sm_build_session_new(
                definition.as_ptr(),
                c"image/jpeg".as_ptr(),
                c"es256".as_ptr(),
                &certificate,
                1,
                &mut session,
                &mut error,
            );
            result(code, error).unwrap();
        }
        assert!(!session.is_null());
        Self(session)
    }

    fn advance(&self) -> AbiResult<(bool, usize)> {
        let mut done = -1;
        let mut count = usize::MAX;
        let mut error = ptr::null_mut();
        let code =
            unsafe { c2pa_sm_build_session_advance(self.0, &mut done, &mut count, &mut error) };
        result(code, error)?;
        Ok((done != 0, count))
    }

    fn request(&self, index: usize) -> AbiResult<C2paSmBuildRequest> {
        let mut request = C2paSmBuildRequest::default();
        let mut error = ptr::null_mut();
        let code =
            unsafe { c2pa_sm_build_session_request(self.0, index, &mut request, &mut error) };
        result(code, error)?;
        Ok(request)
    }

    fn fulfill(&self, reply: C2paSmBuildReply) -> AbiResult<()> {
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_build_session_fulfill(self.0, &reply, &mut error) };
        result(code, error)
    }

    fn acquire(&self, id: u64) -> AbiResult<Lease> {
        let mut raw = ptr::null_mut();
        let mut view = C2paSmMutableBytes::default();
        let mut error = ptr::null_mut();
        let code =
            unsafe { c2pa_sm_build_read_acquire(self.0, id, &mut raw, &mut view, &mut error) };
        result(code, error)?;
        Ok(Lease { raw, view })
    }

    fn fulfill_read(&self, id: u64, completed: &mut Completed) -> AbiResult<()> {
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_build_fulfill_read(self.0, id, &mut completed.0, &mut error) };
        result(code, error)
    }

    fn first_read(&self) -> C2paSmBuildRequest {
        loop {
            let (done, count) = self.advance().unwrap();
            assert!(!done);
            for index in 0..count {
                let request = self.request(index).unwrap();
                if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int {
                    return request;
                }
                assert_eq!(
                    request.kind,
                    C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int
                );
                self.fulfill(C2paSmBuildReply {
                    id: request.id,
                    kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
                    value: SOURCE_JPEG.len() as u64,
                    ..Default::default()
                })
                .unwrap();
            }
        }
    }

    fn finish(&mut self) -> AbiResult<Report> {
        let mut report = ptr::null_mut();
        let mut error = ptr::null_mut();
        let handle = std::mem::replace(&mut self.0, ptr::null_mut());
        let code = unsafe { c2pa_sm_build_session_finish(handle, &mut report, &mut error) };
        result(code, error)?;
        Ok(Report(report))
    }
}

impl Drop for Build {
    fn drop(&mut self) {
        unsafe { c2pa_sm_build_session_free(self.0, ptr::null_mut()) };
    }
}

struct Lease {
    raw: *mut C2paSmReadBuffer,
    view: C2paSmMutableBytes,
}

impl Lease {
    fn seal(&mut self, count: usize) -> AbiResult<Completed> {
        let mut completed = ptr::null_mut();
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_read_seal(&mut self.raw, count, &mut completed, &mut error) };
        result(code, error)?;
        Ok(Completed(completed))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_read_buffer_free(&mut self.raw, ptr::null_mut()) },
            C2PA_SM_OK
        );
    }
}

struct Completed(*mut C2paSmCompletedRead);

impl Drop for Completed {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_completed_read_free(&mut self.0, ptr::null_mut()) },
            C2PA_SM_OK
        );
    }
}

struct WriteLease {
    raw: *mut C2paSmWriteBuffer,
    view: C2paSmBuffer,
}

impl WriteLease {
    fn acquire(build: &Build, id: u64) -> AbiResult<Self> {
        let mut raw = ptr::null_mut();
        let mut view = C2paSmBuffer::default();
        let mut error = ptr::null_mut();
        let code =
            unsafe { c2pa_sm_build_write_acquire(build.0, id, &mut raw, &mut view, &mut error) };
        result(code, error)?;
        Ok(Self { raw, view })
    }
}

impl Drop for WriteLease {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_write_buffer_free(&mut self.raw, ptr::null_mut()) },
            C2PA_SM_OK
        );
    }
}

fn first_write(build: &Build) -> C2paSmBuildRequest {
    loop {
        let (done, count) = build.advance().unwrap();
        assert!(!done);
        assert!(count > 0);
        let requests = (0..count)
            .map(|index| build.request(index).unwrap())
            .collect::<Vec<_>>();
        for request in requests {
            if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int {
                return request;
            }
            let mut reply = C2paSmBuildReply {
                id: request.id,
                ..Default::default()
            };
            let data;
            if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int {
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int;
                reply.value = SOURCE_JPEG.len() as u64;
                data = &[][..];
            } else {
                assert_eq!(
                    request.kind,
                    C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int
                );
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int;
                data =
                    &SOURCE_JPEG[request.offset as usize..(request.offset + request.len) as usize];
            }
            reply.data = C2paSmBuffer::borrowed(data);
            build.fulfill(reply).unwrap();
        }
    }
}

#[derive(Debug)]
struct Report(*mut C2paSmSignReport);

impl Report {
    fn view(&self) -> C2paSmSignReportView {
        let mut view = C2paSmSignReportView::default();
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_sign_report_view(self.0, &mut view, &mut error) };
        result(code, error).unwrap();
        view
    }
}

impl Drop for Report {
    fn drop(&mut self) {
        unsafe { c2pa_sm_sign_report_free(self.0, ptr::null_mut()) };
    }
}

#[derive(Default)]
struct Host {
    output: Vec<u8>,
    seen: [usize; 5],
    fail: Option<c_int>,
    timestamp: Vec<u8>,
    leased: bool,
    source: Option<Vec<u8>>,
    max_reads: usize,
    leased_writes: bool,
    write_leases: Vec<WriteLease>,
    source_buffer: Option<(usize, usize)>,
    shared_source_writes: usize,
}

impl Host {
    fn drive(&mut self, build: &mut Build) -> AbiResult<Report> {
        loop {
            let (done, count) = build.advance()?;
            if done {
                return build.finish();
            }
            assert!(count > 0, "host stalled");
            let requests = (0..count)
                .map(|index| {
                    let request = build.request(index).unwrap();
                    let data = if self.leased_writes
                        && request.kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int
                    {
                        Vec::new()
                    } else {
                        unsafe { request.data.bytes().unwrap().to_vec() }
                    };
                    let algorithm = unsafe { request.algorithm.bytes().unwrap().to_vec() };
                    let url = unsafe { request.url.bytes().unwrap().to_vec() };
                    (request, data, algorithm, url)
                })
                .collect::<Vec<_>>();
            self.max_reads = self.max_reads.max(
                requests
                    .iter()
                    .filter(|(request, ..)| {
                        request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int
                    })
                    .count(),
            );
            for (request, data, algorithm, url) in requests.into_iter().rev() {
                self.seen[request.kind as usize] += 1;
                let mut reply = C2paSmBuildReply {
                    id: request.id,
                    ..Default::default()
                };
                let payload;
                if self.fail == Some(request.kind) {
                    reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_FAILED as c_int;
                    payload = b"host unavailable".to_vec();
                } else {
                    match request.kind {
                        kind if kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int =>
                        {
                            let bytes = match request.stream {
                                stream
                                    if stream
                                        == C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int =>
                                {
                                    self.source.as_deref().unwrap_or(SOURCE_JPEG)
                                }
                                stream
                                    if stream
                                        == C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int =>
                                {
                                    &self.output
                                }
                                _ => panic!("unknown stream"),
                            };
                            let bytes = &bytes
                                [request.offset as usize..(request.offset + request.len) as usize];
                            if self.leased {
                                let mut lease = build.acquire(request.id)?;
                                if request.stream
                                    == C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int
                                {
                                    self.source_buffer =
                                        Some((lease.view.data as usize, lease.view.len));
                                }
                                unsafe {
                                    std::slice::from_raw_parts_mut(lease.view.data, lease.view.len)
                                        .copy_from_slice(bytes);
                                }
                                let mut completed = lease.seal(bytes.len())?;
                                build.fulfill_read(request.id, &mut completed)?;
                                assert!(completed.0.is_null());
                                continue;
                            }
                            payload = bytes.to_vec();
                            reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int;
                        }
                        kind if kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int =>
                        {
                            reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int;
                            reply.value = match request.stream {
                                stream
                                    if stream
                                        == C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int =>
                                {
                                    self.source.as_deref().unwrap_or(SOURCE_JPEG).len() as u64
                                }
                                stream
                                    if stream
                                        == C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int =>
                                {
                                    self.output.len() as u64
                                }
                                _ => panic!("unknown stream"),
                            };
                            payload = Vec::new();
                        }
                        kind if kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int =>
                        {
                            assert_eq!(
                                request.stream,
                                C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int
                            );
                            let offset = request.offset as usize;
                            if self.leased_writes {
                                let lease = WriteLease::acquire(build, request.id)?;
                                assert_eq!(lease.view.data, request.data.data);
                                assert_eq!(lease.view.len, request.data.len);
                                if let Some((pointer, len)) = self.source_buffer {
                                    if len >= 64 * 1024 && len == lease.view.len {
                                        assert_eq!(lease.view.data as usize, pointer);
                                        self.shared_source_writes += 1;
                                    }
                                }
                                let bytes = unsafe { lease.view.bytes().unwrap() };
                                self.output
                                    .resize(self.output.len().max(offset + bytes.len()), 0);
                                self.output[offset..offset + bytes.len()].copy_from_slice(bytes);
                                self.write_leases.push(lease);
                            } else {
                                self.output
                                    .resize(self.output.len().max(offset + data.len()), 0);
                                self.output[offset..offset + data.len()].copy_from_slice(&data);
                            }
                            reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_WRITTEN as c_int;
                            payload = Vec::new();
                        }
                        kind if kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_SIGN as c_int =>
                        {
                            assert_eq!(algorithm, b"es256");
                            payload = c2pa_raw_crypto::signer_from_private_key(
                                TEST_SIGNER_KEY_PEM,
                                c2pa_raw_crypto::SigningAlg::Es256,
                            )
                            .unwrap()
                            .sign(&data)
                            .unwrap();
                            assert_eq!(payload.len(), 64);
                            reply.kind =
                                C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_SIGNATURE as c_int;
                        }
                        kind if kind
                            == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_TIMESTAMP as c_int =>
                        {
                            assert_eq!(url, b"https://tsa.example/");
                            assert_eq!(data.first(), Some(&0x30));
                            payload = self.timestamp.clone();
                            reply.kind =
                                C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_TIMESTAMP as c_int;
                        }
                        _ => panic!("unknown request"),
                    }
                }
                reply.data = C2paSmBuffer::borrowed(&payload);
                build.fulfill(reply)?;
            }
        }
    }
}

#[test]
fn signing_abi_round_trips_a_jpeg_through_the_existing_reader_as_trusted() {
    for leased in [false, true] {
        let mut build = Build::new(BASELINE_DEFINITION);
        let mut host = Host {
            leased,
            ..Default::default()
        };
        let report = host.drive(&mut build).unwrap();
        assert!(build.0.is_null());
        assert_eq!(host.seen[3], 1);
        assert_eq!(host.seen[4], 0);
        let view = report.view();
        let manifest = unsafe { view.manifest.bytes().unwrap() };
        assert!(!manifest.is_empty());
        let exclusions =
            unsafe { std::slice::from_raw_parts(view.exclusions, view.exclusion_count) };
        assert!(!exclusions.is_empty());
        assert!(exclusions.iter().map(|range| range.len).sum::<u64>() >= manifest.len() as u64);
        assert!(exclusions
            .windows(2)
            .all(|pair| pair[0].start <= pair[1].start));
        assert!(exclusions
            .iter()
            .all(|range| range.start + range.len <= host.output.len() as u64));

        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            base64_certificate()
        );
        let settings = format!(r#"{{"trust":{{"trust_anchors":{pem:?}}}}}"#);
        let mut reader = crate::ReadSessionBridge::new("image/jpeg", Some(&settings)).unwrap();
        loop {
            match reader.advance().unwrap() {
                crate::Step::Complete => break,
                crate::Step::Pending(requests) => {
                    for request in requests {
                        let reply = match &request {
                            crate::PendingRequest::Read { start, len, .. } => crate::Reply::Bytes(
                                host.output[*start as usize..(*start + *len) as usize].to_vec(),
                            ),
                            crate::PendingRequest::Length { .. } => {
                                crate::Reply::Length(host.output.len() as u64)
                            }
                            crate::PendingRequest::CurrentDateTime { .. } => {
                                crate::Reply::Time(1_800_000_000)
                            }
                            crate::PendingRequest::Ocsp { .. } => {
                                crate::Reply::Failed("offline".into())
                            }
                            _ => panic!("unexpected reader request"),
                        };
                        reader.fulfill(request.id(), reply).unwrap();
                    }
                }
            }
        }
        let reader = crate::C2paSmReader {
            inner: reader.finish().unwrap().unwrap(),
        };
        assert_eq!(
            unsafe { crate::c2pa_sm_reader_validation_state(&reader) },
            crate::C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED
        );
        let json = reader.inner.json();
        assert!(json.contains("Trusted"), "{json}");
        assert!(json.contains("baseline.jpg"));
        assert!(json.contains("c2pa.actions.v2"));
    }
}

fn base64_certificate() -> String {
    base64::engine::general_purpose::STANDARD.encode(TEST_SIGNER_CERT)
}

#[test]
fn invalid_hard_bindings_are_reported_without_parsing_json() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let mut host = Host::default();
    host.drive(&mut build).unwrap();
    let index = host.output.len() - 3;
    host.output[index] ^= 1;
    let session = crate::tests::new_session("image/jpeg", None);
    let (status, reader, error) = crate::tests::drive(session, &host.output);
    assert_eq!(status, C2PA_SM_OK);
    assert!(error.is_null());
    assert!(!reader.is_null());
    unsafe {
        assert_eq!(
            crate::c2pa_sm_reader_validation_state(reader),
            crate::C2paSmValidationState::C2PA_SM_VALIDATION_INVALID
        );
        crate::c2pa_sm_reader_free(reader);
    }
}

#[test]
fn wrong_and_duplicate_replies_leave_the_protocol_well_defined() {
    let build = Build::new(BASELINE_DEFINITION);
    let (_, count) = build.advance().unwrap();
    assert!(count > 0);
    let request = build.request(0).unwrap();
    assert_eq!(
        request.kind,
        C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int
    );
    let reply = C2paSmBuildReply {
        id: request.id,
        kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
        value: SOURCE_JPEG.len() as u64,
        ..Default::default()
    };
    assert_eq!(
        build
            .fulfill(C2paSmBuildReply {
                kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_WRITTEN as c_int,
                ..reply
            })
            .unwrap_err()
            .0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        build
            .fulfill(C2paSmBuildReply {
                id: u64::MAX,
                ..reply
            })
            .unwrap_err()
            .0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
    build.fulfill(reply).unwrap();
    assert_eq!(
        build.fulfill(reply).unwrap_err().0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn advance_reports_only_new_requests_and_does_not_complete_while_waiting() {
    let build = Build::new(BASELINE_DEFINITION);
    assert_eq!(build.advance().unwrap(), (false, 1));
    assert_eq!(build.advance().unwrap(), (false, 0));
    assert!(build.request(0).is_err());
}

#[test]
fn finish_consumes_incomplete_sessions_and_rejects_stale_handles() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let handle = build.0;
    assert_eq!(
        build.finish().unwrap_err().0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
    let stale = Build(handle);
    assert_eq!(
        stale.advance().unwrap_err().0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn host_failure_in_each_operation_fails_the_build_not_the_process() {
    for kind in 0..=4 {
        let definition = timestamp_definition();
        let mut build = Build::new(&definition);
        let mut host = Host {
            fail: Some(kind),
            ..Default::default()
        };
        let (code, message) = host.drive(&mut build).unwrap_err();
        assert_eq!(
            code,
            C2paSmBuildErrorCode::C2PA_SM_ERR_BUILD as c_int,
            "kind {kind}: {message}"
        );
        assert!(message.contains("host unavailable"), "{message}");
    }
}

fn timestamp_definition() -> String {
    BASELINE_DEFINITION.replace(
        "\"title\"",
        "\"tsa_url\": \"https://tsa.example/\", \"title\"",
    )
}

#[test]
fn timestamp_response_mapping_embeds_a_granted_token() {
    let mut body = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x2c];
    body.extend([0x42; 300]);
    let mut timestamp = vec![0x30, 0x82];
    timestamp.extend((body.len() as u16).to_be_bytes());
    timestamp.extend(body);
    let mut host = Host {
        timestamp,
        ..Default::default()
    };
    let mut build = Build::new(&timestamp_definition());
    let report = host.drive(&mut build).unwrap();
    assert_eq!(host.seen[4], 1);
    assert!(unsafe { report.view().manifest.bytes().unwrap() }
        .windows(300)
        .any(|bytes| bytes == [0x42; 300]));
}

#[test]
fn refused_and_malformed_timestamp_responses_fail_closed() {
    for timestamp in [
        vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02],
        vec![0xff],
        vec![],
    ] {
        let mut host = Host {
            timestamp,
            ..Default::default()
        };
        let mut build = Build::new(&timestamp_definition());
        assert_eq!(
            host.drive(&mut build).unwrap_err().0,
            C2paSmBuildErrorCode::C2PA_SM_ERR_BUILD as c_int
        );
    }
}

fn invalid(call: impl FnOnce(*mut *mut C2paSmError) -> c_int) {
    let mut error = ptr::null_mut();
    let code = call(&mut error);
    assert_eq!(
        result(code, error).unwrap_err().0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn constructor_validates_strings_certificates_and_output_pointers() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let certificate = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    let mut session = ptr::null_mut();
    unsafe {
        for (definition, format, algorithm) in [
            (ptr::null(), c"image/jpeg".as_ptr(), c"es256".as_ptr()),
            (c"{}".as_ptr(), ptr::null(), c"es256".as_ptr()),
            (c"{}".as_ptr(), c"image/jpeg".as_ptr(), ptr::null()),
            (c"{".as_ptr(), c"image/jpeg".as_ptr(), c"es256".as_ptr()),
            (c"{}".as_ptr(), c"image/jpeg".as_ptr(), c"es256".as_ptr()),
            (c"{}".as_ptr(), c"image/jpeg".as_ptr(), c"bad".as_ptr()),
            (c"\xff".as_ptr(), c"image/jpeg".as_ptr(), c"es256".as_ptr()),
        ] {
            invalid(|error| {
                c2pa_sm_build_session_new(
                    definition,
                    format,
                    algorithm,
                    &certificate,
                    1,
                    &mut session,
                    error,
                )
            });
            assert!(session.is_null());
        }
        invalid(|error| {
            c2pa_sm_build_session_new(
                definition.as_ptr(),
                c"image/jpeg".as_ptr(),
                c"es256".as_ptr(),
                &certificate,
                1,
                ptr::null_mut(),
                error,
            )
        });
        for (certs, count) in [(ptr::null(), 1), (&certificate as *const _, usize::MAX)] {
            invalid(|error| {
                c2pa_sm_build_session_new(
                    definition.as_ptr(),
                    c"image/jpeg".as_ptr(),
                    c"es256".as_ptr(),
                    certs,
                    count,
                    &mut session,
                    error,
                )
            });
        }
        for certificate in [
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
        ] {
            invalid(|error| {
                c2pa_sm_build_session_new(
                    definition.as_ptr(),
                    c"image/jpeg".as_ptr(),
                    c"es256".as_ptr(),
                    &certificate,
                    1,
                    &mut session,
                    error,
                )
            });
        }
        let mut error = ptr::null_mut();
        let code = c2pa_sm_build_session_new(
            definition.as_ptr(),
            c"image/png".as_ptr(),
            c"es256".as_ptr(),
            &certificate,
            1,
            &mut session,
            &mut error,
        );
        assert_eq!(
            result(code, error).unwrap_err().0,
            crate::C2PA_SM_ERR_UNSUPPORTED_TYPE
        );
        assert_eq!(
            c2pa_sm_build_session_new(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &mut session,
                ptr::null_mut()
            ),
            crate::C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert!(session.is_null());
        let mut error = ptr::null_mut();
        let code = c2pa_sm_build_session_new(
            definition.as_ptr(),
            c"image/jpeg".as_ptr(),
            c"es256".as_ptr(),
            ptr::null(),
            0,
            &mut session,
            &mut error,
        );
        result(code, error).unwrap();
        result(c2pa_sm_build_session_free(session, &mut error), error).unwrap();
    }
}

#[test]
fn exported_operations_validate_handles_outputs_and_reply_buffers() {
    let build = Build::new(BASELINE_DEFINITION);
    let mut done = 9;
    let mut count = 9;
    unsafe {
        invalid(|error| {
            c2pa_sm_build_session_advance(ptr::null_mut(), &mut done, &mut count, error)
        });
        assert_eq!((done, count), (0, 0));
        invalid(|error| c2pa_sm_build_session_advance(build.0, ptr::null_mut(), &mut count, error));
        invalid(|error| c2pa_sm_build_session_advance(build.0, &mut done, ptr::null_mut(), error));
        invalid(|error| c2pa_sm_build_session_request(build.0, 0, ptr::null_mut(), error));
        let mut view = C2paSmBuildRequest {
            id: 123,
            ..Default::default()
        };
        invalid(|error| c2pa_sm_build_session_request(ptr::null_mut(), 0, &mut view, error));
        assert_eq!(view.id, 0);
        invalid(|error| c2pa_sm_build_session_fulfill(build.0, ptr::null(), error));
        let mut reply = C2paSmBuildReply::default();
        invalid(|error| c2pa_sm_build_session_fulfill(ptr::null_mut(), &reply, error));
        for (kind, data) in [
            (99, C2paSmBuffer::default()),
            (
                C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int,
                C2paSmBuffer {
                    data: ptr::null(),
                    len: 1,
                },
            ),
            (
                C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_SIGNATURE as c_int,
                C2paSmBuffer {
                    data: TEST_SIGNER_CERT.as_ptr(),
                    len: usize::MAX,
                },
            ),
            (
                C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_FAILED as c_int,
                C2paSmBuffer::borrowed(&[0xff]),
            ),
        ] {
            reply.kind = kind;
            reply.data = data;
            invalid(|error| c2pa_sm_build_session_fulfill(build.0, &reply, error));
        }
        let mut report = ptr::null_mut();
        invalid(|error| c2pa_sm_build_session_finish(ptr::null_mut(), &mut report, error));
        assert!(report.is_null());
        invalid(|error| c2pa_sm_sign_report_view(ptr::null(), ptr::null_mut(), error));
        let mut report_view = C2paSmSignReportView {
            exclusion_count: 99,
            ..Default::default()
        };
        invalid(|error| c2pa_sm_sign_report_view(ptr::null(), &mut report_view, error));
        assert_eq!(report_view.exclusion_count, 0);
        invalid(|error| c2pa_sm_sign_report_view(build.0.cast(), &mut report_view, error));
        invalid(|error| c2pa_sm_sign_report_free(build.0.cast(), error));
        assert!(build.advance().is_ok());
        let mut error = ptr::null_mut();
        result(
            c2pa_sm_build_session_free(ptr::null_mut(), &mut error),
            error,
        )
        .unwrap();
        result(c2pa_sm_sign_report_free(ptr::null_mut(), &mut error), error).unwrap();
    }
}

#[test]
fn failed_finish_with_null_output_consumes_the_session() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let handle = std::mem::replace(&mut build.0, ptr::null_mut());
    unsafe {
        invalid(|error| c2pa_sm_build_session_finish(handle, ptr::null_mut(), error));
        invalid(|error| c2pa_sm_build_session_free(handle, error));
    }
}

#[test]
fn reports_are_independent_typed_handles_and_cannot_be_freed_twice() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let mut host = Host::default();
    let mut report = host.drive(&mut build).unwrap();
    let view = report.view();
    assert!(!view.manifest.data.is_null());
    let handle = std::mem::replace(&mut report.0, ptr::null_mut());
    unsafe {
        invalid(|error| c2pa_sm_sign_report_view(handle, ptr::null_mut(), error));
        invalid(|error| c2pa_sm_build_session_free(handle.cast(), error));
        let mut error = ptr::null_mut();
        result(c2pa_sm_sign_report_free(handle, &mut error), error).unwrap();
        invalid(|error| c2pa_sm_sign_report_free(handle, error));
        let mut out = C2paSmSignReportView::default();
        invalid(|error| c2pa_sm_sign_report_view(handle, &mut out, error));
    }
}

#[test]
fn handles_and_owned_errors_can_cross_threads() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<C2paSmBuildSession>();
    assert_send::<C2paSmSignReport>();
    assert_sync::<C2paSmSignReport>();
    let mut build = Build::new(BASELINE_DEFINITION);
    build.advance().unwrap();
    let handle = std::mem::replace(&mut build.0, ptr::null_mut()) as usize;
    let (report, error) = std::thread::spawn(move || {
        let mut build = Build(handle as *mut C2paSmBuildSession);
        let request = build.request(0).unwrap();
        build
            .fulfill(C2paSmBuildReply {
                kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
                id: request.id,
                value: SOURCE_JPEG.len() as u64,
                ..Default::default()
            })
            .unwrap();
        let mut report = Host::default().drive(&mut build).unwrap();
        let mut error = ptr::null_mut();
        let mut done = 0;
        let mut count = 0;
        let code =
            unsafe { c2pa_sm_build_session_advance(build.0, &mut done, &mut count, &mut error) };
        assert_eq!(code, crate::C2PA_SM_ERR_INVALID_ARGUMENT);
        (
            std::mem::replace(&mut report.0, ptr::null_mut()) as usize,
            error as usize,
        )
    })
    .join()
    .unwrap();
    let report = Report(report as *mut C2paSmSignReport);
    assert!(report.view().manifest.len > 0);
    let error = error as *mut C2paSmError;
    let mut ignored = ptr::null_mut();
    unsafe { c2pa_sm_build_session_free(ptr::null_mut(), &mut ignored) };
    assert_eq!(
        result(crate::C2PA_SM_ERR_INVALID_ARGUMENT, error)
            .unwrap_err()
            .0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
}

#[test]
fn all_request_views_map_fields_and_streams_without_borrowing_temporary_values() {
    let requests = [
        PendingRequest::Read {
            id: 1,
            stream: Stream::Source,
            start: 20,
            len: 30,
        },
        PendingRequest::Read {
            id: 2,
            stream: Stream::Output,
            start: 40,
            len: 50,
        },
        PendingRequest::Length {
            id: 3,
            stream: Stream::Output,
        },
        PendingRequest::Write {
            id: 4,
            stream: Stream::Output,
            offset: 60,
            bytes: vec![1, 2].into(),
        },
        PendingRequest::Sign {
            id: 5,
            alg: "es256",
            data: vec![3, 4],
        },
        PendingRequest::Timestamp {
            id: 6,
            url: "https://tsa.example/".into(),
            request: vec![5, 6],
        },
    ];
    for (index, request) in requests.iter().enumerate() {
        let view = describe(request).unwrap();
        assert_eq!(view.id, index as u64 + 1);
        match request {
            PendingRequest::Read {
                stream, start, len, ..
            } => {
                assert_eq!(
                    view.kind,
                    C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int
                );
                assert_eq!(
                    (view.offset, view.len, view.stream),
                    (*start, *len, stream_id(*stream))
                );
            }
            PendingRequest::Length { .. } => assert_eq!(
                view.stream,
                C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int
            ),
            PendingRequest::Write { .. } => {
                assert_eq!(view.offset, 60);
                assert_eq!(unsafe { view.data.bytes().unwrap() }, &[1, 2]);
            }
            PendingRequest::Sign { .. } => {
                assert_eq!(unsafe { view.algorithm.bytes().unwrap() }, b"es256")
            }
            PendingRequest::Timestamp { .. } => {
                assert_eq!(
                    unsafe { view.url.bytes().unwrap() },
                    b"https://tsa.example/"
                );
                assert_eq!(unsafe { view.data.bytes().unwrap() }, &[5, 6]);
            }
            _ => panic!("unknown request"),
        }
    }
}

#[test]
fn busy_handles_cannot_be_freed_or_consumed_by_another_operation() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let checked = cimpl::checkout_exclusive(build.0).unwrap();
    let mut report = ptr::null_mut();
    unsafe {
        invalid(|error| c2pa_sm_build_session_free(build.0, error));
        invalid(|error| c2pa_sm_build_session_finish(build.0, &mut report, error));
    }
    assert!(report.is_null());
    assert_eq!(
        build.advance().unwrap_err().0,
        crate::C2PA_SM_ERR_INVALID_ARGUMENT
    );
    drop(checked);
    let report = Host::default().drive(&mut build).unwrap();
    let checked = cimpl::checkout_shared(report.0).unwrap();
    unsafe { invalid(|error| c2pa_sm_sign_report_free(report.0, error)) };
    drop(checked);
    assert!(report.view().manifest.len > 0);
}

#[test]
fn reply_kind_conversion_accepts_only_declared_variants() {
    use C2paSmBuildReplyKind::*;

    for kind in [
        C2PA_SM_BUILD_REPLY_BYTES,
        C2PA_SM_BUILD_REPLY_LENGTH,
        C2PA_SM_BUILD_REPLY_WRITTEN,
        C2PA_SM_BUILD_REPLY_SIGNATURE,
        C2PA_SM_BUILD_REPLY_TIMESTAMP,
        C2PA_SM_BUILD_REPLY_FAILED,
    ] {
        assert_eq!(C2paSmBuildReplyKind::try_from(kind as c_int), Ok(kind));
    }
    for value in [c_int::MIN, -1, 6, 99, c_int::MAX] {
        assert_eq!(
            C2paSmBuildReplyKind::try_from(value),
            Err("unknown build reply kind")
        );
    }
}

#[test]
fn cimpl_handles_are_exclusive_typed_and_consumable() {
    let handle = cimpl::track_box(Box::into_raw(Box::new(42_u64)));
    assert!(!handle.is_null());
    let mut checked = cimpl::checkout_exclusive(handle).unwrap();
    assert_eq!(*checked, 42);
    *checked = 43;
    assert!(cimpl::checkout_exclusive(handle).is_err());
    assert!(cimpl::checkout_exclusive(handle.cast::<u32>()).is_err());
    assert!(cimpl::untrack_owned(handle).is_err());
    drop(checked);
    assert_eq!(cimpl::untrack_owned(handle).unwrap(), 43);
    assert!(cimpl::checkout_exclusive(handle).is_err());
    assert!(cimpl::untrack_owned(handle).is_err());
    assert!(cimpl::checkout_exclusive::<u64>(std::ptr::null_mut()).is_err());
}

#[test]
fn read_lease_sealing_and_reply_conversion_preserve_the_allocation() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    let mut lease = build.acquire(request.id).unwrap();
    assert_eq!(lease.view.len as u64, request.len);
    let pointer = lease.view.data;
    unsafe { std::slice::from_raw_parts_mut(pointer, lease.view.len).fill(42) };
    let completed = lease.seal(lease.view.len).unwrap();
    assert!(lease.raw.is_null());
    let mut checked = cimpl::checkout_exclusive(completed.0).unwrap();
    let buffer = checked.buffer.as_mut().unwrap();
    assert_eq!(buffer.bytes.as_ptr(), pointer);
    let Reply::Bytes(bytes) = buffer.take_reply() else {
        panic!("not bytes")
    };
    assert_eq!(bytes.as_ptr(), pointer);
    assert!(bytes.iter().all(|byte| *byte == 42));
}

#[test]
fn read_leases_validate_counts_ids_and_sessions_without_consuming_on_error() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    let other = Build::new(BASELINE_DEFINITION);
    let other_request = other.first_read();
    let mut lease = build.acquire(request.id).unwrap();
    let original = lease.raw;
    assert!(build.acquire(request.id).is_err());
    assert!(build.acquire(u64::MAX).is_err());
    assert!(lease.seal(lease.view.len + 1).is_err());
    assert!(lease.seal(lease.view.len - 1).is_err());
    assert_eq!(lease.raw, original);
    assert!(!build.advance().unwrap().0);
    unsafe {
        std::slice::from_raw_parts_mut(lease.view.data, lease.view.len).copy_from_slice(
            &SOURCE_JPEG[request.offset as usize..(request.offset + request.len) as usize],
        );
    }
    let bytes = vec![0; lease.view.len];
    assert!(build
        .fulfill(C2paSmBuildReply {
            id: request.id,
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int,
            data: C2paSmBuffer::borrowed(&bytes),
            ..Default::default()
        })
        .is_err());
    let mut completed = lease.seal(lease.view.len).unwrap();
    let handle = completed.0;
    assert!(other
        .fulfill_read(other_request.id, &mut completed)
        .is_err());
    assert!(build.fulfill_read(u64::MAX, &mut completed).is_err());
    assert_eq!(completed.0, handle);
    build.fulfill_read(request.id, &mut completed).unwrap();
    assert!(completed.0.is_null());
    assert!(build.fulfill_read(request.id, &mut completed).is_err());
    assert!(build.acquire(request.id).is_err());
}

#[test]
fn writable_and_completed_leases_survive_their_session() {
    let mut lease = {
        let build = Build::new(BASELINE_DEFINITION);
        build.acquire(build.first_read().id).unwrap()
    };
    unsafe { std::slice::from_raw_parts_mut(lease.view.data, lease.view.len).fill(7) };
    let completed = lease.seal(lease.view.len).unwrap();
    let checked = cimpl::checkout_exclusive(completed.0).unwrap();
    assert!(checked
        .buffer
        .as_ref()
        .unwrap()
        .bytes
        .iter()
        .all(|byte| *byte == 7));
    drop(checked);
    drop(completed);
}

#[test]
fn abandoning_or_failing_a_read_does_not_reissue_its_lease() {
    for seal in [false, true] {
        let build = Build::new(BASELINE_DEFINITION);
        let request = build.first_read();
        let mut lease = build.acquire(request.id).unwrap();
        let mut completed = if seal {
            Some(lease.seal(lease.view.len).unwrap())
        } else {
            None
        };
        drop(lease);
        assert!(build.acquire(request.id).is_err());
        build
            .fulfill(C2paSmBuildReply {
                id: request.id,
                kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_FAILED as c_int,
                data: C2paSmBuffer::borrowed(b"read cancelled"),
                ..Default::default()
            })
            .unwrap();
        if let Some(completed) = &mut completed {
            let handle = completed.0;
            assert!(build.fulfill_read(request.id, completed).is_err());
            assert_eq!(completed.0, handle);
        }
        assert!(build.advance().is_err());
    }
}

#[test]
fn leased_hash_reads_complete_out_of_order_for_a_large_asset() {
    let mut source = SOURCE_JPEG.to_vec();
    source.resize(512 * 1024, 0);
    let mut host = Host {
        leased: true,
        source: Some(source),
        ..Default::default()
    };
    let mut build = Build::new(BASELINE_DEFINITION);
    assert!(host.drive(&mut build).unwrap().view().manifest.len > 0);
    assert!(host.max_reads > 1);
    let session = crate::tests::new_session("image/jpeg", None);
    let (status, reader, error) = crate::tests::drive(session, &host.output);
    assert_eq!(status, C2PA_SM_OK);
    assert!(error.is_null());
    unsafe {
        assert_eq!(
            crate::c2pa_sm_reader_validation_state(reader),
            crate::C2paSmValidationState::C2PA_SM_VALIDATION_VALID
        );
        crate::c2pa_sm_reader_free(reader);
    }
}

#[test]
fn read_lease_abi_rejects_invalid_outputs_busy_and_wrong_type_handles() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    let mut raw = ptr::null_mut();
    let mut view = C2paSmMutableBytes::default();
    let mut completed = ptr::null_mut();
    unsafe {
        invalid(|error| {
            c2pa_sm_build_read_acquire(build.0, request.id, ptr::null_mut(), &mut view, error)
        });
        invalid(|error| {
            c2pa_sm_build_read_acquire(build.0, request.id, &mut raw, ptr::null_mut(), error)
        });
        invalid(|error| c2pa_sm_read_seal(ptr::null_mut(), 0, &mut completed, error));
        invalid(|error| c2pa_sm_read_seal(&mut raw, 0, ptr::null_mut(), error));
        invalid(|error| c2pa_sm_build_fulfill_read(build.0, request.id, ptr::null_mut(), error));
        invalid(|error| c2pa_sm_read_buffer_free(ptr::null_mut(), error));
        invalid(|error| c2pa_sm_completed_read_free(ptr::null_mut(), error));
        let mut wrong = build.0.cast::<C2paSmReadBuffer>();
        invalid(|error| c2pa_sm_read_buffer_free(&mut wrong, error));
        assert_eq!(wrong, build.0.cast());
    }
    let mut lease = build.acquire(request.id).unwrap();
    let checked = cimpl::checkout_exclusive(lease.raw).unwrap();
    assert!(lease.seal(lease.view.len).is_err());
    unsafe { invalid(|error| c2pa_sm_read_buffer_free(&mut lease.raw, error)) };
    drop(checked);
    let mut completed = lease.seal(lease.view.len).unwrap();
    let checked = cimpl::checkout_exclusive(completed.0).unwrap();
    assert!(build.fulfill_read(request.id, &mut completed).is_err());
    unsafe { invalid(|error| c2pa_sm_completed_read_free(&mut completed.0, error)) };
    drop(checked);
}

#[test]
fn read_allocation_overflow_is_reported_without_leasing_the_request() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    cimpl::checkout_exclusive(build.0)
        .unwrap()
        .reads
        .get_mut(&request.id)
        .unwrap()
        .0 = u64::MAX;
    assert!(build.acquire(request.id).is_err());
    assert!(
        cimpl::checkout_exclusive(build.0).unwrap().reads[&request.id]
            .1
            .is_none()
    );
}

#[test]
fn write_leases_share_storage_and_survive_acknowledgment_and_session_destruction() {
    let (lease, another, expected) = {
        let build = Build::new(BASELINE_DEFINITION);
        let request = first_write(&build);
        let lease = WriteLease::acquire(&build, request.id).unwrap();
        assert_eq!(lease.view.data, request.data.data);
        let expected = unsafe { lease.view.bytes().unwrap().to_vec() };
        assert!(!build.advance().unwrap().0);
        let another = WriteLease::acquire(&build, request.id).unwrap();
        assert_eq!(lease.view.data, another.view.data);
        assert!(build
            .fulfill(C2paSmBuildReply {
                id: request.id,
                kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
                ..Default::default()
            })
            .is_err());
        assert!(WriteLease::acquire(&build, request.id).is_ok());
        build
            .fulfill(C2paSmBuildReply {
                id: request.id,
                kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_WRITTEN as c_int,
                ..Default::default()
            })
            .unwrap();
        assert!(WriteLease::acquire(&build, request.id).is_err());
        build.advance().unwrap();
        (lease, another, expected)
    };
    assert_eq!(unsafe { lease.view.bytes().unwrap() }, expected);
    drop(lease);
    assert_eq!(unsafe { another.view.bytes().unwrap() }, expected);
}

#[test]
fn large_source_read_storage_is_reused_for_writes_through_the_bridge_and_abi() {
    let mut source = SOURCE_JPEG.to_vec();
    source.resize(2 * 1024 * 1024 + 17, 0);
    let mut host = Host {
        leased: true,
        leased_writes: true,
        source: Some(source),
        ..Default::default()
    };
    let mut build = Build::new(BASELINE_DEFINITION);
    assert!(host.drive(&mut build).unwrap().view().manifest.len > 0);
    assert!(build.0.is_null());
    assert!(host.shared_source_writes >= 2);
    for lease in &host.write_leases {
        let checked = cimpl::checkout_shared(lease.raw).unwrap();
        assert_eq!(checked._bytes.as_ptr(), lease.view.data);
        assert_eq!(checked._bytes.as_ref(), unsafe {
            lease.view.bytes().unwrap()
        });
    }
    let session = crate::tests::new_session("image/jpeg", None);
    let (status, reader, error) = crate::tests::drive(session, &host.output);
    assert_eq!(status, C2PA_SM_OK);
    assert!(error.is_null());
    unsafe {
        assert_eq!(
            crate::c2pa_sm_reader_validation_state(reader),
            crate::C2paSmValidationState::C2PA_SM_VALIDATION_VALID
        );
        crate::c2pa_sm_reader_free(reader);
    }
}

#[test]
fn write_acquisition_and_release_validate_outputs_types_and_borrows() {
    let build = Build::new(BASELINE_DEFINITION);
    assert!(WriteLease::acquire(&build, u64::MAX).is_err());
    let read = build.first_read();
    assert!(WriteLease::acquire(&build, read.id).is_err());
    let other = Build::new(BASELINE_DEFINITION);
    let request = first_write(&other);
    let mut raw = ptr::null_mut();
    let mut view = C2paSmBuffer::default();
    unsafe {
        invalid(|error| {
            c2pa_sm_build_write_acquire(other.0, request.id, ptr::null_mut(), &mut view, error)
        });
        invalid(|error| {
            c2pa_sm_build_write_acquire(other.0, request.id, &mut raw, ptr::null_mut(), error)
        });
        invalid(|error| {
            c2pa_sm_build_write_acquire(ptr::null_mut(), request.id, &mut raw, &mut view, error)
        });
        invalid(|error| c2pa_sm_write_buffer_free(ptr::null_mut(), error));
        let mut wrong = other.0.cast::<C2paSmWriteBuffer>();
        invalid(|error| c2pa_sm_write_buffer_free(&mut wrong, error));
        assert_eq!(wrong, other.0.cast());
        assert_eq!(
            c2pa_sm_write_buffer_free(&mut raw, ptr::null_mut()),
            C2PA_SM_OK
        );
    }
    let checked = cimpl::checkout_exclusive(other.0).unwrap();
    assert!(WriteLease::acquire(&other, request.id).is_err());
    drop(checked);
    let mut lease = WriteLease::acquire(&other, request.id).unwrap();
    let handle = lease.raw;
    let checked = cimpl::checkout_shared(handle).unwrap();
    unsafe { invalid(|error| c2pa_sm_write_buffer_free(&mut lease.raw, error)) };
    assert_eq!(lease.raw, handle);
    drop(checked);
    unsafe {
        assert_eq!(
            c2pa_sm_write_buffer_free(&mut lease.raw, ptr::null_mut()),
            C2PA_SM_OK
        );
        assert!(lease.raw.is_null());
        let mut stale = handle;
        invalid(|error| c2pa_sm_write_buffer_free(&mut stale, error));
        assert_eq!(stale, handle);
    }
}

#[test]
fn failed_writes_release_session_ownership_without_revoking_host_storage() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = first_write(&build);
    let lease = WriteLease::acquire(&build, request.id).unwrap();
    let expected = unsafe { lease.view.bytes().unwrap().to_vec() };
    build
        .fulfill(C2paSmBuildReply {
            id: request.id,
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_FAILED as c_int,
            data: C2paSmBuffer::borrowed(b"write failed"),
            ..Default::default()
        })
        .unwrap();
    assert!(WriteLease::acquire(&build, request.id).is_err());
    assert!(build.advance().is_err());
    drop(build);
    assert_eq!(unsafe { lease.view.bytes().unwrap() }, expected);
}
