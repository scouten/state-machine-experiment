#![allow(clippy::unwrap_used, clippy::panic)]

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
                    let data = unsafe { request.data.bytes().unwrap().to_vec() };
                    let algorithm = unsafe { request.algorithm.bytes().unwrap().to_vec() };
                    let url = unsafe { request.url.bytes().unwrap().to_vec() };
                    (request, data, algorithm, url)
                })
                .collect::<Vec<_>>();
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
                                    SOURCE_JPEG
                                }
                                stream
                                    if stream
                                        == C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int =>
                                {
                                    &self.output
                                }
                                _ => panic!("unknown stream"),
                            };
                            payload = bytes
                                [request.offset as usize..(request.offset + request.len) as usize]
                                .to_vec();
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
                                    SOURCE_JPEG.len() as u64
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
                            self.output
                                .resize(self.output.len().max(offset + data.len()), 0);
                            self.output[offset..offset + data.len()].copy_from_slice(&data);
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
    let mut build = Build::new(BASELINE_DEFINITION);
    let mut host = Host::default();
    let report = host.drive(&mut build).unwrap();
    assert!(build.0.is_null());
    assert_eq!(host.seen[3], 1);
    assert_eq!(host.seen[4], 0);
    let view = report.view();
    let manifest = unsafe { view.manifest.bytes().unwrap() };
    assert!(!manifest.is_empty());
    let exclusions = unsafe { std::slice::from_raw_parts(view.exclusions, view.exclusion_count) };
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
    let mut reader = crate::NodeSession::new("image/jpeg", Some(&settings)).unwrap();
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
            bytes: vec![1, 2],
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
