// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.
#![allow(clippy::unwrap_used, clippy::panic)]
use std::{
    ffi::{c_int, CStr, CString},
    ptr,
};

use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

use super::*;
use crate::*;

type AbiResult<T> = Result<T, (c_int, String)>;
fn result(code: c_int, error: *mut C2paSmError) -> AbiResult<()> {
    if code == 0 {
        assert!(error.is_null());
        return Ok(());
    }
    unsafe {
        assert!(!error.is_null());
        assert_eq!(c2pa_sm_error_code(error), code);
        let message = CStr::from_ptr(c2pa_sm_error_message(error))
            .to_str()
            .unwrap()
            .to_owned();
        c2pa_sm_error_free(error);
        Err((code, message))
    }
}
fn invalid(f: impl FnOnce(*mut *mut C2paSmError) -> c_int) {
    let mut e = ptr::null_mut();
    let c = f(&mut e);
    assert_eq!(c, C2PA_SM_ERR_INVALID_ARGUMENT);
    let (code, message) = result(c, e).unwrap_err();
    assert_eq!(code, C2PA_SM_ERR_INVALID_ARGUMENT);
    assert!(!message.is_empty());
}
pub(crate) struct Build(*mut C2paSmBuildSession);
impl Build {
    fn new(def: &str) -> Self {
        Self::with(def, "jpeg", &[TEST_SIGNER_CERT])
    }

    fn with(def: &str, format: &str, certs: &[&[u8]]) -> Self {
        let def = CString::new(def).unwrap();
        let format = CString::new(format).unwrap();
        let certs: Vec<_> = certs.iter().map(|c| C2paSmBuffer::borrowed(c)).collect();
        let mut s = ptr::null_mut();
        let mut e = ptr::null_mut();
        let c = unsafe {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                format.as_ptr(),
                c"es256".as_ptr(),
                certs.as_ptr(),
                certs.len(),
                &mut s,
                &mut e,
            )
        };
        result(c, e).unwrap();
        assert!(!s.is_null());
        Self(s)
    }

    fn advance(&self) -> AbiResult<(bool, usize)> {
        let mut done = -1;
        let mut count = usize::MAX;
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_session_advance(self.0, &mut done, &mut count, &mut e) };
        result(c, e)?;
        Ok((done != 0, count))
    }

    fn request(&self, i: usize) -> AbiResult<C2paSmBuildRequest> {
        let mut r = C2paSmBuildRequest::default();
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_session_request(self.0, i, &mut r, &mut e) };
        result(c, e)?;
        Ok(r)
    }

    fn fulfill(&self, r: C2paSmBuildReply) -> AbiResult<()> {
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_session_fulfill(self.0, &r, &mut e) };
        result(c, e)
    }

    fn acquire(&self, id: u64) -> AbiResult<Lease> {
        let mut raw = ptr::null_mut();
        let mut view = C2paSmMutableBytes::default();
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_read_acquire(self.0, id, &mut raw, &mut view, &mut e) };
        result(c, e)?;
        Ok(Lease { raw, view })
    }

    fn fulfill_read(&self, id: u64, completed: &mut Completed) -> AbiResult<()> {
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_fulfill_read(self.0, id, &mut completed.0, &mut e) };
        result(c, e)
    }

    fn first_read(&self) -> C2paSmBuildRequest {
        loop {
            let (done, n) = self.advance().unwrap();
            assert!(!done);
            assert!(n > 0);
            for i in 0..n {
                let r = self.request(i).unwrap();
                if r.kind == 0 {
                    return r;
                }
                assert_eq!(r.kind, 1);
                self.fulfill(C2paSmBuildReply {
                    kind: 1,
                    id: r.id,
                    value: SOURCE_JPEG.len() as u64,
                    ..Default::default()
                })
                .unwrap();
            }
        }
    }

    fn finish(&mut self) -> AbiResult<Report> {
        let mut r = ptr::null_mut();
        let mut e = ptr::null_mut();
        let s = std::mem::replace(&mut self.0, ptr::null_mut());
        let c = unsafe { c2pa_sm_build_session_finish(s, &mut r, &mut e) };
        result(c, e)?;
        Ok(Report(r))
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
    fn seal(&mut self, n: usize) -> AbiResult<Completed> {
        let mut r = ptr::null_mut();
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_read_seal(&mut self.raw, n, &mut r, &mut e) };
        result(c, e)?;
        Ok(Completed(r))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_read_buffer_free(&mut self.raw, ptr::null_mut()) },
            0
        )
    }
}
struct Completed(*mut C2paSmCompletedRead);
impl Drop for Completed {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_completed_read_free(&mut self.0, ptr::null_mut()) },
            0
        )
    }
}
struct WriteLease {
    raw: *mut C2paSmWriteBuffer,
    view: C2paSmBuffer,
}
impl WriteLease {
    fn acquire(b: &Build, id: u64) -> AbiResult<Self> {
        let mut raw = ptr::null_mut();
        let mut view = C2paSmBuffer::default();
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_build_write_acquire(b.0, id, &mut raw, &mut view, &mut e) };
        result(c, e)?;
        Ok(Self { raw, view })
    }
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_write_buffer_free(&mut self.raw, ptr::null_mut()) },
            0
        )
    }
}
#[derive(Debug)]
struct Report(*mut C2paSmSignReport);
impl Report {
    fn view(&self) -> C2paSmSignReportView {
        let mut v = C2paSmSignReportView::default();
        let mut e = ptr::null_mut();
        let c = unsafe { c2pa_sm_sign_report_view(self.0, &mut v, &mut e) };
        result(c, e).unwrap();
        v
    }
}
impl Drop for Report {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { c2pa_sm_sign_report_free(self.0, ptr::null_mut()) },
            0
        )
    }
}

#[derive(Default)]
struct Host {
    output: Vec<u8>,
    source: Option<Vec<u8>>,
    seen: [usize; 5],
    fail: Option<c_int>,
    timestamp: Vec<u8>,
    leased: bool,
    leased_writes: bool,
    max_reads: usize,
    write_leases: Vec<WriteLease>,
    source_buffer: Option<(usize, usize)>,
    shared_source_writes: usize,
}
impl Host {
    fn drive(&mut self, b: &mut Build) -> AbiResult<Report> {
        loop {
            let (done, n) = b.advance()?;
            if done {
                return b.finish();
            }
            assert!(n > 0, "host stalled");
            let batch = (0..n)
                .map(|i| {
                    let r = b.request(i).unwrap();
                    let data = if self.leased_writes && r.kind == 2 {
                        Vec::new()
                    } else {
                        unsafe { r.data.bytes().unwrap() }.to_vec()
                    };
                    (
                        r,
                        data,
                        unsafe { r.algorithm.bytes().unwrap() }.to_vec(),
                        unsafe { r.url.bytes().unwrap() }.to_vec(),
                    )
                })
                .collect::<Vec<_>>();
            self.max_reads = self
                .max_reads
                .max(batch.iter().filter(|(r, ..)| r.kind == 0).count());
            for (r, data, alg, url) in batch.into_iter().rev() {
                self.seen[r.kind as usize] += 1;
                let mut reply = C2paSmBuildReply {
                    id: r.id,
                    ..Default::default()
                };
                let payload = if self.fail == Some(r.kind) {
                    reply.kind = 5;
                    b"host unavailable".to_vec()
                } else {
                    match r.kind {
                        0 => {
                            let bytes = if r.stream == 0 {
                                self.source.as_deref().unwrap_or(SOURCE_JPEG)
                            } else {
                                assert_eq!(r.stream, 1);
                                &self.output
                            };
                            let bytes = &bytes[r.offset as usize..(r.offset + r.len) as usize];
                            if self.leased {
                                let mut lease = b.acquire(r.id)?;
                                if r.stream == 0 {
                                    self.source_buffer =
                                        Some((lease.view.data as usize, lease.view.len))
                                }
                                unsafe {
                                    std::slice::from_raw_parts_mut(lease.view.data, lease.view.len)
                                }
                                .copy_from_slice(bytes);
                                let mut completed = lease.seal(bytes.len())?;
                                b.fulfill_read(r.id, &mut completed)?;
                                assert!(completed.0.is_null());
                                continue;
                            }
                            reply.kind = 0;
                            bytes.to_vec()
                        }
                        1 => {
                            assert_eq!(r.stream, 0);
                            reply.kind = 1;
                            reply.value =
                                self.source.as_deref().unwrap_or(SOURCE_JPEG).len() as u64;
                            Vec::new()
                        }
                        2 => {
                            assert_eq!(r.stream, 1);
                            let lease = if self.leased_writes {
                                Some(WriteLease::acquire(b, r.id)?)
                            } else {
                                None
                            };
                            if let Some(lease) = &lease {
                                assert_eq!(lease.view.data, r.data.data);
                                assert_eq!(lease.view.len, r.data.len);
                            }
                            let bytes = lease
                                .as_ref()
                                .map_or(data.as_slice(), |l| unsafe { l.view.bytes().unwrap() });
                            if let (Some(l), Some((start, len))) = (&lease, self.source_buffer) {
                                if len >= 64 * 1024 && len == l.view.len {
                                    assert_eq!(l.view.data as usize, start);
                                    self.shared_source_writes += 1
                                }
                            }
                            let start = r.offset as usize;
                            self.output
                                .resize(self.output.len().max(start + bytes.len()), 0);
                            self.output[start..start + bytes.len()].copy_from_slice(bytes);
                            if let Some(lease) = lease {
                                self.write_leases.push(lease)
                            }
                            reply.kind = 2;
                            Vec::new()
                        }
                        3 => {
                            assert_eq!(alg, b"es256");
                            assert!(!data.is_empty());
                            let signer = c2pa_raw_crypto::signer_from_private_key(
                                TEST_SIGNER_KEY_PEM,
                                c2pa_raw_crypto::SigningAlg::Es256,
                            )
                            .unwrap();
                            reply.kind = 3;
                            let signature = signer.sign(&data).unwrap();
                            assert_eq!(signature.len(), 64);
                            signature
                        }
                        4 => {
                            assert_eq!(url, b"https://tsa.example/");
                            assert_eq!(data.first(), Some(&0x30));
                            reply.kind = 4;
                            self.timestamp.clone()
                        }
                        _ => panic!("unknown request"),
                    }
                };
                reply.data = C2paSmBuffer::borrowed(&payload);
                b.fulfill(reply)?;
            }
        }
    }
}
fn first_write(b: &Build) -> C2paSmBuildRequest {
    loop {
        let (done, n) = b.advance().unwrap();
        assert!(!done);
        assert!(n > 0);
        let batch = (0..n).map(|i| b.request(i).unwrap()).collect::<Vec<_>>();
        for r in batch {
            if r.kind == 2 {
                return r;
            }
            let mut reply = C2paSmBuildReply {
                id: r.id,
                ..Default::default()
            };
            if r.kind == 1 {
                reply.kind = 1;
                reply.value = SOURCE_JPEG.len() as u64
            } else {
                assert_eq!(r.kind, 0);
                reply.kind = 0;
                reply.data = C2paSmBuffer::borrowed(
                    &SOURCE_JPEG[r.offset as usize..(r.offset + r.len) as usize],
                )
            }
            b.fulfill(reply).unwrap();
        }
    }
}
fn timestamp_definition() -> String {
    BASELINE_DEFINITION.replace(
        "\"title\"",
        "\"tsa_url\":\"https://tsa.example/\", \"title\"",
    )
}

pub(crate) fn signed_asset(format: &str, source: &[u8], certs: &[&[u8]]) -> Vec<u8> {
    let mut b = Build::with(BASELINE_DEFINITION, format, certs);
    let mut h = Host {
        source: Some(source.to_vec()),
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = h.drive(&mut b).unwrap();
    let view = report.view();
    assert!(view.manifest.len > 0);
    if matches!(format, "tiff" | "dng") {
        assert_eq!(view.exclusion_count, 2);
        let ranges = unsafe { std::slice::from_raw_parts(view.exclusions, view.exclusion_count) };
        assert!(ranges[0].start + ranges[0].len < ranges[1].start);
    }
    h.output.clone()
}

#[test]
fn tiff_and_dng_build_without_the_reader_feature() {
    let source = [
        b'I', b'I', 42, 0, 8, 0, 0, 0, 1, 0, 0, 1, 4, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    for format in ["tiff", "dng"] {
        let output = signed_asset(format, &source, &[TEST_SIGNER_CERT]);
        assert_eq!(&output[..4], &source[..4]);
        assert!(output.len() > source.len());
    }
}

#[test]
fn signing_abi_round_trips_a_jpeg_through_the_existing_reader_as_trusted() {
    for leased in [false, true] {
        let mut b = Build::new(BASELINE_DEFINITION);
        let mut h = Host {
            leased,
            ..Default::default()
        };
        let report = h.drive(&mut b).unwrap();
        assert!(b.0.is_null());
        assert_eq!(h.seen[3..], [1, 0]);
        let v = report.view();
        let m = unsafe { v.manifest.bytes().unwrap() };
        assert!(!m.is_empty());
        assert!(h.output.windows(m.len()).any(|w| w == m));
        let exclusions = unsafe { std::slice::from_raw_parts(v.exclusions, v.exclusion_count) };
        assert!(!exclusions.is_empty());
        assert!(exclusions.iter().map(|r| r.len).sum::<u64>() >= m.len() as u64);
        assert!(exclusions
            .iter()
            .all(|r| r.len > 0 && r.start + r.len <= h.output.len() as u64));
        assert!(exclusions
            .windows(2)
            .all(|p| p[0].start + p[0].len <= p[1].start));
        #[cfg(feature = "read")]
        crate::reading::tests::assert_baseline("jpeg", &h.output, TEST_SIGNER_CERT);
    }
}
#[test]
#[cfg(feature = "read")]
fn invalid_hard_bindings_are_reported_without_parsing_json() {
    let mut bytes = signed_asset("jpeg", SOURCE_JPEG, &[TEST_SIGNER_CERT]);
    let i = bytes.len() - 3;
    bytes[i] ^= 1;
    crate::reading::tests::assert_validation(
        "jpeg",
        &bytes,
        None,
        crate::C2paSmValidationState::C2PA_SM_VALIDATION_INVALID,
    );
}
#[test]
fn wrong_and_duplicate_replies_leave_the_protocol_well_defined() {
    let b = Build::new(BASELINE_DEFINITION);
    assert_eq!(b.advance().unwrap(), (false, 1));
    let r = b.request(0).unwrap();
    assert_eq!(
        r.kind,
        C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int
    );
    let response = C2paSmBuildReply {
        kind: 1,
        id: r.id,
        value: SOURCE_JPEG.len() as u64,
        ..Default::default()
    };
    for r in [
        C2paSmBuildReply {
            kind: 2,
            ..response
        },
        C2paSmBuildReply {
            id: u64::MAX,
            ..response
        },
    ] {
        assert_eq!(b.fulfill(r).unwrap_err().0, 1);
    }
    b.fulfill(response).unwrap();
    assert_eq!(b.fulfill(response).unwrap_err().0, 1);
}
#[test]
fn advance_reports_only_new_requests_and_does_not_complete_while_waiting() {
    let b = Build::new(BASELINE_DEFINITION);
    assert_eq!(b.advance().unwrap(), (false, 1));
    assert_eq!(b.advance().unwrap(), (false, 0));
    assert!(b.request(0).is_err());
}
#[test]
fn finish_consumes_incomplete_sessions_and_rejects_stale_handles() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let handle = b.0;
    assert_eq!(b.finish().unwrap_err().0, 1);
    assert!(b.0.is_null());
    assert!(cimpl::checkout_exclusive(handle).is_err());
    assert_eq!(Build(handle).advance().unwrap_err().0, 1);
}
#[test]
fn host_failure_in_each_operation_fails_the_build_not_the_process() {
    for kind in 0..=4 {
        let mut b = Build::new(&timestamp_definition());
        let mut h = Host {
            fail: Some(kind),
            ..Default::default()
        };
        let (c, m) = h.drive(&mut b).unwrap_err();
        assert_eq!(c, 6);
        assert!(m.contains("host unavailable"), "{m}");
    }
}
#[test]
fn timestamp_response_mapping_embeds_a_granted_token() {
    let mut body = vec![0x30, 3, 2, 1, 0, 0x30, 0x82, 1, 0x2c];
    body.extend([0x42; 300]);
    let mut timestamp = vec![0x30, 0x82];
    timestamp.extend((body.len() as u16).to_be_bytes());
    timestamp.extend(body);
    let mut h = Host {
        timestamp,
        ..Default::default()
    };
    let mut b = Build::new(&timestamp_definition());
    let report = h.drive(&mut b).unwrap();
    assert_eq!(h.seen[4], 1);
    assert!(unsafe { report.view().manifest.bytes().unwrap() }
        .windows(300)
        .any(|w| w == [0x42; 300]));
}
#[test]
fn refused_and_malformed_timestamp_responses_fail_closed() {
    for timestamp in [vec![0x30, 5, 0x30, 3, 2, 1, 2], vec![0xff], vec![]] {
        let mut b = Build::new(&timestamp_definition());
        let mut h = Host {
            timestamp,
            ..Default::default()
        };
        assert_eq!(h.drive(&mut b).unwrap_err().0, 6);
    }
}
#[test]
fn constructor_validates_strings_certificates_and_output_pointers() {
    let def = CString::new(BASELINE_DEFINITION).unwrap();
    let cert = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    let mut s = ptr::null_mut();
    for (d, f, a) in [
        (ptr::null(), c"jpeg".as_ptr(), c"es256".as_ptr()),
        (def.as_ptr(), ptr::null(), c"es256".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), ptr::null()),
        (c"\xff".as_ptr(), c"jpeg".as_ptr(), c"es256".as_ptr()),
        (def.as_ptr(), c"\xff".as_ptr(), c"es256".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), c"\xff".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), c"bad".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), c"".as_ptr()),
        (c"{".as_ptr(), c"jpeg".as_ptr(), c"es256".as_ptr()),
        (c"".as_ptr(), c"jpeg".as_ptr(), c"es256".as_ptr()),
        (c"{}".as_ptr(), c"jpeg".as_ptr(), c"es256".as_ptr()),
    ] {
        s = ptr::dangling_mut();
        unsafe { invalid(|e| c2pa_sm_build_session_new(d, f, a, &cert, 1, &mut s, e)) };
        assert!(s.is_null());
    }
    unsafe {
        invalid(|e| {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                &cert,
                1,
                ptr::null_mut(),
                e,
            )
        });
        invalid(|e| {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                ptr::null(),
                1,
                &mut s,
                e,
            )
        });
        invalid(|e| {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                &cert,
                usize::MAX,
                &mut s,
                e,
            )
        });
        assert!(s.is_null());
        for (format, expected) in [
            (c"image/png", C2PA_SM_ERR_UNSUPPORTED_TYPE),
            (c"", C2PA_SM_ERR_UNSUPPORTED_TYPE),
        ] {
            s = ptr::dangling_mut();
            let mut e = ptr::null_mut();
            let code = c2pa_sm_build_session_new(
                def.as_ptr(),
                format.as_ptr(),
                c"es256".as_ptr(),
                &cert,
                1,
                &mut s,
                &mut e,
            );
            assert_eq!(result(code, e).unwrap_err().0, expected);
            assert!(s.is_null());
        }
        for (d, f, a, certs, count) in [
            (ptr::null(), ptr::null(), ptr::null(), ptr::null(), 0),
            (
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                ptr::null(),
                0,
            ),
        ] {
            s = ptr::dangling_mut();
            assert_eq!(
                c2pa_sm_build_session_new(d, f, a, certs, count, &mut s, ptr::null_mut()),
                C2PA_SM_ERR_INVALID_ARGUMENT
            );
            assert!(s.is_null());
        }
        assert_eq!(
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                &cert,
                1,
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                &cert,
                1,
                &mut s,
                ptr::null_mut(),
            ),
            C2PA_SM_OK
        );
        assert!(!s.is_null());
        assert_eq!(c2pa_sm_build_session_free(s, ptr::null_mut()), C2PA_SM_OK);
    }
}
#[test]
// C literals cannot represent the interior NULs and trailing bytes under test.
#[allow(clippy::manual_c_str_literals)]
fn constructor_strings_end_at_the_first_nul() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let mut nul_definition = definition.as_bytes_with_nul().to_vec();
    nul_definition.extend_from_slice(b"\xffnot json\0");
    let cert = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    for (d, f, a) in [
        (
            nul_definition.as_ptr().cast(),
            c"jpeg".as_ptr(),
            c"es256".as_ptr(),
        ),
        (
            definition.as_ptr(),
            b"jpeg\0\xffunsupported\0".as_ptr().cast(),
            c"es256".as_ptr(),
        ),
        (
            definition.as_ptr(),
            c"jpeg".as_ptr(),
            b"es256\0\xffunsupported\0".as_ptr().cast(),
        ),
    ] {
        let mut s = ptr::null_mut();
        let mut e = ptr::dangling_mut();
        let code = unsafe { c2pa_sm_build_session_new(d, f, a, &cert, 1, &mut s, &mut e) };
        result(code, e).unwrap();
        assert!(!s.is_null());
        assert_eq!(
            unsafe { c2pa_sm_build_session_free(s, ptr::null_mut()) },
            C2PA_SM_OK
        );
    }
    let mut malformed_definition = b"{\0".to_vec();
    malformed_definition.extend_from_slice(definition.as_bytes_with_nul());
    for (d, f, a, expected) in [
        (
            malformed_definition.as_ptr().cast(),
            c"jpeg".as_ptr(),
            c"es256".as_ptr(),
            C2PA_SM_ERR_INVALID_ARGUMENT,
        ),
        (
            definition.as_ptr(),
            b"image/png\0jpeg\0".as_ptr().cast(),
            c"es256".as_ptr(),
            C2PA_SM_ERR_UNSUPPORTED_TYPE,
        ),
        (
            definition.as_ptr(),
            c"jpeg".as_ptr(),
            b"bad\0es256\0".as_ptr().cast(),
            C2PA_SM_ERR_INVALID_ARGUMENT,
        ),
    ] {
        let mut s = ptr::dangling_mut();
        let mut e = ptr::null_mut();
        let code = unsafe { c2pa_sm_build_session_new(d, f, a, &cert, 1, &mut s, &mut e) };
        assert_eq!(result(code, e).unwrap_err().0, expected);
        assert!(s.is_null());
    }
}
#[test]
fn exported_operations_validate_handles_outputs_and_reply_buffers() {
    let b = Build::new(BASELINE_DEFINITION);
    let mut done = 9;
    let mut n = 9;
    let mut r = C2paSmBuildRequest::default();
    unsafe {
        invalid(|e| c2pa_sm_build_session_advance(b.0, ptr::null_mut(), &mut n, e));
        assert_eq!(n, 0);
        invalid(|e| c2pa_sm_build_session_advance(b.0, &mut done, ptr::null_mut(), e));
        assert_eq!(done, 0);
        invalid(|e| c2pa_sm_build_session_request(b.0, 0, ptr::null_mut(), e));
        invalid(|e| c2pa_sm_build_session_request(b.0, 99, &mut r, e));
        invalid(|e| c2pa_sm_build_session_fulfill(b.0, ptr::null(), e));
    }
    for kind in [0, 3, 4, 5] {
        for data in [
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
        ] {
            assert_eq!(
                b.fulfill(C2paSmBuildReply {
                    kind,
                    data,
                    ..Default::default()
                })
                .unwrap_err()
                .0,
                1
            );
            unsafe {
                invalid(|e| c2pa_sm_sign_report_view(ptr::null(), ptr::null_mut(), e));
                let mut view = C2paSmSignReportView {
                    exclusion_count: 99,
                    ..Default::default()
                };
                invalid(|e| c2pa_sm_sign_report_view(ptr::null(), &mut view, e));
                assert_eq!(view.exclusion_count, 0);
                invalid(|e| c2pa_sm_sign_report_view(b.0.cast(), &mut view, e));
                invalid(|e| c2pa_sm_sign_report_free(b.0.cast(), e));
                assert!(b.advance().is_ok());
                let mut e = ptr::dangling_mut();
                let code = c2pa_sm_build_session_free(ptr::null_mut(), &mut e);
                result(code, e).unwrap();
                e = ptr::dangling_mut();
                let code = c2pa_sm_sign_report_free(ptr::null_mut(), &mut e);
                result(code, e).unwrap();
            }
        }
    }
    assert_eq!(
        b.fulfill(C2paSmBuildReply {
            kind: 99,
            ..Default::default()
        })
        .unwrap_err()
        .0,
        1
    );
    assert_eq!(
        b.fulfill(C2paSmBuildReply {
            kind: 5,
            data: C2paSmBuffer::borrowed(&[0xff]),
            ..Default::default()
        })
        .unwrap_err()
        .0,
        1
    );
}
#[test]
fn failed_finish_with_null_output_consumes_the_session() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let handle = std::mem::replace(&mut b.0, ptr::null_mut());
    unsafe { invalid(|e| c2pa_sm_build_session_finish(handle, ptr::null_mut(), e)) };
    assert!(cimpl::checkout_exclusive(handle).is_err());
    unsafe { invalid(|e| c2pa_sm_build_session_free(handle, e)) };
}
#[test]
fn reports_are_independent_typed_handles_and_cannot_be_freed_twice() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let mut h = Host::default();
    let mut report = h.drive(&mut b).unwrap();
    assert!(report.view().manifest.len > 0);
    assert!(!report.view().manifest.data.is_null());
    assert!(b.0.is_null());
    let handle = report.0;
    unsafe {
        invalid(|e| c2pa_sm_build_session_free(handle.cast(), e));
        invalid(|e| c2pa_sm_sign_report_view(handle, ptr::null_mut(), e));
        assert_eq!(c2pa_sm_sign_report_free(handle, ptr::null_mut()), 0);
        report.0 = ptr::null_mut();
        invalid(|e| c2pa_sm_sign_report_free(handle, e));
        let mut out = C2paSmSignReportView::default();
        invalid(|e| c2pa_sm_sign_report_view(handle, &mut out, e));
    }
}
#[test]
fn handles_and_owned_errors_can_cross_threads() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<C2paSmBuildSession>();
    send::<C2paSmSignReport>();
    sync::<C2paSmSignReport>();
    send::<C2paSmError>();
    let mut b = Build::new(BASELINE_DEFINITION);
    assert_eq!(b.advance().unwrap(), (false, 1));
    let raw = std::mem::replace(&mut b.0, ptr::null_mut()) as usize;
    let report = std::thread::spawn(move || {
        let mut b = Build(raw as *mut C2paSmBuildSession);
        let request = b.request(0).unwrap();
        b.fulfill(C2paSmBuildReply {
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
            id: request.id,
            value: SOURCE_JPEG.len() as u64,
            ..Default::default()
        })
        .unwrap();
        let mut report = Host::default().drive(&mut b).unwrap();
        assert!(report.view().manifest.len > 0);
        std::mem::replace(&mut report.0, ptr::null_mut()) as usize
    })
    .join()
    .unwrap();
    let report = Report(report as *mut C2paSmSignReport);
    assert!(report.view().manifest.len > 0);
    let error = std::thread::spawn(|| {
        let mut build = Build::new(BASELINE_DEFINITION);
        let handle = std::mem::replace(&mut build.0, ptr::null_mut());
        let mut error = ptr::null_mut();
        let mut report = ptr::null_mut();
        assert_eq!(
            unsafe { c2pa_sm_build_session_finish(handle, &mut report, &mut error) },
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert!(report.is_null());
        error as usize
    })
    .join()
    .unwrap() as *mut C2paSmError;
    assert_eq!(
        result(C2PA_SM_ERR_INVALID_ARGUMENT, error).unwrap_err().1,
        "build is not complete"
    );
}
#[test]
fn all_request_views_map_fields_and_streams_without_borrowing_temporary_values() {
    let pending = [
        PendingRequest::Read {
            id: 1,
            stream: Stream::Source,
            start: 17,
            len: 19,
        },
        PendingRequest::Length {
            id: 2,
            stream: Stream::Output,
        },
        PendingRequest::Write {
            id: 3,
            stream: Stream::Output,
            offset: 11,
            bytes: vec![1, 2, 3].into(),
        },
        PendingRequest::Sign {
            id: 4,
            alg: "es256",
            data: vec![4, 5],
        },
        PendingRequest::Timestamp {
            id: 5,
            url: "https://tsa/".into(),
            request: vec![6, 7],
        },
    ];
    for (i, p) in pending.iter().enumerate() {
        let r = describe(p).unwrap();
        assert_eq!(r.kind, i as c_int);
        assert_eq!(r.id, (i + 1) as u64);
        match i {
            0 => assert_eq!((r.stream, r.offset, r.len), (0, 17, 19)),
            1 => assert_eq!(r.stream, 1),
            2 => {
                assert_eq!((r.stream, r.offset), (1, 11));
                assert_eq!(unsafe { r.data.bytes().unwrap() }, [1, 2, 3]);
            }
            3 => {
                assert_eq!(unsafe { r.algorithm.bytes().unwrap() }, b"es256");
                assert_eq!(unsafe { r.data.bytes().unwrap() }, [4, 5]);
            }
            4 => {
                assert_eq!(unsafe { r.url.bytes().unwrap() }, b"https://tsa/");
                assert_eq!(unsafe { r.data.bytes().unwrap() }, [6, 7]);
            }
            _ => unreachable!(),
        }
    }
    let output_read = PendingRequest::Read {
        id: 6,
        stream: Stream::Output,
        start: 40,
        len: 50,
    };
    let r = describe(&output_read).unwrap();
    assert_eq!(
        (r.id, r.kind, r.stream, r.offset, r.len),
        (
            6,
            C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int,
            1,
            40,
            50
        )
    );
}
#[test]
fn busy_handles_cannot_be_freed_or_consumed_by_another_operation() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let guard = cimpl::checkout_exclusive(b.0).unwrap();
    let mut out = ptr::null_mut();
    unsafe {
        invalid(|e| c2pa_sm_build_session_free(b.0, e));
        invalid(|e| c2pa_sm_build_session_finish(b.0, &mut out, e));
    }
    assert!(out.is_null());
    assert_eq!(b.advance().unwrap_err().0, C2PA_SM_ERR_INVALID_ARGUMENT);
    drop(guard);
    let report = Host::default().drive(&mut b).unwrap();
    let guard = cimpl::checkout_shared(report.0).unwrap();
    unsafe { invalid(|e| c2pa_sm_sign_report_free(report.0, e)) };
    drop(guard);
    assert!(report.view().manifest.len > 0);
}
#[test]
fn reply_kind_conversion_accepts_only_declared_variants() {
    for i in 0..=5 {
        assert_eq!(C2paSmBuildReplyKind::try_from(i).unwrap() as c_int, i)
    }
    for i in [-1, 6, 99, c_int::MIN, c_int::MAX] {
        assert_eq!(
            C2paSmBuildReplyKind::try_from(i),
            Err("unknown build reply kind")
        )
    }
}
#[test]
fn cimpl_handles_are_exclusive_typed_and_consumable() {
    let h = tracked(42_u64).unwrap();
    let mut guard = cimpl::checkout_exclusive(h).unwrap();
    assert_eq!(*guard, 42);
    *guard = 43;
    assert!(cimpl::checkout_exclusive(h).is_err());
    assert!(cimpl::checkout_exclusive(h.cast::<u32>()).is_err());
    assert!(cimpl::checkout_shared(h).is_err());
    assert!(cimpl::untrack_owned(h).is_err());
    drop(guard);
    assert!(cimpl::checkout_exclusive(h.cast::<u32>()).is_err());
    assert_eq!(cimpl::untrack_owned(h).unwrap(), 43);
    assert!(cimpl::checkout_exclusive(h).is_err());
    assert!(cimpl::untrack_owned(h).is_err());
    assert!(cimpl::checkout_exclusive::<u64>(ptr::null_mut()).is_err());
}
#[test]
fn read_lease_sealing_and_reply_conversion_preserve_the_allocation() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    let mut l = b.acquire(r.id).unwrap();
    assert_eq!(l.view.len as u64, r.len);
    let p = l.view.data;
    unsafe { std::slice::from_raw_parts_mut(p, l.view.len) }.fill(42);
    let c = l.seal(l.view.len).unwrap();
    assert!(l.raw.is_null());
    let mut checked = cimpl::checkout_exclusive(c.0).unwrap();
    let buffer = checked.buffer.as_mut().unwrap();
    assert_eq!(buffer.bytes.as_ptr(), p);
    let Reply::Bytes(bytes) = buffer.take_reply() else {
        panic!("not bytes")
    };
    assert_eq!(bytes.as_ptr(), p);
    assert!(bytes.iter().all(|b| *b == 42));
}
#[test]
fn read_leases_validate_counts_ids_and_sessions_without_consuming_on_error() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    let other = Build::new(BASELINE_DEFINITION);
    let other_r = other.first_read();
    let mut l = b.acquire(r.id).unwrap();
    let h = l.raw;
    assert!(b.acquire(r.id).is_err());
    assert!(b.acquire(u64::MAX).is_err());
    for n in [l.view.len + 1, l.view.len - 1] {
        assert!(l.seal(n).is_err());
        assert_eq!(l.raw, h);
    }
    assert!(!b.advance().unwrap().0);
    unsafe { std::slice::from_raw_parts_mut(l.view.data, l.view.len) }
        .copy_from_slice(&SOURCE_JPEG[r.offset as usize..(r.offset + r.len) as usize]);
    assert!(b
        .fulfill(C2paSmBuildReply {
            kind: 0,
            id: r.id,
            data: C2paSmBuffer::borrowed(&vec![0; l.view.len]),
            ..Default::default()
        })
        .is_err());
    let mut c = l.seal(l.view.len).unwrap();
    let h = c.0;
    assert!(other.fulfill_read(other_r.id, &mut c).is_err());
    assert!(b.fulfill_read(u64::MAX, &mut c).is_err());
    assert_eq!(c.0, h);
    b.fulfill_read(r.id, &mut c).unwrap();
    assert!(c.0.is_null());
    assert!(b.fulfill_read(r.id, &mut c).is_err());
    assert!(b.acquire(r.id).is_err());
}
#[test]
fn writable_and_completed_leases_survive_their_session() {
    let mut l = {
        let b = Build::new(BASELINE_DEFINITION);
        b.acquire(b.first_read().id).unwrap()
    };
    unsafe { std::slice::from_raw_parts_mut(l.view.data, l.view.len) }.fill(7);
    let c = l.seal(l.view.len).unwrap();
    assert!(cimpl::checkout_exclusive(c.0)
        .unwrap()
        .buffer
        .as_ref()
        .unwrap()
        .bytes
        .iter()
        .all(|b| *b == 7));
}
#[test]
fn abandoning_or_failing_a_read_does_not_reissue_its_lease() {
    for seal in [false, true] {
        let b = Build::new(BASELINE_DEFINITION);
        let r = b.first_read();
        let mut l = b.acquire(r.id).unwrap();
        let mut c = if seal {
            Some(l.seal(l.view.len).unwrap())
        } else {
            None
        };
        drop(l);
        assert!(b.acquire(r.id).is_err());
        b.fulfill(C2paSmBuildReply {
            kind: 5,
            id: r.id,
            data: C2paSmBuffer::borrowed(b"cancelled"),
            ..Default::default()
        })
        .unwrap();
        if let Some(c) = &mut c {
            let h = c.0;
            assert!(b.fulfill_read(r.id, c).is_err());
            assert_eq!(c.0, h);
        }
        assert!(b.advance().is_err());
    }
}
#[test]
fn leased_hash_reads_complete_out_of_order_for_a_large_asset() {
    let mut source = SOURCE_JPEG.to_vec();
    source.resize(512 * 1024, 0);
    let mut h = Host {
        source: Some(source),
        leased: true,
        ..Default::default()
    };
    let mut b = Build::new(BASELINE_DEFINITION);
    assert!(h.drive(&mut b).unwrap().view().manifest.len > 0);
    assert!(h.max_reads > 1);
    #[cfg(feature = "read")]
    crate::reading::tests::assert_validation(
        "jpeg",
        &h.output,
        None,
        crate::C2paSmValidationState::C2PA_SM_VALIDATION_VALID,
    );
}
#[test]
fn read_lease_abi_rejects_invalid_outputs_busy_and_wrong_type_handles() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    let mut raw = ptr::null_mut();
    let mut v = C2paSmMutableBytes::default();
    let mut c = ptr::null_mut();
    unsafe {
        invalid(|e| c2pa_sm_build_read_acquire(b.0, r.id, ptr::null_mut(), &mut v, e));
        invalid(|e| c2pa_sm_build_read_acquire(b.0, r.id, &mut raw, ptr::null_mut(), e));
        invalid(|e| c2pa_sm_read_seal(ptr::null_mut(), 0, &mut c, e));
        invalid(|e| c2pa_sm_read_seal(&mut raw, 0, ptr::null_mut(), e));
        invalid(|e| c2pa_sm_build_fulfill_read(b.0, r.id, ptr::null_mut(), e));
        invalid(|e| c2pa_sm_read_buffer_free(ptr::null_mut(), e));
        invalid(|e| c2pa_sm_completed_read_free(ptr::null_mut(), e));
        let mut wrong = b.0.cast();
        invalid(|e| c2pa_sm_read_buffer_free(&mut wrong, e));
        assert_eq!(wrong, b.0.cast());
    }
    let mut l = b.acquire(r.id).unwrap();
    let guard = cimpl::checkout_exclusive(l.raw).unwrap();
    assert!(l.seal(l.view.len).is_err());
    unsafe { invalid(|e| c2pa_sm_read_buffer_free(&mut l.raw, e)) };
    drop(guard);
    let mut c = l.seal(l.view.len).unwrap();
    let guard = cimpl::checkout_exclusive(c.0).unwrap();
    assert!(b.fulfill_read(r.id, &mut c).is_err());
    unsafe { invalid(|e| c2pa_sm_completed_read_free(&mut c.0, e)) };
    drop(guard);
}
#[test]
fn read_allocation_overflow_is_reported_without_leasing_the_request() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    cimpl::checkout_exclusive(b.0)
        .unwrap()
        .reads
        .get_mut(&r.id)
        .unwrap()
        .0 = u64::MAX;
    assert!(b.acquire(r.id).is_err());
    assert!(cimpl::checkout_exclusive(b.0).unwrap().reads[&r.id]
        .1
        .is_none());
}
#[test]
fn write_leases_share_storage_and_survive_acknowledgment_and_session_destruction() {
    let (l, another, expected) = {
        let b = Build::new(BASELINE_DEFINITION);
        let r = first_write(&b);
        let l = WriteLease::acquire(&b, r.id).unwrap();
        assert_eq!(l.view.data, r.data.data);
        let expected = unsafe { l.view.bytes().unwrap() }.to_vec();
        assert!(!b.advance().unwrap().0);
        let another = WriteLease::acquire(&b, r.id).unwrap();
        assert_eq!(l.view.data, another.view.data);
        assert!(b
            .fulfill(C2paSmBuildReply {
                kind: 1,
                id: r.id,
                ..Default::default()
            })
            .is_err());
        assert!(WriteLease::acquire(&b, r.id).is_ok());
        b.fulfill(C2paSmBuildReply {
            kind: 2,
            id: r.id,
            ..Default::default()
        })
        .unwrap();
        assert!(WriteLease::acquire(&b, r.id).is_err());
        b.advance().unwrap();
        (l, another, expected)
    };
    assert_eq!(unsafe { l.view.bytes().unwrap() }, expected);
    drop(l);
    assert_eq!(unsafe { another.view.bytes().unwrap() }, expected);
}
#[test]
fn large_source_read_storage_is_reused_for_writes_through_the_bridge_and_abi() {
    let mut source = SOURCE_JPEG.to_vec();
    source.resize(2 * 1024 * 1024 + 17, 0);
    let mut h = Host {
        source: Some(source),
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let mut b = Build::new(BASELINE_DEFINITION);
    assert!(h.drive(&mut b).unwrap().view().manifest.len > 0);
    assert!(b.0.is_null());
    assert!(h.shared_source_writes >= 2);
    for l in &h.write_leases {
        let checked = cimpl::checkout_shared(l.raw).unwrap();
        assert_eq!(checked._bytes.as_ptr(), l.view.data);
        assert_eq!(checked._bytes.as_ref(), unsafe { l.view.bytes().unwrap() });
    }
    #[cfg(feature = "read")]
    crate::reading::tests::assert_validation(
        "jpeg",
        &h.output,
        None,
        crate::C2paSmValidationState::C2PA_SM_VALIDATION_VALID,
    );
}
#[test]
fn write_acquisition_and_release_validate_outputs_types_and_borrows() {
    let b = Build::new(BASELINE_DEFINITION);
    assert!(WriteLease::acquire(&b, u64::MAX).is_err());
    let read = b.first_read();
    assert!(WriteLease::acquire(&b, read.id).is_err());
    let other = Build::new(BASELINE_DEFINITION);
    let r = first_write(&other);
    let mut raw = ptr::null_mut();
    let mut v = C2paSmBuffer::default();
    unsafe {
        invalid(|e| c2pa_sm_build_write_acquire(other.0, r.id, ptr::null_mut(), &mut v, e));
        invalid(|e| c2pa_sm_build_write_acquire(other.0, r.id, &mut raw, ptr::null_mut(), e));
        invalid(|e| c2pa_sm_build_write_acquire(ptr::null_mut(), r.id, &mut raw, &mut v, e));
        invalid(|e| c2pa_sm_write_buffer_free(ptr::null_mut(), e));
        let mut wrong = other.0.cast();
        invalid(|e| c2pa_sm_write_buffer_free(&mut wrong, e));
        assert_eq!(wrong, other.0.cast());
        assert_eq!(c2pa_sm_write_buffer_free(&mut raw, ptr::null_mut()), 0);
    }
    let guard = cimpl::checkout_exclusive(other.0).unwrap();
    assert!(WriteLease::acquire(&other, r.id).is_err());
    drop(guard);
    let mut l = WriteLease::acquire(&other, r.id).unwrap();
    let h = l.raw;
    let guard = cimpl::checkout_shared(h).unwrap();
    unsafe { invalid(|e| c2pa_sm_write_buffer_free(&mut l.raw, e)) };
    assert_eq!(l.raw, h);
    drop(guard);
    assert_eq!(
        unsafe { c2pa_sm_write_buffer_free(&mut l.raw, ptr::null_mut()) },
        0
    );
    assert!(l.raw.is_null());
    let mut stale = h;
    unsafe { invalid(|e| c2pa_sm_write_buffer_free(&mut stale, e)) };
    assert_eq!(stale, h);
}
#[test]
fn failed_writes_release_session_ownership_without_revoking_host_storage() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = first_write(&b);
    let l = WriteLease::acquire(&b, r.id).unwrap();
    let expected = unsafe { l.view.bytes().unwrap() }.to_vec();
    b.fulfill(C2paSmBuildReply {
        kind: 5,
        id: r.id,
        data: C2paSmBuffer::borrowed(b"failed"),
        ..Default::default()
    })
    .unwrap();
    assert!(WriteLease::acquire(&b, r.id).is_err());
    assert!(b.advance().is_err());
    drop(b);
    assert_eq!(unsafe { l.view.bytes().unwrap() }, expected);
}

mod consolidation;
