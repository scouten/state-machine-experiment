// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! A host for the exported C ABI. It uses only exported functions and types, as
//! a C caller would, so these tests exercise the same surface a C host sees.
#![allow(clippy::unwrap_used, clippy::panic, unsafe_code)]

use std::{
    ffi::{c_char, c_int, CStr, CString},
    ptr,
};

use base64::Engine;
use contentauth_c2pa_sign_baseline::{fixtures::*, Definition, BASELINE_DEFINITION};

use crate::*;

/// The wall clock the host reports to the reader.
const NOW: i64 = 1_800_000_000;

fn text(s: *const c_char) -> String {
    assert!(!s.is_null());
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().into()
}

/// Fails the test with the owned error's code and message, or checks there is none.
fn check(code: c_int, error: *mut C2paSmError) {
    if code == C2PA_SM_OK {
        assert!(error.is_null());
        return;
    }
    assert!(!error.is_null());
    let failure = unsafe {
        (
            c2pa_sm_error_code(error),
            text(c2pa_sm_error_message(error)),
        )
    };
    unsafe { c2pa_sm_error_free(error) };
    panic!("{failure:?}");
}

fn owned(buffer: C2paSmBuffer) -> Vec<u8> {
    if buffer.len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
}

/// What a completed read reports.
pub struct Read {
    pub json: String,
    pub state: C2paSmValidationState,
}

/// Reads `asset`, answering any OCSP request with `ocsp(url, body)`.
pub fn read(
    format: &str,
    settings: Option<&str>,
    asset: &[u8],
    mut ocsp: impl FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
) -> Read {
    let format = CString::new(format).unwrap();
    let settings = settings.map(|s| CString::new(s).unwrap());
    let mut session = ptr::null_mut();
    let mut error = ptr::null_mut();
    let code = unsafe {
        c2pa_sm_session_new(
            format.as_ptr(),
            settings.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            &mut session,
            &mut error,
        )
    };
    check(code, error);

    let fulfill = |kind: c_int, id: u64, value: i64, data: &[u8]| {
        let reply = C2paSmReply {
            kind,
            id,
            value,
            data: data.as_ptr(),
            data_len: data.len(),
        };
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_session_fulfill(session, &reply, &mut error) };
        (code, error)
    };

    loop {
        let mut done = -1;
        let mut error = ptr::null_mut();
        check(
            unsafe { c2pa_sm_session_advance(session, &mut done, &mut error) },
            error,
        );
        if done == 1 {
            break;
        }
        let count = unsafe { c2pa_sm_session_request_count(session) };
        assert!(count > 0, "host stalled");

        // Request views are borrowed until the next mutation: copy the batch first.
        let batch: Vec<_> = (0..count)
            .map(|index| {
                let mut request = std::mem::MaybeUninit::uninit();
                assert!(unsafe { c2pa_sm_session_request(session, index, request.as_mut_ptr()) });
                let request = unsafe { request.assume_init() };
                let (url, body) = if request.kind == C2PA_SM_REQUEST_OCSP {
                    let url = unsafe {
                        std::slice::from_raw_parts(request.url.cast::<u8>(), request.url_len)
                    };
                    let body =
                        unsafe { std::slice::from_raw_parts(request.body, request.body_len) };
                    (std::str::from_utf8(url).unwrap().to_owned(), body.to_vec())
                } else {
                    Default::default()
                };
                (request, url, body)
            })
            .collect();

        for (request, url, body) in batch {
            let (code, error) = match request.kind {
                C2PA_SM_REQUEST_READ => fulfill(
                    C2PA_SM_REPLY_BYTES,
                    request.id,
                    0,
                    &asset[request.start as usize..(request.start + request.len) as usize],
                ),
                C2PA_SM_REQUEST_LENGTH => {
                    fulfill(C2PA_SM_REPLY_LENGTH, request.id, asset.len() as i64, &[])
                }
                C2PA_SM_REQUEST_TIME => fulfill(C2PA_SM_REPLY_TIME, request.id, NOW, &[]),
                C2PA_SM_REQUEST_OCSP => {
                    // A reply of the wrong kind is refused and the request stays outstanding.
                    let (wrong, error) = fulfill(C2PA_SM_REPLY_TIME, request.id, NOW, &[]);
                    assert_eq!(wrong, C2PA_SM_ERR_READ);
                    unsafe { c2pa_sm_error_free(error) };
                    match ocsp(&url, &body) {
                        Ok(response) => fulfill(C2PA_SM_REPLY_OCSP, request.id, 0, &response),
                        Err(message) => {
                            fulfill(C2PA_SM_REPLY_FAILED, request.id, 0, message.as_bytes())
                        }
                    }
                }
                other => panic!("unknown request kind {other}"),
            };
            check(code, error);
        }
    }

    let mut reader = ptr::null_mut();
    let mut error = ptr::null_mut();
    check(
        unsafe { c2pa_sm_session_finish(session, &mut reader, &mut error) },
        error,
    );
    assert!(!reader.is_null());
    unsafe {
        let raw = c2pa_sm_reader_json(reader);
        let json = text(raw);
        c2pa_sm_string_free(raw);
        let state = c2pa_sm_reader_validation_state(reader);
        let label = c2pa_sm_reader_active_label(reader);
        assert!(json.contains(&text(label)));
        c2pa_sm_string_free(label);
        assert!(c2pa_sm_reader_is_embedded(reader));
        c2pa_sm_reader_free(reader);
        Read { json, state }
    }
}

/// Reads `asset` against `anchor` and checks the baseline manifest field by field.
pub fn assert_baseline(format: &str, asset: &[u8], anchor: &[u8]) {
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        base64::engine::general_purpose::STANDARD.encode(anchor)
    );
    let settings = format!(r#"{{"trust":{{"trust_anchors":{pem:?}}}}}"#);
    let Read { json, state } = read(format, Some(&settings), asset, |_, _| {
        Err("offline".to_owned())
    });
    assert_eq!(state, C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED);

    let definition = Definition::from_json(BASELINE_DEFINITION).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["active_manifest"], definition.label);
    assert_eq!(json["validation_state"], "Trusted");
    let manifests = json["manifests"].as_object().unwrap();
    assert_eq!(manifests.len(), 1);
    assert_eq!(
        &manifests[&definition.label],
        &serde_json::json!({
            "label": definition.label,
            "title": definition.title,
            "instance_id": definition.instance_id,
            "claim_generator_info": [{
                "name": definition.claim_generator_info[0].name,
                "version": definition.claim_generator_info[0].version,
                "specVersion": "2.4.0"
            }],
            "claim_version": 2,
            "assertions": ["c2pa.actions.v2", "c2pa.hash.data"]
        })
    );
}

/// What a completed build reports.
pub struct Signed {
    pub asset: Vec<u8>,
    /// Hard-binding exclusions as `(start, len)`.
    pub exclusions: Vec<(u64, u64)>,
}

/// Signs `source` with the baseline definition and the test ES256 key.
pub fn sign(format: &str, source: &[u8], certificates: &[&[u8]]) -> Signed {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let format = CString::new(format).unwrap();
    let certificates: Vec<_> = certificates
        .iter()
        .map(|c| C2paSmBuffer {
            data: c.as_ptr(),
            len: c.len(),
        })
        .collect();
    let mut session = ptr::null_mut();
    let mut error = ptr::null_mut();
    let code = unsafe {
        c2pa_sm_build_session_new(
            definition.as_ptr(),
            format.as_ptr(),
            c"es256".as_ptr(),
            certificates.as_ptr(),
            certificates.len(),
            &mut session,
            &mut error,
        )
    };
    check(code, error);

    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .unwrap();
    let mut output = Vec::new();
    loop {
        let mut done = -1;
        let mut count = usize::MAX;
        let mut error = ptr::null_mut();
        check(
            unsafe { c2pa_sm_build_session_advance(session, &mut done, &mut count, &mut error) },
            error,
        );
        if done != 0 {
            break;
        }
        assert!(count > 0, "host stalled");

        // Request views are borrowed until the next mutation: copy the batch first.
        let batch: Vec<_> = (0..count)
            .map(|index| {
                let mut request = C2paSmBuildRequest::default();
                let mut error = ptr::null_mut();
                check(
                    unsafe {
                        c2pa_sm_build_session_request(session, index, &mut request, &mut error)
                    },
                    error,
                );
                (request, owned(request.data))
            })
            .collect();

        for (request, data) in batch {
            let mut reply = C2paSmBuildReply {
                id: request.id,
                ..Default::default()
            };
            let payload = if request.kind
                == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int
            {
                let stream = if request.stream == C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int {
                    source
                } else {
                    &output
                };
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int;
                stream[request.offset as usize..(request.offset + request.len) as usize].to_vec()
            } else if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int
            {
                assert_eq!(
                    request.stream,
                    C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int
                );
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int;
                reply.value = source.len() as u64;
                Vec::new()
            } else if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int {
                assert_eq!(
                    request.stream,
                    C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int
                );
                let start = request.offset as usize;
                output.resize(output.len().max(start + data.len()), 0);
                output[start..start + data.len()].copy_from_slice(&data);
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_WRITTEN as c_int;
                Vec::new()
            } else if request.kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_SIGN as c_int {
                reply.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_SIGNATURE as c_int;
                signer.sign(&data).unwrap()
            } else {
                panic!("unexpected request kind {}", request.kind);
            };
            reply.data = C2paSmBuffer {
                data: payload.as_ptr(),
                len: payload.len(),
            };
            let mut error = ptr::null_mut();
            check(
                unsafe { c2pa_sm_build_session_fulfill(session, &reply, &mut error) },
                error,
            );
        }
    }

    let mut report = ptr::null_mut();
    let mut error = ptr::null_mut();
    check(
        unsafe { c2pa_sm_build_session_finish(session, &mut report, &mut error) },
        error,
    );
    let mut view = C2paSmSignReportView::default();
    check(
        unsafe { c2pa_sm_sign_report_view(report, &mut view, &mut error) },
        error,
    );
    assert!(view.manifest.len > 0);
    let exclusions = if view.exclusion_count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(view.exclusions, view.exclusion_count) }
            .iter()
            .map(|range| (range.start, range.len))
            .collect()
    };
    assert_eq!(
        unsafe { c2pa_sm_sign_report_free(report, ptr::null_mut()) },
        C2PA_SM_OK
    );
    Signed {
        asset: output,
        exclusions,
    }
}
