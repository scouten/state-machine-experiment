// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use base64::Engine as _;

use super::*;

const OCSP_ROOT: &[u8] =
    include_bytes!("../../../contentauth-c2pa-c-api/tests/fixtures/ocsp-root.der");
const OCSP_LEAF: &[u8] =
    include_bytes!("../../../contentauth-c2pa-c-api/tests/fixtures/ocsp-leaf.der");

fn advance(session: *mut C2paSmSession) -> Result<bool, (c_int, String, String)> {
    let mut done = -1;
    let mut err = ptr::null_mut();
    // SAFETY: callers supply a live session and both outputs are writable.
    let status = unsafe { c2pa_sm_session_advance(session, &mut done, &mut err) };
    if status == C2PA_SM_OK {
        assert!(err.is_null());
        assert!(done == 0 || done == 1);
        Ok(done == 1)
    } else {
        let error = take_error(err);
        assert_eq!(status, error.0);
        Err(error)
    }
}

#[test]
fn constructor_rejects_invalid_settings_types_and_non_utf8_settings() {
    let format = cstr("jpeg");
    let invalid_utf8 = CString::new(vec![0xff]).unwrap();
    for settings in [
        cstr(r#"{"verify":{"ocsp_fetch":"yes"}}"#),
        invalid_utf8,
        cstr(""),
        cstr("  "),
    ] {
        let mut session = ptr::dangling_mut::<C2paSmSession>();
        let mut err = ptr::null_mut();
        // SAFETY: valid C strings, though their contents are intentionally invalid.
        let status = unsafe {
            c2pa_sm_session_new(format.as_ptr(), settings.as_ptr(), &mut session, &mut err)
        };
        assert_eq!(status, C2PA_SM_ERR_INVALID_ARGUMENT);
        assert!(session.is_null());
        let (code, message, name) = take_error(err);
        assert_eq!(code, status);
        assert!(!message.is_empty());
        assert!(!name.is_empty());
    }
    for settings in [None, Some("{}")] {
        let session = new_session("jpg", settings);
        assert_eq!(
            drive(session, &[0xff, 0xd8, 0xff, 0xd9]),
            (C2PA_SM_OK, ptr::null_mut(), ptr::null_mut())
        );
    }
}

#[test]
fn tiff_and_registry_aliases_are_supported() {
    for format in ["image/tiff", "tiff", "tif", "dng", "image/jpg"] {
        let format = cstr(format);
        let mut session = ptr::null_mut();
        let mut err = ptr::null_mut();
        // SAFETY: valid strings and output slots; construction does not read an asset.
        assert_eq!(
            unsafe { c2pa_sm_session_new(format.as_ptr(), ptr::null(), &mut session, &mut err) },
            C2PA_SM_OK
        );
        assert!(!session.is_null());
        assert!(err.is_null());
        unsafe { c2pa_sm_session_free(session) };
    }
}

#[test]
fn all_reply_variants_reject_null_sessions_and_unknown_ids() {
    let session = new_session("jpeg", None);
    for kind in [
        C2PA_SM_REPLY_BYTES,
        C2PA_SM_REPLY_LENGTH,
        C2PA_SM_REPLY_TIME,
        C2PA_SM_REPLY_OCSP,
        C2PA_SM_REPLY_FAILED,
    ] {
        let r = reply(kind, u64::MAX, 0, b"host failed");
        let mut err = ptr::null_mut();
        // SAFETY: null is intentionally tested; other pointers are valid.
        assert_eq!(
            unsafe { c2pa_sm_session_fulfill(ptr::null_mut(), &r, &mut err) },
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(take_error(err).1, "session is null");
        let (code, message) = fulfill(session, &r).unwrap_err();
        assert_eq!(code, C2PA_SM_ERR_INVALID_ARGUMENT);
        assert!(message.contains("no outstanding request"), "{message}");
        // SAFETY: omitting the optional error slot must not change the result.
        assert_eq!(
            unsafe { c2pa_sm_session_fulfill(session, &r, ptr::null_mut()) },
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
    }
    assert_eq!(
        drive(session, &[0xff, 0xd8, 0xff, 0xd9]),
        (C2PA_SM_OK, ptr::null_mut(), ptr::null_mut())
    );
}

#[test]
fn invalid_advance_output_preserves_the_session() {
    let session = new_session("jpeg", None);
    let mut err = ptr::null_mut();
    // SAFETY: null output is intentional; this does not consume the session.
    assert_eq!(
        unsafe { c2pa_sm_session_advance(session, ptr::null_mut(), &mut err) },
        C2PA_SM_ERR_INVALID_ARGUMENT
    );
    assert_eq!(take_error(err).1, "out_done is null");
    assert_eq!(
        drive(session, &[0xff, 0xd8, 0xff, 0xd9]),
        (C2PA_SM_OK, ptr::null_mut(), ptr::null_mut())
    );
}

#[test]
fn invalid_payloads_preserve_requests_and_host_failure_is_terminal() {
    let session = new_session("jpeg", None);
    assert!(!advance(session).unwrap());
    let first = requests(session)[0];
    let wrong_kind = if first.kind == C2PA_SM_REQUEST_TIME {
        C2PA_SM_REPLY_LENGTH
    } else {
        C2PA_SM_REPLY_TIME
    };
    for (r, expected) in [
        (reply(wrong_kind, first.id, 0, &[]), C2PA_SM_ERR_READ),
        (
            reply(C2PA_SM_REPLY_LENGTH, first.id, -1, &[]),
            C2PA_SM_ERR_INVALID_ARGUMENT,
        ),
        (
            reply(C2PA_SM_REPLY_OCSP, first.id, 0, &[]),
            C2PA_SM_ERR_READ,
        ),
        (reply(99, first.id, 0, &[]), C2PA_SM_ERR_INVALID_ARGUMENT),
    ] {
        assert_eq!(fulfill(session, &r).unwrap_err().0, expected);
    }
    // Unlike the old C API, failure text is length-delimited and decoded lossily.
    fulfill(
        session,
        &reply(C2PA_SM_REPLY_FAILED, first.id, 0, b"read cancelled \xff"),
    )
    .unwrap();
    let (code, message, name) = advance(session).unwrap_err();
    assert_eq!(code, C2PA_SM_ERR_READ);
    assert!(message.contains("read cancelled \u{fffd}"), "{message}");
    assert!(name.starts_with("C2pa(Read("), "{name}");
    assert_eq!(advance(session).unwrap_err().0, C2PA_SM_ERR_READ);
    let mut reader = ptr::null_mut();
    let mut err = ptr::null_mut();
    // SAFETY: finish consumes the failed session, even when it returns an error.
    assert_eq!(
        unsafe { c2pa_sm_session_finish(session, &mut reader, &mut err) },
        C2PA_SM_ERR_READ
    );
    assert!(reader.is_null());
    assert_eq!(take_error(err).0, C2PA_SM_ERR_READ);
}

#[test]
fn empty_byte_payloads_are_accepted_then_fail_reading() {
    for (data, data_len) in [(ptr::null(), 0), ([0_u8].as_ptr(), 0), (ptr::null(), 1)] {
        let session = new_session("jpeg", None);
        let pending = loop {
            assert!(!advance(session).unwrap());
            let pending = requests(session);
            if pending.iter().any(|r| r.kind == C2PA_SM_REQUEST_READ) {
                break pending;
            }
            for request in pending {
                answer(session, &request, C_JPG);
            }
        };
        let read = pending
            .iter()
            .find(|r| r.kind == C2PA_SM_REQUEST_READ)
            .unwrap();
        // Unlike the old C API, null or zero length becomes an empty byte reply.
        let r = C2paSmReply {
            data,
            data_len,
            ..reply(C2PA_SM_REPLY_BYTES, read.id, 0, &[])
        };
        fulfill(session, &r).unwrap();
        for request in pending.iter().filter(|request| request.id != read.id) {
            answer(session, request, C_JPG);
        }
        let (status, reader, err) = drive(session, C_JPG);
        assert_eq!(status, C2PA_SM_ERR_READ);
        assert!(reader.is_null());
        assert_eq!(take_error(err).0, C2PA_SM_ERR_READ);
    }
}

#[test]
fn finish_consumes_incomplete_sessions_and_clears_reader_output() {
    for awaiting in [false, true] {
        let session = new_session("jpeg", None);
        if awaiting {
            assert!(!advance(session).unwrap());
        }
        let mut reader = std::ptr::dangling_mut::<C2paSmReader>();
        let mut err = ptr::null_mut();
        // SAFETY: the sentinel is only an output value, never dereferenced.
        let status = unsafe { c2pa_sm_session_finish(session, &mut reader, &mut err) };
        assert_eq!(status, C2PA_SM_ERR_READ);
        assert!(reader.is_null());
        assert!(!take_error(err).1.is_empty());
        // No second finish/free: these reader handles are raw owning pointers,
        // not the old C API's tracked handles.
    }
}

#[test]
fn advance_reports_only_new_requests_until_replies_arrive() {
    let session = new_session("jpeg", None);
    assert!(!advance(session).unwrap());
    let pending = requests(session);
    assert!(!pending.is_empty());
    for _ in 0..2 {
        assert!(!advance(session).unwrap());
        assert!(requests(session).is_empty());
    }
    let mut untouched = C2paSmRequest {
        kind: 99,
        id: u64::MAX,
        start: 17,
        len: 19,
        url: ptr::null(),
        url_len: 0,
        body: ptr::null(),
        body_len: 0,
    };
    // SAFETY: live session and writable output; failed lookup leaves it alone.
    assert!(!unsafe { c2pa_sm_session_request(session, usize::MAX, &mut untouched) });
    assert_eq!(
        (untouched.kind, untouched.id, untouched.start, untouched.len),
        (99, u64::MAX, 17, 19)
    );
    for request in pending.into_iter().rev() {
        answer(session, &request, C_JPG);
    }
    let (status, reader, err) = drive(session, C_JPG);
    assert_eq!((status, err), (C2PA_SM_OK, ptr::null_mut()));
    // SAFETY: the successful read yielded an owned reader.
    unsafe { c2pa_sm_reader_free(reader) };
}

#[test]
fn owned_reader_strings_outlive_the_reader_and_do_not_alias() {
    let (status, reader, err) = drive(new_session("jpeg", None), C_JPG);
    assert_eq!((status, err), (C2PA_SM_OK, ptr::null_mut()));
    // SAFETY: strings are separate owned allocations, not borrows of the reader.
    unsafe {
        let json = c2pa_sm_reader_json(reader);
        let another_json = c2pa_sm_reader_json(reader);
        let label = c2pa_sm_reader_active_label(reader);
        let another_label = c2pa_sm_reader_active_label(reader);
        assert_ne!(json, another_json);
        assert_ne!(label, another_label);
        c2pa_sm_reader_free(reader);
        assert_eq!(text(json), text(another_json));
        assert_eq!(text(label), text(another_label));
        assert!(text(json).contains(&text(label)));
        for string in [json, another_json, label, another_label] {
            c2pa_sm_string_free(string);
        }
        c2pa_sm_string_free(ptr::null_mut());
    }
}

#[test]
fn owned_errors_outlive_the_session_and_success_clears_error_slots() {
    let session = new_session("jpeg", None);
    let mut err = ptr::null_mut();
    let r = reply(C2PA_SM_REPLY_TIME, u64::MAX, 0, &[]);
    // SAFETY: valid outputs; errors are independently owned.
    unsafe {
        assert_eq!(
            c2pa_sm_session_fulfill(session, &r, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let first_error = err;
        let message = c2pa_sm_error_message(first_error);
        let name = c2pa_sm_error_name(first_error);
        let mut done = 0;
        assert_eq!(
            c2pa_sm_session_advance(session, &mut done, &mut err),
            C2PA_SM_OK
        );
        assert!(
            err.is_null(),
            "success must clear, not free, the error slot"
        );
        c2pa_sm_session_free(session);
        assert!(text(message).contains("no outstanding request"));
        assert!(text(name).starts_with("C2pa(BadParam("));
        assert_eq!(c2pa_sm_error_message(first_error), message);
        assert_eq!(c2pa_sm_error_name(first_error), name);
        assert_eq!(take_error(first_error).0, C2PA_SM_ERR_INVALID_ARGUMENT);
    }
}

/// Uses only the public signing ABI to create an asset with the shared OCSP
/// leaf (which has the baseline signing key) and issuer certificates.
fn ocsp_asset() -> Vec<u8> {
    use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

    let definition = cstr(BASELINE_DEFINITION);
    let format = cstr("jpeg");
    let algorithm = cstr("es256");
    let buffer = |bytes: &[u8]| C2paSmBuffer {
        data: bytes.as_ptr(),
        len: bytes.len(),
    };
    let certs = [buffer(OCSP_LEAF), buffer(OCSP_ROOT)];
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .unwrap();
    let mut session = ptr::null_mut();
    let mut err = ptr::null_mut();
    // SAFETY: strings, certificate slices and output slots remain live.
    assert_eq!(
        unsafe {
            c2pa_sm_build_session_new(
                definition.as_ptr(),
                format.as_ptr(),
                algorithm.as_ptr(),
                certs.as_ptr(),
                certs.len(),
                &mut session,
                &mut err,
            )
        },
        C2PA_SM_OK,
        "{:?}",
        take_error(err)
    );
    let mut output = Vec::new();
    loop {
        let mut done = 0;
        let mut count = 0;
        // SAFETY: live session and writable outputs.
        assert_eq!(
            unsafe { c2pa_sm_build_session_advance(session, &mut done, &mut count, &mut err) },
            C2PA_SM_OK,
            "{:?}",
            take_error(err)
        );
        if done != 0 {
            break;
        }
        assert!(count > 0);
        let pending = (0..count)
            .map(|index| {
                let mut request = C2paSmBuildRequest::default();
                // SAFETY: copy every borrowed payload before any fulfill clears the batch.
                assert_eq!(
                    unsafe {
                        c2pa_sm_build_session_request(session, index, &mut request, &mut err)
                    },
                    C2PA_SM_OK,
                    "{:?}",
                    take_error(err)
                );
                let copy = |buffer: C2paSmBuffer| {
                    if buffer.len == 0 {
                        Vec::new()
                    } else {
                        // SAFETY: nonempty request buffers borrow the live session.
                        unsafe { slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
                    }
                };
                (request, copy(request.data), copy(request.algorithm))
            })
            .collect::<Vec<_>>();
        for (request, data, algorithm) in pending {
            let mut r = C2paSmBuildReply {
                id: request.id,
                ..Default::default()
            };
            let payload;
            match request.kind {
                kind if kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_LENGTH as c_int => {
                    assert_eq!(
                        request.stream,
                        C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int
                    );
                    r.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int;
                    r.value = SOURCE_JPEG.len() as u64;
                    payload = Vec::new();
                }
                kind if kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_READ as c_int => {
                    let bytes =
                        if request.stream == C2paSmBuildStream::C2PA_SM_BUILD_SOURCE as c_int {
                            SOURCE_JPEG
                        } else {
                            assert_eq!(
                                request.stream,
                                C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int
                            );
                            &output
                        };
                    payload = bytes
                        [request.offset as usize..(request.offset + request.len) as usize]
                        .to_vec();
                    r.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int;
                }
                kind if kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_WRITE as c_int => {
                    assert_eq!(
                        request.stream,
                        C2paSmBuildStream::C2PA_SM_BUILD_OUTPUT as c_int
                    );
                    let bytes = &data;
                    let start = request.offset as usize;
                    output.resize(output.len().max(start + bytes.len()), 0);
                    output[start..start + bytes.len()].copy_from_slice(bytes);
                    payload = Vec::new();
                    r.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_WRITTEN as c_int;
                }
                kind if kind == C2paSmBuildRequestKind::C2PA_SM_BUILD_REQUEST_SIGN as c_int => {
                    assert_eq!(algorithm, b"es256");
                    payload = signer.sign(&data).unwrap();
                    r.kind = C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_SIGNATURE as c_int;
                }
                other => panic!("unexpected signing request {other}"),
            }
            r.data = buffer(&payload);
            // SAFETY: reply data is copied while payload remains live.
            assert_eq!(
                unsafe { c2pa_sm_build_session_fulfill(session, &r, &mut err) },
                C2PA_SM_OK,
                "{:?}",
                take_error(err)
            );
        }
    }
    let mut report = ptr::null_mut();
    // SAFETY: finish consumes the live completed session; report is freed once.
    unsafe {
        assert_eq!(
            c2pa_sm_build_session_finish(session, &mut report, &mut err),
            C2PA_SM_OK,
            "{:?}",
            take_error(err)
        );
        assert!(!report.is_null());
        assert_eq!(c2pa_sm_sign_report_free(report, &mut err), C2PA_SM_OK);
        assert!(err.is_null());
    }
    output
}

fn read_ocsp_asset(
    asset: &[u8],
    response: Option<Result<&[u8], &str>>,
    fetch: Option<bool>,
) -> (String, C2paSmValidationState, usize) {
    let anchor = base64::engine::general_purpose::STANDARD.encode(OCSP_ROOT);
    let verify = fetch.map_or_else(String::new, |fetch| {
        format!(r#""verify":{{"ocsp_fetch":{fetch}}},"#)
    });
    let settings = format!(
        r#"{{{verify}"trust":{{"anchors":[{{"trust_anchors":"-----BEGIN CERTIFICATE-----\n{anchor}\n-----END CERTIFICATE-----","trust_kind":"manifest"}}]}}}}"#
    );
    let session = new_session("jpeg", Some(&settings));
    let mut ocsp_count = 0;
    while !advance(session).unwrap() {
        let pending = requests(session);
        assert!(!pending.is_empty(), "host stalled");
        for request in pending {
            if request.kind != C2PA_SM_REQUEST_OCSP {
                answer(session, &request, asset);
                continue;
            }
            ocsp_count += 1;
            // SAFETY: request URL and body are borrowed until the next mutation.
            unsafe {
                assert_eq!(
                    slice::from_raw_parts(request.url.cast::<u8>(), request.url_len),
                    b"http://ocsp.example/"
                );
                let der = slice::from_raw_parts(request.body, request.body_len);
                assert_eq!(der[0], 0x30);
                assert!(
                    der.len() > 32,
                    "CertID must include issuer hashes and serial"
                );
            }
            assert_eq!(
                fulfill(session, &reply(C2PA_SM_REPLY_TIME, request.id, NOW, &[]))
                    .unwrap_err()
                    .0,
                C2PA_SM_ERR_READ
            );
            let r = match response.unwrap() {
                Ok(bytes) => reply(C2PA_SM_REPLY_OCSP, request.id, 0, bytes),
                Err(message) => reply(C2PA_SM_REPLY_FAILED, request.id, 0, message.as_bytes()),
            };
            fulfill(session, &r).unwrap();
        }
    }
    let mut reader = ptr::null_mut();
    let mut err = ptr::null_mut();
    // SAFETY: completed session is consumed; reader and owned strings freed once.
    let (json, state) = unsafe {
        assert_eq!(
            c2pa_sm_session_finish(session, &mut reader, &mut err),
            C2PA_SM_OK,
            "{:?}",
            take_error(err)
        );
        assert!(!reader.is_null());
        let string = c2pa_sm_reader_json(reader);
        let json = text(string);
        c2pa_sm_string_free(string);
        let state = c2pa_sm_reader_validation_state(reader);
        let label = c2pa_sm_reader_active_label(reader);
        assert!(!label.is_null());
        assert!(json.contains(&text(label)));
        c2pa_sm_string_free(label);
        assert!(c2pa_sm_reader_is_embedded(reader));
        c2pa_sm_reader_free(reader);
        (json, state)
    };
    (json, state, ocsp_count)
}

#[test]
fn build_and_read_roundtrip_preserves_the_baseline_manifest_fields() {
    use contentauth_c2pa_sign_baseline::{Definition, BASELINE_DEFINITION};

    let definition = Definition::from_json(BASELINE_DEFINITION).unwrap();
    let (json, state, requests) = read_ocsp_asset(&ocsp_asset(), None, Some(false));
    assert_eq!(requests, 0);
    assert_eq!(state, C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED);
    let generator = &definition.claim_generator_info[0];
    // Compare the complete manifest map, not scattered substrings: this also
    // requires exactly one entry and scopes every field to the active manifest.
    let expected = format!(
        r#"{{
  "active_manifest": "{label}",
  "manifests": {{
    "{label}": {{
      "label": "{label}",
      "claim_generator_info": [
        {{
          "name": "{name}",
          "version": "{version}",
          "specVersion": "2.4.0"
        }}
      ],
      "claim_version": 2,
      "title": "{title}",
      "instance_id": "{instance_id}",
      "assertions": [
        "c2pa.actions.v2",
        "c2pa.hash.data"
      ]
    }}
  }},
  "validation_state": "Trusted",
"#,
        label = definition.label,
        name = generator.name,
        version = generator.version,
        title = definition.title.as_deref().unwrap(),
        instance_id = definition.instance_id,
    );
    assert!(json.starts_with(&expected), "{json}");
}

#[test]
fn authenticated_ocsp_responses_distinguish_good_and_revoked_signers() {
    let asset = ocsp_asset();
    for (response, expected_state, expected_json, expected_status) in [
        (
            &include_bytes!("../../../contentauth-c2pa-c-api/tests/fixtures/ocsp-good.der")[..],
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
            "Trusted",
            "signingCredential.ocsp.notRevoked",
        ),
        (
            &include_bytes!("../../../contentauth-c2pa-c-api/tests/fixtures/ocsp-revoked.der")[..],
            C2paSmValidationState::C2PA_SM_VALIDATION_INVALID,
            "Invalid",
            "signingCredential.ocsp.revoked",
        ),
    ] {
        let (json, state, requests) = read_ocsp_asset(&asset, Some(Ok(response)), Some(true));
        assert_eq!(requests, 1);
        assert_eq!(state, expected_state, "{json}");
        assert!(
            json.contains(&format!(r#""validation_state": "{expected_json}""#)),
            "{json}"
        );
        assert!(json.contains(expected_status), "{json}");
        assert!(
            !json.contains("signingCredential.ocsp.inaccessible"),
            "{json}"
        );
    }
}

#[test]
fn ocsp_malformed_and_unavailable_transport_retain_the_manifest_report() {
    let asset = ocsp_asset();
    for (response, reason) in [
        (Ok(&[0x30, 0x00][..]), "could not be authenticated"),
        (Err("OCSP transport unavailable"), "could not be reached"),
    ] {
        let (json, state, requests) = read_ocsp_asset(&asset, Some(response), Some(true));
        assert_eq!(requests, 1);
        assert_eq!(
            state,
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
            "{json}"
        );
        assert!(json.contains(r#""validation_state": "Trusted""#), "{json}");
        assert!(
            json.contains("signingCredential.ocsp.inaccessible"),
            "{json}"
        );
        assert!(json.contains(reason), "{json}");
        assert!(
            !json.contains("signingCredential.ocsp.notRevoked"),
            "{json}"
        );
    }
}

#[test]
fn online_ocsp_is_opt_in_and_can_be_disabled() {
    let asset = ocsp_asset();
    for fetch in [None, Some(false)] {
        let (json, state, requests) = read_ocsp_asset(&asset, None, fetch);
        assert_eq!(requests, 0);
        assert_eq!(
            state,
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
            "{json}"
        );
        assert!(json.contains("signingCredential.ocsp.skipped"), "{json}");
        assert!(
            !json.contains("signingCredential.ocsp.inaccessible"),
            "{json}"
        );
    }
}
