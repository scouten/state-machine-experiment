// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::{
    ffi::{CStr, CString},
    ptr,
};

use super::*;
const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");
const NOW: i64 = 1_800_000_000;
const UNSIGNED: &[u8] = &[0xff, 0xd8, 0xff, 0xd9];

fn text(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().into()
}
fn take_error(e: *mut C2paSmError) -> (c_int, String, String) {
    assert!(!e.is_null());
    let out = unsafe {
        (
            c2pa_sm_error_code(e),
            text(c2pa_sm_error_message(e)),
            text(c2pa_sm_error_name(e)),
        )
    };
    unsafe { c2pa_sm_error_free(e) };
    out
}
fn new_session(format: &str, settings: Option<&str>) -> *mut C2paSmSession {
    let f = CString::new(format).unwrap();
    let s = settings.map(|s| CString::new(s).unwrap());
    let mut session = ptr::null_mut();
    let mut error = ptr::null_mut();
    let code = unsafe {
        c2pa_sm_session_new(
            f.as_ptr(),
            s.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            &mut session,
            &mut error,
        )
    };
    assert_eq!(code, 0, "{:?}", take_error(error));
    assert!(!session.is_null());
    session
}
fn advance(session: *mut C2paSmSession) -> Result<bool, (c_int, String, String)> {
    let mut done = -1;
    let mut error = ptr::null_mut();
    let code = unsafe { c2pa_sm_session_advance(session, &mut done, &mut error) };
    if code == 0 {
        assert!(error.is_null());
        assert!(done == 0 || done == 1);
        Ok(done == 1)
    } else {
        let e = take_error(error);
        assert_eq!(code, e.0);
        Err(e)
    }
}
fn requests(s: *mut C2paSmSession) -> Vec<C2paSmRequest> {
    (0..unsafe { c2pa_sm_session_request_count(s) })
        .map(|i| {
            let mut r = std::mem::MaybeUninit::uninit();
            assert!(unsafe { c2pa_sm_session_request(s, i, r.as_mut_ptr()) });
            unsafe { r.assume_init() }
        })
        .collect()
}
fn reply(kind: c_int, id: u64, value: i64, data: &[u8]) -> C2paSmReply {
    C2paSmReply {
        kind,
        id,
        value,
        data: data.as_ptr(),
        data_len: data.len(),
    }
}
fn fulfill(s: *mut C2paSmSession, r: &C2paSmReply) -> Result<(), (c_int, String)> {
    let mut e = ptr::null_mut();
    let code = unsafe { c2pa_sm_session_fulfill(s, r, &mut e) };
    if code == 0 {
        assert!(e.is_null());
        Ok(())
    } else {
        let e = take_error(e);
        assert_eq!(code, e.0);
        Err((e.0, e.1))
    }
}
fn answer(s: *mut C2paSmSession, r: &C2paSmRequest, asset: &[u8]) {
    let response = match r.kind {
        C2PA_SM_REQUEST_READ => reply(
            0,
            r.id,
            0,
            &asset[r.start as usize..(r.start + r.len) as usize],
        ),
        C2PA_SM_REQUEST_LENGTH => reply(1, r.id, asset.len() as i64, &[]),
        C2PA_SM_REQUEST_TIME => reply(2, r.id, NOW, &[]),
        _ => reply(4, r.id, 0, b"offline"),
    };
    fulfill(s, &response).unwrap();
}
fn drive(s: *mut C2paSmSession, asset: &[u8]) -> (c_int, *mut C2paSmReader, *mut C2paSmError) {
    loop {
        let mut done = 0;
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_session_advance(s, &mut done, &mut error) };
        if code != C2PA_SM_OK {
            unsafe { c2pa_sm_session_free(s) };
            return (code, ptr::null_mut(), error);
        }
        assert!(error.is_null());
        if done != 0 {
            break;
        }
        for r in requests(s) {
            answer(s, &r, asset);
        }
    }
    let mut reader = ptr::null_mut();
    let mut error = ptr::null_mut();
    let code = unsafe { c2pa_sm_session_finish(s, &mut reader, &mut error) };
    (code, reader, error)
}
fn signed_reader() -> *mut C2paSmReader {
    let (code, r, e) = drive(new_session("jpeg", None), C_JPG);
    assert_eq!(code, 0, "{:?}", take_error(e));
    assert!(!r.is_null());
    r
}

#[test]
fn a_signed_jpeg_reads_through_the_c_abi() {
    let r = signed_reader();
    unsafe {
        let j = c2pa_sm_reader_json(r);
        let l = c2pa_sm_reader_active_label(r);
        let json: serde_json::Value = serde_json::from_str(&text(j)).unwrap();
        assert_eq!(json["validation_state"], "Valid");
        assert_eq!(json["active_manifest"], text(l));
        assert_eq!(json["manifests"].as_object().unwrap().len(), 1);
        assert_eq!(
            c2pa_sm_reader_validation_state(r),
            C2paSmValidationState::C2PA_SM_VALIDATION_VALID
        );
        assert!(c2pa_sm_reader_is_embedded(r));
        c2pa_sm_string_free(j);
        c2pa_sm_string_free(l);
        c2pa_sm_reader_free(r);
    }
}
#[test]
fn an_asset_with_no_manifest_store_finishes_with_no_reader() {
    assert_eq!(
        drive(new_session("jpg", None), UNSIGNED),
        (0, ptr::null_mut(), ptr::null_mut())
    );
}
#[test]
fn a_malformed_asset_is_a_read_error_not_a_panic() {
    let (c, r, e) = drive(new_session("jpeg", None), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(c, 4);
    assert!(r.is_null());
    let e = take_error(e);
    assert_eq!(e.0, 4);
    assert!(!e.1.is_empty());
}
#[test]
fn session_creation_failures_are_values() {
    for (f, s, expected) in [
        (c"image/png", c"{}", 2),
        (c"jpeg", c"{bad", 1),
        (c"\xff", c"{}", 1),
    ] {
        let mut session = ptr::null_mut();
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_session_new(f.as_ptr(), s.as_ptr(), &mut session, &mut error) };
        assert_eq!(code, expected);
        assert!(session.is_null());
        assert_eq!(take_error(error).0, expected);
    }
}
#[test]
fn null_and_malformed_arguments_are_errors_not_undefined_behavior() {
    unsafe {
        let mut s = ptr::null_mut();
        let mut e = ptr::null_mut();
        assert_eq!(
            c2pa_sm_session_new(ptr::null(), ptr::null(), &mut s, &mut e),
            1
        );
        assert_eq!(take_error(e).1, "format is null");
        assert_eq!(
            c2pa_sm_session_new(c"jpeg".as_ptr(), ptr::null(), ptr::null_mut(), &mut e),
            1
        );
        take_error(e);
        assert_eq!(
            c2pa_sm_session_new(ptr::null(), ptr::null(), &mut s, ptr::null_mut()),
            1
        );
        let s = new_session("jpeg", None);
        assert_eq!(c2pa_sm_session_fulfill(s, ptr::null(), &mut e), 1);
        take_error(e);
        assert_eq!(
            c2pa_sm_session_finish(ptr::null_mut(), ptr::null_mut(), &mut e),
            1
        );
        take_error(e);
        assert!(!c2pa_sm_session_request(ptr::null(), 0, ptr::null_mut()));
        let mut done = 0;
        assert_eq!(
            c2pa_sm_session_advance(ptr::null_mut(), &mut done, &mut e),
            1
        );
        take_error(e);
        assert!(!c2pa_sm_session_request(s, 0, ptr::null_mut()));
        assert!(c2pa_sm_reader_json(ptr::null()).is_null());
        assert!(c2pa_sm_reader_active_label(ptr::null()).is_null());
        assert!(!c2pa_sm_reader_is_embedded(ptr::null()));
        assert_eq!(
            c2pa_sm_reader_validation_state(ptr::null()),
            C2paSmValidationState::C2PA_SM_VALIDATION_UNAVAILABLE
        );
        c2pa_sm_session_free(s);
        c2pa_sm_reader_free(ptr::null_mut());
        c2pa_sm_session_free(ptr::null_mut());
    }
}
#[test]
fn misanswered_requests_are_rejected_and_stay_outstanding() {
    let s = new_session("jpeg", None);
    assert!(!advance(s).unwrap());
    let r = requests(s)[0];
    assert_eq!(fulfill(s, &reply(2, u64::MAX, 0, &[])).unwrap_err().0, 1);
    assert_eq!(fulfill(s, &reply(1, r.id, -1, &[])).unwrap_err().0, 1);
    answer(s, &r, C_JPG);
    assert_eq!(fulfill(s, &reply(4, r.id, 0, b"late")).unwrap_err().0, 1);
    assert!(requests(s).is_empty());
    unsafe { c2pa_sm_session_free(s) };
}
#[test]
fn every_request_kind_is_described() {
    let s = tracked(C2paSmSession {
        inner: ReadSessionBridge::new("jpeg", None).unwrap(),
        fresh: vec![
            PendingRequest::Read {
                id: 1,
                start: 7,
                len: 9,
            },
            PendingRequest::Length { id: 2 },
            PendingRequest::CurrentDateTime { id: 3 },
            PendingRequest::Ocsp {
                id: 4,
                url: "http://ocsp/".into(),
                request_der: vec![1, 2, 3],
            },
        ],
    })
    .unwrap();
    let r = requests(s);
    assert_eq!(
        r.iter().map(|r| r.kind).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    assert_eq!((r[0].start, r[0].len), (7, 9));
    unsafe {
        assert_eq!(
            std::slice::from_raw_parts(r[3].url.cast::<u8>(), r[3].url_len),
            b"http://ocsp/"
        );
        assert_eq!(
            std::slice::from_raw_parts(r[3].body, r[3].body_len),
            [1, 2, 3]
        );
        c2pa_sm_session_free(s);
    }
}
#[test]
fn engine_errors_map_to_their_codes() {
    for (e, c) in [
        (C2paError::JumbfNotFound, 3),
        (C2paError::UnsupportedType, 2),
        (C2paError::BadParam("bad".into()), 1),
    ] {
        assert_eq!(Failure::from(Error::C2pa(e)).code, c);
    }
}
#[test]
fn an_ocsp_reply_is_marshalled_and_refused_by_id() {
    let s = new_session("jpeg", None);
    assert_eq!(fulfill(s, &reply(3, 99, 0, b"DER")).unwrap_err().0, 1);
    unsafe { c2pa_sm_session_free(s) };
}
#[test]
fn sessions_move_between_threads_and_readers_are_shared() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<C2paSmSession>();
    send::<C2paSmReader>();
    sync::<C2paSmReader>();
    send::<C2paSmError>();
    let s = new_session("jpeg", None) as usize;
    std::thread::spawn(move || {
        let s = s as *mut C2paSmSession;
        assert!(!advance(s).unwrap());
        unsafe { c2pa_sm_session_free(s) }
    })
    .join()
    .unwrap();
}
#[test]
fn constructor_rejects_invalid_settings_types_and_non_utf8_settings() {
    for settings in [c"{\"verify\":{\"ocsp_fetch\":\"yes\"}}", c"\xff"] {
        let mut s = ptr::null_mut();
        let mut e = ptr::null_mut();
        assert_eq!(
            unsafe { c2pa_sm_session_new(c"jpeg".as_ptr(), settings.as_ptr(), &mut s, &mut e) },
            1
        );
        assert!(s.is_null());
        assert_eq!(take_error(e).0, 1);
    }
    for settings in [None, Some("{}"), Some(""), Some(" \n\t ")] {
        assert_eq!(
            drive(new_session("jpeg", settings), UNSIGNED),
            (0, ptr::null_mut(), ptr::null_mut())
        );
    }
}
#[test]
fn tiff_and_registry_aliases_are_supported() {
    for f in [
        "image/tiff",
        "tiff",
        "tif",
        "dng",
        "image/dng",
        "image/x-adobe-dng",
        "image/jpg",
        "JPEG",
    ] {
        unsafe { c2pa_sm_session_free(new_session(f, None)) };
    }
}
#[test]
fn all_reply_variants_reject_null_sessions_and_unknown_ids() {
    let s = new_session("jpeg", None);
    for kind in 0..=4 {
        let r = reply(kind, u64::MAX, 0, b"host failed");
        assert_eq!(
            fulfill(ptr::null_mut(), &r).unwrap_err(),
            (1, "session is null".into())
        );
        assert_eq!(fulfill(s, &r).unwrap_err().0, 1);
        assert_eq!(
            unsafe { c2pa_sm_session_fulfill(s, &r, ptr::null_mut()) },
            1
        );
    }
    assert_eq!(drive(s, UNSIGNED), (0, ptr::null_mut(), ptr::null_mut()));
}
#[test]
fn invalid_advance_output_preserves_the_session() {
    let s = new_session("jpeg", None);
    let mut e = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_session_advance(s, ptr::null_mut(), &mut e) },
        1
    );
    assert_eq!(take_error(e).1, "out_done is null");
    assert_eq!(drive(s, UNSIGNED), (0, ptr::null_mut(), ptr::null_mut()));
}
#[test]
fn invalid_payloads_preserve_requests_and_host_failure_is_terminal() {
    let s = new_session("jpeg", None);
    assert!(!advance(s).unwrap());
    let r = requests(s)[0];
    for (kind, value, code) in [(2, 0, 4), (1, -1, 1), (3, 0, 4), (99, 0, 1)] {
        assert_eq!(
            fulfill(s, &reply(kind, r.id, value, &[])).unwrap_err().0,
            code
        );
    }
    fulfill(s, &reply(4, r.id, 0, b"read cancelled \xff")).unwrap();
    let e = advance(s).unwrap_err();
    assert_eq!(e.0, 4);
    assert!(e.1.contains("read cancelled \u{fffd}"), "{e:?}");
    assert_eq!(advance(s).unwrap_err().0, 4);
    let mut r = ptr::null_mut();
    let mut e = ptr::null_mut();
    assert_eq!(unsafe { c2pa_sm_session_finish(s, &mut r, &mut e) }, 4);
    assert!(r.is_null());
    take_error(e);
}
#[test]
fn empty_byte_payloads_are_accepted_then_fail_reading() {
    for data in [ptr::null(), b"x".as_ptr()] {
        let s = new_session("jpeg", None);
        let pending = loop {
            assert!(!advance(s).unwrap());
            let p = requests(s);
            if p.iter().any(|r| r.kind == 0) {
                break p;
            }
            for r in p {
                answer(s, &r, C_JPG);
            }
        };
        let r = pending.iter().find(|r| r.kind == 0).unwrap();
        fulfill(
            s,
            &C2paSmReply {
                data,
                data_len: 0,
                ..reply(0, r.id, 0, &[])
            },
        )
        .unwrap();
        for other in pending.iter().filter(|p| p.id != r.id) {
            answer(s, other, C_JPG);
        }
        let (c, r, e) = drive(s, C_JPG);
        assert_eq!(c, 4);
        assert!(r.is_null());
        take_error(e);
    }
}
#[test]
fn nonempty_null_or_overflow_payload_is_rejected_without_consuming_request() {
    let s = new_session("jpeg", None);
    assert!(!advance(s).unwrap());
    let r = requests(s)[0];
    for (data, data_len) in [(ptr::null(), 1), (b"x".as_ptr(), usize::MAX)] {
        assert_eq!(
            fulfill(
                s,
                &C2paSmReply {
                    data,
                    data_len,
                    ..reply(0, r.id, 0, &[])
                }
            )
            .unwrap_err()
            .0,
            1
        );
    }
    answer(s, &r, UNSIGNED);
    assert_eq!(drive(s, UNSIGNED), (0, ptr::null_mut(), ptr::null_mut()));
}
#[test]
fn finish_consumes_incomplete_sessions_and_clears_reader_output() {
    for waiting in [false, true] {
        let s = new_session("jpeg", None);
        if waiting {
            assert!(!advance(s).unwrap());
        }
        let mut r = ptr::dangling_mut();
        let mut e = ptr::null_mut();
        assert_eq!(unsafe { c2pa_sm_session_finish(s, &mut r, &mut e) }, 4);
        assert!(r.is_null());
        take_error(e);
        assert!(cimpl::checkout_exclusive(s).is_err());
    }
    let s = new_session("jpeg", None);
    let mut e = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_session_finish(s, ptr::null_mut(), &mut e) },
        1
    );
    take_error(e);
    assert!(cimpl::checkout_exclusive(s).is_err());
}
#[test]
fn advance_reports_only_new_requests_until_replies_arrive() {
    let s = new_session("jpeg", None);
    assert!(!advance(s).unwrap());
    let p = requests(s);
    for _ in 0..2 {
        assert!(!advance(s).unwrap());
        assert!(requests(s).is_empty());
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
    assert!(!unsafe { c2pa_sm_session_request(s, usize::MAX, &mut untouched) });
    assert_eq!(
        (untouched.kind, untouched.id, untouched.start, untouched.len),
        (99, u64::MAX, 17, 19)
    );
    for r in p.into_iter().rev() {
        answer(s, &r, C_JPG);
    }
    let (c, r, e) = drive(s, C_JPG);
    assert_eq!((c, e), (0, ptr::null_mut()));
    unsafe { c2pa_sm_reader_free(r) };
}
#[test]
fn owned_reader_strings_outlive_the_reader_and_do_not_alias() {
    let r = signed_reader();
    unsafe {
        let j = c2pa_sm_reader_json(r);
        let j2 = c2pa_sm_reader_json(r);
        let l = c2pa_sm_reader_active_label(r);
        let l2 = c2pa_sm_reader_active_label(r);
        assert_ne!(j, j2);
        assert_ne!(l, l2);
        c2pa_sm_reader_free(r);
        assert_eq!(text(j), text(j2));
        assert_eq!(text(l), text(l2));
        assert!(text(j).contains(&text(l)));
        for s in [j, j2, l, l2] {
            c2pa_sm_string_free(s);
            c2pa_sm_string_free(s);
        }
    }
}
#[test]
fn owned_errors_outlive_the_session_and_success_clears_error_slots() {
    let s = new_session("jpeg", None);
    let mut e = ptr::null_mut();
    let r = reply(2, u64::MAX, 0, &[]);
    unsafe {
        assert_eq!(c2pa_sm_session_fulfill(s, &r, &mut e), 1);
        let owned = e;
        let message = c2pa_sm_error_message(owned);
        let mut done = 0;
        assert_eq!(c2pa_sm_session_advance(s, &mut done, &mut e), 0);
        assert!(e.is_null());
        c2pa_sm_session_free(s);
        assert!(text(message).contains("no outstanding request"));
        assert_eq!(take_error(owned).0, 1);
    }
}
#[test]
fn tracked_reader_sessions_and_strings_reject_stale_wrong_type_and_busy_handles() {
    let s = new_session("jpeg", None);
    let mut done = 0;
    let mut e = ptr::null_mut();
    unsafe {
        c2pa_sm_reader_free(s.cast());
        c2pa_sm_error_free(s.cast());
        c2pa_sm_string_free(s.cast());
        assert!(cimpl::checkout_exclusive(s).is_ok());
        let borrowed = cimpl::checkout_exclusive(s).unwrap();
        c2pa_sm_session_free(s);
        assert_eq!(c2pa_sm_session_advance(s, &mut done, &mut e), 1);
        take_error(e);
        drop(borrowed);
        assert_eq!(c2pa_sm_session_advance(s, &mut done, &mut e), 0);
        c2pa_sm_session_free(s);
        assert_eq!(c2pa_sm_session_advance(s, &mut done, &mut e), 1);
        take_error(e);
        assert_eq!(c2pa_sm_session_request_count(s), 0);
        assert!(!c2pa_sm_session_request(s, 0, ptr::null_mut()));
        c2pa_sm_session_free(s);
        let r = signed_reader();
        c2pa_sm_session_free(r.cast());
        c2pa_sm_string_free(r.cast());
        let guard = cimpl::checkout_shared(r).unwrap();
        c2pa_sm_reader_free(r);
        assert!(cimpl::checkout_shared(r).is_ok());
        drop(guard);
        c2pa_sm_reader_free(r);
        assert!(c2pa_sm_reader_json(r).is_null());
        c2pa_sm_reader_free(r);
    }
}

#[cfg(feature = "build")]
pub(crate) fn assert_validation(
    format: &str,
    asset: &[u8],
    settings: Option<&str>,
    expected: C2paSmValidationState,
) {
    let (c, r, e) = drive(new_session(format, settings), asset);
    assert_eq!(c, 0, "{:?}", take_error(e));
    assert!(!r.is_null());
    unsafe {
        assert_eq!(c2pa_sm_reader_validation_state(r), expected);
        c2pa_sm_reader_free(r);
    }
}
#[cfg(feature = "build")]
pub(crate) fn assert_baseline(format: &str, asset: &[u8], anchor: &[u8]) {
    use base64::Engine;
    use contentauth_c2pa_sign_baseline::{Definition, BASELINE_DEFINITION};
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        base64::engine::general_purpose::STANDARD.encode(anchor)
    );
    let settings = format!(r#"{{"trust":{{"trust_anchors":{pem:?}}}}}"#);
    let (c, r, e) = drive(new_session(format, Some(&settings)), asset);
    assert_eq!(c, 0, "{:?}", take_error(e));
    let d = Definition::from_json(BASELINE_DEFINITION).unwrap();
    unsafe {
        assert_eq!(
            c2pa_sm_reader_validation_state(r),
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED
        );
        let raw = c2pa_sm_reader_json(r);
        let json: serde_json::Value = serde_json::from_str(&text(raw)).unwrap();
        c2pa_sm_string_free(raw);
        assert_eq!(json["active_manifest"], d.label);
        let manifests = json["manifests"].as_object().unwrap();
        assert_eq!(manifests.len(), 1);
        let m = &manifests[&d.label];
        assert_eq!(
            m,
            &serde_json::json!({
                "label": d.label,
                "title": d.title,
                "instance_id": d.instance_id,
                "claim_generator_info": [{
                    "name": d.claim_generator_info[0].name,
                    "version": d.claim_generator_info[0].version,
                    "specVersion": "2.4.0"
                }],
                "claim_version": 2,
                "assertions": ["c2pa.actions.v2", "c2pa.hash.data"]
            })
        );
        assert_eq!(json["validation_state"], "Trusted");
        c2pa_sm_reader_free(r);
    }
}

#[cfg(feature = "build")]
mod roundtrip {
    use base64::Engine;
    use contentauth_c2pa_sign_baseline::fixtures::*;

    use super::*;
    const ROOT: &[u8] = include_bytes!("../tests/fixtures/ocsp-root.der");
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/ocsp-leaf.der");
    fn asset() -> Vec<u8> {
        crate::signing::tests::signed_asset("jpeg", SOURCE_JPEG, &[LEAF, ROOT])
    }
    fn ocsp(
        asset: &[u8],
        fetch: Option<bool>,
        response: Option<Result<&[u8], &str>>,
    ) -> (String, C2paSmValidationState, usize) {
        let root = base64::engine::general_purpose::STANDARD.encode(ROOT);
        let verify = fetch.map_or(String::new(), |f| {
            format!(r#""verify":{{"ocsp_fetch":{f}}},"#)
        });
        let settings = format!(
            r#"{{{verify}"trust":{{"anchors":[{{"trust_anchors":"-----BEGIN CERTIFICATE-----\n{root}\n-----END CERTIFICATE-----","trust_kind":"manifest"}}]}}}}"#
        );
        let s = new_session("jpeg", Some(&settings));
        let mut count = 0;
        while !advance(s).unwrap() {
            let batch = requests(s);
            assert!(!batch.is_empty());
            for r in batch {
                if r.kind != 3 {
                    answer(s, &r, asset);
                    continue;
                }
                count += 1;
                unsafe {
                    assert_eq!(
                        std::slice::from_raw_parts(r.url.cast::<u8>(), r.url_len),
                        b"http://ocsp.example/"
                    );
                    let der = std::slice::from_raw_parts(r.body, r.body_len);
                    assert_eq!(der[0], 0x30);
                    assert!(der.len() > 32);
                }
                assert_eq!(fulfill(s, &reply(2, r.id, NOW, &[])).unwrap_err().0, 4);
                let response = match response.unwrap() {
                    Ok(b) => reply(3, r.id, 0, b),
                    Err(m) => reply(4, r.id, 0, m.as_bytes()),
                };
                fulfill(s, &response).unwrap();
            }
        }
        let mut r = ptr::null_mut();
        let mut e = ptr::null_mut();
        assert_eq!(
            unsafe { c2pa_sm_session_finish(s, &mut r, &mut e) },
            0,
            "{:?}",
            take_error(e)
        );
        unsafe {
            let raw = c2pa_sm_reader_json(r);
            let json = text(raw);
            c2pa_sm_string_free(raw);
            let state = c2pa_sm_reader_validation_state(r);
            let label = c2pa_sm_reader_active_label(r);
            assert!(json.contains(&text(label)));
            c2pa_sm_string_free(label);
            assert!(c2pa_sm_reader_is_embedded(r));
            c2pa_sm_reader_free(r);
            (json, state, count)
        }
    }
    #[test]
    fn build_and_read_roundtrip_preserves_the_baseline_manifest_fields() {
        let bytes = asset();
        assert_baseline("jpeg", &bytes, ROOT);
    }
    #[test]
    fn authenticated_ocsp_responses_distinguish_good_and_revoked_signers() {
        let bytes = asset();
        for (response, state, json_state, status) in [
            (
                &include_bytes!("../tests/fixtures/ocsp-good.der")[..],
                C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
                "Trusted",
                "signingCredential.ocsp.notRevoked",
            ),
            (
                &include_bytes!("../tests/fixtures/ocsp-revoked.der")[..],
                C2paSmValidationState::C2PA_SM_VALIDATION_INVALID,
                "Invalid",
                "signingCredential.ocsp.revoked",
            ),
        ] {
            let (json, actual, n) = ocsp(&bytes, Some(true), Some(Ok(response)));
            assert_eq!(n, 1);
            assert_eq!(actual, state, "{json}");
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["validation_state"], json_state);
            assert!(json.contains(status), "{json}");
            assert!(!json.contains("signingCredential.ocsp.inaccessible"));
        }
    }
    #[test]
    fn ocsp_malformed_and_unavailable_transport_retain_the_manifest_report() {
        let bytes = asset();
        for (response, reason) in [
            (Ok(&[0x30, 0][..]), "could not be authenticated"),
            (Err("OCSP transport unavailable"), "could not be reached"),
        ] {
            let (json, state, n) = ocsp(&bytes, Some(true), Some(response));
            assert_eq!(n, 1);
            assert_eq!(
                state,
                C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
                "{json}"
            );
            assert!(
                json.contains("signingCredential.ocsp.inaccessible"),
                "{json}"
            );
            assert!(json.contains(reason), "{json}");
            assert!(!json.contains("signingCredential.ocsp.notRevoked"));
        }
    }
    #[test]
    fn online_ocsp_is_opt_in_and_can_be_disabled() {
        let bytes = asset();
        for fetch in [None, Some(false)] {
            let (json, state, n) = ocsp(&bytes, fetch, None);
            assert_eq!(n, 0);
            assert_eq!(state, C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED);
            assert!(json.contains("signingCredential.ocsp.skipped"));
            assert!(!json.contains("signingCredential.ocsp.inaccessible"));
        }
    }
    #[test]
    fn tiff_and_dng_roundtrip_have_two_nonadjacent_exclusions() {
        // A minimal little-endian TIFF with one ImageWidth entry.
        let source = [
            b'I', b'I', 42, 0, 8, 0, 0, 0, 1, 0, 0, 1, 4, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        for format in ["tiff", "dng"] {
            let bytes = crate::signing::tests::signed_asset(format, &source, &[TEST_SIGNER_CERT]);
            assert_baseline(format, &bytes, TEST_SIGNER_CERT);
        }
    }
}
