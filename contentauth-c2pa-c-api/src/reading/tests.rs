// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::{
    ffi::{CStr, CString},
    ptr,
};

use super::*;
const C_JPG: &[u8] = include_bytes!("../../../contentauth-c2pa-reader/tests/fixtures/C.jpg");
const NOW: i64 = 1_800_000_000;
const UNSIGNED: &[u8] = &[0xff, 0xd8, 0xff, 0xd9];

fn text(s: *const c_char) -> String {
    assert!(!s.is_null());
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
    assert!(error.is_null());
    session
}

#[test]
fn session_phase_is_returned_as_an_owned_string() {
    let session = new_session("jpeg", None);
    let phase = unsafe { c2pa_sm_session_phase(session) };
    assert_eq!(text(phase), "Locating > Scanning > Start");
    unsafe {
        c2pa_sm_string_free(phase);
        c2pa_sm_session_free(session);
    }
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
    assert!(e.is_null());
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
    assert!(e.2.starts_with("C2pa(Read("), "{e:?}");
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
        let error = take_error(error);
        assert_eq!(error.0, expected);
        if expected == C2PA_SM_ERR_UNSUPPORTED_TYPE {
            assert_eq!(error.1, "type is unsupported");
            assert_eq!(error.2, "C2pa(UnsupportedType)");
        } else {
            assert!(error.2.starts_with("C2pa(BadParam("), "{error:?}");
        }
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
        assert!(s.is_null());
        assert_eq!(
            c2pa_sm_session_new(c"\xff\xfe".as_ptr(), ptr::null(), &mut s, &mut e),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert!(s.is_null());
        assert_eq!(take_error(e).1, "format is not valid UTF-8");
        let s = new_session("jpeg", None);
        assert_eq!(
            c2pa_sm_session_advance(s, ptr::null_mut(), &mut e),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        take_error(e);
        assert_eq!(c2pa_sm_session_request_count(ptr::null()), 0);
        let mut request = std::mem::MaybeUninit::<C2paSmRequest>::uninit();
        assert!(!c2pa_sm_session_request(
            ptr::null(),
            0,
            request.as_mut_ptr()
        ));
        assert!(!c2pa_sm_session_request(s, 0, request.as_mut_ptr()));
        assert_eq!(c2pa_sm_session_fulfill(s, ptr::null(), &mut e), 1);
        take_error(e);
        assert_eq!(
            c2pa_sm_session_fulfill(ptr::null_mut(), &reply(2, 0, 0, &[]), &mut e),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        take_error(e);
        assert_eq!(
            c2pa_sm_session_fulfill(s, &reply(99, 0, 0, &[]), &mut e),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(take_error(e).1, "unknown reply kind 99");
        let mut reader = ptr::null_mut();
        assert_eq!(
            c2pa_sm_session_finish(ptr::null_mut(), &mut reader, &mut e),
            1
        );
        assert!(reader.is_null());
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
        assert_eq!(c2pa_sm_session_finish(s, ptr::null_mut(), &mut e), 1);
        take_error(e);
        assert!(cimpl::checkout_exclusive(s).is_err());
        c2pa_sm_session_free(s);
        c2pa_sm_reader_free(ptr::null_mut());
        c2pa_sm_session_free(ptr::null_mut());
        c2pa_sm_string_free(ptr::null_mut());
        c2pa_sm_error_free(ptr::null_mut());
        assert_eq!(
            c2pa_sm_error_code(ptr::null()),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(text(c2pa_sm_error_message(ptr::null())), "");
        assert_eq!(text(c2pa_sm_error_name(ptr::null())), "");
    }
}
#[test]
fn misanswered_requests_are_rejected_and_stay_outstanding() {
    let s = new_session("jpeg", None);
    assert!(!advance(s).unwrap());
    let r = requests(s)[0];
    let error = fulfill(s, &reply(2, u64::MAX, 0, &[])).unwrap_err();
    assert_eq!(error.0, 1);
    assert!(error.1.contains("no outstanding request"), "{error:?}");
    let error = fulfill(s, &reply(1, r.id, -1, &[])).unwrap_err();
    assert_eq!(error.0, 1);
    assert!(error.1.contains("negative"), "{error:?}");
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
    assert_eq!((r[0].id, r[0].start, r[0].len), (1, 7, 9));
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
    assert_eq!(
        Failure::from(Error::C2pa(C2paError::JumbfNotFound)).name,
        "C2pa(JumbfNotFound)"
    );
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
        let mut s = ptr::dangling_mut();
        let mut e = ptr::null_mut();
        assert_eq!(
            unsafe { c2pa_sm_session_new(c"jpeg".as_ptr(), settings.as_ptr(), &mut s, &mut e) },
            1
        );
        assert!(s.is_null());
        let error = take_error(e);
        assert_eq!(error.0, 1);
        assert!(!error.1.is_empty());
        assert!(!error.2.is_empty());
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
        let error = fulfill(s, &r).unwrap_err();
        assert_eq!(error.0, 1);
        assert!(error.1.contains("no outstanding request"), "{error:?}");
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
    let wrong_kind = if r.kind == C2PA_SM_REQUEST_TIME {
        C2PA_SM_REPLY_LENGTH
    } else {
        C2PA_SM_REPLY_TIME
    };
    for (kind, value, code) in [(wrong_kind, 0, 4), (1, -1, 1), (3, 0, 4), (99, 0, 1)] {
        assert_eq!(
            fulfill(s, &reply(kind, r.id, value, &[])).unwrap_err().0,
            code
        );
    }
    fulfill(s, &reply(4, r.id, 0, b"read cancelled \xff")).unwrap();
    let e = advance(s).unwrap_err();
    assert_eq!(e.0, 4);
    assert!(e.1.contains("read cancelled \u{fffd}"), "{e:?}");
    assert!(e.2.starts_with("C2pa(Read("), "{e:?}");
    assert_eq!(advance(s).unwrap_err().0, 4);
    let mut r = ptr::null_mut();
    let mut e = ptr::null_mut();
    assert_eq!(unsafe { c2pa_sm_session_finish(s, &mut r, &mut e) }, 4);
    assert!(r.is_null());
    assert_eq!(take_error(e).0, C2PA_SM_ERR_READ);
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
        assert_eq!(take_error(e).0, C2PA_SM_ERR_READ);
    }
}
#[test]
fn nonempty_null_or_overflow_payload_is_rejected_without_consuming_request() {
    for target_kind in [C2PA_SM_REQUEST_LENGTH, C2PA_SM_REQUEST_READ] {
        let s = new_session("jpeg", None);
        let pending = loop {
            assert!(!advance(s).unwrap());
            let pending = requests(s);
            if pending.iter().any(|r| r.kind == target_kind) {
                break pending;
            }
            for r in pending {
                answer(s, &r, C_JPG);
            }
        };
        let r = pending.iter().find(|r| r.kind == target_kind).unwrap();
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
                C2PA_SM_ERR_INVALID_ARGUMENT
            );
        }
        for r in pending {
            answer(s, &r, C_JPG);
        }
        let (code, reader, error) = drive(s, C_JPG);
        assert_eq!((code, error), (C2PA_SM_OK, ptr::null_mut()));
        assert!(!reader.is_null());
        unsafe {
            assert_eq!(
                c2pa_sm_reader_validation_state(reader),
                C2paSmValidationState::C2PA_SM_VALIDATION_VALID
            );
            c2pa_sm_reader_free(reader);
        }
    }
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
        assert!(!take_error(e).1.is_empty());
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
    assert!(!p.is_empty());
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
        c2pa_sm_string_free(ptr::null_mut());
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
        let name = c2pa_sm_error_name(owned);
        let mut done = 0;
        assert_eq!(c2pa_sm_session_advance(s, &mut done, &mut e), 0);
        assert!(e.is_null());
        c2pa_sm_session_free(s);
        assert!(text(message).contains("no outstanding request"));
        assert!(text(name).starts_with("C2pa(BadParam("));
        assert_eq!(c2pa_sm_error_message(owned), message);
        assert_eq!(c2pa_sm_error_name(owned), name);
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
    assert!(e.is_null());
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
    assert!(e.is_null());
    assert!(!r.is_null());
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
        let label = c2pa_sm_reader_active_label(r);
        assert_eq!(text(label), d.label);
        c2pa_sm_string_free(label);
        assert!(c2pa_sm_reader_is_embedded(r));
        c2pa_sm_reader_free(r);
    }
}
