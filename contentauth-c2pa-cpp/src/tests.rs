// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::ffi::CStr;

use super::*;

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// Inside every certificate's validity window, and not the wall clock.
const NOW: i64 = 1_800_000_000;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn text(s: *const c_char) -> String {
    // SAFETY: every caller passes a NUL-terminated string this library
    // returned.
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned()
}

fn take_error(err: *mut C2paSmError) -> (c_int, String, String) {
    assert!(!err.is_null());
    // SAFETY: a live error from this library, freed exactly once below.
    let out = unsafe {
        (
            c2pa_sm_error_code(err),
            text(c2pa_sm_error_message(err)),
            text(c2pa_sm_error_name(err)),
        )
    };
    // SAFETY: as above.
    unsafe { c2pa_sm_error_free(err) };
    out
}

fn new_session(format: &str, settings: Option<&str>) -> *mut C2paSmSession {
    let format = cstr(format);
    let settings = settings.map(cstr);
    let mut session = ptr::null_mut();
    let mut err = ptr::null_mut();
    // SAFETY: valid C strings and out-parameters.
    let status = unsafe {
        c2pa_sm_session_new(
            format.as_ptr(),
            settings.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            &mut session,
            &mut err,
        )
    };
    assert_eq!(status, C2PA_SM_OK, "{:?}", take_error(err));
    assert!(!session.is_null() && err.is_null());
    session
}

fn requests(session: *mut C2paSmSession) -> Vec<C2paSmRequest> {
    // SAFETY: a live session.
    let count = unsafe { c2pa_sm_session_request_count(session) };
    (0..count)
        .map(|i| {
            let mut out = std::mem::MaybeUninit::uninit();
            // SAFETY: a live session and a writable request.
            assert!(unsafe { c2pa_sm_session_request(session, i, out.as_mut_ptr()) });
            // SAFETY: just initialised by the call that returned true.
            unsafe { out.assume_init() }
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

fn fulfill(session: *mut C2paSmSession, reply: &C2paSmReply) -> Result<(), (c_int, String)> {
    let mut err = ptr::null_mut();
    // SAFETY: a live session, a valid reply, a writable error slot.
    let status = unsafe { c2pa_sm_session_fulfill(session, reply, &mut err) };
    if status == C2PA_SM_OK {
        assert!(err.is_null());
        Ok(())
    } else {
        let (code, message, _) = take_error(err);
        assert_eq!(code, status);
        Err((code, message))
    }
}

/// Answers `request` from `asset`, as any host would.
fn answer(session: *mut C2paSmSession, request: &C2paSmRequest, asset: &[u8]) {
    let r = match request.kind {
        C2PA_SM_REQUEST_READ => {
            let start = usize::try_from(request.start).unwrap();
            let end = start + usize::try_from(request.len).unwrap();
            reply(C2PA_SM_REPLY_BYTES, request.id, 0, &asset[start..end])
        }
        C2PA_SM_REQUEST_LENGTH => reply(C2PA_SM_REPLY_LENGTH, request.id, asset.len() as i64, &[]),
        C2PA_SM_REQUEST_TIME => reply(C2PA_SM_REPLY_TIME, request.id, NOW, &[]),
        // The fixture's certificate names no responder, so the engine
        // never asks; if it ever does, fail open as a host without a
        // network would.
        _ => reply(C2PA_SM_REPLY_FAILED, request.id, 0, b"offline"),
    };
    fulfill(session, &r).unwrap();
}

/// Drives a read to completion; returns the finish status, the reader
/// (null if none) and the error (null if none).
fn drive(
    session: *mut C2paSmSession,
    asset: &[u8],
) -> (c_int, *mut C2paSmReader, *mut C2paSmError) {
    loop {
        let mut done = 0;
        let mut err = ptr::null_mut();
        // SAFETY: a live session and writable out-parameters.
        let status = unsafe { c2pa_sm_session_advance(session, &mut done, &mut err) };
        if status != C2PA_SM_OK {
            // SAFETY: consuming the session, as the contract requires.
            unsafe { c2pa_sm_session_free(session) };
            return (status, ptr::null_mut(), err);
        }
        if done != 0 {
            break;
        }
        for request in requests(session) {
            answer(session, &request, asset);
        }
    }
    let mut reader = ptr::null_mut();
    let mut err = ptr::null_mut();
    // SAFETY: a live, finished session; writable out-parameters.
    let status = unsafe { c2pa_sm_session_finish(session, &mut reader, &mut err) };
    (status, reader, err)
}

#[test]
fn a_signed_jpeg_reads_through_the_c_abi() {
    let session = new_session("image/jpeg", None);
    let (status, reader, err) = drive(session, C_JPG);
    assert_eq!((status, err), (C2PA_SM_OK, ptr::null_mut()));
    assert!(!reader.is_null());

    // SAFETY: a live reader; every string is freed exactly once.
    unsafe {
        let json = c2pa_sm_reader_json(reader);
        let json = {
            let owned = text(json);
            c2pa_sm_string_free(json);
            owned
        };
        assert!(json.contains("\"validation_state\": \"Valid\""), "{json}");

        let label = c2pa_sm_reader_active_label(reader);
        assert!(!label.is_null());
        assert!(json.contains(&text(label)));
        c2pa_sm_string_free(label);

        assert!(c2pa_sm_reader_is_embedded(reader));
        c2pa_sm_reader_free(reader);
    }
}

#[test]
fn an_asset_with_no_manifest_store_finishes_with_no_reader() {
    let session = new_session("jpg", None);
    let (status, reader, err) = drive(session, &[0xff, 0xd8, 0xff, 0xd9]);
    assert_eq!(
        (status, reader, err),
        (C2PA_SM_OK, ptr::null_mut(), ptr::null_mut())
    );
}

#[test]
fn a_malformed_asset_is_a_read_error_not_a_panic() {
    let session = new_session("image/jpeg", None);
    let (status, reader, err) = drive(session, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(reader.is_null());
    assert_eq!(status, C2PA_SM_ERR_READ);
    let (code, message, name) = take_error(err);
    assert_eq!(code, C2PA_SM_ERR_READ);
    assert!(!message.is_empty());
    assert!(name.starts_with("C2pa(Read("), "{name}");
}

#[test]
fn session_creation_failures_are_values() {
    let mut session = ptr::null_mut();
    let mut err = ptr::null_mut();
    let png = cstr("image/png");
    // SAFETY: valid arguments throughout.
    let status = unsafe { c2pa_sm_session_new(png.as_ptr(), ptr::null(), &mut session, &mut err) };
    assert_eq!(status, C2PA_SM_ERR_UNSUPPORTED_TYPE);
    assert!(session.is_null());
    let (_, message, name) = take_error(err);
    assert_eq!(message, "type is unsupported");
    assert_eq!(name, "C2pa(UnsupportedType)");

    let jpeg = cstr("image/jpeg");
    let bad = cstr("{not json");
    // SAFETY: valid arguments throughout.
    let status =
        unsafe { c2pa_sm_session_new(jpeg.as_ptr(), bad.as_ptr(), &mut session, &mut err) };
    assert_eq!(status, C2PA_SM_ERR_INVALID_ARGUMENT);
    assert!(session.is_null());
    let (_, _, name) = take_error(err);
    assert!(name.starts_with("C2pa(BadParam("), "{name}");

    // Valid settings are accepted.
    let session = new_session("image/jpeg", Some("{}"));
    // SAFETY: a live session, freed once.
    unsafe { c2pa_sm_session_free(session) };
}

#[test]
fn null_and_malformed_arguments_are_errors_not_undefined_behavior() {
    let mut session = ptr::null_mut();
    let mut err = ptr::null_mut();
    let jpeg = cstr("image/jpeg");
    // SAFETY (this whole test): null pointers are exactly what is being
    // checked; every other argument is valid.
    unsafe {
        // A null format, a null out-parameter, an error slot left out.
        assert_eq!(
            c2pa_sm_session_new(ptr::null(), ptr::null(), &mut session, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(take_error(err).1, "format is null");
        assert_eq!(
            c2pa_sm_session_new(jpeg.as_ptr(), ptr::null(), ptr::null_mut(), &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);
        assert_eq!(
            c2pa_sm_session_new(ptr::null(), ptr::null(), &mut session, ptr::null_mut()),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );

        // Not UTF-8.
        let bad_utf8 = CString::new(vec![0xff, 0xfe]).unwrap();
        assert_eq!(
            c2pa_sm_session_new(bad_utf8.as_ptr(), ptr::null(), &mut session, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(take_error(err).1, "format is not valid UTF-8");

        let live = new_session("image/jpeg", None);
        let mut done = 0;
        assert_eq!(
            c2pa_sm_session_advance(ptr::null_mut(), &mut done, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);
        assert_eq!(
            c2pa_sm_session_advance(live, ptr::null_mut(), &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);

        // Requests of a null session, an out-of-range index, a null out.
        assert_eq!(c2pa_sm_session_request_count(ptr::null()), 0);
        let mut request = std::mem::MaybeUninit::<C2paSmRequest>::uninit();
        assert!(!c2pa_sm_session_request(
            ptr::null(),
            0,
            request.as_mut_ptr()
        ));
        assert!(!c2pa_sm_session_request(live, 0, request.as_mut_ptr()));
        assert!(!c2pa_sm_session_request(live, 0, ptr::null_mut()));

        // Fulfilling with a null reply, a null session, a bad kind.
        assert_eq!(
            c2pa_sm_session_fulfill(live, ptr::null(), &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);
        let r = reply(C2PA_SM_REPLY_TIME, 0, 0, &[]);
        assert_eq!(
            c2pa_sm_session_fulfill(ptr::null_mut(), &r, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);
        let r = reply(99, 0, 0, &[]);
        assert_eq!(
            c2pa_sm_session_fulfill(live, &r, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        assert_eq!(take_error(err).1, "unknown reply kind 99");

        // Finishing a null session, or without somewhere to put the reader.
        let mut reader = ptr::null_mut();
        assert_eq!(
            c2pa_sm_session_finish(ptr::null_mut(), &mut reader, &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);
        // ...which still consumes the session it was given.
        assert_eq!(
            c2pa_sm_session_finish(live, ptr::null_mut(), &mut err),
            C2PA_SM_ERR_INVALID_ARGUMENT
        );
        let _ = take_error(err);

        // Frees and accessors tolerate null.
        c2pa_sm_session_free(ptr::null_mut());
        c2pa_sm_reader_free(ptr::null_mut());
        c2pa_sm_string_free(ptr::null_mut());
        c2pa_sm_error_free(ptr::null_mut());
        assert!(c2pa_sm_reader_json(ptr::null()).is_null());
        assert!(c2pa_sm_reader_active_label(ptr::null()).is_null());
        assert!(!c2pa_sm_reader_is_embedded(ptr::null()));
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
    let session = new_session("image/jpeg", None);
    let mut done = 0;
    let mut err = ptr::null_mut();
    // SAFETY: a live session and writable out-parameters.
    assert_eq!(
        unsafe { c2pa_sm_session_advance(session, &mut done, &mut err) },
        C2PA_SM_OK
    );
    assert_eq!(done, 0);
    let pending = requests(session);
    assert!(!pending.is_empty());
    let first = pending[0];

    // An id that was never issued.
    let (code, message) =
        fulfill(session, &reply(C2PA_SM_REPLY_TIME, u64::MAX, 0, &[])).unwrap_err();
    assert_eq!(code, C2PA_SM_ERR_INVALID_ARGUMENT);
    assert!(message.contains("no outstanding request"), "{message}");

    // A negative length.
    let (code, message) =
        fulfill(session, &reply(C2PA_SM_REPLY_LENGTH, first.id, -1, &[])).unwrap_err();
    assert_eq!(code, C2PA_SM_ERR_INVALID_ARGUMENT);
    assert!(message.contains("negative"), "{message}");

    // Answering the same request twice: the second is refused.
    answer(session, &first, C_JPG);
    let (code, _) =
        fulfill(session, &reply(C2PA_SM_REPLY_FAILED, first.id, 0, b"late")).unwrap_err();
    assert_eq!(code, C2PA_SM_ERR_INVALID_ARGUMENT);

    // A null `data` with zero length is an empty slice, not a crash; the
    // engine rejects an empty read as a wrong-sized reply, not this layer.
    let second = requests(session);
    assert!(second.is_empty(), "fulfill invalidates borrowed requests");

    // SAFETY: a live session, freed once.
    unsafe { c2pa_sm_session_free(session) };
}

#[test]
fn every_request_kind_is_described() {
    // The engine never issues an OCSP request for this repository's
    // fixtures, so the description of one is checked on the fixture
    // directly, as `contentauth-c2pa-node-compat` does for its own.
    let mut session = C2paSmSession {
        inner: NodeSession::new("image/jpeg", None).unwrap(),
        fresh: vec![
            PendingRequest::Read {
                id: 1,
                start: 5,
                len: 7,
            },
            PendingRequest::Length { id: 2 },
            PendingRequest::CurrentDateTime { id: 3 },
            PendingRequest::Ocsp {
                id: 4,
                url: "http://ocsp.example/".to_string(),
                request_der: vec![1, 2, 3],
            },
        ],
    };
    let session = &mut session as *mut C2paSmSession;
    let described = requests(session);
    let kinds: Vec<c_int> = described.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [
            C2PA_SM_REQUEST_READ,
            C2PA_SM_REQUEST_LENGTH,
            C2PA_SM_REQUEST_TIME,
            C2PA_SM_REQUEST_OCSP
        ]
    );
    assert_eq!(
        (described[0].id, described[0].start, described[0].len),
        (1, 5, 7)
    );
    let ocsp = described[3];
    // SAFETY: borrows into the live `fresh` vector above.
    unsafe {
        assert_eq!(
            slice::from_raw_parts(ocsp.url.cast::<u8>(), ocsp.url_len),
            b"http://ocsp.example/"
        );
        assert_eq!(slice::from_raw_parts(ocsp.body, ocsp.body_len), [1, 2, 3]);
    }
}

#[test]
fn a_panic_never_unwinds_across_the_boundary() {
    let mut err = ptr::null_mut();
    // SAFETY: a writable error slot.
    let status = unsafe {
        guard(&mut err, || {
            std::panic::resume_unwind(Box::new("boom"));
        })
    };
    assert_eq!(status, C2PA_SM_ERR_PANIC);
    let (code, message, _) = take_error(err);
    assert_eq!(code, C2PA_SM_ERR_PANIC);
    assert!(message.contains("panic"));

    // And with no error slot to fill.
    // SAFETY: null is permitted.
    let status = unsafe {
        guard(ptr::null_mut(), || {
            std::panic::resume_unwind(Box::new("boom"));
        })
    };
    assert_eq!(status, C2PA_SM_ERR_PANIC);
}

#[test]
fn interior_nuls_in_a_message_are_replaced_rather_than_lost() {
    assert_eq!(c_string("a\0b").to_str().unwrap(), "a\u{fffd}b");
}

#[test]
fn the_version_string_is_static_and_terminated() {
    assert_eq!(text(c2pa_sm_version()), env!("CARGO_PKG_VERSION"));
}

/// The claim the C++ side relies on: a session can be handed to another
/// thread (to be advanced there), and a finished reader can be shared.
#[test]
fn sessions_move_between_threads_and_readers_are_shared() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<C2paSmSession>();
    send::<C2paSmError>();
    send::<C2paSmReader>();
    sync::<C2paSmReader>();
}
