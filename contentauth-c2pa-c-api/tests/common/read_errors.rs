// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::{ffi::CString, ptr};

use contentauth_c2pa_c_api::*;

use crate::error::{assert_error, take_phase};

fn new_session() -> *mut C2paSmReadSession {
    let format = CString::new("jpeg").unwrap();
    let mut err = ptr::null_mut();
    let session = unsafe { c2pa_sm_read_new(format.as_ptr(), ptr::null(), &mut err) };
    assert!(!session.is_null());
    assert!(err.is_null());
    session
}

#[test]
fn constructor_rejects_non_utf8_format_and_settings() {
    let format = CString::new("jpeg").unwrap();
    let invalid = CString::new(vec![0xff]).unwrap();
    for invalid_format in [true, false] {
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_read_new(
                if invalid_format {
                    invalid.as_ptr()
                } else {
                    format.as_ptr()
                },
                if invalid_format {
                    ptr::null()
                } else {
                    invalid.as_ptr()
                },
                &mut err,
            )
        };
        assert!(session.is_null());
        assert_error(
            err,
            if invalid_format {
                "unsupported format"
            } else {
                "settings JSON"
            },
        );
    }
}

#[test]
fn every_read_entry_point_rejects_a_null_session() {
    let mut requests = ptr::null();
    let mut count = 0;
    let mut json = ptr::null_mut();
    let mut found = false;
    let message = CString::new("host failed").unwrap();
    for case in 0..7 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_read_advance(ptr::null_mut(), &mut requests, &mut count, &mut err),
                1 => c2pa_sm_read_fulfill_bytes(ptr::null_mut(), 0, [0].as_ptr(), 1, &mut err),
                2 => c2pa_sm_read_fulfill_length(ptr::null_mut(), 0, 1, &mut err),
                3 => c2pa_sm_read_fulfill_time(ptr::null_mut(), 0, 0, &mut err),
                4 => c2pa_sm_read_fulfill_ocsp(ptr::null_mut(), 0, [0].as_ptr(), 1, &mut err),
                5 => c2pa_sm_read_fulfill_failed(ptr::null_mut(), 0, message.as_ptr(), &mut err),
                6 => c2pa_sm_read_finish(ptr::null_mut(), &mut json, &mut found, &mut err),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1, "case {case}");
        assert_error(err, "NullParameter");
    }
    let mut err = ptr::null_mut();
    assert!(unsafe { c2pa_sm_read_phase(ptr::null_mut(), &mut err) }.is_null());
    assert_error(err, "NullParameter");
}

#[test]
fn invalid_read_outputs_do_not_consume_the_session() {
    let session = new_session();
    let mut requests = ptr::null();
    let mut count = 0;
    let mut json = ptr::null_mut();
    let mut found = false;
    for case in 0..4 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_read_advance(session, ptr::null_mut(), &mut count, &mut err),
                1 => c2pa_sm_read_advance(session, &mut requests, ptr::null_mut(), &mut err),
                2 => c2pa_sm_read_finish(session, ptr::null_mut(), &mut found, &mut err),
                3 => c2pa_sm_read_finish(session, &mut json, ptr::null_mut(), &mut err),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1);
        assert_error(err, "NullParameter");
    }
    let mut err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_PENDING
    );
    assert!(count > 0);
    assert!(err.is_null());
    unsafe { c2pa_sm_read_free(session) };
}

#[test]
fn invalid_read_payloads_preserve_the_outstanding_request() {
    let session = new_session();
    let mut err = ptr::null_mut();
    let mut requests = ptr::null();
    let mut count = 0;
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_PENDING
    );
    assert!(count > 0);
    let id = unsafe { (*requests).id };
    for case in 0..5 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_read_fulfill_bytes(session, id, ptr::null(), 1, &mut err),
                1 => c2pa_sm_read_fulfill_bytes(session, id, [0].as_ptr(), 0, &mut err),
                2 => c2pa_sm_read_fulfill_ocsp(session, id, ptr::null(), 1, &mut err),
                3 => c2pa_sm_read_fulfill_ocsp(session, id, [0].as_ptr(), 0, &mut err),
                4 => c2pa_sm_read_fulfill_failed(session, id, ptr::null(), &mut err),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1);
        assert_error(
            err,
            if case == 1 || case == 3 {
                "InvalidBufferSize"
            } else {
                "NullParameter"
            },
        );
    }
    let message = CString::new("read cancelled").unwrap();
    assert_eq!(
        unsafe { c2pa_sm_read_fulfill_failed(session, id, message.as_ptr(), &mut err) },
        0
    );
    assert!(err.is_null());
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_ERROR
    );
    assert_error(err, "read cancelled");
    err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_ERROR
    );
    assert_error(err, "session failed on an earlier call");
    err = ptr::null_mut();
    let phase = take_phase(unsafe { c2pa_sm_read_phase(session, &mut err) });
    assert!(err.is_null());
    assert!(!phase.is_empty() && phase != "Finished", "{phase}");
    let mut json = ptr::null_mut();
    let mut found = false;
    err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_read_finish(session, &mut json, &mut found, &mut err) },
        -1
    );
    assert_error(err, "session failed on an earlier call");
    err = ptr::null_mut();
    assert_eq!(
        take_phase(unsafe { c2pa_sm_read_phase(session, &mut err) }),
        "Finished"
    );
    assert!(json.is_null());
    assert!(!found);
    unsafe { c2pa_sm_read_free(session) };
}

#[test]
fn finishing_before_completion_returns_an_error_and_is_terminal() {
    let session = new_session();
    let mut json = ptr::null_mut();
    let mut found = false;
    let mut err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_read_finish(session, &mut json, &mut found, &mut err) },
        -1
    );
    assert_error(err, "session has not reached a terminal state");
    assert!(json.is_null());
    assert!(!found);
    err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_read_finish(session, &mut json, &mut found, &mut err) },
        -1
    );
    assert_error(err, "already been finished");
    unsafe { c2pa_sm_read_free(session) };
}
