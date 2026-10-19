// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::{ffi::CString, ptr};

use contentauth_c2pa_c_api::*;
use contentauth_c2pa_sign_baseline::{fixtures::TEST_SIGNER_CERT, BASELINE_DEFINITION};

use crate::error::{assert_error, take_phase};

fn new_session() -> *mut C2paSmBuildSession {
    let format = CString::new("jpeg").unwrap();
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let alg = CString::new("es256").unwrap();
    let mut err = ptr::null_mut();
    let session = unsafe {
        c2pa_sm_build_new(
            format.as_ptr(),
            definition.as_ptr(),
            alg.as_ptr(),
            &TEST_SIGNER_CERT.as_ptr(),
            &TEST_SIGNER_CERT.len(),
            1,
            &mut err,
        )
    };
    assert!(!session.is_null());
    assert!(err.is_null());
    session
}

#[test]
fn constructor_rejects_missing_strings_and_certificate_arrays() {
    let format = CString::new("jpeg").unwrap();
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let alg = CString::new("es256").unwrap();
    for case in 0..5 {
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_build_new(
                if case == 0 {
                    ptr::null()
                } else {
                    format.as_ptr()
                },
                if case == 1 {
                    ptr::null()
                } else {
                    definition.as_ptr()
                },
                if case == 2 { ptr::null() } else { alg.as_ptr() },
                if case == 3 {
                    ptr::null()
                } else {
                    &TEST_SIGNER_CERT.as_ptr()
                },
                if case == 4 {
                    ptr::null()
                } else {
                    &TEST_SIGNER_CERT.len()
                },
                1,
                &mut err,
            )
        };
        assert!(session.is_null());
        assert_error(err, "NullParameter");
    }
    let mut err = ptr::null_mut();
    assert!(unsafe { c2pa_sm_build_phase(ptr::null_mut(), &mut err) }.is_null());
    assert_error(err, "NullParameter");
}

#[test]
fn constructor_rejects_non_utf8_strings() {
    let format = CString::new("jpeg").unwrap();
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let alg = CString::new("es256").unwrap();
    let invalid = CString::new(vec![0xff]).unwrap();
    for case in 0..3 {
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_build_new(
                if case == 0 {
                    invalid.as_ptr()
                } else {
                    format.as_ptr()
                },
                if case == 1 {
                    invalid.as_ptr()
                } else {
                    definition.as_ptr()
                },
                if case == 2 {
                    invalid.as_ptr()
                } else {
                    alg.as_ptr()
                },
                &TEST_SIGNER_CERT.as_ptr(),
                &TEST_SIGNER_CERT.len(),
                1,
                &mut err,
            )
        };
        assert!(session.is_null());
        assert_error(
            err,
            match case {
                0 => "unsupported format",
                1 => "definition error",
                2 => "unsupported signing algorithm",
                _ => unreachable!(),
            },
        );
    }
}

#[test]
fn every_build_entry_point_rejects_a_null_session() {
    let mut requests = ptr::null();
    let mut count = 0;
    let mut manifest = ptr::null_mut();
    let mut len = 0;
    let mut exclusions = ptr::null_mut();
    let message = CString::new("host failed").unwrap();
    for case in 0..8 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_build_advance(ptr::null_mut(), &mut requests, &mut count, &mut err),
                1 => c2pa_sm_build_fulfill_bytes(ptr::null_mut(), 0, [0].as_ptr(), 1, &mut err),
                2 => c2pa_sm_build_fulfill_length(ptr::null_mut(), 0, 1, &mut err),
                3 => c2pa_sm_build_fulfill_written(ptr::null_mut(), 0, &mut err),
                4 => c2pa_sm_build_fulfill_signature(ptr::null_mut(), 0, [0].as_ptr(), 1, &mut err),
                5 => c2pa_sm_build_fulfill_timestamp(ptr::null_mut(), 0, [0].as_ptr(), 1, &mut err),
                6 => c2pa_sm_build_fulfill_failed(ptr::null_mut(), 0, message.as_ptr(), &mut err),
                7 => c2pa_sm_build_finish(
                    ptr::null_mut(),
                    &mut manifest,
                    &mut len,
                    &mut exclusions,
                    &mut count,
                    &mut err,
                ),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1, "case {case}");
        assert_error(err, "NullParameter");
    }
    let mut err = ptr::null_mut();
    assert!(unsafe { c2pa_sm_exclusions_data(ptr::null_mut(), &mut err) }.is_null());
    assert_error(err, "NullParameter");
}

#[test]
fn invalid_build_outputs_do_not_consume_the_session() {
    let session = new_session();
    let mut requests = ptr::null();
    let mut count = 0;
    let mut manifest = ptr::null_mut();
    let mut len = 0;
    let mut exclusions = ptr::null_mut();
    for case in 0..6 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_build_advance(session, ptr::null_mut(), &mut count, &mut err),
                1 => c2pa_sm_build_advance(session, &mut requests, ptr::null_mut(), &mut err),
                2..=5 => c2pa_sm_build_finish(
                    session,
                    if case == 2 {
                        ptr::null_mut()
                    } else {
                        &mut manifest
                    },
                    if case == 3 { ptr::null_mut() } else { &mut len },
                    if case == 4 {
                        ptr::null_mut()
                    } else {
                        &mut exclusions
                    },
                    if case == 5 {
                        ptr::null_mut()
                    } else {
                        &mut count
                    },
                    &mut err,
                ),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1);
        assert_error(err, "NullParameter");
    }
    let mut err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_PENDING
    );
    assert!(count > 0);
    assert!(err.is_null());
    unsafe { c2pa_sm_build_free(session) };
}

#[test]
fn invalid_build_payloads_preserve_the_outstanding_request() {
    let session = new_session();
    let mut err = ptr::null_mut();
    let mut requests = ptr::null();
    let mut count = 0;
    assert_eq!(
        unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_PENDING
    );
    assert!(count > 0);
    let id = unsafe { (*requests).id };
    for case in 0..7 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_build_fulfill_bytes(session, id, ptr::null(), 1, &mut err),
                1 => c2pa_sm_build_fulfill_bytes(session, id, [0].as_ptr(), 0, &mut err),
                2 => c2pa_sm_build_fulfill_signature(session, id, ptr::null(), 1, &mut err),
                3 => c2pa_sm_build_fulfill_signature(session, id, [0].as_ptr(), 0, &mut err),
                4 => c2pa_sm_build_fulfill_timestamp(session, id, ptr::null(), 1, &mut err),
                5 => c2pa_sm_build_fulfill_timestamp(session, id, [0].as_ptr(), 0, &mut err),
                6 => c2pa_sm_build_fulfill_failed(session, id, ptr::null(), &mut err),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1);
        assert_error(
            err,
            if case == 1 || case == 3 || case == 5 {
                "InvalidBufferSize"
            } else {
                "NullParameter"
            },
        );
    }
    let message = CString::new("build cancelled").unwrap();
    assert_eq!(
        unsafe { c2pa_sm_build_fulfill_failed(session, id, message.as_ptr(), &mut err) },
        0
    );
    assert!(err.is_null());
    assert_eq!(
        unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_ERROR
    );
    assert_error(err, "build cancelled");
    err = ptr::null_mut();
    assert_eq!(
        unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_ERROR
    );
    assert_error(err, "session failed on an earlier call");
    err = ptr::null_mut();
    let phase = take_phase(unsafe { c2pa_sm_build_phase(session, &mut err) });
    assert!(err.is_null());
    assert!(!phase.is_empty() && phase != "Finished", "{phase}");
    let mut manifest = ptr::null_mut();
    let mut len = 0;
    let mut exclusions = ptr::null_mut();
    err = ptr::null_mut();
    assert_eq!(
        unsafe {
            c2pa_sm_build_finish(
                session,
                &mut manifest,
                &mut len,
                &mut exclusions,
                &mut count,
                &mut err,
            )
        },
        -1
    );
    assert_error(err, "session failed on an earlier call");
    err = ptr::null_mut();
    assert_eq!(
        take_phase(unsafe { c2pa_sm_build_phase(session, &mut err) }),
        "Finished"
    );
    assert!(manifest.is_null());
    assert!(exclusions.is_null());
    assert_eq!(len, 0);
    unsafe { c2pa_sm_build_free(session) };
}

#[test]
fn unknown_build_ids_are_rejected_by_every_fulfillment() {
    let session = new_session();
    let message = CString::new("host failed").unwrap();
    for case in 0..6 {
        let mut err = ptr::null_mut();
        let rc = unsafe {
            match case {
                0 => c2pa_sm_build_fulfill_bytes(session, u64::MAX, [0].as_ptr(), 1, &mut err),
                1 => c2pa_sm_build_fulfill_length(session, u64::MAX, 1, &mut err),
                2 => c2pa_sm_build_fulfill_written(session, u64::MAX, &mut err),
                3 => c2pa_sm_build_fulfill_signature(session, u64::MAX, [0].as_ptr(), 1, &mut err),
                4 => c2pa_sm_build_fulfill_timestamp(session, u64::MAX, [0].as_ptr(), 1, &mut err),
                5 => c2pa_sm_build_fulfill_failed(session, u64::MAX, message.as_ptr(), &mut err),
                _ => unreachable!(),
            }
        };
        assert_eq!(rc, -1);
        assert_error(err, "no outstanding build request");
    }
    unsafe { c2pa_sm_build_free(session) };
}

#[test]
fn finishing_before_completion_returns_no_allocations_and_is_terminal() {
    let session = new_session();
    let mut manifest = ptr::null_mut();
    let mut len = 0;
    let mut exclusions = ptr::null_mut();
    let mut count = 0;
    for expected in [
        "session has not reached a terminal state",
        "already been finished",
    ] {
        let mut err = ptr::null_mut();
        assert_eq!(
            unsafe {
                c2pa_sm_build_finish(
                    session,
                    &mut manifest,
                    &mut len,
                    &mut exclusions,
                    &mut count,
                    &mut err,
                )
            },
            -1
        );
        assert_error(err, expected);
        assert!(manifest.is_null());
        assert!(exclusions.is_null());
        assert_eq!(len, 0);
        assert_eq!(count, 0);
    }
    unsafe { c2pa_sm_build_free(session) };
}
