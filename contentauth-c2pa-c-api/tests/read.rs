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

//! Read-only C API integration tests.

#![allow(clippy::unwrap_used)]

use std::{
    ffi::{CStr, CString},
    ptr, slice,
};

use contentauth_c2pa_c_api::{
    c2pa_sm_read_advance, c2pa_sm_read_finish, c2pa_sm_read_free, c2pa_sm_read_fulfill_bytes,
    c2pa_sm_read_fulfill_length, c2pa_sm_read_fulfill_time, c2pa_sm_read_new, c2pa_sm_string_free,
    C2paSmReadRequest, C2PA_SM_READ_REQ_CURRENT_DATE_TIME, C2PA_SM_READ_REQ_LENGTH,
    C2PA_SM_READ_REQ_OCSP, C2PA_SM_READ_REQ_READ, C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_PENDING,
};
use contentauth_c2pa_sign_baseline::fixtures::SOURCE_JPEG;

const FIXED_NOW: i64 = 1_800_000_000;

#[path = "common/error.rs"]
mod error;

#[path = "common/read_errors.rs"]
mod read_errors;

#[test]
fn invalid_settings_and_formats_return_owned_errors() {
    for (format, settings, expected) in [
        ("unknown", "", "unsupported format"),
        ("jpg", "{", "settings JSON"),
        ("jpg", r#"{"verify":{"ocsp_fetch":"yes"}}"#, "settings JSON"),
    ] {
        let format = CString::new(format).unwrap();
        let settings = CString::new(settings).unwrap();
        let mut err = ptr::null_mut();
        let session = unsafe { c2pa_sm_read_new(format.as_ptr(), settings.as_ptr(), &mut err) };
        assert!(session.is_null());
        error::assert_error(err, expected);
    }
}

#[test]
fn unknown_request_ids_and_host_failures_are_reported() {
    use contentauth_c2pa_c_api::{c2pa_sm_read_fulfill_failed, c2pa_sm_read_fulfill_ocsp};

    let format = CString::new("image/jpg").unwrap();
    let settings = CString::new("  ").unwrap();
    let mut err = ptr::null_mut();
    let session = unsafe { c2pa_sm_read_new(format.as_ptr(), settings.as_ptr(), &mut err) };
    assert!(!session.is_null());
    let message = CString::new("asset unavailable").unwrap();
    let results = [
        unsafe { c2pa_sm_read_fulfill_bytes(session, u64::MAX, [0].as_ptr(), 1, &mut err) },
        unsafe { c2pa_sm_read_fulfill_length(session, u64::MAX, 0, ptr::null_mut()) },
        unsafe { c2pa_sm_read_fulfill_time(session, u64::MAX, 0, ptr::null_mut()) },
        unsafe { c2pa_sm_read_fulfill_ocsp(session, u64::MAX, [0].as_ptr(), 1, ptr::null_mut()) },
        unsafe {
            c2pa_sm_read_fulfill_failed(session, u64::MAX, message.as_ptr(), ptr::null_mut())
        },
    ];
    assert!(results.iter().all(|rc| *rc == -1));
    error::assert_error(err, "no outstanding read request");
    err = ptr::null_mut();

    let mut requests = ptr::null();
    let mut count = 0;
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        C2PA_SM_STEP_PENDING
    );
    assert!(count > 0);
    let id = unsafe { (*requests).id };
    assert_eq!(
        unsafe { c2pa_sm_read_fulfill_failed(session, id, message.as_ptr(), &mut err) },
        0
    );
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        contentauth_c2pa_c_api::C2PA_SM_STEP_ERROR
    );
    error::assert_error(err, "asset unavailable");
    unsafe {
        c2pa_sm_read_free(session);
        c2pa_sm_read_free(ptr::null_mut());
    }
}

#[test]
fn finishing_a_manifest_free_jpeg_returns_no_json_and_cannot_be_repeated() {
    let format = CString::new("jpeg").unwrap();
    let mut err = ptr::null_mut();
    let session = unsafe { c2pa_sm_read_new(format.as_ptr(), ptr::null(), &mut err) };
    assert!(!session.is_null());
    let asset = [0xff, 0xd8, 0xff, 0xd9];
    loop {
        let mut requests = ptr::null();
        let mut count = 0;
        let step = unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) };
        assert!(err.is_null());
        if step == C2PA_SM_STEP_COMPLETE {
            break;
        }
        assert_eq!(step, C2PA_SM_STEP_PENDING);
        assert!(count > 0);
        for request in unsafe { slice::from_raw_parts(requests, count) } {
            let rc = match request.kind {
                C2PA_SM_READ_REQ_LENGTH => unsafe {
                    c2pa_sm_read_fulfill_length(session, request.id, asset.len() as u64, &mut err)
                },
                C2PA_SM_READ_REQ_READ => {
                    let bytes = &asset[request.start as usize..][..request.len as usize];
                    unsafe {
                        c2pa_sm_read_fulfill_bytes(
                            session,
                            request.id,
                            bytes.as_ptr(),
                            bytes.len(),
                            &mut err,
                        )
                    }
                }
                _ => panic!("unexpected manifest-free request"),
            };
            assert_eq!(rc, 0);
        }
    }
    let mut json = ptr::null_mut();
    let mut found = true;
    assert_eq!(
        unsafe { c2pa_sm_read_finish(session, &mut json, &mut found, &mut err) },
        0
    );
    assert!(!found);
    assert!(json.is_null());
    assert_eq!(
        unsafe { c2pa_sm_read_finish(session, &mut json, &mut found, &mut err) },
        -1
    );
    error::assert_error(err, "already been finished");
    err = ptr::null_mut();
    let mut requests = ptr::null();
    let mut count = 0;
    assert_eq!(
        unsafe { c2pa_sm_read_advance(session, &mut requests, &mut count, &mut err) },
        -1
    );
    error::assert_error(err, "already been finished");
    unsafe { c2pa_sm_read_free(session) };
}

#[test]
fn test_cimpl_error_is_returned_as_tracked_string() {
    let mut err_out: *mut std::ffi::c_char = ptr::null_mut();
    let session = unsafe { c2pa_sm_read_new(ptr::null(), ptr::null(), &mut err_out) };

    assert!(session.is_null());
    assert!(!err_out.is_null());
    let error = unsafe { CStr::from_ptr(err_out) }.to_string_lossy();
    assert!(error.contains("NullParameter"));

    unsafe { c2pa_sm_string_free(err_out) };
}

#[test]
fn test_c_api_read_existing_manifest() {
    let format = CString::new("image/jpeg").unwrap();
    let mut err_out: *mut std::ffi::c_char = ptr::null_mut();

    let session = unsafe { c2pa_sm_read_new(format.as_ptr(), ptr::null(), &mut err_out) };
    assert!(!session.is_null(), "failed to create read session");
    assert!(err_out.is_null(), "unexpected error creating session");

    loop {
        let mut req_ptr: *const C2paSmReadRequest = ptr::null();
        let mut req_count: usize = 0;
        let step =
            unsafe { c2pa_sm_read_advance(session, &mut req_ptr, &mut req_count, &mut err_out) };
        assert!(err_out.is_null());

        if step == C2PA_SM_STEP_COMPLETE {
            break;
        }
        assert_eq!(step, C2PA_SM_STEP_PENDING);
        assert!(req_count > 0);

        let requests = unsafe { slice::from_raw_parts(req_ptr, req_count) };
        for req in requests {
            match req.kind {
                C2PA_SM_READ_REQ_LENGTH => {
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_length(
                            session,
                            req.id,
                            SOURCE_JPEG.len() as u64,
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_READ_REQ_READ => {
                    let start = req.start as usize;
                    let end = (start + req.len as usize).min(SOURCE_JPEG.len());
                    let slice = &SOURCE_JPEG[start..end];
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_bytes(
                            session,
                            req.id,
                            slice.as_ptr(),
                            slice.len(),
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_READ_REQ_CURRENT_DATE_TIME => {
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_time(session, req.id, FIXED_NOW, &mut err_out)
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_READ_REQ_OCSP => {
                    panic!("did not expect OCSP request on baseline fixture");
                }
                _ => panic!("unexpected read request kind: {}", req.kind),
            }
        }
    }

    let mut out_json: *mut std::ffi::c_char = ptr::null_mut();
    let mut has_manifest: bool = false;
    let rc =
        unsafe { c2pa_sm_read_finish(session, &mut out_json, &mut has_manifest, &mut err_out) };
    assert_eq!(rc, 0);
    assert!(err_out.is_null());
    assert!(has_manifest);
    assert!(!out_json.is_null());

    let json_str = unsafe { CStr::from_ptr(out_json).to_str().unwrap() };
    assert!(json_str.contains("manifests"));

    unsafe {
        c2pa_sm_string_free(out_json);
        c2pa_sm_read_free(session);
    }
}
