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
