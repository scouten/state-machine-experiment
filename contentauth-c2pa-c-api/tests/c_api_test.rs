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

//! Integration tests exercising the C ABI directly: creating sessions,
//! driving the sans-I/O advance/fulfill/finish loop in pure Rust calling
//! extern "C" functions, and round-tripping signed assets.

#![allow(clippy::unwrap_used)]

use std::{ffi::CStr, ptr};
#[cfg(any(feature = "read", feature = "build"))]
use std::{ffi::CString, slice};

use contentauth_c2pa_c_api::c2pa_sm_string_free;
#[cfg(feature = "build")]
use contentauth_c2pa_c_api::{
    c2pa_sm_build_advance, c2pa_sm_build_finish, c2pa_sm_build_free, c2pa_sm_build_fulfill_bytes,
    c2pa_sm_build_fulfill_length, c2pa_sm_build_fulfill_signature, c2pa_sm_build_fulfill_written,
    c2pa_sm_build_new, c2pa_sm_bytes_free, c2pa_sm_exclusions_data, c2pa_sm_exclusions_free,
    C2paSmBuildRequest, C2paSmExclusionList, C2PA_SM_BUILD_REQ_LENGTH, C2PA_SM_BUILD_REQ_READ,
    C2PA_SM_BUILD_REQ_SIGN, C2PA_SM_BUILD_REQ_WRITE, C2PA_SM_STREAM_OUTPUT, C2PA_SM_STREAM_SOURCE,
};
#[cfg(feature = "read")]
use contentauth_c2pa_c_api::{
    c2pa_sm_read_advance, c2pa_sm_read_finish, c2pa_sm_read_free, c2pa_sm_read_fulfill_bytes,
    c2pa_sm_read_fulfill_length, c2pa_sm_read_fulfill_time, c2pa_sm_read_new, C2paSmReadRequest,
    C2PA_SM_READ_REQ_CURRENT_DATE_TIME, C2PA_SM_READ_REQ_LENGTH, C2PA_SM_READ_REQ_OCSP,
    C2PA_SM_READ_REQ_READ,
};
#[cfg(any(feature = "read", feature = "build"))]
use contentauth_c2pa_c_api::{C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_PENDING};
#[cfg(any(feature = "read", feature = "build"))]
use contentauth_c2pa_sign_baseline::fixtures::*;
#[cfg(feature = "build")]
use contentauth_c2pa_sign_baseline::BASELINE_DEFINITION;

#[cfg(feature = "read")]
const FIXED_NOW: i64 = 1_800_000_000;

#[test]
fn test_shared_string_cleanup() {
    let string = cimpl::to_c_string("shared allocation".to_owned());
    assert!(!string.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(string) }.to_bytes(),
        b"shared allocation"
    );
    unsafe {
        c2pa_sm_string_free(string);
        c2pa_sm_string_free(ptr::null_mut());
    }
}

#[cfg(feature = "read")]
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

#[cfg(feature = "read")]
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

#[cfg(feature = "build")]
#[test]
fn test_c_api_build_manifest() {
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .expect("valid test signer");

    let format = CString::new("image/jpeg").unwrap();
    let def_json = CString::new(BASELINE_DEFINITION).unwrap();
    let alg = CString::new("es256").unwrap();
    let cert_ptr = TEST_SIGNER_CERT.as_ptr();
    let cert_len = TEST_SIGNER_CERT.len();
    let certs_ptrs = [cert_ptr];
    let certs_lens = [cert_len];
    let mut err_out: *mut std::ffi::c_char = ptr::null_mut();

    let build_session = unsafe {
        c2pa_sm_build_new(
            format.as_ptr(),
            def_json.as_ptr(),
            alg.as_ptr(),
            certs_ptrs.as_ptr(),
            certs_lens.as_ptr(),
            1,
            &mut err_out,
        )
    };
    assert!(!build_session.is_null());
    assert!(err_out.is_null());

    let mut output_bytes: Vec<u8> = Vec::new();

    loop {
        let mut req_ptr: *const C2paSmBuildRequest = ptr::null();
        let mut req_count: usize = 0;
        let step = unsafe {
            c2pa_sm_build_advance(build_session, &mut req_ptr, &mut req_count, &mut err_out)
        };
        assert!(err_out.is_null());

        if step == C2PA_SM_STEP_COMPLETE {
            break;
        }
        assert_eq!(step, C2PA_SM_STEP_PENDING);
        assert!(req_count > 0);

        let requests = unsafe { slice::from_raw_parts(req_ptr, req_count) };
        for req in requests {
            match req.kind {
                C2PA_SM_BUILD_REQ_LENGTH => {
                    assert_eq!(req.stream, C2PA_SM_STREAM_SOURCE);
                    let rc = unsafe {
                        c2pa_sm_build_fulfill_length(
                            build_session,
                            req.id,
                            SOURCE_JPEG.len() as u64,
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_BUILD_REQ_READ => {
                    let buf = match req.stream {
                        C2PA_SM_STREAM_SOURCE => SOURCE_JPEG,
                        C2PA_SM_STREAM_OUTPUT => &output_bytes[..],
                        _ => panic!("unknown stream: {}", req.stream),
                    };
                    let start = req.offset as usize;
                    let end = (start + req.len as usize).min(buf.len());
                    let slice = &buf[start..end];
                    let rc = unsafe {
                        c2pa_sm_build_fulfill_bytes(
                            build_session,
                            req.id,
                            slice.as_ptr(),
                            slice.len(),
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_BUILD_REQ_WRITE => {
                    assert_eq!(req.stream, C2PA_SM_STREAM_OUTPUT);
                    let start = req.offset as usize;
                    let end = start + req.len as usize;
                    if output_bytes.len() < end {
                        output_bytes.resize(end, 0);
                    }
                    let slice_to_write =
                        unsafe { slice::from_raw_parts(req.data, req.len as usize) };
                    output_bytes[start..end].copy_from_slice(slice_to_write);

                    let rc = unsafe {
                        c2pa_sm_build_fulfill_written(build_session, req.id, &mut err_out)
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                C2PA_SM_BUILD_REQ_SIGN => {
                    let to_sign = unsafe { slice::from_raw_parts(req.data, req.data_len) };
                    let sig = signer.sign(to_sign).expect("signing succeeds");
                    let rc = unsafe {
                        c2pa_sm_build_fulfill_signature(
                            build_session,
                            req.id,
                            sig.as_ptr(),
                            sig.len(),
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                _ => panic!("unexpected build request: {}", req.kind),
            }
        }
    }

    let mut manifest_ptr: *mut u8 = ptr::null_mut();
    let mut manifest_len: usize = 0;
    let mut exclusions_ptr: *mut C2paSmExclusionList = ptr::null_mut();
    let mut exclusions_count: usize = 0;

    let rc = unsafe {
        c2pa_sm_build_finish(
            build_session,
            &mut manifest_ptr,
            &mut manifest_len,
            &mut exclusions_ptr,
            &mut exclusions_count,
            &mut err_out,
        )
    };
    assert_eq!(rc, 0);
    assert!(err_out.is_null());
    assert!(!manifest_ptr.is_null());
    assert!(manifest_len > 0);
    assert!(!exclusions_ptr.is_null());
    assert!(exclusions_count > 0);
    let exclusions_data = unsafe { c2pa_sm_exclusions_data(exclusions_ptr, &mut err_out) };
    assert!(err_out.is_null());
    assert!(!exclusions_data.is_null());
    assert!(
        unsafe { slice::from_raw_parts(exclusions_data, exclusions_count) }
            .iter()
            .all(|range| range.len > 0)
    );

    unsafe {
        c2pa_sm_bytes_free(manifest_ptr, manifest_len);
        c2pa_sm_exclusions_free(exclusions_ptr);
        c2pa_sm_build_free(build_session);
    }

    #[cfg(feature = "read")]
    read_signed_output(&output_bytes);
}

#[cfg(all(feature = "read", feature = "build"))]
fn read_signed_output(output_bytes: &[u8]) {
    let format = CString::new("image/jpeg").unwrap();
    let mut err_out = ptr::null_mut();
    let trust_settings = serde_json::json!({
        "trust_anchors": [TEST_SIGNER_CERT]
    });
    let trust_settings_json =
        CString::new(serde_json::to_string(&trust_settings).unwrap()).unwrap();

    let read_session =
        unsafe { c2pa_sm_read_new(format.as_ptr(), trust_settings_json.as_ptr(), &mut err_out) };
    assert!(!read_session.is_null());
    assert!(err_out.is_null());

    loop {
        let mut req_ptr: *const C2paSmReadRequest = ptr::null();
        let mut req_count: usize = 0;
        let step = unsafe {
            c2pa_sm_read_advance(read_session, &mut req_ptr, &mut req_count, &mut err_out)
        };
        assert!(err_out.is_null());

        if step == C2PA_SM_STEP_COMPLETE {
            break;
        }
        assert_eq!(step, C2PA_SM_STEP_PENDING);

        let requests = unsafe { slice::from_raw_parts(req_ptr, req_count) };
        for req in requests {
            match req.kind {
                C2PA_SM_READ_REQ_LENGTH => {
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_length(
                            read_session,
                            req.id,
                            output_bytes.len() as u64,
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                }
                C2PA_SM_READ_REQ_READ => {
                    let start = req.start as usize;
                    let end = (start + req.len as usize).min(output_bytes.len());
                    let slice = &output_bytes[start..end];
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_bytes(
                            read_session,
                            req.id,
                            slice.as_ptr(),
                            slice.len(),
                            &mut err_out,
                        )
                    };
                    assert_eq!(rc, 0);
                }
                C2PA_SM_READ_REQ_CURRENT_DATE_TIME => {
                    let rc = unsafe {
                        c2pa_sm_read_fulfill_time(read_session, req.id, FIXED_NOW, &mut err_out)
                    };
                    assert_eq!(rc, 0);
                    assert!(err_out.is_null());
                }
                _ => panic!("unexpected request kind: {}", req.kind),
            }
        }
    }

    let mut out_json: *mut std::ffi::c_char = ptr::null_mut();
    let mut has_manifest: bool = false;
    let rc = unsafe {
        c2pa_sm_read_finish(read_session, &mut out_json, &mut has_manifest, &mut err_out)
    };
    assert_eq!(rc, 0);
    assert!(has_manifest);
    assert!(!out_json.is_null());

    let json_str = unsafe { CStr::from_ptr(out_json).to_str().unwrap() };
    assert!(json_str.contains("baseline.jpg"));
    assert!(json_str.contains("urn:uuid:00000000-0000-4000-8000-000000000002"));

    unsafe {
        c2pa_sm_string_free(out_json);
        c2pa_sm_read_free(read_session);
    }
}
