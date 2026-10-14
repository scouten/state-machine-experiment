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

#![allow(clippy::unwrap_used)]

use std::{ffi::CString, ptr, slice};

use contentauth_c2pa_c_api::{
    c2pa_sm_build_advance, c2pa_sm_build_finish, c2pa_sm_build_free, c2pa_sm_build_fulfill_bytes,
    c2pa_sm_build_fulfill_length, c2pa_sm_build_fulfill_signature, c2pa_sm_build_fulfill_timestamp,
    c2pa_sm_build_fulfill_written, c2pa_sm_build_new, c2pa_sm_bytes_free, c2pa_sm_exclusions_data,
    c2pa_sm_exclusions_free, C2paSmBuildRequest, C2paSmExclusion, C2paSmExclusionList,
    C2PA_SM_BUILD_REQ_LENGTH, C2PA_SM_BUILD_REQ_READ, C2PA_SM_BUILD_REQ_SIGN,
    C2PA_SM_BUILD_REQ_TIMESTAMP, C2PA_SM_BUILD_REQ_WRITE, C2PA_SM_STEP_COMPLETE,
    C2PA_SM_STEP_PENDING, C2PA_SM_STREAM_OUTPUT, C2PA_SM_STREAM_SOURCE,
};
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

pub struct BuildOutput {
    pub asset: Vec<u8>,
    pub manifest: Vec<u8>,
    pub exclusions: Vec<C2paSmExclusion>,
}

pub fn build_signed_asset() -> BuildOutput {
    build_with_definition(BASELINE_DEFINITION, None)
}

pub fn build_with_definition(definition: &str, timestamp_response: Option<&[u8]>) -> BuildOutput {
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .expect("valid test signer");

    let format = CString::new("image/jpeg").unwrap();
    let def_json = CString::new(definition).unwrap();
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
                C2PA_SM_BUILD_REQ_TIMESTAMP => {
                    assert!(!req.url.is_null());
                    let url = unsafe { std::ffi::CStr::from_ptr(req.url) }
                        .to_str()
                        .unwrap();
                    assert_eq!(url, "https://tsa.example/");
                    let request = unsafe { slice::from_raw_parts(req.data, req.data_len) };
                    assert_eq!(request[0], 0x30);
                    assert!(request.ends_with(&[0x01, 0x01, 0xff]));
                    let response = timestamp_response.expect("timestamp transport configured");
                    assert_eq!(
                        unsafe {
                            c2pa_sm_build_fulfill_timestamp(
                                build_session,
                                req.id,
                                response.as_ptr(),
                                response.len(),
                                &mut err_out,
                            )
                        },
                        0
                    );
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
    assert!(!exclusions_ptr.is_null());
    let exclusions_data = unsafe { c2pa_sm_exclusions_data(exclusions_ptr, &mut err_out) };
    assert!(err_out.is_null());
    assert!(!exclusions_data.is_null());
    let manifest = unsafe { slice::from_raw_parts(manifest_ptr, manifest_len) }.to_vec();
    let exclusions = unsafe { slice::from_raw_parts(exclusions_data, exclusions_count) }.to_vec();

    unsafe {
        c2pa_sm_bytes_free(manifest_ptr, manifest_len);
        c2pa_sm_exclusions_free(exclusions_ptr);
        c2pa_sm_build_free(build_session);
    }

    BuildOutput {
        asset: output_bytes,
        manifest,
        exclusions,
    }
}
