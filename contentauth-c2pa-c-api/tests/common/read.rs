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

use std::{
    ffi::{CStr, CString},
    ptr, slice,
};

use base64::Engine as _;
use contentauth_c2pa_c_api::{
    c2pa_sm_read_advance, c2pa_sm_read_finish, c2pa_sm_read_free, c2pa_sm_read_fulfill_bytes,
    c2pa_sm_read_fulfill_length, c2pa_sm_read_fulfill_time, c2pa_sm_read_new, c2pa_sm_string_free,
    C2paSmReadRequest, C2PA_SM_READ_REQ_CURRENT_DATE_TIME, C2PA_SM_READ_REQ_LENGTH,
    C2PA_SM_READ_REQ_READ, C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_PENDING,
};
use contentauth_c2pa_sign_baseline::fixtures::TEST_SIGNER_CERT;

const FIXED_NOW: i64 = 1_800_000_000;

pub struct ReadOutput {
    pub has_manifest: bool,
    pub json: Option<String>,
}

pub fn read_signed_output(output_bytes: &[u8]) -> ReadOutput {
    let format = CString::new("image/jpeg").unwrap();
    let mut err_out = ptr::null_mut();
    let cert_base64 = base64::engine::general_purpose::STANDARD.encode(TEST_SIGNER_CERT);
    let cert_pem = format!("-----BEGIN CERTIFICATE-----\n{cert_base64}\n-----END CERTIFICATE-----");
    let trust_settings = serde_json::json!({
        "trust": {
            "anchors": [{
                "trust_anchors": cert_pem,
                "trust_kind": "manifest"
            }]
        }
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
    let json = if out_json.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(out_json) }
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };

    unsafe {
        c2pa_sm_string_free(out_json);
        c2pa_sm_read_free(read_session);
    }

    ReadOutput { has_manifest, json }
}
