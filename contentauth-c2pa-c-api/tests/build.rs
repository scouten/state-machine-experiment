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

//! Build-only C API integration tests.

#[path = "common/build.rs"]
mod build_host;

#[path = "common/error.rs"]
mod error;

#[test]
fn invalid_build_inputs_return_owned_errors() {
    use std::{ffi::CString, ptr};

    use contentauth_c2pa_c_api::c2pa_sm_build_new;
    use contentauth_c2pa_sign_baseline::{fixtures::TEST_SIGNER_CERT, BASELINE_DEFINITION};

    for (format, definition, algorithm, certificates, expected) in [
        (
            "jpeg",
            BASELINE_DEFINITION,
            "es256",
            false,
            "at least one certificate",
        ),
        (
            "bad",
            BASELINE_DEFINITION,
            "es256",
            true,
            "unsupported format",
        ),
        (
            "jpeg",
            BASELINE_DEFINITION,
            "bad",
            true,
            "unsupported signing algorithm",
        ),
        ("jpeg", "{", "es256", true, "definition"),
    ] {
        let format = CString::new(format).unwrap();
        let definition = CString::new(definition).unwrap();
        let algorithm = CString::new(algorithm).unwrap();
        let cert = TEST_SIGNER_CERT.as_ptr();
        let len = TEST_SIGNER_CERT.len();
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_build_new(
                format.as_ptr(),
                definition.as_ptr(),
                algorithm.as_ptr(),
                &cert,
                &len,
                usize::from(certificates),
                &mut err,
            )
        };
        assert!(session.is_null());
        error::assert_error(err, expected);
    }
    let format = CString::new("jpeg").unwrap();
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let algorithm = CString::new("es256").unwrap();
    for (cert, len) in [(ptr::null(), 1), (TEST_SIGNER_CERT.as_ptr(), 0)] {
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_build_new(
                format.as_ptr(),
                definition.as_ptr(),
                algorithm.as_ptr(),
                &cert,
                &len,
                1,
                &mut err,
            )
        };
        assert!(session.is_null());
        error::assert_error(err, "certificate 0 is invalid");
    }
}

#[test]
fn build_failures_and_invalid_timestamp_responses_are_reported() {
    use std::{ffi::CString, ptr};

    use contentauth_c2pa_c_api::*;
    use contentauth_c2pa_sign_baseline::{fixtures::TEST_SIGNER_CERT, BASELINE_DEFINITION};

    let format = CString::new("jpeg").unwrap();
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let algorithm = CString::new("es256").unwrap();
    let message = CString::new("source unavailable").unwrap();
    let cert = TEST_SIGNER_CERT.as_ptr();
    let len = TEST_SIGNER_CERT.len();
    for invalid_timestamp in [false, true] {
        let mut err = ptr::null_mut();
        let session = unsafe {
            c2pa_sm_build_new(
                format.as_ptr(),
                definition.as_ptr(),
                algorithm.as_ptr(),
                &cert,
                &len,
                1,
                &mut err,
            )
        };
        assert!(!session.is_null());
        assert_eq!(
            unsafe {
                c2pa_sm_build_fulfill_timestamp(session, u64::MAX, [0].as_ptr(), 1, &mut err)
            },
            -1
        );
        crate::error::assert_error(err, "no outstanding build request");
        err = ptr::null_mut();
        let mut requests = ptr::null();
        let mut count = 0;
        assert_eq!(
            unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
            C2PA_SM_STEP_PENDING
        );
        assert!(count > 0);
        let id = unsafe { (*requests).id };
        if invalid_timestamp {
            assert_eq!(
                unsafe { c2pa_sm_build_fulfill_timestamp(session, id, [0].as_ptr(), 1, &mut err) },
                -1
            );
            crate::error::assert_error(err, "invalid timestamp response");
        } else {
            assert_eq!(
                unsafe { c2pa_sm_build_fulfill_failed(session, id, message.as_ptr(), &mut err) },
                0
            );
            assert_eq!(
                unsafe { c2pa_sm_build_advance(session, &mut requests, &mut count, &mut err) },
                C2PA_SM_STEP_ERROR
            );
            crate::error::assert_error(err, "source unavailable");
        }
        unsafe { c2pa_sm_build_free(session) };
    }
    unsafe {
        c2pa_sm_build_free(ptr::null_mut());
        c2pa_sm_bytes_free(ptr::null_mut(), 0);
        c2pa_sm_exclusions_free(ptr::null_mut());
    }
}

#[test]
fn timestamp_request_and_response_cross_the_c_abi() {
    use contentauth_c2pa_sign_baseline::BASELINE_DEFINITION;

    let definition = BASELINE_DEFINITION.replace(
        "\"title\"",
        "\"tsa_url\": \"https://tsa.example/\", \"title\"",
    );
    // The adapter unwraps and embeds tokens; validating the TSA signature belongs to the reader.
    let response = [
        0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a,
    ];
    let output = build_host::build_with_definition(&definition, Some(&response));
    let token = &response[7..];
    assert!(output
        .manifest
        .windows(token.len())
        .any(|bytes| bytes == token));
}

#[test]
fn build_manifest() {
    let output = build_host::build_signed_asset();

    assert!(!output.asset.is_empty());
    assert!(!output.manifest.is_empty());
    assert!(
        output
            .asset
            .windows(output.manifest.len())
            .any(|bytes| bytes == output.manifest),
        "the returned manifest must be embedded in the output asset"
    );
    assert!(!output.exclusions.is_empty());
    for range in &output.exclusions {
        assert!(range.len > 0);
        assert!(range.start <= output.asset.len() as u64);
        assert!(range.len <= output.asset.len() as u64 - range.start);
    }
}
