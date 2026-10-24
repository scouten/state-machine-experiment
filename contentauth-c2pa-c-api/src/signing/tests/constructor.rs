// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! Session construction: strings, formats and certificate chains.
use super::*;

#[test]
fn c_api_constructor_scenarios_validate_each_string_with_valid_companion_fields() {
    let def = CString::new(BASELINE_DEFINITION).unwrap();
    let cert = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    for (d, f, a) in [
        (def.as_ptr(), c"\xff".as_ptr(), c"es256".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), c"\xff".as_ptr()),
        (def.as_ptr(), c"jpeg".as_ptr(), c"unsupported".as_ptr()),
    ] {
        let mut s = ptr::null_mut();
        unsafe { invalid(|e| c2pa_sm_build_session_new(d, f, a, &cert, 1, &mut s, e)) };
        assert!(s.is_null());
    }
}

#[test]
fn build_session_phase_is_returned_as_an_owned_string() {
    let build = Build::new(BASELINE_DEFINITION);
    let phase = unsafe { c2pa_sm_build_session_phase(build.0) };
    assert!(!phase.is_null());
    assert!(unsafe { CStr::from_ptr(phase) }
        .to_str()
        .unwrap()
        .contains("Building"));
    unsafe { c2pa_sm_string_free(phase) };
}

#[test]
fn build_format_aliases_select_registered_handlers() {
    let def = CString::new(BASELINE_DEFINITION).unwrap();
    let cert = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    for format in [
        "image/jpeg",
        "jpeg",
        "jpg",
        "JPEG",
        "image/jpg",
        "image/tiff",
        "tiff",
        "tif",
        "dng",
        "image/dng",
        "image/x-adobe-dng",
        "image/png",
    ] {
        let format = CString::new(format).unwrap();
        let mut s = ptr::null_mut();
        let mut e = ptr::null_mut();
        let code = unsafe {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                format.as_ptr(),
                c"es256".as_ptr(),
                &cert,
                1,
                &mut s,
                &mut e,
            )
        };
        if format.to_bytes() == b"image/png" {
            assert_eq!(code, 2);
            assert!(s.is_null());
            result(code, e).unwrap_err();
        } else {
            result(code, e).unwrap();
            assert!(!s.is_null());
            assert_eq!(unsafe { c2pa_sm_build_session_free(s, ptr::null_mut()) }, 0);
        }
    }
}
#[test]
fn certificate_arrays_reject_null_misaligned_and_oversized_inputs() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let storage = [C2paSmBuffer::borrowed(TEST_SIGNER_CERT); 2];
    let misaligned = unsafe { storage.as_ptr().cast::<u8>().add(1) }.cast::<C2paSmBuffer>();
    assert!(!misaligned.is_aligned());
    for (certs, count) in [
        (ptr::null(), 1),
        (misaligned, 1),
        (storage.as_ptr(), usize::MAX),
    ] {
        let mut session = ptr::dangling_mut();
        unsafe {
            invalid(|error| {
                c2pa_sm_build_session_new(
                    definition.as_ptr(),
                    c"jpeg".as_ptr(),
                    c"es256".as_ptr(),
                    certs,
                    count,
                    &mut session,
                    error,
                )
            })
        };
        assert!(session.is_null());
    }
}
#[test]
fn empty_certificate_chain_and_entries_are_rejected_at_construction() {
    let def = CString::new(BASELINE_DEFINITION).unwrap();
    for (cert, count) in [
        (C2paSmBuffer::default(), 0),
        (C2paSmBuffer::default(), 1),
        (
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            1,
        ),
        (
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: 0,
            },
            1,
        ),
        (
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
            1,
        ),
    ] {
        let mut s = ptr::null_mut();
        unsafe {
            invalid(|e| {
                c2pa_sm_build_session_new(
                    def.as_ptr(),
                    c"jpeg".as_ptr(),
                    c"es256".as_ptr(),
                    &cert,
                    count,
                    &mut s,
                    e,
                )
            })
        };
        assert!(s.is_null());
    }
    for certs in [
        [
            C2paSmBuffer::borrowed(TEST_SIGNER_CERT),
            C2paSmBuffer::default(),
        ],
        [
            C2paSmBuffer::default(),
            C2paSmBuffer::borrowed(TEST_SIGNER_CERT),
        ],
    ] {
        let mut s = ptr::dangling_mut();
        unsafe {
            invalid(|e| {
                c2pa_sm_build_session_new(
                    def.as_ptr(),
                    c"jpeg".as_ptr(),
                    c"es256".as_ptr(),
                    certs.as_ptr(),
                    certs.len(),
                    &mut s,
                    e,
                )
            })
        };
        assert!(s.is_null());
    }
}
