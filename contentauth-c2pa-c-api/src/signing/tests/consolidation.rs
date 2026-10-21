// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.
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
    let certs = [
        C2paSmBuffer::borrowed(TEST_SIGNER_CERT),
        C2paSmBuffer::default(),
    ];
    let mut s = ptr::null_mut();
    unsafe {
        invalid(|e| {
            c2pa_sm_build_session_new(
                def.as_ptr(),
                c"jpeg".as_ptr(),
                c"es256".as_ptr(),
                certs.as_ptr(),
                2,
                &mut s,
                e,
            )
        })
    };
    assert!(s.is_null());
}
#[test]
fn c_api_unknown_build_ids_are_rejected_for_every_reply_kind() {
    let mut b = Build::new(BASELINE_DEFINITION);
    for kind in 0..=5 {
        assert_eq!(
            b.fulfill(C2paSmBuildReply {
                kind,
                id: u64::MAX,
                data: C2paSmBuffer::borrowed(b"host reply"),
                ..Default::default()
            })
            .unwrap_err()
            .0,
            1
        );
    }
    assert!(Host::default().drive(&mut b).unwrap().view().manifest.len > 0);
}
#[test]
fn c_api_malformed_payload_matrix_preserves_the_pending_build_request() {
    let mut b = Build::new(BASELINE_DEFINITION);
    assert_eq!(b.advance().unwrap(), (false, 1));
    let r = b.request(0).unwrap();
    for kind in [0, 3, 4, 5] {
        for data in [
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
        ] {
            assert_eq!(
                b.fulfill(C2paSmBuildReply {
                    kind,
                    id: r.id,
                    data,
                    ..Default::default()
                })
                .unwrap_err()
                .0,
                1
            );
        }
    }
    assert_eq!(b.advance().unwrap(), (false, 0));
    b.fulfill(C2paSmBuildReply {
        kind: 1,
        id: r.id,
        value: SOURCE_JPEG.len() as u64,
        ..Default::default()
    })
    .unwrap();
    assert!(Host::default().drive(&mut b).unwrap().view().manifest.len > 0);
}
#[test]
fn c_api_failed_build_remains_terminal_and_finish_returns_no_report() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    b.fulfill(C2paSmBuildReply {
        kind: 5,
        id: r.id,
        data: C2paSmBuffer::borrowed(b"cancelled"),
        ..Default::default()
    })
    .unwrap();
    for _ in 0..2 {
        assert_eq!(b.advance().unwrap_err().0, 6)
    }
    assert_eq!(b.finish().unwrap_err().0, 1);
    assert!(b.0.is_null());
}
#[test]
fn empty_copying_read_reply_is_accepted_then_rejected_by_engine_length_validation() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    assert!(r.len > 0);
    b.fulfill(C2paSmBuildReply {
        kind: 0,
        id: r.id,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(b.advance().unwrap_err().0, 6);
}
#[test]
fn c_api_short_form_timestamp_token_is_embedded_without_its_response_envelope() {
    let timestamp = vec![0x30, 10, 0x30, 3, 2, 1, 0, 0x30, 3, 2, 1, 42];
    let mut b = Build::new(&timestamp_definition());
    let mut h = Host {
        timestamp: timestamp.clone(),
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = h.drive(&mut b).unwrap();
    assert_eq!(h.seen[4], 1);
    let v = report.view();
    let m = unsafe { v.manifest.bytes().unwrap() };
    assert!(m
        .windows(timestamp[7..].len())
        .any(|w| w == &timestamp[7..]));
    assert!(!m.windows(timestamp.len()).any(|w| w == timestamp));
}
#[test]
fn c_api_returned_manifest_is_embedded_and_every_exclusion_is_nonempty_and_in_bounds() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let mut h = Host {
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = h.drive(&mut b).unwrap();
    let v = report.view();
    let m = unsafe { v.manifest.bytes().unwrap() };
    assert!(h.output.windows(m.len()).any(|w| w == m));
    let ex = unsafe { std::slice::from_raw_parts(v.exclusions, v.exclusion_count) };
    assert_eq!(ex.len(), 1);
    assert!(ex.iter().all(|r| r.len > 0
        && r.start
            .checked_add(r.len)
            .is_some_and(|end| end <= h.output.len() as u64)));
}
#[test]
fn all_build_session_exports_reject_null_and_wrong_type_handles_without_consuming_results() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let mut h = Host::default();
    let report = h.drive(&mut b).unwrap();
    for bad in [ptr::null_mut(), report.0.cast()] {
        let mut done = 7;
        let mut n = 8;
        let mut r = C2paSmBuildRequest::default();
        let mut out = ptr::null_mut();
        unsafe {
            invalid(|e| c2pa_sm_build_session_advance(bad, &mut done, &mut n, e));
            assert_eq!((done, n), (0, 0));
            invalid(|e| c2pa_sm_build_session_request(bad, 0, &mut r, e));
            invalid(|e| c2pa_sm_build_session_fulfill(bad, &C2paSmBuildReply::default(), e));
            invalid(|e| c2pa_sm_build_session_finish(bad, &mut out, e));
            assert!(out.is_null());
            if bad.is_null() {
                assert_eq!(c2pa_sm_build_session_free(bad, ptr::null_mut()), 0)
            } else {
                invalid(|e| c2pa_sm_build_session_free(bad, e));
            }
        }
        assert!(report.view().manifest.len > 0);
    }
}
#[test]
fn read_lease_wrong_type_and_stale_handles_preserve_the_real_owners() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    let mut l = b.acquire(r.id).unwrap();
    let stale = l.raw;
    let mut c = l.seal(l.view.len).unwrap();
    unsafe {
        let mut wrong = c.0.cast();
        invalid(|e| c2pa_sm_read_buffer_free(&mut wrong, e));
        assert_eq!(wrong, c.0.cast());
        let mut wrong = b.0.cast();
        invalid(|e| c2pa_sm_completed_read_free(&mut wrong, e));
        assert_eq!(wrong, b.0.cast());
        let mut stale = stale;
        invalid(|e| c2pa_sm_read_seal(&mut stale, 0, &mut ptr::null_mut(), e));
        let old = c.0;
        assert_eq!(c2pa_sm_completed_read_free(&mut c.0, ptr::null_mut()), 0);
        assert!(c.0.is_null());
        let mut stale = old;
        invalid(|e| c2pa_sm_completed_read_free(&mut stale, e));
        assert_eq!(stale, old);
    }
    assert!(cimpl::checkout_exclusive(b.0).is_ok());
}
