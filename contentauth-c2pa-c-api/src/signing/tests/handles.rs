// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! Null, stale, wrong-type and busy handles are rejected without consuming
//! the objects that really own the storage.
use super::*;

#[test]
fn all_build_session_exports_reject_null_and_wrong_type_handles_without_consuming_results() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let mut h = Host::default();
    let report = h.drive(&mut b).unwrap();
    for bad in [ptr::null_mut(), report.0.cast()] {
        let mut done = 7;
        let mut n = 8;
        let mut r = C2paSmBuildRequest {
            id: 42,
            ..Default::default()
        };
        let mut out = ptr::dangling_mut();
        unsafe {
            invalid(|e| c2pa_sm_build_session_advance(bad, &mut done, &mut n, e));
            assert_eq!((done, n), (0, 0));
            invalid(|e| c2pa_sm_build_session_request(bad, 0, &mut r, e));
            assert_eq!(r.id, 0);
            invalid(|e| c2pa_sm_build_session_fulfill(bad, &C2paSmBuildReply::default(), e));
            invalid(|e| c2pa_sm_build_session_finish(bad, &mut out, e));
            assert!(out.is_null());
            if bad.is_null() {
                assert_eq!(c2pa_sm_build_session_free(bad, ptr::null_mut()), 0)
            } else {
                invalid(|e| c2pa_sm_build_session_free(bad, e));
            }
            let mut read = ptr::dangling_mut();
            let mut writable = C2paSmMutableBytes {
                data: ptr::dangling_mut(),
                len: 99,
            };
            invalid(|e| c2pa_sm_build_read_acquire(bad, 1, &mut read, &mut writable, e));
            assert!(read.is_null());
            assert!(writable.data.is_null());
            assert_eq!(writable.len, 0);
            let mut write = ptr::dangling_mut();
            let mut bytes = C2paSmBuffer {
                data: ptr::dangling(),
                len: 99,
            };
            invalid(|e| c2pa_sm_build_write_acquire(bad, 1, &mut write, &mut bytes, e));
            assert!(write.is_null());
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
            let mut completed = ptr::null_mut();
            invalid(|e| c2pa_sm_build_fulfill_read(bad, 1, &mut completed, e));
            assert!(completed.is_null());
        }
        assert!(report.view().manifest.len > 0);
    }
}
#[test]
fn read_lease_wrong_type_and_stale_handles_preserve_the_real_owners() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    let guard = cimpl::checkout_exclusive(b.0).unwrap();
    assert_eq!(
        b.acquire(r.id).err().unwrap().0,
        C2PA_SM_ERR_INVALID_ARGUMENT
    );
    drop(guard);
    let mut l = b.acquire(r.id).unwrap();
    unsafe {
        let mut wrong = b.0.cast();
        let mut output = ptr::dangling_mut();
        invalid(|e| c2pa_sm_read_seal(&mut wrong, 0, &mut output, e));
        assert_eq!(wrong, b.0.cast());
        assert!(output.is_null());
        let mut wrong = l.raw.cast();
        invalid(|e| c2pa_sm_completed_read_free(&mut wrong, e));
        assert_eq!(wrong, l.raw.cast());
        invalid(|e| c2pa_sm_build_fulfill_read(b.0, r.id, &mut wrong, e));
        assert_eq!(wrong, l.raw.cast());
    }
    let stale = l.raw;
    let mut c = l.seal(l.view.len).unwrap();
    assert!(l.raw.is_null());
    unsafe {
        let mut wrong = c.0.cast();
        invalid(|e| c2pa_sm_read_buffer_free(&mut wrong, e));
        assert_eq!(wrong, c.0.cast());
        let mut wrong = b.0.cast();
        invalid(|e| c2pa_sm_completed_read_free(&mut wrong, e));
        assert_eq!(wrong, b.0.cast());
        let mut stale = stale;
        let mut output = ptr::dangling_mut();
        invalid(|e| c2pa_sm_read_seal(&mut stale, 0, &mut output, e));
        assert!(!stale.is_null());
        assert!(output.is_null());
        invalid(|e| c2pa_sm_read_buffer_free(&mut stale, e));
        assert!(!stale.is_null());
        let old = c.0;
        assert_eq!(c2pa_sm_completed_read_free(&mut c.0, ptr::null_mut()), 0);
        assert!(c.0.is_null());
        let mut stale = old;
        invalid(|e| c2pa_sm_completed_read_free(&mut stale, e));
        assert_eq!(stale, old);
    }
    assert!(cimpl::checkout_exclusive(b.0).is_ok());
}
