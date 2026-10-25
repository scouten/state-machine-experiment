#![allow(clippy::unwrap_used, clippy::panic)]
use std::ffi::CStr;

use super::*;

#[test]
fn common_errors_are_tracked_typed_and_independent() {
    let mut error = ptr::null_mut();
    assert_eq!(
        unsafe { guard(&mut error, || Err(Failure::invalid("bad\0input"))) },
        1
    );
    let wrong = tracked(42_u64).unwrap();
    unsafe {
        assert_eq!(c2pa_sm_error_code(error), 1);
        assert_eq!(
            CStr::from_ptr(c2pa_sm_error_message(error))
                .to_str()
                .unwrap(),
            "bad\u{fffd}input"
        );
        assert_eq!(c2pa_sm_error_code(wrong.cast()), 1);
        assert_eq!(
            CStr::from_ptr(c2pa_sm_error_message(wrong.cast())).to_bytes(),
            b""
        );
        c2pa_sm_error_free(wrong.cast());
        assert_eq!(*cimpl::checkout_shared(wrong).unwrap(), 42);
        let borrowed = cimpl::checkout_shared(error).unwrap();
        c2pa_sm_error_free(error);
        assert!(cimpl::checkout_shared(error).is_ok());
        drop(borrowed);
        c2pa_sm_error_free(error);
        assert!(cimpl::checkout_shared(error).is_err());
        assert_eq!(CStr::from_ptr(c2pa_sm_error_name(error)).to_bytes(), b"");
        c2pa_sm_error_free(error);
        c2pa_sm_error_free(ptr::null_mut());
    }
    assert_eq!(cimpl::untrack_owned(wrong).unwrap(), 42);
}

#[test]
fn a_panic_never_unwinds_across_the_boundary() {
    let mut error = ptr::null_mut();
    assert_eq!(
        unsafe { guard(&mut error, || panic!("caught")) },
        C2PA_SM_ERR_PANIC
    );
    unsafe {
        assert_eq!(c2pa_sm_error_code(error), C2PA_SM_ERR_PANIC);
        assert_eq!(
            CStr::from_ptr(c2pa_sm_error_name(error)).to_bytes(),
            b"Panic"
        );
        assert!(CStr::from_ptr(c2pa_sm_error_message(error))
            .to_str()
            .unwrap()
            .contains("panic"));
        c2pa_sm_error_free(error);
    }
    assert_eq!(
        unsafe { guard(ptr::null_mut(), || panic!("caught")) },
        C2PA_SM_ERR_PANIC
    );
}

#[test]
fn interior_nuls_in_a_message_are_replaced_rather_than_lost() {
    assert_eq!(c_string("a\0b").to_str().unwrap(), "a\u{fffd}b");
}

#[test]
fn the_version_string_is_static_and_terminated() {
    assert_eq!(c2pa_sm_version(), c2pa_sm_version());
    assert_eq!(
        unsafe { CStr::from_ptr(c2pa_sm_version()) }
            .to_str()
            .unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    unsafe {
        c2pa_sm_string_free(ptr::null_mut());
        c2pa_sm_string_free(c2pa_sm_version().cast_mut());
        assert_eq!(c2pa_sm_error_code(ptr::null()), 1);
        assert_eq!(
            CStr::from_ptr(c2pa_sm_error_message(ptr::null())).to_bytes(),
            b""
        );
    }
}
