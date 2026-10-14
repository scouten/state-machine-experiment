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

//! C FFI exports, using cimpl for pointer validation and owned allocations.

use std::{
    ffi::{c_char, c_void},
    panic::{catch_unwind, AssertUnwindSafe},
};

use crate::error::Error;

#[cfg(feature = "build")]
mod build;
#[cfg(feature = "read")]
mod read;

#[cfg(feature = "build")]
pub use build::*;
#[cfg(feature = "read")]
pub use read::*;

#[cfg(any(feature = "read", feature = "build"))]
fn store_error(err_out: *mut *mut c_char, message: &str) {
    if !err_out.is_null() {
        let message = cimpl::to_c_string(message.to_owned());
        // SAFETY: the caller guarantees a valid writable output pointer when non-null.
        unsafe { *err_out = message };
    }
}

#[cfg(any(feature = "read", feature = "build"))]
fn ffi_call<T>(err_out: *mut *mut c_char, fallback: T, f: impl FnOnce() -> T) -> T {
    let _ = cimpl::Error::take_last();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => {
            if let Some(error) = cimpl::Error::take_last() {
                store_error(err_out, error.message());
            }
            value
        }
        Err(_) => {
            cimpl::Error::from(Error::Panic(
                "panic caught at the C ABI boundary".to_owned(),
            ))
            .set_last();
            if let Some(error) = cimpl::Error::take_last() {
                store_error(err_out, error.message());
            }
            fallback
        }
    }
}

fn ffi_call_without_error_output(f: impl FnOnce()) {
    let _ = cimpl::Error::take_last();
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        cimpl::Error::from(Error::Panic(
            "panic caught at the C ABI boundary".to_owned(),
        ))
        .set_last();
    }
}

/// Frees a string allocated by this library.
///
/// # Safety
/// `string` must be null or an allocation returned by this library.
#[no_mangle]
pub unsafe extern "C" fn c2pa_sm_string_free(string: *mut c_char) {
    ffi_call_without_error_output(|| {
        if !string.is_null() {
            let _ = cimpl::cimpl_free(string.cast::<c_void>());
        }
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    #[cfg(any(feature = "read", feature = "build"))]
    #[test]
    fn panics_return_the_fallback_and_a_tracked_error() {
        let mut error = std::ptr::null_mut();
        let result = ffi_call(&mut error, -7, || panic!("test boundary panic"));
        assert_eq!(result, -7);
        assert!(!error.is_null());
        let message = unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy();
        assert!(message.contains("panic caught at the C ABI boundary"));
        unsafe { c2pa_sm_string_free(error) };
        assert!(cimpl::Error::take_last().is_none());
    }

    #[cfg(any(feature = "read", feature = "build"))]
    #[test]
    fn an_error_output_is_optional_and_stale_errors_are_cleared() {
        cimpl::Error::other("stale error").set_last();
        let mut error = std::ptr::null_mut();
        assert_eq!(ffi_call(&mut error, -1, || 3), 3);
        assert!(error.is_null());
        assert_eq!(
            ffi_call(std::ptr::null_mut(), -1, || {
                cimpl::Error::other("current error").set_last();
                -1
            }),
            -1
        );
        assert!(cimpl::Error::take_last().is_none());
    }

    #[test]
    fn panics_without_an_output_are_recorded_as_last_error() {
        ffi_call_without_error_output(|| panic!("test cleanup panic"));
        let error = cimpl::Error::take_last();
        assert!(error.is_some());
        assert!(error
            .as_ref()
            .is_some_and(|error| error.message().contains("panic caught")));
    }
}
