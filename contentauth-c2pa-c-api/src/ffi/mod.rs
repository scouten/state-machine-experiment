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
