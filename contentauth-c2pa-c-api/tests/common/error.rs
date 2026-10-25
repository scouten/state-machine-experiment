// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::ffi::{c_char, CStr};

pub fn assert_error(error: *mut c_char, expected: &str) {
    assert!(!error.is_null(), "expected error containing {expected:?}");
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { contentauth_c2pa_c_api::c2pa_sm_string_free(error) };
    assert!(message.contains(expected), "{message}");
}

/// Takes ownership of a phase string returned by `c2pa_sm_*_phase`.
pub fn take_phase(phase: *mut c_char) -> String {
    assert!(!phase.is_null(), "expected a phase");
    let text = unsafe { CStr::from_ptr(phase) }
        .to_string_lossy()
        .into_owned();
    unsafe { contentauth_c2pa_c_api::c2pa_sm_string_free(phase) };
    text
}
