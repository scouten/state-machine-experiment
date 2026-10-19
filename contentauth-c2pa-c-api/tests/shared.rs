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

//! Feature-independent allocation cleanup.

use std::{ffi::CStr, ptr};

use contentauth_c2pa_c_api::c2pa_sm_string_free;

#[test]
fn test_shared_string_cleanup() {
    let string = cimpl::to_c_string("shared allocation".to_owned());
    assert!(!string.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(string) }.to_bytes(),
        b"shared allocation"
    );
    unsafe {
        c2pa_sm_string_free(string);
        c2pa_sm_string_free(ptr::null_mut());
    }
}
