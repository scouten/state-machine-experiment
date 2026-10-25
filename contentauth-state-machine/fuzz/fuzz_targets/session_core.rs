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

//! Fuzzes `SessionCore` (and the `RequestTracker` beneath it): arbitrary
//! bytes decode to a script of issue / fulfill / take / mark calls, many of
//! them illegal, checked against a reference model after every step.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/model.rs"]
mod model;

fuzz_target!(|data: &[u8]| {
    model::run_core(&model::decode_core(data));
});
