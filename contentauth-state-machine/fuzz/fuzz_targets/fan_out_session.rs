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

//! Fuzzes a complete `Session` through the public `advance` / `fulfill` /
//! `outstanding_requests` / `finish` contract, with a host that replies
//! out of order, with the wrong payload, to IDs it was never given, and
//! after the session has finished or failed.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/model.rs"]
mod model;

fuzz_target!(|data: &[u8]| {
    model::run_session(&model::decode_session(data));
});
