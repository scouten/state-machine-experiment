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

//! End-to-end C API test requiring both workflows.

#[path = "common/build.rs"]
mod build_host;
#[path = "common/read.rs"]
mod read_host;

#[test]
fn build_and_read_roundtrip() {
    let asset = build_host::build_signed_asset();
    read_host::read_signed_output(&asset);
}
