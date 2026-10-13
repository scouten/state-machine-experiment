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

//! Build-only C API integration test.

#[path = "common/build.rs"]
mod build_host;

#[test]
fn build_manifest() {
    let output = build_host::build_signed_asset();

    assert!(!output.asset.is_empty());
    assert!(!output.manifest.is_empty());
    assert!(
        output
            .asset
            .windows(output.manifest.len())
            .any(|bytes| bytes == output.manifest),
        "the returned manifest must be embedded in the output asset"
    );
    assert!(!output.exclusions.is_empty());
    for range in &output.exclusions {
        assert!(range.len > 0);
        assert!(range.start <= output.asset.len() as u64);
        assert!(range.len <= output.asset.len() as u64 - range.start);
    }
}
