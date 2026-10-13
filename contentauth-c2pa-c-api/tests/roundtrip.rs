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

use contentauth_c2pa_sign_baseline::BASELINE_DEFINITION;

#[path = "common/build.rs"]
mod build_host;
#[path = "common/read.rs"]
mod read_host;

#[test]
fn build_and_read_roundtrip() {
    let output = build_host::build_signed_asset();
    assert!(!output.manifest.is_empty());
    assert!(!output.exclusions.is_empty());

    let report = read_host::read_signed_output(&output.asset);
    assert!(report.has_manifest);
    let json = report.json.expect("signed asset has a manifest report");
    let store: serde_json::Value = serde_json::from_str(&json).expect("valid report JSON");
    let definition: serde_json::Value =
        serde_json::from_str(BASELINE_DEFINITION).expect("valid baseline definition");

    assert_eq!(store["validation_state"], "Trusted");
    assert_eq!(store["active_manifest"], definition["label"]);
    let manifests = store["manifests"].as_object().expect("manifest map");
    assert_eq!(manifests.len(), 1);
    let label = definition["label"].as_str().expect("definition label");
    let manifest = manifests.get(label).expect("active manifest in store");
    assert_eq!(manifest["label"], definition["label"]);
    assert_eq!(manifest["title"], definition["title"]);
    assert_eq!(manifest["instance_id"], definition["instance_id"]);
    assert_eq!(manifest["claim_version"], 2);
    let assertions = manifest["assertions"].as_array().expect("assertion labels");
    assert!(assertions.iter().any(|label| label == "c2pa.actions.v2"));
    assert!(assertions.iter().any(|label| label == "c2pa.hash.data"));
}
