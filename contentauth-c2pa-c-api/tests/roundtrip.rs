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

    let report = read_host::read_signed_output(
        &output.asset,
        contentauth_c2pa_sign_baseline::fixtures::TEST_SIGNER_CERT,
        None,
    );
    assert_eq!(report.ocsp_requests, 0);
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

#[test]
fn ocsp_responses_and_transport_failures_are_reported_through_the_c_abi() {
    let root = include_bytes!("fixtures/ocsp-root.der");
    let leaf = include_bytes!("fixtures/ocsp-leaf.der");
    let output = build_host::build_with_definition(BASELINE_DEFINITION, None, &[leaf, root]);
    for (reply, expected_reason) in [
        (Ok(&[0x30, 0x00][..]), "could not be authenticated"),
        (Err("OCSP transport unavailable"), "could not be reached"),
    ] {
        let report = read_host::read_signed_output(&output.asset, root, Some(reply));
        assert_eq!(report.ocsp_requests, 1);
        assert!(report.has_manifest);
        let json = report
            .json
            .expect("OCSP result must retain the manifest report");
        let store: serde_json::Value = serde_json::from_str(&json).expect("report JSON");
        assert_eq!(store["validation_state"], "Trusted");
        assert!(json.contains("signingCredential.ocsp.inaccessible"));
        assert!(json.contains(expected_reason), "{json}");
        assert!(!json.contains("signingCredential.ocsp.notRevoked"));
    }
}

#[test]
fn authenticated_ocsp_responses_distinguish_good_and_revoked_signers() {
    let root = include_bytes!("fixtures/ocsp-root.der");
    let leaf = include_bytes!("fixtures/ocsp-leaf.der");
    let output = build_host::build_with_definition(BASELINE_DEFINITION, None, &[leaf, root]);
    for (response, expected_state, expected_status) in [
        (
            &include_bytes!("fixtures/ocsp-good.der")[..],
            "Trusted",
            "signingCredential.ocsp.notRevoked",
        ),
        (
            &include_bytes!("fixtures/ocsp-revoked.der")[..],
            "Invalid",
            "signingCredential.ocsp.revoked",
        ),
    ] {
        let report = read_host::read_signed_output(&output.asset, root, Some(Ok(response)));
        assert_eq!(report.ocsp_requests, 1);
        assert!(report.has_manifest);
        let json = report.json.expect("signed asset has a manifest report");
        let store: serde_json::Value = serde_json::from_str(&json).expect("valid report JSON");
        assert_eq!(store["validation_state"], expected_state, "{json}");
        assert!(json.contains(expected_status), "{json}");
        assert!(
            !json.contains("signingCredential.ocsp.inaccessible"),
            "{json}"
        );
    }
}
