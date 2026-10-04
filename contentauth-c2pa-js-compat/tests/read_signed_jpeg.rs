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

//! End to end, through this crate's c2pa-wasm-shaped surface only: a
//! manifest built and signed by `contentauth-c2pa-builder`, embedded into
//! a JPEG by `contentauth-c2pa-format-jpeg`, then read back through
//! `Reader::from_blob(format, blob, context_json, platform)` — the
//! `fromBlob` this crate exists to provide — and reported the way
//! c2pa-wasm's `activeLabel`/`manifestStore`/`activeManifest`/`json` do.
//!
//! The asset is an in-memory `Vec<u8>` `Blob` here, so every host future
//! resolves immediately; `tests/async_host.rs` is where the host is made
//! to genuinely suspend.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod support;

use contentauth_c2pa_js_compat::{
    C2paError, ClaimVersion, Context, Error, OfflinePlatform, Reader, ValidationState,
};
use contentauth_c2pa_reader::ReadSettings;
use support::{
    block_on, build_and_embed, pem_of, unsigned_jpeg, FixedClock, C_JPG, TEST_SIGNER_CERT,
};

#[test]
fn a_manifest_written_by_the_builder_reads_back_as_trusted_with_anchors_from_context_json() {
    let (_plan, asset) = build_and_embed(C_JPG);

    // Trust anchors arrive exactly as c2pa-web would pass them: as a PEM
    // bundle inside c2pa-rs settings JSON.
    let context_json = serde_json::json!({
        "trust": { "trust_anchors": pem_of(TEST_SIGNER_CERT) },
        "verify": { "ocsp_fetch": false },
    })
    .to_string();

    let reader = block_on(Reader::from_blob(
        "image/jpeg",
        &asset,
        Some(&context_json),
        &FixedClock,
    ))
    .expect("the asset just built should read back cleanly");

    assert_eq!(
        reader.active_label().as_deref(),
        Some("urn:uuid:test-manifest")
    );

    let store = reader.manifest_store();
    assert_eq!(store.validation_state, ValidationState::Trusted);
    assert_eq!(
        store.active_manifest.as_deref(),
        Some("urn:uuid:test-manifest")
    );
    assert_eq!(store.manifests.len(), 1);
    assert!(store
        .validation_status
        .iter()
        .any(|status| status.code == "claimSignature.validated"));

    let active = reader.active_manifest().expect("has an active manifest");
    assert_eq!(active.label, "urn:uuid:test-manifest");
    assert_eq!(active.title.as_deref(), Some("test.jpg"));
    // A v2 claim, which has no `dc:format`: its generator is one map.
    assert_eq!(active.format, None);
    assert_eq!(active.claim_version, ClaimVersion::V2);
    assert_eq!(active.claim_generator_info.len(), 1);
    assert_eq!(
        active.claim_generator_info[0].spec_version.as_deref(),
        Some("2.4.0")
    );
    assert_eq!(active.instance_id, "xmp:iid:test-instance");
    assert_eq!(active.assertions, ["c2pa.hash.data"]);
    // The builder writes structured `claim_generator_info`, not the legacy
    // free-form string, so this fixture has none to report.
    assert_eq!(active.claim_generator, None);
    assert_eq!(store.manifests["urn:uuid:test-manifest"], active);

    // `json()` is `manifestStore()` serialized, and c2pa-web's callers
    // parse it as such — check it field by field rather than as a
    // substring of the raw string.
    let json: serde_json::Value =
        serde_json::from_str(&reader.json()).expect("Reader::json produces valid JSON");
    assert_eq!(json["active_manifest"], "urn:uuid:test-manifest");
    assert_eq!(json["validation_state"], "Trusted");
    let manifest_json = &json["manifests"]["urn:uuid:test-manifest"];
    assert_eq!(manifest_json["label"], "urn:uuid:test-manifest");
    assert_eq!(manifest_json["title"], "test.jpg");
    assert_eq!(manifest_json["instance_id"], "xmp:iid:test-instance");
    assert_eq!(
        manifest_json["assertions"],
        serde_json::json!(["c2pa.hash.data"])
    );
    assert!(json["validation_status"]
        .as_array()
        .expect("validation_status is a JSON array")
        .iter()
        .any(|status| status["code"] == "claimSignature.validated"));
}

#[test]
fn without_context_json_the_same_manifest_reads_back_only_as_valid() {
    let (_plan, asset) = build_and_embed(C_JPG);

    let reader = block_on(Reader::from_blob("image/jpeg", &asset, None, &FixedClock))
        .expect("should still read and validate cleanly");

    assert_eq!(
        reader.manifest_store().validation_state,
        ValidationState::Valid
    );
    let json: serde_json::Value = serde_json::from_str(&reader.json()).unwrap();
    assert_eq!(json["validation_state"], "Valid");
}

#[test]
fn a_trust_uri_in_context_json_is_reported_as_the_trust_list_uri() {
    let (_plan, asset) = build_and_embed(C_JPG);

    let context_json = serde_json::json!({
        "trust": { "anchors": [{
            "trust_anchors": pem_of(TEST_SIGNER_CERT),
            "trust_kind": "manifest",
            "trust_uri": "https://example.com/signers",
        }] },
    })
    .to_string();

    let reader = block_on(Reader::from_blob(
        "image/jpeg",
        &asset,
        Some(&context_json),
        &FixedClock,
    ))
    .expect("reads cleanly");

    let store = reader.manifest_store();
    assert_eq!(store.validation_state, ValidationState::Trusted);

    let trusted = store
        .validation_status
        .iter()
        .find(|status| status.code == "signingCredential.trusted")
        .expect("a trusted status");
    assert_eq!(
        trusted.trust_list_uri.as_deref(),
        Some("https://example.com/signers")
    );
    assert!(store
        .validation_status
        .iter()
        .filter(|status| status.code != "signingCredential.trusted")
        .all(|status| status.trust_list_uri.is_none()));

    // As in c2pa-rs, the field is reachable but never serialized.
    assert!(!reader.json().contains("trust_list_uri"));
    assert!(!reader.json().contains("https://example.com/signers"));
}

#[test]
fn a_context_built_from_this_workspaces_own_settings_is_accepted_too() {
    let (_plan, asset) = build_and_embed(C_JPG);

    let context = Context::from_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        check_ocsp: false,
        ..ReadSettings::default()
    });
    let reader = block_on(Reader::from_blob_with_context(
        "jpg",
        &asset,
        context,
        &FixedClock,
    ))
    .expect("reads cleanly");

    assert_eq!(
        reader.manifest_store().validation_state,
        ValidationState::Trusted
    );
}

#[test]
fn a_real_c2pa_rs_signed_fixture_reports_its_claim_generator() {
    let reader = block_on(Reader::from_blob("jpeg", C_JPG, None, &FixedClock))
        .expect("C.jpg carries a real c2pa-rs-signed manifest");

    let active = reader.active_manifest().expect("has an active manifest");
    assert_eq!(
        active.claim_generator.as_deref(),
        Some("make_test_images/0.33.1 c2pa-rs/0.33.1")
    );
}

#[test]
fn the_offline_platform_reads_with_the_system_clock() {
    // `OfflinePlatform` is the one platform this crate ships for native
    // hosts; the fixture's certificates are valid today, so it should
    // agree with `FixedClock` on this asset.
    let reader = block_on(Reader::from_blob(
        "image/jpeg",
        C_JPG,
        None,
        &OfflinePlatform,
    ))
    .expect("C.jpg reads under the system clock");
    assert_eq!(
        reader.manifest_store().validation_state,
        ValidationState::Valid
    );
}

#[test]
fn a_tampered_asset_reads_back_as_invalid() {
    let (plan, mut asset) = build_and_embed(C_JPG);

    // Flip a byte inside the image's scan data, well clear of both the
    // manifest's own segments and the file's framing.
    let exclusion_end = (plan.exclusions[0].start + plan.exclusions[0].len) as usize;
    let offset = exclusion_end + (asset.len() - exclusion_end) / 2;
    asset[offset] ^= 0xff;

    let reader = block_on(Reader::from_blob("image/jpeg", &asset, None, &FixedClock))
        .expect("a tampered asset still reads, it just fails validation");

    let store = reader.manifest_store();
    assert_eq!(store.validation_state, ValidationState::Invalid);
    assert!(store
        .validation_status
        .iter()
        .any(|status| status.code == "assertion.dataHash.mismatch"));
}

#[test]
fn a_jpeg_with_no_manifest_store_is_jumbf_not_found_and_crosses_to_js_as_c2pa_web_expects() {
    let err = block_on(Reader::from_blob(
        "image/jpeg",
        &unsigned_jpeg(),
        None,
        &FixedClock,
    ))
    .expect_err("an unsigned JPEG carries no manifest store");

    assert!(
        matches!(err, Error::C2pa(C2paError::JumbfNotFound)),
        "{err:?}"
    );
    // The exact string c2pa-web's `reader.ts` matches to return `null`
    // rather than throw.
    assert_eq!(err.js_message(), "C2pa(JumbfNotFound)");
}

#[test]
fn a_format_no_handler_recognizes_is_unsupported_without_touching_the_blob() {
    let err = block_on(Reader::from_blob("image/png", C_JPG, None, &FixedClock))
        .expect_err("no handler recognizes PNG yet");
    assert!(
        matches!(err, Error::C2pa(C2paError::UnsupportedType)),
        "{err:?}"
    );
}

#[test]
fn unparseable_context_json_is_a_bad_param() {
    let err = block_on(Reader::from_blob(
        "image/jpeg",
        C_JPG,
        Some("not json"),
        &FixedClock,
    ))
    .expect_err("settings that cannot be parsed are refused");
    assert!(
        matches!(err, Error::C2pa(C2paError::BadParam(_))),
        "{err:?}"
    );
}

#[test]
fn a_jpeg_format_with_unparseable_content_surfaces_as_a_read_error() {
    let err = block_on(Reader::from_blob(
        "image/jpeg",
        b"this is not a JPEG at all".as_slice(),
        None,
        &FixedClock,
    ))
    .expect_err("no SOI marker, so the handler can't locate anything");
    assert!(matches!(err, Error::C2pa(C2paError::Read(_))), "{err:?}");
}

#[test]
fn supported_formats_lists_jpeg_as_mime_type_and_extensions() {
    assert_eq!(Reader::supported_formats(), ["image/jpeg", "jpeg", "jpg"]);
}
