//! The interop direction `v2_manifests.rs` does not cover: a JPEG signed by
//! **this workspace's** builder is read back the same way by both real
//! c2pa-rs and this workspace's reader.
//!
//! This is the scenario the slow-storage benchmark exercises, pinned as a
//! fast assertion. It covers a plain JPEG and one carrying a leading `COM`
//! segment, because the benchmark pads with `COM` segments and an earlier
//! run showed that path mattered for request counts; both must still read
//! as valid through either backend.
//!
//! The manifest is built from the baseline crate's conformant definition
//! (a `c2pa.actions.v2` assertion with a `c2pa.created` action). c2pa-rs's
//! spec-2.x validation requires the first action to be `created`/`opened`
//! and reports `assertion.action.malformed` otherwise, so a manifest
//! lacking it reads as `Invalid` there even though its hard binding is
//! sound — which is exactly what a hand-rolled, action-less definition hit
//! before this test existed.

use std::io::Cursor;

use contentauth_c2pa_file_builder::{build_and_sign, HostError, SigningAlg};
use contentauth_c2pa_file_reader::{read_manifest, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_sign_baseline::{
    fixtures::{SOURCE_JPEG, TEST_SIGNER_CERT, TEST_SIGNER_KEY_PEM},
    Definition, BASELINE_DEFINITION,
};

/// `SOURCE_JPEG` with a single `COM` (0xFFFE) segment inserted right after
/// `SOI`, before the original segments.
fn with_leading_comment() -> Vec<u8> {
    let comment = b"conformance comment padding";
    let mut out = SOURCE_JPEG[..2].to_vec(); // SOI
    out.extend_from_slice(&[0xff, 0xfe]);
    out.extend_from_slice(&((comment.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(comment);
    out.extend_from_slice(&SOURCE_JPEG[2..]);
    out
}

/// Signs `asset` with this workspace's builder and the baseline (conformant)
/// manifest definition.
fn sign(asset: Vec<u8>) -> Vec<u8> {
    let settings = Definition::from_json(BASELINE_DEFINITION)
        .and_then(|definition| {
            definition.into_settings(SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
        })
        .expect("the baseline definition should build settings");

    let mut output = Cursor::new(Vec::new());
    build_and_sign(
        JpegFormat,
        Cursor::new(asset),
        &mut output,
        settings,
        |_alg, data| {
            let signer = c2pa_raw_crypto::signer_from_private_key(
                TEST_SIGNER_KEY_PEM,
                c2pa_raw_crypto::SigningAlg::Es256,
            )
            .map_err(|err| HostError::new(err.to_string()))?;
            signer
                .sign(data)
                .map_err(|err| HostError::new(err.to_string()))
        },
        None,
        None,
    )
    .expect("build_and_sign should succeed");
    output.into_inner()
}

/// real c2pa-rs's validation state for `signed`, by name.
fn c2pa_rs_state(signed: &[u8]) -> &'static str {
    let reader = c2pa::Reader::from_context(c2pa::Context::new())
        .with_stream("image/jpeg", Cursor::new(signed.to_vec()))
        .expect("c2pa-rs should parse the signed asset");
    match reader.validation_state() {
        c2pa::ValidationState::Trusted => "Trusted",
        c2pa::ValidationState::Valid => "Valid",
        c2pa::ValidationState::Invalid => "Invalid",
    }
}

/// This workspace's reader validation state for `signed`, by name.
fn workspace_state(signed: &[u8]) -> String {
    let report = read_manifest(
        &JpegFormat,
        Cursor::new(signed.to_vec()),
        ReadSettings::default(),
    )
    .expect("the workspace reader should read the signed asset");
    // `Some(Valid)` etc. — compared by name rather than importing the enum,
    // which is not a dependency of this crate.
    format!("{:?}", report.validation_state)
}

#[test]
fn a_plain_jpeg_signed_here_reads_valid_through_both_backends() {
    let signed = sign(SOURCE_JPEG.to_vec());
    assert_eq!(c2pa_rs_state(&signed), "Valid");
    assert_eq!(workspace_state(&signed), "Some(Valid)");
}

#[test]
fn a_com_padded_jpeg_signed_here_reads_valid_through_both_backends() {
    let signed = sign(with_leading_comment());
    assert_eq!(c2pa_rs_state(&signed), "Valid");
    assert_eq!(workspace_state(&signed), "Some(Valid)");
}
