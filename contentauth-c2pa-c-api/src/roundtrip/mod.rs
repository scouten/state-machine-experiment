// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! Signs through the exported C ABI and reads the result back through it,
//! driving both with the host in [`host`] rather than this crate's internals.
#![allow(clippy::unwrap_used, clippy::panic)]

mod host;

use base64::Engine;
use contentauth_c2pa_sign_baseline::fixtures::*;
use host::{assert_baseline, read, sign, Read};

use crate::C2paSmValidationState;

const ROOT: &[u8] = include_bytes!("../../tests/fixtures/ocsp-root.der");
const LEAF: &[u8] = include_bytes!("../../tests/fixtures/ocsp-leaf.der");
const OCSP_GOOD: &[u8] = include_bytes!("../../tests/fixtures/ocsp-good.der");
const OCSP_REVOKED: &[u8] = include_bytes!("../../tests/fixtures/ocsp-revoked.der");

fn asset() -> Vec<u8> {
    sign("jpeg", SOURCE_JPEG, &[LEAF, ROOT]).asset
}

/// Reads `asset` trusting `ROOT`, answering OCSP with `response`; also returns
/// how many OCSP requests the reader made.
fn read_with_ocsp(
    asset: &[u8],
    fetch: Option<bool>,
    response: Option<Result<&[u8], &str>>,
) -> (Read, usize) {
    let root = base64::engine::general_purpose::STANDARD.encode(ROOT);
    let verify = fetch.map_or(String::new(), |f| {
        format!(r#""verify":{{"ocsp_fetch":{f}}},"#)
    });
    let settings = format!(
        r#"{{{verify}"trust":{{"anchors":[{{"trust_anchors":"-----BEGIN CERTIFICATE-----\n{root}\n-----END CERTIFICATE-----","trust_kind":"manifest"}}]}}}}"#
    );
    let mut count = 0;
    let read = read("jpeg", Some(&settings), asset, |url, body| {
        count += 1;
        assert_eq!(url, "http://ocsp.example/");
        assert_eq!(body[0], 0x30);
        assert!(body.len() > 32);
        response.unwrap().map(<[u8]>::to_vec).map_err(str::to_owned)
    });
    (read, count)
}

#[test]
fn build_and_read_roundtrip_preserves_the_baseline_manifest_fields() {
    let bytes = asset();
    assert_baseline("jpeg", &bytes, ROOT);
    let (read, count) = read_with_ocsp(&bytes, Some(false), None);
    assert_eq!(count, 0);
    assert_eq!(
        read.state,
        C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED
    );
    let json: serde_json::Value = serde_json::from_str(&read.json).unwrap();
    assert_eq!(json["validation_state"], "Trusted");
}

#[test]
fn authenticated_ocsp_responses_distinguish_good_and_revoked_signers() {
    let bytes = asset();
    for (response, state, json_state, status) in [
        (
            OCSP_GOOD,
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
            "Trusted",
            "signingCredential.ocsp.notRevoked",
        ),
        (
            OCSP_REVOKED,
            C2paSmValidationState::C2PA_SM_VALIDATION_INVALID,
            "Invalid",
            "signingCredential.ocsp.revoked",
        ),
    ] {
        let (read, count) = read_with_ocsp(&bytes, Some(true), Some(Ok(response)));
        assert_eq!(count, 1);
        assert_eq!(read.state, state, "{}", read.json);
        let value: serde_json::Value = serde_json::from_str(&read.json).unwrap();
        assert_eq!(value["validation_state"], json_state);
        assert!(read.json.contains(status), "{}", read.json);
        assert!(!read.json.contains("signingCredential.ocsp.inaccessible"));
    }
}

#[test]
fn ocsp_malformed_and_unavailable_transport_retain_the_manifest_report() {
    let bytes = asset();
    for (response, reason) in [
        (Ok(&[0x30, 0][..]), "could not be authenticated"),
        (Err("OCSP transport unavailable"), "could not be reached"),
    ] {
        let (read, count) = read_with_ocsp(&bytes, Some(true), Some(response));
        assert_eq!(count, 1);
        assert_eq!(
            read.state,
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED,
            "{}",
            read.json
        );
        let value: serde_json::Value = serde_json::from_str(&read.json).unwrap();
        assert_eq!(value["validation_state"], "Trusted");
        assert!(
            read.json.contains("signingCredential.ocsp.inaccessible"),
            "{}",
            read.json
        );
        assert!(read.json.contains(reason), "{}", read.json);
        assert!(!read.json.contains("signingCredential.ocsp.notRevoked"));
    }
}

#[test]
fn online_ocsp_is_opt_in_and_can_be_disabled() {
    let bytes = asset();
    for fetch in [None, Some(false)] {
        let (read, count) = read_with_ocsp(&bytes, fetch, None);
        assert_eq!(count, 0);
        assert_eq!(
            read.state,
            C2paSmValidationState::C2PA_SM_VALIDATION_TRUSTED
        );
        assert!(read.json.contains("signingCredential.ocsp.skipped"));
        assert!(!read.json.contains("signingCredential.ocsp.inaccessible"));
    }
}

#[test]
fn tiff_and_dng_roundtrip_have_two_nonadjacent_exclusions() {
    // A minimal little-endian TIFF with one ImageWidth entry.
    let source = [
        b'I', b'I', 42, 0, 8, 0, 0, 0, 1, 0, 0, 1, 4, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    ];
    for format in ["tiff", "dng"] {
        let signed = sign(format, &source, &[TEST_SIGNER_CERT]);
        assert_eq!(signed.exclusions.len(), 2);
        let (first, second) = (signed.exclusions[0], signed.exclusions[1]);
        assert!(first.0 + first.1 < second.0);
        assert_baseline(format, &signed.asset, TEST_SIGNER_CERT);
    }
}
