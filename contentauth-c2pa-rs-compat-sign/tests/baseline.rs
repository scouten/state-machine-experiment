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
//! The baseline signing case, through the synchronous Rust binding: sign
//! a JPEG with a `Signer`, then read it back through the sibling
//! read-side compat layer and check every clause of the baseline.

#![allow(clippy::unwrap_used)]

use std::{io::Cursor, path::PathBuf};

use contentauth_c2pa_rs_compat::{ClaimVersion, Context, ReadSettings, Reader, ValidationState};
use contentauth_c2pa_rs_compat_sign::{Builder, Error, HostError, Signer, SigningAlg};
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

/// Signs with the repository's test key. It protects nothing.
struct TestSigner;

impl Signer for TestSigner {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY_PEM,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .and_then(|signer| signer.sign(data))
        .map_err(|err| HostError::new(err.to_string()))
    }
}

fn context() -> Context {
    Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    })
}

fn assert_baseline(reader: &Reader) {
    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert_eq!(
        reader.active_label(),
        Some("urn:uuid:00000000-0000-4000-8000-000000000002")
    );

    let active = reader.active_manifest().unwrap();
    assert_eq!(active.title(), Some("baseline.jpg"));
    // A v2 claim has no `dc:format`, and one `claim_generator_info` map.
    assert_eq!(active.format(), None);
    assert_eq!(active.claim_version(), ClaimVersion::V2);
    assert_eq!(active.claim_generator_info().len(), 1);
    assert_eq!(
        active.claim_generator_info()[0].name.as_deref(),
        Some("c2pa-sign-baseline")
    );
    assert_eq!(
        active.instance_id(),
        "xmp:iid:00000000-0000-4000-8000-000000000001"
    );

    let json: serde_json::Value = serde_json::from_str(&reader.json()).unwrap();
    let labels: Vec<&str> = json["manifests"][reader.active_label().unwrap()]["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|label| label.as_str().unwrap())
        .collect();
    assert!(labels.contains(&"c2pa.actions.v2"), "{labels:?}");
    assert!(labels.contains(&"c2pa.hash.data"), "{labels:?}");
}

#[test]
fn the_baseline_case_signs_a_file_that_reads_back_trusted() {
    let source: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "baseline-in.jpg"]
        .iter()
        .collect();
    let dest: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "baseline-out.jpg"]
        .iter()
        .collect();
    std::fs::write(&source, SOURCE_JPEG).unwrap();

    let manifest = Builder::from_json(BASELINE_DEFINITION)
        .unwrap()
        .sign_file(&TestSigner, &source, &dest)
        .unwrap();
    assert!(!manifest.is_empty());

    let reader = Reader::from_context(context()).with_file(&dest).unwrap();
    assert_baseline(&reader);
}

#[test]
fn the_baseline_case_signs_streams_identically_to_files() {
    let mut dest = Cursor::new(Vec::new());
    let manifest = Builder::from_json(BASELINE_DEFINITION)
        .unwrap()
        .sign(
            &TestSigner,
            "image/jpeg",
            Cursor::new(SOURCE_JPEG),
            &mut dest,
        )
        .unwrap();

    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "baseline-stream.jpg"]
        .iter()
        .collect();
    std::fs::write(&path, dest.into_inner()).unwrap();
    assert!(!manifest.is_empty());
    assert_baseline(&Reader::from_context(context()).with_file(&path).unwrap());
}

#[test]
fn an_untrusted_signer_still_signs_but_does_not_read_back_trusted() {
    let mut dest = Cursor::new(Vec::new());
    Builder::from_json(BASELINE_DEFINITION)
        .unwrap()
        .sign(
            &TestSigner,
            "image/jpeg",
            Cursor::new(SOURCE_JPEG),
            &mut dest,
        )
        .unwrap();

    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "baseline-untrusted.jpg"]
        .iter()
        .collect();
    std::fs::write(&path, dest.into_inner()).unwrap();
    let reader = Reader::from_context(Context::new())
        .with_file(&path)
        .unwrap();
    assert_ne!(reader.validation_state(), ValidationState::Trusted);
}

#[test]
fn a_signer_that_fails_fails_the_build_and_leaves_the_destination_untouched() {
    struct Refuses;
    impl Signer for Refuses {
        fn alg(&self) -> SigningAlg {
            SigningAlg::Es256
        }

        fn certs(&self) -> Vec<Vec<u8>> {
            vec![TEST_SIGNER_CERT.to_vec()]
        }

        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, HostError> {
            Err(HostError::new("hsm unavailable"))
        }
    }

    let source: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "refuse-in.jpg"]
        .iter()
        .collect();
    let dest: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "refuse-out.jpg"]
        .iter()
        .collect();
    std::fs::write(&source, SOURCE_JPEG).unwrap();
    let _ = std::fs::remove_file(&dest);

    let err = Builder::from_json(BASELINE_DEFINITION)
        .unwrap()
        .sign_file(&Refuses, &source, &dest)
        .unwrap_err();
    assert!(matches!(err, Error::Build(_)), "{err:?}");
    assert!(err.to_string().contains("hsm unavailable"), "{err}");
    assert!(!dest.exists());
}

#[test]
fn unsupported_formats_and_extensions_are_rejected_up_front() {
    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();

    let err = builder
        .sign(
            &TestSigner,
            "image/png",
            Cursor::new(SOURCE_JPEG),
            Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedType(_)));

    let err = builder
        .sign_file(&TestSigner, "in.png", "out.png")
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedPath { .. }));
}

#[test]
fn a_bad_definition_is_rejected_before_any_io() {
    assert!(matches!(Builder::from_json("{"), Err(Error::Definition(_))));
}
