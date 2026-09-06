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

//! End to end, through real files on disk: a manifest built and signed by
//! this crate, embedded into a real JPEG (replacing its existing c2pa-rs
//! store), written out, and read back — as `Trusted` — by
//! `contentauth-c2pa-file-reader`. The two new crates' only relationship
//! is that they both implement the same `contentauth-c2pa-format`
//! contract; this is the proof they actually agree on what it means.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use contentauth_c2pa_file_builder::{
    build_and_sign_file, BuilderSettings, GeneratorInfo, HostError, SigningAlg,
};
use contentauth_c2pa_file_reader::read_manifest_from_file;
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_reader::{ReadSettings, ValidationState};

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// A real JPEG signed by c2pa-rs, reused from `contentauth-c2pa-reader`'s
/// own fixtures.
const C_JPG_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../contentauth-c2pa-reader/tests/fixtures/C.jpg"
);

fn settings() -> BuilderSettings {
    let mut settings = BuilderSettings::new(
        "image/jpeg",
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-file-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.jpg".to_string());
    settings
}

/// Signs with [`TEST_SIGNER_KEY`], the self-signed test key
/// `contentauth-c2pa-builder`'s own tests sign with. It protects nothing.
fn sign(alg: SigningAlg, data: &[u8]) -> Result<Vec<u8>, HostError> {
    assert_eq!(alg, SigningAlg::Es256);
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .map_err(|err| HostError::new(err.to_string()))?;
    signer
        .sign(data)
        .map_err(|err| HostError::new(err.to_string()))
}

#[test]
fn a_jpeg_built_and_signed_reads_back_as_trusted() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "signed.jpg"].iter().collect();

    let report = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign)
        .expect("building and signing should succeed");

    // Replaces the existing c2pa-rs store at the same offset, per
    // `JpegFormat`'s own insertion rule.
    assert_eq!(report.manifest_range.start, 20);
    assert!(!report.manifest.is_empty());

    let read = read_manifest_from_file(
        &JpegFormat,
        &output,
        ReadSettings {
            trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("the signed file should read back cleanly");

    assert_eq!(read.validation_state, Some(ValidationState::Trusted));

    let active = read.active().expect("has an active manifest");
    assert_eq!(active.label, "urn:uuid:test-manifest");
    assert_eq!(
        active.data_hash.as_ref().unwrap().exclusions,
        [report.manifest_range]
    );
}

#[test]
fn a_missing_source_file_is_reported_as_an_io_error() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "never-written.jpg"]
        .iter()
        .collect();

    let err = build_and_sign_file(
        JpegFormat,
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/no-such-file.jpg"),
        &output,
        settings(),
        sign,
    )
    .expect_err("a missing source file cannot be read");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Io { .. }
    ));
}

#[test]
fn an_unwritable_output_path_is_reported_as_an_io_error() {
    let output: PathBuf = [
        env!("CARGO_TARGET_TMPDIR"),
        "no-such-directory",
        "signed.jpg",
    ]
    .iter()
    .collect();

    let err = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign)
        .expect_err("a nonexistent output directory cannot be written to");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Io { .. }
    ));
}
