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

/// A build that fails after the temporary file has already been created —
/// here, a signer that always refuses — must not leave that temporary
/// file behind, nor touch `output_path` at all: the rename into place
/// only ever happens once the whole build has succeeded.
#[test]
fn a_failed_build_removes_the_temporary_file_and_leaves_the_output_untouched() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "never-signed.jpg"]
        .iter()
        .collect();
    let temp = temp_path_for(&output);
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&temp);

    fn never_signs(_alg: SigningAlg, _data: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("this test never signs anything"))
    }

    let err = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), never_signs)
        .expect_err("a build whose signer always refuses cannot succeed");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Build(_)
    ));
    assert!(!output.exists(), "the output path must be untouched");
    assert!(!temp.exists(), "the temporary file must be cleaned up");
}

/// A failure renaming the finished temporary file into place — here,
/// because `output_path` is an existing directory rather than a file — is
/// reported like any other I/O error, not silently swallowed.
#[test]
fn a_rename_failure_is_reported_as_an_io_error() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "signed-as-a-directory.jpg"]
        .iter()
        .collect();
    std::fs::create_dir_all(&output).unwrap();

    let err = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign)
        .expect_err("renaming onto an existing directory cannot succeed");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Io { .. }
    ));
}

/// Mirrors the crate's own private `temp_path_for`, so this test can check
/// for the temporary file without depending on its internals directly.
fn temp_path_for(output_path: &std::path::Path) -> PathBuf {
    let mut temp = output_path.as_os_str().to_owned();
    temp.push(".c2pa-tmp");
    PathBuf::from(temp)
}
