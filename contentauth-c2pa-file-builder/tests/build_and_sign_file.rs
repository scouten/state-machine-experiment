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
    build_and_sign_file, BuilderSettings, GeneratorInfo, HashAlgorithm, HostError, SigningAlg,
    TimestampSettings,
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

    let report = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign, None)
        .expect("building and signing should succeed");

    // Replaces the existing c2pa-rs store at the same offset, per
    // `JpegFormat`'s own insertion rule.
    assert_eq!(report.exclusions[0].start, 20);
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
        report.exclusions
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
        None,
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

    let err = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign, None)
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
    let _ = std::fs::remove_file(&output);
    remove_temp_files_for(&output);

    fn never_signs(_alg: SigningAlg, _data: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("this test never signs anything"))
    }

    let err = build_and_sign_file(
        JpegFormat,
        C_JPG_PATH,
        &output,
        settings(),
        never_signs,
        None,
    )
    .expect_err("a build whose signer always refuses cannot succeed");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Build(_)
    ));
    assert!(!output.exists(), "the output path must be untouched");
    assert!(
        !any_temp_file_exists_for(&output),
        "the temporary file must be cleaned up"
    );
}

/// A failure renaming the finished temporary file into place — here,
/// because `output_path` is an existing directory rather than a file — is
/// reported like any other I/O error, not silently swallowed, and does
/// not leave the temporary file behind either.
#[test]
fn a_rename_failure_is_reported_as_an_io_error_and_cleans_up_the_temporary_file() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "signed-as-a-directory.jpg"]
        .iter()
        .collect();
    std::fs::create_dir_all(&output).unwrap();
    remove_temp_files_for(&output);

    let err = build_and_sign_file(JpegFormat, C_JPG_PATH, &output, settings(), sign, None)
        .expect_err("renaming onto an existing directory cannot succeed");

    assert!(matches!(
        err,
        contentauth_c2pa_file_builder::Error::Io { .. }
    ));
    assert!(
        !any_temp_file_exists_for(&output),
        "the temporary file must be cleaned up even when the rename itself fails"
    );
}

/// The prefix every temporary file [`build_and_sign_file`] creates for
/// `output_path` starts with — the crate's own naming scheme is private
/// and unpredictable by design (see its own docs), so tests can only ever
/// look for this much of it.
fn temp_file_prefix(output_path: &std::path::Path) -> String {
    format!(
        "{}.c2pa-tmp-",
        output_path.file_name().unwrap().to_string_lossy()
    )
}

fn any_temp_file_exists_for(output_path: &std::path::Path) -> bool {
    let Some(dir) = output_path.parent() else {
        return false;
    };
    let prefix = temp_file_prefix(output_path);

    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
}

fn remove_temp_files_for(output_path: &std::path::Path) {
    let Some(dir) = output_path.parent() else {
        return;
    };
    let prefix = temp_file_prefix(output_path);

    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// An opaque stand-in for a TSA's token: the builder embeds whatever bytes
/// the host returns, at the reserved size, without decoding them (whether
/// a real token is trusted is the reader's business, covered by its own
/// suite).
const FAKE_TOKEN: [u8; 300] = [0x42; 300];

fn timestamped_settings() -> BuilderSettings {
    let mut settings = settings();
    settings.timestamp = Some(TimestampSettings::new(1000));
    settings
}

#[test]
fn a_timestamp_function_supplies_the_token_embedded_in_the_manifest() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "timestamped.jpg"]
        .iter()
        .collect();
    let mut asked = Vec::new();

    let report = build_and_sign_file(
        JpegFormat,
        C_JPG_PATH,
        &output,
        timestamped_settings(),
        sign,
        Some(&mut |alg, digest| {
            asked.push((alg, digest.len()));
            Ok(FAKE_TOKEN.to_vec())
        }),
    )
    .expect("building with a timestamp should succeed");

    // Asked exactly once, for a SHA-256 digest.
    assert_eq!(asked, [(HashAlgorithm::Sha256, 32)]);
    assert!(
        report
            .manifest
            .windows(FAKE_TOKEN.len())
            .any(|window| window == FAKE_TOKEN),
        "the token must appear in the manifest store"
    );

    // And the result is still a manifest the reader can read and verify.
    let parsed = read_manifest_from_file(&JpegFormat, &output, ReadSettings::default()).unwrap();
    let active = parsed.active().unwrap();
    assert!(active.has_signature);
    assert!(active.data_hash.is_some());
}

#[test]
fn a_failed_timestamp_fails_the_build_and_leaves_the_output_untouched() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "timestamp-failed.jpg"]
        .iter()
        .collect();
    std::fs::write(&output, b"existing").unwrap();

    let err = build_and_sign_file(
        JpegFormat,
        C_JPG_PATH,
        &output,
        timestamped_settings(),
        sign,
        Some(&mut |_, _| Err(HostError::new("the authority is down"))),
    )
    .unwrap_err();

    assert!(err.to_string().contains("the authority is down"), "{err}");
    assert_eq!(std::fs::read(&output).unwrap(), b"existing");
}

#[test]
fn no_timestamp_function_means_a_timestamp_request_fails_the_build() {
    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "timestamp-refused.jpg"]
        .iter()
        .collect();
    let err = build_and_sign_file(
        JpegFormat,
        C_JPG_PATH,
        &output,
        timestamped_settings(),
        sign,
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("timestamp"), "{err}");
}
