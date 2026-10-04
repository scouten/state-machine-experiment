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

//! The compat `Reader` over a second container format, and over files
//! whose names do not say what they are: this crate is the *host* that
//! picks a format handler, and picks it by content.
//!
//! Nothing here touches `Reader` differently for TIFF than for JPEG — the
//! point is that it does not need to.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::path::PathBuf;

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    FormatHandler,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_format_tiff::TiffFormat;
use contentauth_c2pa_rs_compat::{Context, Error, ReadSettings, Reader, ValidationState};
use contentauth_state_machine::Session;

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// A little-endian TIFF: one IFD, one entry, no image data to speak of.
const TIFF: &[u8] = b"II\x2a\0\x08\0\0\0\x01\0\0\x01\x03\0\x01\0\0\0\x01\0\0\0\0\0\0\0";

/// Builds and signs a manifest and embeds it into `source` through
/// `handler`, as a host writing a file would.
fn sign<H: FormatHandler>(handler: &H, source: &[u8]) -> Vec<u8> {
    let settings = BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-rs-compat-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );

    let mut session = BuilderSession::new(settings);
    let mut asset = source.to_vec();
    let mut plan = None;

    loop {
        if session.advance().unwrap() == BuilderStep::Complete {
            session.finish().unwrap();
            return asset;
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    let embed_plan = MemoryHost::of(source.to_vec())
                        .run(handler.plan_embed(STREAM, placeholder.len() as u64))
                        .unwrap();
                    asset = embed_plan.materialize(source, placeholder).unwrap();
                    let exclusion = embed_plan.exclusion;
                    plan = Some(embed_plan);
                    BuilderHostReply::PlaceholderReserved(exclusion)
                }
                BuilderRequest::AssetLength { .. } => {
                    BuilderHostReply::AssetLength(asset.len() as u64)
                }
                BuilderRequest::AssetBytes { range, .. } => BuilderHostReply::AssetBytes(
                    asset[range.start as usize..][..range.len as usize].to_vec(),
                ),
                BuilderRequest::Sign { data, .. } => {
                    let signer = c2pa_raw_crypto::signer_from_private_key(
                        TEST_SIGNER_KEY,
                        c2pa_raw_crypto::SigningAlg::Es256,
                    )
                    .unwrap();
                    BuilderHostReply::Signature(signer.sign(data).unwrap())
                }
                BuilderRequest::CommitManifest { manifest, .. } => {
                    let embed_plan = plan.as_ref().unwrap();
                    asset = embed_plan.materialize(source, manifest).unwrap();
                    for patch in handler.commit(embed_plan, manifest).unwrap() {
                        patch.apply(&mut asset).unwrap();
                    }
                    BuilderHostReply::ManifestCommitted
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), name].iter().collect();
    std::fs::write(&path, bytes).unwrap();
    path
}

fn trusting() -> Context {
    Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    })
}

fn signed_tiff() -> Vec<u8> {
    sign(&TiffFormat, TIFF)
}

fn signed_jpeg() -> Vec<u8> {
    sign(&JpegFormat, C_JPG)
}

#[test]
fn a_signed_tiff_reads_back_as_trusted() {
    let path = write_temp("signed.tif", &signed_tiff());

    let reader = Reader::from_context(trusting()).with_file(&path).unwrap();

    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert_eq!(reader.active_label(), Some("urn:uuid:test-manifest"));
}

#[test]
fn an_unsigned_tiff_has_no_manifest() {
    let path = write_temp("unsigned.tiff", TIFF);

    let err = Reader::from_context(trusting())
        .with_file(&path)
        .unwrap_err();
    assert!(matches!(err, Error::JumbfNotFound { .. }), "{err:?}");
}

#[test]
fn content_decides_not_the_file_name() {
    let tiff = signed_tiff();
    let jpeg = signed_jpeg();

    for (name, bytes) in [
        ("tiff_named.jpg", &tiff),
        ("tiff_named.dat", &tiff),
        ("tiff_named_nothing", &tiff),
        ("jpeg_named.tif", &jpeg),
        ("jpeg_named.dat", &jpeg),
    ] {
        let path = write_temp(name, bytes);
        let reader = Reader::from_context(trusting())
            .with_file(&path)
            .unwrap_or_else(|err| panic!("{name}: {err:?}"));
        assert_eq!(
            reader.validation_state(),
            ValidationState::Trusted,
            "{name}"
        );
    }
}

#[test]
fn a_file_no_format_recognizes_is_unsupported_whatever_it_is_called() {
    let path = write_temp("mystery.dat", b"nothing any registered format claims");

    let err = Reader::from_context(trusting())
        .with_file(&path)
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedType { .. }), "{err:?}");
}

#[test]
fn a_broken_file_with_a_telling_extension_reports_what_is_wrong_with_it() {
    // No signature matches, but the extension names TIFF — so the TIFF
    // handler gets to say what is wrong, rather than "unsupported".
    let path = write_temp("truncated.tif", b"II\x2a");

    let err = Reader::from_context(trusting())
        .with_file(&path)
        .unwrap_err();
    assert!(matches!(err, Error::Read(_)), "{err:?}");
}

#[test]
fn a_file_that_cannot_be_read_while_sniffing_is_an_io_error() {
    // A directory opens but cannot be read, which first shows up when the
    // host reads the leading bytes to detect the format.
    let err = Reader::from_context(trusting())
        .with_file(env!("CARGO_TARGET_TMPDIR"))
        .unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "{err:?}");
}
