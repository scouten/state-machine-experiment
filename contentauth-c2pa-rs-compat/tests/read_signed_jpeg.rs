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

//! End to end, through a real file on disk and this crate's compat
//! surface only: a manifest built and signed by `contentauth-c2pa-builder`,
//! embedded into a JPEG by `contentauth-c2pa-format-jpeg`, written to an
//! actual file, then read back through
//! [`contentauth_c2pa_rs_compat::Reader::from_file`] — the c2pa-rs-shaped
//! entry point this crate exists to provide.
//!
//! The embedding side plays the same "host does it by hand" role every
//! sibling crate's own end-to-end test does, using
//! `contentauth-c2pa-format`'s `MemoryHost` test scaffolding to build the
//! fixture; nothing about that is what this crate ships.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::path::PathBuf;

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    EmbedPlan, FormatHandler,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_rs_compat::{Error, ReadSettings, Reader, ValidationState};
use contentauth_state_machine::Session;

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// Builds and signs a manifest, embeds it into `source` via [`JpegFormat`],
/// and returns the resulting bytes and the plan used to place them.
fn build_and_embed(source: &[u8]) -> (EmbedPlan, Vec<u8>) {
    let mut settings = BuilderSettings::new(
        "image/jpeg",
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-rs-compat-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.jpg".to_string());

    let mut session = BuilderSession::new(settings);
    let mut asset = source.to_vec();
    let mut plan: Option<EmbedPlan> = None;

    loop {
        if session.advance().unwrap() == BuilderStep::Complete {
            session.finish().unwrap();
            return (plan.unwrap(), asset);
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    let embed_plan = MemoryHost::of(source.to_vec())
                        .run(JpegFormat.plan_embed(STREAM, placeholder.len() as u64))
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

                BuilderRequest::Sign { alg, data } => {
                    assert_eq!(*alg, SigningAlg::Es256);
                    let signer = c2pa_raw_crypto::signer_from_private_key(
                        TEST_SIGNER_KEY,
                        c2pa_raw_crypto::SigningAlg::Es256,
                    )
                    .unwrap();
                    BuilderHostReply::Signature(signer.sign(data).unwrap())
                }

                BuilderRequest::CommitManifest {
                    range, manifest, ..
                } => {
                    let embed_plan = plan.as_ref().unwrap();
                    assert_eq!(*range, embed_plan.exclusion);

                    let patches = JpegFormat.commit(embed_plan, manifest).unwrap();
                    asset = embed_plan.materialize(source, manifest).unwrap();
                    for patch in patches {
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

/// A minimal, well-formed JPEG with no `APP11` segments at all — same
/// layout `contentauth-c2pa-format-jpeg`'s own unit tests scan against —
/// standing in for a photo nobody has ever signed. `C.jpg` will not do for
/// this: it is itself a manifest fixture c2pa-rs signed.
fn unsigned_jpeg() -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8]; // SOI

    let jfif: &[u8] = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0";
    bytes.push(0xff);
    bytes.push(0xe0); // APP0
    bytes.extend_from_slice(&(jfif.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(jfif);

    let dqt = [0u8; 65];
    bytes.push(0xff);
    bytes.push(0xdb); // DQT
    bytes.extend_from_slice(&(dqt.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(&dqt);

    let sos = [1u8, 1, 0, 0, 0x3f, 0];
    bytes.push(0xff);
    bytes.push(0xda); // SOS
    bytes.extend_from_slice(&(sos.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(&sos);

    bytes.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]); // scan data
    bytes.extend_from_slice(&[0xff, 0xd9]); // EOI
    bytes
}

/// Writes `bytes` under `CARGO_TARGET_TMPDIR` and returns the path.
fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), name].iter().collect();
    std::fs::write(&path, bytes).expect("should write the asset to disk");
    path
}

#[test]
fn a_manifest_written_by_the_builder_reads_back_as_trusted_through_the_compat_reader() {
    let (_plan, asset) = build_and_embed(C_JPG);
    let path = write_temp("signed.jpg", &asset);

    let reader = Reader::from_file_with_settings(
        &path,
        ReadSettings {
            trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("the file just written should read back cleanly");

    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert_eq!(reader.active_label(), Some("urn:uuid:test-manifest"));

    let active = reader.active_manifest().unwrap();
    assert_eq!(active.label(), "urn:uuid:test-manifest");
    assert_eq!(active.title(), Some("test.jpg"));
    assert_eq!(active.format(), Some("image/jpeg"));
    assert_eq!(active.instance_id(), "xmp:iid:test-instance");

    assert!(reader.get_manifest("urn:uuid:test-manifest").is_some());
    assert!(reader.get_manifest("urn:uuid:nonexistent").is_none());
    assert_eq!(reader.iter_manifests().count(), 1);

    let json = reader.json();
    assert!(json.contains("urn:uuid:test-manifest"));
    assert!(json.contains("\"validation_state\": \"Trusted\""));

    assert!(reader.validation_status().is_some());
}

#[test]
fn without_a_trust_anchor_the_same_manifest_reads_back_only_as_valid() {
    let (_plan, asset) = build_and_embed(C_JPG);
    let path = write_temp("signed_untrusted.jpg", &asset);

    let reader = Reader::from_file(&path).expect("should still read and validate cleanly");

    assert_eq!(reader.validation_state(), ValidationState::Valid);
}

#[test]
fn a_jpeg_with_no_manifest_store_is_reported_as_jumbf_not_found() {
    let path = write_temp("no_manifest.jpg", &unsigned_jpeg());

    let err = Reader::from_file(&path).expect_err("an unsigned JPEG carries no manifest store");
    assert!(matches!(err, Error::JumbfNotFound { .. }), "{err:?}");
}

#[test]
fn an_unrecognized_extension_is_reported_as_unsupported() {
    let path = write_temp("asset.png", C_JPG);

    let err = Reader::from_file(&path).expect_err("no handler recognizes .png yet");
    assert!(matches!(err, Error::UnsupportedType { .. }), "{err:?}");
}
