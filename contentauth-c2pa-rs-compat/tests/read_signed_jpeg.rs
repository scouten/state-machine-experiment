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

use std::{io::Cursor, path::PathBuf};

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
use jumbf::builder::SuperBoxBuilder;

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

/// JUMBF type UUID of a C2PA manifest store superbox — `"c2pa"` followed by
/// the fixed suffix every C2PA box type UUID shares. Reproduced here rather
/// than shared, since `contentauth-c2pa-reader`'s copy is private to that
/// crate.
const MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// A real, well-formed, but entirely empty C2PA manifest store: a `c2pa`
/// superbox with no manifest children at all. Built with the `jumbf` crate's
/// own builder rather than hand-assembled bytes, so it is a genuine JUMBF
/// structure — just one with nothing in it — standing in for a container
/// whose format handler locates *something* shaped like a manifest store,
/// but that store turns out to hold no manifest.
fn empty_manifest_store_bytes() -> Vec<u8> {
    let sbox = SuperBoxBuilder::new(&MANIFEST_STORE_UUID);
    let mut out = Cursor::new(Vec::new());
    sbox.write_jumbf(&mut out)
        .expect("an empty superbox always serializes");
    out.into_inner()
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
    // The builder writes structured `claim_generator_info`, not the legacy
    // free-form `claim_generator` string, so this crate's own fixture has
    // none to report; `a_real_c2pa_rs_signed_fixture_reports_its_claim_generator`
    // below exercises the `Some` case against a manifest that does.
    assert_eq!(active.claim_generator(), None);

    assert!(reader.get_manifest("urn:uuid:test-manifest").is_some());
    assert!(reader.get_manifest("urn:uuid:nonexistent").is_none());
    assert_eq!(reader.iter_manifests().count(), 1);

    let json = reader.json();
    assert!(json.contains("urn:uuid:test-manifest"));
    assert!(json.contains("\"validation_state\": \"Trusted\""));

    let statuses = reader.validation_status().expect("checks were recorded");
    assert!(!statuses.is_empty());
    let signature_status = statuses
        .iter()
        .find(|status| status.code() == "claimSignature.validated")
        .expect("the claim signature should have verified");
    assert_eq!(
        signature_status.url(),
        Some("self#jumbf=/c2pa/urn:uuid:test-manifest/c2pa.signature")
    );
    assert!(signature_status.explanation().is_some());
}

#[test]
fn without_a_trust_anchor_the_same_manifest_reads_back_only_as_valid() {
    let (_plan, asset) = build_and_embed(C_JPG);
    let path = write_temp("signed_untrusted.jpg", &asset);

    let reader = Reader::from_file(&path).expect("should still read and validate cleanly");

    assert_eq!(reader.validation_state(), ValidationState::Valid);
    assert!(reader.json().contains("\"validation_state\": \"Valid\""));
}

#[test]
fn supported_extensions_lists_jpeg_and_jpg() {
    assert_eq!(Reader::supported_extensions(), ["jpg", "jpeg"]);
}

#[test]
fn a_real_c2pa_rs_signed_fixture_reports_its_claim_generator() {
    let path = write_temp("c_from_c2pa_rs.jpg", C_JPG);

    let reader = Reader::from_file(&path).expect("C.jpg carries a real c2pa-rs-signed manifest");

    let active = reader
        .active_manifest()
        .expect("C.jpg has an active manifest");
    assert_eq!(
        active.claim_generator(),
        Some("make_test_images/0.33.1 c2pa-rs/0.33.1")
    );
}

#[test]
fn a_tampered_asset_reads_back_as_invalid() {
    let (plan, mut asset) = build_and_embed(C_JPG);

    // Flip a byte roughly midway between the end of the manifest's own
    // segments and the end of the file: safely inside the image's scan
    // data (which the JPEG handler never inspects, only hashes), and far
    // from both the framing at the very start and the EOI marker at the
    // very end.
    let exclusion_end = (plan.exclusion.start + plan.exclusion.len) as usize;
    let offset = exclusion_end + (asset.len() - exclusion_end) / 2;
    asset[offset] ^= 0xff;

    let path = write_temp("tampered.jpg", &asset);
    let reader =
        Reader::from_file(&path).expect("a tampered asset still reads, it just fails validation");

    assert_eq!(reader.validation_state(), ValidationState::Invalid);
    assert!(reader
        .validation_status()
        .expect("checks were recorded")
        .iter()
        .any(|status| status.code() == "assertion.dataHash.mismatch"));
    assert!(reader.json().contains("\"validation_state\": \"Invalid\""));
}

#[test]
fn an_empty_manifest_store_has_no_validation_status_and_reads_as_invalid() {
    let (_plan, asset) = contentauth_c2pa_format::test_util::conformance::embed(
        &JpegFormat,
        &unsigned_jpeg(),
        &empty_manifest_store_bytes(),
    );
    let path = write_temp("empty_store.jpg", &asset);

    let reader = Reader::from_file(&path).expect("an empty-but-present manifest store still reads");

    assert!(reader.active_manifest().is_none());
    assert!(reader.active_label().is_none());
    assert!(reader.validation_status().is_none());
    assert_eq!(reader.validation_state(), ValidationState::Invalid);
}

#[test]
fn a_jpeg_with_no_manifest_store_is_reported_as_jumbf_not_found() {
    let path = write_temp("no_manifest.jpg", &unsigned_jpeg());

    let err = Reader::from_file(&path).expect_err("an unsigned JPEG carries no manifest store");
    assert!(matches!(err, Error::JumbfNotFound { .. }), "{err:?}");
}

#[test]
fn a_jpg_extension_with_unparseable_content_surfaces_as_a_read_error() {
    let path = write_temp("garbage.jpg", b"this is not a JPEG at all");

    let err =
        Reader::from_file(&path).expect_err("no SOI marker, so the handler can't locate anything");
    assert!(matches!(err, Error::Read(_)), "{err:?}");
}

#[test]
fn an_unrecognized_extension_is_reported_as_unsupported() {
    let path = write_temp("asset.png", C_JPG);

    let err = Reader::from_file(&path).expect_err("no handler recognizes .png yet");
    assert!(matches!(err, Error::UnsupportedType { .. }), "{err:?}");
}
