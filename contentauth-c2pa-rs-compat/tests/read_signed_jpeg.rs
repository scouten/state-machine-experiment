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
use jumbf::{
    builder::{DataBoxBuilder, SuperBoxBuilder},
    BoxType,
};

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

/// Builds a JUMBF type UUID from its four-character code, the same way
/// `contentauth-c2pa-reader`'s own (private) copy of this helper does: the
/// fourcc followed by the fixed suffix every C2PA box type UUID shares.
const fn type_uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}

/// Type UUID of the manifest store superbox.
const MANIFEST_STORE_UUID: [u8; 16] = type_uuid(*b"c2pa");

/// Type UUID of a manifest superbox.
///
/// Not actually consulted by the reader (it finds manifests by walking
/// every child superbox of the store, whatever their UUID, and goes by
/// label instead — see `contentauth-c2pa-reader`'s own `child_superboxes`);
/// used here only so the fixture looks like a real manifest store.
const MANIFEST_UUID: [u8; 16] = type_uuid(*b"c2ma");

/// Type UUID of a manifest's claim superbox — this one *is* load-bearing:
/// it's how the reader finds a manifest's claim among its other children.
const CLAIM_UUID: [u8; 16] = type_uuid(*b"c2cl");

/// Serializes a manifest store superbox containing `manifests`, in order.
fn manifest_store_bytes(manifests: Vec<SuperBoxBuilder<'static>>) -> Vec<u8> {
    let mut store = SuperBoxBuilder::new(&MANIFEST_STORE_UUID);
    for manifest in manifests {
        store = store.add_child_box(manifest);
    }

    let mut out = Cursor::new(Vec::new());
    store
        .write_jumbf(&mut out)
        .expect("a well-formed store always serializes");
    out.into_inner()
}

/// The smallest CBOR claim `contentauth-c2pa-reader` can decode: a
/// one-entry map holding just `dc:title`. Hand-encoded rather than built
/// with a CBOR library — two short text strings fit comfortably in CBOR's
/// single-byte "short form" length encoding, so there is no ambiguity to
/// get wrong.
fn claim_cbor_with_title(title: &str) -> Vec<u8> {
    let title = title.as_bytes();
    assert!(title.len() < 24, "helper only handles short titles");

    let mut bytes = vec![0xa1, 0x68]; // map(1), then text(8) for the key
    bytes.extend_from_slice(b"dc:title");
    bytes.push(0x60 | title.len() as u8); // text(len) for the value
    bytes.extend_from_slice(title);
    bytes
}

/// A minimal manifest superbox: `label`, and a claim child carrying just a
/// `dc:title` — nothing else `contentauth-c2pa-reader` requires in order to
/// parse it (no assertion store, no signature).
fn minimal_manifest(label: &str, title: &str) -> SuperBoxBuilder<'static> {
    let claim_cbor = DataBoxBuilder::from_owned(BoxType(*b"cbor"), claim_cbor_with_title(title));
    let claim_box = SuperBoxBuilder::new(&CLAIM_UUID).add_child_box(claim_cbor);

    SuperBoxBuilder::new(&MANIFEST_UUID)
        .set_label(label)
        .add_child_box(claim_box)
}

/// A real, well-formed, but entirely empty C2PA manifest store: a `c2pa`
/// superbox with no manifest children at all. Built with the `jumbf` crate's
/// own builder rather than hand-assembled bytes, so it is a genuine JUMBF
/// structure — just one with nothing in it — standing in for a container
/// whose format handler locates *something* shaped like a manifest store,
/// but that store turns out to hold no manifest.
fn empty_manifest_store_bytes() -> Vec<u8> {
    manifest_store_bytes(vec![])
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

    // Parsed and checked field by field, rather than matched as a
    // substring of the raw string: a substring check would still pass if
    // `manifests` lost its `instance_id`/`assertions` fields, moved
    // `active_manifest` under the wrong key, or serialized
    // `validation_status` as something other than a list of `{code, ...}`
    // objects.
    let json: serde_json::Value =
        serde_json::from_str(&reader.json()).expect("Reader::json produces valid JSON");
    assert_eq!(json["active_manifest"], "urn:uuid:test-manifest");
    assert_eq!(json["validation_state"], "Trusted");

    let manifest_json = &json["manifests"]["urn:uuid:test-manifest"];
    assert_eq!(manifest_json["label"], "urn:uuid:test-manifest");
    assert_eq!(manifest_json["title"], "test.jpg");
    assert_eq!(manifest_json["format"], "image/jpeg");
    assert_eq!(manifest_json["instance_id"], "xmp:iid:test-instance");
    assert_eq!(
        manifest_json["assertions"],
        serde_json::json!(["c2pa.hash.data"])
    );

    let status_codes: Vec<&str> = json["validation_status"]
        .as_array()
        .expect("validation_status is a JSON array")
        .iter()
        .map(|status| {
            status["code"]
                .as_str()
                .expect("each validation status has a string code")
        })
        .collect();
    assert!(status_codes.contains(&"claimSignature.validated"));

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

    let json: serde_json::Value =
        serde_json::from_str(&reader.json()).expect("Reader::json produces valid JSON");
    assert_eq!(json["validation_state"], "Valid");
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

    let json: serde_json::Value =
        serde_json::from_str(&reader.json()).expect("Reader::json produces valid JSON");
    assert_eq!(json["validation_state"], "Invalid");
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
fn active_manifest_picks_the_last_of_duplicate_labels() {
    // Nothing about the manifest store parser enforces unique labels; two
    // manifests sharing one is valid input, and `active_manifest` is
    // documented (both here and in `contentauth-c2pa-reader`) as meaning
    // the *last* manifest in the store, not merely "the one with the active
    // label" — those coincide only when labels happen to be unique.
    let store = manifest_store_bytes(vec![
        minimal_manifest("urn:uuid:duplicate", "first"),
        minimal_manifest("urn:uuid:duplicate", "second"),
    ]);
    let (_plan, asset) = contentauth_c2pa_format::test_util::conformance::embed(
        &JpegFormat,
        &unsigned_jpeg(),
        &store,
    );
    let path = write_temp("duplicate_label.jpg", &asset);

    let reader = Reader::from_file(&path).expect("a store with duplicate labels still reads");

    assert_eq!(reader.active_label(), Some("urn:uuid:duplicate"));
    assert_eq!(reader.iter_manifests().count(), 2);
    assert_eq!(
        reader
            .active_manifest()
            .expect("the store has an active manifest")
            .title(),
        Some("second"),
        "the last manifest in the store is active, not merely the first one sharing its label"
    );
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
