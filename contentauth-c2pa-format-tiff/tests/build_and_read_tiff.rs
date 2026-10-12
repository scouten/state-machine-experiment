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

//! The end-to-end proof: a manifest built and signed by
//! `contentauth-c2pa-builder`, embedded into a TIFF through this crate by
//! a simulated host, then located through this crate again and read back
//! by `contentauth-c2pa-reader` as trusted — with the reader's own hard
//! binding check confirming that the exclusion range this crate declared
//! is the one the signed hash was computed over.
//!
//! The host here does by hand what `contentauth-c2pa-file-builder` and
//! `-file-reader` do for a file: answer the builder's `ReservePlaceholder` by running
//! `plan_embed` and materializing the plan, and answer the reader's
//! `ManifestStore` by running `locate`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod common;

use common::{tiff, ALL_KINDS};
use contentauth_c2pa_builder::{
    Assertion, BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep,
    GeneratorInfo, SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    EmbedPlan, FormatHandler,
};
use contentauth_c2pa_format_tiff::TiffFormat;
use contentauth_c2pa_reader::{
    ReadHostReply, ReadReport, ReadRequest, ReadSession, ReadSettings, ReadStep, ValidationState,
};
use contentauth_state_machine::Session;

/// The self-signed test certificate and key `contentauth-c2pa-builder`'s
/// own tests sign with. They protect nothing.
const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// A simulated host that keeps the source TIFF and the asset being
/// written apart — as a real host writing to a new file would — and
/// consults [`TiffFormat`] for every container question.
struct Host {
    source: Vec<u8>,
    asset: Vec<u8>,
    plan: Option<EmbedPlan>,
}

impl Host {
    fn new(source: Vec<u8>) -> Self {
        Self {
            asset: source.clone(),
            source,
            plan: None,
        }
    }

    fn build(&mut self, mut session: BuilderSession) -> Vec<u8> {
        loop {
            if session.advance().unwrap() == BuilderStep::Complete {
                let report = session.finish().unwrap();
                assert_eq!(report.exclusions, self.plan.as_ref().unwrap().exclusions);
                return self.asset.clone();
            }

            for request in session.outstanding_requests().to_vec() {
                let reply = self.reply_to(&request.kind);
                session.fulfill(request.id, reply).unwrap();
            }
        }
    }

    fn reply_to(&mut self, request: &BuilderRequest) -> BuilderHostReply {
        match request {
            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                let plan = MemoryHost::of(self.source.clone())
                    .run(TiffFormat.plan_embed(STREAM, placeholder.len() as u64))
                    .unwrap();
                self.asset = plan.materialize(&self.source, placeholder).unwrap();
                let exclusions = plan.exclusions.clone();
                self.plan = Some(plan);
                BuilderHostReply::PlaceholderReserved {
                    exclusions,
                    hash: None,
                }
            }

            BuilderRequest::AssetLength { .. } => {
                BuilderHostReply::AssetLength(self.asset.len() as u64)
            }

            BuilderRequest::AssetBytes { range, .. } => BuilderHostReply::AssetBytes(
                self.asset[range.start as usize..][..range.len as usize].to_vec(),
            ),

            BuilderRequest::Sign { alg, data, .. } => {
                assert_eq!(*alg, SigningAlg::Es256);
                let signer = c2pa_raw_crypto::signer_from_private_key(
                    TEST_SIGNER_KEY,
                    c2pa_raw_crypto::SigningAlg::Es256,
                )
                .unwrap();
                BuilderHostReply::Signature(signer.sign(data).unwrap())
            }

            BuilderRequest::CommitManifest {
                exclusions,
                manifest,
                ..
            } => {
                let plan = self.plan.as_ref().unwrap();
                assert_eq!(*exclusions, plan.exclusions);

                // Write last, once: the final store goes into the plan's
                // slots, and the handler's patches (none, for TIFF) on
                // top.
                let patches = TiffFormat.commit(plan, manifest).unwrap();
                self.asset = plan.materialize(&self.source, manifest).unwrap();
                for patch in patches {
                    patch.apply(&mut self.asset).unwrap();
                }
                BuilderHostReply::ManifestCommitted
            }

            other => panic!("unexpected request: {other:?}"),
        }
    }
}

fn settings(assertions: Vec<Assertion>) -> BuilderSettings {
    let mut settings = BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-format-tiff-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.tif".to_string());
    settings.assertions = assertions;
    settings
}

/// Reads `asset` back, locating its store through [`TiffFormat`] and
/// trusting [`TEST_SIGNER_CERT`].
fn read_back(asset: &[u8]) -> ReadReport {
    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    });

    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            return session.finish().unwrap();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    let location = MemoryHost::of(asset.to_vec())
                        .run(TiffFormat.locate(STREAM))
                        .unwrap();
                    ReadHostReply::ManifestStore(location.embedded.map(|e| e.jumbf))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_800_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => ReadHostReply::AssetBytes(
                    asset[range.start as usize..][..range.len as usize].to_vec(),
                ),
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

#[test]
fn a_manifest_embedded_in_a_tiff_reads_back_as_trusted_in_every_flavor() {
    for kind in ALL_KINDS {
        let source = tiff(kind, 2, 0);
        let mut host = Host::new(source.clone());
        let asset = host.build(BuilderSession::new(settings(vec![])));
        let plan = host.plan.unwrap();

        assert_eq!(plan.replaced, None);
        assert!(asset.len() > source.len());

        let report = read_back(&asset);
        assert_eq!(
            report.validation_state,
            Some(ValidationState::Trusted),
            "{kind:?}"
        );

        let active = report.active().unwrap();
        assert_eq!(active.label, "urn:uuid:test-manifest");
        assert_eq!(
            active.data_hash.as_ref().unwrap().exclusions,
            plan.exclusions,
            "the hard binding excludes exactly the ranges this crate declared"
        );
    }
}

#[test]
fn re_signing_replaces_the_manifest_and_reads_back_as_trusted() {
    let kind = ALL_KINDS[2];
    let mut first = Host::new(tiff(kind, 1, 1));
    let signed_once = first.build(BuilderSession::new(settings(vec![])));

    let mut second = Host::new(signed_once.clone());
    let signed_twice = second.build(BuilderSession::new(settings(vec![Assertion::new(
        "c2pa.metadata",
        vec![0x5a, 0x00, 0x00, 0x08, 0x00]
            .into_iter()
            .chain(vec![7u8; 2048])
            .collect(),
    )])));
    let plan = second.plan.unwrap();

    // Everything from the old `count` field to the old end of the file.
    let cut = first.plan.unwrap().exclusions[0].start;
    assert_eq!(
        plan.replaced,
        Some(contentauth_c2pa_format::ByteRange {
            start: cut,
            len: signed_once.len() as u64 - cut
        })
    );
    assert!(signed_twice.len() > signed_once.len());
    assert_eq!(
        read_back(&signed_twice).validation_state,
        Some(ValidationState::Trusted)
    );
}

#[test]
fn flipping_a_byte_of_image_data_breaks_the_hard_binding() {
    let source = tiff(ALL_KINDS[0], 1, 0);
    let mut host = Host::new(source.clone());
    let mut asset = host.build(BuilderSession::new(settings(vec![])));

    // The last byte of the source's pixel data.
    asset[source.len() - 1] ^= 0xff;

    assert_ne!(
        read_back(&asset).validation_state,
        Some(ValidationState::Trusted)
    );
}

#[test]
fn the_rewritten_ifd_pointer_is_covered_by_the_hard_binding() {
    // The one source byte the embed changes is the last IFD's next
    // pointer. It sits outside the exclusion, so pointing it elsewhere
    // — hiding the store, say — must invalidate the signature.
    let kind = ALL_KINDS[0];
    let source = tiff(kind, 1, 0);
    let mut host = Host::new(source.clone());
    let mut asset = host.build(BuilderSession::new(settings(vec![])));

    let pointer = source.len() - common::PIXELS - 4;
    assert_ne!(asset[pointer..pointer + 4], [0; 4]);
    asset[pointer..pointer + 4].copy_from_slice(&[0; 4]);

    assert_ne!(
        read_back(&asset).validation_state,
        Some(ValidationState::Trusted)
    );
}

#[test]
fn the_value_offset_between_the_two_exclusions_is_hashed() {
    // Only the `count` field and the store are excluded; the entry's value
    // offset and the next pointer sit between them, so they are inside the
    // hash — redirecting the offset (to a different store, say) would
    // invalidate the signature, not just the reader's view of the file.
    for kind in ALL_KINDS {
        let mut host = Host::new(tiff(kind, 1, 0));
        let asset = host.build(BuilderSession::new(settings(vec![])));
        let plan = host.plan.unwrap();

        let [count_field, store] = plan.exclusions[..] else {
            panic!("expected two exclusions");
        };
        let between = count_field.start + count_field.len..store.start;
        // The offset and next pointer, then (BigTIFF) four bytes of padding
        // that align the store.
        let pad = if kind.big { 4 } else { 0 };
        assert_eq!(between.end - between.start, 2 * kind.word() as u64 + pad);

        // The bytes there are the value offset, which points at the store.
        let offset = &asset[between.start as usize..][..kind.word()];
        let mut expected = store.start.to_be_bytes()[8 - kind.word()..].to_vec();
        if kind.little {
            expected.reverse();
        }
        assert_eq!(offset, &expected[..], "{kind:?}");
    }
}
