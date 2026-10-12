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
//! `contentauth-c2pa-builder`, embedded into a JPEG through this crate by
//! a simulated host, then located through this crate again and read back
//! by `contentauth-c2pa-reader` as trusted — with the reader's own hard
//! binding check confirming that the exclusion range this crate declared
//! is the one the signed hash was computed over.
//!
//! No orchestrating session exists yet, so the host here does by hand
//! what one will do: answer the builder's `ReservePlaceholder` by running
//! `plan_embed` and materializing the plan, and answer the reader's
//! `ManifestStore` by running `locate`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod common;

use common::{unsigned_jpeg, AFTER_APP0, C_JPG};
use contentauth_c2pa_builder::{
    Assertion, BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep,
    GeneratorInfo, SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    ByteRange, EmbedPlan, FormatHandler,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
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

/// A simulated host that keeps the source JPEG and the asset being
/// written apart — as a real host writing to a new file would — and
/// consults [`JpegFormat`] for every container question.
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
                    .run(JpegFormat.plan_embed(STREAM, placeholder.len() as u64))
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
                // slots, and the handler's patches (none, for JPEG) on
                // top.
                let patches = JpegFormat.commit(plan, manifest).unwrap();
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
        GeneratorInfo::new("contentauth-c2pa-format-jpeg-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.jpg".to_string());
    settings.assertions = assertions;
    settings
}

/// Reads `asset` back, locating its store through [`JpegFormat`] and
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
                        .run(JpegFormat.locate(STREAM))
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
fn a_manifest_embedded_in_an_unsigned_jpeg_reads_back_as_trusted() {
    let mut host = Host::new(unsigned_jpeg(true, true));
    let asset = host.build(BuilderSession::new(settings(vec![])));
    let plan = host.plan.unwrap();

    assert_eq!(plan.replaced, None);
    assert_eq!(plan.exclusions[0].start, AFTER_APP0);

    let report = read_back(&asset);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));

    let active = report.active().unwrap();
    assert_eq!(active.label, "urn:uuid:test-manifest");
    assert_eq!(
        active.data_hash.as_ref().unwrap().exclusions,
        plan.exclusions,
        "the hard binding excludes exactly the segment run this crate declared"
    );
}

#[test]
fn a_manifest_large_enough_to_span_segments_reads_back_as_trusted() {
    // An opaque assertion carrying a 70,000-byte CBOR byte string pushes
    // the store past one segment's capacity, so the reader only sees a
    // valid store if this crate split and reassembled it correctly.
    let payload = vec![0x5a_u8, 0x00, 0x01, 0x11, 0x70]
        .into_iter()
        .chain((0..70_000u32).map(|i| (i % 253) as u8))
        .collect();
    let assertion = Assertion::new("c2pa.metadata", payload);

    let mut host = Host::new(unsigned_jpeg(true, false));
    let asset = host.build(BuilderSession::new(settings(vec![assertion])));
    let plan = host.plan.unwrap();

    assert!(plan.manifest_len > 64_000);
    assert_eq!(
        plan.edits
            .iter()
            .filter(|e| matches!(e, contentauth_c2pa_format::Edit::Placeholder(_)))
            .count(),
        2
    );

    let report = read_back(&asset);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert_eq!(
        report
            .active()
            .unwrap()
            .data_hash
            .as_ref()
            .unwrap()
            .exclusions,
        plan.exclusions
    );
}

#[test]
fn re_signing_a_c2pa_rs_file_replaces_its_manifest_and_reads_back_as_trusted() {
    let mut host = Host::new(C_JPG.to_vec());
    let asset = host.build(BuilderSession::new(settings(vec![])));
    let plan = host.plan.unwrap();

    assert_eq!(
        plan.replaced,
        Some(ByteRange {
            start: 20,
            len: 45884
        }),
        "the c2pa-rs store was replaced, and the plan says so"
    );
    assert_eq!(plan.exclusions[0].start, 20);

    let report = read_back(&asset);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));

    // Only the new manifest is there: this is replacement, not (yet)
    // incorporation as a parent.
    assert_eq!(report.manifests.len(), 1);
    assert_eq!(report.active().unwrap().label, "urn:uuid:test-manifest");
    assert_eq!(
        report
            .active()
            .unwrap()
            .data_hash
            .as_ref()
            .unwrap()
            .exclusions,
        plan.exclusions
    );
}
