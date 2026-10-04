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

//! End to end, through a real file on disk: a manifest built and signed by
//! `contentauth-c2pa-builder`, embedded into a JPEG by
//! `contentauth-c2pa-format-jpeg`, written to an actual file, then read
//! back — as `Trusted` — by this crate's `read_manifest_from_file`, the
//! only piece of this pipeline under test.
//!
//! The embedding side plays the same "host does it by hand" role
//! `contentauth-c2pa-format-jpeg`'s own end-to-end test does, using
//! `contentauth-c2pa-format`'s `MemoryHost` test scaffolding to build the
//! fixture; nothing about that is what this crate ships.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::path::PathBuf;

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    SigningAlg,
};
use contentauth_c2pa_file_reader::{read_manifest_from_file, ReadSettings};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    EmbedPlan, FormatHandler,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_reader::ValidationState;
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
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-file-reader-tests", "0.1"),
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

#[test]
fn a_manifest_written_by_the_builder_reads_back_as_trusted_from_a_real_file() {
    let (plan, asset) = build_and_embed(C_JPG);

    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "signed.jpg"].iter().collect();
    std::fs::write(&path, &asset).expect("should write the signed asset to disk");

    let report = read_manifest_from_file(
        &JpegFormat,
        &path,
        ReadSettings {
            trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("the file just written should read back cleanly");

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));

    let active = report.active().unwrap();
    assert_eq!(active.label, "urn:uuid:test-manifest");
    assert_eq!(
        active.data_hash.as_ref().unwrap().exclusions,
        [plan.exclusion],
        "the exclusion the reader verified against the real file matches what the builder placed"
    );
}
