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

//! Shared scaffolding for this crate's integration tests: a minimal
//! executor (so the async host can be driven without pulling an async
//! runtime into the workspace), a fixed-clock platform, and the same
//! build-and-embed fixture every sibling crate's end-to-end tests use.

#![allow(dead_code)]

use std::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    EmbedPlan, FormatHandler,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_js_compat::Platform;
use contentauth_c2pa_primitives::HostError;
use contentauth_state_machine::Session;

pub const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
pub const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// A real JPEG signed by c2pa-rs, reused from `contentauth-c2pa-reader`'s
/// own fixtures.
pub const C_JPG: &[u8] = include_bytes!("../../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// 2027-01-15T08:00:00Z — inside the validity window of every certificate
/// fixture in this repository, and deliberately not the wall-clock time,
/// so a test that passes did so on the instant *this* platform reported.
pub const FIXED_NOW: i64 = 1_800_000_000;

/// Polls `future` to completion on the current thread, re-polling
/// immediately whenever it is pending.
///
/// A no-op waker suffices because every future these tests drive is
/// either ready at once or pending exactly until its next poll (see
/// `tests/async_host.rs`'s `Yielding`); nothing here waits on an external
/// event that would need a real wake-up.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// Polls several futures round-robin on the current thread — one poll
/// each, in order, repeated until all are complete — returning their
/// outputs in the order given.
///
/// The simplest possible single-threaded scheduler, and enough to show
/// what a browser's event loop would see: whenever one future suspends,
/// the next one runs.
pub fn join_all_round_robin<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + '_>>>) -> Vec<T> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut slots: Vec<Option<Pin<Box<dyn Future<Output = T> + '_>>>> =
        futures.into_iter().map(Some).collect();
    let mut outputs: Vec<Option<T>> = slots.iter().map(|_| None).collect();

    while slots.iter().any(Option::is_some) {
        for (slot, output) in slots.iter_mut().zip(outputs.iter_mut()) {
            if let Some(future) = slot {
                if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                    *output = Some(value);
                    *slot = None;
                }
            }
        }
    }

    outputs
        .into_iter()
        .map(|output| output.expect("every future completed"))
        .collect()
}

/// A [`Platform`] reporting [`FIXED_NOW`] and no network.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedClock;

impl Platform for FixedClock {
    async fn current_date_time(&self) -> Result<i64, HostError> {
        Ok(FIXED_NOW)
    }

    async fn ocsp(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("FixedClock has no network"))
    }
}

/// Builds and signs a manifest with the repository's test signer, embeds
/// it into `source` via [`JpegFormat`], and returns the resulting bytes
/// and the plan used to place them.
pub fn build_and_embed(source: &[u8]) -> (EmbedPlan, Vec<u8>) {
    let mut settings = BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-js-compat-tests", "0.1"),
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
/// standing in for a photo nobody has ever signed.
pub fn unsigned_jpeg() -> Vec<u8> {
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

/// `der` as a PEM `CERTIFICATE` block, the form c2pa-rs settings JSON
/// carries trust anchors in.
pub fn pem_of(der: &[u8]) -> String {
    use base64::Engine as _;

    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}
