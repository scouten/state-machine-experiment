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

//! Does the **real c2pa-rs** accept a sidecar manifest built from this
//! workspace's independent elements (`contentauth-c2pa-sidecar-builder`)?
//!
//! The sidecar is validated through c2pa-rs's own sidecar path,
//! `Reader::with_manifest_data_and_stream`, against a JPEG with no
//! manifest of its own, trusting the sidecar's ephemeral CA by
//! configuration — the same step a user of Gavin's sample is told to take
//! with `c2patool trust --trust_anchors`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::{
    io::Cursor,
    time::{SystemTime, UNIX_EPOCH},
};

use c2pa::{Context, Reader, ValidationState};
use contentauth_c2pa_assertion_actions::{Action, Actions, DIGITAL_SOURCE_TYPE_EMPTY};
use contentauth_c2pa_claim::GeneratorInfo;
use contentauth_c2pa_ephemeral_cert::{generate, EphemeralChain, Params};
use contentauth_c2pa_sidecar_builder::{
    Session, SidecarReply, SidecarRequest, SidecarSession, SidecarSettings, Step,
};
use contentauth_c2pa_sign_baseline::fixtures::SOURCE_JPEG;

/// `SOURCE_JPEG` with its `APP11` (JUMBF) segments removed: a plain JPEG
/// carrying no manifest, so the sidecar is the only manifest in play.
fn plain_jpeg() -> Vec<u8> {
    let src = SOURCE_JPEG;
    assert_eq!(&src[..2], &[0xff, 0xd8]);
    let mut out = vec![0xff, 0xd8];
    let mut i = 2;
    while i + 4 <= src.len() && src[i] == 0xff {
        let marker = src[i + 1];
        if marker == 0xda {
            break; // start of scan: the rest is entropy-coded data
        }
        let len = u16::from_be_bytes([src[i + 2], src[i + 3]]) as usize;
        if marker != 0xeb {
            out.extend_from_slice(&src[i..i + 2 + len]);
        }
        i += 2 + len;
    }
    out.extend_from_slice(&src[i..]);
    out
}

fn chain() -> EphemeralChain {
    // The chain must be valid *now*, by c2pa-rs's clock.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut seed = now as u64 ^ 0x9e37_79b9_7f4a_7c15;
    generate(
        &Params::new("sidecar-conformance.local", now),
        &mut |buf: &mut [u8]| {
            for b in buf {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (seed >> 33) as u8;
            }
        },
    )
    .unwrap()
}

fn sign_sidecar(chain: &EphemeralChain, asset: &[u8]) -> Vec<u8> {
    let actions = Actions::new()
        .with(Action::created(DIGITAL_SOURCE_TYPE_EMPTY))
        .encode()
        .unwrap();
    let mut session = SidecarSession::new(SidecarSettings {
        manifest_label: "urn:uuid:7b2e0a43-4f7e-4d6c-9a58-0d1c5b6e8f21".into(),
        instance_id: "xmp:iid:7b2e0a43-4f7e-4d6c-9a58-0d1c5b6e8f21".into(),
        title: Some("plain.jpg".into()),
        generator: GeneratorInfo::new("sidecar-conformance", Some("0.1".into())),
        signing_alg: chain.alg(),
        certificates: chain.x5chain(),
        assertions: vec![actions],
    });
    loop {
        if session.advance().unwrap() == Step::Complete {
            return session.finish().unwrap().manifest_store;
        }
        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                SidecarRequest::AssetLength { .. } => SidecarReply::AssetLength(asset.len() as u64),
                SidecarRequest::AssetBytes { range, .. } => {
                    let s = range.start as usize;
                    SidecarReply::AssetBytes(asset[s..s + range.len as usize].to_vec())
                }
                SidecarRequest::Sign { data, .. } => SidecarReply::Signature(chain.sign(&data)),
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn context_trusting(chain: &EphemeralChain) -> Context {
    let settings = serde_json::json!({
        "version": 1,
        "trust": { "anchors": [{ "trust_anchors": chain.ca_pem, "trust_kind": "manifest" }] },
    });
    Context::new().with_settings(settings).unwrap()
}

#[test]
fn c2pa_rs_validates_a_sidecar_built_from_independent_elements() {
    let asset = plain_jpeg();
    let chain = chain();
    let sidecar = sign_sidecar(&chain, &asset);

    let reader = Reader::from_context(context_trusting(&chain))
        .with_manifest_data_and_stream(&sidecar, "image/jpeg", Cursor::new(asset))
        .unwrap();

    let results = format!("{:#?}", reader.validation_results());
    assert_eq!(
        reader.validation_state(),
        ValidationState::Trusted,
        "{results}"
    );

    let active = reader.active_manifest().unwrap();
    assert_eq!(active.title(), Some("plain.jpg"));
    assert_eq!(
        reader.active_label(),
        Some("urn:uuid:7b2e0a43-4f7e-4d6c-9a58-0d1c5b6e8f21")
    );
}

#[test]
fn c2pa_rs_rejects_the_sidecar_against_a_different_asset() {
    let asset = plain_jpeg();
    let chain = chain();
    let sidecar = sign_sidecar(&chain, &asset);

    let mut tampered = asset;
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xff;

    let outcome = Reader::from_context(context_trusting(&chain)).with_manifest_data_and_stream(
        &sidecar,
        "image/jpeg",
        Cursor::new(tampered),
    );
    // Either c2pa-rs refuses outright or it reports the mismatch; what it
    // must not do is call this valid.
    let codes = match &outcome {
        Ok(reader) => {
            assert_eq!(reader.validation_state(), ValidationState::Invalid);
            format!("{:?}", reader.validation_results())
        }
        Err(e) => e.to_string(),
    };
    assert!(
        codes.contains("dataHash.mismatch") || codes.contains("DataHash"),
        "{codes}"
    );
}

#[test]
fn without_the_ca_configured_c2pa_rs_does_not_trust_it() {
    let asset = plain_jpeg();
    let chain = chain();
    let sidecar = sign_sidecar(&chain, &asset);

    let reader = Reader::from_context(Context::new())
        .with_manifest_data_and_stream(&sidecar, "image/jpeg", Cursor::new(asset))
        .unwrap();
    // Cryptographically sound and bound to the asset, but anchored to
    // nothing c2pa-rs was told to trust.
    assert_eq!(reader.validation_state(), ValidationState::Valid);
    assert!(format!("{:?}", reader.validation_results()).contains("signingCredential.untrusted"));
}
