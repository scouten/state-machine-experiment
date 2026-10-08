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

//! The sidecar use case end to end: build a sidecar for an asset with a
//! `SidecarSession`, then read it back through the independently-written
//! `ReadSession` — sidecar bytes answering its `ManifestStore` request,
//! the asset answering its hashing requests — and require `Trusted`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_assertion_actions::{Action, Actions, DIGITAL_SOURCE_TYPE_EMPTY};
use contentauth_c2pa_claim::GeneratorInfo;
use contentauth_c2pa_ephemeral_cert::{generate, EphemeralChain, Params};
use contentauth_c2pa_primitives::EncodedAssertion;
use contentauth_c2pa_reader::{
    ReadHostReply, ReadReport, ReadRequest, ReadSession, ReadSettings, ReadStep, ValidationState,
};
use contentauth_c2pa_sidecar_builder::{
    Error, Session, SidecarReply, SidecarRequest, SidecarSession, SidecarSettings, Step,
};

const NOW: i64 = 1_800_000_000;

fn chain() -> EphemeralChain {
    let mut n = 0u8;
    generate(
        &Params::new("sidecar-test.local", NOW),
        &mut |buf: &mut [u8]| {
            for b in buf {
                n = n.wrapping_mul(31).wrapping_add(17);
                *b = n;
            }
        },
    )
    .unwrap()
}

fn asset(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i % 251) as u8).collect()
}

fn actions() -> EncodedAssertion {
    Actions::new()
        .with(Action::created(DIGITAL_SOURCE_TYPE_EMPTY))
        .encode()
        .unwrap()
}

fn settings(chain: &EphemeralChain, assertions: Vec<EncodedAssertion>) -> SidecarSettings {
    SidecarSettings {
        manifest_label: "urn:uuid:sidecar-test".into(),
        instance_id: "xmp:iid:sidecar-test".into(),
        title: Some("asset.bin".into()),
        generator: GeneratorInfo::new("sidecar-tests", Some("0.1".into())),
        signing_alg: chain.alg(),
        certificates: chain.x5chain(),
        assertions,
    }
}

/// A host that owns the asset and the key.
fn build(
    chain: &EphemeralChain,
    asset: &[u8],
    settings: SidecarSettings,
) -> Result<Vec<u8>, Error> {
    let mut session = SidecarSession::new(settings);
    loop {
        if session.advance()? == Step::Complete {
            return Ok(session.finish()?.manifest_store);
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
            session.fulfill(request.id, reply)?;
        }
    }
}

fn read(chain: &EphemeralChain, asset: &[u8], sidecar: &[u8]) -> ReadReport {
    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![chain.ca_der.clone()],
        ..ReadSettings::default()
    });
    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            return session.finish().unwrap();
        }
        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    ReadHostReply::ManifestStore(Some(sidecar.to_vec()))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(NOW),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => {
                    let s = range.start as usize;
                    ReadHostReply::AssetBytes(asset[s..s + range.len as usize].to_vec())
                }
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

#[test]
fn a_sidecar_for_gavins_use_case_reads_back_trusted() {
    let chain = chain();
    let asset = asset(200_000); // several hashing chunks
    let sidecar = build(&chain, &asset, settings(&chain, vec![actions()])).unwrap();

    let report = read(&chain, &asset, &sidecar);
    assert_eq!(
        report.validation_state,
        Some(ValidationState::Trusted),
        "{:#?}",
        report.statuses
    );

    let active = report.active().unwrap();
    assert_eq!(active.label, "urn:uuid:sidecar-test");
    assert_eq!(active.claim.title.as_deref(), Some("asset.bin"));
    assert!(active.claim.missing_required_fields().is_empty());
    assert!(active.data_hash.is_some());
}

#[test]
fn a_different_asset_fails_the_hard_binding() {
    let chain = chain();
    let original = asset(5000);
    let sidecar = build(&chain, &original, settings(&chain, vec![actions()])).unwrap();

    let mut tampered = original.clone();
    tampered[1234] ^= 0xff;
    let report = read(&chain, &tampered, &sidecar);
    assert_ne!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn the_ca_must_be_trusted_explicitly() {
    let chain = chain();
    let asset = asset(1000);
    let sidecar = build(&chain, &asset, settings(&chain, vec![actions()])).unwrap();

    let mut session = ReadSession::new(ReadSettings::default());
    let state = loop {
        if session.advance().unwrap() == ReadStep::Complete {
            break session.finish().unwrap().validation_state;
        }
        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    ReadHostReply::ManifestStore(Some(sidecar.clone()))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(NOW),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => {
                    let s = range.start as usize;
                    ReadHostReply::AssetBytes(asset[s..s + range.len as usize].to_vec())
                }
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    };
    assert_ne!(state, Some(ValidationState::Trusted));
}

#[test]
fn bad_settings_are_refused() {
    let chain = chain();
    let asset = asset(10);

    let mut no_certs = settings(&chain, vec![actions()]);
    no_certs.certificates.clear();
    assert!(matches!(
        build(&chain, &asset, no_certs),
        Err(Error::NoCertificates)
    ));

    let dup = settings(&chain, vec![actions(), actions()]);
    assert!(matches!(
        build(&chain, &asset, dup),
        Err(Error::DuplicateLabel(_))
    ));

    let reserved = settings(
        &chain,
        vec![EncodedAssertion::new("c2pa.hash.data", vec![0xa0])],
    );
    assert!(matches!(
        build(&chain, &asset, reserved),
        Err(Error::DuplicateLabel(_))
    ));
}

#[test]
fn a_host_failure_is_fatal() {
    let chain = chain();
    let mut session = SidecarSession::new(settings(&chain, vec![actions()]));
    session.advance().unwrap();
    let id = session.outstanding_requests()[0].id;
    session
        .fulfill(
            id,
            SidecarReply::Failed(contentauth_c2pa_sidecar_builder::HostError::new("gone")),
        )
        .unwrap();
    assert!(matches!(session.advance(), Err(Error::DataHash(_))));
}
