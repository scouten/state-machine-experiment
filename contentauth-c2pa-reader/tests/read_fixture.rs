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

//! Reads a real C2PA manifest store, written by c2pa-rs, end to end through
//! the public state-machine API — including verifying its hard binding
//! against the actual asset it was written for.
//!
//! The unit tests build synthetic stores; these prove the reader copes with
//! bytes from a production writer. See `tests/fixtures/README.md` for the
//! fixtures' provenance.

use contentauth_c2pa_reader::{
    validation::status_code, ByteRange, Error, HostError, ReadHostReply, ReadReport, ReadRequest,
    ReadSession, ReadSettings, ReadStep, RequestId, ValidationState,
};
use contentauth_state_machine::Session;

/// A raw manifest store produced by make_test_images 0.33.1 / c2pa-rs
/// 0.33.1.
const MANIFEST_STORE: &[u8] = include_bytes!("fixtures/manifest_data.c2pa");

/// The very asset that manifest store was written for: the store above sits
/// embedded at offset 32.
const ASSET: &[u8] = include_bytes!("fixtures/C.jpg");

/// Label of the fixture's single manifest.
const MANIFEST_LABEL: &str = "contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3";

/// The intermediate CA that issued the fixture's claim signer, extracted
/// from the same `x5chain`. The root above it is not in the chain and this
/// repository does not have it, so this is the highest certificate that can
/// stand as an anchor for the fixture.
const FIXTURE_ISSUER: &[u8] = include_bytes!("fixtures/signer-issuer.der");

/// The trust anchor for the timestamping authority that stamped this
/// fixture: DigiCert Trusted Root G4, extracted from the token itself.
const TIMESTAMP_ANCHOR: &[u8] = include_bytes!("fixtures/digicert-trusted-root-g4.der");

/// The evaluation instant the host reports: 2027-01-15T08:00:00Z, inside the
/// fixture chain's validity window (2022-06-10 .. 2030-08-26).
///
/// Fixed rather than read from the clock so that the test says the same
/// thing in 2031 as it does today — at which point it will be saying
/// something about a chain that has since expired, which is exactly the
/// property being pinned.
const NOW: i64 = 1_800_000_000;

/// The instant the fixture's own timestamp attests to,
/// 2024-08-06T21:53:37Z. Not a value this repository chose: it is what the
/// DigiCert authority wrote into the token in 2024.
const GEN_TIME: i64 = 1_722_981_217;

/// A simulated host: it owns the asset and the manifest store, and answers
/// whatever the session asks for.
struct Host<'a> {
    manifest_store: &'a [u8],

    /// The asset, or `None` for a host that has none to offer.
    asset: Option<&'a [u8]>,

    /// The instant to report for [`ReadRequest::CurrentDateTime`].
    now: i64,

    /// DER-encoded trust anchors to configure the session with.
    anchors: Vec<Vec<u8>>,

    /// DER-encoded timestamp trust anchors.
    timestamp_anchors: Vec<Vec<u8>>,

    /// Fulfil each round's requests in reverse order, to prove the session
    /// does not depend on arrival order.
    reverse: bool,
}

/// What the host has been asked for, captured so the borrow on the session
/// can be released before fulfilling.
enum Ask {
    Store(RequestId),
    Time(RequestId),
    Length(RequestId),
    Bytes(RequestId, ByteRange),
}

impl Host<'_> {
    /// Drives a read session to completion.
    fn read(&self) -> Result<ReadReport, Error> {
        let mut session = ReadSession::new(ReadSettings {
            trust_anchors: self.anchors.clone(),
            timestamp_trust_anchors: self.timestamp_anchors.clone(),
            ..ReadSettings::default()
        });

        loop {
            if session.advance()? == ReadStep::Complete {
                return session.finish();
            }

            let mut asks: Vec<Ask> = session
                .outstanding_requests()
                .iter()
                .map(|request| match &request.kind {
                    ReadRequest::ManifestStore { .. } => Ask::Store(request.id),
                    ReadRequest::CurrentDateTime => Ask::Time(request.id),
                    ReadRequest::AssetLength { .. } => Ask::Length(request.id),
                    ReadRequest::AssetBytes { range, .. } => Ask::Bytes(request.id, *range),
                    other => panic!("unexpected request {other:?}"),
                })
                .collect();

            assert!(!asks.is_empty(), "session parked with nothing outstanding");

            if self.reverse {
                asks.reverse();
            }

            for ask in asks {
                match ask {
                    Ask::Store(id) => session.fulfill(
                        id,
                        ReadHostReply::ManifestStore(Some(self.manifest_store.to_vec())),
                    )?,

                    Ask::Time(id) => {
                        session.fulfill(id, ReadHostReply::CurrentDateTime(self.now))?
                    }

                    Ask::Length(id) => match self.asset {
                        Some(asset) => {
                            session.fulfill(id, ReadHostReply::AssetLength(asset.len() as u64))?
                        }
                        None => session
                            .fulfill(id, ReadHostReply::Failed(HostError::new("no asset here")))?,
                    },

                    Ask::Bytes(id, range) => {
                        let asset = self.asset.expect("bytes asked for without an asset");
                        let start = range.start as usize;
                        let end = start + range.len as usize;
                        session
                            .fulfill(id, ReadHostReply::AssetBytes(asset[start..end].to_vec()))?
                    }
                }
            }
        }
    }
}

/// A host holding both fixtures, answering in order, trusting nobody.
fn host() -> Host<'static> {
    Host {
        manifest_store: MANIFEST_STORE,
        asset: Some(ASSET),
        now: NOW,
        anchors: vec![],
        timestamp_anchors: vec![],
        reverse: false,
    }
}

fn read() -> ReadReport {
    host().read().expect("fixture should read cleanly")
}

/// Returns the status codes recorded, in order.
fn codes(report: &ReadReport) -> Vec<&str> {
    report.statuses.iter().map(|s| s.code.as_str()).collect()
}

#[test]
fn reads_the_active_manifest_claim() {
    let report = read();

    assert!(report.manifest_store_found);
    assert_eq!(report.manifests.len(), 1);
    assert_eq!(report.active_manifest.as_deref(), Some(MANIFEST_LABEL));

    let active = report.active().expect("fixture has an active manifest");
    assert_eq!(active.label, MANIFEST_LABEL);
    assert!(active.has_signature);

    let claim = &active.claim;
    assert_eq!(claim.title.as_deref(), Some("C.jpg"));
    assert_eq!(claim.format.as_deref(), Some("image/jpeg"));
    assert_eq!(
        claim.instance_id.as_deref(),
        Some("xmp:iid:22704d84-c37f-4733-a207-56c4c2e67b1a")
    );
    assert_eq!(
        claim.claim_generator.as_deref(),
        Some("make_test_images/0.33.1 c2pa-rs/0.33.1")
    );
    assert_eq!(
        claim.signature.as_deref(),
        Some("self#jumbf=c2pa.signature")
    );
    assert_eq!(claim.alg.as_deref(), Some("sha256"));
}

#[test]
fn reads_structured_claim_generator_info() {
    let report = read();
    let info = &report.active().unwrap().claim.claim_generator_info;

    assert_eq!(info.len(), 2);
    assert_eq!(info[0].name.as_deref(), Some("make_test_images"));
    assert_eq!(info[0].version.as_deref(), Some("0.33.1"));
    assert_eq!(info[1].name.as_deref(), Some("c2pa-rs"));
    assert_eq!(info[1].version.as_deref(), Some("0.33.1"));
}

#[test]
fn reads_the_claims_hashed_assertion_references() {
    let report = read();
    let assertions = &report.active().unwrap().claim.assertions;

    let urls: Vec<&str> = assertions.iter().map(|a| a.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg",
            "self#jumbf=c2pa.assertions/stds.schema-org.CreativeWork",
            "self#jumbf=c2pa.assertions/c2pa.actions",
            "self#jumbf=c2pa.assertions/c2pa.hash.data",
        ]
    );

    for assertion in assertions {
        assert_eq!(assertion.hash.len(), 32, "{} hash width", assertion.url);
    }
}

#[test]
fn walks_the_assertion_store_boxes() {
    let report = read();

    // The `stds.schema-org.CreativeWork` entry is the one whose description
    // box carries a salt, so reaching it exercises the private-toggle path
    // against real bytes.
    assert_eq!(
        report.active().unwrap().assertion_labels,
        [
            "c2pa.thumbnail.claim.jpeg",
            "stds.schema-org.CreativeWork",
            "c2pa.actions",
            "c2pa.hash.data",
        ]
    );
}

#[test]
fn reads_the_hard_binding() {
    let binding = read()
        .active()
        .unwrap()
        .data_hash
        .clone()
        .expect("fixture has a hard binding");

    assert_eq!(
        binding.exclusions,
        [ByteRange {
            start: 20,
            len: 45884
        }],
        "the exclusion covers the manifest embedded in the asset"
    );
    assert_eq!(binding.name.as_deref(), Some("jumbf manifest"));
    assert_eq!(binding.hash.len(), 32);
}

#[test]
fn every_hash_in_the_real_manifest_verifies() {
    let report = read();

    // Four assertion hashes, the claim signature, the certificate chain's
    // validity and trust findings, then the hard binding over the asset
    // itself. Nothing here is synthetic: the bytes, the recorded digests,
    // the exclusion ranges, the RSA-PSS signature and the certificates it
    // was made with were all produced by c2pa-rs.
    assert_eq!(
        codes(&report),
        [
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::CLAIM_SIGNATURE_VALIDATED,
            status_code::TIMESTAMP_VALIDATED,
            status_code::TIMESTAMP_UNTRUSTED,
            status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY,
            status_code::SIGNING_CREDENTIAL_UNTRUSTED,
            status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED,
            status_code::ASSERTION_DATAHASH_MATCH,
        ],
        "{report:#?}"
    );
}

#[test]
fn out_of_order_fulfilment_reaches_the_same_verdict() {
    let in_order = read();

    let reversed = Host {
        reverse: true,
        ..host()
    }
    .read()
    .expect("reversed fulfilment should still read cleanly");

    // The asset is streamed in several chunks; answering them backwards
    // must not change a single finding.
    assert_eq!(codes(&reversed), codes(&in_order));
    assert_eq!(reversed.validation_state, in_order.validation_state);
}

#[test]
fn a_verified_manifest_with_no_configured_anchor_is_valid_but_not_trusted() {
    let report = read();

    // Every hash matches, the RSA-PSS signature verifies, and the chain
    // from the signer to the intermediate holds up — but this host trusts
    // nobody, so nothing ties that intermediate to anyone it recognizes.
    // The report must not claim more than that.
    assert_eq!(report.validation_state, Some(ValidationState::Valid));
    assert_ne!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn configuring_the_fixtures_issuer_as_an_anchor_reaches_trusted() {
    let report = Host {
        anchors: vec![FIXTURE_ISSUER.to_vec()],
        ..host()
    }
    .read()
    .expect("the fixture should still read cleanly");

    // The same bytes, the same checks — the only thing that changed is
    // what this verifier was told to trust.
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(codes(&report).contains(&status_code::SIGNING_CREDENTIAL_TRUSTED));
}

#[test]
fn the_fixtures_own_timestamp_validates_in_core() {
    // Nothing synthetic: a DigiCert token, minted in 2024, countersigning
    // a claim this repository did not write. Validating it means the CMS
    // was unwrapped, the authority's signature over its signed attributes
    // verified, the `message-digest` attribute matched the encapsulated
    // `TSTInfo`, and the token's message imprint reproduced the
    // `CounterSignature` structure over the fixture's own claim.
    let report = read();
    assert!(
        codes(&report).contains(&status_code::TIMESTAMP_VALIDATED),
        "{report:#?}"
    );

    // ...but this host configured no timestamp anchor, so the authority's
    // word on the time is not taken.
    assert!(codes(&report).contains(&status_code::TIMESTAMP_UNTRUSTED));
}

#[test]
fn a_trusted_timestamp_lets_a_manifest_outlive_its_signers_certificate() {
    // The fixture's signer expires on 2030-08-26. A host reading it in
    // 2031 with no usable timestamp sees an expired credential...
    let after_expiry = 1_950_000_000; // 2031-10-17T20:40:00Z

    let untimestamped = Host {
        now: after_expiry,
        anchors: vec![FIXTURE_ISSUER.to_vec()],
        ..host()
    }
    .read()
    .expect("reads cleanly");

    assert!(codes(&untimestamped).contains(&status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY));
    assert_eq!(
        untimestamped.validation_state,
        Some(ValidationState::Invalid)
    );

    // ...and the same bytes, read by a host that trusts the authority that
    // stamped them, are judged at the instant the token attests to instead
    // of at the reader's clock. This is the whole point of a timestamp,
    // and it is the difference between the two halves of this test.
    let timestamped = Host {
        now: after_expiry,
        anchors: vec![FIXTURE_ISSUER.to_vec()],
        timestamp_anchors: vec![TIMESTAMP_ANCHOR.to_vec()],
        ..host()
    }
    .read()
    .expect("reads cleanly");

    assert!(
        codes(&timestamped).contains(&status_code::TIMESTAMP_TRUSTED),
        "{timestamped:#?}"
    );
    assert!(codes(&timestamped).contains(&status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY));
    assert_eq!(timestamped.validation_state, Some(ValidationState::Trusted));

    // The signer's window is what changed the verdict, and the instant
    // that did it is the token's, not the host's.
    let signer_expiry = 1_914_000_388; // 2030-08-26T18:46:28Z
    assert!(GEN_TIME < signer_expiry && signer_expiry < after_expiry);
}

#[test]
fn an_untrusted_timestamp_does_not_get_to_choose_the_time() {
    // The token is perfectly valid, but this host trusts a *different*
    // authority — so the authority's word on the time is refused and the
    // host's clock still decides. An attacker who can mint tokens must not
    // be able to revive an expired credential just by naming an instant.
    let report = Host {
        now: 1_950_000_000, // after the signer expires
        anchors: vec![FIXTURE_ISSUER.to_vec()],
        timestamp_anchors: vec![FIXTURE_ISSUER.to_vec()],
        ..host()
    }
    .read()
    .expect("reads cleanly");

    assert!(codes(&report).contains(&status_code::TIMESTAMP_VALIDATED));
    assert!(codes(&report).contains(&status_code::TIMESTAMP_UNTRUSTED));
    assert!(codes(&report).contains(&status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY));
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

#[test]
fn a_trusted_timestamp_carries_a_host_that_has_no_clock() {
    // A host that cannot tell the time can still validate a timestamped
    // manifest: the token brings its own instant. Before timestamps, this
    // combination could only reach `Incomplete`.
    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
        timestamp_trust_anchors: vec![TIMESTAMP_ANCHOR.to_vec()],
        ..ReadSettings::default()
    });

    assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
    let id = session.outstanding_requests()[0].id;
    session
        .fulfill(
            id,
            ReadHostReply::ManifestStore(Some(MANIFEST_STORE.to_vec())),
        )
        .unwrap();

    assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
    let id = session.outstanding_requests()[0].id;
    session
        .fulfill(id, ReadHostReply::Failed(HostError::new("no clock here")))
        .unwrap();

    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            break;
        }

        let asks: Vec<(RequestId, Option<ByteRange>)> = session
            .outstanding_requests()
            .iter()
            .map(|request| match &request.kind {
                ReadRequest::AssetLength { .. } => (request.id, None),
                ReadRequest::AssetBytes { range, .. } => (request.id, Some(*range)),
                other => panic!("unexpected request {other:?}"),
            })
            .collect();

        for (id, range) in asks {
            let reply = match range {
                None => ReadHostReply::AssetLength(ASSET.len() as u64),
                Some(range) => {
                    let start = range.start as usize;
                    ReadHostReply::AssetBytes(ASSET[start..start + range.len as usize].to_vec())
                }
            };
            session.fulfill(id, reply).unwrap();
        }
    }

    let report = session.finish().unwrap();

    assert!(
        codes(&report).contains(&status_code::TIMESTAMP_TRUSTED),
        "{report:#?}"
    );
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn a_chain_evaluated_outside_its_validity_window_is_invalid() {
    // The fixture's signer expires on 2030-08-26; a host reporting a later
    // instant is asking about a certificate that has run out.
    let report = Host {
        now: 1_950_000_000, // 2031-10-17T20:40:00Z
        anchors: vec![FIXTURE_ISSUER.to_vec()],
        ..host()
    }
    .read()
    .expect("an expired chain is a finding, not a read failure");

    assert!(
        codes(&report).contains(&status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY),
        "{report:#?}"
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));

    // Nothing about the *manifest* changed, and the report still says so:
    // every hash and the signature itself came back clean.
    assert!(codes(&report).contains(&status_code::CLAIM_SIGNATURE_VALIDATED));
    assert!(codes(&report).contains(&status_code::ASSERTION_DATAHASH_MATCH));
}

#[test]
fn a_host_with_no_clock_leaves_the_chain_unevaluated() {
    let mut session = ReadSession::new(ReadSettings::default());
    assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

    let id = session.outstanding_requests()[0].id;
    session
        .fulfill(
            id,
            ReadHostReply::ManifestStore(Some(MANIFEST_STORE.to_vec())),
        )
        .unwrap();

    assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
    let id = session.outstanding_requests()[0].id;
    session
        .fulfill(id, ReadHostReply::Failed(HostError::new("no clock here")))
        .unwrap();

    // The rest of the workflow carries on: the asset is still hashed.
    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            break;
        }

        let asks: Vec<(RequestId, Option<ByteRange>)> = session
            .outstanding_requests()
            .iter()
            .map(|request| match &request.kind {
                ReadRequest::AssetLength { .. } => (request.id, None),
                ReadRequest::AssetBytes { range, .. } => (request.id, Some(*range)),
                other => panic!("unexpected request {other:?}"),
            })
            .collect();

        for (id, range) in asks {
            let reply = match range {
                None => ReadHostReply::AssetLength(ASSET.len() as u64),
                Some(range) => {
                    let start = range.start as usize;
                    ReadHostReply::AssetBytes(ASSET[start..start + range.len as usize].to_vec())
                }
            };
            session.fulfill(id, reply).unwrap();
        }
    }

    let report = session.finish().unwrap();

    assert!(codes(&report).contains(&status_code::ASSERTION_DATAHASH_MATCH));

    // Trust was not checked, so the verdict stops short of `Valid` rather
    // than asserting something nobody established.
    assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
}

#[test]
fn tampering_with_the_asset_breaks_the_hard_binding() {
    // Alter a byte of the image data, well outside the excluded manifest
    // region, so only the hard binding can notice.
    let mut tampered = ASSET.to_vec();
    tampered[100_000] ^= 0xff;

    let report = Host {
        asset: Some(&tampered),
        ..host()
    }
    .read()
    .expect("tampering should not break parsing");

    assert_eq!(
        codes(&report),
        [
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::CLAIM_SIGNATURE_VALIDATED,
            status_code::TIMESTAMP_VALIDATED,
            status_code::TIMESTAMP_UNTRUSTED,
            status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY,
            status_code::SIGNING_CREDENTIAL_UNTRUSTED,
            status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED,
            status_code::ASSERTION_DATAHASH_MISMATCH,
        ],
        "the assertions and the credential are untouched; only the asset changed: {report:#?}"
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

#[test]
fn tampering_with_an_assertion_is_detected() {
    // Flip a byte deep inside the thumbnail assertion's embedded JPEG data
    // in the manifest store, which cannot disturb any box header — and
    // which the asset's hard binding excludes, so only the assertion hash
    // can notice.
    let marker = MANIFEST_STORE
        .windows(4)
        .position(|w| w == b"bidb")
        .expect("fixture has an embedded-file data box");

    let mut tampered = MANIFEST_STORE.to_vec();
    tampered[marker + 100] ^= 0xff;

    let report = Host {
        manifest_store: &tampered,
        ..host()
    }
    .read()
    .expect("tampering should not break parsing");

    let mismatches: Vec<&str> = report
        .statuses
        .iter()
        .filter(|s| s.code == status_code::ASSERTION_HASHEDURI_MISMATCH)
        .filter_map(|s| s.url.as_deref())
        .collect();

    assert_eq!(
        mismatches,
        ["self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg"],
        "only the tampered assertion should fail: {report:#?}"
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

#[test]
fn a_host_with_no_asset_leaves_the_binding_unchecked() {
    let report = Host {
        asset: None,
        ..host()
    }
    .read()
    .expect("a detached manifest is still readable");

    // Not being able to check is not the same as checking and failing, so
    // the store is unverified rather than invalid. The signature and the
    // chain still checked out — but "valid" would assert that the asset
    // matches its binding, which nobody established.
    assert_eq!(codes(&report).last(), Some(&status_code::GENERAL_ERROR));
    assert!(codes(&report).contains(&status_code::CLAIM_SIGNATURE_VALIDATED));
    assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
}

#[test]
fn truncating_the_store_is_reported_as_malformed() {
    let truncated = &MANIFEST_STORE[..MANIFEST_STORE.len() / 2];

    match (Host {
        manifest_store: truncated,
        ..host()
    })
    .read()
    {
        Err(Error::MalformedManifestStore(_)) => {}
        other => panic!("expected a malformed store error, got {other:?}"),
    }
}
