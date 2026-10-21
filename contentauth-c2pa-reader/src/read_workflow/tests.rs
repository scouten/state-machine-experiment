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

//! Tests for [`read_workflow`](super::read_workflow).
//!
//! Most mirror a `ReadSession` test of the same name in `read.rs`, and the
//! `assert_same_report` ones run both implementations against the same host
//! and compare what they report.

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use contentauth_state_machine::{HostRequest as OldHostRequest, Session as OldSession};
use sans_io_engine::{
    drive, FailureKind, ProtocolError as EngineProtocolError, RequestId, Session, Step,
    TraceEvent,
};

use super::*;
use crate::{
    cert::{self, Certificate},
    error::HostError,
    read::ReadStep,
    request::ReadHostReply,
    test_support,
};

/// 2027-01-15T08:00:00Z — inside the validity window of every certificate
/// fixture in this repository.
const NOW: i64 = 1_800_000_000;

// ---------------------------------------------------------------------------
// A host that serves a fixed store and asset, for either implementation.
// ---------------------------------------------------------------------------

enum Answer {
    Store(Option<Vec<u8>>),
    Bytes(Vec<u8>),
    Length(u64),
    Time(i64),
}

#[derive(Clone)]
struct Fixture {
    store: Option<Vec<u8>>,
    asset: Option<Vec<u8>>,
    now: Option<i64>,
}

impl Fixture {
    fn store(store: Vec<u8>) -> Self {
        Self {
            store: Some(store),
            asset: None,
            now: Some(NOW),
        }
    }

    fn no_store() -> Self {
        Self {
            store: None,
            asset: None,
            now: Some(NOW),
        }
    }

    fn with_asset(mut self, asset: Vec<u8>) -> Self {
        self.asset = Some(asset);
        self
    }

    fn without_clock(mut self) -> Self {
        self.now = None;
        self
    }

    /// `None` means the host cannot perform the request.
    fn answer(&self, request: &ReadRequest) -> Option<Answer> {
        match request {
            ReadRequest::ManifestStore { .. } => Some(Answer::Store(self.store.clone())),
            ReadRequest::CurrentDateTime => self.now.map(Answer::Time),
            ReadRequest::AssetLength { .. } => self
                .asset
                .as_ref()
                .map(|asset| Answer::Length(asset.len() as u64)),
            ReadRequest::AssetBytes { range, .. } => {
                let asset = self.asset.as_ref()?;
                let start = usize::try_from(range.start).ok()?;
                let end = start.checked_add(usize::try_from(range.len).ok()?)?;
                asset.get(start..end).map(|bytes| Answer::Bytes(bytes.to_vec()))
            }
            // None of the synthetic certificates names an OCSP responder.
            _ => None,
        }
    }
}

fn new_reply(answer: Answer) -> Reply {
    match answer {
        Answer::Store(store) => Reply::ManifestStore(store),
        Answer::Bytes(bytes) => Reply::AssetBytes(bytes),
        Answer::Length(len) => Reply::AssetLength(len),
        Answer::Time(now) => Reply::CurrentDateTime(now),
    }
}

fn unavailable() -> HostFailure {
    HostFailure::new(FailureKind::Unsupported, "not available")
}

/// Runs the workflow against `fixture`, and says what the host was asked.
fn run_new(
    fixture: &Fixture,
    settings: ReadSettings,
) -> (Result<ReadReport, WorkflowError>, Vec<&'static str>) {
    let mut asked = Vec::new();
    let mut session = read_workflow(settings);

    let driven = drive(&mut session, |_, request| {
        asked.push(request.kind.name());
        fixture
            .answer(&request.kind)
            .map(new_reply)
            .ok_or_else(unavailable)
    });

    (driven.and_then(|()| session.finish()), asked)
}

/// Runs the hand-written `ReadSession` against the same `fixture`.
fn run_old(fixture: &Fixture, settings: ReadSettings) -> Result<ReadReport, Error> {
    let mut session = ReadSession::new(settings);

    loop {
        if session.advance()? == ReadStep::Complete {
            return session.finish();
        }

        let requests: Vec<OldHostRequest<ReadRequest>> = session.outstanding_requests().to_vec();

        for request in requests {
            let reply = match fixture.answer(&request.kind) {
                Some(Answer::Store(store)) => ReadHostReply::ManifestStore(store),
                Some(Answer::Bytes(bytes)) => ReadHostReply::AssetBytes(bytes),
                Some(Answer::Length(len)) => ReadHostReply::AssetLength(len),
                Some(Answer::Time(now)) => ReadHostReply::CurrentDateTime(now),
                None => ReadHostReply::Failed(HostError::new("not available")),
            };
            session.fulfill(request.id, reply)?;
        }
    }
}

/// Both implementations report exactly the same thing.
fn assert_same_report(fixture: &Fixture, settings: ReadSettings) -> ReadReport {
    let (new, _) = run_new(fixture, settings.clone());
    let new = new.unwrap();
    let old = run_old(fixture, settings).unwrap();

    assert_eq!(format!("{new:#?}"), format!("{old:#?}"));
    new
}

fn last_code(report: &ReadReport) -> Option<&str> {
    report.statuses.last().map(|s| s.code.as_str())
}

// ---------------------------------------------------------------------------
// The protocol, as a host sees it.
// ---------------------------------------------------------------------------

#[test]
fn no_manifest_store_completes_with_report() {
    let mut session = read_workflow(ReadSettings::default());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let requests = session.outstanding_requests();
    assert_eq!(requests.len(), 1);
    assert!(matches!(
        requests[0].kind,
        ReadRequest::ManifestStore {
            stream: ReadSession::PRIMARY_STREAM
        }
    ));

    let id = requests[0].id;
    session.fulfill(id, Reply::ManifestStore(None)).unwrap();

    assert_eq!(session.advance().unwrap(), Step::Complete);
    assert_eq!(session.advance().unwrap(), Step::Complete, "idempotently");

    let report = session.finish().unwrap();
    assert!(!report.manifest_store_found);
    assert!(report.validation_state.is_none());
    assert!(report.statuses.is_empty());
}

#[test]
fn advance_is_idempotent_while_waiting() {
    let mut session = read_workflow(ReadSettings::default());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    assert_eq!(session.outstanding_requests().len(), 1);
}

#[test]
fn fulfill_is_checked_by_the_engine() {
    let mut session = read_workflow(ReadSettings::default());
    session.advance().unwrap();
    let id = session.outstanding_requests()[0].id;

    // The wrong kind of reply.
    assert!(matches!(
        session.fulfill(id, Reply::AssetLength(0)),
        Err(WorkflowError::Engine(EngineProtocolError::ReplyMismatch {
            request: "ManifestStore",
            ..
        }))
    ));
    assert_eq!(session.outstanding_requests().len(), 1, "still outstanding");

    session.fulfill(id, Reply::ManifestStore(None)).unwrap();

    // Not twice.
    assert!(matches!(
        session.fulfill(id, Reply::ManifestStore(None)),
        Err(WorkflowError::Engine(EngineProtocolError::UnknownRequest(unknown))) if unknown == id
    ));

    assert_eq!(session.advance().unwrap(), Step::Complete);
    assert!(matches!(
        session.fulfill(id, Reply::ManifestStore(None)),
        Err(WorkflowError::Engine(EngineProtocolError::SessionComplete))
    ));
}

#[test]
fn finish_rejects_incomplete_session() {
    let session = read_workflow(ReadSettings::default());
    assert!(matches!(
        session.finish(),
        Err(WorkflowError::Engine(
            EngineProtocolError::SessionNotComplete
        ))
    ));
}

#[test]
fn a_trust_anchor_that_is_not_a_certificate_is_refused_up_front() {
    let mut session = read_workflow(ReadSettings {
        trust_anchors: vec![
            test_support::TEST_SIGNER_CERT.to_vec(),
            b"not a certificate".to_vec(),
        ],
        ..ReadSettings::default()
    });

    // Refused before the host is asked for anything at all.
    assert!(matches!(
        session.advance(),
        Err(WorkflowError::Read(Error::MalformedTrustAnchor {
            index: 1,
            ..
        }))
    ));
    assert!(session.outstanding_requests().is_empty());
    assert!(matches!(
        session.finish(),
        Err(WorkflowError::Engine(EngineProtocolError::SessionFailed))
    ));
}

#[test]
fn host_failure_on_the_manifest_store_terminates_the_session() {
    let mut session = read_workflow(ReadSettings::default());
    session.advance().unwrap();
    let id = session.outstanding_requests()[0].id;

    session
        .fail(id, HostFailure::new(FailureKind::Io, "disk on fire"))
        .unwrap();

    assert!(matches!(
        session.advance(),
        Err(WorkflowError::Host {
            request: "ManifestStore",
            ..
        })
    ));
    assert!(matches!(
        session.advance(),
        Err(WorkflowError::Engine(EngineProtocolError::SessionFailed))
    ));
    assert!(matches!(
        session.finish(),
        Err(WorkflowError::Engine(EngineProtocolError::SessionFailed))
    ));
}

#[test]
fn a_malformed_manifest_store_fails_the_session() {
    let (result, _) = run_new(&Fixture::store(vec![0u8; 4]), ReadSettings::default());
    assert!(matches!(
        result,
        Err(WorkflowError::Read(Error::MalformedManifestStore(_)))
    ));
}

// ---------------------------------------------------------------------------
// What is reported: the same as `ReadSession`, case by case.
// ---------------------------------------------------------------------------

#[test]
fn reads_a_manifest_store_through_the_workflow() {
    let fixture = Fixture::store(test_support::manifest_store(&[
        test_support::manifest("urn:uuid:older", "older.jpg", &["c2pa.actions"]),
        test_support::manifest(
            "urn:uuid:active",
            "active.jpg",
            &["c2pa.actions", "stds.schema-org.CreativeWork"],
        ),
    ]));

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert!(report.manifest_store_found);
    assert_eq!(report.manifests.len(), 2);
    assert_eq!(report.active_manifest.as_deref(), Some("urn:uuid:active"));
    assert_eq!(report.validation_state, Some(ValidationState::Valid));
    assert_eq!(report.statuses.len(), 9, "{report:#?}");
}

#[test]
fn an_empty_store_has_no_active_manifest() {
    let fixture = Fixture::store(test_support::manifest_store(&[]));
    let report = assert_same_report(&fixture, ReadSettings::default());

    assert!(report.manifest_store_found);
    assert!(report.manifests.is_empty());
    assert!(report.active().is_none());
}

#[test]
fn no_store_reports_the_same_as_read_session() {
    let report = assert_same_report(&Fixture::no_store(), ReadSettings::default());
    assert!(!report.manifest_store_found);
}

#[test]
fn configuring_the_signer_as_an_anchor_reaches_trusted() {
    let fixture = Fixture::store(test_support::manifest_store(&[test_support::manifest(
        "urn:uuid:one",
        "one.jpg",
        &["c2pa.actions"],
    )]));

    let report = assert_same_report(
        &fixture,
        ReadSettings {
            trust_anchors: vec![test_support::TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    );
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));

    // An unrelated anchor leaves it merely valid.
    let report = assert_same_report(
        &fixture,
        ReadSettings {
            trust_anchors: vec![test_support::FIXTURE_ISSUER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    );
    assert_eq!(report.validation_state, Some(ValidationState::Valid));
}

#[test]
fn a_host_with_no_clock_leaves_trust_unevaluated() {
    let fixture = Fixture::store(test_support::manifest_store(&[test_support::manifest(
        "urn:uuid:one",
        "one.jpg",
        &[],
    )]))
    .without_clock();

    let report = assert_same_report(&fixture, ReadSettings::default());

    // The signature still verified; what could not be established is trust.
    assert!(report
        .statuses
        .iter()
        .any(|status| status.code == status_code::CLAIM_SIGNATURE_VALIDATED));
    assert_eq!(last_code(&report), Some(status_code::GENERAL_ERROR));
    assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
}

#[test]
fn a_manifest_whose_signature_does_not_verify_skips_the_trust_evaluation() {
    let fixture = Fixture::store(test_support::manifest_store(&[
        test_support::manifest_with_broken_signature(
            "urn:uuid:broken",
            &[],
            test_support::claim_box("broken.jpg"),
        ),
    ]));

    let report = assert_same_report(&fixture, ReadSettings::default());
    let (_, asked) = run_new(&fixture, ReadSettings::default());

    // No chain to evaluate, so the clock is never asked for.
    assert_eq!(asked, ["ManifestStore"]);
    assert_eq!(
        report
            .statuses
            .iter()
            .map(|s| s.code.as_str())
            .collect::<Vec<_>>(),
        [status_code::CLAIM_SIGNATURE_MISMATCH]
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

// ---------------------------------------------------------------------------
// The hard binding: streaming the asset through the hasher.
// ---------------------------------------------------------------------------

/// Builds a store whose active manifest binds to an asset with the given
/// exclusions, using `hash` as the recorded digest.
fn store_bound_to(exclusions: &[(u64, u64)], hash: Vec<u8>) -> Vec<u8> {
    let binding = test_support::data_hash_box(exclusions, hash);
    let refs = vec![test_support::hashed_uri("c2pa.hash.data", &binding)];

    test_support::manifest_store(&[test_support::manifest_with_claim(
        "urn:uuid:bound",
        &[binding],
        test_support::claim_box_with_assertions("bound.jpg", refs),
    )])
}

/// The digest of `asset` outside the given exclusions.
fn expected_digest(asset: &[u8], exclusions: &[(u64, u64)]) -> Vec<u8> {
    let mut covered = Vec::new();
    let mut cursor = 0usize;

    for (start, len) in exclusions {
        covered.extend_from_slice(&asset[cursor..*start as usize]);
        cursor = (*start + *len) as usize;
    }
    covered.extend_from_slice(&asset[cursor..]);

    HashAlgorithm::Sha256.digest(&covered)
}

/// Builds a store bound to an asset, with an explicit algorithm on the
/// binding and on the claim.
fn store_bound_with_algs(
    binding_alg: Option<&str>,
    claim_alg: Option<&str>,
    hash: Vec<u8>,
) -> Vec<u8> {
    let binding = test_support::data_hash_box_with_alg(&[], hash, binding_alg);
    let refs = vec![test_support::hashed_uri("c2pa.hash.data", &binding)];

    test_support::manifest_store(&[test_support::manifest_with_claim(
        "urn:uuid:bound",
        &[binding],
        test_support::claim_box_with_alg("bound.jpg", claim_alg, refs),
    )])
}

#[test]
fn a_matching_hard_binding_is_reported_as_a_match() {
    // Large enough to span several streamed chunks.
    let asset: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let exclusions = [(1000u64, 5000u64)];
    let fixture = Fixture::store(store_bound_to(
        &exclusions,
        expected_digest(&asset, &exclusions),
    ))
    .with_asset(asset);

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MATCH)
    );
    assert_eq!(report.validation_state, Some(ValidationState::Valid));
}

#[test]
fn a_wrong_hard_binding_invalidates_the_store() {
    let asset: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(asset);

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MISMATCH)
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

#[test]
fn exclusions_that_do_not_fit_the_asset_are_malformed() {
    let fixture =
        Fixture::store(store_bound_to(&[(50, 500)], vec![0u8; 32])).with_asset(vec![7u8; 100]);

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MALFORMED)
    );
    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
}

#[test]
fn a_binding_naming_no_algorithm_defaults_to_sha256() {
    let asset = vec![9u8; 5000];
    let expected = HashAlgorithm::Sha256.digest(&asset);
    let fixture = Fixture::store(store_bound_with_algs(None, None, expected)).with_asset(asset);

    let report = assert_same_report(&fixture, ReadSettings::default());
    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MATCH)
    );
}

#[test]
fn a_binding_algorithm_overrides_the_claims() {
    let asset = vec![3u8; 5000];
    let expected = HashAlgorithm::Sha512.digest(&asset);
    let fixture =
        Fixture::store(store_bound_with_algs(Some("sha512"), Some("sha256"), expected))
            .with_asset(asset);

    let report = assert_same_report(&fixture, ReadSettings::default());
    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MATCH)
    );
}

#[test]
fn an_unsupported_binding_algorithm_leaves_it_unchecked() {
    let fixture = Fixture::store(store_bound_with_algs(Some("sha1"), None, vec![0u8; 20]))
        .with_asset(vec![1u8; 100]);

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert!(report
        .statuses
        .iter()
        .any(|s| s.code == status_code::ALGORITHM_UNSUPPORTED));
    assert!(report
        .statuses
        .iter()
        .all(|s| s.code != status_code::ASSERTION_DATAHASH_MATCH));
    assert_eq!(report.validation_state, Some(ValidationState::Incomplete));

    // The binding was never checked, so the asset was never asked for.
    let (_, asked) = run_new(&fixture, ReadSettings::default());
    assert!(!asked.contains(&"AssetLength"), "{asked:?}");
}

#[test]
fn a_host_with_no_asset_leaves_the_binding_unchecked() {
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32]));

    let report = assert_same_report(&fixture, ReadSettings::default());

    assert_eq!(last_code(&report), Some(status_code::GENERAL_ERROR));
    assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
}

#[test]
fn a_manifest_without_a_hard_binding_never_asks_for_the_asset() {
    let fixture = Fixture::store(test_support::manifest_store(&[test_support::manifest(
        "urn:uuid:none",
        "none.jpg",
        &["c2pa.actions"],
    )]));

    let (result, asked) = run_new(&fixture, ReadSettings::default());
    result.unwrap();

    // The signature's chain still wants a time; the asset does not get asked
    // for.
    assert_eq!(asked, ["ManifestStore", "CurrentDateTime"]);
}

/// Answers every outstanding request, last first, from `fixture`.
fn answer_reversed(session: &mut ReadWorkflow, fixture: &Fixture) {
    let answers: Vec<(RequestId, Reply)> = session
        .outstanding_requests()
        .iter()
        .map(|request| {
            let answer = fixture.answer(&request.kind).expect("the fixture can answer");
            (request.id, new_reply(answer))
        })
        .collect();

    for (id, reply) in answers.into_iter().rev() {
        session.fulfill(id, reply).unwrap();
    }
}

#[test]
fn chunk_reads_overlap_up_to_the_window_and_may_be_answered_in_any_order() {
    // 16 chunks, twice the window.
    let asset: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    let fixture =
        Fixture::store(store_bound_to(&[], expected_digest(&asset, &[]))).with_asset(asset);

    let mut session = read_workflow(ReadSettings::default());
    let mut most_in_flight = 0;

    while session.advance().unwrap() != Step::Complete {
        let reads = session
            .outstanding_requests()
            .iter()
            .filter(|request| matches!(request.kind, ReadRequest::AssetBytes { .. }))
            .count();
        most_in_flight = most_in_flight.max(reads);

        // Reversed, so every later chunk arrives before an earlier one and
        // has to wait its turn to be folded.
        answer_reversed(&mut session, &fixture);
    }

    assert_eq!(most_in_flight, WINDOW);

    let report = session.finish().unwrap();
    assert_eq!(
        last_code(&report),
        Some(status_code::ASSERTION_DATAHASH_MATCH)
    );
}

#[test]
fn a_short_chunk_withholds_the_partial_report() {
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(vec![4u8; 200_000]);
    let mut session = read_workflow(ReadSettings::default());

    let result = drive(&mut session, |_, request| match &request.kind {
        // Short: can never be folded in.
        ReadRequest::AssetBytes { .. } => Ok(Reply::AssetBytes(vec![4u8; 10])),
        other => fixture
            .answer(other)
            .map(new_reply)
            .ok_or_else(unavailable),
    });

    assert!(matches!(
        result,
        Err(WorkflowError::Read(Error::AssetBytesLengthMismatch { .. }))
    ));

    // The report was partly built by then; handing it over would report a
    // manifest whose hard binding was silently never checked.
    assert!(matches!(
        session.finish(),
        Err(WorkflowError::Engine(EngineProtocolError::SessionFailed))
    ));
}

#[test]
fn a_chunk_longer_than_asked_is_refused_by_the_engine() {
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(vec![4u8; 200_000]);
    let mut session = read_workflow(ReadSettings::default());

    let result = drive(&mut session, |_, request| match &request.kind {
        ReadRequest::AssetBytes { range, .. } => {
            Ok(Reply::AssetBytes(vec![4u8; range.len as usize + 1]))
        }
        other => fixture
            .answer(other)
            .map(new_reply)
            .ok_or_else(unavailable),
    });

    assert!(matches!(
        result,
        Err(WorkflowError::Engine(EngineProtocolError::ReplyMismatch {
            request: "AssetBytes",
            ..
        }))
    ));
}

#[test]
fn a_host_failure_while_hashing_is_fatal() {
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(vec![4u8; 200_000]);
    let mut session = read_workflow(ReadSettings::default());

    let result = drive(&mut session, |_, request| match &request.kind {
        ReadRequest::AssetBytes { .. } => Err(HostFailure::new(FailureKind::Io, "unreadable")),
        other => fixture
            .answer(other)
            .map(new_reply)
            .ok_or_else(unavailable),
    });

    assert!(matches!(
        result,
        Err(WorkflowError::Host {
            request: "AssetBytes",
            ..
        })
    ));
}

#[test]
fn a_failed_read_withdraws_the_chunks_still_in_flight() {
    let fixture =
        Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(vec![4u8; 1_048_576]);
    let mut session = read_workflow(ReadSettings::default());
    session.enable_trace(256);

    // Answer everything but the chunk reads; fail only the first of those.
    loop {
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);

        let first_read = session
            .outstanding_requests()
            .iter()
            .find(|request| matches!(request.kind, ReadRequest::AssetBytes { .. }))
            .map(|request| request.id);

        match first_read {
            Some(id) => {
                session
                    .fail(id, HostFailure::new(FailureKind::Io, "unreadable"))
                    .unwrap();
                break;
            }
            None => answer_reversed(&mut session, &fixture),
        }
    }

    assert!(matches!(
        session.advance(),
        Err(WorkflowError::Host {
            request: "AssetBytes",
            ..
        })
    ));

    // The other seven chunks in the window were dropped unanswered, so the
    // host is not left to service reads nobody will look at.
    assert!(session.outstanding_requests().is_empty());
    let withdrawn = session
        .trace()
        .unwrap()
        .events()
        .filter(|event| matches!(event, TraceEvent::Cancelled { .. }))
        .count();
    assert_eq!(withdrawn, WINDOW - 1);
}

#[test]
fn a_parked_workflow_says_where_it_is_waiting() {
    let fixture = Fixture::store(store_bound_to(&[], vec![0u8; 32])).with_asset(vec![4u8; 100]);
    let mut session = read_workflow(ReadSettings::default());

    // Up to the asset length request.
    for _ in 0..3 {
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        answer_reversed(&mut session, &fixture);
    }
    assert_eq!(session.advance().unwrap(), Step::AwaitHost);

    let description = session.describe();
    assert!(description.contains("AssetBytes"), "{description}");
    assert!(description.contains("read_workflow.rs"), "{description}");
}

// ---------------------------------------------------------------------------
// Revocation: stapled responses, then online queries, issued together.
// ---------------------------------------------------------------------------

/// A real, structurally valid two-certificate chain, with an OCSP responder
/// URL grafted onto the leaf.
fn chain_with_responder(url: &str) -> Vec<Certificate> {
    let mut leaf = cert::decode(test_support::FIXTURE_LEAF_CERT).unwrap();
    leaf.ocsp_responder_url = Some(url.to_string());
    vec![
        leaf,
        cert::decode(test_support::FIXTURE_ISSUER_CERT).unwrap(),
    ]
}

const TRUST_LEAF: &[u8] = include_bytes!("../../tests/fixtures/trust-leaf.der");
const TRUST_INTERMEDIATE: &[u8] = include_bytes!("../../tests/fixtures/trust-intermediate.der");
const TRUST_ROOT: &[u8] = include_bytes!("../../tests/fixtures/trust-root.der");

/// The chain (leaf, intermediate) and the anchor (root) that extends it to a
/// second link.
fn three_tier_chain() -> (Vec<Certificate>, Vec<Anchor>) {
    (
        vec![
            cert::decode(TRUST_LEAF).unwrap(),
            cert::decode(TRUST_INTERMEDIATE).unwrap(),
        ],
        vec![Anchor::anonymous(cert::decode(TRUST_ROOT).unwrap())],
    )
}

fn three_tier_chain_with_ca_responder() -> (Vec<Certificate>, Vec<Anchor>) {
    let (mut certificates, anchors) = three_tier_chain();
    certificates[1].ocsp_responder_url = Some("http://ocsp.example/ca".to_string());
    (certificates, anchors)
}

fn pending_chain(label: &str, url: &str, certificates: Vec<Certificate>) -> PendingChain {
    PendingChain {
        manifest_label: label.to_string(),
        url: url.to_string(),
        certificates,
        timestamp: None,
        rvals: vec![],
    }
}

struct OcspRun {
    ctx: Context,
    asked: Vec<&'static str>,
}

impl OcspRun {
    fn ocsp_codes(&self) -> Vec<&str> {
        self.ctx
            .report
            .statuses
            .iter()
            .filter(|s| s.code.starts_with("signingCredential.ocsp"))
            .map(|s| s.code.as_str())
            .collect()
    }
}

fn context(settings: ReadSettings) -> Context {
    Context::new(settings).unwrap()
}

/// Evaluates trust over `chains` and settles whatever online checks it
/// issues, the host answering the first with `answer` and failing the rest.
fn run_ocsp(
    mut ctx: Context,
    chains: Vec<PendingChain>,
    answer: Result<Reply, HostFailure>,
) -> OcspRun {
    let mut session: Workflow<'static, ReadRequest, Context, WorkflowError> =
        Workflow::new(move |host| async move {
            let pending = ctx.evaluate_trust(&host, &chains, Some(NOW));
            ctx.settle_ocsp(pending).await?;
            Ok(ctx)
        });

    let mut asked = Vec::new();
    let mut answer = Some(answer);
    drive(&mut session, |_, request| {
        asked.push(request.kind.name());
        answer.take().unwrap_or_else(|| Err(unavailable()))
    })
    .unwrap();

    OcspRun {
        ctx: session.finish().unwrap(),
        asked,
    }
}

fn no_network() -> Result<Reply, HostFailure> {
    Err(HostFailure::new(FailureKind::Network, "no network"))
}

#[test]
fn the_signer_is_skipped_when_ocsp_checking_is_disabled() {
    let ctx = context(ReadSettings {
        check_ocsp: false,
        ..ReadSettings::default()
    });
    let chains = vec![pending_chain(
        "urn:uuid:one",
        "self#jumbf=x",
        chain_with_responder("http://ocsp.example/"),
    )];

    let run = run_ocsp(ctx, chains, no_network());

    assert!(run.asked.is_empty());
    assert_eq!(
        last_code_of(&run.ctx),
        Some(status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED)
    );
}

fn last_code_of(ctx: &Context) -> Option<&str> {
    ctx.report.statuses.last().map(|s| s.code.as_str())
}

#[test]
fn one_ocsp_request_is_issued_per_named_responder() {
    let chains = vec![
        pending_chain(
            "urn:uuid:ingredient",
            "self#jumbf=ingredient",
            chain_with_responder("http://ocsp.example/ingredient"),
        ),
        pending_chain(
            "urn:uuid:active",
            "self#jumbf=active",
            chain_with_responder("http://ocsp.example/active"),
        ),
    ];

    let run = run_ocsp(context(ReadSettings::default()), chains, no_network());

    assert_eq!(run.asked, ["Ocsp", "Ocsp"]);
}

#[test]
fn a_chain_the_structural_checks_already_rejected_is_never_asked_about() {
    // Flip a bit of the leaf's signature: the chain fails `chain::validate`
    // outright, before OCSP is ever considered.
    let mut broken = chain_with_responder("http://ocsp.example/");
    let last = broken[0].signature.len() - 1;
    broken[0].signature[last] ^= 0x01;

    let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", broken)];
    let run = run_ocsp(context(ReadSettings::default()), chains, no_network());

    assert!(run.asked.is_empty());
}

#[test]
fn a_garbage_stapled_response_does_not_prevent_falling_through_to_online() {
    let mut chain = pending_chain(
        "urn:uuid:one",
        "self#jumbf=x",
        chain_with_responder("http://ocsp.example/"),
    );
    chain.rvals = vec![vec![0xff, 0xff]];

    let run = run_ocsp(context(ReadSettings::default()), vec![chain], no_network());

    assert_eq!(run.asked, ["Ocsp"]);
}

#[test]
fn a_ca_certificates_unresolved_staples_are_silently_skipped() {
    let mut ctx = context(ReadSettings::default());
    let (certificates, anchors) = three_tier_chain();
    ctx.anchors = anchors;

    let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
    let run = run_ocsp(ctx, chains, no_network());

    // Nothing is left outstanding for either link of the path, and the CA
    // link records no status of its own.
    assert!(run.asked.is_empty());
    assert_eq!(
        run.ocsp_codes(),
        [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED]
    );
}

#[test]
fn a_ca_certificate_naming_a_responder_is_asked_online_too() {
    let mut ctx = context(ReadSettings::default());
    let (certificates, anchors) = three_tier_chain_with_ca_responder();
    ctx.anchors = anchors;

    let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
    let run = run_ocsp(ctx, chains, no_network());

    assert_eq!(run.asked, ["Ocsp"]);
}

#[test]
fn a_ca_certificate_is_not_asked_online_when_online_checking_is_disabled() {
    let mut ctx = context(ReadSettings {
        check_ocsp: false,
        ..ReadSettings::default()
    });
    let (certificates, anchors) = three_tier_chain_with_ca_responder();
    ctx.anchors = anchors;

    let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
    let run = run_ocsp(ctx, chains, no_network());

    assert!(run.asked.is_empty());
    // Only the signer's own skipped status; a CA has none of its own.
    assert_eq!(
        run.ocsp_codes(),
        [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED]
    );
}

#[test]
fn an_unreachable_or_unconvincing_ca_responder_records_nothing_and_leaves_trust_untouched() {
    for answer in [no_network(), Ok(Reply::Ocsp(vec![0xff, 0xff]))] {
        let mut ctx = context(ReadSettings::default());
        ctx.report.active_manifest = Some("urn:uuid:one".to_string());
        let (certificates, anchors) = three_tier_chain_with_ca_responder();
        ctx.anchors = anchors;

        let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
        let run = run_ocsp(ctx, chains, answer);

        assert_eq!(run.asked, ["Ocsp"]);
        // The trust the chain established on its own, before OCSP.
        assert!(matches!(
            run.ctx.trust,
            Some(Trust::Anchored | Trust::Unanchored)
        ));
        assert_eq!(
            run.ocsp_codes(),
            [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED]
        );
    }
}

#[test]
fn a_host_that_cannot_answer_ocsp_records_inaccessible_and_leaves_trust_untouched() {
    let mut ctx = context(ReadSettings::default());
    ctx.report.active_manifest = Some("urn:uuid:one".to_string());

    let chains = vec![pending_chain(
        "urn:uuid:one",
        "self#jumbf=x",
        chain_with_responder("http://ocsp.example/"),
    )];
    let run = run_ocsp(ctx, chains, no_network());

    assert_eq!(run.ctx.trust, Some(Trust::Unanchored));
    assert_eq!(
        last_code_of(&run.ctx),
        Some(status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
    );
}

#[test]
fn an_uninterpretable_online_response_records_inaccessible_and_is_fail_open() {
    let mut ctx = context(ReadSettings::default());
    ctx.report.active_manifest = Some("urn:uuid:one".to_string());

    let chains = vec![pending_chain(
        "urn:uuid:one",
        "self#jumbf=x",
        chain_with_responder("http://ocsp.example/"),
    )];
    let run = run_ocsp(ctx, chains, Ok(Reply::Ocsp(vec![0xff, 0xff])));

    assert_eq!(run.ctx.trust, Some(Trust::Unanchored));
    assert_eq!(
        last_code_of(&run.ctx),
        Some(status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
    );
}

/// A context parked awaiting one *CA* OCSP check, answered with a response
/// that revokes it at 1_200 (the claim being judged at 1_500).
fn settle_a_revoked_ca(is_active: bool) -> Context {
    let (check, response) = ocsp::revoked_fixture(1_200);

    let mut session: Workflow<'static, ReadRequest, Context, WorkflowError> =
        Workflow::new(move |host| async move {
            let mut ctx = Context::new(ReadSettings::default())?;
            ctx.report.active_manifest = Some("urn:uuid:active".to_string());
            ctx.trust = Some(Trust::Anchored);

            let reply = host.request(ReadRequest::Ocsp {
                url: "http://ocsp.example/ca".to_string(),
                request_der: check.request_der.clone(),
            });
            ctx.settle_ocsp(vec![PendingChainOcsp {
                url: "self#jumbf=x".to_string(),
                is_active,
                now: Some(1_500),
                attested: Some(1_500),
                checks: vec![(reply, check, false)],
            }])
            .await?;

            Ok(ctx)
        });

    let mut response = Some(Reply::Ocsp(response));
    drive(&mut session, |_, _| response.take().ok_or_else(unavailable)).unwrap();
    session.finish().unwrap()
}

#[test]
fn a_revoked_ca_in_a_live_response_rejects_the_active_chain() {
    let ctx = settle_a_revoked_ca(true);

    assert_eq!(ctx.trust, Some(Trust::Rejected));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
    assert!(status.is_failure());
}

#[test]
fn a_revoked_ca_in_a_live_response_on_an_ingredient_chain_is_not_a_failure() {
    let ctx = settle_a_revoked_ca(false);

    assert_eq!(ctx.trust, Some(Trust::Anchored));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
    assert!(!status.is_failure());
}

#[test]
fn a_request_dropped_unawaited_is_never_shown_to_the_host() {
    let (check, _) = ocsp::revoked_fixture(1_200);

    let mut session: Workflow<'static, ReadRequest, (), WorkflowError> =
        Workflow::new(move |host| async move {
            let _ = host.request(ReadRequest::Ocsp {
                url: "http://ocsp.example/".to_string(),
                request_der: check.request_der.clone(),
            });
            Ok(())
        });
    // The workflow finishes at once: its one request was dropped unawaited,
    // so it was withdrawn before the host could see it.
    assert_eq!(session.advance().unwrap(), Step::Complete);
    assert!(session.outstanding_requests().is_empty());
}

// ---------------------------------------------------------------------------
// How outcomes are recorded.
// ---------------------------------------------------------------------------

#[test]
fn apply_online_outcome_not_revoked_records_a_success_code() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Unanchored);

    ctx.apply_online_outcome(ocsp::OnlineOutcome::NotRevoked, "self#jumbf=x", true);

    assert_eq!(ctx.trust, Some(Trust::Unanchored));
    assert_eq!(
        last_code_of(&ctx),
        Some(status_code::SIGNING_CREDENTIAL_OCSP_NOT_REVOKED)
    );
}

#[test]
fn apply_online_outcome_revoked_fails_the_active_chain() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_online_outcome(ocsp::OnlineOutcome::Revoked, "self#jumbf=x", true);

    assert_eq!(ctx.trust, Some(Trust::Rejected));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
    assert!(status.is_failure());
}

#[test]
fn apply_online_outcome_revoked_for_an_inactive_chain_spares_trust() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_online_outcome(ocsp::OnlineOutcome::Revoked, "self#jumbf=ingredient", false);

    assert_eq!(ctx.trust, Some(Trust::Anchored));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
    assert!(!status.is_failure());
}

#[test]
fn apply_online_outcome_unknown_records_an_informational_code() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_online_outcome(ocsp::OnlineOutcome::Unknown, "self#jumbf=x", true);

    assert_eq!(ctx.trust, Some(Trust::Anchored));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_UNKNOWN);
    assert!(!status.is_failure());
}

#[test]
fn a_revoked_ca_certificate_is_reported_as_untrusted_but_still_fails_the_claim() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_revocation(false, true, "self#jumbf=x", "a CA certificate was revoked");

    assert_eq!(ctx.trust, Some(Trust::Rejected));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
    assert!(status.is_failure());
}

#[test]
fn a_revoked_ca_certificate_for_an_inactive_chain_spares_trust() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_revocation(
        false,
        false,
        "self#jumbf=ingredient",
        "a CA certificate was revoked",
    );

    assert_eq!(ctx.trust, Some(Trust::Anchored));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
    assert!(!status.is_failure());
}

#[test]
fn a_revoked_signer_certificate_for_an_inactive_chain_spares_the_verdict() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_revocation(
        true,
        false,
        "self#jumbf=ingredient",
        "the signer's certificate was revoked",
    );

    assert_eq!(ctx.trust, Some(Trust::Anchored));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
    assert!(!status.is_failure());
}

#[test]
fn a_revoked_signer_certificate_fails_the_claim_outright() {
    let mut ctx = context(ReadSettings::default());
    ctx.trust = Some(Trust::Anchored);

    ctx.apply_revocation(
        true,
        true,
        "self#jumbf=x",
        "the signer's certificate was revoked",
    );

    assert_eq!(ctx.trust, Some(Trust::Rejected));
    let status = ctx.report.statuses.last().unwrap();
    assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
    assert!(status.is_failure());
}
