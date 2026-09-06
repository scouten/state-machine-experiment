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

//! Drives [`FileBuilderSession`] by hand, proving the session composes
//! correctly independent of this crate's own `Read + Seek` + signing-
//! function convenience host in `src/drive.rs` — and, since a hand-rolled
//! host controls exactly what it answers, that this session's protocol
//! properties hold: it never reports `AwaitHost` with nothing outstanding,
//! never reissues a request still outstanding, and reports `Complete`
//! idempotently once the workflow has actually finished.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_file_builder::{
    BuilderSettings, FileBuilderReply, FileBuilderRequest, FileBuilderSession, GeneratorInfo,
    HostError, SigningAlg, TimestampSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_state_machine::{RequestId, Session, Step};

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");
const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

fn settings() -> BuilderSettings {
    BuilderSettings::new(
        "image/jpeg",
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-file-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    )
}

/// Answers `request` straight from [`C_JPG`], signing with
/// [`TEST_SIGNER_KEY`] and refusing any timestamp request.
fn answer(request: &FileBuilderRequest) -> FileBuilderReply {
    match request {
        FileBuilderRequest::Read { range, .. } => {
            let start = range.start as usize;
            let end = start + range.len as usize;
            match C_JPG.get(start..end) {
                Some(bytes) => FileBuilderReply::Bytes(bytes.to_vec()),
                None => FileBuilderReply::Failed(HostError::new("range out of bounds")),
            }
        }
        FileBuilderRequest::Length { .. } => FileBuilderReply::Length(C_JPG.len() as u64),
        FileBuilderRequest::Sign { alg, data } => {
            assert_eq!(*alg, SigningAlg::Es256);
            let signer = c2pa_raw_crypto::signer_from_private_key(
                TEST_SIGNER_KEY,
                c2pa_raw_crypto::SigningAlg::Es256,
            )
            .unwrap();
            FileBuilderReply::Signature(signer.sign(data).unwrap())
        }
        FileBuilderRequest::Timestamp { .. } => {
            FileBuilderReply::Failed(HostError::new("this test never times tamps"))
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn a_hand_rolled_host_can_build_and_sign_a_real_jpeg() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        // A session reporting `AwaitHost` with nothing outstanding would
        // leave a host that trusts the contract waiting forever.
        assert!(!session.outstanding_requests().is_empty());

        for request in session.outstanding_requests().to_vec() {
            session.fulfill(request.id, answer(&request.kind)).unwrap();
        }
    }

    let report = session.finish().unwrap();
    assert_eq!(report.manifest_range.start, 20);
    assert!(!report.asset.is_empty());
    assert_ne!(report.asset, C_JPG);
}

#[test]
fn advancing_past_complete_is_idempotent() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            session.fulfill(request.id, answer(&request.kind)).unwrap();
        }
    }

    assert_eq!(session.advance().unwrap(), Step::Complete);
    assert_eq!(session.advance().unwrap(), Step::Complete);

    session.finish().unwrap();
}

#[test]
fn advancing_twice_without_new_replies_does_not_reissue_requests() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let first_round: Vec<RequestId> = session
        .outstanding_requests()
        .iter()
        .map(|request| request.id)
        .collect();
    assert!(!first_round.is_empty());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let second_round: Vec<RequestId> = session
        .outstanding_requests()
        .iter()
        .map(|request| request.id)
        .collect();

    assert_eq!(first_round, second_round);
}

#[test]
fn a_host_reporting_a_length_failure_fails_the_build() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let request = session.outstanding_requests()[0].id;
    session
        .fulfill(
            request,
            FileBuilderReply::Failed(HostError::new("no source here")),
        )
        .unwrap();

    let err = session
        .advance()
        .expect_err("a failed Length request cannot be recovered from");
    assert!(
        matches!(
            err,
            contentauth_c2pa_file_builder::Error::HostFailure { .. }
        ),
        "{err:?}"
    );
}

#[test]
fn a_host_returning_the_wrong_number_of_bytes_fails_the_build() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let length_request = session.outstanding_requests()[0].id;
    session
        .fulfill(length_request, FileBuilderReply::Length(C_JPG.len() as u64))
        .unwrap();

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let read_request = session.outstanding_requests()[0].id;
    session
        .fulfill(read_request, FileBuilderReply::Bytes(vec![0; 3]))
        .unwrap();

    let err = session
        .advance()
        .expect_err("a short read must never be tolerated");
    assert!(
        matches!(
            err,
            contentauth_c2pa_file_builder::Error::ReadLengthMismatch { .. }
        ),
        "{err:?}"
    );
}

#[test]
fn advancing_past_a_pending_sign_request_does_not_reissue_it() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    // Drive past the internally-answered steps (fetch source, reserve
    // placeholder, hash the asset) up to the point where a `Sign` request
    // is the only thing outstanding.
    let sign_request = loop {
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let requests = session.outstanding_requests().to_vec();
        assert_eq!(
            requests.len(),
            1,
            "no concurrent requests are expected here"
        );

        if matches!(requests[0].kind, FileBuilderRequest::Sign { .. }) {
            break requests[0].id;
        }

        session
            .fulfill(requests[0].id, answer(&requests[0].kind))
            .unwrap();
    };

    // Advancing again without fulfilling the `Sign` request must not
    // issue a second one.
    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let requests = session.outstanding_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].id, sign_request);
}

#[test]
fn a_host_that_cannot_timestamp_fails_the_build_when_one_is_requested() {
    let mut with_timestamp = settings();
    with_timestamp.timestamp = Some(TimestampSettings::new(4096));

    let mut session = FileBuilderSession::new(JpegFormat, with_timestamp);

    let err = loop {
        match session.advance() {
            Ok(Step::Complete) => panic!("build should have failed once timestamping did"),
            Ok(Step::AwaitHost) => {
                for request in session.outstanding_requests().to_vec() {
                    session.fulfill(request.id, answer(&request.kind)).unwrap();
                }
            }
            Ok(other) => panic!("unexpected step: {other:?}"),
            Err(err) => break err,
        }
    };

    assert!(
        matches!(err, contentauth_c2pa_file_builder::Error::Build(_)),
        "{err:?}"
    );
}
