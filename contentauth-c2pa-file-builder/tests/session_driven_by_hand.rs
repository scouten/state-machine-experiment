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
//! correctly independent of this crate's own `Read + Seek` /
//! `Read + Write + Seek` + signing-function convenience host in
//! `src/drive.rs` — and, since a hand-rolled host controls exactly what it
//! answers, that this session's protocol properties hold: it never
//! reports `AwaitHost` with nothing outstanding, never reissues a request
//! still outstanding, and reports `Complete` idempotently once the
//! workflow has actually finished.
//!
//! The host here plays both streams itself: [`C_JPG`] answers reads
//! against [`FileBuilderSession::SOURCE_STREAM`], and a plain growable
//! buffer answers reads and writes against
//! [`FileBuilderSession::OUTPUT_STREAM`] — standing in for whatever real
//! storage a host would use, exactly as `src/drive.rs`'s `Read + Write +
//! Seek` bound does.

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

fn source_stream() -> contentauth_c2pa_primitives::StreamId {
    FileBuilderSession::<JpegFormat>::SOURCE_STREAM
}

fn settings() -> BuilderSettings {
    BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-file-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    )
}

/// Answers `request` from [`C_JPG`] (the source) and `output` (standing in
/// for [`FileBuilderSession::OUTPUT_STREAM`]'s real storage), signing with
/// [`TEST_SIGNER_KEY`] and refusing any timestamp request.
fn answer(output: &mut Vec<u8>, request: &FileBuilderRequest) -> FileBuilderReply {
    match request {
        FileBuilderRequest::Read { stream, range } => {
            let start = range.start as usize;
            let end = start + range.len as usize;
            let source = if *stream == source_stream() {
                C_JPG
            } else {
                output.as_slice()
            };
            match source.get(start..end) {
                Some(bytes) => FileBuilderReply::Bytes(bytes.to_vec()),
                None => FileBuilderReply::Failed(HostError::new("range out of bounds")),
            }
        }
        FileBuilderRequest::Length { stream } => {
            let len = if *stream == source_stream() {
                C_JPG.len()
            } else {
                output.len()
            };
            FileBuilderReply::Length(len as u64)
        }
        FileBuilderRequest::Write { offset, bytes, .. } => {
            let start = *offset as usize;
            let end = start + bytes.len();
            if output.len() < end {
                output.resize(end, 0);
            }
            output[start..end].copy_from_slice(bytes);
            FileBuilderReply::Written
        }
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
    let mut output = Vec::new();

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        // A session reporting `AwaitHost` with nothing outstanding would
        // leave a host that trusts the contract waiting forever.
        assert!(!session.outstanding_requests().is_empty());

        for request in session.outstanding_requests().to_vec() {
            session
                .fulfill(request.id, answer(&mut output, &request.kind))
                .unwrap();
        }
    }

    let report = session.finish().unwrap();
    assert_eq!(report.manifest_range.start, 20);
    assert!(!output.is_empty());
    assert_ne!(output, C_JPG);
}

#[test]
fn advancing_past_complete_is_idempotent() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());
    let mut output = Vec::new();

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            session
                .fulfill(request.id, answer(&mut output, &request.kind))
                .unwrap();
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

/// The very first thing this session ever asks for is the source's
/// length, alone — `plan_embed`'s scan needs it before it can read
/// anything. A host that cannot report it can never get started.
#[test]
fn a_host_reporting_a_length_failure_fails_the_build() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let requests = session.outstanding_requests().to_vec();
    assert_eq!(
        requests.len(),
        1,
        "no concurrent requests are expected here"
    );
    assert!(matches!(
        requests[0].kind,
        FileBuilderRequest::Length { .. }
    ));

    session
        .fulfill(
            requests[0].id,
            FileBuilderReply::Failed(HostError::new("no source here")),
        )
        .unwrap();

    let err = session
        .advance()
        .expect_err("a failed Length request cannot be recovered from");
    assert!(
        matches!(err, contentauth_c2pa_file_builder::Error::Format(_)),
        "{err:?}"
    );
}

/// A source read returning fewer bytes than asked for must never be
/// tolerated, wherever in the workflow it happens — whether it is
/// `plan_embed`'s own scan (a `contentauth-c2pa-format` protocol
/// violation) or this session copying a planned range into the output (an
/// `Error::ReadLengthMismatch` of this crate's own).
#[test]
fn a_host_returning_the_wrong_number_of_bytes_fails_the_build() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());
    let mut output = Vec::new();
    let mut corrupted = false;

    let err = loop {
        match session.advance() {
            Ok(Step::Complete) => panic!("a short read should have failed the build"),
            Ok(Step::AwaitHost) => {
                for request in session.outstanding_requests().to_vec() {
                    if !corrupted {
                        if let FileBuilderRequest::Read { range, .. } = &request.kind {
                            if range.len > 0 {
                                corrupted = true;
                                session
                                    .fulfill(
                                        request.id,
                                        FileBuilderReply::Bytes(vec![0; range.len as usize - 1]),
                                    )
                                    .unwrap();
                                continue;
                            }
                        }
                    }
                    session
                        .fulfill(request.id, answer(&mut output, &request.kind))
                        .unwrap();
                }
            }
            Ok(other) => panic!("unexpected step: {other:?}"),
            Err(err) => break err,
        }
    };

    assert!(corrupted, "the test never got a chance to corrupt a read");
    assert!(
        matches!(err, contentauth_c2pa_file_builder::Error::Format(_))
            || matches!(
                err,
                contentauth_c2pa_file_builder::Error::ReadLengthMismatch { .. }
            ),
        "{err:?}"
    );
}

#[test]
fn advancing_past_a_pending_sign_request_does_not_reissue_it() {
    let mut session = FileBuilderSession::new(JpegFormat, settings());
    let mut output = Vec::new();

    // Drive past every internally-resolved step (planning the embed,
    // writing the placeholder, hashing the output — which, unlike the
    // rest, may have several concurrent `AssetBytes` reads outstanding at
    // once) up to the point where a `Sign` request appears.
    let sign_request = loop {
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let requests = session.outstanding_requests().to_vec();
        assert!(!requests.is_empty());

        if let Some(sign) = requests
            .iter()
            .find(|request| matches!(request.kind, FileBuilderRequest::Sign { .. }))
        {
            break sign.id;
        }

        for request in requests {
            session
                .fulfill(request.id, answer(&mut output, &request.kind))
                .unwrap();
        }
    };

    // Advancing again without fulfilling the `Sign` request must not
    // issue a second one, nor anything else alongside it.
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
    let mut output = Vec::new();

    let err = loop {
        match session.advance() {
            Ok(Step::Complete) => panic!("build should have failed once timestamping did"),
            Ok(Step::AwaitHost) => {
                for request in session.outstanding_requests().to_vec() {
                    session
                        .fulfill(request.id, answer(&mut output, &request.kind))
                        .unwrap();
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
