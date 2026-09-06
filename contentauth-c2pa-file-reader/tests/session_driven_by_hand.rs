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

//! Drives [`FileReadSession`] by hand, as a host that is neither
//! synchronous-file-backed nor bound to the wall clock would: this test's
//! own host answers every request straight from a byte slice already in
//! memory (standing in for, say, a cache or a network fetch) and reports a
//! fixed instant rather than [`std::time::SystemTime::now`] — exactly the
//! two things `read_manifest`/`read_manifest_from_file` hard-code and a
//! caller with different needs cannot override through them.
//!
//! This is `contentauth-c2pa-file-reader`'s own analogue of
//! `contentauth-c2pa-reader/tests/read_fixture.rs`'s hand-rolled `Host`:
//! proof that the session composes correctly independent of this crate's
//! own convenience host in `src/drive.rs`, including the protocol-level
//! properties that host never has to think about (idempotent completion,
//! partial fulfillment, not reissuing a request that is already
//! outstanding) and the failures a real asset can produce at either
//! stage of the workflow.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::io::Cursor;

use contentauth_c2pa_file_reader::{
    read_manifest, Error, FileReadReply, FileReadRequest, FileReadSession, ReadSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_primitives::HostError;
use contentauth_c2pa_reader::ValidationState;
use contentauth_state_machine::{RequestId, Session, Step};

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");
const FIXTURE_ISSUER: &[u8] =
    include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/signer-issuer.der");

/// 2027-01-15T08:00:00Z — inside the fixture chain's validity window, and
/// not the real wall-clock time, proving this instant (not
/// `SystemTime::now`) is what decided the verdict.
const FIXED_NOW: i64 = 1_800_000_000;

/// Answers `request` straight from [`C_JPG`], with [`FIXED_NOW`] standing
/// in for the wall clock.
fn answer(request: &FileReadRequest) -> FileReadReply {
    match request {
        FileReadRequest::Read { range, .. } => {
            let start = range.start as usize;
            let end = start + range.len as usize;
            match C_JPG.get(start..end) {
                Some(bytes) => FileReadReply::Bytes(bytes.to_vec()),
                None => FileReadReply::Failed(HostError::new("range out of bounds")),
            }
        }
        FileReadRequest::Length { .. } => FileReadReply::Length(C_JPG.len() as u64),
        FileReadRequest::CurrentDateTime => FileReadReply::CurrentDateTime(FIXED_NOW),
        other => panic!("unexpected request: {other:?}"),
    }
}

fn trusting_session() -> FileReadSession<JpegFormat> {
    FileReadSession::new(
        &JpegFormat,
        ReadSettings {
            trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
            ..ReadSettings::default()
        },
    )
}

#[test]
fn a_hand_rolled_host_can_supply_its_own_clock() {
    let mut session = trusting_session();

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
    assert!(report.manifest_store_found);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn advancing_past_complete_is_idempotent() {
    let mut session = trusting_session();

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            session.fulfill(request.id, answer(&request.kind)).unwrap();
        }
    }

    // The session already finished the workflow; the `Session` contract
    // promises `advance` keeps reporting so idempotently rather than
    // erroring or re-running anything.
    assert_eq!(session.advance().unwrap(), Step::Complete);
    assert_eq!(session.advance().unwrap(), Step::Complete);

    let report = session.finish().unwrap();
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn advancing_twice_without_new_replies_does_not_reissue_requests() {
    let mut session = trusting_session();

    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let first_round: Vec<RequestId> = session
        .outstanding_requests()
        .iter()
        .map(|request| request.id)
        .collect();
    assert!(!first_round.is_empty());

    // Nothing was fulfilled, so advancing again must report exactly the
    // same outstanding requests rather than issuing duplicates for
    // whatever the inner session still has pending.
    assert_eq!(session.advance().unwrap(), Step::AwaitHost);
    let second_round: Vec<RequestId> = session
        .outstanding_requests()
        .iter()
        .map(|request| request.id)
        .collect();

    assert_eq!(first_round, second_round);
}

#[test]
fn advancing_with_only_some_replies_ready_still_makes_progress() {
    let mut session = trusting_session();
    let mut saw_partial_fulfillment = false;

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        let requests = session.outstanding_requests().to_vec();

        if requests.len() > 1 && !saw_partial_fulfillment {
            // Answer only the first request this round — the host services
            // "any subset" of what is outstanding, per the interaction
            // contract — and confirm the session copes rather than
            // demanding everything at once.
            let first = &requests[0];
            session.fulfill(first.id, answer(&first.kind)).unwrap();
            saw_partial_fulfillment = true;
            continue;
        }

        for request in requests {
            session.fulfill(request.id, answer(&request.kind)).unwrap();
        }
    }

    assert!(
        saw_partial_fulfillment,
        "expected at least one round with more than one concurrent request \
         (the asset's hard-binding hash streams several chunks at once)"
    );

    let report = session.finish().unwrap();
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn a_malformed_asset_fails_during_locate() {
    // Not a JPEG at all, so `JpegFormat::locate` cannot even find `SOI`.
    let not_a_jpeg = b"\x89PNG\r\n\x1a\n".to_vec();

    let err = read_manifest(
        &JpegFormat,
        Cursor::new(not_a_jpeg),
        ReadSettings::default(),
    )
    .expect_err("a non-JPEG asset cannot be located");

    assert!(matches!(err, Error::Format(_)), "{err:?}");
}

#[test]
fn a_malformed_trust_anchor_fails_during_reading() {
    // `C_JPG` locates and its store parses cleanly; only the configured
    // anchor is broken, so this failure can only surface once the read
    // session itself is driven, not while locating the store.
    let err = read_manifest(
        &JpegFormat,
        Cursor::new(C_JPG.to_vec()),
        ReadSettings {
            trust_anchors: vec![vec![1, 2, 3]],
            ..ReadSettings::default()
        },
    )
    .expect_err("a trust anchor that is not a certificate cannot be decoded");

    assert!(matches!(err, Error::Read(_)), "{err:?}");
}

/// A marker segment with a length field — the minimal byte-layout helper
/// `contentauth-c2pa-format-jpeg`'s own tests use, reproduced here rather
/// than shared, since it is test-only scaffolding private to that crate.
fn segment(marker: u8, contents: &[u8]) -> Vec<u8> {
    let len = u16::try_from(contents.len() + 2).unwrap();
    let mut bytes = vec![0xff, marker];
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(contents);
    bytes
}

/// A JUMBF `APP11` segment carrying packet `z` of box instance `en`.
fn app11(en: [u8; 2], z: u32, payload: &[u8]) -> Vec<u8> {
    let mut contents = b"JP".to_vec();
    contents.extend_from_slice(&en);
    contents.extend_from_slice(&z.to_be_bytes());
    contents.extend_from_slice(payload);
    segment(0xeb, &contents)
}

/// A plausible manifest store of `len` bytes: a real superbox and
/// description-box header naming it a C2PA store, then filler bytes.
fn store(len: usize) -> Vec<u8> {
    const MANIFEST_STORE_UUID: [u8; 16] = [
        0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b,
        0x71,
    ];
    assert!(len >= 32);
    let mut store = (len as u32).to_be_bytes().to_vec();
    store.extend_from_slice(b"jumb");
    store.extend_from_slice(&[0, 0, 0, 0x1e]);
    store.extend_from_slice(b"jumd");
    store.extend_from_slice(&MANIFEST_STORE_UUID);
    store.extend((32..len).map(|i| (i % 251) as u8));
    store
}

#[test]
fn a_store_split_across_non_adjacent_segments_fails_locating() {
    // Two packets of the same box instance, correctly numbered, but with
    // an unrelated marker segment wedged between them: `JpegFormat` itself
    // is tested against this exact shape (`malformed_assets_are_reported_by_both_operations`
    // in that crate's own suite) and rejects it as malformed rather than
    // reassembling nonsense. Reproduced here to see which of this
    // session's two failure points — `advance` mid-scan or `finish` at
    // reassembly — a real handler's rejection surfaces through.
    let mut split = vec![0xff, 0xd8];
    split.extend(app11([2, 0x11], 1, &store(100)[..60]));
    split.extend(segment(0xfe, b"in between"));
    let mut second = store(100)[..8].to_vec();
    second.extend_from_slice(&store(100)[60..]);
    split.extend(app11([2, 0x11], 2, &second));
    split.extend_from_slice(&[0xff, 0xd9]);

    let err = read_manifest(&JpegFormat, Cursor::new(split), ReadSettings::default())
        .expect_err("non-adjacent manifest packets must not reassemble");

    assert!(matches!(err, Error::Format(_)), "{err:?}");
}
