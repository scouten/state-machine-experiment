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
//! own convenience host in `src/drive.rs`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_file_reader::{FileReadReply, FileReadRequest, FileReadSession, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_primitives::HostError;
use contentauth_c2pa_reader::ValidationState;
use contentauth_state_machine::{Session, Step};

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");
const FIXTURE_ISSUER: &[u8] =
    include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/signer-issuer.der");

/// 2027-01-15T08:00:00Z — inside the fixture chain's validity window, and
/// not the real wall-clock time, proving this instant (not
/// `SystemTime::now`) is what decided the verdict.
const FIXED_NOW: i64 = 1_800_000_000;

#[test]
fn a_hand_rolled_host_can_supply_its_own_clock() {
    let mut session = FileReadSession::new(
        &JpegFormat,
        ReadSettings {
            trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
            ..ReadSettings::default()
        },
    );

    loop {
        if session.advance().unwrap() == Step::Complete {
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
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
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }

    let report = session.finish().unwrap();
    assert!(report.manifest_store_found);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}
