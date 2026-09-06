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

//! Drives [`FileReadSession`] directly, as a host that is neither
//! synchronous-file-backed nor bound to the wall clock would be: this
//! host answers every request from an asset it already holds in memory
//! (standing in for a cache, or bytes a network fetch already produced)
//! and reports a fixed instant instead of consulting the system clock.
//!
//! `read_manifest`/`read_manifest_from_file` cannot be configured to do
//! either of those things — they always seek a `Read + Seek` source and
//! always ask [`std::time::SystemTime::now`]. This is the interface to
//! reach for once that stops being the right answer.
//!
//! Run with `cargo run --example custom_host -p contentauth-c2pa-file-reader`.

use contentauth_c2pa_file_reader::{
    Error, FileReadReply, FileReadRequest, FileReadSession, ReadSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_primitives::HostError;
use contentauth_state_machine::{Session, Step};

/// A real JPEG signed by c2pa-rs, reused from `contentauth-c2pa-reader`'s
/// own fixtures.
const ASSET: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// A fixed instant inside the fixture's certificate validity window,
/// standing in for whatever clock this host actually trusts.
const FIXED_NOW: i64 = 1_800_000_000;

fn main() -> Result<(), Error> {
    let mut session = FileReadSession::new(&JpegFormat, ReadSettings::default());

    loop {
        if session.advance()? == Step::Complete {
            let report = session.finish()?;
            println!("validation state: {:?}", report.validation_state);
            return Ok(());
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(&request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

/// Answers a request straight from `ASSET`, with `FIXED_NOW` standing in
/// for the wall clock.
fn answer(request: &FileReadRequest) -> FileReadReply {
    match request {
        FileReadRequest::Read { range, .. } => {
            let start = range.start as usize;
            let end = start + range.len as usize;
            match ASSET.get(start..end) {
                Some(bytes) => FileReadReply::Bytes(bytes.to_vec()),
                None => FileReadReply::Failed(HostError::new("range lies past the end of ASSET")),
            }
        }

        FileReadRequest::Length { .. } => FileReadReply::Length(ASSET.len() as u64),

        FileReadRequest::CurrentDateTime => FileReadReply::CurrentDateTime(FIXED_NOW),

        other => FileReadReply::Failed(HostError::new(format!("unsupported request: {other:?}"))),
    }
}
