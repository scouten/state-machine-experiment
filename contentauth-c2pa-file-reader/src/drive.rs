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

//! A synchronous [`FileReadSession`] host for callers with a plain
//! `Read + Seek` source and no need for their own clock.
//!
//! This is one possible host, not the only one: [`FileReadSession`] itself
//! performs no I/O, so a host with asynchronous or network-backed access to
//! the asset, or that wants to supply something other than the wall clock,
//! drives it directly instead of going through this module.
//!
//! Every request [`FileReadSession`] issues names an absolute byte range,
//! not a position relative to a previous request, so this host seeks for
//! every read rather than assuming forward-only access — the reason `Seek`
//! is part of the bound, not just `Read`.

use std::{
    io::{self, Read, Seek, SeekFrom},
    time::{SystemTime, UNIX_EPOCH},
};

use contentauth_c2pa_format::FormatHandler;
use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_c2pa_reader::{ReadReport, ReadSettings};
use contentauth_state_machine::{Session, Step};

use crate::{
    error::Error,
    session::{FileReadReply, FileReadRequest, FileReadSession},
};

/// Locates and reads the manifest store embedded in `source`, validating it
/// per `settings`.
pub(crate) fn read<H: FormatHandler, R: Read + Seek>(
    handler: &H,
    mut source: R,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let mut session = FileReadSession::new(handler, settings);

    loop {
        if session.advance()? == Step::Complete {
            return session.finish();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(&mut source, &request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

fn answer<R: Read + Seek>(source: &mut R, request: &FileReadRequest) -> FileReadReply {
    match request {
        FileReadRequest::Read { range, .. } => match read_range(source, *range) {
            Ok(bytes) => FileReadReply::Bytes(bytes),
            Err(err) => FileReadReply::Failed(read_failed(*range, &err)),
        },

        FileReadRequest::Length { .. } => match stream_len(source) {
            Ok(len) => FileReadReply::Length(len),
            Err(err) => FileReadReply::Failed(length_failed(&err)),
        },

        FileReadRequest::CurrentDateTime => FileReadReply::CurrentDateTime(now_unix()),
    }
}

/// The current wall-clock time as Unix seconds, falling back to the epoch
/// on a clock reporting a time before it — a hypothetical this crate has no
/// better answer for, and the reader treats as any other implausible time.
fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// The stream's total length, found by seeking to its end.
///
/// `Seek::stream_len` would do this (and restore the original position),
/// but is not yet stable; nothing here depends on the position `source`
/// was left at, since every other operation seeks to an absolute offset
/// before reading.
fn stream_len<R: Seek>(source: &mut R) -> io::Result<u64> {
    source.seek(SeekFrom::End(0))
}

/// Seeks to `range.start` and reads exactly `range.len` bytes.
fn read_range<R: Read + Seek>(source: &mut R, range: ByteRange) -> io::Result<Vec<u8>> {
    let len = usize::try_from(range.len)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    source.seek(SeekFrom::Start(range.start))?;
    let mut buf = vec![0u8; len];
    source.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_failed(range: ByteRange, err: &io::Error) -> HostError {
    HostError::new(format!(
        "could not read {}+{} bytes: {err}",
        range.start, range.len
    ))
}

fn length_failed(err: &io::Error) -> HostError {
    HostError::new(format!("could not determine stream length: {err}"))
}
