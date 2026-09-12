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
//!
//! This host has no network access, so it answers
//! [`FileReadRequest::Ocsp`] with [`FileReadReply::Failed`] — the same
//! outcome a caller sees from any other request this host cannot service.
//! That is a safe default rather than a limitation to work around: OCSP
//! checking is fail-open (see
//! [`ReadSettings::check_ocsp`](contentauth_c2pa_reader::ReadSettings::check_ocsp)),
//! so a manifest reads exactly as it would if checking were disabled. A
//! host that wants live OCSP checks drives [`FileReadSession`] directly and
//! answers that request itself — see, for instance,
//! `contentauth-c2pa-rs-compat`'s `reqwest`-backed host.

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

        // This host has no network access of its own — see the module
        // docs. Failing the request is safe: revocation checking is
        // fail-open (`ReadSettings::check_ocsp`'s own docs), so this reads
        // exactly as "could not be checked" rather than as a rejection.
        FileReadRequest::Ocsp { .. } => {
            FileReadReply::Failed(HostError::new("this host has no network access for OCSP"))
        }
    }
}

/// The current wall-clock time as Unix seconds.
fn now_unix() -> i64 {
    unix_seconds(SystemTime::now())
}

/// `time` as Unix seconds, falling back to the epoch for a time before it —
/// a hypothetical this crate has no better answer for, and the reader
/// treats as any other implausible time.
fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{io::Cursor, time::Duration};

    use contentauth_c2pa_primitives::StreamId;

    use super::*;

    /// A `Read + Seek` source whose every operation fails — standing in
    /// for a source this host cannot actually reach (a dropped network
    /// connection, an unreadable device), since `Cursor` cannot fail this
    /// way itself.
    struct AlwaysFails;

    impl Read for AlwaysFails {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("always fails"))
        }
    }

    impl Seek for AlwaysFails {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Err(io::Error::other("always fails"))
        }
    }

    fn stream() -> StreamId {
        StreamId::new(0)
    }

    #[test]
    fn a_read_past_the_end_of_the_source_is_reported_as_failed() {
        let mut source = Cursor::new(vec![1u8, 2, 3]);
        let reply = answer(
            &mut source,
            &FileReadRequest::Read {
                stream: stream(),
                range: ByteRange { start: 0, len: 10 },
            },
        );

        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_length_is_reported_as_failed() {
        let reply = answer(
            &mut AlwaysFails,
            &FileReadRequest::Length { stream: stream() },
        );
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_read_is_reported_as_failed() {
        let reply = answer(
            &mut AlwaysFails,
            &FileReadRequest::Read {
                stream: stream(),
                range: ByteRange { start: 0, len: 1 },
            },
        );

        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_clock_before_the_epoch_reports_the_epoch_itself() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("this platform can represent an instant before the epoch");

        assert_eq!(unix_seconds(before_epoch), 0);
    }
}
