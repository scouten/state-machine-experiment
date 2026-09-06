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

//! Drives a [`FormatHandler`] operation and a [`ReadSession`], both against
//! the same `Read + Seek` source.
//!
//! Neither the reader nor a format handler knows about the other: the
//! reader asks its host for "the manifest store's bytes" and a handler's
//! `locate` operation answers exactly that question, but nothing wires them
//! together except a host. This module is that host, playing it the same
//! way `contentauth-c2pa-format-jpeg`'s own end-to-end test does by hand,
//! generalized to any handler and reused as library code instead of test
//! scaffolding.
//!
//! Every request either side issues names an absolute byte range, and
//! requests are not guaranteed to arrive or be answered in order (the
//! reader hashes an asset out of sequence when its host does), so this
//! module seeks for every read rather than assuming a forward-only stream —
//! the reason `Seek` is part of the bound, not just `Read`.

use std::{
    io::{self, Read, Seek, SeekFrom},
    time::{SystemTime, UNIX_EPOCH},
};

use contentauth_c2pa_format::{FormatHandler, FormatOp, IoReply, IoRequest, Step as FormatStep};
use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_c2pa_reader::{
    ReadHostReply, ReadReport, ReadRequest, ReadSession, ReadSettings, ReadStep,
};
use contentauth_state_machine::Session;

use crate::error::Error;

/// Locates and reads the manifest store embedded in `source`, validating it
/// per `settings`.
pub(crate) fn read<H: FormatHandler, R: Read + Seek>(
    handler: &H,
    mut source: R,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let manifest_store = locate(handler, &mut source)?;

    let mut session = ReadSession::new(settings);
    loop {
        if session.advance()? == ReadStep::Complete {
            return Ok(session.finish()?);
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = read_reply(&mut source, &manifest_store, &request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

/// Runs `handler`'s `locate` operation against `source` and returns the
/// embedded manifest store's bytes, if any.
fn locate<H: FormatHandler, R: Read + Seek>(
    handler: &H,
    source: &mut R,
) -> Result<Option<Vec<u8>>, contentauth_c2pa_format::FormatError> {
    let location = run_format_op(source, handler.locate(ReadSession::PRIMARY_STREAM))?;
    Ok(location.embedded.map(|manifest| manifest.jumbf))
}

/// Drives any [`FormatOp`] to completion, answering every [`IoRequest`] it
/// issues by reading from `source`.
fn run_format_op<Output, R: Read + Seek>(
    source: &mut R,
    mut op: impl FormatOp<Output>,
) -> Result<Output, contentauth_c2pa_format::FormatError> {
    loop {
        if op.advance()? == FormatStep::Complete {
            return op.finish();
        }

        for request in op.outstanding_requests().to_vec() {
            let reply = io_reply(source, &request.kind);
            op.fulfill(request.id, reply)?;
        }
    }
}

fn io_reply<R: Read + Seek>(source: &mut R, request: &IoRequest) -> IoReply {
    match request {
        IoRequest::Read { range, .. } => match read_range(source, *range) {
            Ok(bytes) => IoReply::Bytes(bytes),
            Err(err) => IoReply::Failed(read_failed(*range, &err)),
        },

        IoRequest::Length { .. } => match stream_len(source) {
            Ok(len) => IoReply::Length(len),
            Err(err) => IoReply::Failed(length_failed(&err)),
        },

        _ => IoReply::Failed(HostError::new("unsupported request")),
    }
}

fn read_reply<R: Read + Seek>(
    source: &mut R,
    manifest_store: &Option<Vec<u8>>,
    request: &ReadRequest,
) -> ReadHostReply {
    match request {
        ReadRequest::ManifestStore { .. } => ReadHostReply::ManifestStore(manifest_store.clone()),

        ReadRequest::AssetLength { .. } => match stream_len(source) {
            Ok(len) => ReadHostReply::AssetLength(len),
            Err(err) => ReadHostReply::Failed(length_failed(&err)),
        },

        ReadRequest::AssetBytes { range, .. } => match read_range(source, *range) {
            Ok(bytes) => ReadHostReply::AssetBytes(bytes),
            Err(err) => ReadHostReply::Failed(read_failed(*range, &err)),
        },

        ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(now_unix()),

        _ => ReadHostReply::Failed(HostError::new("unsupported request")),
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
