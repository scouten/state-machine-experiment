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
//! the same in-memory byte buffer.
//!
//! Neither the reader nor a format handler knows about the other: the
//! reader asks its host for "the manifest store's bytes" and a handler's
//! `locate` operation answers exactly that question, but nothing wires them
//! together except a host. This module is that host, playing it the same
//! way `contentauth-c2pa-format-jpeg`'s own end-to-end test does by hand,
//! generalized to any handler and reused as library code instead of test
//! scaffolding.

use std::time::{SystemTime, UNIX_EPOCH};

use contentauth_c2pa_format::{FormatHandler, FormatOp, IoReply, IoRequest, Step as FormatStep};
use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_c2pa_reader::{
    ReadHostReply, ReadReport, ReadRequest, ReadSession, ReadSettings, ReadStep,
};
use contentauth_state_machine::Session;

use crate::error::Error;

/// Locates and reads the manifest store embedded in `bytes`, validating it
/// per `settings`.
pub(crate) fn read<H: FormatHandler>(
    handler: &H,
    bytes: &[u8],
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let manifest_store = locate(handler, bytes)?;

    let mut session = ReadSession::new(settings);
    loop {
        if session.advance()? == ReadStep::Complete {
            return Ok(session.finish()?);
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = read_reply(bytes, &manifest_store, &request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

/// Runs `handler`'s `locate` operation against `bytes` and returns the
/// embedded manifest store's bytes, if any.
fn locate<H: FormatHandler>(
    handler: &H,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, contentauth_c2pa_format::FormatError> {
    let location = run_format_op(bytes, handler.locate(ReadSession::PRIMARY_STREAM))?;
    Ok(location.embedded.map(|manifest| manifest.jumbf))
}

/// Drives any [`FormatOp`] to completion, answering every [`IoRequest`] it
/// issues by slicing `bytes`.
fn run_format_op<Output>(
    bytes: &[u8],
    mut op: impl FormatOp<Output>,
) -> Result<Output, contentauth_c2pa_format::FormatError> {
    loop {
        if op.advance()? == FormatStep::Complete {
            return op.finish();
        }

        for request in op.outstanding_requests().to_vec() {
            let reply = io_reply(bytes, &request.kind);
            op.fulfill(request.id, reply)?;
        }
    }
}

fn io_reply(bytes: &[u8], request: &IoRequest) -> IoReply {
    match request {
        IoRequest::Read { range, .. } => match slice(bytes, *range) {
            Some(slice) => IoReply::Bytes(slice.to_vec()),
            None => IoReply::Failed(out_of_range(*range, bytes.len())),
        },

        IoRequest::Length { .. } => IoReply::Length(bytes.len() as u64),

        _ => IoReply::Failed(HostError::new("unsupported request")),
    }
}

fn read_reply(
    bytes: &[u8],
    manifest_store: &Option<Vec<u8>>,
    request: &ReadRequest,
) -> ReadHostReply {
    match request {
        ReadRequest::ManifestStore { .. } => ReadHostReply::ManifestStore(manifest_store.clone()),

        ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(bytes.len() as u64),

        ReadRequest::AssetBytes { range, .. } => match slice(bytes, *range) {
            Some(slice) => ReadHostReply::AssetBytes(slice.to_vec()),
            None => ReadHostReply::Failed(out_of_range(*range, bytes.len())),
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

fn slice(bytes: &[u8], range: ByteRange) -> Option<&[u8]> {
    let end = range.start.checked_add(range.len)?;
    if end > bytes.len() as u64 {
        return None;
    }
    Some(&bytes[range.start as usize..end as usize])
}

fn out_of_range(range: ByteRange, len: usize) -> HostError {
    HostError::new(format!(
        "range {}+{} lies past the end of the asset ({len} bytes)",
        range.start, range.len
    ))
}
