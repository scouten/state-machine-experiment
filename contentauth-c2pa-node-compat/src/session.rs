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

//! [`NodeSession`]: the synchronous surface Node drives.

use std::collections::HashMap;

use contentauth_c2pa_file_reader::{FileReadReply, FileReadRequest, FileReadSession};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_js_compat::{for_format, C2paError, Context, Error};
use contentauth_c2pa_primitives::HostError;
use contentauth_state_machine::{RequestId, Session};

use crate::reader::Reader;

/// One thing the session needs its host to do, as plain data.
///
/// `id` is what to quote back to [`NodeSession::fulfill`]. Every field is
/// a number, string or byte vector: nothing here needs the host to know
/// about this workspace's types.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PendingRequest {
    /// Read exactly `len` bytes of the asset starting at `start`.
    /// Answer with [`Reply::Bytes`].
    Read {
        /// The handle to pass to [`NodeSession::fulfill`].
        id: u64,
        /// Offset of the first byte.
        start: u64,
        /// Number of bytes.
        len: u64,
    },

    /// Report the asset's total length. Answer with [`Reply::Length`].
    Length {
        /// The handle to pass to [`NodeSession::fulfill`].
        id: u64,
    },

    /// Report the wall clock. Answer with [`Reply::Time`].
    CurrentDateTime {
        /// The handle to pass to [`NodeSession::fulfill`].
        id: u64,
    },

    /// POST `request_der` to the OCSP responder at `url` and return the
    /// response body. Answer with [`Reply::Ocsp`].
    Ocsp {
        /// The handle to pass to [`NodeSession::fulfill`].
        id: u64,
        /// The responder's URL.
        url: String,
        /// The DER `OCSPRequest` to send.
        request_der: Vec<u8>,
    },
}

impl PendingRequest {
    /// The handle to pass to [`NodeSession::fulfill`].
    pub fn id(&self) -> u64 {
        match self {
            Self::Read { id, .. }
            | Self::Length { id }
            | Self::CurrentDateTime { id }
            | Self::Ocsp { id, .. } => *id,
        }
    }
}

/// The host's answer to one [`PendingRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// The bytes a [`PendingRequest::Read`] asked for.
    Bytes(Vec<u8>),
    /// The asset's length in bytes.
    Length(u64),
    /// Seconds since the Unix epoch (UTC).
    Time(i64),
    /// An OCSP response body.
    Ocsp(Vec<u8>),
    /// The host could not do it. Valid for any request; the engine
    /// decides what that means (fail-open for OCSP, an unevaluated
    /// validity window for the clock, an error for an asset read).
    Failed(String),
}

/// What [`NodeSession::advance`] reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Not finished. The vector holds the requests that are *new* since
    /// the last call — possibly none, if the session is still waiting on
    /// requests already reported. Start them, [`fulfill`](NodeSession::fulfill)
    /// as they settle, and advance again once at least one has.
    Pending(Vec<PendingRequest>),

    /// Finished; call [`NodeSession::finish`].
    Complete,
}

/// A read of one asset, driven entirely by its caller.
///
/// A thin, FFI-shaped wrapper over
/// [`FileReadSession`]: it never blocks, never
/// spawns, and holds no lock. It is `Send` or not exactly as the engine
/// is, and nothing here requires either.
pub struct NodeSession {
    inner: FileReadSession<JpegFormat>,

    /// Numbers handed to the host, mapped to the engine's own ids. The
    /// engine's `RequestId` is opaque (and rightly so); the host's handle
    /// is a plain number.
    handles: HashMap<u64, RequestId>,
    next_handle: u64,

    /// Engine ids already reported by a previous `advance`, so each
    /// request is surfaced to the host exactly once.
    reported: HashMap<RequestId, u64>,
}

impl NodeSession {
    /// Starts a read of an asset of type `format` (a MIME type or bare
    /// extension, as c2pa-node's `mimeType`), under c2pa-rs settings JSON
    /// `settings_json` (none: c2pa-rs defaults).
    ///
    /// Fails with [`C2paError::UnsupportedType`] or
    /// [`C2paError::BadParam`] before any request is made.
    pub fn new(format: &str, settings_json: Option<&str>) -> Result<Self, Error> {
        let handler = for_format(format)?;
        let context = match settings_json {
            Some(json) => Context::from_json(json)?,
            None => Context::default(),
        };

        Ok(Self {
            inner: FileReadSession::new(&handler, context.into_settings()),
            handles: HashMap::new(),
            next_handle: 0,
            reported: HashMap::new(),
        })
    }

    /// Runs the engine as far as it can go without the host.
    ///
    /// Synchronous and bounded: one slice of parsing or hashing, then
    /// either completion or the requests that stand in its way.
    pub fn advance(&mut self) -> Result<Step, Error> {
        use contentauth_state_machine::Step as Engine;

        match self.inner.advance().map_err(C2paError::from)? {
            Engine::Complete => Ok(Step::Complete),
            _ => {
                let mut fresh = Vec::new();
                for request in self.inner.outstanding_requests() {
                    if self.reported.contains_key(&request.id) {
                        continue;
                    }
                    let handle = self.next_handle;
                    let pending = describe(handle, &request.kind)?;
                    self.next_handle += 1;
                    self.reported.insert(request.id, handle);
                    self.handles.insert(handle, request.id);
                    fresh.push(pending);
                }
                Ok(Step::Pending(fresh))
            }
        }
    }

    /// Reports the outcome of one pending request. Replies may arrive in
    /// any order and any subset between calls to [`Self::advance`].
    ///
    /// Fails if `id` was never issued, was already answered, or `reply`
    /// is the wrong kind for it.
    pub fn fulfill(&mut self, id: u64, reply: Reply) -> Result<(), Error> {
        let engine_id = *self.handles.get(&id).ok_or_else(|| {
            C2paError::BadParam(format!("no outstanding request with handle {id}"))
        })?;

        let reply = engine_reply(reply);

        self.inner
            .fulfill(engine_id, reply)
            .map_err(C2paError::from)?;
        // Answered, so the engine no longer lists it as outstanding: forget
        // it, rather than keep an entry per request for the whole read.
        self.handles.remove(&id);
        self.reported.remove(&engine_id);
        Ok(())
    }

    /// Consumes the finished session.
    ///
    /// `None` if the asset carries no manifest store — the case c2pa-node
    /// turns the `JumbfNotFound` error into a `null` reader for.
    pub fn finish(self) -> Result<Option<Reader>, Error> {
        let report = self.inner.finish().map_err(C2paError::from)?;
        Ok(report.manifest_store_found.then(|| Reader::new(report)))
    }
}

/// Describes `request` to the host as plain data, under `handle`.
///
/// Fails for a request this wrapper has no description for:
/// `FileReadRequest` is `#[non_exhaustive]`, so a future variant must fail
/// the read loudly rather than be silently misdescribed.
fn describe(handle: u64, request: &FileReadRequest) -> Result<PendingRequest, C2paError> {
    Ok(match request {
        FileReadRequest::Read { range, .. } => PendingRequest::Read {
            id: handle,
            start: range.start,
            len: range.len,
        },
        FileReadRequest::Length { .. } => PendingRequest::Length { id: handle },
        FileReadRequest::CurrentDateTime => PendingRequest::CurrentDateTime { id: handle },
        FileReadRequest::Ocsp { url, request_der } => PendingRequest::Ocsp {
            id: handle,
            url: url.clone(),
            request_der: request_der.clone(),
        },
        other => {
            return Err(C2paError::BadParam(format!(
                "unsupported request {other:?}"
            )))
        }
    })
}

/// The engine's form of the host's `reply`.
fn engine_reply(reply: Reply) -> FileReadReply {
    match reply {
        Reply::Bytes(bytes) => FileReadReply::Bytes(bytes),
        Reply::Length(len) => FileReadReply::Length(len),
        Reply::Time(secs) => FileReadReply::CurrentDateTime(secs),
        Reply::Ocsp(bytes) => FileReadReply::OcspResponse(bytes),
        Reply::Failed(message) => FileReadReply::Failed(HostError::new(message)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use contentauth_c2pa_primitives::{ByteRange, StreamId};

    use super::*;

    // No asset in this repository's fixtures is signed by a certificate
    // with an OCSP responder, so the engine never issues an OCSP request
    // end to end here; the mapping of that one request and reply is
    // checked directly instead.

    #[test]
    fn every_engine_request_is_described_to_the_host() {
        let stream = StreamId::new(0);
        let range = ByteRange { start: 5, len: 7 };

        assert_eq!(
            describe(1, &FileReadRequest::Read { stream, range }).ok(),
            Some(PendingRequest::Read {
                id: 1,
                start: 5,
                len: 7
            })
        );
        assert_eq!(
            describe(2, &FileReadRequest::Length { stream }).ok(),
            Some(PendingRequest::Length { id: 2 })
        );
        assert_eq!(
            describe(3, &FileReadRequest::CurrentDateTime).ok(),
            Some(PendingRequest::CurrentDateTime { id: 3 })
        );
        assert_eq!(
            describe(
                4,
                &FileReadRequest::Ocsp {
                    url: "http://ocsp.example/".to_string(),
                    request_der: vec![1, 2, 3],
                }
            )
            .ok(),
            Some(PendingRequest::Ocsp {
                id: 4,
                url: "http://ocsp.example/".to_string(),
                request_der: vec![1, 2, 3],
            })
        );
    }

    #[test]
    fn an_answered_request_is_forgotten_rather_than_kept_for_the_whole_read() {
        let mut session = NodeSession::new("image/jpeg", None).unwrap();
        let Step::Pending(requests) = session.advance().unwrap() else {
            panic!("a fresh session needs the host");
        };
        assert_eq!(session.reported.len(), requests.len());
        assert_eq!(session.handles.len(), requests.len());

        session
            .fulfill(requests[0].id(), Reply::Failed("no".to_string()))
            .unwrap();
        assert_eq!(session.reported.len(), requests.len() - 1);
        assert_eq!(session.handles.len(), requests.len() - 1);
    }

    #[test]
    fn every_pending_request_reports_its_own_handle() {
        let requests = [
            PendingRequest::Read {
                id: 7,
                start: 0,
                len: 0,
            },
            PendingRequest::Length { id: 8 },
            PendingRequest::CurrentDateTime { id: 9 },
            PendingRequest::Ocsp {
                id: 10,
                url: String::new(),
                request_der: vec![],
            },
        ];
        let ids: Vec<u64> = requests.iter().map(PendingRequest::id).collect();
        assert_eq!(ids, [7, 8, 9, 10]);
    }

    #[test]
    fn every_host_reply_becomes_the_engines_reply_of_the_same_kind() {
        assert!(matches!(engine_reply(Reply::Bytes(vec![1])), FileReadReply::Bytes(b) if b == [1]));
        assert!(matches!(
            engine_reply(Reply::Length(9)),
            FileReadReply::Length(9)
        ));
        assert!(matches!(
            engine_reply(Reply::Time(-1)),
            FileReadReply::CurrentDateTime(-1)
        ));
        assert!(matches!(
            engine_reply(Reply::Ocsp(vec![4, 5])),
            FileReadReply::OcspResponse(b) if b == [4, 5]
        ));
        assert!(matches!(
            engine_reply(Reply::Failed("no".to_string())),
            FileReadReply::Failed(e) if e.message == "no"
        ));
    }
}
