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

//! [`FileReadSession`]: a sans-I/O session that composes a
//! [`FormatHandler`]'s `locate` operation with a [`ReadSession`], so a host
//! never has to know that two separate sessions are involved.
//!
//! Neither inner session performs I/O itself — that is the whole point of
//! the pattern this workspace builds on (see the root README). This crate's
//! [`read_manifest`](crate::read_manifest) and
//! [`read_manifest_from_file`](crate::read_manifest_from_file) are one
//! possible host for [`FileReadSession`], answering it synchronously from a
//! `Read + Seek` source. A host that only has asynchronous or
//! network-backed access to the asset — or that wants to supply its own
//! clock rather than the wall clock — drives [`FileReadSession`] directly
//! instead, exactly as it would any other session in this workspace.

use std::collections::HashMap;

use contentauth_c2pa_format::{FormatHandler, IoReply, IoRequest};
use contentauth_c2pa_primitives::{ByteRange, HostError, StreamId};
use contentauth_c2pa_reader::{
    ReadHostReply, ReadReport, ReadRequest, ReadSession, ReadSettings, ReadStep,
};
use contentauth_state_machine::{
    HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
};

use crate::error::Error;

/// The operations a [`FileReadSession`] may ask its host to perform.
///
/// Every variant names an absolute byte range or the whole stream, never a
/// position relative to a previous request: [`FileReadSession`] does not
/// assume its host can only answer them in order.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum FileReadRequest {
    /// Read a range of bytes from the asset. Reply with
    /// [`FileReadReply::Bytes`], carrying exactly `range.len` bytes.
    Read {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Report the total length of the asset, in bytes. Reply with
    /// [`FileReadReply::Length`].
    Length {
        /// The stream to measure.
        stream: StreamId,
    },

    /// Report the current wall-clock time. Reply with
    /// [`FileReadReply::CurrentDateTime`].
    CurrentDateTime,
}

impl Request for FileReadRequest {
    type Reply = FileReadReply;

    fn expected_reply(&self) -> &'static str {
        match self {
            Self::Read { .. } => "Bytes",
            Self::Length { .. } => "Length",
            Self::CurrentDateTime => "CurrentDateTime",
        }
    }

    fn accepts(&self, reply: &FileReadReply) -> bool {
        matches!(
            (self, reply),
            (_, FileReadReply::Failed(_))
                | (Self::Read { .. }, FileReadReply::Bytes(_))
                | (Self::Length { .. }, FileReadReply::Length(_))
                | (Self::CurrentDateTime, FileReadReply::CurrentDateTime(_))
        )
    }
}

/// The host's report of the outcome of one [`FileReadRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FileReadReply {
    /// Answers [`FileReadRequest::Read`]: the requested bytes.
    Bytes(Vec<u8>),

    /// Answers [`FileReadRequest::Length`]: the stream's total length in
    /// bytes.
    Length(u64),

    /// Answers [`FileReadRequest::CurrentDateTime`]: seconds since the Unix
    /// epoch (UTC).
    CurrentDateTime(i64),

    /// Reports that the host could not perform the requested operation.
    /// Valid for any request.
    Failed(HostError),
}

/// Where a [`FileReadSession`] is in its workflow.
enum Phase<H: FormatHandler> {
    /// Running `handler.locate(..)` to find the manifest store.
    Locating(H::Locate),

    /// Running the [`ReadSession`] that validates the store `Locating`
    /// found.
    Reading {
        /// The embedded manifest store `Locating` found, if any — answers
        /// [`ReadRequest::ManifestStore`] without ever surfacing it to this
        /// session's own host.
        manifest_store: Option<Vec<u8>>,
        session: Box<ReadSession>,
    },

    /// The workflow has finished.
    Done(ReadReport),
}

/// Locates and reads a C2PA manifest store, for any container format with a
/// [`FormatHandler`], without performing any I/O itself.
///
/// Two sessions run in sequence under one interface: `handler`'s `locate`
/// operation finds the manifest store, then a [`ReadSession`] validates it.
/// Both speak to this session's host through one merged vocabulary,
/// [`FileReadRequest`] — [`ReadRequest::ManifestStore`] is answered
/// internally, from `locate`'s result, and never reaches the host at all.
///
/// See the crate-level docs for why this exists alongside
/// [`crate::read_manifest`]: a host with only synchronous, local access can
/// use that convenience function instead of driving this session by hand.
pub struct FileReadSession<H: FormatHandler> {
    core: SessionCore<FileReadRequest>,

    /// Maps a request this session issued to its own host (the key) back to
    /// the inner session's request it stands in for (the value).
    pending: HashMap<RequestId, RequestId>,

    phase: Option<Phase<H>>,
    settings: Option<ReadSettings>,
}

impl<H: FormatHandler> FileReadSession<H> {
    /// Starts a new session: locates the manifest store via `handler`, then
    /// reads and validates it per `settings`.
    pub fn new(handler: &H, settings: ReadSettings) -> Self {
        Self {
            core: SessionCore::default(),
            pending: HashMap::new(),
            phase: Some(Phase::Locating(handler.locate(ReadSession::PRIMARY_STREAM))),
            settings: Some(settings),
        }
    }

    /// Removes and returns every reply this session's host has provided for
    /// a currently pending request, paired with the inner request it
    /// answers.
    fn ready_replies(&mut self) -> Vec<(RequestId, FileReadReply)> {
        let outer_ids: Vec<RequestId> = self.pending.keys().copied().collect();
        let mut ready = Vec::new();

        for outer_id in outer_ids {
            if let Some(reply) = self.core.take_reply(outer_id) {
                if let Some(inner_id) = self.pending.remove(&outer_id) {
                    ready.push((inner_id, reply));
                }
            }
        }

        ready
    }

    /// True if `inner_id` already has a host request pending for it.
    fn already_pending(&self, inner_id: RequestId) -> bool {
        self.pending.values().any(|&id| id == inner_id)
    }
}

impl<H: FormatHandler> Session for FileReadSession<H> {
    type Error = Error;
    type Output = ReadReport;
    type Request = FileReadRequest;

    fn advance(&mut self) -> Result<Step, Error> {
        loop {
            match self.phase.take() {
                None => {
                    self.core.mark_failed();
                    return Err(ProtocolError::SessionFailed.into());
                }

                Some(Phase::Locating(mut op)) => {
                    for (id, reply) in self.ready_replies() {
                        op.fulfill(id, to_io_reply(reply))?;
                    }

                    let step = match op.advance() {
                        Ok(step) => step,
                        Err(err) => {
                            self.core.mark_failed();
                            return Err(err.into());
                        }
                    };

                    if step == Step::Complete {
                        let location = match op.finish() {
                            Ok(location) => location,
                            Err(err) => {
                                self.core.mark_failed();
                                return Err(err.into());
                            }
                        };

                        self.phase = Some(Phase::Reading {
                            manifest_store: location.embedded.map(|manifest| manifest.jumbf),
                            session: Box::new(ReadSession::new(
                                self.settings.take().unwrap_or_default(),
                            )),
                        });
                        continue;
                    }

                    for request in op.outstanding_requests().to_vec() {
                        if self.already_pending(request.id) {
                            continue;
                        }

                        match from_io_request(&request.kind) {
                            Some(outer_kind) => {
                                let outer_id = self.core.issue(outer_kind);
                                self.pending.insert(outer_id, request.id);
                            }
                            None => {
                                op.fulfill(
                                    request.id,
                                    IoReply::Failed(HostError::new("unsupported request")),
                                )?;
                            }
                        }
                    }

                    self.phase = Some(Phase::Locating(op));
                    return Ok(Step::AwaitHost);
                }

                Some(Phase::Reading {
                    manifest_store,
                    mut session,
                }) => {
                    for (id, reply) in self.ready_replies() {
                        session.fulfill(id, to_read_host_reply(reply))?;
                    }

                    let step = match session.advance() {
                        Ok(step) => step,
                        Err(err) => {
                            self.core.mark_failed();
                            return Err(err.into());
                        }
                    };

                    if step == ReadStep::Complete {
                        let report = match session.finish() {
                            Ok(report) => report,
                            Err(err) => {
                                self.core.mark_failed();
                                return Err(err.into());
                            }
                        };

                        self.core.mark_complete();
                        self.phase = Some(Phase::Done(report));
                        return Ok(Step::Complete);
                    }

                    let mut answered_internally = false;

                    for request in session.outstanding_requests().to_vec() {
                        if self.already_pending(request.id) {
                            continue;
                        }

                        if let ReadRequest::ManifestStore { .. } = request.kind {
                            session.fulfill(
                                request.id,
                                ReadHostReply::ManifestStore(manifest_store.clone()),
                            )?;
                            answered_internally = true;
                            continue;
                        }

                        match from_read_request(&request.kind) {
                            Some(outer_kind) => {
                                let outer_id = self.core.issue(outer_kind);
                                self.pending.insert(outer_id, request.id);
                            }
                            None => {
                                session.fulfill(
                                    request.id,
                                    ReadHostReply::Failed(HostError::new("unsupported request")),
                                )?;
                            }
                        }
                    }

                    self.phase = Some(Phase::Reading {
                        manifest_store,
                        session,
                    });

                    if answered_internally {
                        continue;
                    }
                    return Ok(Step::AwaitHost);
                }

                Some(Phase::Done(report)) => {
                    self.phase = Some(Phase::Done(report));
                    return Ok(Step::Complete);
                }
            }
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<FileReadRequest>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: FileReadReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<ReadReport, Error> {
        self.core.finish_check()?;
        match self.phase {
            Some(Phase::Done(report)) => Ok(report),
            _ => Err(ProtocolError::SessionNotComplete.into()),
        }
    }
}

fn from_io_request(request: &IoRequest) -> Option<FileReadRequest> {
    match request {
        IoRequest::Read { stream, range } => Some(FileReadRequest::Read {
            stream: *stream,
            range: *range,
        }),
        IoRequest::Length { stream } => Some(FileReadRequest::Length { stream: *stream }),
        _ => None,
    }
}

/// Translates every [`ReadRequest`] kind this session's host answers
/// directly. [`ReadRequest::ManifestStore`] is not among them — the caller
/// answers it itself, from `locate`'s result, before this function ever
/// sees it.
fn from_read_request(request: &ReadRequest) -> Option<FileReadRequest> {
    match request {
        ReadRequest::AssetBytes { stream, range } => Some(FileReadRequest::Read {
            stream: *stream,
            range: *range,
        }),
        ReadRequest::AssetLength { stream } => Some(FileReadRequest::Length { stream: *stream }),
        ReadRequest::CurrentDateTime => Some(FileReadRequest::CurrentDateTime),
        _ => None,
    }
}

fn to_io_reply(reply: FileReadReply) -> IoReply {
    match reply {
        FileReadReply::Bytes(bytes) => IoReply::Bytes(bytes),
        FileReadReply::Length(len) => IoReply::Length(len),
        FileReadReply::Failed(err) => IoReply::Failed(err),
        FileReadReply::CurrentDateTime(_) => {
            IoReply::Failed(HostError::new("locate never asks for the time"))
        }
    }
}

fn to_read_host_reply(reply: FileReadReply) -> ReadHostReply {
    match reply {
        FileReadReply::Bytes(bytes) => ReadHostReply::AssetBytes(bytes),
        FileReadReply::Length(len) => ReadHostReply::AssetLength(len),
        FileReadReply::CurrentDateTime(time) => ReadHostReply::CurrentDateTime(time),
        FileReadReply::Failed(err) => ReadHostReply::Failed(err),
    }
}
