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

//! [`FileBuilderSession`]: a sans-I/O session that composes a
//! [`FormatHandler`]'s `plan_embed`/`commit` operations with a
//! [`BuilderSession`], so a host never has to know that two separate
//! sessions — or a container format at all — are involved.
//!
//! Neither inner piece performs I/O itself: `plan_embed` and `commit` only
//! ever need to *read* the source asset (never write it — see the
//! `contentauth-c2pa-format` crate docs for why), and `BuilderSession`
//! externalizes signing, timestamping, and the asset bytes it works over.
//! This session holds the whole source asset in memory once it has been
//! read (materializing the output is not, today, something this
//! workspace's `EmbedPlan` can do a range at a time — see the crate-level
//! docs for what a future streaming orchestrator would change), and
//! answers every `BuilderRequest` this composition can resolve on its own
//! — `ReservePlaceholder`, `AssetLength`, `AssetBytes`, and
//! `CommitManifest` — without ever surfacing them to its own host. Only
//! `Sign` and `Timestamp` reach the host: nothing in this workspace can
//! stand in for a real signing key or a timestamp authority round trip.

use std::collections::HashMap;

use contentauth_c2pa_builder::{BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings};
use contentauth_c2pa_format::{EmbedPlan, FormatHandler, FormatOp, IoReply, IoRequest};
use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, HostError, SigningAlg, StreamId};
use contentauth_state_machine::{
    HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
};

use crate::error::Error;

/// The operations a [`FileBuilderSession`] may ask its host to perform.
///
/// `Read` and `Length` concern only the source asset, read once in full
/// before this session does anything else; `Sign` and `Timestamp` are
/// forwarded verbatim from the [`BuilderSession`] this composes.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum FileBuilderRequest {
    /// Read a range of bytes from the source asset. Reply with
    /// [`FileBuilderReply::Bytes`], carrying exactly `range.len` bytes.
    Read {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Report the total length of the source asset, in bytes. Reply with
    /// [`FileBuilderReply::Length`].
    Length {
        /// The stream to measure.
        stream: StreamId,
    },

    /// Sign `data` — a COSE `Sig_structure` — with `alg`. Reply with
    /// [`FileBuilderReply::Signature`].
    ///
    /// Mirrors [`BuilderRequest::Sign`] exactly: the host is responsible
    /// for however it holds or reaches the signing key.
    Sign {
        /// The algorithm to sign with.
        alg: SigningAlg,

        /// The exact bytes to sign.
        data: Vec<u8>,
    },

    /// Obtain an RFC 3161 countersignature over `digest`. Reply with
    /// [`FileBuilderReply::Timestamp`].
    ///
    /// Mirrors [`BuilderRequest::Timestamp`] exactly: the host is
    /// responsible for the full timestamp authority round trip.
    Timestamp {
        /// The digest the timestamp must cover.
        digest: Vec<u8>,

        /// The algorithm `digest` was computed with.
        hash_alg: HashAlgorithm,
    },
}

impl Request for FileBuilderRequest {
    type Reply = FileBuilderReply;

    fn expected_reply(&self) -> &'static str {
        match self {
            Self::Read { .. } => "Bytes",
            Self::Length { .. } => "Length",
            Self::Sign { .. } => "Signature",
            Self::Timestamp { .. } => "Timestamp",
        }
    }

    fn accepts(&self, reply: &FileBuilderReply) -> bool {
        matches!(
            (self, reply),
            (_, FileBuilderReply::Failed(_))
                | (Self::Read { .. }, FileBuilderReply::Bytes(_))
                | (Self::Length { .. }, FileBuilderReply::Length(_))
                | (Self::Sign { .. }, FileBuilderReply::Signature(_))
                | (Self::Timestamp { .. }, FileBuilderReply::Timestamp(_))
        )
    }
}

/// The host's report of the outcome of one [`FileBuilderRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FileBuilderReply {
    /// Answers [`FileBuilderRequest::Read`]: the requested bytes.
    Bytes(Vec<u8>),

    /// Answers [`FileBuilderRequest::Length`]: the stream's total length
    /// in bytes.
    Length(u64),

    /// Answers [`FileBuilderRequest::Sign`]: the raw signature bytes.
    Signature(Vec<u8>),

    /// Answers [`FileBuilderRequest::Timestamp`]: the bare
    /// `TimeStampToken` bytes.
    Timestamp(Vec<u8>),

    /// Reports that the host could not perform the requested operation.
    /// Valid for any request.
    Failed(HostError),
}

/// The result of a completed [`FileBuilderSession`] workflow.
#[derive(Debug)]
#[non_exhaustive]
pub struct FileBuilderReport {
    /// The complete output asset, with the signed manifest store embedded.
    pub asset: Vec<u8>,

    /// The final, signed C2PA manifest store bytes alone — identical to
    /// the bytes embedded at [`Self::manifest_range`].
    pub manifest: Vec<u8>,

    /// The byte range of the container structure carrying the manifest,
    /// framing included — the hard binding's exclusion.
    pub manifest_range: ByteRange,
}

/// Where a [`FileBuilderSession`] is in its workflow.
enum Phase {
    /// Learning how large the source asset is.
    FetchingLength(RequestId),

    /// Reading the whole source asset in one range, now that its length
    /// is known.
    FetchingSource { len: u64, request: RequestId },

    /// Driving the inner [`BuilderSession`], with the whole source asset
    /// cached. `plan`/`output` are populated once `ReservePlaceholder` has
    /// been answered.
    Building {
        session: Box<BuilderSession>,
        source: Vec<u8>,
        plan: Option<EmbedPlan>,
        output: Option<Vec<u8>>,
    },

    /// The workflow has finished.
    Done(FileBuilderReport),
}

/// Builds and signs a C2PA manifest store, for any container format with a
/// [`FormatHandler`], without performing any I/O itself beyond what only
/// its host can do: reading the source asset, signing, and (optionally)
/// timestamping.
///
/// A [`BuilderSession`] runs underneath, but never speaks to this
/// session's host directly: `ReservePlaceholder`, `AssetLength`,
/// `AssetBytes`, and `CommitManifest` are all answered internally, from
/// the format handler's `plan_embed`/`commit` and the cached source and
/// output bytes. Only `Sign` and `Timestamp` — the two things nothing in
/// this workspace can do on a host's behalf — are forwarded, as
/// [`FileBuilderRequest::Sign`] and [`FileBuilderRequest::Timestamp`].
///
/// See the crate-level docs for why this exists alongside
/// [`crate::build_and_sign`]: a host with only synchronous, local access
/// to the source (and a plain signing function) can use that convenience
/// function instead of driving this session by hand.
pub struct FileBuilderSession<H: FormatHandler + Send> {
    core: SessionCore<FileBuilderRequest>,

    /// Maps a request this session issued to its own host (the key) back
    /// to the [`BuilderSession`] request it stands in for (the value).
    /// Only ever holds `Sign`/`Timestamp` pairs — everything else this
    /// composition answers itself.
    pending: HashMap<RequestId, RequestId>,

    handler: H,
    stream: StreamId,
    settings: Option<BuilderSettings>,
    phase: Option<Phase>,
}

impl<H: FormatHandler + Send> FileBuilderSession<H> {
    /// Starts a new session: reads the whole source asset via `handler`'s
    /// stream, then builds and signs a manifest for it per `settings`.
    pub fn new(handler: H, settings: BuilderSettings) -> Self {
        let mut core = SessionCore::default();
        let stream = BuilderSession::PRIMARY_STREAM;
        let request = core.issue(FileBuilderRequest::Length { stream });

        Self {
            core,
            pending: HashMap::new(),
            handler,
            stream,
            settings: Some(settings),
            phase: Some(Phase::FetchingLength(request)),
        }
    }

    /// Removes and returns every reply this session's host has provided
    /// for a currently pending request, paired with the
    /// [`BuilderSession`] request it answers.
    fn ready_replies(&mut self) -> Vec<(RequestId, FileBuilderReply)> {
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

    /// Marks this session failed if `result` is an error, so `self.core`
    /// never disagrees with the workflow this session has actually
    /// abandoned — see [`crate`] for why every fallible call in `advance`
    /// after `self.phase.take()` is routed through this.
    fn poisoning<T, E: Into<Error>>(&mut self, result: Result<T, E>) -> Result<T, Error> {
        result.map_err(|err| {
            self.core.mark_failed();
            err.into()
        })
    }
}

impl<H: FormatHandler + Send> Session for FileBuilderSession<H> {
    type Error = Error;
    type Output = FileBuilderReport;
    type Request = FileBuilderRequest;

    fn advance(&mut self) -> Result<Step, Error> {
        loop {
            match self.phase.take() {
                None => {
                    self.core.mark_failed();
                    return Err(ProtocolError::SessionFailed.into());
                }

                Some(Phase::FetchingLength(request)) => {
                    let result = take_length(&mut self.core, request);
                    let reply = self.poisoning(result)?;

                    let Some(len) = reply else {
                        self.phase = Some(Phase::FetchingLength(request));
                        return Ok(Step::AwaitHost);
                    };

                    let request = self.core.issue(FileBuilderRequest::Read {
                        stream: self.stream,
                        range: ByteRange { start: 0, len },
                    });
                    self.phase = Some(Phase::FetchingSource { len, request });
                    continue;
                }

                Some(Phase::FetchingSource { len, request }) => {
                    let range = ByteRange { start: 0, len };
                    let result = take_bytes(&mut self.core, request, range);
                    let reply = self.poisoning(result)?;

                    let Some(source) = reply else {
                        self.phase = Some(Phase::FetchingSource { len, request });
                        return Ok(Step::AwaitHost);
                    };

                    // Taken exactly once, right here, so this can only be
                    // `None` if this arm somehow ran twice for one
                    // session — a bug worth failing loudly over rather
                    // than silently building with fabricated settings.
                    let settings = self.settings.take();
                    let settings =
                        self.poisoning(settings.ok_or(Error::Invariant("settings already taken")))?;

                    self.phase = Some(Phase::Building {
                        session: Box::new(BuilderSession::new(settings)),
                        source,
                        plan: None,
                        output: None,
                    });
                    continue;
                }

                Some(Phase::Building {
                    mut session,
                    source,
                    mut plan,
                    mut output,
                }) => {
                    for (id, reply) in self.ready_replies() {
                        let translated = to_builder_host_reply(reply);
                        let result = session.fulfill(id, translated);
                        self.poisoning(result)?;
                    }

                    let step = self.poisoning(session.advance())?;

                    if step == Step::Complete {
                        let report = self.poisoning(session.finish())?;

                        // `BuilderSession` cannot reach `Complete` without
                        // first issuing `CommitManifest`, which is what
                        // sets `output` — unreachable in practice, but
                        // this session materializes the final asset
                        // itself, so nothing double-checks that on
                        // `BuilderSession`'s behalf.
                        let asset = match output {
                            Some(asset) => asset,
                            None => {
                                self.core.mark_failed();
                                return Err(Error::Invariant(
                                    "builder completed without ever committing a manifest",
                                ));
                            }
                        };

                        self.core.mark_complete();
                        self.phase = Some(Phase::Done(FileBuilderReport {
                            asset,
                            manifest: report.manifest,
                            manifest_range: report.manifest_range,
                        }));
                        return Ok(Step::Complete);
                    }

                    let mut answered_internally = false;

                    for request in session.outstanding_requests().to_vec() {
                        if self.already_pending(request.id) {
                            continue;
                        }

                        match &request.kind {
                            BuilderRequest::ReservePlaceholder {
                                stream,
                                placeholder,
                            } => {
                                let result = reserve_placeholder(
                                    &self.handler,
                                    &source,
                                    *stream,
                                    placeholder,
                                );
                                let (embed_plan, materialized) = self.poisoning(result)?;

                                let exclusion = embed_plan.exclusion;
                                plan = Some(embed_plan);
                                output = Some(materialized);

                                let result = session.fulfill(
                                    request.id,
                                    BuilderHostReply::PlaceholderReserved(exclusion),
                                );
                                self.poisoning(result)?;
                                answered_internally = true;
                            }

                            BuilderRequest::AssetLength { .. } => {
                                let asset = output.as_ref().ok_or(Error::Invariant(
                                    "AssetLength asked for before ReservePlaceholder",
                                ));
                                let len = self.poisoning(asset.map(|asset| asset.len() as u64))?;

                                let result =
                                    session.fulfill(request.id, BuilderHostReply::AssetLength(len));
                                self.poisoning(result)?;
                                answered_internally = true;
                            }

                            BuilderRequest::AssetBytes { range, .. } => {
                                let bytes = output
                                    .as_ref()
                                    .ok_or(Error::Invariant(
                                        "AssetBytes asked for before ReservePlaceholder",
                                    ))
                                    .and_then(|asset| slice(asset, *range));
                                let bytes = self.poisoning(bytes)?;

                                let result = session.fulfill(
                                    request.id,
                                    BuilderHostReply::AssetBytes(bytes.to_vec()),
                                );
                                self.poisoning(result)?;
                                answered_internally = true;
                            }

                            BuilderRequest::Sign { alg, data } => {
                                let outer_id = self.core.issue(FileBuilderRequest::Sign {
                                    alg: *alg,
                                    data: data.clone(),
                                });
                                self.pending.insert(outer_id, request.id);
                            }

                            BuilderRequest::Timestamp { digest, hash_alg } => {
                                let outer_id = self.core.issue(FileBuilderRequest::Timestamp {
                                    digest: digest.clone(),
                                    hash_alg: *hash_alg,
                                });
                                self.pending.insert(outer_id, request.id);
                            }

                            BuilderRequest::CommitManifest { manifest, .. } => {
                                let result =
                                    commit_manifest(&self.handler, &source, &plan, manifest);
                                let materialized = self.poisoning(result)?;
                                output = Some(materialized);

                                let result = session
                                    .fulfill(request.id, BuilderHostReply::ManifestCommitted);
                                self.poisoning(result)?;
                                answered_internally = true;
                            }

                            // Unreachable with today's `BuilderRequest`;
                            // kept for `#[non_exhaustive]` forward
                            // compatibility, matching
                            // `contentauth-c2pa-file-reader`'s own
                            // fallback for the same situation.
                            _ => {
                                let result = session.fulfill(
                                    request.id,
                                    BuilderHostReply::Failed(HostError::new("unsupported request")),
                                );
                                self.poisoning(result)?;
                                answered_internally = true;
                            }
                        }
                    }

                    self.phase = Some(Phase::Building {
                        session,
                        source,
                        plan,
                        output,
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

    fn outstanding_requests(&self) -> &[HostRequest<FileBuilderRequest>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: FileBuilderReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<FileBuilderReport, Error> {
        self.core.finish_check()?;
        match self.phase {
            Some(Phase::Done(report)) => Ok(report),
            _ => Err(ProtocolError::SessionNotComplete.into()),
        }
    }
}

/// Runs `handler.plan_embed` against `source`, entirely in memory, then
/// materializes the output with `placeholder` embedded.
fn reserve_placeholder<H: FormatHandler>(
    handler: &H,
    source: &[u8],
    stream: StreamId,
    placeholder: &[u8],
) -> Result<(EmbedPlan, Vec<u8>), contentauth_c2pa_format::FormatError> {
    let plan = run_format_op(source, handler.plan_embed(stream, placeholder.len() as u64))?;
    let materialized = plan.materialize(source, placeholder)?;
    Ok((plan, materialized))
}

/// Runs `handler.commit` against the cached `plan`, then materializes the
/// final output with `manifest` embedded and every patch applied.
fn commit_manifest<H: FormatHandler>(
    handler: &H,
    source: &[u8],
    plan: &Option<EmbedPlan>,
    manifest: &[u8],
) -> Result<Vec<u8>, Error> {
    let plan = plan.as_ref().ok_or(Error::Invariant(
        "CommitManifest asked for before ReservePlaceholder",
    ))?;

    let patches = handler.commit(plan, manifest)?;
    let mut materialized = plan.materialize(source, manifest)?;
    // JPEG (the only handler in this workspace so far) never returns a
    // patch — nothing in its framing depends on the store's content — so
    // this loop body is exercised only by a future handler that does,
    // such as one that recomputes a container-level checksum.
    for patch in &patches {
        patch.apply(&mut materialized)?;
    }
    Ok(materialized)
}

/// Drives any [`FormatOp`] to completion, answering every [`IoRequest`] it
/// issues by reading from `source` — already fully in memory, so no host
/// round trip is needed.
fn run_format_op<Output>(
    source: &[u8],
    mut op: impl FormatOp<Output>,
) -> Result<Output, contentauth_c2pa_format::FormatError> {
    loop {
        if op.advance()? == Step::Complete {
            return op.finish();
        }

        for request in op.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                IoRequest::Read { range, .. } => match slice(source, *range) {
                    Ok(bytes) => IoReply::Bytes(bytes.to_vec()),
                    Err(_) => IoReply::Failed(HostError::new("range lies past the end of source")),
                },
                IoRequest::Length { .. } => IoReply::Length(source.len() as u64),
                // Unreachable with today's `IoRequest`; see
                // `contentauth-c2pa-file-reader`'s identical fallback.
                _ => IoReply::Failed(HostError::new("unsupported request")),
            };
            op.fulfill(request.id, reply)?;
        }
    }
}

fn to_builder_host_reply(reply: FileBuilderReply) -> BuilderHostReply {
    match reply {
        FileBuilderReply::Signature(sig) => BuilderHostReply::Signature(sig),
        FileBuilderReply::Timestamp(ts) => BuilderHostReply::Timestamp(ts),
        FileBuilderReply::Failed(err) => BuilderHostReply::Failed(err),

        // `Bytes`/`Length` never reach `BuilderSession`: they answer this
        // session's own source-fetch requests, already consumed before
        // `Phase::Building` is ever entered. `SessionCore::fulfill`
        // validates a reply against `FileBuilderRequest::accepts` before
        // this function ever sees it, so a real host cannot produce this
        // pairing for a `Sign`/`Timestamp` request either — kept for
        // exhaustiveness.
        FileBuilderReply::Bytes(_) | FileBuilderReply::Length(_) => {
            BuilderHostReply::Failed(HostError::new("unexpected reply shape"))
        }
    }
}

fn slice(bytes: &[u8], range: ByteRange) -> Result<&[u8], Error> {
    let end = range
        .start
        .checked_add(range.len)
        .ok_or(Error::ReadLengthMismatch { range, actual: 0 })?;
    if end > bytes.len() as u64 {
        return Err(Error::ReadLengthMismatch {
            range,
            actual: bytes.len() as u64,
        });
    }
    Ok(&bytes[range.start as usize..end as usize])
}

/// Consumes the reply to a [`FileBuilderRequest::Length`], if the host has
/// provided one.
fn take_length(
    core: &mut SessionCore<FileBuilderRequest>,
    id: RequestId,
) -> Result<Option<u64>, Error> {
    match core.take_reply(id) {
        None => Ok(None),
        Some(FileBuilderReply::Length(len)) => Ok(Some(len)),
        Some(FileBuilderReply::Failed(source)) => Err(Error::HostFailure { id, source }),

        // `RequestTracker::fulfill` rejects a reply that does not match
        // `FileBuilderRequest::accepts` before it is ever stored, so this
        // arm is unreachable in practice; kept as defense in depth,
        // mirroring `contentauth-c2pa-format::request`'s identical
        // `take_length`.
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Length",
        }
        .into()),
    }
}

/// Consumes the reply to a [`FileBuilderRequest::Read`] for `range`, if
/// the host has provided one.
fn take_bytes(
    core: &mut SessionCore<FileBuilderRequest>,
    id: RequestId,
    range: ByteRange,
) -> Result<Option<Vec<u8>>, Error> {
    match core.take_reply(id) {
        None => Ok(None),
        Some(FileBuilderReply::Bytes(bytes)) => {
            let actual = bytes.len() as u64;
            if actual != range.len {
                return Err(Error::ReadLengthMismatch { range, actual });
            }
            Ok(Some(bytes))
        }
        Some(FileBuilderReply::Failed(source)) => Err(Error::HostFailure { id, source }),

        // Unreachable in practice; see `take_length`.
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Bytes",
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_format_jpeg::JpegFormat;

    use super::*;

    fn stream() -> StreamId {
        StreamId::new(0)
    }

    fn range() -> ByteRange {
        ByteRange { start: 0, len: 4 }
    }

    fn all_requests() -> Vec<FileBuilderRequest> {
        vec![
            FileBuilderRequest::Read {
                stream: stream(),
                range: range(),
            },
            FileBuilderRequest::Length { stream: stream() },
            FileBuilderRequest::Sign {
                alg: SigningAlg::Es256,
                data: vec![1, 2, 3],
            },
            FileBuilderRequest::Timestamp {
                digest: vec![4, 5, 6],
                hash_alg: HashAlgorithm::Sha256,
            },
        ]
    }

    fn all_replies() -> Vec<(FileBuilderReply, &'static str)> {
        vec![
            (FileBuilderReply::Bytes(vec![1]), "Bytes"),
            (FileBuilderReply::Length(4), "Length"),
            (FileBuilderReply::Signature(vec![0; 64]), "Signature"),
            (FileBuilderReply::Timestamp(vec![9; 8]), "Timestamp"),
            (FileBuilderReply::Failed(HostError::new("nope")), ""),
        ]
    }

    /// Every request accepts exactly the reply named by its
    /// `expected_reply` string, plus `Failed` — the same property every
    /// other request vocabulary in this workspace tests of itself.
    #[test]
    fn accepts_matches_expected_reply_exactly() {
        for request in &all_requests() {
            for (reply, answers) in all_replies() {
                let should_accept = matches!(reply, FileBuilderReply::Failed(_))
                    || *answers == *request.expected_reply();
                assert_eq!(
                    request.accepts(&reply),
                    should_accept,
                    "request {request:?} vs reply {reply:?}"
                );
            }
        }
    }

    #[test]
    fn replies_translate_to_builder_host_replies() {
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Signature(vec![1])),
            BuilderHostReply::Signature(bytes) if bytes == [1]
        ));
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Timestamp(vec![2])),
            BuilderHostReply::Timestamp(bytes) if bytes == [2]
        ));
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Failed(HostError::new("x"))),
            BuilderHostReply::Failed(_)
        ));

        // Neither `BuilderSession` nor `SessionCore::fulfill` (which
        // validates against `FileBuilderRequest::accepts` first) can
        // produce this pairing in practice — kept for exhaustiveness now
        // that `FileBuilderReply` has variants this function must still
        // account for.
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Bytes(vec![1])),
            BuilderHostReply::Failed(_)
        ));
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Length(1)),
            BuilderHostReply::Failed(_)
        ));
    }

    #[test]
    fn slice_rejects_a_range_past_the_end_or_that_overflows() {
        let bytes = [1u8, 2, 3, 4];
        assert_eq!(
            slice(&bytes, ByteRange { start: 1, len: 2 }).unwrap(),
            [2, 3]
        );
        assert!(slice(&bytes, ByteRange { start: 3, len: 2 }).is_err());
        assert!(slice(
            &bytes,
            ByteRange {
                start: u64::MAX,
                len: 1
            }
        )
        .is_err());
    }

    /// `advance` treats a `None` phase as a poisoned session rather than
    /// panicking. Every real code path reassigns `phase` before returning
    /// or looping, so this state is otherwise unreachable — exercised here
    /// by constructing it directly, the same way
    /// `contentauth-c2pa-file-reader`'s `FileReadSession` tests its own
    /// "kept as defense in depth" branch.
    #[test]
    fn advance_fails_defensively_if_phase_is_ever_none() {
        let mut session: FileBuilderSession<JpegFormat> = FileBuilderSession {
            core: SessionCore::default(),
            pending: HashMap::new(),
            handler: JpegFormat,
            stream: stream(),
            settings: None,
            phase: None,
        };

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
        assert!(session.core.is_failed());
    }

    /// `finish` does not trust `SessionCore`'s lifecycle alone: it also
    /// checks that `phase` actually holds a result. The two can only
    /// disagree if something bypasses `advance`'s own bookkeeping, as this
    /// test does directly.
    #[test]
    fn finish_fails_defensively_if_core_and_phase_disagree() {
        let mut core = SessionCore::default();
        core.mark_complete();

        let session: FileBuilderSession<JpegFormat> = FileBuilderSession {
            core,
            pending: HashMap::new(),
            handler: JpegFormat,
            stream: stream(),
            settings: None,
            phase: None,
        };

        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionNotComplete))
        ));
    }

    /// `poisoning` must mark the session failed on the way out, not just
    /// convert the error type — every fallible call in `advance` after
    /// `self.phase.take()` relies on this to keep `self.core` from
    /// disagreeing with a workflow `advance` has actually abandoned.
    #[test]
    fn poisoning_marks_the_session_failed_on_error() {
        let mut session = FileBuilderSession::new(JpegFormat, test_settings());

        let result: Result<(), Error> = session.poisoning(Err(Error::Invariant("boom")));
        assert!(matches!(result, Err(Error::Invariant("boom"))));
        assert!(session.core.is_failed());
    }

    fn test_settings() -> BuilderSettings {
        BuilderSettings::new(
            "image/jpeg",
            "xmp:iid:test",
            "urn:uuid:test",
            contentauth_c2pa_builder::GeneratorInfo::new("test", "0.0"),
            SigningAlg::Es256,
            vec![vec![0]],
        )
    }
}
