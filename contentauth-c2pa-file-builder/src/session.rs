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
//! Neither inner piece performs I/O itself, and neither does this session:
//! `EmbedPlan::materialize` (the in-memory reference for turning a plan
//! into bytes) is never called here. Instead this session checks a plan
//! against its own [`EmbedPlan::check`] before trusting it — a
//! `FormatHandler` answers only through [`EmbedPlan::new`], not
//! necessarily [`EmbedPlan::splice`]'s own validation — then walks its
//! [`Edit`]s, issuing a [`FileBuilderRequest::Read`] against
//! [`FileBuilderSession::SOURCE_STREAM`] for each [`Edit::Copy`] (in
//! bounded chunks for a single large range) and a
//! [`FileBuilderRequest::Write`] against
//! [`FileBuilderSession::OUTPUT_STREAM`] for every byte it produces —
//! never holding the source or the output it is assembling in memory.
//! `BuilderSession`'s own `AssetBytes` (needed to hash the output for the
//! hard binding) is forwarded the same way, as a plain read against the
//! output stream once it has been written; `AssetLength` is answered from
//! the plan's own known output length instead, so a host's stream being
//! longer than the new content can never leak stale bytes into the hash.
//! Only `Sign` and `Timestamp` — the two things nothing in this workspace
//! can do on a host's behalf — ever reach this session's own host as
//! themselves.

use std::collections::{HashMap, VecDeque};

use contentauth_c2pa_builder::{BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings};
use contentauth_c2pa_format::{Edit, EmbedPlan, FormatHandler, IoReply, IoRequest};
use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, HostError, SigningAlg, StreamId};
use contentauth_state_machine::{
    HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
};

use crate::error::Error;

/// The stream id this session uses on its own requests for the source
/// asset — read-only, and never written to. Exposed as
/// [`FileBuilderSession::SOURCE_STREAM`].
const SOURCE: StreamId = StreamId::new(0);

/// The stream id this session uses on its own requests for the asset it
/// is assembling. Exposed as [`FileBuilderSession::OUTPUT_STREAM`].
const OUTPUT: StreamId = StreamId::new(1);

/// The operations a [`FileBuilderSession`] may ask its host to perform.
///
/// `Read`/`Length`/`Write` each name which physical destination they
/// concern via `stream`: [`FileBuilderSession::SOURCE_STREAM`] (read-only —
/// the asset being signed) or [`FileBuilderSession::OUTPUT_STREAM`]
/// (write-then-read-back — the asset this session assembles). `Sign` and
/// `Timestamp` are forwarded verbatim from the [`BuilderSession`] this
/// composes.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum FileBuilderRequest {
    /// Read a range of bytes from `stream`. Reply with
    /// [`FileBuilderReply::Bytes`], carrying exactly `range.len` bytes.
    ///
    /// Issued against [`FileBuilderSession::SOURCE_STREAM`] while copying
    /// source bytes through to the output, and against
    /// [`FileBuilderSession::OUTPUT_STREAM`] while hashing the output for
    /// the hard binding — so an [`FileBuilderSession::OUTPUT_STREAM`] host
    /// must be able to read back what it has already been asked to write.
    Read {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Report the total length of `stream`, in bytes. Reply with
    /// [`FileBuilderReply::Length`].
    Length {
        /// The stream to measure.
        stream: StreamId,
    },

    /// Write `bytes` at `offset` of [`FileBuilderSession::OUTPUT_STREAM`].
    /// Reply with [`FileBuilderReply::Written`] once durable enough to be
    /// read back by a later [`Self::Read`].
    ///
    /// Every byte of the output this session assembles arrives through
    /// exactly one of these — nothing here is ever collected into a
    /// complete in-memory asset.
    Write {
        /// The stream to write to — always
        /// [`FileBuilderSession::OUTPUT_STREAM`] today, but named
        /// explicitly for the same forward-compatibility reason every
        /// other request here does.
        stream: StreamId,

        /// Offset within the output to write at.
        offset: u64,

        /// The bytes to write there.
        bytes: Vec<u8>,
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
            Self::Write { .. } => "Written",
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
                | (Self::Write { .. }, FileBuilderReply::Written)
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

    /// Answers [`FileBuilderRequest::Write`]: the bytes are durably
    /// written.
    Written,

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
///
/// The output asset itself is not here: every byte of it was already
/// delivered to the host through [`FileBuilderRequest::Write`] as it was
/// produced.
#[derive(Debug)]
#[non_exhaustive]
pub struct FileBuilderReport {
    /// The final, signed C2PA manifest store bytes alone — identical to
    /// the bytes written at [`Self::manifest_range`] of the output.
    pub manifest: Vec<u8>,

    /// The byte range of the container structure carrying the manifest,
    /// framing included — the hard binding's exclusion.
    pub manifest_range: ByteRange,
}

/// One pending unit of output: bytes to place at `output_offset`, either
/// already in hand or still to be read from the source.
enum WriteTask {
    /// Read `source_range` from [`FileBuilderSession::SOURCE_STREAM`],
    /// then write it at `output_offset`.
    CopyFromSource {
        output_offset: u64,
        source_range: ByteRange,
    },

    /// Write `bytes`, already known, at `output_offset`.
    WriteBytes { output_offset: u64, bytes: Vec<u8> },
}

/// A request this session has issued to its own host on a [`Sub::Writing`]
/// task's behalf, awaiting a reply.
enum Inflight {
    /// Reading `source_range` before the write it feeds can be issued.
    Read {
        id: RequestId,
        output_offset: u64,
        source_range: ByteRange,
    },

    /// Writing bytes already in hand.
    Write { id: RequestId },
}

/// What a [`Sub::Writing`] run answers, and how, once every task is done.
enum WriteThen {
    /// Answer the outstanding `ReservePlaceholder` with the plan's
    /// exclusion range.
    PlaceholderReserved { exclusion: ByteRange },

    /// Answer the outstanding `CommitManifest`.
    ManifestCommitted,
}

/// An internal sub-operation a [`FileBuilderSession`] is driving on behalf
/// of one outstanding [`BuilderRequest`], without surfacing it to its own
/// host as anything but the plain `Read`/`Length`/`Write` requests that
/// sub-operation actually needs.
enum Sub<H: FormatHandler> {
    /// Driving `handler.plan_embed`, forwarding its [`IoRequest`]s to this
    /// session's own host against [`FileBuilderSession::SOURCE_STREAM`].
    /// `pending` maps a forwarded request's outer id back to `op`'s own —
    /// the same translation-layer shape as [`FileBuilderSession::pending`],
    /// scoped to this one sub-operation instead.
    Planning {
        op: H::PlanEmbed,
        placeholder: Vec<u8>,
        request: RequestId,
        pending: HashMap<RequestId, RequestId>,
    },

    /// Confirming the plan `plan_embed` returned actually holds together
    /// before walking its edits: a handler answers only through
    /// [`EmbedPlan::new`], not [`EmbedPlan::splice`]'s own validation, so
    /// nothing has necessarily checked it yet. Awaits one
    /// [`FileBuilderRequest::Length`] against
    /// [`FileBuilderSession::SOURCE_STREAM`] to learn the source length
    /// [`EmbedPlan::check`] needs.
    Validating {
        plan: EmbedPlan,
        placeholder: Vec<u8>,
        request: RequestId,
        length_request: RequestId,
    },

    /// Writing a queued sequence of output ranges to
    /// [`FileBuilderSession::OUTPUT_STREAM`], one at a time.
    Writing {
        tasks: VecDeque<WriteTask>,
        inflight: Option<Inflight>,
        request: RequestId,
        then: WriteThen,
    },
}

/// Where a [`FileBuilderSession`] is in its workflow.
enum Phase<H: FormatHandler> {
    /// Driving the inner [`BuilderSession`]. `plan` is cached from the
    /// moment a placeholder is reserved, since `CommitManifest` needs it
    /// again; `sub` holds whichever internal sub-operation is in progress
    /// answering `ReservePlaceholder` or `CommitManifest`, or `None` while
    /// this session is simply forwarding everything else.
    Building {
        session: Box<BuilderSession>,
        plan: Option<EmbedPlan>,
        sub: Option<Sub<H>>,
    },

    /// The workflow has finished.
    Done(FileBuilderReport),
}

/// Builds and signs a C2PA manifest store, for any container format with a
/// [`FormatHandler`], without performing any I/O itself beyond what only
/// its host can do: reading the source asset, writing the output asset,
/// signing, and (optionally) timestamping.
///
/// A [`BuilderSession`] runs underneath, but never speaks to this
/// session's host directly: `ReservePlaceholder` and `CommitManifest` are
/// resolved by walking an [`EmbedPlan`]'s edits and issuing
/// `Read`/`Write` requests for each; `AssetLength` and `AssetBytes` are
/// forwarded as plain reads of the output stream once it has been
/// written. Only `Sign` and `Timestamp` — the two things nothing in this
/// workspace can do on a host's behalf — are forwarded, as
/// [`FileBuilderRequest::Sign`] and [`FileBuilderRequest::Timestamp`].
///
/// See the crate-level docs for why this exists alongside
/// [`crate::build_and_sign`]: a host with only synchronous, local
/// `Read + Seek` / `Read + Write + Seek` access (and a plain signing
/// function) can use that convenience function instead of driving this
/// session by hand.
pub struct FileBuilderSession<H: FormatHandler + Send> {
    core: SessionCore<FileBuilderRequest>,

    /// Maps a request this session issued to its own host (the key) back
    /// to the [`BuilderSession`] request it stands in for (the value).
    /// Only ever holds `AssetLength`/`AssetBytes`/`Sign`/`Timestamp`
    /// pairs: `ReservePlaceholder` and `CommitManifest` are answered
    /// through [`Sub`] instead, since resolving either takes more than
    /// one host round trip.
    pending: HashMap<RequestId, RequestId>,

    handler: H,
    phase: Option<Phase<H>>,
}

impl<H: FormatHandler + Send> FileBuilderSession<H> {
    /// The stream id this session uses on its own `Read`/`Length`/`Write`
    /// requests for the asset it is assembling. A host must be able to
    /// read back whatever it has already been asked to write here: the
    /// hard binding is hashed from these reads once the placeholder or
    /// final manifest has been written.
    pub const OUTPUT_STREAM: StreamId = OUTPUT;
    /// The stream id this session uses on its own `Read`/`Length`
    /// requests for the source asset — read-only, and never written to.
    pub const SOURCE_STREAM: StreamId = SOURCE;

    /// Starts a new session: builds and signs a manifest per `settings`
    /// for the asset `handler` locates on [`Self::SOURCE_STREAM`],
    /// writing the result to [`Self::OUTPUT_STREAM`].
    pub fn new(handler: H, settings: BuilderSettings) -> Self {
        Self {
            core: SessionCore::default(),
            pending: HashMap::new(),
            handler,
            phase: Some(Phase::Building {
                session: Box::new(BuilderSession::new(settings)),
                plan: None,
                sub: None,
            }),
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

                Some(Phase::Building {
                    session,
                    plan,
                    sub:
                        Some(Sub::Planning {
                            op,
                            placeholder,
                            request,
                            pending,
                        }),
                }) => {
                    let result =
                        step_planning::<H>(&mut self.core, op, placeholder, request, pending);
                    match self.poisoning(result)? {
                        PlanningStep::AwaitHost(sub) => {
                            self.phase = Some(Phase::Building {
                                session,
                                plan,
                                sub: Some(sub),
                            });
                            return Ok(Step::AwaitHost);
                        }

                        PlanningStep::Done {
                            plan,
                            placeholder,
                            request,
                        } => {
                            let length_request = self
                                .core
                                .issue(FileBuilderRequest::Length { stream: SOURCE });
                            let sub = Some(Sub::Validating {
                                plan,
                                placeholder,
                                request,
                                length_request,
                            });
                            self.phase = Some(Phase::Building {
                                session,
                                plan: None,
                                sub,
                            });
                            continue;
                        }
                    }
                }

                Some(Phase::Building {
                    session,
                    plan: _,
                    sub:
                        Some(Sub::Validating {
                            plan,
                            placeholder,
                            request,
                            length_request,
                        }),
                }) => {
                    let result = step_validating::<H>(
                        &mut self.core,
                        plan,
                        placeholder,
                        request,
                        length_request,
                    );
                    match self.poisoning(result)? {
                        ValidatingStep::AwaitHost(sub) => {
                            self.phase = Some(Phase::Building {
                                session,
                                plan: None,
                                sub: Some(sub),
                            });
                            return Ok(Step::AwaitHost);
                        }

                        ValidatingStep::Done {
                            plan: embed_plan,
                            tasks,
                            request,
                            exclusion,
                        } => {
                            let plan = Some(embed_plan);
                            let sub = Some(Sub::Writing {
                                tasks,
                                inflight: None,
                                request,
                                then: WriteThen::PlaceholderReserved { exclusion },
                            });
                            self.phase = Some(Phase::Building { session, plan, sub });
                            continue;
                        }
                    }
                }

                Some(Phase::Building {
                    mut session,
                    plan,
                    sub:
                        Some(Sub::Writing {
                            tasks,
                            inflight,
                            request,
                            then,
                        }),
                }) => {
                    let result = step_writing::<H>(&mut self.core, tasks, inflight, request, then);
                    match self.poisoning(result)? {
                        WritingStep::AwaitHost(sub) => {
                            self.phase = Some(Phase::Building {
                                session,
                                plan,
                                sub: Some(sub),
                            });
                            return Ok(Step::AwaitHost);
                        }

                        WritingStep::Done { request, then } => {
                            let reply = match then {
                                WriteThen::PlaceholderReserved { exclusion } => {
                                    BuilderHostReply::PlaceholderReserved(exclusion)
                                }
                                WriteThen::ManifestCommitted => BuilderHostReply::ManifestCommitted,
                            };
                            let result = session.fulfill(request, reply);
                            self.poisoning(result)?;
                            self.phase = Some(Phase::Building {
                                session,
                                plan,
                                sub: None,
                            });
                            continue;
                        }
                    }
                }

                Some(Phase::Building {
                    mut session,
                    plan,
                    sub: None,
                }) => {
                    for (id, reply) in self.ready_replies() {
                        let translated = to_builder_host_reply(reply);
                        let result = session.fulfill(id, translated);
                        self.poisoning(result)?;
                    }

                    let step = self.poisoning(session.advance())?;

                    if step == Step::Complete {
                        let report = self.poisoning(session.finish())?;
                        self.core.mark_complete();
                        self.phase = Some(Phase::Done(FileBuilderReport {
                            manifest: report.manifest,
                            manifest_range: report.manifest_range,
                        }));
                        return Ok(Step::Complete);
                    }

                    let mut sub = None;
                    let mut answered_internally = false;

                    for request in session.outstanding_requests().to_vec() {
                        if self.already_pending(request.id) {
                            continue;
                        }

                        match &request.kind {
                            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                                let op = self.handler.plan_embed(SOURCE, placeholder.len() as u64);
                                sub = Some(Sub::Planning {
                                    op,
                                    placeholder: placeholder.clone(),
                                    request: request.id,
                                    pending: HashMap::new(),
                                });
                                answered_internally = true;
                                // `ReservePlaceholder` is always issued alone.
                                break;
                            }

                            // Answered from the plan itself, not the host:
                            // an output length only this session already
                            // knows for certain is the length the hard
                            // binding must cover, whatever the host's
                            // stream happens to physically be — asking the
                            // host instead would let a stream reused (or
                            // simply longer than needed) from an earlier
                            // build leak trailing bytes into the hash.
                            BuilderRequest::AssetLength { .. } => {
                                let result =
                                    plan.as_ref()
                                        .and_then(EmbedPlan::output_len)
                                        .ok_or(Error::Invariant(
                                        "AssetLength asked for before ReservePlaceholder, or the \
                                         plan's output length overflows",
                                    ));
                                let len = self.poisoning(result)?;
                                let result =
                                    session.fulfill(request.id, BuilderHostReply::AssetLength(len));
                                self.poisoning(result)?;
                                answered_internally = true;
                            }

                            BuilderRequest::AssetBytes { range, .. } => {
                                let outer = self.core.issue(FileBuilderRequest::Read {
                                    stream: OUTPUT,
                                    range: *range,
                                });
                                self.pending.insert(outer, request.id);
                            }

                            BuilderRequest::Sign { alg, data } => {
                                let outer = self.core.issue(FileBuilderRequest::Sign {
                                    alg: *alg,
                                    data: data.clone(),
                                });
                                self.pending.insert(outer, request.id);
                            }

                            BuilderRequest::Timestamp { digest, hash_alg } => {
                                let outer = self.core.issue(FileBuilderRequest::Timestamp {
                                    digest: digest.clone(),
                                    hash_alg: *hash_alg,
                                });
                                self.pending.insert(outer, request.id);
                            }

                            BuilderRequest::CommitManifest { manifest, .. } => {
                                let result = (|| {
                                    let plan_ref = plan.as_ref().ok_or(Error::Invariant(
                                        "CommitManifest asked for before ReservePlaceholder",
                                    ))?;
                                    tasks_for_commit(&self.handler, plan_ref, manifest)
                                })();
                                let tasks = self.poisoning(result)?;
                                sub = Some(Sub::Writing {
                                    tasks,
                                    inflight: None,
                                    request: request.id,
                                    then: WriteThen::ManifestCommitted,
                                });
                                answered_internally = true;
                                // `CommitManifest` is always issued alone.
                                break;
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

                    self.phase = Some(Phase::Building { session, plan, sub });

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

/// The result of one [`step_planning`] call.
enum PlanningStep<H: FormatHandler> {
    /// Still in progress; this is the sub-operation's next state.
    AwaitHost(Sub<H>),

    /// `plan_embed` finished with a plan matching the placeholder's
    /// length. Not yet trusted for anything more than that: the next
    /// step is [`Sub::Validating`], not [`Sub::Writing`], since nothing
    /// has checked the plan's edits actually hold together.
    Done {
        plan: EmbedPlan,
        placeholder: Vec<u8>,
        request: RequestId,
    },
}

/// Drives one round of [`Sub::Planning`]: feeds it any replies its
/// forwarded [`IoRequest`]s have received, advances it, and forwards
/// whatever it asks for next.
fn step_planning<H: FormatHandler>(
    core: &mut SessionCore<FileBuilderRequest>,
    mut op: H::PlanEmbed,
    placeholder: Vec<u8>,
    request: RequestId,
    mut pending: HashMap<RequestId, RequestId>,
) -> Result<PlanningStep<H>, Error> {
    let outer_ids: Vec<RequestId> = pending.keys().copied().collect();
    for outer_id in outer_ids {
        if let Some(reply) = core.take_reply(outer_id) {
            if let Some(inner_id) = pending.remove(&outer_id) {
                op.fulfill(inner_id, to_io_reply(reply))?;
            }
        }
    }

    if op.advance()? == Step::Complete {
        let embed_plan = op.finish()?;

        if placeholder.len() as u64 != embed_plan.manifest_len {
            return Err(Error::Invariant(
                "plan_embed's plan does not match the placeholder's length",
            ));
        }

        return Ok(PlanningStep::Done {
            plan: embed_plan,
            placeholder,
            request,
        });
    }

    for io_request in op.outstanding_requests().to_vec() {
        if pending.values().any(|&id| id == io_request.id) {
            continue;
        }

        match &io_request.kind {
            IoRequest::Read { range, .. } => {
                let outer = core.issue(FileBuilderRequest::Read {
                    stream: SOURCE,
                    range: *range,
                });
                pending.insert(outer, io_request.id);
            }

            IoRequest::Length { .. } => {
                let outer = core.issue(FileBuilderRequest::Length { stream: SOURCE });
                pending.insert(outer, io_request.id);
            }

            // Unreachable with today's `IoRequest`; see
            // `contentauth-c2pa-file-reader`'s identical fallback.
            _ => {
                op.fulfill(
                    io_request.id,
                    IoReply::Failed(HostError::new("unsupported request")),
                )?;
            }
        }
    }

    Ok(PlanningStep::AwaitHost(Sub::Planning {
        op,
        placeholder,
        request,
        pending,
    }))
}

/// The result of one [`step_validating`] call.
enum ValidatingStep<H: FormatHandler> {
    /// Still in progress; this is the sub-operation's next state.
    AwaitHost(Sub<H>),

    /// The plan checks out. `tasks` lays out the planned placeholder
    /// embedding, ready for [`Sub::Writing`].
    Done {
        plan: EmbedPlan,
        tasks: VecDeque<WriteTask>,
        request: RequestId,
        exclusion: ByteRange,
    },
}

/// Drives one round of [`Sub::Validating`]: once the source length this
/// session asked for arrives, runs [`EmbedPlan::check`] against it — the
/// validation every consumer of a plan relies on, which nothing has
/// necessarily done yet for a plan built by hand rather than through
/// [`EmbedPlan::splice`] — before ever indexing into it.
fn step_validating<H: FormatHandler>(
    core: &mut SessionCore<FileBuilderRequest>,
    plan: EmbedPlan,
    placeholder: Vec<u8>,
    request: RequestId,
    length_request: RequestId,
) -> Result<ValidatingStep<H>, Error> {
    let Some(source_len) = take_length(core, length_request)? else {
        return Ok(ValidatingStep::AwaitHost(Sub::Validating {
            plan,
            placeholder,
            request,
            length_request,
        }));
    };

    plan.check(source_len)?;

    let exclusion = plan.exclusion;
    let tasks = tasks_for_edits(&plan.edits, &placeholder)?;
    Ok(ValidatingStep::Done {
        plan,
        tasks,
        request,
        exclusion,
    })
}

/// The result of one [`step_writing`] call.
enum WritingStep<H: FormatHandler> {
    /// Still in progress; this is the sub-operation's next state.
    AwaitHost(Sub<H>),

    /// Every task is written.
    Done { request: RequestId, then: WriteThen },
}

/// Drives one round of [`Sub::Writing`]: resolves whatever request is
/// currently inflight, then issues the next task's request.
fn step_writing<H: FormatHandler>(
    core: &mut SessionCore<FileBuilderRequest>,
    mut tasks: VecDeque<WriteTask>,
    inflight: Option<Inflight>,
    request: RequestId,
    then: WriteThen,
) -> Result<WritingStep<H>, Error> {
    match inflight {
        // A task's `Read` has resolved: issue the `Write` it feeds and
        // await that instead — the next queued task, if any, waits its
        // turn.
        Some(Inflight::Read {
            id,
            output_offset,
            source_range,
        }) => {
            return match take_bytes(core, id, source_range)? {
                None => Ok(WritingStep::AwaitHost(Sub::Writing {
                    tasks,
                    inflight: Some(Inflight::Read {
                        id,
                        output_offset,
                        source_range,
                    }),
                    request,
                    then,
                })),
                Some(bytes) => {
                    let write_id = core.issue(FileBuilderRequest::Write {
                        stream: OUTPUT,
                        offset: output_offset,
                        bytes,
                    });
                    Ok(WritingStep::AwaitHost(Sub::Writing {
                        tasks,
                        inflight: Some(Inflight::Write { id: write_id }),
                        request,
                        then,
                    }))
                }
            };
        }

        // A task's `Write` is still outstanding: await it before moving
        // on to the next task.
        Some(Inflight::Write { id }) if take_write_ack(core, id)?.is_none() => {
            return Ok(WritingStep::AwaitHost(Sub::Writing {
                tasks,
                inflight: Some(Inflight::Write { id }),
                request,
                then,
            }));
        }
        Some(Inflight::Write { .. }) => {}

        // Nothing was in flight: ready to issue the first/next task.
        None => {}
    }

    match tasks.pop_front() {
        None => Ok(WritingStep::Done { request, then }),

        Some(WriteTask::CopyFromSource {
            output_offset,
            source_range,
        }) => {
            let id = core.issue(FileBuilderRequest::Read {
                stream: SOURCE,
                range: source_range,
            });
            Ok(WritingStep::AwaitHost(Sub::Writing {
                tasks,
                inflight: Some(Inflight::Read {
                    id,
                    output_offset,
                    source_range,
                }),
                request,
                then,
            }))
        }

        Some(WriteTask::WriteBytes {
            output_offset,
            bytes,
        }) => {
            let id = core.issue(FileBuilderRequest::Write {
                stream: OUTPUT,
                offset: output_offset,
                bytes,
            });
            Ok(WritingStep::AwaitHost(Sub::Writing {
                tasks,
                inflight: Some(Inflight::Write { id }),
                request,
                then,
            }))
        }
    }
}

/// The most this session ever asks a host to read from the source (or
/// write to the output) in one [`WriteTask`] — bounding how much of a
/// single, arbitrarily large [`Edit::Copy`] it holds in memory at once,
/// the same way every other range this session reads is already bounded
/// by the plan's own framing.
const COPY_CHUNK_LEN: u64 = 1 << 20;

/// Lays out `edits` — a freshly planned embedding — as a sequence of
/// writes to the output, filling every [`Edit::Placeholder`] slot from
/// `placeholder`. Edits producing no bytes are skipped.
fn tasks_for_edits(edits: &[Edit], placeholder: &[u8]) -> Result<VecDeque<WriteTask>, Error> {
    let mut tasks = VecDeque::new();
    let mut offset = 0u64;

    for edit in edits {
        let len = edit.len();

        if len > 0 {
            match edit {
                Edit::Copy(range) => push_copy_chunks(&mut tasks, offset, *range),

                Edit::Emit(bytes) => tasks.push_back(WriteTask::WriteBytes {
                    output_offset: offset,
                    bytes: bytes.clone(),
                }),

                Edit::Placeholder(range) => {
                    let bytes = slice(placeholder, *range).ok_or(Error::Invariant(
                        "a placeholder slot lies outside the placeholder bytes",
                    ))?;
                    tasks.push_back(WriteTask::WriteBytes {
                        output_offset: offset,
                        bytes: bytes.to_vec(),
                    });
                }

                // Unreachable with today's `Edit`; kept for
                // `#[non_exhaustive]` forward compatibility.
                _ => return Err(Error::Invariant("unsupported edit kind")),
            }
        }

        offset = offset
            .checked_add(len)
            .ok_or(Error::Invariant("output offset overflows"))?;
    }

    Ok(tasks)
}

/// Appends one [`WriteTask::CopyFromSource`] per [`COPY_CHUNK_LEN`]-sized
/// piece of `source_range`, landing at consecutive offsets starting at
/// `output_offset` — so a single large [`Edit::Copy`] still moves through
/// this session in bounded pieces rather than one host round trip sized
/// to the whole range.
fn push_copy_chunks(tasks: &mut VecDeque<WriteTask>, output_offset: u64, source_range: ByteRange) {
    let mut done = 0u64;

    while done < source_range.len {
        let chunk_len = (source_range.len - done).min(COPY_CHUNK_LEN);
        tasks.push_back(WriteTask::CopyFromSource {
            output_offset: output_offset + done,
            source_range: ByteRange {
                start: source_range.start + done,
                len: chunk_len,
            },
        });
        done += chunk_len;
    }
}

/// Slices `bytes` at `range`, rejecting a range that overflows or reaches
/// past the end rather than panicking — the only defense a plan or
/// manifest this session did not itself produce gets before it is used to
/// index into a buffer.
fn slice(bytes: &[u8], range: ByteRange) -> Option<&[u8]> {
    let end = range.start.checked_add(range.len)?;
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(end).ok()?;
    bytes.get(start..end)
}

/// Lays out the writes a manifest commit needs: `handler.commit`'s
/// patches, plus a rewrite of every [`Edit::Placeholder`] slot in `plan`
/// with the matching bytes of the final `manifest` — `Copy`/`Emit` edits
/// need no rewrite, since a commit changes only the manifest store's
/// content, never its framing or the source bytes around it.
fn tasks_for_commit<H: FormatHandler>(
    handler: &H,
    plan: &EmbedPlan,
    manifest: &[u8],
) -> Result<VecDeque<WriteTask>, Error> {
    if manifest.len() as u64 != plan.manifest_len {
        return Err(Error::Invariant(
            "final manifest store length differs from the plan's",
        ));
    }

    let patches = handler.commit(plan, manifest)?;

    let mut tasks = VecDeque::new();
    let mut offset = 0u64;

    for edit in &plan.edits {
        let len = edit.len();

        if len > 0 {
            if let Edit::Placeholder(range) = edit {
                let bytes = slice(manifest, *range).ok_or(Error::Invariant(
                    "a placeholder slot lies outside the final manifest bytes",
                ))?;
                tasks.push_back(WriteTask::WriteBytes {
                    output_offset: offset,
                    bytes: bytes.to_vec(),
                });
            }
        }

        offset = offset
            .checked_add(len)
            .ok_or(Error::Invariant("output offset overflows"))?;
    }

    for patch in patches {
        // `FormatHandler::commit`'s own contract: every patch must lie
        // within the exclusion range, since bytes outside it are already
        // hashed into the hard binding. A handler that violates this is
        // buggy, not this session's problem to route around.
        if !patch.lies_within(plan.exclusion) {
            return Err(Error::Invariant(
                "commit() returned a patch outside the plan's exclusion range",
            ));
        }

        tasks.push_back(WriteTask::WriteBytes {
            output_offset: patch.offset,
            bytes: patch.bytes,
        });
    }

    Ok(tasks)
}

fn to_io_reply(reply: FileBuilderReply) -> IoReply {
    match reply {
        FileBuilderReply::Bytes(bytes) => IoReply::Bytes(bytes),
        FileBuilderReply::Length(len) => IoReply::Length(len),
        FileBuilderReply::Failed(err) => IoReply::Failed(err),

        // `SessionCore::fulfill` validates a reply against
        // `FileBuilderRequest::accepts` before this function ever sees
        // it, and only `Read`/`Length` requests are ever forwarded to
        // `plan_embed`'s operation — kept for exhaustiveness.
        FileBuilderReply::Written
        | FileBuilderReply::Signature(_)
        | FileBuilderReply::Timestamp(_) => {
            IoReply::Failed(HostError::new("unexpected reply shape"))
        }
    }
}

fn to_builder_host_reply(reply: FileBuilderReply) -> BuilderHostReply {
    match reply {
        // Answers a forwarded `AssetBytes` — the output stream, read back
        // after being written.
        FileBuilderReply::Bytes(bytes) => BuilderHostReply::AssetBytes(bytes),

        FileBuilderReply::Signature(sig) => BuilderHostReply::Signature(sig),
        FileBuilderReply::Timestamp(ts) => BuilderHostReply::Timestamp(ts),
        FileBuilderReply::Failed(err) => BuilderHostReply::Failed(err),

        // Neither ever answers a forwarded `BuilderRequest`: `AssetLength`
        // is answered directly from the plan rather than forwarded (see
        // `advance`), and `ReservePlaceholder`/`CommitManifest` are
        // answered once their own `Sub::Writing` finishes, not through
        // this path — kept for exhaustiveness.
        FileBuilderReply::Length(_) | FileBuilderReply::Written => {
            BuilderHostReply::Failed(HostError::new("unexpected reply shape"))
        }
    }
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
        // arm is unreachable in practice; kept as defense in depth.
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

        // `RequestTracker::fulfill` rejects a reply that does not match
        // `FileBuilderRequest::accepts` before it is ever stored, so this
        // arm is unreachable in practice; kept as defense in depth.
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Bytes",
        }
        .into()),
    }
}

/// Consumes the reply to a [`FileBuilderRequest::Write`], if the host has
/// provided one.
fn take_write_ack(
    core: &mut SessionCore<FileBuilderRequest>,
    id: RequestId,
) -> Result<Option<()>, Error> {
    match core.take_reply(id) {
        None => Ok(None),
        Some(FileBuilderReply::Written) => Ok(Some(())),
        Some(FileBuilderReply::Failed(source)) => Err(Error::HostFailure { id, source }),

        // `RequestTracker::fulfill` rejects a reply that does not match
        // `FileBuilderRequest::accepts` before it is ever stored, so this
        // arm is unreachable in practice; kept as defense in depth.
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Written",
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
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
            FileBuilderRequest::Write {
                stream: stream(),
                offset: 0,
                bytes: vec![1, 2, 3],
            },
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
            (FileBuilderReply::Written, "Written"),
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
            to_builder_host_reply(FileBuilderReply::Bytes(vec![1])),
            BuilderHostReply::AssetBytes(bytes) if bytes == [1]
        ));
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

        // Neither `Length` (`AssetLength` is answered from the plan, not
        // forwarded) nor `Written` ever reaches this function in
        // practice — kept for exhaustiveness.
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Length(4)),
            BuilderHostReply::Failed(_)
        ));
        assert!(matches!(
            to_builder_host_reply(FileBuilderReply::Written),
            BuilderHostReply::Failed(_)
        ));
    }

    #[test]
    fn replies_translate_to_io_replies() {
        assert!(matches!(
            to_io_reply(FileBuilderReply::Bytes(vec![1])),
            IoReply::Bytes(bytes) if bytes == [1]
        ));
        assert!(matches!(
            to_io_reply(FileBuilderReply::Length(4)),
            IoReply::Length(4)
        ));
        assert!(matches!(
            to_io_reply(FileBuilderReply::Failed(HostError::new("x"))),
            IoReply::Failed(_)
        ));

        // Unreachable in practice; see `replies_translate_to_builder_host_replies`.
        assert!(matches!(
            to_io_reply(FileBuilderReply::Written),
            IoReply::Failed(_)
        ));
        assert!(matches!(
            to_io_reply(FileBuilderReply::Signature(vec![1])),
            IoReply::Failed(_)
        ));
        assert!(matches!(
            to_io_reply(FileBuilderReply::Timestamp(vec![1])),
            IoReply::Failed(_)
        ));
    }

    #[test]
    fn tasks_for_edits_skips_empty_edits_and_fills_placeholder_slots() {
        let edits = vec![
            Edit::Copy(ByteRange { start: 0, len: 10 }),
            Edit::Emit(vec![0xaa; 4]),
            Edit::Placeholder(ByteRange { start: 0, len: 0 }),
            Edit::Placeholder(ByteRange { start: 0, len: 3 }),
        ];
        let placeholder = vec![1, 2, 3];

        let tasks = tasks_for_edits(&edits, &placeholder).unwrap();
        assert_eq!(tasks.len(), 3);
        assert!(matches!(
            tasks[0],
            WriteTask::CopyFromSource {
                output_offset: 0,
                source_range: ByteRange { start: 0, len: 10 }
            }
        ));
        assert!(matches!(
            &tasks[1],
            WriteTask::WriteBytes { output_offset: 10, bytes } if *bytes == [0xaa; 4]
        ));
        assert!(matches!(
            &tasks[2],
            WriteTask::WriteBytes { output_offset: 14, bytes } if *bytes == [1, 2, 3]
        ));
    }

    #[test]
    fn tasks_for_edits_rejects_a_placeholder_slot_past_the_placeholder_bytes() {
        let edits = vec![Edit::Placeholder(ByteRange { start: 0, len: 5 })];
        assert!(matches!(
            tasks_for_edits(&edits, &[1, 2]),
            Err(Error::Invariant(_))
        ));
    }

    /// A single `Edit::Copy` larger than [`COPY_CHUNK_LEN`] must still
    /// move through this session in bounded pieces — never one `Read`
    /// sized to the whole range, which would undo the point of streaming
    /// for exactly the assets large enough to matter.
    #[test]
    fn a_large_copy_edit_is_split_into_bounded_chunks() {
        let edits = vec![Edit::Copy(ByteRange {
            start: 100,
            len: COPY_CHUNK_LEN * 2 + 1,
        })];

        let tasks = tasks_for_edits(&edits, &[]).unwrap();
        assert_eq!(tasks.len(), 3);

        let mut expected_output_offset = 0;
        let mut expected_source_start = 100;
        for (task, expected_len) in tasks.iter().zip([COPY_CHUNK_LEN, COPY_CHUNK_LEN, 1]) {
            assert!(matches!(
                task,
                WriteTask::CopyFromSource { output_offset, source_range }
                    if *output_offset == expected_output_offset
                        && *source_range == ByteRange { start: expected_source_start, len: expected_len }
            ));
            expected_output_offset += expected_len;
            expected_source_start += expected_len;
        }
    }

    #[test]
    fn slice_rejects_a_range_past_the_end_or_that_overflows() {
        let bytes = [1u8, 2, 3, 4];
        assert_eq!(
            slice(&bytes, ByteRange { start: 1, len: 2 }),
            Some(&bytes[1..3])
        );
        assert_eq!(slice(&bytes, ByteRange { start: 3, len: 2 }), None);
        assert_eq!(
            slice(
                &bytes,
                ByteRange {
                    start: u64::MAX,
                    len: 1
                }
            ),
            None
        );
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

    #[test]
    fn tasks_for_commit_rejects_a_manifest_of_the_wrong_length() {
        let plan = EmbedPlan::new(
            vec![Edit::Placeholder(ByteRange { start: 0, len: 5 })],
            5,
            ByteRange { start: 0, len: 5 },
            None,
        );
        assert!(matches!(
            tasks_for_commit(&JpegFormat, &plan, &[1, 2, 3]),
            Err(Error::Invariant(_))
        ));
    }

    /// A commit rewrites only the placeholder slot, never the `Copy`/`Emit`
    /// edits around it — those bytes are identical between the
    /// placeholder and final passes by construction.
    #[test]
    fn tasks_for_commit_rewrites_only_the_placeholder_slot() {
        // `JpegFormat::commit` verifies the store begins with the JUMBF
        // superbox header its framing already assumed — an 8-byte BMFF
        // box header, `LBox` (the store's length) then `TBox` (`"jumb"`)
        // — so the manifest here needs to actually look like one.
        let manifest_len = 8u64;
        let mut manifest = (manifest_len as u32).to_be_bytes().to_vec();
        manifest.extend_from_slice(b"jumb");

        let plan = EmbedPlan::new(
            vec![
                Edit::Copy(ByteRange { start: 0, len: 10 }),
                Edit::Emit(vec![0xaa; 2]),
                Edit::Placeholder(ByteRange {
                    start: 0,
                    len: manifest_len,
                }),
            ],
            manifest_len,
            ByteRange { start: 10, len: 10 },
            None,
        );

        // `JpegFormat::commit` never returns a patch — see its own docs —
        // so this also proves an empty patch list leaves the placeholder
        // rewrite as the only task.
        let tasks = tasks_for_commit(&JpegFormat, &plan, &manifest).unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(matches!(
            &tasks[0],
            WriteTask::WriteBytes { output_offset: 12, bytes } if *bytes == manifest
        ));
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

    /// A source read a `CopyFromSource` task needs must not be reissued
    /// while it is still outstanding — the same "no duplicate requests"
    /// property this crate's session-level tests prove end to end, here
    /// isolated to `step_writing` itself.
    #[test]
    fn step_writing_does_not_reissue_a_still_pending_source_read() {
        let mut core = SessionCore::default();
        let outer_request = core.issue(FileBuilderRequest::Sign {
            alg: SigningAlg::Es256,
            data: vec![],
        });
        let tasks: VecDeque<WriteTask> = VecDeque::from([WriteTask::CopyFromSource {
            output_offset: 0,
            source_range: ByteRange { start: 0, len: 4 },
        }]);

        let step = step_writing::<JpegFormat>(
            &mut core,
            tasks,
            None,
            outer_request,
            WriteThen::ManifestCommitted,
        )
        .unwrap();
        let sub = match step {
            WritingStep::AwaitHost(sub) => sub,
            WritingStep::Done { .. } => panic!("expected to await the source read"),
        };
        let Sub::Writing {
            tasks, inflight, ..
        } = sub
        else {
            panic!("expected Sub::Writing");
        };
        let first_id = match &inflight {
            Some(Inflight::Read { id, .. }) => *id,
            _ => panic!("expected a pending source read"),
        };

        let step = step_writing::<JpegFormat>(
            &mut core,
            tasks,
            inflight,
            outer_request,
            WriteThen::ManifestCommitted,
        )
        .unwrap();
        match step {
            WritingStep::AwaitHost(Sub::Writing {
                inflight: Some(Inflight::Read { id, .. }),
                ..
            }) => assert_eq!(id, first_id),
            _ => panic!("expected the same read still pending, unchanged"),
        }
    }

    /// The mirror of the above for a `Write` a task has already issued.
    #[test]
    fn step_writing_does_not_reissue_a_still_pending_write() {
        let mut core = SessionCore::default();
        let outer_request = core.issue(FileBuilderRequest::Sign {
            alg: SigningAlg::Es256,
            data: vec![],
        });
        let tasks: VecDeque<WriteTask> = VecDeque::from([WriteTask::WriteBytes {
            output_offset: 0,
            bytes: vec![1, 2, 3],
        }]);

        let step = step_writing::<JpegFormat>(
            &mut core,
            tasks,
            None,
            outer_request,
            WriteThen::ManifestCommitted,
        )
        .unwrap();
        let sub = match step {
            WritingStep::AwaitHost(sub) => sub,
            WritingStep::Done { .. } => panic!("expected to await the write"),
        };
        let Sub::Writing {
            tasks, inflight, ..
        } = sub
        else {
            panic!("expected Sub::Writing");
        };
        let first_id = match &inflight {
            Some(Inflight::Write { id }) => *id,
            _ => panic!("expected a pending write"),
        };

        let step = step_writing::<JpegFormat>(
            &mut core,
            tasks,
            inflight,
            outer_request,
            WriteThen::ManifestCommitted,
        )
        .unwrap();
        match step {
            WritingStep::AwaitHost(Sub::Writing {
                inflight: Some(Inflight::Write { id }),
                ..
            }) => assert_eq!(id, first_id),
            _ => panic!("expected the same write still pending, unchanged"),
        }
    }

    /// A plan `plan_embed` returned unchecked — one with a `Copy` edit
    /// reaching past the end of the source it was supposedly built from —
    /// must be rejected before this session ever indexes into anything
    /// using its offsets, not silently trusted.
    #[test]
    fn step_validating_rejects_a_plan_that_does_not_check_out() {
        let mut core = SessionCore::default();
        let request = core.issue(FileBuilderRequest::Sign {
            alg: SigningAlg::Es256,
            data: vec![],
        });
        let length_request = core.issue(FileBuilderRequest::Length { stream: stream() });
        core.fulfill(length_request, FileBuilderReply::Length(5))
            .unwrap();

        let plan = EmbedPlan::new(
            vec![Edit::Copy(ByteRange { start: 0, len: 10 })],
            0,
            ByteRange { start: 0, len: 0 },
            None,
        );

        let result =
            step_validating::<JpegFormat>(&mut core, plan, vec![], request, length_request);
        assert!(matches!(result, Err(Error::Format(_))));
    }

    #[test]
    fn step_validating_awaits_a_still_pending_source_length() {
        let mut core = SessionCore::default();
        let request = core.issue(FileBuilderRequest::Sign {
            alg: SigningAlg::Es256,
            data: vec![],
        });
        let length_request = core.issue(FileBuilderRequest::Length { stream: stream() });

        let plan = EmbedPlan::new(vec![], 0, ByteRange { start: 0, len: 0 }, None);

        let step = step_validating::<JpegFormat>(&mut core, plan, vec![], request, length_request)
            .unwrap();
        assert!(matches!(
            step,
            ValidatingStep::AwaitHost(Sub::Validating { .. })
        ));
    }

    /// Mirrors `contentauth_c2pa_format::request`'s own tests of its
    /// identical `take_bytes`: outstanding, a wrong-length reply, and a
    /// host failure.
    #[test]
    fn take_bytes_reports_outstanding_wrong_length_and_failure() {
        let mut core = SessionCore::default();
        let range = ByteRange { start: 4, len: 3 };

        let id = core.issue(FileBuilderRequest::Read {
            stream: stream(),
            range,
        });
        assert!(take_bytes(&mut core, id, range).unwrap().is_none());

        core.fulfill(id, FileBuilderReply::Bytes(vec![0; 2]))
            .unwrap();
        assert!(matches!(
            take_bytes(&mut core, id, range),
            Err(Error::ReadLengthMismatch { actual: 2, .. })
        ));

        let id = core.issue(FileBuilderRequest::Read {
            stream: stream(),
            range,
        });
        core.fulfill(id, FileBuilderReply::Failed(HostError::new("unreadable")))
            .unwrap();
        assert!(matches!(
            take_bytes(&mut core, id, range),
            Err(Error::HostFailure { .. })
        ));

        let id = core.issue(FileBuilderRequest::Read {
            stream: stream(),
            range,
        });
        core.fulfill(id, FileBuilderReply::Bytes(vec![7; 3]))
            .unwrap();
        assert_eq!(take_bytes(&mut core, id, range).unwrap(), Some(vec![7; 3]));
    }

    /// Mirrors `take_bytes_reports_outstanding_wrong_length_and_failure`
    /// for `take_write_ack`.
    #[test]
    fn take_write_ack_reports_outstanding_and_failure() {
        let mut core = SessionCore::default();

        let id = core.issue(FileBuilderRequest::Write {
            stream: stream(),
            offset: 0,
            bytes: vec![1],
        });
        assert!(take_write_ack(&mut core, id).unwrap().is_none());
        core.fulfill(id, FileBuilderReply::Written).unwrap();
        assert_eq!(take_write_ack(&mut core, id).unwrap(), Some(()));

        let id = core.issue(FileBuilderRequest::Write {
            stream: stream(),
            offset: 0,
            bytes: vec![1],
        });
        core.fulfill(id, FileBuilderReply::Failed(HostError::new("no disk")))
            .unwrap();
        assert!(matches!(
            take_write_ack(&mut core, id),
            Err(Error::HostFailure { .. })
        ));
    }
}
