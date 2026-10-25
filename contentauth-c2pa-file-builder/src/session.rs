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

use std::{
    collections::VecDeque,
    fmt,
    future::{poll_fn, Future},
    marker::PhantomData,
    pin::pin,
};

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, SignPurpose,
};
use contentauth_c2pa_format::{Edit, EmbedPlan, FormatHandler, FormatOp, IoReply, IoRequest};
use contentauth_c2pa_primitives::{
    ByteRange, Bytes, HashAlgorithm, HostError, SigningAlg, StreamId,
};
use contentauth_state_machine::{
    Host, HostRequest, Nested, ProtocolError, Request, RequestId, Session, Step, Workflow,
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
        bytes: Bytes,
    },

    /// Sign `data` — a COSE `Sig_structure` — with `alg`. Reply with
    /// [`FileBuilderReply::Signature`].
    ///
    /// Mirrors [`BuilderRequest::Sign`] exactly: the host is responsible
    /// for however it holds or reaches the signing key.
    Sign {
        /// What is being signed, and so whose key is wanted — see
        /// [`BuilderRequest::Sign`].
        purpose: SignPurpose,

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
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum FileBuilderReply {
    /// Answers [`FileBuilderRequest::Read`]: the requested bytes.
    Bytes(Bytes),

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
    /// the bytes written into the plan's placeholder slots, inside
    /// [`Self::exclusions`], of the output.
    pub manifest: Bytes,

    /// The hard binding's exclusions: the container structure carrying the
    /// manifest, framing included, and anything else the format's
    /// specification excludes.
    pub exclusions: Vec<ByteRange>,
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
    WriteBytes { output_offset: u64, bytes: Bytes },
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
/// The whole composition is one `async fn` run by a [`Workflow`]: the
/// [`BuilderSession`] and the handler's `plan_embed` operation are each
/// driven through a [`Nested`] adapter, so answering one of the builder's
/// requests with a sub-operation of several host round trips is an
/// ordinary `.await` rather than a phase of a hand-written state machine.
///
/// See the crate-level docs for why this exists alongside
/// [`crate::build_and_sign`]: a host with only synchronous, local
/// `Read + Seek` / `Read + Write + Seek` access (and a plain signing
/// function) can use that convenience function instead of driving this
/// session by hand.
pub struct FileBuilderSession<H: FormatHandler> {
    workflow: Workflow<FileBuilderRequest, FileBuilderReport, Error>,

    /// The handler is moved into the workflow; this only keeps the type
    /// parameter callers already name.
    handler: PhantomData<fn() -> H>,
}

impl<H: FormatHandler> FileBuilderSession<H> {
    /// The stream id this session uses on its own `Read`/`Length`/`Write`
    /// requests for the asset it is assembling. A host must be able to
    /// read back whatever it has already been asked to write here: the
    /// hard binding is hashed from these reads once the placeholder or
    /// final manifest has been written.
    pub const OUTPUT_STREAM: StreamId = OUTPUT;
    /// The stream id this session uses on its own `Read`/`Length`
    /// requests for the source asset — read-only, and never written to.
    pub const SOURCE_STREAM: StreamId = SOURCE;
}

impl<H> FileBuilderSession<H>
where
    H: FormatHandler + Send + 'static,
    H::PlanEmbed: Send,
{
    /// Starts a new session: builds and signs a manifest per `settings`
    /// for the asset `handler` locates on [`Self::SOURCE_STREAM`],
    /// writing the result to [`Self::OUTPUT_STREAM`].
    pub fn new(handler: H, settings: BuilderSettings) -> Self {
        Self {
            workflow: Workflow::new(|host| {
                host.set_phase("Building > Start");
                build_file(host, handler, settings)
            }),
            handler: PhantomData,
        }
    }
}

impl<H: FormatHandler> fmt::Debug for FileBuilderSession<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileBuilderSession")
            .field("workflow", &self.workflow)
            .finish()
    }
}

impl<H: FormatHandler> Session for FileBuilderSession<H> {
    type Error = Error;
    type Output = FileBuilderReport;
    type Request = FileBuilderRequest;

    fn advance(&mut self) -> Result<Step, Error> {
        self.workflow.advance()
    }

    fn outstanding_requests(&self) -> &[HostRequest<FileBuilderRequest>] {
        self.workflow.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: FileBuilderReply) -> Result<(), Error> {
        self.workflow.fulfill(id, reply)
    }

    fn phase(&self) -> String {
        self.workflow.phase()
    }

    fn finish(self) -> Result<FileBuilderReport, Error> {
        self.workflow.finish()
    }
}

/// The whole composition: runs a [`BuilderSession`], answering each of its
/// requests either here or by forwarding it to this session's own host.
///
/// `handler` is only ever borrowed between `.await`s — `plan_embed` and
/// `commit` are both synchronous — so it need not be `Sync` for the
/// workflow to be `Send`.
async fn build_file<H: FormatHandler>(
    host: Host<FileBuilderRequest>,
    handler: H,
    settings: BuilderSettings,
) -> Result<FileBuilderReport, Error> {
    let mut builder = Nested::new(BuilderSession::new(settings));

    // Set once the placeholder is reserved; `AssetLength` and
    // `CommitManifest` both need it again.
    let mut plan: Option<EmbedPlan> = None;

    while let Some(request) = next(&host, &mut builder, "Building").await? {
        let id = request.id;

        match request.kind {
            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                let op = handler.plan_embed(SOURCE, placeholder.len() as u64);
                let reserved = reserve_placeholder(&host, op, &placeholder).await?;
                let exclusions = reserved.exclusions.clone();
                plan = Some(reserved);
                builder.fulfill(id, BuilderHostReply::PlaceholderReserved(exclusions))?;
            }

            // Answered from the plan itself, not the host: an output length
            // only this session already knows for certain is the length the
            // hard binding must cover, whatever the host's stream happens to
            // physically be — asking the host instead would let a stream
            // reused (or simply longer than needed) from an earlier build
            // leak trailing bytes into the hash.
            BuilderRequest::AssetLength { .. } => {
                let len = plan
                    .as_ref()
                    .and_then(EmbedPlan::output_len)
                    .ok_or(Error::Invariant(
                        "AssetLength asked for before ReservePlaceholder, or the plan's output \
                         length overflows",
                    ))?;
                builder.fulfill(id, BuilderHostReply::AssetLength(len))?;
            }

            BuilderRequest::AssetBytes { range, .. } => builder.forward(
                id,
                host.request(FileBuilderRequest::Read {
                    stream: OUTPUT,
                    range,
                }),
                to_builder_host_reply,
            ),

            BuilderRequest::Sign { purpose, alg, data } => builder.forward(
                id,
                host.request(FileBuilderRequest::Sign { purpose, alg, data }),
                to_builder_host_reply,
            ),

            BuilderRequest::Timestamp { digest, hash_alg } => builder.forward(
                id,
                host.request(FileBuilderRequest::Timestamp { digest, hash_alg }),
                to_builder_host_reply,
            ),

            BuilderRequest::CommitManifest { manifest, .. } => {
                host.set_phase("Building > Committing");
                let plan = plan.as_ref().ok_or(Error::Invariant(
                    "CommitManifest asked for before ReservePlaceholder",
                ))?;
                let tasks = tasks_for_commit(&handler, plan, &manifest)?;
                write_all(&host, tasks).await?;
                builder.fulfill(id, BuilderHostReply::ManifestCommitted)?;
            }

            // Unreachable with today's `BuilderRequest`; kept for
            // `#[non_exhaustive]` forward compatibility, matching
            // `contentauth-c2pa-file-reader`'s own fallback for the same
            // situation.
            _ => builder.fulfill(
                id,
                BuilderHostReply::Failed(HostError::new("unsupported request")),
            )?,
        }
    }

    let report = builder.finish()?;
    Ok(FileBuilderReport {
        manifest: report.manifest,
        exclusions: report.exclusions,
    })
}

/// Refreshes the enclosing phase after every inner poll, including a
/// pending or failed one. `Nested::next` keeps its progress in the adapter,
/// so dropping this temporary future between polls does not lose requests.
async fn next<S>(
    host: &Host<FileBuilderRequest>,
    session: &mut Nested<S, FileBuilderRequest>,
    phase: &str,
) -> Result<Option<HostRequest<S::Request>>, S::Error>
where
    S: Session,
    S::Request: Clone,
{
    poll_fn(|cx| {
        let poll = {
            let mut next = pin!(session.next());
            next.as_mut().poll(cx)
        };
        host.set_phase(format!("{phase} > {}", session.phase()));
        poll
    })
    .await
}

/// Answers a `ReservePlaceholder`: plans the embedding with `op` (a
/// handler's `plan_embed` operation), then writes it out.
async fn reserve_placeholder<Op: FormatOp<EmbedPlan>>(
    host: &Host<FileBuilderRequest>,
    op: Op,
    placeholder: &Bytes,
) -> Result<EmbedPlan, Error> {
    let plan = plan_embed(host, op).await?;

    if placeholder.len() as u64 != plan.manifest_len {
        return Err(Error::Invariant(
            "plan_embed's plan does not match the placeholder's length",
        ));
    }

    write_plan(host, plan, placeholder).await
}

/// Runs a handler's `plan_embed` operation, forwarding every read it needs
/// to [`FileBuilderSession::SOURCE_STREAM`].
async fn plan_embed<Op: FormatOp<EmbedPlan>>(
    host: &Host<FileBuilderRequest>,
    op: Op,
) -> Result<EmbedPlan, Error> {
    let mut op = Nested::new(op);

    while let Some(request) = next(host, &mut op, "Building > Planning").await? {
        match request.kind {
            IoRequest::Read { range, .. } => op.forward(
                request.id,
                host.request(FileBuilderRequest::Read {
                    stream: SOURCE,
                    range,
                }),
                to_io_reply,
            ),

            IoRequest::Length { .. } => op.forward(
                request.id,
                host.request(FileBuilderRequest::Length { stream: SOURCE }),
                to_io_reply,
            ),

            // Unreachable with today's `IoRequest`; see
            // `contentauth-c2pa-file-reader`'s identical fallback.
            _ => op.fulfill(
                request.id,
                IoReply::Failed(HostError::new("unsupported request")),
            )?,
        }
    }

    Ok(op.finish()?)
}

/// Confirms `plan` actually holds together before walking its edits — a
/// handler answers only through [`EmbedPlan::new`], not
/// [`EmbedPlan::splice`]'s own validation, so nothing has necessarily
/// checked it yet — then writes the planned output, with `placeholder` in
/// its slots.
async fn write_plan(
    host: &Host<FileBuilderRequest>,
    plan: EmbedPlan,
    placeholder: &Bytes,
) -> Result<EmbedPlan, Error> {
    host.set_phase("Building > Validating");
    let source_len = ask(
        host,
        FileBuilderRequest::Length { stream: SOURCE },
        "Length",
        |reply| match reply {
            FileBuilderReply::Length(len) => Some(len),
            _ => None,
        },
    )
    .await?;

    plan.check(source_len)?;
    write_all(host, tasks_for_edits(&plan.edits, placeholder)?).await?;
    Ok(plan)
}

/// Performs `tasks` in order, one host round trip at a time: never more
/// than one chunk of the asset is in memory.
async fn write_all(
    host: &Host<FileBuilderRequest>,
    tasks: VecDeque<WriteTask>,
) -> Result<(), Error> {
    host.set_phase("Building > Writing");
    for task in tasks {
        let (offset, bytes) = match task {
            WriteTask::CopyFromSource {
                output_offset,
                source_range,
            } => (output_offset, read_source(host, source_range).await?),

            WriteTask::WriteBytes {
                output_offset,
                bytes,
            } => (output_offset, bytes),
        };

        ask(
            host,
            FileBuilderRequest::Write {
                stream: OUTPUT,
                offset,
                bytes,
            },
            "Written",
            |reply| matches!(reply, FileBuilderReply::Written).then_some(()),
        )
        .await?;
    }

    Ok(())
}

/// Reads exactly `range` of [`FileBuilderSession::SOURCE_STREAM`].
async fn read_source(host: &Host<FileBuilderRequest>, range: ByteRange) -> Result<Bytes, Error> {
    let bytes = ask(
        host,
        FileBuilderRequest::Read {
            stream: SOURCE,
            range,
        },
        "Bytes",
        |reply| match reply {
            FileBuilderReply::Bytes(bytes) => Some(bytes),
            _ => None,
        },
    )
    .await?;

    let actual = bytes.len() as u64;
    if actual != range.len {
        return Err(Error::ReadLengthMismatch { range, actual });
    }
    Ok(bytes)
}

/// Asks the host for something and waits for the answer, turning a
/// [`FileBuilderReply::Failed`] into [`Error::HostFailure`] and a reply of
/// the wrong kind (which `fulfill` should already have refused) into
/// [`ProtocolError::ReplyMismatch`].
async fn ask<T>(
    host: &Host<FileBuilderRequest>,
    request: FileBuilderRequest,
    expected: &'static str,
    pick: impl FnOnce(FileBuilderReply) -> Option<T>,
) -> Result<T, Error> {
    host.ask(request, |id, reply| match reply {
        FileBuilderReply::Failed(source) => Err(Error::HostFailure { id, source }),
        reply => pick(reply).ok_or_else(|| ProtocolError::ReplyMismatch { id, expected }.into()),
    })
    .await
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
fn tasks_for_edits(edits: &[Edit], placeholder: &Bytes) -> Result<VecDeque<WriteTask>, Error> {
    let mut tasks = VecDeque::new();
    let mut offset = 0u64;

    for edit in edits {
        let len = edit.len();

        if len > 0 {
            match edit {
                Edit::Copy(range) => push_copy_chunks(&mut tasks, offset, *range),

                Edit::Emit(bytes) => tasks.push_back(WriteTask::WriteBytes {
                    output_offset: offset,
                    bytes: Bytes::copy_from_slice(bytes),
                }),

                Edit::Placeholder(range) => {
                    let bytes = slice(placeholder, *range).ok_or(Error::Invariant(
                        "a placeholder slot lies outside the placeholder bytes",
                    ))?;
                    tasks.push_back(WriteTask::WriteBytes {
                        output_offset: offset,
                        bytes,
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
///
/// The slice shares `bytes`' buffer: filling a placeholder slot copies
/// nothing.
fn slice(bytes: &Bytes, range: ByteRange) -> Option<Bytes> {
    let end = range.start.checked_add(range.len)?;
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(end).ok()?;
    (start <= end && end <= bytes.len()).then(|| bytes.slice(start..end))
}

/// Lays out the writes a manifest commit needs: `handler.commit`'s
/// patches, plus a rewrite of every [`Edit::Placeholder`] slot in `plan`
/// with the matching bytes of the final `manifest` — `Copy`/`Emit` edits
/// need no rewrite, since a commit changes only the manifest store's
/// content, never its framing or the source bytes around it.
fn tasks_for_commit<H: FormatHandler>(
    handler: &H,
    plan: &EmbedPlan,
    manifest: &Bytes,
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
                    bytes,
                });
            }
        }

        offset = offset
            .checked_add(len)
            .ok_or(Error::Invariant("output offset overflows"))?;
    }

    for patch in patches {
        // `FormatHandler::commit`'s own contract: every patch must lie
        // within an exclusion, since bytes outside them are already
        // hashed into the hard binding. A handler that violates this is
        // buggy, not this session's problem to route around.
        if !plan.excludes(patch.range()) {
            return Err(Error::Invariant(
                "commit() returned a patch outside the plan's exclusions",
            ));
        }

        tasks.push_back(WriteTask::WriteBytes {
            output_offset: patch.offset,
            bytes: patch.bytes.into(),
        });
    }

    Ok(tasks)
}

fn to_io_reply(reply: FileBuilderReply) -> IoReply {
    match reply {
        FileBuilderReply::Bytes(bytes) => IoReply::Bytes(bytes),
        FileBuilderReply::Length(len) => IoReply::Length(len),
        FileBuilderReply::Failed(err) => IoReply::Failed(err),

        // `Workflow::fulfill` validates a reply against
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_format::FormatError;
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
                bytes: vec![1, 2, 3].into(),
            },
            FileBuilderRequest::Sign {
                purpose: SignPurpose::Claim,
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
            (FileBuilderReply::Bytes(vec![1].into()), "Bytes"),
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
            to_builder_host_reply(FileBuilderReply::Bytes(vec![1].into())),
            BuilderHostReply::AssetBytes(bytes) if bytes[..] == [1]
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
            to_io_reply(FileBuilderReply::Bytes(vec![1].into())),
            IoReply::Bytes(bytes) if bytes[..] == [1]
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
        let placeholder = Bytes::from(vec![1, 2, 3]);

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
            WriteTask::WriteBytes { output_offset: 10, bytes } if bytes[..] == [0xaa; 4]
        ));
        assert!(matches!(
            &tasks[2],
            WriteTask::WriteBytes { output_offset: 14, bytes } if bytes[..] == [1, 2, 3]
        ));

        // The slot shares the placeholder's buffer rather than copying it.
        assert!(matches!(
            &tasks[2],
            WriteTask::WriteBytes { bytes, .. } if bytes.as_ptr() == placeholder.as_ptr()
        ));
    }

    #[test]
    fn tasks_for_edits_rejects_a_placeholder_slot_past_the_placeholder_bytes() {
        let edits = vec![Edit::Placeholder(ByteRange { start: 0, len: 5 })];
        assert!(matches!(
            tasks_for_edits(&edits, &Bytes::from(vec![1, 2])),
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

        let tasks = tasks_for_edits(&edits, &Bytes::new()).unwrap();
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
        let bytes = Bytes::from(vec![1u8, 2, 3, 4]);
        assert_eq!(
            slice(&bytes, ByteRange { start: 1, len: 2 }),
            Some(bytes.slice(1..3))
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
            vec![ByteRange { start: 0, len: 5 }],
            None,
        );
        assert!(matches!(
            tasks_for_commit(&JpegFormat, &plan, &Bytes::from(vec![1, 2, 3])),
            Err(Error::Invariant(_))
        ));
    }

    /// A JPEG in every respect but `commit`, which returns whatever patches
    /// it was given: the only way to exercise a handler that patches
    /// bytes, since no handler in this workspace has any to patch.
    struct Patching(Vec<contentauth_c2pa_format::Patch>);

    impl FormatHandler for Patching {
        type Locate = <JpegFormat as FormatHandler>::Locate;
        type PlanEmbed = <JpegFormat as FormatHandler>::PlanEmbed;

        fn descriptor(&self) -> &contentauth_c2pa_format::FormatDescriptor {
            JpegFormat.descriptor()
        }

        fn locate(&self, stream: contentauth_c2pa_format::StreamId) -> Self::Locate {
            JpegFormat.locate(stream)
        }

        fn plan_embed(
            &self,
            stream: contentauth_c2pa_format::StreamId,
            manifest_len: u64,
        ) -> Self::PlanEmbed {
            JpegFormat.plan_embed(stream, manifest_len)
        }

        fn commit(
            &self,
            _plan: &EmbedPlan,
            _manifest: &[u8],
        ) -> Result<Vec<contentauth_c2pa_format::Patch>, contentauth_c2pa_format::FormatError>
        {
            Ok(self.0.clone())
        }
    }

    /// A patch the handler returns is written, if it lies within an
    /// exclusion — and refused, as a handler bug, if it does not.
    #[test]
    fn tasks_for_commit_writes_patches_within_an_exclusion_and_refuses_others() {
        let plan = EmbedPlan::new(
            vec![
                Edit::Copy(ByteRange { start: 0, len: 4 }),
                Edit::Placeholder(ByteRange { start: 0, len: 5 }),
            ],
            5,
            vec![ByteRange { start: 4, len: 5 }],
            None,
        );
        let manifest = Bytes::from(vec![1u8, 2, 3, 4, 5]);

        // The stub is a JPEG in every other respect.
        let stub = Patching(Vec::new());
        assert_eq!(stub.descriptor().name, "jpeg");
        let stream = contentauth_c2pa_format::StreamId::new(0);
        drop(stub.locate(stream));
        drop(stub.plan_embed(stream, 8));

        let inside = Patching(vec![contentauth_c2pa_format::Patch::new(5, vec![9])]);
        let tasks = tasks_for_commit(&inside, &plan, &manifest).unwrap();
        assert!(matches!(
            tasks.back(),
            Some(WriteTask::WriteBytes { output_offset: 5, bytes }) if bytes[..] == [9]
        ));

        let outside = Patching(vec![contentauth_c2pa_format::Patch::new(0, vec![9])]);
        assert!(matches!(
            tasks_for_commit(&outside, &plan, &manifest),
            Err(Error::Invariant(m)) if m.contains("outside")
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
            vec![ByteRange { start: 10, len: 10 }],
            None,
        );

        // `JpegFormat::commit` never returns a patch — see its own docs —
        // so this also proves an empty patch list leaves the placeholder
        // rewrite as the only task.
        let tasks = tasks_for_commit(&JpegFormat, &plan, &Bytes::from(manifest.clone())).unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(matches!(
            &tasks[0],
            WriteTask::WriteBytes { output_offset: 12, bytes } if *bytes == manifest
        ));
    }

    /// A probe session running one of this module's `async` helpers alone.
    type Probe<T> = Workflow<FileBuilderRequest, T, Error>;

    /// The single outstanding request of `session`.
    fn only<T: Send>(session: &Probe<T>) -> HostRequest<FileBuilderRequest> {
        let requests = session.outstanding_requests();
        assert_eq!(requests.len(), 1, "one request at a time: {requests:?}");
        requests[0].clone()
    }

    #[test]
    fn write_all_moves_one_chunk_at_a_time() {
        let tasks = VecDeque::from([
            WriteTask::CopyFromSource {
                output_offset: 0,
                source_range: ByteRange { start: 8, len: 2 },
            },
            WriteTask::WriteBytes {
                output_offset: 2,
                bytes: vec![7].into(),
            },
        ]);
        let mut session: Probe<()> =
            Workflow::new(|host| async move { write_all(&host, tasks).await });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let read = only(&session);
        assert!(matches!(
            read.kind,
            FileBuilderRequest::Read {
                stream: SOURCE,
                range: ByteRange { start: 8, len: 2 }
            }
        ));
        session
            .fulfill(read.id, FileBuilderReply::Bytes(vec![1, 2].into()))
            .unwrap();

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let write = only(&session);
        assert!(matches!(
            &write.kind,
            FileBuilderRequest::Write { stream: OUTPUT, offset: 0, bytes } if bytes[..] == [1, 2]
        ));
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(only(&session).id, write.id, "not reissued while pending");
        session
            .fulfill(write.id, FileBuilderReply::Written)
            .unwrap();

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let write = only(&session);
        assert!(matches!(
            &write.kind,
            FileBuilderRequest::Write { stream: OUTPUT, offset: 2, bytes } if bytes[..] == [7]
        ));
        session
            .fulfill(write.id, FileBuilderReply::Written)
            .unwrap();

        assert_eq!(session.advance().unwrap(), Step::Complete);
    }

    #[test]
    fn read_source_rejects_a_reply_of_the_wrong_length() {
        let range = ByteRange { start: 4, len: 3 };
        let mut session: Probe<Bytes> =
            Workflow::new(move |host| async move { read_source(&host, range).await });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let id = only(&session).id;
        session
            .fulfill(id, FileBuilderReply::Bytes(vec![1].into()))
            .unwrap();
        assert!(matches!(
            session.advance(),
            Err(Error::ReadLengthMismatch { actual: 1, .. })
        ));
    }

    #[test]
    fn ask_reports_a_host_failure_with_its_request_id() {
        let mut session: Probe<Bytes> = Workflow::new(|host| async move {
            read_source(&host, ByteRange { start: 0, len: 1 }).await
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let id = only(&session).id;
        session
            .fulfill(id, FileBuilderReply::Failed(HostError::new("nope")))
            .unwrap();
        assert!(matches!(
            session.advance(),
            Err(Error::HostFailure { id: failed, .. }) if failed == id
        ));
    }

    /// `fulfill` refuses a reply of the wrong kind before `ask` ever sees
    /// it; this is the defense in depth behind that.
    #[test]
    fn ask_rejects_a_reply_of_the_wrong_kind() {
        let mut session: Probe<Bytes> = Workflow::new(|host| async move {
            read_source(&host, ByteRange { start: 0, len: 1 }).await
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let id = only(&session).id;
        session.fulfill_unchecked(id, FileBuilderReply::Written);
        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "Bytes",
                ..
            }))
        ));
    }

    /// A plan `plan_embed` returned unchecked — one with a `Copy` edit
    /// reaching past the end of the source it was supposedly built from —
    /// must be rejected before this session ever indexes into anything
    /// using its offsets, not silently trusted.
    #[test]
    fn write_plan_rejects_a_plan_that_does_not_check_out() {
        let plan = EmbedPlan::new(
            vec![Edit::Copy(ByteRange { start: 0, len: 10 })],
            0,
            vec![ByteRange { start: 0, len: 0 }],
            None,
        );
        let mut session: Probe<EmbedPlan> =
            Workflow::new(|host| async move { write_plan(&host, plan, &Bytes::new()).await });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let length = only(&session);
        assert!(matches!(
            length.kind,
            FileBuilderRequest::Length { stream: SOURCE }
        ));
        session
            .fulfill(length.id, FileBuilderReply::Length(5))
            .unwrap();
        assert!(matches!(session.advance(), Err(Error::Format(_))));
    }

    /// A stand-in `plan_embed` operation — itself a [`Workflow`], which
    /// [`Nested`] drives exactly as it would a handler's hand-written one —
    /// that asks for the source's length and its first byte, then plans a
    /// manifest of `manifest_len` bytes.
    type FakePlanEmbed = Workflow<IoRequest, EmbedPlan, FormatError>;

    fn fake_plan_embed(manifest_len: u64) -> FakePlanEmbed {
        Workflow::new(move |host| async move {
            let length = host.request(IoRequest::Length {
                stream: StreamId::new(7),
            });
            let read = host.request(IoRequest::Read {
                stream: StreamId::new(7),
                range: ByteRange { start: 0, len: 1 },
            });
            let (IoReply::Length(len), IoReply::Bytes(_)) = (length.await, read.await) else {
                return Err(FormatError::Malformed("unexpected reply".into()));
            };

            Ok(EmbedPlan::new(
                vec![
                    Edit::Copy(ByteRange { start: 0, len }),
                    Edit::Placeholder(ByteRange {
                        start: 0,
                        len: manifest_len,
                    }),
                ],
                manifest_len,
                vec![ByteRange {
                    start: len,
                    len: manifest_len,
                }],
                None,
            ))
        })
    }

    /// Answers whatever a [`Probe`] asks, against a one-byte source, and
    /// returns how many host requests were outstanding at most at once.
    fn drive<T: Send>(session: &mut Probe<T>) -> Result<usize, Error> {
        let mut widest = 0;
        while session.advance()? == Step::AwaitHost {
            let requests = session.outstanding_requests().to_vec();
            widest = widest.max(requests.len());
            for request in requests {
                let reply = match request.kind {
                    FileBuilderRequest::Length { stream: SOURCE } => FileBuilderReply::Length(1),
                    FileBuilderRequest::Read {
                        stream: SOURCE,
                        range,
                    } => FileBuilderReply::Bytes(vec![0; range.len as usize].into()),
                    FileBuilderRequest::Write { stream: OUTPUT, .. } => FileBuilderReply::Written,
                    other => panic!("unexpected request: {other:?}"),
                };
                session.fulfill(request.id, reply)?;
            }
        }
        Ok(widest)
    }

    #[test]
    fn reserve_placeholder_plans_against_the_source_then_writes_the_plan() {
        let placeholder = Bytes::from(vec![9; 3]);
        let mut session: Probe<EmbedPlan> = Workflow::new(|host| async move {
            reserve_placeholder(&host, fake_plan_embed(3), &placeholder).await
        });

        let widest = drive(&mut session).unwrap();
        assert_eq!(
            widest, 2,
            "the operation's two requests are in flight together"
        );
        let plan = session.finish().unwrap();
        assert_eq!(plan.output_len(), Some(4));
    }

    #[test]
    fn reserve_placeholder_rejects_a_plan_of_the_wrong_length() {
        let placeholder = Bytes::from(vec![9; 3]);
        let mut session: Probe<EmbedPlan> = Workflow::new(|host| async move {
            reserve_placeholder(&host, fake_plan_embed(2), &placeholder).await
        });

        assert!(matches!(drive(&mut session), Err(Error::Invariant(_))));
    }

    #[test]
    fn an_inner_operation_failure_fails_the_session() {
        let mut session: Probe<EmbedPlan> =
            Workflow::new(|host| async move { plan_embed(&host, fake_plan_embed(2)).await });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        for request in session.outstanding_requests().to_vec() {
            session
                .fulfill(request.id, FileBuilderReply::Failed(HostError::new("nope")))
                .unwrap();
        }
        assert!(matches!(session.advance(), Err(Error::Format(_))));
    }

    #[test]
    fn debug_names_the_session() {
        let session = FileBuilderSession::new(JpegFormat, test_settings());
        assert!(format!("{session:?}").starts_with("FileBuilderSession"));
    }
}
