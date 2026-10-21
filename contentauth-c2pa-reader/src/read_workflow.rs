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

//! The read/validate workflow of [`ReadSession`](crate::ReadSession),
//! written as one `async fn` on [`sans_io_engine`].
//!
//! Experimental, and only built with the `engine` feature. It reports what
//! [`ReadSession`](crate::ReadSession) reports, from the same trust, OCSP and
//! hard-binding rules, to compare the two ways of authoring the same
//! state machine:
//!
//! * `ReadSession` keeps a phase enum (`State`) with one variant per wait,
//!   each carrying its locals, plus a `handle_*` function per variant and a
//!   `HashStream` that re-implements ordering and windowing by hand.
//! * Here the phases are the straight-line text of one `async fn`: locals live in
//!   ordinary variables, `?` is the early exit, the hashing window is a
//!   `VecDeque` of pending replies, and OCSP checks are issued together and
//!   awaited in turn.
//!
//! The host-facing vocabulary is the same [`ReadRequest`]. Replies differ in
//! one respect: failure is not a reply variant. A host that cannot perform a
//! request calls [`Session::fail`](sans_io_engine::Session::fail), and this
//! workflow decides, request by request, whether that is fatal (no manifest
//! store) or data (no clock, no OCSP responder, no asset).

use std::{collections::VecDeque, fmt};

use contentauth_c2pa_primitives::{hash::Hasher, ByteRange, HashAlgorithm};
use sans_io_engine::{Host, HostFailure, PendingReply, Request as EngineRequest, Workflow};

use crate::{
    chain::{self, Anchor, PendingChain, Trust},
    error::{AnchorKind, Error},
    hash_stream::{self, CHUNK_SIZE, WINDOW},
    manifest_store, ocsp,
    read::{
        decode_anchors, plan_hard_binding, PendingBinding, ReadReport, ReadSession, ReadSettings,
    },
    request::ReadRequest,
    timestamp,
    validation::{status_code, ValidationState, ValidationStatus},
};

/// The host's answer to a [`ReadRequest`] under the engine.
///
/// The same payloads as [`ReadHostReply`](crate::ReadHostReply) without its
/// `Failed` variant: the host reports failure with
/// [`Session::fail`](sans_io_engine::Session::fail).
pub enum Reply {
    /// Answers [`ReadRequest::ManifestStore`]: the store's bytes, or `None`
    /// if the asset has none.
    ManifestStore(Option<Vec<u8>>),

    /// Answers [`ReadRequest::AssetBytes`]: exactly the bytes asked for.
    AssetBytes(Vec<u8>),

    /// Answers [`ReadRequest::AssetLength`].
    AssetLength(u64),

    /// Answers [`ReadRequest::CurrentDateTime`]: seconds since the Unix
    /// epoch (UTC).
    CurrentDateTime(i64),

    /// Answers [`ReadRequest::Ocsp`]: the responder's body, verbatim.
    Ocsp(Vec<u8>),
}

// Lengths only: a reply can carry a 64 KiB asset chunk.
impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestStore(Some(bytes)) => write!(f, "ManifestStore({} bytes)", bytes.len()),
            Self::ManifestStore(None) => f.write_str("ManifestStore(none)"),
            Self::AssetBytes(bytes) => write!(f, "AssetBytes({} bytes)", bytes.len()),
            Self::AssetLength(len) => write!(f, "AssetLength({len})"),
            Self::CurrentDateTime(now) => write!(f, "CurrentDateTime({now})"),
            Self::Ocsp(bytes) => write!(f, "Ocsp({} bytes)", bytes.len()),
        }
    }
}

impl EngineRequest for ReadRequest {
    type Reply = Reply;

    fn name(&self) -> &'static str {
        match self {
            Self::ManifestStore { .. } => "ManifestStore",
            Self::AssetBytes { .. } => "AssetBytes",
            Self::AssetLength { .. } => "AssetLength",
            Self::CurrentDateTime => "CurrentDateTime",
            Self::Ocsp { .. } => "Ocsp",
        }
    }

    fn accepts(&self, reply: &Reply) -> bool {
        match (self, reply) {
            (Self::ManifestStore { .. }, Reply::ManifestStore(_)) => true,
            // Never more than was asked for. A *short* read is accepted
            // here and rejected by the workflow, which names the range.
            (Self::AssetBytes { range, .. }, Reply::AssetBytes(bytes)) => {
                bytes.len() as u64 <= range.len
            }
            (Self::AssetLength { .. }, Reply::AssetLength(_)) => true,
            (Self::CurrentDateTime, Reply::CurrentDateTime(_)) => true,
            (Self::Ocsp { .. }, Reply::Ocsp(_)) => true,
            _ => false,
        }
    }
}

/// Why a [`ReadWorkflow`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkflowError {
    /// The read itself failed: malformed store, misconfigured anchor, a
    /// short asset read, and so on.
    #[error(transparent)]
    Read(#[from] Error),

    /// The host used the session API incorrectly.
    #[error(transparent)]
    Engine(#[from] sans_io_engine::ProtocolError),

    /// A host operation failed and the workflow cannot continue without it.
    #[error("host could not perform {request}: {source}")]
    Host {
        /// [`EngineRequest::name`] of the request that failed.
        request: &'static str,

        /// What the host reported.
        source: HostFailure,
    },

    /// The host's reply passed the request's check but is the wrong kind.
    /// Unreachable through the engine's own validation; kept as an error
    /// rather than a panic.
    #[error("unexpected reply to {expected}")]
    UnexpectedReply {
        /// The request that was answered.
        expected: &'static str,
    },
}

/// A read session: a [`sans_io_engine::Session`] producing a [`ReadReport`].
pub type ReadWorkflow = Workflow<'static, ReadRequest, ReadReport, WorkflowError>;

/// Starts reading and validating the primary asset's manifest store.
///
/// Drive it with [`sans_io_engine::drive`] or any loop over
/// [`sans_io_engine::Session`].
pub fn read_workflow(settings: ReadSettings) -> ReadWorkflow {
    Workflow::new(|host| read(host, settings))
}

impl Reply {
    fn manifest_store(self) -> Result<Option<Vec<u8>>, WorkflowError> {
        match self {
            Self::ManifestStore(store) => Ok(store),
            _ => Err(WorkflowError::UnexpectedReply {
                expected: "ManifestStore",
            }),
        }
    }

    fn asset_bytes(self) -> Result<Vec<u8>, WorkflowError> {
        match self {
            Self::AssetBytes(bytes) => Ok(bytes),
            _ => Err(WorkflowError::UnexpectedReply {
                expected: "AssetBytes",
            }),
        }
    }

    fn asset_length(self) -> Result<u64, WorkflowError> {
        match self {
            Self::AssetLength(len) => Ok(len),
            _ => Err(WorkflowError::UnexpectedReply {
                expected: "AssetLength",
            }),
        }
    }

    fn current_date_time(self) -> Result<i64, WorkflowError> {
        match self {
            Self::CurrentDateTime(now) => Ok(now),
            _ => Err(WorkflowError::UnexpectedReply {
                expected: "CurrentDateTime",
            }),
        }
    }
}

/// Maps a host failure on a request the workflow cannot do without.
fn fatal(request: &'static str) -> impl FnOnce(HostFailure) -> WorkflowError {
    move |source| WorkflowError::Host { request, source }
}

/// The whole read, top to bottom.
async fn read(
    host: Host<ReadRequest>,
    settings: ReadSettings,
) -> Result<ReadReport, WorkflowError> {
    // Before the host is asked to do anything: an anchor that is not a
    // certificate is a configuration mistake, and surfaces the same way
    // every time.
    let mut ctx = Context::new(settings)?;

    let store = host
        .request(ReadRequest::ManifestStore {
            stream: ReadSession::PRIMARY_STREAM,
        })
        .await
        .map_err(fatal("ManifestStore"))?
        .manifest_store()?;

    let Some(bytes) = store else {
        // The report already reads as "nothing found".
        return Ok(ctx.into_report());
    };

    let parsed = manifest_store::parse(&bytes)?;
    let mut statuses = parsed.statuses;

    // Planned before the report is built, so the plan is a pure function of
    // what was parsed.
    let binding = parsed
        .active_manifest
        .as_deref()
        .and_then(|label| parsed.manifests.iter().find(|m| m.label == label))
        .and_then(|active| plan_hard_binding(active, &mut statuses));

    ctx.report = ReadReport {
        manifest_store_found: true,
        manifests: parsed.manifests,
        active_manifest: parsed.active_manifest,
        validation_state: None,
        statuses,
    };

    // Nothing to judge against a clock means the host is never asked for one.
    if !(parsed.chains.is_empty() && parsed.identity_chains.is_empty()) {
        let now = match host.request(ReadRequest::CurrentDateTime).await {
            Ok(reply) => Some(reply.current_date_time()?),
            // A host that cannot tell the time is not necessarily stuck: a
            // signature carrying a trusted timestamp brings its own
            // instant, and only the ones that do not are left unevaluated.
            Err(_) => None,
        };

        ctx.evaluate_identity_trust(&parsed.identity_chains, now);
        let pending = ctx.evaluate_trust(&host, &parsed.chains, now);
        ctx.settle_ocsp(pending).await?;
    }

    if let Some(binding) = binding {
        ctx.check_hard_binding(&host, binding).await?;
    }

    Ok(ctx.into_report())
}

/// Hashes `ranges` of the primary asset, with up to [`WINDOW`] chunk reads
/// in flight at once.
///
/// Replies are awaited in chunk order, so they are folded in order whatever
/// order the host answers in; one that arrives early waits in the engine's
/// mailbox. At most `WINDOW` chunks exist at once, bounding memory the same
/// way `HashStream` does.
async fn hash_ranges(
    host: &Host<ReadRequest>,
    algorithm: HashAlgorithm,
    ranges: &[ByteRange],
) -> Result<Vec<u8>, WorkflowError> {
    let mut chunks = Vec::new();
    for range in ranges {
        let mut offset = range.start;
        let end = range.start.saturating_add(range.len);
        while offset < end {
            let len = CHUNK_SIZE.min(end - offset);
            chunks.push(ByteRange { start: offset, len });
            offset += len;
        }
    }
    let total: u64 = chunks.iter().map(|c| c.len).sum();

    let mut hasher = Hasher::new(algorithm);
    let mut folded = 0u64;
    let mut next = 0;
    let mut in_flight: VecDeque<(ByteRange, PendingReply<ReadRequest>)> = VecDeque::new();

    loop {
        while next < chunks.len() && in_flight.len() < WINDOW {
            let range = chunks[next];
            let reply = host.request(ReadRequest::AssetBytes {
                stream: ReadSession::PRIMARY_STREAM,
                range,
            });
            in_flight.push_back((range, reply));
            next += 1;
        }

        let Some((range, reply)) = in_flight.pop_front() else {
            break;
        };
        let bytes = reply
            .await
            .map_err(fatal("AssetBytes"))?
            .asset_bytes()?;

        // A short or long read would shift every byte after it, so this can
        // never be tolerated.
        if bytes.len() as u64 != range.len {
            return Err(Error::AssetBytesLengthMismatch {
                range,
                actual: bytes.len() as u64,
            }
            .into());
        }

        hasher.update(&bytes);
        folded += range.len;
        host.recycle(bytes);
    }

    if folded != total {
        return Err(Error::IncompleteAssetHash {
            folded,
            expected: total,
        }
        .into());
    }

    Ok(hasher.finish())
}

/// One claim signer chain's outstanding OCSP checks, and enough about the
/// chain's own outcome and timing to act on whatever they establish.
struct PendingChainOcsp {
    /// The chain's claim signature URL.
    url: String,

    /// Whether this is the *active* manifest's own chain, the one whose
    /// [`Trust`] feeds the report's validation state.
    is_active: bool,

    /// The host's current time, if it supplied one.
    now: Option<i64>,

    /// The claim signature's attested signing instant, from a trusted RFC
    /// 3161 timestamp.
    attested: Option<i64>,

    /// Checks not yet answered, each with the request it was issued as and
    /// whether it asks about the claim signer's own certificate (`true`) or
    /// a CA above it (`false`). Dropping one withdraws its request.
    checks: Vec<(PendingReply<ReadRequest>, ocsp::PendingOcspCheck, bool)>,
}

/// What the workflow accumulates: settings, decoded anchors, and the report.
struct Context {
    settings: ReadSettings,
    anchors: Vec<Anchor>,
    timestamp_anchors: Vec<Anchor>,
    identity_anchors: Vec<Anchor>,

    /// How far trust was established for the *active* manifest.
    trust: Option<Trust>,

    report: ReadReport,
}

impl Context {
    fn new(settings: ReadSettings) -> Result<Self, Error> {
        let anchors = decode_anchors(
            &settings.trust_lists,
            &settings.trust_anchors,
            AnchorKind::Claim,
        )?;
        let timestamp_anchors = decode_anchors(
            &settings.timestamp_trust_lists,
            &settings.timestamp_trust_anchors,
            AnchorKind::Timestamp,
        )?;
        let identity_anchors = decode_anchors(
            &settings.identity_trust_lists,
            &settings.identity_trust_anchors,
            AnchorKind::Identity,
        )?;

        Ok(Self {
            settings,
            anchors,
            timestamp_anchors,
            identity_anchors,
            trust: None,
            report: ReadReport {
                manifest_store_found: false,
                manifests: vec![],
                active_manifest: None,
                validation_state: None,
                statuses: vec![],
            },
        })
    }

    /// Validates each verified identity signature's certificate chain
    /// against the configured identity anchors. As in `ReadSession`: no
    /// revocation check, and no outcome changes the store's
    /// [`ValidationState`].
    fn evaluate_identity_trust(&mut self, chains: &[PendingChain], now: Option<i64>) {
        for pending in chains {
            let mut statuses = Vec::new();

            let attested =
                pending.timestamp.as_ref().and_then(|timestamp| {
                    match timestamp::validate(
                        timestamp,
                        &self.timestamp_anchors,
                        &pending.url,
                        &mut statuses,
                    ) {
                        timestamp::Timestamped::Trusted(gen_time) => Some(gen_time),
                        _ => None,
                    }
                });

            match attested.or(now) {
                Some(instant) => {
                    chain::validate(
                        &pending.certificates,
                        &self.identity_anchors,
                        instant,
                        &pending.url,
                        chain::CAWG_X509_SIGNER,
                        &mut statuses,
                    );
                }

                // Reported as untrusted rather than under `general.error`,
                // which would leave the whole store `Incomplete` for a
                // finding that is only this assertion's.
                None => statuses.push(ValidationStatus::for_url(
                    status_code::CAWG_X509_CREDENTIAL_UNTRUSTED,
                    &pending.url,
                    "no trusted timestamp and no current time, so the identity credential's certificate chain was not evaluated",
                )),
            }

            self.report.statuses.append(&mut statuses);
        }
    }

    /// Validates each verified claim signature's certificate chain against
    /// the configured anchors, and works through C2PA spec §15.9's
    /// revocation process: stapled `rVals` first (no host round trip), then
    /// an online query for what they left open.
    ///
    /// The online queries are issued here, all at once, and returned for
    /// [`Self::settle_ocsp`] to await. Same rules as
    /// `ReadSession::evaluate_trust`.
    fn evaluate_trust(
        &mut self,
        host: &Host<ReadRequest>,
        chains: &[PendingChain],
        now: Option<i64>,
    ) -> Vec<PendingChainOcsp> {
        let mut pending_ocsp = Vec::new();

        for pending in chains {
            let mut statuses = Vec::new();

            let stamped = pending.timestamp.as_ref().map(|timestamp| {
                timestamp::validate(
                    timestamp,
                    &self.timestamp_anchors,
                    &pending.url,
                    &mut statuses,
                )
            });

            // Only a trusted authority's word on the time is taken.
            // `attested` is kept apart from the merged `instant` because
            // C2PA spec §15.9.1/§15.9.2 care about the two separately.
            let attested = match stamped {
                Some(timestamp::Timestamped::Trusted(gen_time)) => Some(gen_time),
                _ => None,
            };
            let instant = attested.or(now);

            let Some(instant) = instant else {
                // TODO: confirm `GENERAL_ERROR` is the correct status code
                // for this case (#2).
                statuses.push(ValidationStatus::for_url(
                    status_code::GENERAL_ERROR,
                    &pending.url,
                    "no trusted timestamp and no current time, so the certificate chain was not evaluated",
                ));
                self.report.statuses.append(&mut statuses);
                continue;
            };

            let trust = chain::validate(
                &pending.certificates,
                &self.anchors,
                instant,
                &pending.url,
                chain::CLAIM_SIGNER,
                &mut statuses,
            );
            self.report.statuses.append(&mut statuses);

            // Only the active manifest's outcome shapes the store's
            // validation state.
            let is_active =
                self.report.active_manifest.as_deref() == Some(pending.manifest_label.as_str());
            if is_active {
                self.trust = Some(trust);
            }

            // A chain the checks above already rejected is not worth
            // asking about.
            if trust == Trust::Rejected {
                continue;
            }

            let mut online_checks = Vec::new();

            for chain::OcspCheckPlan { check, is_signer } in
                chain::ocsp_checks(&pending.certificates, &self.anchors)
            {
                let staple_outcome = pending.rvals.iter().find_map(|response_der| {
                    match ocsp::evaluate_stapled(&check, response_der, now, attested) {
                        ocsp::StapledOutcome::Inconclusive => None,
                        resolved => Some(resolved),
                    }
                });

                match staple_outcome {
                    Some(ocsp::StapledOutcome::NotRevoked) => {
                        // §15.9 defines no status for a *CA* certificate
                        // confirmed not revoked, only the signer's own.
                        if is_signer {
                            self.record(ValidationStatus::for_url(
                                status_code::SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
                                &pending.url,
                                "a stapled OCSP response says this credential was not revoked at the time of signing",
                            ));
                        }
                    }

                    Some(ocsp::StapledOutcome::Revoked) => self.apply_revocation(
                        is_signer,
                        is_active,
                        &pending.url,
                        "a stapled OCSP response says a certificate in this credential's chain was revoked",
                    ),

                    // Nothing was established in the store, so §15.9 falls
                    // through to an online check, for the signer's own
                    // certificate with a status of its own.
                    None | Some(ocsp::StapledOutcome::Inconclusive) if is_signer => {
                        match (&check.responder_url, self.settings.check_ocsp) {
                            (Some(responder_url), true) => {
                                let reply = host.request(ReadRequest::Ocsp {
                                    url: responder_url.clone(),
                                    request_der: check.request_der.clone(),
                                });
                                online_checks.push((reply, check, true));
                            }

                            (Some(_), false) => {
                                self.record(ValidationStatus::for_url(
                                    status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED,
                                    &pending.url,
                                    "no revocation information for this credential was found in the manifest, and online OCSP checking is disabled",
                                ));
                            }

                            (None, _) => {
                                self.record(ValidationStatus::for_url(
                                    status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED,
                                    &pending.url,
                                    "no revocation information for this credential was found in the manifest, and its certificate names no OCSP responder to query online",
                                ));
                            }
                        }
                    }

                    // A CA certificate whose staples resolved nothing:
                    // ask its own responder when allowed to. Nothing is
                    // recorded unless the CA turns out to be revoked.
                    None | Some(ocsp::StapledOutcome::Inconclusive) => {
                        if let (Some(responder_url), true) =
                            (&check.responder_url, self.settings.check_ocsp)
                        {
                            let reply = host.request(ReadRequest::Ocsp {
                                url: responder_url.clone(),
                                request_der: check.request_der.clone(),
                            });
                            online_checks.push((reply, check, false));
                        }
                    }
                }
            }

            if !online_checks.is_empty() {
                pending_ocsp.push(PendingChainOcsp {
                    url: pending.url.clone(),
                    is_active,
                    now,
                    attested,
                    checks: online_checks,
                });
            }
        }

        pending_ocsp
    }

    /// Awaits each online OCSP check issued by [`Self::evaluate_trust`] and
    /// records the C2PA spec §15.9.2 status it establishes.
    ///
    /// All of the requests are already with the host, so the waits overlap;
    /// this only decides the order the answers are read in. Returning early
    /// (an error) drops the remaining replies, which withdraws their
    /// requests.
    async fn settle_ocsp(&mut self, pending: Vec<PendingChainOcsp>) -> Result<(), WorkflowError> {
        for chain_pending in pending {
            let PendingChainOcsp {
                url,
                is_active,
                now,
                attested,
                checks,
            } = chain_pending;

            for (reply, check, is_signer) in checks {
                match (reply.await, is_signer) {
                    (Ok(Reply::Ocsp(response_der)), false) => {
                        if ocsp::evaluate_ca_online(&check, &response_der, now, attested) {
                            self.apply_revocation(
                                false,
                                is_active,
                                &url,
                                "an OCSP response says a certificate in this credential's chain was revoked",
                            );
                        }
                    }

                    // A CA's responder that cannot be reached is no finding
                    // at all.
                    (Err(_), false) => {}

                    (Ok(Reply::Ocsp(response_der)), true) => {
                        let outcome =
                            ocsp::evaluate_online(&check, &response_der, now, attested);
                        self.apply_online_outcome(outcome, &url, is_active);
                    }

                    // "Unable to receive a response" (C2PA spec §15.9.2).
                    (Err(_), true) => {
                        self.record(ValidationStatus::for_url(
                            status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
                            &url,
                            "the OCSP responder could not be reached",
                        ));
                    }

                    (Ok(_), _) => {
                        return Err(WorkflowError::UnexpectedReply { expected: "Ocsp" });
                    }
                }
            }
        }

        Ok(())
    }

    /// Records what an online OCSP check (C2PA spec §15.9.2) established
    /// about the signer's own certificate.
    fn apply_online_outcome(&mut self, outcome: ocsp::OnlineOutcome, url: &str, is_active: bool) {
        match outcome {
            ocsp::OnlineOutcome::NotRevoked => self.record(ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
                url,
                "an OCSP response says this credential was not revoked at the time of signing",
            )),

            ocsp::OnlineOutcome::Revoked => {
                self.apply_revocation(
                    true,
                    is_active,
                    url,
                    "an OCSP response says this credential was revoked",
                );
            }

            ocsp::OnlineOutcome::Unknown => self.record(ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_OCSP_UNKNOWN,
                url,
                "an OCSP response reported this credential's status as unknown",
            )),

            // The response could not be authenticated for this certificate
            // at all, operationally no different from never having
            // received one.
            ocsp::OnlineOutcome::Inconclusive => self.record(ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
                url,
                "the OCSP response could not be authenticated for this credential",
            )),
        }
    }

    /// Records a confirmed revocation (C2PA spec §15.9) for the claim
    /// signer's own certificate or a CA above it. See
    /// `ReadSession::apply_revocation` for why the four combinations are
    /// reported as they are.
    fn apply_revocation(&mut self, is_signer: bool, is_active: bool, url: &str, explanation: &str) {
        let status = match (is_signer, is_active) {
            (true, true) => ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_OCSP_REVOKED,
                url,
                explanation,
            ),
            (true, false) => ValidationStatus::for_url_suppressing_failure(
                status_code::SIGNING_CREDENTIAL_OCSP_REVOKED,
                url,
                explanation,
            ),
            (false, true) => ValidationStatus::for_url_forcing_failure(
                status_code::SIGNING_CREDENTIAL_UNTRUSTED,
                url,
                explanation,
            ),
            (false, false) => ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_UNTRUSTED,
                url,
                explanation,
            ),
        };

        self.record(status);

        if is_active {
            self.trust = Some(Trust::Rejected);
        }
    }

    /// Verifies the active manifest's hard binding against the asset.
    async fn check_hard_binding(
        &mut self,
        host: &Host<ReadRequest>,
        binding: PendingBinding,
    ) -> Result<(), WorkflowError> {
        let asset_len = match host
            .request(ReadRequest::AssetLength {
                stream: ReadSession::PRIMARY_STREAM,
            })
            .await
        {
            Ok(reply) => reply.asset_length()?,

            // A host with no asset to offer, reading a detached manifest
            // say, leaves the binding unchecked rather than failed.
            Err(_) => {
                self.record(ValidationStatus::for_url(
                    status_code::GENERAL_ERROR,
                    &binding.url,
                    "asset not available, so the hard binding was not checked",
                ));
                return Ok(());
            }
        };

        let Some(ranges) = hash_stream::included_ranges(&binding.exclusions, asset_len) else {
            self.record(ValidationStatus::for_url(
                status_code::ASSERTION_DATAHASH_MALFORMED,
                &binding.url,
                "hard binding exclusions do not describe this asset",
            ));
            return Ok(());
        };

        let actual = hash_ranges(host, binding.algorithm, &ranges).await?;

        self.record(if actual == binding.expected {
            ValidationStatus::for_url(
                status_code::ASSERTION_DATAHASH_MATCH,
                &binding.url,
                "asset hashed as recorded in the hard binding",
            )
        } else {
            ValidationStatus::for_url(
                status_code::ASSERTION_DATAHASH_MISMATCH,
                &binding.url,
                "asset does not hash to the value recorded in the hard binding",
            )
        });

        Ok(())
    }

    /// Appends a validation status to the in-progress report.
    fn record(&mut self, status: ValidationStatus) {
        self.report.statuses.push(status);
    }

    /// Computes the overall outcome and hands over the report.
    fn into_report(mut self) -> ReadReport {
        self.report.validation_state = if self.report.manifests.is_empty() {
            // Nothing was validated, so no outcome can be reported.
            None
        } else if self
            .report
            .statuses
            .iter()
            .any(ValidationStatus::affects_validation_state)
        {
            Some(ValidationState::Invalid)
        } else if self
            .report
            .statuses
            .iter()
            .any(ValidationStatus::is_unchecked)
        {
            // Something that bears on the verdict was never established.
            Some(ValidationState::Incomplete)
        } else {
            match self.trust {
                Some(Trust::Anchored) => Some(ValidationState::Trusted),
                Some(Trust::Unanchored) => Some(ValidationState::Valid),

                // Neither arm is reachable today, and both are here so
                // that the safe answer is the default if that changes.
                Some(Trust::Rejected) | None => Some(ValidationState::Incomplete),
            }
        };

        self.report
    }
}

#[cfg(test)]
mod tests;
