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

//! The read/validate workflow: [`ReadSession`].

use core::mem::replace;

use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, StreamId};
/// [`Step::AwaitHost`] / [`Step::Complete`], under the name this crate's
/// docs and tests use for [`ReadSession`]'s own steps. This is the very
/// same type as [`contentauth_state_machine::Step`] — see the crate root.
pub use contentauth_state_machine::Step as ReadStep;
use contentauth_state_machine::{
    HostRequest, ProtocolError, RequestId, Session, SessionCore, Step,
};

use crate::{
    cert::{self, Certificate},
    chain::{self, PendingChain, Trust},
    data_hash,
    error::Error,
    hash_stream::{self, HashStream},
    manifest_store::{self, Manifest},
    request::{ReadHostReply, ReadRequest},
    timestamp,
    validation::{status_code, ValidationState, ValidationStatus},
};

/// Configuration for a [`ReadSession`].
///
/// Experimental: this will grow to cover the rest of the trust
/// configuration (additional allowed EKUs, revocation policy), remote-
/// manifest policy, verification options, and so on — roughly the
/// read-relevant subset of the c2pa-rs settings system.
#[derive(Clone, Debug, Default)]
pub struct ReadSettings {
    /// If true, the session may issue an HTTP-fetch-style request to
    /// retrieve a remote manifest store referenced by the asset.
    ///
    /// Aspirational: nothing in [`ReadSession`] issues such a request
    /// today, since the request vocabulary this crate implements does not
    /// yet include one. Carried here so hosts that already read this
    /// setting do not need to change when it lands.
    pub fetch_remote_manifests: bool,

    /// DER-encoded certificates to treat as trust anchors.
    ///
    /// A claim signature whose certificate path terminates at one of these
    /// reaches [`ValidationState::Trusted`]; one that does not reaches
    /// [`ValidationState::Valid`] at best. Leaving this empty is a
    /// supported configuration and simply means no signer is ever trusted
    /// — the chain is still built and checked, so a broken one is still
    /// reported as broken.
    ///
    /// Anchors are trusted *a priori*: their own signatures are never
    /// verified, which is what distinguishes an anchor from a certificate
    /// that merely appears in a chain. Their validity windows still are:
    /// an anchor that has expired takes the whole path down with it rather
    /// than going on trusting indefinitely. Supplying one is a deliberate act,
    /// and a byte string that is not a certificate is a configuration
    /// mistake rather than a validation finding — see
    /// [`Error::MalformedTrustAnchor`].
    pub trust_anchors: Vec<Vec<u8>>,

    /// DER-encoded certificates to treat as trust anchors for RFC 3161
    /// timestamping authorities.
    ///
    /// A separate list from [`Self::trust_anchors`] because it answers a
    /// different question. Those anchors say whose claims you believe;
    /// these say whose word on *the time* you take — and the authorities
    /// that stamp time are public CAs with no relationship to whoever
    /// signed the manifest.
    ///
    /// Leaving this empty means no timestamp is ever trusted, and every
    /// certificate is judged against the host's current time. That is the
    /// stricter reading: a manifest signed with a since-expired credential
    /// reads as outside its validity window, however good its timestamp.
    pub timestamp_trust_anchors: Vec<Vec<u8>>,
}

/// Reads and validates a C2PA manifest store from a digital asset.
///
/// This is the synchronous, sans-I/O counterpart of `Reader` in c2pa-rs. It
/// implements the [`Session`] trait from `contentauth-state-machine`: it
/// never touches the asset, the network, or a clock itself; it issues host
/// requests and the host reports outcomes back in any order.
///
/// # Interaction contract
///
/// See the [`Session`] trait for the full contract. Concretely:
///
/// 1. Create the session with [`ReadSession::new`].
/// 2. Call [`Session::advance`] to let the session do as much synchronous
///    work as it can. It returns [`ReadStep::AwaitHost`] when blocked on the
///    host, or [`ReadStep::Complete`] when done.
/// 3. While `AwaitHost`: service any subset of
///    [`Session::outstanding_requests`] (concurrently if desired), report
///    each outcome via [`Session::fulfill`], and call
///    [`Session::advance`] again.
/// 4. On `Complete`: consume the session with [`Session::finish`] to obtain
///    the [`ReadReport`].
///
/// # Example
///
/// A host whose asset contains no manifest store:
///
/// ```
/// use contentauth_c2pa_reader::{Error, ReadHostReply, ReadSession, ReadSettings, ReadStep};
/// use contentauth_state_machine::Session;
///
/// let mut session = ReadSession::new(ReadSettings::default());
///
/// assert_eq!(session.advance()?, ReadStep::AwaitHost);
///
/// // The host looks inside the asset's container format... and finds no
/// // C2PA manifest store.
/// let id = session.outstanding_requests()[0].id;
/// session.fulfill(id, ReadHostReply::ManifestStore(None))?;
///
/// assert_eq!(session.advance()?, ReadStep::Complete);
///
/// let report = session.finish()?;
/// assert!(!report.manifest_store_found);
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
pub struct ReadSession {
    settings: ReadSettings,
    core: SessionCore<ReadRequest>,
    state: State,

    /// The decoded form of [`ReadSettings::trust_anchors`], decoded once at
    /// the start of the workflow.
    anchors: Vec<Certificate>,

    /// The same for [`ReadSettings::timestamp_trust_anchors`].
    timestamp_anchors: Vec<Certificate>,

    /// How far trust was established for the *active* manifest, which is
    /// what [`ValidationState`] describes. `None` until the evaluation
    /// runs, which is also the answer when it never does.
    trust: Option<Trust>,

    /// Built up as the workflow proceeds; handed over by [`Session::finish`]
    /// once the session reaches a terminal state. Held directly rather
    /// than behind an `Option` so there is no "no report yet" state to
    /// defend against.
    report: ReadReport,
}

/// The read workflow's own phase, tracked separately from whether the
/// session as a whole has completed or failed — that half of the lifecycle
/// belongs to [`SessionCore`], via [`ReadSession::core`].
#[derive(Debug)]
enum State {
    Start,
    AwaitingManifestStore {
        request: RequestId,
    },
    AwaitingSigningTime {
        request: RequestId,
        chains: Vec<PendingChain>,
        binding: Option<PendingBinding>,
    },
    AwaitingAssetLength {
        request: RequestId,
        binding: PendingBinding,
    },
    HashingAsset {
        /// Boxed because a part-built hasher is far larger than any other
        /// variant, and a session spends most of its life not hashing.
        stream: Box<HashStream>,
        binding: PendingBinding,
    },

    /// Installed while a phase is being processed (see
    /// [`ReadSession::run`]), and left behind if that phase exits early —
    /// every `?` and every `return Err(…)` in [`ReadSession::run`] does,
    /// since none of them install a successor state. [`ReadSession::advance`]
    /// turns that into [`SessionCore::mark_failed`], so a later call finds
    /// this variant again and reports [`ProtocolError::SessionFailed`]
    /// without needing to distinguish "just poisoned" from "already
    /// reported".
    Poisoned,
}

/// Decodes one of the configured trust anchor lists.
///
/// A byte string that is not a certificate is refused rather than skipped:
/// silently dropping an anchor would quietly downgrade every manifest that
/// should have chained to it from [`ValidationState::Trusted`] to
/// [`ValidationState::Valid`], which is exactly the kind of wrong answer
/// nobody would think to look for.
fn decode_anchors(anchors: &[Vec<u8>], timestamp: bool) -> Result<Vec<Certificate>, Error> {
    anchors
        .iter()
        .enumerate()
        .map(|(index, der)| {
            cert::decode(der).map_err(|source| Error::MalformedTrustAnchor {
                index,
                timestamp,
                source,
            })
        })
        .collect()
}

/// Plans verification of a manifest's hard binding, if it has one this
/// crate can check.
///
/// Only the *active* manifest's binding is ever planned: an ingredient
/// manifest's hard binding covers the asset *it* described, which is not
/// the asset being read, so checking it here would compare unrelated
/// bytes.
fn plan_hard_binding(
    active: &Manifest,
    statuses: &mut Vec<ValidationStatus>,
) -> Option<PendingBinding> {
    // `None` covers both "no hard binding" and "present but malformed",
    // the latter already recorded while parsing.
    let data_hash = active.data_hash.as_ref()?;

    let url = format!("self#jumbf=c2pa.assertions/{}", data_hash::LABEL);
    let named = data_hash.alg.as_deref().or(active.claim.alg.as_deref());

    let algorithm = match named {
        // The specification's default when no algorithm is named.
        None => HashAlgorithm::Sha256,
        Some(name) => match HashAlgorithm::from_c2pa_name(name) {
            Some(algorithm) => algorithm,
            None => {
                statuses.push(ValidationStatus::for_url(
                    status_code::ALGORITHM_UNSUPPORTED,
                    &url,
                    format!("hash algorithm {name:?} is not supported"),
                ));
                return None;
            }
        },
    };

    Some(PendingBinding {
        algorithm,
        expected: data_hash.hash.clone(),
        exclusions: data_hash.exclusions.clone(),
        url,
    })
}

/// What this crate needs to remember while it verifies a hard binding.
#[derive(Debug)]
struct PendingBinding {
    algorithm: HashAlgorithm,
    expected: Vec<u8>,
    exclusions: Vec<ByteRange>,
    url: String,
}

impl ReadSession {
    /// The primary asset stream being read.
    pub const PRIMARY_STREAM: StreamId = StreamId::new(0);

    /// Creates a new read session for a single asset.
    ///
    /// The asset itself stays on the host side; the session refers to it as
    /// [`Self::PRIMARY_STREAM`].
    pub fn new(settings: ReadSettings) -> Self {
        Self {
            settings,
            core: SessionCore::default(),
            state: State::Start,
            anchors: vec![],
            timestamp_anchors: vec![],
            trust: None,
            report: ReadReport {
                manifest_store_found: false,
                manifests: vec![],
                active_manifest: None,
                validation_state: None,
                statuses: vec![],
            },
        }
    }

    /// The state-machine loop proper, factored out of [`Session::advance`]
    /// so that every error exit is poisoned in one place (there) rather
    /// than at each fallible call within the loop.
    fn run(&mut self) -> Result<Step, Error> {
        loop {
            // Checked before matching the phase: a phase that finishes the
            // workflow (see `finish_report`) marks the session complete
            // through `self.core` without installing a phase of its own to
            // match on, so completion has to be noticed here rather than
            // as a `State` variant.
            if self.core.is_complete() {
                return Ok(Step::Complete);
            }

            // Taking the state out lets each phase move what it owns (a
            // part-built hasher, say) into the next one. The value left
            // behind is `Poisoned`, so any exit that does not deliberately
            // install a successor state — every `?` and every `return
            // Err(…)` below — leaves it behind for the next call to find.
            //
            // Each handler reports `Ok(Some(step))` to return that step from
            // `run()`, or `Ok(None)` to let the loop go around again and
            // match on whatever successor state it installed.
            let outcome = match replace(&mut self.state, State::Poisoned) {
                State::Start => self.handle_start(),

                State::AwaitingManifestStore { request } => {
                    self.handle_awaiting_manifest_store(request)
                }

                State::AwaitingSigningTime {
                    request,
                    chains,
                    binding,
                } => self.handle_awaiting_signing_time(request, chains, binding),

                State::AwaitingAssetLength { request, binding } => {
                    self.handle_awaiting_asset_length(request, binding)
                }

                State::HashingAsset { stream, binding } => {
                    self.handle_hashing_asset(stream, binding)
                }

                // Left poisoned by an earlier error; `self.core` was marked
                // failed by `Session::advance` at the same time.
                State::Poisoned => return Err(ProtocolError::SessionFailed.into()),
            }?;

            if let Some(step) = outcome {
                return Ok(step);
            }
        }
    }

    /// Handles [`State::Start`]: decodes the configured trust anchors and
    /// asks the host for the manifest store.
    fn handle_start(&mut self) -> Result<Option<Step>, Error> {
        // Before the host is asked to do any work: a trust
        // anchor that is not a certificate is a configuration
        // mistake, and it should surface the same way every
        // time rather than only when a store happens to carry
        // a chain that would have consulted it.
        self.anchors = decode_anchors(&self.settings.trust_anchors, false)?;
        self.timestamp_anchors = decode_anchors(&self.settings.timestamp_trust_anchors, true)?;

        let request = self.core.issue(ReadRequest::ManifestStore {
            stream: Self::PRIMARY_STREAM,
        });
        self.state = State::AwaitingManifestStore { request };

        Ok(Some(Step::AwaitHost))
    }

    /// Handles [`State::AwaitingManifestStore`]: consumes the host's reply
    /// to the [`ReadRequest::ManifestStore`] request.
    fn handle_awaiting_manifest_store(
        &mut self,
        request: RequestId,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingManifestStore { request };
                return Ok(Some(Step::AwaitHost));
            }

            Some(ReadHostReply::ManifestStore(None)) => {
                // The report already reads as "nothing found".
                self.finish_report();
            }

            Some(ReadHostReply::ManifestStore(Some(bytes))) => {
                let parsed = manifest_store::parse(&bytes)?;
                let mut statuses = parsed.statuses;

                // Planned before the report is built, so the
                // plan is a pure function of what was parsed.
                let binding = parsed
                    .active_manifest
                    .as_deref()
                    .and_then(|label| parsed.manifests.iter().find(|m| m.label == label))
                    .and_then(|active| plan_hard_binding(active, &mut statuses));

                self.report = ReadReport {
                    manifest_store_found: true,
                    manifests: parsed.manifests,
                    active_manifest: parsed.active_manifest,
                    validation_state: None,
                    statuses,
                };

                if parsed.chains.is_empty() {
                    // Nothing to judge against a clock, so the
                    // host is never asked for one.
                    self.begin_binding(binding);
                } else {
                    let request = self.core.issue(ReadRequest::CurrentDateTime);
                    self.state = State::AwaitingSigningTime {
                        request,
                        chains: parsed.chains,
                        binding,
                    };
                }
            }

            Some(ReadHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            // `RequestTracker::fulfill` rejects mismatched
            // reply payloads, so this arm is unreachable in
            // practice.
            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "ManifestStore",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::AwaitingSigningTime`]: consumes the host's reply to
    /// the [`ReadRequest::CurrentDateTime`] request and evaluates trust for
    /// every pending certificate chain.
    fn handle_awaiting_signing_time(
        &mut self,
        request: RequestId,
        chains: Vec<PendingChain>,
        binding: Option<PendingBinding>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingSigningTime {
                    request,
                    chains,
                    binding,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(ReadHostReply::CurrentDateTime(now)) => {
                self.evaluate_trust(&chains, Some(now));
                self.begin_binding(binding);
            }

            // A host that cannot tell the time is not
            // necessarily stuck: a signature carrying a trusted
            // timestamp brings its own instant, and only the
            // ones that do not are left unevaluated.
            Some(ReadHostReply::Failed(_)) => {
                self.evaluate_trust(&chains, None);
                self.begin_binding(binding);
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "CurrentDateTime",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::AwaitingAssetLength`]: consumes the host's reply to
    /// the [`ReadRequest::AssetLength`] request and starts hashing, if the
    /// asset was available.
    fn handle_awaiting_asset_length(
        &mut self,
        request: RequestId,
        binding: PendingBinding,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingAssetLength { request, binding };
                return Ok(Some(Step::AwaitHost));
            }

            Some(ReadHostReply::AssetLength(asset_len)) => {
                self.begin_hashing(binding, asset_len);
            }

            // A host with no asset to offer — reading a
            // detached manifest, say — leaves the binding
            // unchecked rather than failed.
            Some(ReadHostReply::Failed(_)) => {
                self.record(ValidationStatus::for_url(
                    status_code::GENERAL_ERROR,
                    &binding.url,
                    "asset not available, so the hard binding was not checked",
                ));
                self.finish_report();
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "AssetLength",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::HashingAsset`]: streams asset bytes into the hard-
    /// binding hasher until it is done, then records the outcome.
    fn handle_hashing_asset(
        &mut self,
        mut stream: Box<HashStream>,
        binding: PendingBinding,
    ) -> Result<Option<Step>, Error> {
        stream.absorb(&mut self.core)?;

        if !stream.is_complete() {
            stream.issue(&mut self.core, Self::PRIMARY_STREAM);
            self.state = State::HashingAsset { stream, binding };
            return Ok(Some(Step::AwaitHost));
        }

        let actual = stream.finish()?;

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

        self.finish_report();

        Ok(None)
    }

    /// Validates each verified claim signature's certificate chain against
    /// the configured anchors.
    ///
    /// `now` is the fallback instant — the host's current time, in seconds
    /// since the Unix epoch (see [`ReadHostReply::CurrentDateTime`]). A signature
    /// carrying a timestamp from an authority that chains to a configured
    /// timestamp anchor is judged against *that* instant instead, which is
    /// the whole point of carrying one: it is what lets a manifest signed
    /// years ago with a since-expired certificate still read as valid.
    fn evaluate_trust(&mut self, chains: &[PendingChain], now: Option<i64>) {
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

            // Only a trusted authority's word on the time is taken. An
            // untrusted or broken token leaves the fallback in place: the
            // finding is recorded either way, so a report says which
            // instant its verdict rests on.
            let instant = match stamped {
                Some(timestamp::Timestamped::Trusted(gen_time)) => Some(gen_time),
                _ => now,
            };

            let Some(instant) = instant else {
                // No timestamp worth using and no clock either, so nothing
                // can be said about validity windows.
                //
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
            // validation state. An ingredient's chain is still validated —
            // a broken one is a failure wherever it sits — but an
            // ingredient signed by an untrusted party does not make the
            // active manifest's own signer any less trusted.
            if self.report.active_manifest.as_deref() == Some(pending.manifest_label.as_str()) {
                self.trust = Some(trust);
            }
        }
    }

    /// Moves on to the hard binding, or finishes if there is none to check.
    fn begin_binding(&mut self, binding: Option<PendingBinding>) {
        match binding {
            Some(binding) => {
                let request = self.core.issue(ReadRequest::AssetLength {
                    stream: Self::PRIMARY_STREAM,
                });
                self.state = State::AwaitingAssetLength { request, binding };
            }
            None => self.finish_report(),
        }
    }

    /// Turns the binding's exclusions into the ranges to hash and starts
    /// streaming them.
    fn begin_hashing(&mut self, binding: PendingBinding, asset_len: u64) {
        let Some(ranges) = hash_stream::included_ranges(&binding.exclusions, asset_len) else {
            self.record(ValidationStatus::for_url(
                status_code::ASSERTION_DATAHASH_MALFORMED,
                &binding.url,
                "hard binding exclusions do not describe this asset",
            ));
            self.finish_report();
            return;
        };

        let mut stream = Box::new(HashStream::new(binding.algorithm, &ranges));
        stream.issue(&mut self.core, Self::PRIMARY_STREAM);

        self.state = State::HashingAsset { stream, binding };
    }

    /// Appends a validation status to the in-progress report.
    fn record(&mut self, status: ValidationStatus) {
        self.report.statuses.push(status);
    }

    /// Computes the overall outcome and marks the session complete.
    fn finish_report(&mut self) {
        self.report.validation_state = if self.report.manifests.is_empty() {
            // Nothing was validated, so no outcome can be reported.
            None
        } else if self
            .report
            .statuses
            .iter()
            .any(ValidationStatus::is_failure)
        {
            Some(ValidationState::Invalid)
        } else if self
            .report
            .statuses
            .iter()
            .any(ValidationStatus::is_unchecked)
        {
            // Something that bears on the verdict was never established —
            // an asset that could not be hashed, an algorithm this crate
            // cannot compute. Everything that ran passed, which is a
            // weaker statement than `Valid` makes.
            Some(ValidationState::Incomplete)
        } else {
            match self.trust {
                // Every check passed and the active manifest's signer
                // chains to an anchor the host configured.
                Some(Trust::Anchored) => Some(ValidationState::Trusted),

                // Cryptographically sound, but nothing ties the signer to
                // anyone the host recognizes.
                Some(Trust::Unanchored) => Some(ValidationState::Valid),

                // Neither arm is reachable today, and both are here so
                // that the safe answer is the default if that changes.
                // `Rejected` always records a failure, so the first
                // branch catches it; `None` means the evaluation never
                // ran, and every way that happens — a signature that is
                // missing, unreadable or wrong, or a host with no clock —
                // records a status that is a failure or an unchecked, so
                // one of the branches above catches that too.
                Some(Trust::Rejected) | None => Some(ValidationState::Incomplete),
            }
        };

        self.core.mark_complete();
    }
}

impl Session for ReadSession {
    type Error = Error;
    type Output = ReadReport;
    type Request = ReadRequest;

    /// Performs as much synchronous work as possible.
    ///
    /// Returns [`ReadStep::AwaitHost`] if the session is blocked on host
    /// requests, or [`ReadStep::Complete`] once the workflow has finished
    /// (idempotently, on subsequent calls as well).
    ///
    /// If this returns an error, the session is spent: it cannot be advanced
    /// or fulfilled again, and [`Session::finish`] will refuse to hand over
    /// the half-built report. Every later call reports
    /// [`ProtocolError::SessionFailed`].
    fn advance(&mut self) -> Result<Step, Error> {
        if self.core.is_complete() {
            return Ok(Step::Complete);
        }

        match self.run() {
            Ok(step) => Ok(step),
            Err(err) => {
                self.core.mark_failed();
                Err(err)
            }
        }
    }

    /// Returns the requests the host has not yet fulfilled.
    fn outstanding_requests(&self) -> &[HostRequest<ReadRequest>] {
        self.core.outstanding_requests()
    }

    /// Reports the outcome of one outstanding request.
    ///
    /// Outcomes may be reported in any order and at any pace; call
    /// [`Session::advance`] afterward to let the session consume them.
    fn fulfill(&mut self, id: RequestId, reply: ReadHostReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    /// Consumes the session and returns the completed report.
    ///
    /// Fails with [`ProtocolError::SessionNotComplete`] if the workflow has
    /// not reached [`ReadStep::Complete`], or with
    /// [`ProtocolError::SessionFailed`] if [`Session::advance`] returned an
    /// error: a report that stopped partway through validation would
    /// understate what was checked, so it is never handed out.
    fn finish(self) -> Result<ReadReport, Error> {
        self.core.finish_check()?;
        Ok(self.report)
    }
}

/// The result of a completed read workflow.
///
/// Experimental: this will grow into the full equivalent of the c2pa-rs
/// `Reader` surface — the ingredient tree, resolved resources, and detailed
/// validation results.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReadReport {
    /// True if the asset contained (or referenced) a C2PA manifest store.
    pub manifest_store_found: bool,

    /// Manifests read from the store, in store order.
    pub manifests: Vec<Manifest>,

    /// Label of the active manifest — the last one in the store — if the
    /// store contained any.
    pub active_manifest: Option<String>,

    /// Overall validation outcome; `None` if there was nothing to validate,
    /// or (in this crate, today) if validation has not run.
    pub validation_state: Option<ValidationState>,

    /// Individual validation status codes recorded during the workflow, in
    /// the vocabulary of the C2PA specification (compare
    /// `validation_status` in c2pa-rs).
    pub statuses: Vec<ValidationStatus>,
}

impl ReadReport {
    /// Returns the active manifest, if the store contained one.
    pub fn active(&self) -> Option<&Manifest> {
        let label = self.active_manifest.as_deref()?;
        self.manifests.iter().find(|m| m.label == label)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{error::HostError, test_support};

    /// 2027-01-15T08:00:00Z — inside the validity window of every
    /// certificate fixture in this repository.
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn no_manifest_store_completes_with_report() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let requests = session.outstanding_requests();
        assert_eq!(requests.len(), 1);
        assert!(matches!(
            requests[0].kind,
            ReadRequest::ManifestStore {
                stream: ReadSession::PRIMARY_STREAM
            }
        ));

        let id = requests[0].id;
        session
            .fulfill(id, ReadHostReply::ManifestStore(None))
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::Complete);

        // Advancing a complete session is idempotent.
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);

        let report = session.finish().unwrap();
        assert!(!report.manifest_store_found);
        assert!(report.validation_state.is_none());
        assert!(report.statuses.is_empty());
    }

    #[test]
    fn advance_is_idempotent_while_waiting() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        assert_eq!(session.outstanding_requests().len(), 1);
    }

    #[test]
    fn mismatched_stored_reply_is_defensively_rejected() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        // Bypass `fulfill`'s payload validation to exercise the state
        // machine's own defense-in-depth check.
        let id = session.outstanding_requests()[0].id;
        session
            .core
            .fulfill_unchecked(id, ReadHostReply::AssetLength(0));

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "ManifestStore",
                ..
            }))
        ));
    }

    /// Drives a session to completion against the given manifest store
    /// bytes, with no asset and no configured trust anchors.
    fn read_store(bytes: Vec<u8>) -> Result<ReadReport, Error> {
        read_store_anchored(bytes, vec![])
    }

    /// Drives a session over a manifest store, with the given trust anchors
    /// configured. The stores these tests build carry no hard binding, so
    /// the asset is never asked for.
    fn read_store_anchored(bytes: Vec<u8>, anchors: Vec<Vec<u8>>) -> Result<ReadReport, Error> {
        let mut session = ReadSession::new(ReadSettings {
            trust_anchors: anchors,
            ..ReadSettings::default()
        });

        loop {
            if session.advance()? == ReadStep::Complete {
                return session.finish();
            }

            let asks: Vec<(RequestId, bool)> = session
                .outstanding_requests()
                .iter()
                .map(|request| match &request.kind {
                    ReadRequest::ManifestStore { .. } => (request.id, true),
                    ReadRequest::CurrentDateTime => (request.id, false),
                    other => panic!("unexpected request {other:?}"),
                })
                .collect();

            for (id, is_store) in asks {
                let reply = if is_store {
                    ReadHostReply::ManifestStore(Some(bytes.clone()))
                } else {
                    ReadHostReply::CurrentDateTime(NOW)
                };
                session.fulfill(id, reply)?;
            }
        }
    }

    #[test]
    fn reads_a_manifest_store_through_the_state_machine() {
        let report = read_store(test_support::manifest_store(&[
            test_support::manifest("urn:uuid:older", "older.jpg", &["c2pa.actions"]),
            test_support::manifest(
                "urn:uuid:active",
                "active.jpg",
                &["c2pa.actions", "stds.schema-org.CreativeWork"],
            ),
        ]))
        .unwrap();

        assert!(report.manifest_store_found);
        assert_eq!(report.manifests.len(), 2);
        assert_eq!(report.active_manifest.as_deref(), Some("urn:uuid:active"));

        let active = report.active().unwrap();
        assert_eq!(active.label, "urn:uuid:active");
        assert_eq!(active.claim.title.as_deref(), Some("active.jpg"));
        assert_eq!(
            active.assertion_labels,
            ["c2pa.actions", "stds.schema-org.CreativeWork"]
        );
        assert!(active.has_signature);

        // Every check passed, and the synthetic signer's chain was built
        // and found sound — but nothing was configured to trust it, so the
        // outcome stops at `Valid`.
        assert_eq!(report.validation_state, Some(ValidationState::Valid));

        // Three assertion references across the two manifests, plus a
        // verified signature, a validity finding and a trust finding each.
        assert_eq!(report.statuses.len(), 9, "{report:#?}");

        let count = |code: &str| {
            report
                .statuses
                .iter()
                .filter(|status| status.code == code)
                .count()
        };

        assert_eq!(count(status_code::ASSERTION_HASHEDURI_MATCH), 3);
        assert_eq!(count(status_code::CLAIM_SIGNATURE_VALIDATED), 2);
        assert_eq!(count(status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY), 2);
        assert_eq!(count(status_code::SIGNING_CREDENTIAL_UNTRUSTED), 2);
    }

    #[test]
    fn configuring_the_signer_as_an_anchor_reaches_trusted() {
        let store = test_support::manifest_store(&[test_support::manifest(
            "urn:uuid:one",
            "one.jpg",
            &["c2pa.actions"],
        )]);

        // The synthetic signer is self-signed, so trusting it means listing
        // the certificate itself — the "explicitly trusted end-entity
        // certificate" case.
        let report =
            read_store_anchored(store.clone(), vec![test_support::TEST_SIGNER_CERT.to_vec()])
                .unwrap();

        assert_eq!(report.validation_state, Some(ValidationState::Trusted));
        assert!(report
            .statuses
            .iter()
            .any(|status| status.code == status_code::SIGNING_CREDENTIAL_TRUSTED));

        // The same store with an unrelated anchor stays merely valid, so
        // the previous assertion is about *this* anchor rather than about
        // anchors being configured at all.
        let report =
            read_store_anchored(store, vec![test_support::FIXTURE_ISSUER_CERT.to_vec()]).unwrap();

        assert_eq!(report.validation_state, Some(ValidationState::Valid));
    }

    #[test]
    fn a_trust_anchor_that_is_not_a_certificate_is_refused_up_front() {
        let mut session = ReadSession::new(ReadSettings {
            trust_anchors: vec![
                test_support::TEST_SIGNER_CERT.to_vec(),
                b"not a certificate".to_vec(),
            ],
            ..ReadSettings::default()
        });

        // Refused before the host is asked for anything at all, so a
        // misconfigured verifier never gets as far as producing a report
        // that quietly ignored one of its anchors.
        assert!(matches!(
            session.advance(),
            Err(Error::MalformedTrustAnchor { index: 1, .. })
        ));
        assert!(session.outstanding_requests().is_empty());
        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
    }

    #[test]
    fn a_host_with_no_clock_leaves_trust_unevaluated() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(test_support::manifest_store(&[
                    test_support::manifest("urn:uuid:one", "one.jpg", &[]),
                ]))),
            )
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;
        assert!(matches!(
            session.outstanding_requests()[0].kind,
            ReadRequest::CurrentDateTime
        ));
        session
            .fulfill(id, ReadHostReply::Failed(HostError::new("no clock here")))
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::Complete);
        let report = session.finish().unwrap();

        // The signature still verified; what could not be established is
        // trust. Not knowing is not the same as knowing it is wrong.
        assert!(report
            .statuses
            .iter()
            .any(|status| status.code == status_code::CLAIM_SIGNATURE_VALIDATED));
        assert_eq!(
            report.statuses.last().map(|status| status.code.as_str()),
            Some(status_code::GENERAL_ERROR)
        );
        assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
    }

    #[test]
    fn a_mismatched_signing_time_reply_is_defensively_rejected() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(test_support::manifest_store(&[
                    test_support::manifest("urn:uuid:one", "one.jpg", &[]),
                ]))),
            )
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        // Bypass `fulfill`'s payload validation to reach the session's own
        // defence-in-depth check.
        let id = session.outstanding_requests()[0].id;
        session
            .core
            .fulfill_unchecked(id, ReadHostReply::AssetLength(0));

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "CurrentDateTime",
                ..
            }))
        ));
    }

    #[test]
    fn a_manifest_whose_signature_does_not_verify_skips_the_trust_evaluation() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(test_support::manifest_store(&[
                    test_support::manifest_with_broken_signature(
                        "urn:uuid:broken",
                        &[],
                        test_support::claim_box("broken.jpg"),
                    ),
                ]))),
            )
            .unwrap();

        // No chain to evaluate, so the clock is never asked for: judging
        // whose key signed a claim is moot once the signature says it was
        // not that key.
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);

        let report = session.finish().unwrap();
        assert_eq!(
            report
                .statuses
                .iter()
                .map(|s| s.code.as_str())
                .collect::<Vec<_>>(),
            [status_code::CLAIM_SIGNATURE_MISMATCH]
        );
        assert_eq!(report.validation_state, Some(ValidationState::Invalid));
    }

    /// Drives a session with a synthetic asset, the way a host would.
    ///
    /// A host with no asset to offer is exercised against the real fixture
    /// in `tests/read_fixture.rs` instead, where the store's binding is one
    /// c2pa-rs wrote rather than one these tests built.
    fn read_with_asset(store: Vec<u8>, asset: Vec<u8>) -> Result<ReadReport, Error> {
        let mut session = ReadSession::new(ReadSettings::default());

        loop {
            if session.advance()? == ReadStep::Complete {
                return session.finish();
            }

            let requests: Vec<HostRequest<ReadRequest>> = session.outstanding_requests().to_vec();

            for request in requests {
                match request.kind {
                    ReadRequest::ManifestStore { .. } => session.fulfill(
                        request.id,
                        ReadHostReply::ManifestStore(Some(store.clone())),
                    )?,

                    ReadRequest::CurrentDateTime => {
                        session.fulfill(request.id, ReadHostReply::CurrentDateTime(NOW))?
                    }

                    ReadRequest::AssetLength { .. } => session
                        .fulfill(request.id, ReadHostReply::AssetLength(asset.len() as u64))?,

                    ReadRequest::AssetBytes { range, .. } => {
                        let start = range.start as usize;
                        let bytes = asset[start..start + range.len as usize].to_vec();
                        session.fulfill(request.id, ReadHostReply::AssetBytes(bytes))?
                    }
                }
            }
        }
    }

    /// Builds a store whose active manifest binds to `asset` with the given
    /// exclusions, using `hash` as the recorded digest.
    fn store_bound_to(exclusions: &[(u64, u64)], hash: Vec<u8>) -> Vec<u8> {
        let binding = test_support::data_hash_box(exclusions, hash);
        let refs = vec![test_support::hashed_uri("c2pa.hash.data", &binding)];

        test_support::manifest_store(&[test_support::manifest_with_claim(
            "urn:uuid:bound",
            &[binding],
            test_support::claim_box_with_assertions("bound.jpg", refs),
        )])
    }

    /// The digest of `asset` outside the given exclusions.
    fn expected_digest(asset: &[u8], exclusions: &[(u64, u64)]) -> Vec<u8> {
        let mut covered = Vec::new();
        let mut cursor = 0usize;

        for (start, len) in exclusions {
            covered.extend_from_slice(&asset[cursor..*start as usize]);
            cursor = (*start + *len) as usize;
        }
        covered.extend_from_slice(&asset[cursor..]);

        HashAlgorithm::Sha256.digest(&covered)
    }

    #[test]
    fn a_matching_hard_binding_is_reported_as_a_match() {
        // An asset large enough to span several streamed chunks.
        let asset: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let exclusions = [(1000u64, 5000u64)];

        let report = read_with_asset(
            store_bound_to(&exclusions, expected_digest(&asset, &exclusions)),
            asset,
        )
        .unwrap();

        assert_eq!(
            report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::ASSERTION_DATAHASH_MATCH)
        );

        // Every check passed, including the signer's chain — which reaches
        // no configured anchor, so the verdict stops short of `Trusted`.
        assert_eq!(report.validation_state, Some(ValidationState::Valid));
    }

    #[test]
    fn a_wrong_hard_binding_invalidates_the_store() {
        let asset: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

        let report = read_with_asset(store_bound_to(&[], vec![0u8; 32]), asset).unwrap();

        assert_eq!(
            report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::ASSERTION_DATAHASH_MISMATCH)
        );
        assert_eq!(report.validation_state, Some(ValidationState::Invalid));
    }

    #[test]
    fn exclusions_that_do_not_fit_the_asset_are_malformed() {
        let asset = vec![7u8; 100];

        // The exclusion reaches past the end of the asset.
        let report = read_with_asset(store_bound_to(&[(50, 500)], vec![0u8; 32]), asset).unwrap();

        assert_eq!(
            report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::ASSERTION_DATAHASH_MALFORMED)
        );
        assert_eq!(report.validation_state, Some(ValidationState::Invalid));
    }

    /// Builds a store bound to an asset, with an explicit algorithm on the
    /// binding and on the claim.
    fn store_bound_with_algs(
        binding_alg: Option<&str>,
        claim_alg: Option<&str>,
        hash: Vec<u8>,
    ) -> Vec<u8> {
        let binding = test_support::data_hash_box_with_alg(&[], hash, binding_alg);
        let refs = vec![test_support::hashed_uri("c2pa.hash.data", &binding)];

        test_support::manifest_store(&[test_support::manifest_with_claim(
            "urn:uuid:bound",
            &[binding],
            test_support::claim_box_with_alg("bound.jpg", claim_alg, refs),
        )])
    }

    #[test]
    fn a_binding_naming_no_algorithm_defaults_to_sha256() {
        let asset = vec![9u8; 5000];
        let expected = HashAlgorithm::Sha256.digest(&asset);

        // Neither the binding nor the claim names an algorithm.
        let report = read_with_asset(store_bound_with_algs(None, None, expected), asset).unwrap();

        assert_eq!(
            report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::ASSERTION_DATAHASH_MATCH)
        );
    }

    #[test]
    fn a_binding_algorithm_overrides_the_claims() {
        let asset = vec![3u8; 5000];
        let expected = HashAlgorithm::Sha512.digest(&asset);

        // The claim says sha256; the binding says sha512 and wins.
        let report = read_with_asset(
            store_bound_with_algs(Some("sha512"), Some("sha256"), expected),
            asset,
        )
        .unwrap();

        assert_eq!(
            report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::ASSERTION_DATAHASH_MATCH)
        );
    }

    #[test]
    fn an_unsupported_binding_algorithm_leaves_it_unchecked() {
        let asset = vec![1u8; 100];

        let report = read_with_asset(
            store_bound_with_algs(Some("sha1"), None, vec![0u8; 20]),
            asset,
        )
        .unwrap();

        assert!(
            report
                .statuses
                .iter()
                .any(|s| s.code == status_code::ALGORITHM_UNSUPPORTED),
            "{report:#?}"
        );

        // Unchecked, not failed — and since the binding was never checked,
        // the asset was never asked for either, and the verdict cannot
        // reach `Valid` however well everything else went.
        assert!(report
            .statuses
            .iter()
            .all(|s| s.code != status_code::ASSERTION_DATAHASH_MATCH));
        assert_eq!(report.validation_state, Some(ValidationState::Incomplete));
    }

    #[test]
    fn a_mismatched_asset_length_reply_is_defensively_rejected() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(store_bound_with_algs(
                    None,
                    None,
                    vec![0u8; 32],
                ))),
            )
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::CurrentDateTime(NOW))
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        // Bypass `fulfill`'s payload validation to reach the session's own
        // defence-in-depth check.
        let id = session.outstanding_requests()[0].id;
        session
            .core
            .fulfill_unchecked(id, ReadHostReply::CurrentDateTime(0));

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "AssetLength",
                ..
            }))
        ));
    }

    #[test]
    fn a_manifest_without_a_hard_binding_never_asks_for_the_asset() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(test_support::manifest_store(&[
                    test_support::manifest("urn:uuid:none", "none.jpg", &["c2pa.actions"]),
                ]))),
            )
            .unwrap();

        // The signature's chain still wants a time; the asset does not get
        // asked for.
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;
        assert!(matches!(
            session.outstanding_requests()[0].kind,
            ReadRequest::CurrentDateTime
        ));
        session
            .fulfill(id, ReadHostReply::CurrentDateTime(NOW))
            .unwrap();

        // No asset request is issued, so a host holding only a manifest
        // store is never asked for bytes it does not have.
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);
        assert!(session.outstanding_requests().is_empty());
    }

    #[test]
    fn active_returns_none_without_a_store() {
        let report = read_store(test_support::manifest_store(&[])).unwrap();
        assert!(report.manifest_store_found);
        assert!(report.manifests.is_empty());
        assert!(report.active().is_none());
    }

    #[test]
    fn malformed_manifest_store_fails_the_session() {
        assert!(matches!(
            read_store(vec![0u8; 4]),
            Err(Error::MalformedManifestStore(_))
        ));
    }

    #[test]
    fn host_failure_terminates_session() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::Failed(HostError::new("disk on fire")))
            .unwrap();

        match session.advance() {
            Err(Error::HostFailure { id: failed_id, .. }) => assert_eq!(failed_id, id),
            other => panic!("expected HostFailure, got {other:?}"),
        }

        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
    }

    #[test]
    fn a_failed_session_stays_failed() {
        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::ManifestStore(Some(vec![0u8; 4])))
            .unwrap();

        assert!(matches!(
            session.advance(),
            Err(Error::MalformedManifestStore(_))
        ));

        // The failure is remembered rather than forgotten: the session can
        // be neither advanced nor fulfilled, and it never claims to be
        // complete.
        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
        assert!(matches!(
            session.fulfill(id, ReadHostReply::ManifestStore(None)),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
    }

    #[test]
    fn a_failure_while_hashing_withholds_the_partial_report() {
        let asset = vec![4u8; 200_000];

        let mut session = ReadSession::new(ReadSettings::default());
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(
                id,
                ReadHostReply::ManifestStore(Some(store_bound_to(&[], vec![0u8; 32]))),
            )
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::CurrentDateTime(NOW))
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::AssetLength(asset.len() as u64))
            .unwrap();

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        // A chunk the host returns short can never be folded in.
        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::AssetBytes(vec![4u8; 10]))
            .unwrap();

        assert!(matches!(
            session.advance(),
            Err(Error::AssetBytesLengthMismatch { .. })
        ));

        // By this point the store had been parsed and the report partly
        // built. Handing that over would report a manifest whose hard
        // binding was silently never checked.
        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionFailed))
        ));
    }

    #[test]
    fn fulfill_rejects_unknown_request_id() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::ManifestStore(None))
            .unwrap();

        // The request has already been answered and removed from what is
        // outstanding — fulfilling it again (before `advance` has
        // consumed the reply) finds nothing left to answer.
        assert!(matches!(
            session.fulfill(id, ReadHostReply::ManifestStore(None)),
            Err(Error::Protocol(ProtocolError::UnknownRequest(unknown))) if unknown == id
        ));
    }

    #[test]
    fn fulfill_rejects_mismatched_reply_payload() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        assert!(matches!(
            session.fulfill(id, ReadHostReply::AssetLength(0)),
            Err(Error::Protocol(ProtocolError::ReplyMismatch { expected, .. })) if expected == "ManifestStore"
        ));

        // The request is still outstanding and can be fulfilled correctly.
        assert_eq!(session.outstanding_requests().len(), 1);
        session
            .fulfill(id, ReadHostReply::ManifestStore(None))
            .unwrap();
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);
    }

    #[test]
    fn fulfill_rejects_completed_session() {
        let mut session = ReadSession::new(ReadSettings::default());

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);

        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, ReadHostReply::ManifestStore(None))
            .unwrap();
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);

        assert!(matches!(
            session.fulfill(id, ReadHostReply::ManifestStore(None)),
            Err(Error::Protocol(ProtocolError::SessionComplete))
        ));
    }

    #[test]
    fn finish_rejects_incomplete_session() {
        let session = ReadSession::new(ReadSettings::default());
        assert!(matches!(
            session.finish(),
            Err(Error::Protocol(ProtocolError::SessionNotComplete))
        ));
    }
}
