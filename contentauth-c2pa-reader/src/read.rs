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
    ocsp,
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
#[derive(Clone, Debug)]
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

    /// Whether the session *desires to verify* a certificate's revocation
    /// status by querying an OCSP responder online (C2PA spec §15.9.2),
    /// when nothing already in the C2PA Manifest Store settled the
    /// question. `true` by default.
    ///
    /// This governs only the *online* query — evaluating a response
    /// already stapled into the claim signature's `rVals` header (§15.9.1)
    /// always happens regardless of this setting, since it costs no
    /// network round trip. The specification makes the online query itself
    /// opt-out on purpose: querying a responder can reveal the asset's
    /// identity to an observer (§15.9.2's own note), which is a cost only
    /// the caller can decide is worth paying. Setting this to `false`
    /// records [`status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED`] for the
    /// signer's own certificate rather than issuing [`ReadRequest::Ocsp`].
    ///
    /// A host with no network access, or that cannot reach the responder,
    /// answers [`ReadRequest::Ocsp`] with [`ReadHostReply::Failed`],
    /// recorded as [`status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE`]
    /// rather than held against the manifest — offline verification stays
    /// possible. A response the host *does* return, though, is judged by
    /// the C2PA specification's own, less forgiving rule: an authenticated
    /// response that does not affirmatively vouch for the certificate
    /// reads as [`status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`] rather
    /// than merely inconclusive. A revoked *CA* certificate above the
    /// signer is reported differently — see
    /// [`status_code::SIGNING_CREDENTIAL_UNTRUSTED`] — and is looked up the
    /// same way (a stapled response, else its own AIA responder when this
    /// is `true`), though a CA's responder being skipped, unreachable or
    /// unconvincing records nothing, since §15.9 defines no status for it.
    ///
    /// The timestamping authority's own chain is never OCSP-checked: a
    /// stale timestamp authority credential is a much smaller concern than
    /// a stale signing credential, and RFC 3161 authorities rotate their
    /// certificates on their own schedule this crate has no stake in.
    pub check_ocsp: bool,
}

impl Default for ReadSettings {
    fn default() -> Self {
        Self {
            fetch_remote_manifests: false,
            trust_anchors: vec![],
            timestamp_trust_anchors: vec![],
            check_ocsp: true,
        }
    }
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
    AwaitingOcspResponses {
        pending: Vec<PendingChainOcsp>,
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

/// One claim signer chain's outstanding OCSP checks, and enough about the
/// chain's own outcome and timing to act on whatever they establish.
///
/// A chain only reaches this state once [`chain::validate`] has already
/// run and recorded its own findings; nothing here repeats or overrides
/// them except [`Self::is_active`]'s chain being downgraded on a validly
/// signed `revoked` answer for its own signer.
#[derive(Debug)]
struct PendingChainOcsp {
    /// The chain's claim signature URL, so a finding is attributed the
    /// same way every other finding about this chain is.
    url: String,

    /// Whether this is the *active* manifest's own chain — the one whose
    /// [`Trust`] feeds [`ReadReport::validation_state`]. An ingredient's
    /// chain is still checked (a revoked ingredient signer is still worth
    /// reporting), but revoking it does not, by itself, invalidate the
    /// asset being read.
    is_active: bool,

    /// The host's current time, if it supplied one — C2PA spec §15.9.2's
    /// fallback instant for an online check when there is no trusted
    /// timestamp, and the freshness gate §15.9.1 applies to a stapled
    /// response regardless of a timestamp.
    now: Option<i64>,

    /// The claim signature's attested signing instant, from a trusted RFC
    /// 3161 timestamp — the *only* instant §15.9.1 will judge a stapled
    /// response against, and §15.9.2's preferred one for an online check.
    attested: Option<i64>,

    /// Checks not yet answered by an online query, each paired with the
    /// host request it was issued under and whether it asks about the
    /// claim signer's own certificate (`true`) or a CA above it (`false`)
    /// — see [`ReadSession::handle_awaiting_ocsp_responses`].
    checks: Vec<(RequestId, crate::ocsp::PendingOcspCheck, bool)>,
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

                State::AwaitingOcspResponses { pending, binding } => {
                    self.handle_awaiting_ocsp_responses(pending, binding)
                }

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
                let pending_ocsp = self.evaluate_trust(&chains, Some(now));
                self.proceed_after_trust(pending_ocsp, binding);
            }

            // A host that cannot tell the time is not
            // necessarily stuck: a signature carrying a trusted
            // timestamp brings its own instant, and only the
            // ones that do not are left unevaluated.
            Some(ReadHostReply::Failed(_)) => {
                let pending_ocsp = self.evaluate_trust(&chains, None);
                self.proceed_after_trust(pending_ocsp, binding);
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
    /// the configured anchors, and works through C2PA spec §15.9's
    /// revocation process for every certificate in it that names an OCSP
    /// responder.
    ///
    /// `now` is the host's current time, in seconds since the Unix epoch
    /// (see [`ReadHostReply::CurrentDateTime`]) — the fallback instant for
    /// validity-window checks, and (per §15.9.2) for an online OCSP check
    /// when the claim signature carries no trusted timestamp. A signature
    /// carrying a timestamp from an authority that chains to a configured
    /// timestamp anchor is judged against *that* attested instant instead
    /// wherever one is available, which is the whole point of carrying
    /// one: it is what lets a manifest signed years ago with a
    /// since-expired certificate still read as valid.
    ///
    /// Every certificate's stapled `rVals` responses (see
    /// [`PendingChain::rvals`]) are tried first, synchronously, since they
    /// cost no host round trip; only a signer's certificate whose staples
    /// left nothing established, and only when
    /// [`ReadSettings::check_ocsp`] says to, goes on to an online query.
    /// Returns the chains that still have such a query outstanding.
    fn evaluate_trust(
        &mut self,
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

            // Only a trusted authority's word on the time is taken. An
            // untrusted or broken token leaves the fallback in place: the
            // finding is recorded either way, so a report says which
            // instant its verdict rests on. `attested` is kept apart from
            // the merged `instant` below because C2PA spec §15.9.1/§15.9.2
            // care about the two separately — the current time on its own
            // never stands in for a signing time no timestamp attested to.
            let attested = match stamped {
                Some(timestamp::Timestamped::Trusted(gen_time)) => Some(gen_time),
                _ => None,
            };
            let instant = attested.or(now);

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
            let is_active =
                self.report.active_manifest.as_deref() == Some(pending.manifest_label.as_str());
            if is_active {
                self.trust = Some(trust);
            }

            // A chain the checks above already rejected is not worth
            // asking about: nothing an OCSP response could say would make
            // a structurally broken path any less broken.
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
                        // confirmed not revoked — only the signer's own.
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

                    // Inconclusive, or no rVals to try in the first
                    // place: nothing was established in the store, so
                    // §15.9 falls through to an online check — but only
                    // for the signer's own certificate. (`find_map` above
                    // never actually produces `Some(Inconclusive)` — it
                    // maps that case to `None` itself — but the type
                    // system does not know that, so both are handled the
                    // same way here rather than declared unreachable.)
                    None | Some(ocsp::StapledOutcome::Inconclusive) if is_signer => {
                        match (&check.responder_url, self.settings.check_ocsp) {
                            (Some(responder_url), true) => {
                                let request = self.core.issue(ReadRequest::Ocsp {
                                    url: responder_url.clone(),
                                    request_der: check.request_der.clone(),
                                });
                                online_checks.push((request, check, true));
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
                    // §15.9 says a validator "should" look its status up
                    // through its own AIA extension, so ask online when
                    // allowed to. Whatever the CA's responder says,
                    // nothing is recorded unless the CA turns out to be
                    // revoked: §15.9 defines no skipped, inaccessible or
                    // not-revoked status for a CA.
                    None | Some(ocsp::StapledOutcome::Inconclusive) => {
                        if let (Some(responder_url), true) =
                            (&check.responder_url, self.settings.check_ocsp)
                        {
                            let request = self.core.issue(ReadRequest::Ocsp {
                                url: responder_url.clone(),
                                request_der: check.request_der.clone(),
                            });
                            online_checks.push((request, check, false));
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

    /// Moves on from trust evaluation: straight to the hard binding if no
    /// OCSP checks are outstanding, or [`State::AwaitingOcspResponses`]
    /// otherwise.
    fn proceed_after_trust(
        &mut self,
        pending: Vec<PendingChainOcsp>,
        binding: Option<PendingBinding>,
    ) {
        if pending.is_empty() {
            self.begin_binding(binding);
        } else {
            self.state = State::AwaitingOcspResponses { pending, binding };
        }
    }

    /// Handles [`State::AwaitingOcspResponses`]: consumes whatever OCSP
    /// replies have arrived, records the C2PA spec §15.9.2 status they
    /// establish, and moves on once every chain's checks are accounted
    /// for — answered or not.
    ///
    /// A queued check is for the claim signer's own certificate or, per
    /// §15.9's "should", for a CA above it; only the signer's gets the
    /// full §15.9.2 treatment, a CA's being reported only if it is revoked
    /// (see [`ocsp::evaluate_ca_online`]).
    fn handle_awaiting_ocsp_responses(
        &mut self,
        mut pending: Vec<PendingChainOcsp>,
        binding: Option<PendingBinding>,
    ) -> Result<Option<Step>, Error> {
        for chain_pending in &mut pending {
            let mut still_outstanding = Vec::with_capacity(chain_pending.checks.len());

            for (request, check, is_signer) in chain_pending.checks.drain(..) {
                match self.core.take_reply(request) {
                    None => still_outstanding.push((request, check, is_signer)),

                    Some(ReadHostReply::Ocsp(response_der)) if !is_signer => {
                        if ocsp::evaluate_ca_online(
                            &check,
                            &response_der,
                            chain_pending.now,
                            chain_pending.attested,
                        ) {
                            self.apply_revocation(
                                false,
                                chain_pending.is_active,
                                &chain_pending.url,
                                "an OCSP response says a certificate in this credential's chain was revoked",
                            );
                        }
                    }

                    // A CA's responder that cannot be reached is no
                    // finding at all — see `evaluate_trust`.
                    Some(ReadHostReply::Failed(_)) if !is_signer => {}

                    Some(ReadHostReply::Ocsp(response_der)) => {
                        let outcome = ocsp::evaluate_online(
                            &check,
                            &response_der,
                            chain_pending.now,
                            chain_pending.attested,
                        );
                        self.apply_online_outcome(
                            outcome,
                            &chain_pending.url,
                            chain_pending.is_active,
                        );
                    }

                    // "Unable to receive a response" (C2PA spec §15.9.2).
                    Some(ReadHostReply::Failed(_)) => {
                        self.record(ValidationStatus::for_url(
                            status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
                            &chain_pending.url,
                            "the OCSP responder could not be reached",
                        ));
                    }

                    Some(_) => {
                        return Err(ProtocolError::ReplyMismatch {
                            id: request,
                            expected: "Ocsp",
                        }
                        .into());
                    }
                }
            }

            chain_pending.checks = still_outstanding;
        }

        if pending.iter().any(|chain| !chain.checks.is_empty()) {
            self.state = State::AwaitingOcspResponses { pending, binding };
            return Ok(Some(Step::AwaitHost));
        }

        self.begin_binding(binding);
        Ok(None)
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

            // The response could not be authenticated for this
            // certificate at all — operationally no different, to this
            // validator, from never having received one.
            ocsp::OnlineOutcome::Inconclusive => self.record(ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
                url,
                "the OCSP response could not be authenticated for this credential",
            )),
        }
    }

    /// Records a confirmed revocation (C2PA spec §15.9), for either the
    /// claim signer's own certificate or a CA certificate above it — the
    /// two are reported under different vocabulary, and both, on the
    /// *active* chain, are failures: the spec calls for the claim
    /// signature itself to be rejected either way
    /// ([`status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`] for the signer; a
    /// CA certificate is reported under
    /// [`status_code::SIGNING_CREDENTIAL_UNTRUSTED`] — the same code an
    /// ordinary untrusted chain also carries — but built with
    /// [`ValidationStatus::for_url_forcing_failure`] rather than the
    /// ordinary constructor, since §15.9's own text is explicit that this
    /// circumstance is "a failure status", unlike the ordinary one).
    ///
    /// On an *inactive* (ingredient) chain, neither is: a revoked
    /// ingredient signer still gets
    /// [`status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`] — worth reporting
    /// — but built with [`ValidationStatus::for_url_suppressing_failure`],
    /// since that code is otherwise always a failure and an ingredient's
    /// own revocation does not, by itself, invalidate the asset being
    /// read (see [`PendingChainOcsp::is_active`]'s own doc comment); a
    /// revoked ingredient CA needs no such override, since
    /// `signingCredential.untrusted` already defaults to non-failing.
    /// [`Trust::Rejected`] here is really just keeping [`Self::trust`] in
    /// step with a verdict the status already recorded for the active
    /// chain.
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

                    // None of this module's synthetic certificates carry an
                    // Authority Information Access extension, so this is
                    // never actually issued — kept so the match stays
                    // exhaustive as `ReadRequest` grows.
                    ReadRequest::Ocsp { .. } => session.fulfill(
                        request.id,
                        ReadHostReply::Failed(HostError::new("no OCSP responder configured")),
                    )?,
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

    /// A real, structurally valid two-certificate chain (proven so by
    /// `chain.rs`'s own `the_real_c2pa_rs_fixture_chain_validates`), with an
    /// OCSP responder URL grafted onto the leaf — none of this repository's
    /// fixtures carry that extension natively.
    fn chain_with_responder(url: &str) -> Vec<Certificate> {
        let mut leaf = cert::decode(test_support::FIXTURE_LEAF_CERT).unwrap();
        leaf.ocsp_responder_url = Some(url.to_string());
        vec![
            leaf,
            cert::decode(test_support::FIXTURE_ISSUER_CERT).unwrap(),
        ]
    }

    /// `trust-leaf`/`trust-intermediate`/`trust-root` — the same synthetic,
    /// structurally valid three-tier fixture chain `chain.rs`'s own
    /// `ocsp_checks_still_rebuilds_the_path_through_a_configured_anchor`
    /// uses, here so a test can drive `evaluate_trust` far enough to reach
    /// a *second* certificate-path link (a CA above the signer) — the two-
    /// certificate [`chain_with_responder`] never has one.
    const TRUST_LEAF: &[u8] = include_bytes!("../tests/fixtures/trust-leaf.der");
    const TRUST_INTERMEDIATE: &[u8] = include_bytes!("../tests/fixtures/trust-intermediate.der");
    const TRUST_ROOT: &[u8] = include_bytes!("../tests/fixtures/trust-root.der");

    /// The chain (leaf, intermediate) and the anchor (root) that extends it
    /// to a second link, per [`TRUST_LEAF`]/[`TRUST_INTERMEDIATE`]/
    /// [`TRUST_ROOT`].
    fn three_tier_chain() -> (Vec<Certificate>, Vec<Certificate>) {
        (
            vec![
                cert::decode(TRUST_LEAF).unwrap(),
                cert::decode(TRUST_INTERMEDIATE).unwrap(),
            ],
            vec![cert::decode(TRUST_ROOT).unwrap()],
        )
    }

    /// A [`PendingChain`] over `certificates`, carrying no timestamp and no
    /// stapled `rVals` by default, so most tests below exercise the online
    /// path; a test that wants a staple sets `rvals` on the result.
    fn pending_chain(label: &str, url: &str, certificates: Vec<Certificate>) -> PendingChain {
        PendingChain {
            manifest_label: label.to_string(),
            url: url.to_string(),
            certificates,
            timestamp: None,
            rvals: vec![],
        }
    }

    #[test]
    fn evaluate_trust_skips_the_signer_when_ocsp_checking_is_disabled() {
        let mut session = ReadSession::new(ReadSettings {
            check_ocsp: false,
            ..ReadSettings::default()
        });

        let chains = vec![pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        )];

        let pending = session.evaluate_trust(&chains, Some(NOW));

        assert!(pending.is_empty());
        assert!(session.outstanding_requests().is_empty());
        assert_eq!(
            session.report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED)
        );
    }

    #[test]
    fn evaluate_trust_issues_one_ocsp_request_per_named_responder() {
        let mut session = ReadSession::new(ReadSettings::default());

        let chains = vec![pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        )];

        let pending = session.evaluate_trust(&chains, Some(NOW));

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].checks.len(), 1);

        // No active manifest was recorded on this report, so nothing
        // matches it — see the next test for a chain that does.
        assert!(!pending[0].is_active);

        let requests = session.outstanding_requests();
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0].kind, ReadRequest::Ocsp { .. }));

        // Nothing about revocation was established yet — that only
        // happens once the host answers — though `chain::validate`'s own
        // (non-OCSP) findings are already recorded.
        assert!(!session
            .report
            .statuses
            .iter()
            .any(|s| s.code.starts_with("signingCredential.ocsp")));
    }

    #[test]
    fn only_the_active_manifests_chain_is_marked_active() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.report.active_manifest = Some("urn:uuid:active".to_string());

        let chains = vec![
            pending_chain(
                "urn:uuid:ingredient",
                "self#jumbf=ingredient",
                chain_with_responder("http://ocsp.example/ingredient"),
            ),
            pending_chain(
                "urn:uuid:active",
                "self#jumbf=active",
                chain_with_responder("http://ocsp.example/active"),
            ),
        ];

        let pending = session.evaluate_trust(&chains, Some(NOW));

        assert_eq!(pending.len(), 2);
        assert!(!pending[0].is_active);
        assert!(pending[1].is_active);
    }

    #[test]
    fn a_chain_the_structural_checks_already_rejected_is_never_asked_about() {
        let mut session = ReadSession::new(ReadSettings::default());

        // Flip a bit of the leaf's signature: the chain fails
        // `chain::validate` outright, before OCSP is ever considered.
        let mut broken = chain_with_responder("http://ocsp.example/");
        let last = broken[0].signature.len() - 1;
        broken[0].signature[last] ^= 0x01;

        let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", broken)];

        let pending = session.evaluate_trust(&chains, Some(NOW));
        assert!(pending.is_empty());
    }

    #[test]
    fn a_garbage_stapled_response_does_not_prevent_falling_through_to_online() {
        // A staple that cannot even be decoded is exactly as useful as no
        // staple at all: `evaluate_trust` still asks online.
        let mut session = ReadSession::new(ReadSettings::default());

        let mut chain = pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        );
        chain.rvals = vec![vec![0xff, 0xff]];

        let pending = session.evaluate_trust(&[chain], Some(NOW));

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].checks.len(), 1);
    }

    #[test]
    fn a_ca_certificates_unresolved_staples_are_silently_skipped() {
        // The CA link (intermediate/root) names no responder here, so
        // with nothing in the manifest store to resolve it either, §15.9
        // has nothing further to say about it: no status of its own, and
        // it never keeps this chain's evaluation outstanding.
        let mut session = ReadSession::new(ReadSettings::default());
        let (certificates, anchors) = three_tier_chain();
        session.anchors = anchors;

        let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];

        let pending = session.evaluate_trust(&chains, Some(NOW));

        // The signer's own certificate names no responder either, so its
        // check is recorded as skipped rather than queried online —
        // nothing is left outstanding for either link of the path.
        assert!(pending.is_empty(), "{pending:?}");

        let ocsp_statuses: Vec<_> = session
            .report
            .statuses
            .iter()
            .filter(|s| s.code.starts_with("signingCredential.ocsp"))
            .collect();
        assert_eq!(
            ocsp_statuses
                .iter()
                .map(|s| s.code.as_str())
                .collect::<Vec<_>>(),
            [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED],
            "the CA link should not record a status of its own: {ocsp_statuses:?}"
        );
    }

    #[test]
    fn a_mismatched_ocsp_reply_is_defensively_rejected() {
        let mut session = ReadSession::new(ReadSettings::default());

        let chains = vec![pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        )];

        let pending = session.evaluate_trust(&chains, Some(NOW));
        session.proceed_after_trust(pending, None);

        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let id = session.outstanding_requests()[0].id;

        // Bypass `fulfill`'s payload validation to exercise the state
        // machine's own defense-in-depth check.
        session
            .core
            .fulfill_unchecked(id, ReadHostReply::AssetLength(0));

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "Ocsp",
                ..
            }))
        ));
    }

    /// [`three_tier_chain`] with an OCSP responder named on the CA (the
    /// intermediate), but not on the signer.
    fn three_tier_chain_with_ca_responder() -> (Vec<Certificate>, Vec<Certificate>) {
        let (mut certificates, anchors) = three_tier_chain();
        certificates[1].ocsp_responder_url = Some("http://ocsp.example/ca".to_string());
        (certificates, anchors)
    }

    fn ocsp_status_codes(session: &ReadSession) -> Vec<&str> {
        session
            .report
            .statuses
            .iter()
            .filter(|s| s.code.starts_with("signingCredential.ocsp"))
            .map(|s| s.code.as_str())
            .collect()
    }

    #[test]
    fn a_ca_certificate_naming_a_responder_is_asked_online_too() {
        let mut session = ReadSession::new(ReadSettings::default());
        let (certificates, anchors) = three_tier_chain_with_ca_responder();
        session.anchors = anchors;

        let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
        let pending = session.evaluate_trust(&chains, Some(NOW));

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].checks.len(), 1);
        assert!(!pending[0].checks[0].2, "the check should be for the CA");
        assert_eq!(
            pending[0].checks[0].1.responder_url.as_deref(),
            Some("http://ocsp.example/ca")
        );
    }

    #[test]
    fn a_ca_certificate_is_not_asked_online_when_online_checking_is_disabled() {
        let mut session = ReadSession::new(ReadSettings {
            check_ocsp: false,
            ..ReadSettings::default()
        });
        let (certificates, anchors) = three_tier_chain_with_ca_responder();
        session.anchors = anchors;

        let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
        let pending = session.evaluate_trust(&chains, Some(NOW));

        assert!(pending.is_empty(), "{pending:?}");
        // Only the signer's own skipped status; a CA has none of its own.
        assert_eq!(
            ocsp_status_codes(&session),
            [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED]
        );
    }

    #[test]
    fn an_unreachable_or_unconvincing_ca_responder_records_nothing_and_leaves_trust_untouched() {
        for reply in [
            ReadHostReply::Failed(HostError::new("no network")),
            ReadHostReply::Ocsp(vec![0xff, 0xff]),
        ] {
            let mut session = ReadSession::new(ReadSettings::default());
            session.report.active_manifest = Some("urn:uuid:one".to_string());
            let (certificates, anchors) = three_tier_chain_with_ca_responder();
            session.anchors = anchors;

            let chains = vec![pending_chain("urn:uuid:one", "self#jumbf=x", certificates)];
            let pending = session.evaluate_trust(&chains, Some(NOW));
            let trust = session.trust;
            session.proceed_after_trust(pending, None);

            resolve_ocsp(&mut session, reply);

            assert_eq!(session.trust, trust);
            // Only the signer's own skipped status, recorded up front.
            assert_eq!(
                ocsp_status_codes(&session),
                [status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED]
            );
        }
    }

    /// A session parked awaiting one *CA* OCSP check's reply, as
    /// `evaluate_trust` would leave it, with a response that revokes it at
    /// 1_200 (the claim being judged at 1_500).
    fn session_awaiting_a_revoked_ca(is_active: bool) -> (ReadSession, ReadHostReply) {
        let (check, response) = ocsp::revoked_fixture(1_200);

        let mut session = ReadSession::new(ReadSettings::default());
        session.report.active_manifest = Some("urn:uuid:active".to_string());
        session.trust = Some(Trust::Anchored);

        let request = session.core.issue(ReadRequest::Ocsp {
            url: "http://ocsp.example/ca".to_string(),
            request_der: check.request_der.clone(),
        });
        let pending = vec![PendingChainOcsp {
            url: "self#jumbf=x".to_string(),
            is_active,
            now: Some(1_500),
            attested: Some(1_500),
            checks: vec![(request, check, false)],
        }];
        session.proceed_after_trust(pending, None);

        (session, ReadHostReply::Ocsp(response))
    }

    #[test]
    fn a_revoked_ca_in_a_live_response_rejects_the_active_chain() {
        let (mut session, reply) = session_awaiting_a_revoked_ca(true);

        resolve_ocsp(&mut session, reply);

        assert_eq!(session.trust, Some(Trust::Rejected));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
        assert!(status.is_failure());
    }

    #[test]
    fn a_revoked_ca_in_a_live_response_on_an_ingredient_chain_is_not_a_failure() {
        let (mut session, reply) = session_awaiting_a_revoked_ca(false);

        resolve_ocsp(&mut session, reply);

        assert_eq!(session.trust, Some(Trust::Anchored));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
        assert!(!status.is_failure());
    }

    /// Drives a session already parked in `State::AwaitingOcspResponses`
    /// (as `evaluate_trust` would leave it) to completion, fulfilling its
    /// one outstanding request with `reply`. Leaves `session` in place so
    /// callers can inspect `trust`/`report` directly afterward.
    fn resolve_ocsp(session: &mut ReadSession, reply: ReadHostReply) {
        assert_eq!(session.advance().unwrap(), ReadStep::AwaitHost);
        let requests = session.outstanding_requests().to_vec();
        assert_eq!(requests.len(), 1, "{requests:?}");

        session.fulfill(requests[0].id, reply).unwrap();
        assert_eq!(session.advance().unwrap(), ReadStep::Complete);
    }

    #[test]
    fn a_host_that_cannot_answer_ocsp_records_inaccessible_and_leaves_trust_untouched() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.report.active_manifest = Some("urn:uuid:one".to_string());

        let chains = vec![pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        )];

        let pending = session.evaluate_trust(&chains, Some(NOW));
        assert_eq!(session.trust, Some(Trust::Unanchored));
        session.proceed_after_trust(pending, None);

        resolve_ocsp(
            &mut session,
            ReadHostReply::Failed(HostError::new("no network")),
        );

        assert_eq!(session.trust, Some(Trust::Unanchored));
        assert_eq!(
            session.report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
        );
    }

    #[test]
    fn an_uninterpretable_online_response_records_inaccessible_and_is_fail_open() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.report.active_manifest = Some("urn:uuid:one".to_string());

        let chains = vec![pending_chain(
            "urn:uuid:one",
            "self#jumbf=x",
            chain_with_responder("http://ocsp.example/"),
        )];

        let pending = session.evaluate_trust(&chains, Some(NOW));
        session.proceed_after_trust(pending, None);

        resolve_ocsp(&mut session, ReadHostReply::Ocsp(vec![0xff, 0xff]));

        assert_eq!(session.trust, Some(Trust::Unanchored));
        assert_eq!(
            session.report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
        );
    }

    #[test]
    fn apply_online_outcome_not_revoked_records_a_success_code() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Unanchored);

        session.apply_online_outcome(ocsp::OnlineOutcome::NotRevoked, "self#jumbf=x", true);

        assert_eq!(session.trust, Some(Trust::Unanchored));
        assert_eq!(
            session.report.statuses.last().map(|s| s.code.as_str()),
            Some(status_code::SIGNING_CREDENTIAL_OCSP_NOT_REVOKED)
        );
    }

    #[test]
    fn apply_online_outcome_revoked_fails_the_active_chain() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_online_outcome(ocsp::OnlineOutcome::Revoked, "self#jumbf=x", true);

        assert_eq!(session.trust, Some(Trust::Rejected));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
        assert!(status.is_failure());
    }

    #[test]
    fn apply_online_outcome_revoked_for_an_inactive_chain_spares_trust() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_online_outcome(ocsp::OnlineOutcome::Revoked, "self#jumbf=ingredient", false);

        assert_eq!(session.trust, Some(Trust::Anchored));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);

        // Worth reporting, but an ingredient's own revocation must not,
        // by itself, invalidate the whole asset being read.
        assert!(!status.is_failure());
    }

    #[test]
    fn apply_online_outcome_unknown_records_an_informational_code() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_online_outcome(ocsp::OnlineOutcome::Unknown, "self#jumbf=x", true);

        assert_eq!(session.trust, Some(Trust::Anchored));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_UNKNOWN);
        assert!(!status.is_failure());
    }

    #[test]
    fn a_revoked_ca_certificate_is_reported_as_untrusted_but_still_fails_the_claim() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_revocation(false, true, "self#jumbf=x", "a CA certificate was revoked");

        // Reported under the same code an ordinary untrusted chain
        // carries, but §15.9's own text calls this circumstance out as a
        // failure, unlike the ordinary one — see
        // `ValidationStatus::for_url_forcing_failure`.
        assert_eq!(session.trust, Some(Trust::Rejected));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
        assert!(status.is_failure());
    }

    #[test]
    fn a_revoked_ca_certificate_for_an_inactive_chain_spares_trust() {
        // An ingredient's chain is still checked and still reported, but
        // neither `Self::trust` nor the overall verdict is swayed by it —
        // only the *active* manifest's own chain determines either.
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_revocation(
            false,
            false,
            "self#jumbf=ingredient",
            "a CA certificate was revoked",
        );

        assert_eq!(session.trust, Some(Trust::Anchored));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_UNTRUSTED);
        assert!(!status.is_failure());
    }

    #[test]
    fn a_revoked_signer_certificate_for_an_inactive_chain_spares_the_verdict() {
        // An ingredient's own revoked signer is still worth reporting
        // (hence the ordinary `SIGNING_CREDENTIAL_OCSP_REVOKED` code), but
        // must not flip the overall report to `Invalid` on its own.
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_revocation(
            true,
            false,
            "self#jumbf=ingredient",
            "the signer's certificate was revoked",
        );

        assert_eq!(session.trust, Some(Trust::Anchored));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
        assert!(!status.is_failure());
    }

    #[test]
    fn a_revoked_signer_certificate_fails_the_claim_outright() {
        let mut session = ReadSession::new(ReadSettings::default());
        session.trust = Some(Trust::Anchored);

        session.apply_revocation(
            true,
            true,
            "self#jumbf=x",
            "the signer's certificate was revoked",
        );

        assert_eq!(session.trust, Some(Trust::Rejected));
        let status = session.report.statuses.last().unwrap();
        assert_eq!(status.code, status_code::SIGNING_CREDENTIAL_OCSP_REVOKED);
        assert!(status.is_failure());
    }
}
