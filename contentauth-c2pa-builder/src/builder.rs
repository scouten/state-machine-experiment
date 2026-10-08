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

//! The build/sign workflow: [`BuilderSession`].

use core::mem::replace;

use contentauth_c2pa_primitives::{ByteRange, SigningAlg, StreamId};
pub use contentauth_state_machine::Step as BuilderStep;
use contentauth_state_machine::{
    HostRequest, ProtocolError, RequestId, Session, SessionCore, Step,
};

use crate::{
    cose, data_hash,
    error::Error,
    hash_stream::{self, HashStream},
    identity::{self, IdentitySettings},
    jumbf::{AssertionInput, IdentityInput, ManifestBuilder, ManifestInputs},
    request::{BuilderHostReply, BuilderRequest, SignPurpose},
};

/// Configuration for a [`BuilderSession`].
///
/// Experimental: this will grow to cover more of the c2pa-rs settings
/// system (ingredients, additional hard binding kinds, OCSP) — see this
/// crate's README for the current scope.
#[derive(Debug)]
#[non_exhaustive]
pub struct BuilderSettings {
    /// Human-readable title of the asset, if any.
    pub title: Option<String>,

    /// Identifier for this specific instance of the asset.
    pub instance_id: String,

    /// Identifies the manifest within its store — typically a
    /// `urn:uuid:` string.
    ///
    /// This crate holds no randomness source of its own (the same "no
    /// clock of its own" posture `contentauth-c2pa-reader` takes toward
    /// wall-clock time), so the host supplies this rather than the session
    /// generating one.
    pub manifest_label: String,

    /// Describes the software that generated this manifest.
    ///
    /// A single entry: c2pa-rs itself requires exactly one for v2 claims,
    /// and this crate does not yet support more than one. A future version
    /// of this crate that does would widen this to a `Vec<GeneratorInfo>`.
    pub claim_generator_info: GeneratorInfo,

    /// Assertions to embed, beyond the hard binding this session adds
    /// itself.
    ///
    /// Each is opaque, pre-encoded CBOR: this crate does not yet model
    /// specific assertion schemas (actions, thumbnails, …) — see this
    /// crate's README. Each also carries an [`AssertionKind`], set by the
    /// host, saying whether this claim's generator created it or gathered
    /// it from elsewhere.
    pub assertions: Vec<Assertion>,

    /// The algorithm to sign the claim with.
    pub signing_alg: SigningAlg,

    /// DER-encoded certificate chain for the claim signature's `x5chain`
    /// header, signer first.
    ///
    /// Passed through opaquely: this crate does not decode or validate
    /// certificates, unlike `contentauth-c2pa-reader`'s `cert` module — the
    /// host vouches for what it supplies here.
    pub certificates: Vec<Vec<u8>>,

    /// The exact signature length `signing_alg` will produce.
    ///
    /// Required if and only if `signing_alg` is an RSASSA-PSS algorithm,
    /// whose signature length is the signing key's modulus size rather
    /// than a constant — typically the length of the leaf certificate's
    /// public key, in bytes.
    pub rsa_signature_len: Option<usize>,

    /// If set, this session requests an RFC 3161 timestamp for the claim
    /// signature.
    pub timestamp: Option<TimestampSettings>,

    /// CAWG identity assertions to add, each a named actor vouching for
    /// the manifest's assertions and its hard binding with a credential of
    /// their own. See [`IdentitySettings`].
    ///
    /// Each is signed separately from the claim, so the host is asked to
    /// sign once for the claim and once per identity, told which by
    /// [`BuilderRequest::Sign`]'s `purpose`. They become the assertions
    /// `cawg.identity`, `cawg.identity__1`, … in this order.
    pub identities: Vec<IdentitySettings>,
}

impl BuilderSettings {
    /// Creates settings from the fields every manifest needs, with no
    /// title, no assertions beyond the hard binding this session adds
    /// itself, no RSA signature length (only meaningful for RSASSA-PSS
    /// algorithms), no timestamp, and no identity assertions — set the
    /// corresponding public field afterward to change any of those.
    pub fn new(
        instance_id: impl Into<String>,
        manifest_label: impl Into<String>,
        claim_generator_info: GeneratorInfo,
        signing_alg: SigningAlg,
        certificates: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            title: None,
            instance_id: instance_id.into(),
            manifest_label: manifest_label.into(),
            claim_generator_info,
            assertions: Vec::new(),
            signing_alg,
            certificates,
            rsa_signature_len: None,
            timestamp: None,
            identities: Vec::new(),
        }
    }
}

/// Configuration for requesting an RFC 3161 timestamp.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct TimestampSettings {
    /// Bytes reserved in the manifest for the timestamp token.
    ///
    /// The token's real size depends on the timestamp authority's
    /// response and cannot be predicted, so this crate reserves room for
    /// it up front (mirroring c2pa-rs's own fixed timestamp reserve) and
    /// pads out the difference once the real token is known. A token
    /// larger than this is a fatal [`Error::TimestampTooLarge`], not a
    /// silent fallback to no timestamp.
    pub reserve_size: usize,
}

impl TimestampSettings {
    /// Requests a timestamp with the given reserve size.
    pub fn new(reserve_size: usize) -> Self {
        Self { reserve_size }
    }
}

impl Default for TimestampSettings {
    /// 10,000 bytes — comfortably larger than a typical RFC 3161 token
    /// (which carries the timestamp authority's own certificate chain),
    /// matching the order of magnitude c2pa-rs reserves for the same
    /// purpose.
    fn default() -> Self {
        Self {
            reserve_size: 10_000,
        }
    }
}

/// One assertion to embed, as opaque, pre-encoded CBOR.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Assertion {
    /// The assertion's label (for example, `"c2pa.actions"`).
    pub label: String,

    /// The assertion's CBOR-encoded content.
    pub cbor: Vec<u8>,

    /// Whether this claim's generator created the assertion itself, or
    /// gathered it from elsewhere — for example, content produced by
    /// another tool or plugin, or otherwise not authored fresh for this
    /// claim. The host supplies the assertion's content in the first
    /// place, so it is the one that knows which; this crate has no way to
    /// infer it. Determines whether the assertion is encoded in the
    /// claim's `created_assertions` or `gathered_assertions`.
    pub kind: AssertionKind,
}

impl Assertion {
    /// Creates an assertion this claim's generator created itself, with
    /// the given label and pre-encoded CBOR content.
    pub fn new(label: impl Into<String>, cbor: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            cbor,
            kind: AssertionKind::Created,
        }
    }

    /// Creates an assertion gathered from elsewhere, rather than created
    /// by this claim's generator, with the given label and pre-encoded
    /// CBOR content.
    pub fn gathered(label: impl Into<String>, cbor: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            cbor,
            kind: AssertionKind::Gathered,
        }
    }
}

/// Whether an assertion was created by this claim's generator or
/// gathered from elsewhere. See [`Assertion::kind`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AssertionKind {
    /// Created by this claim's generator; encoded in the claim's
    /// `created_assertions`.
    Created,

    /// Gathered from elsewhere rather than created by this claim's
    /// generator; encoded in the claim's `gathered_assertions`.
    Gathered,
}

/// Describes the software that generated a claim.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratorInfo {
    /// Name of the generating product.
    pub name: String,

    /// Version of the generating product.
    pub version: String,
}

impl GeneratorInfo {
    /// Describes a claim generator by name and version.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// Generates and signs a C2PA manifest store for a digital asset.
///
/// This is the synchronous, sans-I/O counterpart of `Builder` in c2pa-rs.
/// It implements the [`Session`] trait from `contentauth-state-machine`: it
/// never touches the asset, a signing key, the network, or a clock itself;
/// it issues host requests and the host reports outcomes back.
///
/// # Interaction contract
///
/// See the [`Session`] trait for the full contract. Concretely:
///
/// 1. Create the session with [`BuilderSession::new`].
/// 2. Call [`Session::advance`] to let the session do as much synchronous
///    work as it can. It returns [`BuilderStep::AwaitHost`] when blocked on
///    the host, or [`BuilderStep::Complete`] when done.
/// 3. While `AwaitHost`: service [`Session::outstanding_requests`], report
///    each outcome via [`Session::fulfill`], and call
///    [`Session::advance`] again.
/// 4. On `Complete`: consume the session with [`Session::finish`] to obtain
///    the [`BuilderReport`].
///
/// Unlike [`contentauth_c2pa_reader::ReadSession`], every host failure here
/// is fatal — see [`crate::Error`]'s documentation for why.
///
/// [`contentauth_c2pa_reader::ReadSession`]: https://docs.rs/contentauth-c2pa-reader/latest/contentauth_c2pa_reader/struct.ReadSession.html
#[derive(Debug)]
pub struct BuilderSession {
    settings: BuilderSettings,
    core: SessionCore<BuilderRequest>,
    state: State,
    report: Option<BuilderReport>,
}

/// The build workflow's own phase, tracked separately from whether the
/// session as a whole has completed or failed — that half of the
/// lifecycle belongs to [`SessionCore`], via [`BuilderSession::core`].
#[derive(Debug)]
enum State {
    Start,
    AwaitingPlaceholderReserved {
        request: RequestId,
        manifest: Box<ManifestBuilder>,
    },
    AwaitingAssetLength {
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    },
    HashingAsset {
        /// Boxed for the same reason `contentauth-c2pa-reader`'s
        /// `HashStream` is: far larger than any other variant, and a
        /// session spends most of its life not hashing.
        stream: Box<HashStream>,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    },
    AwaitingIdentitySignature {
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,

        /// Which of the manifest's identity assertions was sent to be
        /// signed.
        index: usize,
    },
    AwaitingSignature {
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    },
    AwaitingTimestamp {
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
        signature: Vec<u8>,
    },
    AwaitingCommit {
        request: RequestId,
        manifest: Vec<u8>,
        exclusions: Vec<ByteRange>,
    },

    /// Installed while a phase is being processed (see
    /// [`BuilderSession::run`]), and left behind if that phase exits
    /// early — every `?` and every `return Err(…)` in
    /// [`BuilderSession::run`] does. [`BuilderSession::advance`] turns
    /// that into [`SessionCore::mark_failed`], so a later call finds this
    /// variant again and reports [`ProtocolError::SessionFailed`].
    Poisoned,
}

impl BuilderSession {
    /// The asset stream this session embeds its manifest into.
    pub const PRIMARY_STREAM: StreamId = StreamId::new(0);

    /// Creates a new build session for a single asset.
    ///
    /// The asset itself stays on the host side; the session refers to it
    /// as [`Self::PRIMARY_STREAM`].
    pub fn new(settings: BuilderSettings) -> Self {
        Self {
            settings,
            core: SessionCore::default(),
            state: State::Start,
            report: None,
        }
    }

    /// The state-machine loop proper, factored out of [`Session::advance`]
    /// so that every error exit is poisoned in one place rather than at
    /// each fallible call within the loop.
    fn run(&mut self) -> Result<Step, Error> {
        loop {
            if self.core.is_complete() {
                return Ok(Step::Complete);
            }

            let outcome = match replace(&mut self.state, State::Poisoned) {
                State::Start => self.handle_start(),

                State::AwaitingPlaceholderReserved { request, manifest } => {
                    self.handle_awaiting_placeholder_reserved(request, manifest)
                }

                State::AwaitingAssetLength {
                    request,
                    manifest,
                    exclusions,
                } => self.handle_awaiting_asset_length(request, manifest, exclusions),

                State::HashingAsset {
                    stream,
                    manifest,
                    exclusions,
                } => self.handle_hashing_asset(stream, manifest, exclusions),

                State::AwaitingIdentitySignature {
                    request,
                    manifest,
                    exclusions,
                    index,
                } => self.handle_awaiting_identity_signature(request, manifest, exclusions, index),

                State::AwaitingSignature {
                    request,
                    manifest,
                    exclusions,
                } => self.handle_awaiting_signature(request, manifest, exclusions),

                State::AwaitingTimestamp {
                    request,
                    manifest,
                    exclusions,
                    signature,
                } => self.handle_awaiting_timestamp(request, manifest, exclusions, signature),

                State::AwaitingCommit {
                    request,
                    manifest,
                    exclusions,
                } => self.handle_awaiting_commit(request, manifest, exclusions),

                State::Poisoned => return Err(ProtocolError::SessionFailed.into()),
            }?;

            if let Some(step) = outcome {
                return Ok(step);
            }
        }
    }

    /// Handles [`State::Start`]: validates settings, assembles the
    /// placeholder manifest, and asks the host to embed it.
    fn handle_start(&mut self) -> Result<Option<Step>, Error> {
        if self.settings.certificates.is_empty() {
            return Err(Error::NoCertificates);
        }

        let mut assertion_labels = std::collections::HashSet::from([data_hash::LABEL]);
        for assertion in &self.settings.assertions {
            if !assertion_labels.insert(assertion.label.as_str()) {
                return Err(Error::InvalidAssertionLabel(assertion.label.clone()));
            }
        }

        // The labels this crate generates for identity assertions are as
        // reserved as the hard binding's.
        for index in 0..self.settings.identities.len() {
            let label = identity::label_for(index);
            if assertion_labels.contains(label.as_str()) {
                return Err(Error::InvalidAssertionLabel(label));
            }
        }

        let identity_inputs = self
            .settings
            .identities
            .iter()
            .map(|identity| {
                let referenced = match &identity.referenced_assertions {
                    None => self
                        .settings
                        .assertions
                        .iter()
                        .map(|a| a.label.as_str())
                        .collect(),
                    Some(labels) => {
                        let mut seen = std::collections::HashSet::new();
                        for label in labels {
                            if !self.settings.assertions.iter().any(|a| &a.label == label) {
                                return Err(Error::UnknownReferencedAssertion(label.clone()));
                            }
                            // Naming one twice would write an assertion the
                            // reader reports as a duplicate reference.
                            if !seen.insert(label.as_str()) {
                                return Err(Error::DuplicateReferencedAssertion(label.clone()));
                            }
                        }
                        labels.iter().map(String::as_str).collect()
                    }
                };

                Ok(IdentityInput {
                    credential: &identity.credential,
                    roles: &identity.roles,
                    referenced,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let signature_len =
            cose::signature_len(self.settings.signing_alg, self.settings.rsa_signature_len)?;
        let generator = &self.settings.claim_generator_info;

        let assertions: Vec<AssertionInput<'_>> = self
            .settings
            .assertions
            .iter()
            .map(|a| AssertionInput {
                label: &a.label,
                cbor: &a.cbor,
                kind: a.kind,
            })
            .collect();

        let inputs = ManifestInputs {
            manifest_label: &self.settings.manifest_label,
            title: self.settings.title.as_deref(),
            instance_id: &self.settings.instance_id,
            generator_name: &generator.name,
            generator_version: &generator.version,
            assertions: &assertions,
            signing_alg: self.settings.signing_alg,
            certificates: &self.settings.certificates,
            signature_len,
            timestamp_reserve: self.settings.timestamp.map(|t| t.reserve_size),
            identities: &identity_inputs,
        };

        let manifest = ManifestBuilder::build_placeholder(&inputs)?;
        let placeholder = manifest.placeholder_bytes().to_vec();

        let request = self.core.issue(BuilderRequest::ReservePlaceholder {
            stream: Self::PRIMARY_STREAM,
            placeholder,
        });
        self.state = State::AwaitingPlaceholderReserved {
            request,
            manifest: Box::new(manifest),
        };

        Ok(Some(Step::AwaitHost))
    }

    /// Handles [`State::AwaitingPlaceholderReserved`].
    fn handle_awaiting_placeholder_reserved(
        &mut self,
        request: RequestId,
        manifest: Box<ManifestBuilder>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingPlaceholderReserved { request, manifest };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::PlaceholderReserved(exclusions)) => {
                // The container's framing around the placeholder (a
                // JPEG's APP11 segment headers, say) belongs inside the
                // exclusions, so they may total more than the
                // placeholder — but never less, which would leave part
                // of the manifest inside its own hash.
                let excluded = exclusions
                    .iter()
                    .try_fold(0u64, |total, range| total.checked_add(range.len));
                if excluded
                    .is_none_or(|excluded| excluded < manifest.placeholder_bytes().len() as u64)
                {
                    return Err(Error::PlaceholderRangeInvalid(
                        "the reserved ranges are shorter than the placeholder that was embedded",
                    ));
                }

                let request = self.core.issue(BuilderRequest::AssetLength {
                    stream: Self::PRIMARY_STREAM,
                });
                self.state = State::AwaitingAssetLength {
                    request,
                    manifest,
                    exclusions,
                };
            }

            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "PlaceholderReserved",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::AwaitingAssetLength`].
    fn handle_awaiting_asset_length(
        &mut self,
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingAssetLength {
                    request,
                    manifest,
                    exclusions,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::AssetLength(asset_len)) => {
                let ranges = hash_stream::included_ranges(&exclusions, asset_len).ok_or(
                    Error::PlaceholderRangeInvalid(
                        "the reserved placeholder range does not fit the asset",
                    ),
                )?;

                let hash_alg = self.settings.signing_alg.claim_hash_algorithm();
                let mut stream = Box::new(HashStream::new(hash_alg, &ranges));
                stream.issue(&mut self.core, Self::PRIMARY_STREAM);

                self.state = State::HashingAsset {
                    stream,
                    manifest,
                    exclusions,
                };
            }

            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
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

    /// Handles [`State::HashingAsset`]: streams asset bytes into the hard
    /// binding hasher until it is done, then signs.
    fn handle_hashing_asset(
        &mut self,
        mut stream: Box<HashStream>,
        mut manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    ) -> Result<Option<Step>, Error> {
        stream.absorb(&mut self.core)?;

        if !stream.is_complete() {
            stream.issue(&mut self.core, Self::PRIMARY_STREAM);
            self.state = State::HashingAsset {
                stream,
                manifest,
                exclusions,
            };
            return Ok(Some(Step::AwaitHost));
        }

        let hash = stream.finish()?;
        manifest.apply_hard_binding(&exclusions, hash)?;

        self.begin_signing(manifest, exclusions, 0)?;

        Ok(Some(Step::AwaitHost))
    }

    /// Asks the host for the next signature the manifest needs: identity
    /// assertion `next_identity`'s, if there is one, else the claim's.
    ///
    /// The claim comes last because it lists every assertion's hash, and
    /// an identity assertion's hash is not known until it is signed.
    fn begin_signing(
        &mut self,
        mut manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
        next_identity: usize,
    ) -> Result<(), Error> {
        if next_identity < manifest.identity_count() {
            let (label, alg, data) = manifest.identity_to_be_signed(next_identity)?;

            let request = self.core.issue(BuilderRequest::Sign {
                purpose: SignPurpose::Identity { label },
                alg,
                data,
            });
            self.state = State::AwaitingIdentitySignature {
                request,
                manifest,
                exclusions,
                index: next_identity,
            };
        } else {
            let to_be_signed = manifest.apply_claim()?;

            let request = self.core.issue(BuilderRequest::Sign {
                purpose: SignPurpose::Claim,
                alg: self.settings.signing_alg,
                data: to_be_signed,
            });
            self.state = State::AwaitingSignature {
                request,
                manifest,
                exclusions,
            };
        }

        Ok(())
    }

    /// Handles [`State::AwaitingIdentitySignature`]: writes the identity
    /// assertion the signature completes, then asks for whatever is signed
    /// next.
    fn handle_awaiting_identity_signature(
        &mut self,
        request: RequestId,
        mut manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
        index: usize,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingIdentitySignature {
                    request,
                    manifest,
                    exclusions,
                    index,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::Signature(signature)) => {
                manifest.apply_identity_signature(index, &signature)?;
                self.begin_signing(manifest, exclusions, index + 1)?;
            }

            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "Signature",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::AwaitingSignature`]: on a real signature, either
    /// requests a timestamp or moves straight to committing the manifest.
    fn handle_awaiting_signature(
        &mut self,
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingSignature {
                    request,
                    manifest,
                    exclusions,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::Signature(signature)) => {
                match manifest.countersigned_bytes(&signature) {
                    Some(countersigned) => {
                        let hash_alg = self.settings.signing_alg.claim_hash_algorithm();
                        let digest = hash_alg.digest(&countersigned);

                        let request = self
                            .core
                            .issue(BuilderRequest::Timestamp { digest, hash_alg });
                        self.state = State::AwaitingTimestamp {
                            request,
                            manifest,
                            exclusions,
                            signature,
                        };
                    }
                    None => self.commit(manifest, exclusions, &signature, None)?,
                }
            }

            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "Signature",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Handles [`State::AwaitingTimestamp`].
    fn handle_awaiting_timestamp(
        &mut self,
        request: RequestId,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
        signature: Vec<u8>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingTimestamp {
                    request,
                    manifest,
                    exclusions,
                    signature,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::Timestamp(token)) => {
                self.commit(manifest, exclusions, &signature, Some(&token))?;
            }

            // A failed timestamp is fatal, not a silent fallback to an
            // unstamped signature — see the crate-level error docs.
            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "Timestamp",
                }
                .into());
            }
        }

        Ok(None)
    }

    /// Finalizes the manifest with the real signature (and timestamp, if
    /// any) and asks the host to patch it into the asset.
    fn commit(
        &mut self,
        manifest: Box<ManifestBuilder>,
        exclusions: Vec<ByteRange>,
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> Result<(), Error> {
        let final_bytes = manifest.finish(signature, timestamp_token)?;

        let request = self.core.issue(BuilderRequest::CommitManifest {
            stream: Self::PRIMARY_STREAM,
            exclusions: exclusions.clone(),
            manifest: final_bytes.clone(),
        });
        self.state = State::AwaitingCommit {
            request,
            manifest: final_bytes,
            exclusions,
        };

        Ok(())
    }

    /// Handles [`State::AwaitingCommit`].
    fn handle_awaiting_commit(
        &mut self,
        request: RequestId,
        manifest: Vec<u8>,
        exclusions: Vec<ByteRange>,
    ) -> Result<Option<Step>, Error> {
        match self.core.take_reply(request) {
            None => {
                self.state = State::AwaitingCommit {
                    request,
                    manifest,
                    exclusions,
                };
                return Ok(Some(Step::AwaitHost));
            }

            Some(BuilderHostReply::ManifestCommitted) => {
                self.report = Some(BuilderReport {
                    manifest,
                    exclusions,
                });
                self.core.mark_complete();
            }

            Some(BuilderHostReply::Failed(source)) => {
                return Err(Error::HostFailure {
                    id: request,
                    source,
                });
            }

            Some(_) => {
                return Err(ProtocolError::ReplyMismatch {
                    id: request,
                    expected: "ManifestCommitted",
                }
                .into());
            }
        }

        Ok(None)
    }
}

impl Session for BuilderSession {
    type Error = Error;
    type Output = BuilderReport;
    type Request = BuilderRequest;

    /// Performs as much synchronous work as possible.
    ///
    /// Returns [`BuilderStep::AwaitHost`] if the session is blocked on
    /// host requests, or [`BuilderStep::Complete`] once the workflow has
    /// finished (idempotently, on subsequent calls as well).
    ///
    /// If this returns an error, the session is spent: it cannot be
    /// advanced or fulfilled again, and [`Session::finish`] will refuse to
    /// hand over a manifest that was never actually completed. Every later
    /// call reports [`ProtocolError::SessionFailed`].
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
    fn outstanding_requests(&self) -> &[HostRequest<BuilderRequest>] {
        self.core.outstanding_requests()
    }

    /// Reports the outcome of one outstanding request.
    fn fulfill(&mut self, id: RequestId, reply: BuilderHostReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    /// Consumes the session and returns the completed manifest.
    ///
    /// Fails with [`ProtocolError::SessionNotComplete`] if the workflow
    /// has not reached [`BuilderStep::Complete`], or with
    /// [`ProtocolError::SessionFailed`] if [`Session::advance`] returned
    /// an error.
    fn finish(self) -> Result<BuilderReport, Error> {
        self.core.finish_check()?;
        self.report
            .ok_or_else(|| ProtocolError::SessionFailed.into())
    }
}

/// The result of a completed build workflow.
#[derive(Debug)]
#[non_exhaustive]
pub struct BuilderReport {
    /// The final, signed C2PA manifest store bytes — identical to what was
    /// patched into the asset via `BuilderRequest::CommitManifest`.
    pub manifest: Vec<u8>,

    /// The hard binding's exclusions, as the host reported them via
    /// `BuilderHostReply::PlaceholderReserved`: the container structure
    /// carrying the manifest, framing included, and anything else the
    /// format's specification excludes.
    pub exclusions: Vec<ByteRange>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    const CERT: &[u8] = include_bytes!("../tests/fixtures/test-signer.der");

    /// Drives a session with one identity assertion to the point where it
    /// has asked for that assertion's signature, and returns the session
    /// and that request's id.
    fn session_at_identity_signature() -> (BuilderSession, RequestId) {
        let mut settings = BuilderSettings::new(
            "xmp:iid:1",
            "urn:uuid:1",
            GeneratorInfo::new("test", "1"),
            SigningAlg::Es256,
            vec![CERT.to_vec()],
        );
        settings.identities = vec![IdentitySettings::x509(
            SigningAlg::Es256,
            vec![CERT.to_vec()],
        )];

        let mut session = BuilderSession::new(settings);
        let mut asset = vec![0u8; 4000];

        loop {
            session.advance().unwrap();

            for request in session.outstanding_requests().to_vec() {
                let reply = match &request.kind {
                    BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                        asset.splice(100..100, placeholder.iter().copied());
                        BuilderHostReply::PlaceholderReserved(vec![ByteRange {
                            start: 100,
                            len: placeholder.len() as u64,
                        }])
                    }
                    BuilderRequest::AssetLength { .. } => {
                        BuilderHostReply::AssetLength(asset.len() as u64)
                    }
                    BuilderRequest::AssetBytes { range, .. } => {
                        let start = range.start as usize;
                        BuilderHostReply::AssetBytes(
                            asset[start..start + range.len as usize].to_vec(),
                        )
                    }
                    BuilderRequest::Sign { purpose, .. } => {
                        assert!(matches!(purpose, SignPurpose::Identity { .. }));
                        return (session, request.id);
                    }
                    other => panic!("unexpected request {other:?}"),
                };
                session.fulfill(request.id, reply).unwrap();
            }
        }
    }

    /// `fulfill` refuses a reply of the wrong kind, so the session's own
    /// check — defence in depth against a bug in that gate — is reached by
    /// going around it.
    #[test]
    fn a_reply_of_the_wrong_kind_to_an_identity_signature_request_is_refused() {
        let (mut session, id) = session_at_identity_signature();

        session
            .core
            .fulfill_unchecked(id, BuilderHostReply::ManifestCommitted);

        assert!(matches!(
            session.advance().unwrap_err(),
            Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "Signature",
                ..
            })
        ));
    }

    #[test]
    fn a_session_whose_identity_signature_is_pending_waits_for_it() {
        let (mut session, _id) = session_at_identity_signature();

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert!(matches!(
            session.state,
            State::AwaitingIdentitySignature { index: 0, .. }
        ));
    }
}
