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

//! [`SidecarSession`]: the composition.

use std::collections::HashSet;

use contentauth_c2pa_assertion_data_hash::{
    DataHashReply, DataHashRequest, DataHashSession, DataHashSettings,
};
use contentauth_c2pa_claim::{signature, Claim, GeneratorInfo};
use contentauth_c2pa_primitives::{
    hashed_uri::assertion_uri, EncodedAssertion, HashAlgorithm, HashedUri, SigningAlg, StreamId,
};
use contentauth_state_machine::{
    HostRequest, ProtocolError, RequestId, Session, SessionCore, Step,
};

use crate::{
    request::{SidecarReply, SidecarRequest},
    store, Error,
};

/// The stream the asset is read from.
pub const ASSET_STREAM: StreamId = StreamId::new(0);

/// Everything a sidecar manifest is made from, except the asset itself.
#[derive(Clone, Debug)]
pub struct SidecarSettings {
    /// The manifest's label (typically a `urn:uuid:` — the engine has no
    /// RNG, so the host mints it).
    pub manifest_label: String,

    /// The claim's `instanceID`.
    ///
    /// TODO: when the asset has XMP, this should be its `xmpMM:InstanceID`;
    /// nothing here checks (see `contentauth-c2pa-claim`).
    pub instance_id: String,

    /// The asset's title (`dc:title`), if any.
    pub title: Option<String>,

    /// The generating product.
    pub generator: GeneratorInfo,

    /// The claim signature algorithm.
    pub signing_alg: SigningAlg,

    /// The signer's certificate chain, end-entity first. Passed through
    /// opaquely; the host vouches for it.
    pub certificates: Vec<Vec<u8>>,

    /// The assertions to include, already encoded. The session never looks
    /// inside them. The hard binding is added by the session itself and
    /// must not be among them.
    pub assertions: Vec<EncodedAssertion>,
}

/// The finished sidecar.
#[derive(Debug)]
#[non_exhaustive]
pub struct SidecarReport {
    /// The manifest store's JUMBF bytes: the content of a `.c2pa` file.
    pub manifest_store: Vec<u8>,

    /// The manifest's label.
    pub manifest_label: String,
}

#[derive(Debug)]
enum State {
    Start,
    Hashing(Box<Hashing>),
    AwaitingSignature(Box<Signing>),
    Done(Box<SidecarReport>),
    Poisoned,
}

/// The data-hash sub-session, and which of its requests are forwarded to
/// the host as which of ours.
#[derive(Debug)]
struct Hashing {
    inner: DataHashSession,
    forwarded: Vec<(RequestId, RequestId)>,
}

#[derive(Debug)]
struct Signing {
    request: RequestId,
    alg: SigningAlg,
    protected: Vec<u8>,

    /// Each assertion as a complete, framed JUMBF box: rendered once, hashed
    /// for the claim, and stored as-is.
    assertion_boxes: Vec<Vec<u8>>,
    claim_cbor: Vec<u8>,
}

/// Builds and signs a sidecar manifest store for an asset.
///
/// The session composes independent elements and owns none of their
/// knowledge: the hard binding is a [`DataHashSession`] it drives as a
/// sub-machine and forwards the requests of; the other assertions are opaque
/// [`EncodedAssertion`]s; the claim and its signature envelope come from
/// `contentauth-c2pa-claim`; every reference is a [`HashedUri`]. What is
/// left for the session itself is the order of operations, and the JUMBF.
#[derive(Debug)]
pub struct SidecarSession {
    settings: SidecarSettings,
    core: SessionCore<SidecarRequest>,
    state: State,
}

impl SidecarSession {
    /// Prepares to build a sidecar.
    pub fn new(settings: SidecarSettings) -> Self {
        Self {
            settings,
            core: SessionCore::default(),
            state: State::Start,
        }
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.settings.signing_alg.claim_hash_algorithm()
    }

    fn step(&mut self) -> Result<Option<Step>, Error> {
        match std::mem::replace(&mut self.state, State::Poisoned) {
            State::Start => {
                self.validate()?;
                let inner = DataHashSession::new(DataHashSettings::whole_asset(
                    ASSET_STREAM,
                    self.hash_alg(),
                ));
                self.state = State::Hashing(Box::new(Hashing {
                    inner,
                    forwarded: Vec::new(),
                }));
                Ok(None)
            }

            State::Hashing(mut hashing) => {
                // Hand the sub-session whatever the host has answered.
                let mut i = 0;
                while i < hashing.forwarded.len() {
                    let (ours, theirs) = hashing.forwarded[i];
                    match self.core.take_reply(ours) {
                        None => i += 1,
                        Some(reply) => {
                            let reply = match reply {
                                SidecarReply::AssetLength(n) => DataHashReply::AssetLength(n),
                                SidecarReply::AssetBytes(b) => DataHashReply::AssetBytes(b),
                                SidecarReply::Failed(e) => DataHashReply::Failed(e),
                                _ => return Err(ProtocolError::SessionFailed.into()),
                            };
                            hashing.inner.fulfill(theirs, reply)?;
                            hashing.forwarded.swap_remove(i);
                        }
                    }
                }

                match hashing.inner.advance()? {
                    Step::Complete => {
                        let data_hash = hashing.inner.finish()?;
                        self.sign_request(data_hash)
                    }
                    _ => {
                        // Forward requests the sub-session has newly made.
                        for request in hashing.inner.outstanding_requests() {
                            if hashing.forwarded.iter().any(|(_, t)| *t == request.id) {
                                continue;
                            }
                            let ours = self.core.issue(match &request.kind {
                                DataHashRequest::AssetLength { stream } => {
                                    SidecarRequest::AssetLength { stream: *stream }
                                }
                                DataHashRequest::AssetBytes { stream, range } => {
                                    SidecarRequest::AssetBytes {
                                        stream: *stream,
                                        range: *range,
                                    }
                                }
                                _ => return Err(ProtocolError::SessionFailed.into()),
                            });
                            hashing.forwarded.push((ours, request.id));
                        }
                        self.state = State::Hashing(hashing);
                        Ok(Some(Step::AwaitHost))
                    }
                }
            }

            State::AwaitingSignature(signing) => match self.core.take_reply(signing.request) {
                None => {
                    self.state = State::AwaitingSignature(signing);
                    Ok(Some(Step::AwaitHost))
                }
                Some(SidecarReply::Signature(sig)) => {
                    let report = self.finish_store(*signing, &sig)?;
                    self.state = State::Done(Box::new(report));
                    self.core.mark_complete();
                    Ok(Some(Step::Complete))
                }
                Some(SidecarReply::Failed(e)) => Err(Error::Host(e)),
                Some(_) => Err(ProtocolError::SessionFailed.into()),
            },

            State::Done(report) => {
                self.state = State::Done(report);
                Ok(Some(Step::Complete))
            }

            State::Poisoned => Err(ProtocolError::SessionFailed.into()),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.settings.certificates.is_empty() {
            return Err(Error::NoCertificates);
        }
        let mut seen = HashSet::from([contentauth_c2pa_assertion_data_hash::LABEL]);
        for a in &self.settings.assertions {
            if !seen.insert(a.label.as_str()) {
                return Err(Error::DuplicateLabel(a.label.clone()));
            }
        }
        Ok(())
    }

    /// Everything that can be done once the hard binding exists: hash every
    /// assertion, write the claim, and ask for its signature.
    fn sign_request(&mut self, data_hash: EncodedAssertion) -> Result<Option<Step>, Error> {
        let alg = self.settings.signing_alg;
        let hash_alg = self.hash_alg();

        let mut assertions = self.settings.assertions.clone();
        assertions.push(data_hash);

        let mut claim = Claim::new(
            self.settings.manifest_label.clone(),
            self.settings.instance_id.clone(),
            self.settings.generator.clone(),
            hash_alg,
        );
        if let Some(title) = &self.settings.title {
            claim = claim.with_title(title.clone());
        }
        let mut assertion_boxes = Vec::with_capacity(assertions.len());
        for a in &assertions {
            let rendered = store::assertion_box(&a.label, &a.cbor)?;
            claim = claim.with_created(HashedUri::from_box(
                assertion_uri(&a.label),
                hash_alg,
                false,
                &rendered,
            )?);
            assertion_boxes.push(rendered);
        }
        let claim_cbor = claim.encode()?;

        let protected = signature::protected_header(alg, &self.settings.certificates)?;
        let request = self.core.issue(SidecarRequest::Sign {
            alg,
            data: signature::to_be_signed(&protected, &claim_cbor),
        });
        self.state = State::AwaitingSignature(Box::new(Signing {
            request,
            alg,
            protected,
            assertion_boxes,
            claim_cbor,
        }));
        Ok(Some(Step::AwaitHost))
    }

    fn finish_store(&self, signing: Signing, sig: &[u8]) -> Result<SidecarReport, Error> {
        let cose = signature::assemble(signing.alg, &signing.protected, sig)?;
        Ok(SidecarReport {
            manifest_store: store::manifest_store(
                &self.settings.manifest_label,
                &signing.assertion_boxes,
                &signing.claim_cbor,
                &cose,
            )?,
            manifest_label: self.settings.manifest_label.clone(),
        })
    }
}

impl Session for SidecarSession {
    type Error = Error;
    type Output = SidecarReport;
    type Request = SidecarRequest;

    fn advance(&mut self) -> Result<Step, Error> {
        loop {
            match self.step() {
                Ok(Some(step)) => return Ok(step),
                Ok(None) => {}
                Err(e) => {
                    self.core.mark_failed();
                    return Err(e);
                }
            }
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<SidecarRequest>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: SidecarReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<SidecarReport, Error> {
        self.core.finish_check()?;
        match self.state {
            State::Done(report) => Ok(*report),
            _ => Err(ProtocolError::SessionNotComplete.into()),
        }
    }
}
