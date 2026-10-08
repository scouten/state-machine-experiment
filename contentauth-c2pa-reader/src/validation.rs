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

//! Validation findings, and the checks that produce them.
//!
//! Validation problems are *reported*, not thrown: a read workflow
//! produces a complete report wherever it can, recording what it found as
//! [`ValidationStatus`] entries in the vocabulary of the C2PA
//! specification. Errors are reserved for protocol misuse and structural
//! damage.
//!
//! # What is checked so far
//!
//! *Integrity* — that the manifest's own bytes hash to what the claim says
//! they should, and that the asset matches its hard binding — the *claim
//! signature*, verified in-core against the public key in the first
//! certificate of the signature's chain, and *trust*: the certificate chain
//! is validated against the host's anchors in the crate's `chain`
//! module.
//!
//! Those two are deliberately separated, and the seam is
//! `check_claim_signature`'s return value. A signature verifies against a
//! public key with nothing outside the manifest; a chain cannot be judged
//! without an instant to compare validity windows against, which only the
//! host can supply. So this module verifies what it can synchronously and
//! hands the decoded chain back for the session to evaluate once it has a
//! time.
//!
//! An RFC 3161 timestamp, where the signature carries one, decides *which*
//! instant the chain is judged against — see the crate's `timestamp`
//! module.
//!
//! Still missing, and capable of changing a verdict: revocation (OCSP and
//! CRL). A report can now reach [`ValidationState::Valid`] and
//! [`ValidationState::Trusted`], but only when the trust evaluation
//! actually ran — see [`ValidationState::Incomplete`].

use c2pa_raw_crypto::validator_for_signing_alg;
use contentauth_c2pa_primitives::HashAlgorithm;
use jumbf::parser::{DataBox, SuperBox};

use crate::{
    cert,
    chain::PendingChain,
    claim::Claim,
    cose::{self, TimestampHeader},
    manifest_store::CLAIM_V2_LABEL,
    timestamp::PendingTimestamp,
};

/// Label of a manifest's assertion store, used to anchor JUMBF URIs.
const ASSERTIONS_LABEL: &str = "c2pa.assertions";

/// The hash algorithm assumed when a claim names none.
const DEFAULT_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

/// C2PA validation status codes this core emits.
///
/// These strings are defined by the C2PA specification; they are not this
/// crate's invention, and they match the constants c2pa-rs uses.
pub mod status_code {
    /// A hashed URI's target hashed to the value the claim recorded.
    pub const ASSERTION_HASHEDURI_MATCH: &str = "assertion.hashedURI.match";

    /// A hashed URI's target did not hash to the value the claim recorded.
    pub const ASSERTION_HASHEDURI_MISMATCH: &str = "assertion.hashedURI.mismatch";

    /// A hashed URI pointed at a box that is not present in the store.
    pub const HASHED_URI_MISSING: &str = "hashedURI.missing";

    /// A hash algorithm was named that this core cannot compute, so the
    /// reference could not be checked either way.
    pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";

    /// The asset hashed to the value the hard binding recorded.
    pub const ASSERTION_DATAHASH_MATCH: &str = "assertion.dataHash.match";

    /// The asset did not hash to the value the hard binding recorded.
    pub const ASSERTION_DATAHASH_MISMATCH: &str = "assertion.dataHash.mismatch";

    /// The hard binding assertion could not be interpreted.
    pub const ASSERTION_DATAHASH_MALFORMED: &str = "assertion.dataHash.malformed";

    /// A v2 claim lacks a field the specification requires of it
    /// (`instanceID`, `signature`, `created_assertions`,
    /// `claim_generator_info`, or the latter's `name`).
    pub const CLAIM_MALFORMED: &str = "claim.malformed";

    /// A v2 claim's `redacted_assertions` names an assertion in the
    /// claim's own manifest, which a claim may not redact.
    pub const ASSERTION_SELF_REDACTED: &str = "assertion.selfRedacted";

    /// The claim signature verified against the signer's public key.
    ///
    /// This says the claim bytes are intact and were signed by the holder
    /// of that key. It says nothing about whether the key is *trusted* —
    /// that is a separate finding.
    pub const CLAIM_SIGNATURE_VALIDATED: &str = "claimSignature.validated";

    /// The claim signature did not verify against the signer's public key.
    pub const CLAIM_SIGNATURE_MISMATCH: &str = "claimSignature.mismatch";

    /// The manifest carries no claim signature box at all.
    pub const CLAIM_SIGNATURE_MISSING: &str = "claimSignature.missing";

    /// The signing credential could not be interpreted, or does not meet
    /// the C2PA certificate profile — an unreadable COSE structure, a
    /// certificate that is not well-formed X.509, a chain that does not
    /// link up, or a certificate used outside the purposes it names.
    pub const SIGNING_CREDENTIAL_INVALID: &str = "signingCredential.invalid";

    /// Every certificate in the signer's path was inside its validity
    /// window at the instant the chain was evaluated against.
    pub const CLAIM_SIGNATURE_INSIDE_VALIDITY: &str = "claimSignature.insideValidity";

    /// The signer's own certificate was outside its validity window.
    pub const CLAIM_SIGNATURE_OUTSIDE_VALIDITY: &str = "claimSignature.outsideValidity";

    /// A certificate above the signer in the path was outside its validity
    /// window.
    pub const SIGNING_CREDENTIAL_EXPIRED: &str = "signingCredential.expired";

    /// The signer's certificate chains to a configured trust anchor.
    pub const SIGNING_CREDENTIAL_TRUSTED: &str = "signingCredential.trusted";

    /// The signer's certificate does not chain to a configured trust
    /// anchor — including because none are configured. Also the code the
    /// C2PA specification names for a *different* finding this crate
    /// reports the same way: a CA certificate above the signer, found
    /// revoked by OCSP.
    ///
    /// The two are not equally severe, even though they share a code: an
    /// ordinary untrusted chain is not a failure (see
    /// [`super::ValidationStatus::is_failure`]) — a manifest with no
    /// configured trust anchors is meant to read as
    /// [`super::ValidationState::Valid`], not `Invalid`. A confirmed
    /// *revoked* CA certificate is different: §15.9's own text is explicit
    /// that "the claim signature shall be rejected with a failure status
    /// of `signingCredential.untrusted`" in that case. Since the code
    /// string alone cannot carry that distinction, the revoked-CA finding
    /// is built with a constructor that forces it to be treated as a
    /// failure regardless of code, instead of the plain one, in the read
    /// session's own revocation handling.
    pub const SIGNING_CREDENTIAL_UNTRUSTED: &str = "signingCredential.untrusted";

    /// A validly signed, timely OCSP response established that the
    /// *signer's own* certificate was not revoked at the time of signing
    /// (C2PA spec §15.9.1/§15.9.2).
    ///
    /// A finding, not merely a non-failure: reached only when a stapled or
    /// freshly fetched response actually satisfied the spec's acceptance
    /// conditions (`CertID` match, an authorized responder's signature,
    /// the right time window). See [`SIGNING_CREDENTIAL_OCSP_SKIPPED`],
    /// [`SIGNING_CREDENTIAL_OCSP_INACCESSIBLE`] and
    /// [`SIGNING_CREDENTIAL_OCSP_UNKNOWN`] for the ways nothing was
    /// established either way.
    pub const SIGNING_CREDENTIAL_OCSP_NOT_REVOKED: &str = "signingCredential.ocsp.notRevoked";

    /// A validly signed OCSP response established that the *signer's own*
    /// certificate had been revoked at the time of signing (C2PA spec
    /// §15.9.1/§15.9.2).
    ///
    /// Unlike [`SIGNING_CREDENTIAL_UNTRUSTED`] (used instead for a revoked
    /// certificate further up the path), this is a failure: the spec calls
    /// for the claim itself to be rejected when its own signer's
    /// credential is revoked — *when this is the active manifest's own
    /// chain*. The same code on an ingredient's chain is still recorded,
    /// but built so it does not count as a failure instead, since an
    /// ingredient's own revocation does not, by itself, invalidate the
    /// asset being read (see the read session's own revocation handling).
    pub const SIGNING_CREDENTIAL_OCSP_REVOKED: &str = "signingCredential.ocsp.revoked";

    /// The validator chose not to query an OCSP responder online for the
    /// signer's certificate — no stapled or in-store response resolved
    /// its status, and [`crate::read::ReadSettings::check_ocsp`] is
    /// `false`.
    ///
    /// Informational, not a failure: the C2PA specification makes the
    /// online query optional specifically because it can reveal the
    /// asset's identity to an observer (§15.9.2's own note).
    pub const SIGNING_CREDENTIAL_OCSP_SKIPPED: &str = "signingCredential.ocsp.skipped";

    /// The validator attempted to query an OCSP responder for the
    /// signer's certificate but could not obtain a usable response —
    /// unreachable, malformed, unauthenticated, or naming the wrong
    /// certificate.
    ///
    /// Informational, not a failure: this is exactly the fail-open case
    /// the C2PA specification's own offline-verification design goal
    /// requires. See [`crate::read::ReadSettings::check_ocsp`].
    pub const SIGNING_CREDENTIAL_OCSP_INACCESSIBLE: &str = "signingCredential.ocsp.inaccessible";

    /// An authenticated OCSP response for the signer's certificate
    /// reported `certStatus` as `unknown`.
    ///
    /// Informational, not a failure — the responder was reached and
    /// answered honestly; it simply does not know this certificate.
    pub const SIGNING_CREDENTIAL_OCSP_UNKNOWN: &str = "signingCredential.ocsp.unknown";

    /// The timestamp token is well-formed, its message imprint covers the
    /// right bytes, and the authority's certificates were inside their
    /// validity windows.
    pub const TIMESTAMP_VALIDATED: &str = "timeStamp.validated";

    /// The timestamping authority chains to a configured timestamp anchor.
    ///
    /// Only a trusted authority's `genTime` is used as the time of signing:
    /// an untrusted one could name any instant it liked.
    pub const TIMESTAMP_TRUSTED: &str = "timeStamp.trusted";

    /// The timestamping authority does not chain to a configured timestamp
    /// anchor — including because none are configured.
    pub const TIMESTAMP_UNTRUSTED: &str = "timeStamp.untrusted";

    /// The timestamp's message imprint does not cover this signature.
    pub const TIMESTAMP_MISMATCH: &str = "timeStamp.mismatch";

    /// The timestamp token could not be interpreted, or the authority's
    /// own credentials do not hold up.
    pub const TIMESTAMP_MALFORMED: &str = "timeStamp.malformed";

    /// A certificate in the timestamping authority's path was outside its
    /// validity window at the instant the token claims.
    pub const TIMESTAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";

    /// A check could not be carried out at all — for instance because the
    /// asset the hard binding covers was not available.
    pub const GENERAL_ERROR: &str = "general.error";

    /// A CAWG identity assertion's CBOR could not be interpreted.
    pub const CAWG_IDENTITY_CBOR_INVALID: &str = "cawg.identity.cbor.invalid";

    /// A CAWG identity assertion's `pad1` or `pad2` holds a byte other
    /// than zero.
    pub const CAWG_IDENTITY_PAD_INVALID: &str = "cawg.identity.pad.invalid";

    /// A CAWG identity assertion's `sig_type` is one this crate does not
    /// recognise at all.
    pub const CAWG_IDENTITY_SIG_TYPE_UNKNOWN: &str = "cawg.identity.sig_type.unknown";

    /// A CAWG identity assertion's `sig_type` names a credential type the
    /// CAWG specification defines but this crate cannot yet verify (today,
    /// identity claims aggregation).
    ///
    /// **Not a code from the CAWG specification** — this crate's own, so
    /// that "known, not checked" is not misreported as the spec's
    /// "unknown". Informational, never a failure.
    pub const CAWG_IDENTITY_SIG_TYPE_UNSUPPORTED: &str = "cawg.identity.sig_type.unsupported";

    /// A CAWG identity assertion references an assertion the claim does not
    /// list, or lists with a different hash.
    pub const CAWG_IDENTITY_ASSERTION_MISMATCH: &str = "cawg.identity.assertion.mismatch";

    /// A CAWG identity assertion references no hard binding assertion.
    pub const CAWG_IDENTITY_HARD_BINDING_MISSING: &str = "cawg.identity.hard_binding_missing";

    /// A CAWG identity assertion references the same assertion twice.
    pub const CAWG_IDENTITY_ASSERTION_DUPLICATE: &str = "cawg.identity.assertion.duplicate";

    /// A CAWG identity assertion passed every check of its own and its
    /// credential's.
    pub const CAWG_IDENTITY_WELL_FORMED: &str = "cawg.identity.well-formed";

    /// The X.509 signature over a CAWG identity assertion verified.
    pub const CAWG_X509_SIGNATURE_VALIDATED: &str = "cawg.x509.signature.validated";

    /// The X.509 signature over a CAWG identity assertion did not verify.
    pub const CAWG_X509_SIGNATURE_MISMATCH: &str = "cawg.x509.signature.mismatch";

    /// A certificate in the identity signer's path was outside its
    /// validity window at the instant of evaluation.
    pub const CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY: &str = "cawg.x509.signature.outside_validity";

    /// The identity signer's certificate chains to a configured CAWG trust
    /// anchor.
    pub const CAWG_X509_CREDENTIAL_TRUSTED: &str = "cawg.x509.credential.trusted";

    /// The identity signer's certificate does not chain to a configured
    /// CAWG trust anchor — including because none are configured.
    pub const CAWG_X509_CREDENTIAL_UNTRUSTED: &str = "cawg.x509.credential.untrusted";

    /// The identity signer's certificate, or its chain, is outside the
    /// certificate profile or cannot be interpreted.
    pub const CAWG_X509_CREDENTIAL_INVALID: &str = "cawg.x509.credential.invalid";

    /// The identity signature's algorithm has no validator in this build.
    pub const CAWG_X509_ALGORITHM_UNSUPPORTED: &str = "cawg.x509.algorithm.unsupported";
}

/// Overall validation outcome for a manifest store.
///
/// Mirrors `ValidationState` in c2pa-rs, plus [`Self::Incomplete`] for the
/// state this experiment is actually in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationState {
    /// Valid, and the signer's credential chains to a configured trust
    /// anchor.
    Trusted,

    /// Cryptographically valid, but the signer's credential is not on the
    /// configured trust list.
    Valid,

    /// Validation failed: at least one check came back negative.
    Invalid,

    /// Every check that ran passed, but the checks that ran are not
    /// sufficient to call the manifest valid.
    ///
    /// Reached when the active manifest's certificate chain was never
    /// evaluated — it carries no signature this core could read, or the
    /// host could not supply an instant to judge validity windows against.
    /// Treating `Incomplete` as if it were [`Self::Valid`] would assert
    /// something that has not been checked.
    Incomplete,
}

/// One validation status observation, in the vocabulary of the C2PA
/// specification's validation status codes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValidationStatus {
    /// Status code, e.g. `assertion.hashedURI.match`. See [`status_code`].
    pub code: String,

    /// JUMBF URI of the manifest store element the status pertains to.
    pub url: Option<String>,

    /// Human-readable explanation.
    pub explanation: Option<String>,

    /// On [`status_code::SIGNING_CREDENTIAL_TRUSTED`] and
    /// [`status_code::TIMESTAMP_TRUSTED`], the URI of the named trust list
    /// ([`TrustList::uri`]) whose anchor the credential chained to.
    ///
    /// `None` on every other status, and on a trusted one whose anchor was
    /// configured as a plain DER entry in
    /// [`ReadSettings::trust_anchors`] or
    /// [`ReadSettings::timestamp_trust_anchors`], which carry no identity.
    /// Mirrors c2pa-rs's `ValidationStatus::trust_list_uri`.
    ///
    /// [`TrustList::uri`]: crate::read::TrustList::uri
    /// [`ReadSettings::trust_anchors`]: crate::read::ReadSettings::trust_anchors
    /// [`ReadSettings::timestamp_trust_anchors`]: crate::read::ReadSettings::timestamp_trust_anchors
    pub trust_list_uri: Option<String>,

    /// Overrides [`Self::is_failure`] to this value, regardless of
    /// [`Self::code`], when set.
    ///
    /// Two circumstances need this, both because a single code string is
    /// shared between two findings of different severity:
    ///
    /// * A CA certificate confirmed revoked by OCSP is reported under
    ///   [`status_code::SIGNING_CREDENTIAL_UNTRUSTED`] — the same code an
    ///   ordinary chain that simply does not reach a trust anchor also
    ///   carries — but, unlike that ordinary case, C2PA spec §15.9 calls
    ///   for the claim signature itself to be rejected when it is *this*
    ///   chain's own confirmed revocation, not merely a missing anchor.
    ///   See [`Self::for_url_forcing_failure`].
    /// * A revoked *signer* certificate on an ingredient's chain is
    ///   reported under [`status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`]
    ///   — normally always a failure — but an ingredient's own revocation
    ///   does not, by itself, invalidate the asset being read (see
    ///   [`crate::read::ReadSession`]'s own `is_active` field). See
    ///   [`Self::for_url_suppressing_failure`].
    is_failure_override: Option<bool>,
}

impl ValidationStatus {
    /// Builds a status for a specific JUMBF URI.
    pub(crate) fn for_url(code: &str, url: &str, explanation: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            url: Some(url.to_string()),
            explanation: Some(explanation.into()),
            trust_list_uri: None,
            is_failure_override: None,
        }
    }

    /// As [`Self::for_url`], but [`Self::is_failure`] reports `true`
    /// regardless of `code` — see [`Self::is_failure_override`].
    pub(crate) fn for_url_forcing_failure(
        code: &str,
        url: &str,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            is_failure_override: Some(true),
            ..Self::for_url(code, url, explanation)
        }
    }

    /// As [`Self::for_url`], but [`Self::is_failure`] reports `false`
    /// regardless of `code` — see [`Self::is_failure_override`].
    pub(crate) fn for_url_suppressing_failure(
        code: &str,
        url: &str,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            is_failure_override: Some(false),
            ..Self::for_url(code, url, explanation)
        }
    }

    /// True if this status records a failed check.
    ///
    /// Statuses that record an *unperformed* check (a missing target, an
    /// algorithm the core cannot compute) are deliberately not failures:
    /// they mean "not checked", which is weaker than "checked and wrong".
    ///
    /// [`status_code::SIGNING_CREDENTIAL_UNTRUSTED`] is also not a failure
    /// by itself, for a different reason: usually the check ran and came
    /// back negative because the signer is absent from *this verifier's*
    /// anchor list. That is a statement about the configuration, not about
    /// the manifest, and treating it as a failure would make
    /// [`ValidationState::Valid`] — defined as "cryptographically valid,
    /// but not on the configured trust list" — unreachable. (c2pa-rs
    /// classifies the same code as a failure in `log_kind` and then
    /// excludes it again where the state is computed; this crate draws the
    /// line once, here.) A revoked-CA finding carrying that same code
    /// overrides this by forcing failure regardless of code, since that
    /// circumstance is not the ordinary one — and a revoked ingredient
    /// signer overrides the reverse way, since
    /// [`status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`] is otherwise
    /// always a failure but an ingredient's own revocation must not, by
    /// itself, invalidate the asset being read.
    pub fn is_failure(&self) -> bool {
        if let Some(is_failure) = self.is_failure_override {
            return is_failure;
        }

        matches!(
            self.code.as_str(),
            status_code::ASSERTION_HASHEDURI_MISMATCH
                | status_code::ASSERTION_DATAHASH_MISMATCH
                | status_code::ASSERTION_DATAHASH_MALFORMED
                | status_code::CLAIM_MALFORMED
                | status_code::ASSERTION_SELF_REDACTED
                | status_code::CLAIM_SIGNATURE_MISMATCH
                | status_code::CLAIM_SIGNATURE_MISSING
                | status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY
                | status_code::SIGNING_CREDENTIAL_INVALID
                | status_code::SIGNING_CREDENTIAL_EXPIRED
                | status_code::SIGNING_CREDENTIAL_OCSP_REVOKED
                | status_code::CAWG_IDENTITY_CBOR_INVALID
                | status_code::CAWG_IDENTITY_PAD_INVALID
                | status_code::CAWG_IDENTITY_SIG_TYPE_UNKNOWN
                | status_code::CAWG_IDENTITY_ASSERTION_MISMATCH
                | status_code::CAWG_IDENTITY_HARD_BINDING_MISSING
                | status_code::CAWG_IDENTITY_ASSERTION_DUPLICATE
                | status_code::CAWG_X509_SIGNATURE_MISMATCH
                | status_code::CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY
                | status_code::CAWG_X509_CREDENTIAL_INVALID
        )
    }

    /// True if this status is a finding about a CAWG identity assertion
    /// (`cawg.identity.*` or `cawg.x509.*`).
    ///
    /// A failure among these is scoped to the one identity assertion it
    /// names: it says that named actor's claim is not to be believed, and
    /// says nothing about the content credential itself, whose own
    /// signature and hard binding are checked separately. It therefore
    /// counts as a failure ([`Self::is_failure`]) but never lowers the
    /// store's [`ValidationState`] — see [`Self::affects_validation_state`].
    pub fn is_identity_finding(&self) -> bool {
        self.code.starts_with("cawg.identity.") || self.code.starts_with("cawg.x509.")
    }

    /// True if this status, being a failure, takes the store's
    /// [`ValidationState`] down to [`ValidationState::Invalid`].
    ///
    /// Every failure does except a CAWG identity finding, whose blast
    /// radius is only its own assertion (the same rule c2pa-rs applies).
    pub fn affects_validation_state(&self) -> bool {
        self.is_failure() && !self.is_identity_finding()
    }

    /// True if this status records a check that could not be carried out.
    ///
    /// The complement of [`Self::is_failure`] among the negative findings:
    /// these say *nothing was learned*, which is neither a pass nor a
    /// failure. A report carrying one cannot reach
    /// [`ValidationState::Valid`], because some part of what "valid" would
    /// assert was never established — an asset that was not available to
    /// hash, a digest algorithm this core cannot compute, an assertion the
    /// claim points at but the store does not contain.
    /// Timestamp findings are in neither class, and deliberately so. A
    /// broken or untrusted timestamp does not invalidate a manifest and
    /// does not leave a check unperformed: its only consequence is that
    /// the certificate chain falls back to being judged against the host's
    /// current time. The report says what was found either way.
    pub fn is_unchecked(&self) -> bool {
        matches!(
            self.code.as_str(),
            status_code::ALGORITHM_UNSUPPORTED
                | status_code::HASHED_URI_MISSING
                | status_code::GENERAL_ERROR
        )
    }
}

/// What a manifest offers in place of a claim signature.
///
/// Three states rather than an `Option`, because "no signature box" and "a
/// signature box holding nothing" are different findings: the first is a
/// missing signature, the second an unreadable one. Collapsing them
/// produces a report that calls a signature missing from a manifest whose
/// own `has_signature` says otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureBox<'a> {
    /// The manifest carries no claim signature superbox.
    Absent,

    /// It carries one, but the box holds no COSE content.
    Empty,

    /// The `COSE_Sign1` bytes.
    Present(&'a [u8]),
}

/// Verifies a manifest's claim signature against the signer's public key,
/// and returns the chain it carried for the session to evaluate.
///
/// The signature is a detached-payload `COSE_Sign1`: the bytes it commits
/// to are the claim's, which live in a sibling JUMBF box, so both are
/// needed here.
///
/// # What this establishes, and what it does not
///
/// A [`status_code::CLAIM_SIGNATURE_VALIDATED`] means the claim bytes are
/// intact and were signed by whoever holds the key in the first
/// certificate of the chain. It does **not** mean the signer is trusted —
/// that is [`crate::chain::validate`]'s answer, and it needs an instant
/// this function has no way to obtain.
///
/// # Why the chain comes back only when the signature verified
///
/// A [`PendingChain`] is returned only for a signature that checked out.
/// Establishing whose key signed a claim is pointless when the signature
/// says the claim was not signed with that key at all: the chain could
/// reach an impeccable anchor and the manifest would still be broken. The
/// verdict is already [`ValidationState::Invalid`] at that point, so the
/// trust evaluation is skipped rather than run to produce statuses that
/// could only mislead.
pub(crate) fn check_claim_signature(
    manifest_label: &str,
    claim_bytes: &[u8],
    signature: SignatureBox<'_>,
    statuses: &mut Vec<ValidationStatus>,
) -> Option<PendingChain> {
    let url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature");

    let signature = match signature {
        SignatureBox::Present(bytes) => bytes,

        SignatureBox::Absent => {
            statuses.push(ValidationStatus::for_url(
                status_code::CLAIM_SIGNATURE_MISSING,
                &url,
                "manifest carries no claim signature box",
            ));
            return None;
        }

        // Distinct from `Absent`: the manifest does carry a signature box,
        // so reporting the signature as *missing* would contradict the
        // manifest's own shape. What is wrong is that the box holds
        // nothing readable.
        SignatureBox::Empty => {
            statuses.push(ValidationStatus::for_url(
                status_code::SIGNING_CREDENTIAL_INVALID,
                &url,
                "claim signature box carries no COSE content",
            ));
            return None;
        }
    };

    let verified = check_cose_signature(
        &url,
        claim_bytes,
        signature,
        &CLAIM_SIGNATURE_CODES,
        statuses,
    )?;

    Some(PendingChain {
        manifest_label: manifest_label.to_string(),
        url,
        certificates: verified.certificates,
        timestamp: verified.timestamp,
        rvals: verified.rvals,
    })
}

/// The status vocabulary one detached-payload `COSE_Sign1` check reports
/// under.
///
/// A claim signature and a CAWG identity assertion's X.509 signature are
/// the same construction — a `COSE_Sign1` over a payload that lives
/// elsewhere, signed by the first certificate of an `x5chain` — but the
/// specifications name their findings differently, so the checks are
/// shared and the codes are a parameter, as they are for
/// [`crate::chain::Vocabulary`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct SignatureCodes {
    /// What the signature is a signature *of*, for explanations.
    pub(crate) noun: &'static str,

    /// The structure or certificates cannot be interpreted.
    pub(crate) invalid: &'static str,

    /// The signature verified.
    pub(crate) validated: &'static str,

    /// It did not.
    pub(crate) mismatch: &'static str,

    /// The algorithm has no validator in this build.
    pub(crate) unsupported: &'static str,
}

/// The claim signature's vocabulary.
const CLAIM_SIGNATURE_CODES: SignatureCodes = SignatureCodes {
    noun: "claim signature",
    invalid: status_code::SIGNING_CREDENTIAL_INVALID,
    validated: status_code::CLAIM_SIGNATURE_VALIDATED,
    mismatch: status_code::CLAIM_SIGNATURE_MISMATCH,
    unsupported: status_code::ALGORITHM_UNSUPPORTED,
};

/// The CAWG X.509 identity signature's vocabulary.
pub(crate) const CAWG_X509_SIGNATURE_CODES: SignatureCodes = SignatureCodes {
    noun: "identity assertion signature",
    invalid: status_code::CAWG_X509_CREDENTIAL_INVALID,
    validated: status_code::CAWG_X509_SIGNATURE_VALIDATED,
    mismatch: status_code::CAWG_X509_SIGNATURE_MISMATCH,
    unsupported: status_code::CAWG_X509_ALGORITHM_UNSUPPORTED,
};

/// What a verified detached-payload `COSE_Sign1` leaves for the session to
/// evaluate once it has a time.
#[derive(Debug)]
pub(crate) struct VerifiedSignature {
    /// The decoded chain, signer first.
    pub(crate) certificates: Vec<cert::Certificate>,

    /// The RFC 3161 timestamp on the signature, if it carried a readable
    /// one.
    pub(crate) timestamp: Option<PendingTimestamp>,

    /// Stapled OCSP responses from the `rVals` header.
    pub(crate) rvals: Vec<Vec<u8>>,
}

/// Verifies a detached-payload `COSE_Sign1` against the public key in the
/// first certificate of its `x5chain`, recording one status under `url`.
///
/// Returns the chain and timestamp only for a signature that verified; see
/// [`check_claim_signature`] for why nothing is returned otherwise.
pub(crate) fn check_cose_signature(
    url: &str,
    payload: &[u8],
    signature: &[u8],
    codes: &SignatureCodes,
    statuses: &mut Vec<ValidationStatus>,
) -> Option<VerifiedSignature> {
    let signature = match cose::parse(signature) {
        Ok(signature) => signature,
        Err(reason) => {
            statuses.push(ValidationStatus::for_url(codes.invalid, url, reason));
            return None;
        }
    };

    // The whole chain is decoded here, not just the signer: a chain with an
    // undecodable certificate in it cannot be walked, and finding that out
    // now keeps the failure in one place instead of splitting it between
    // this check and the trust evaluation.
    let mut certificates = Vec::with_capacity(signature.certificates.len());
    for (position, der) in signature.certificates.iter().enumerate() {
        match cert::decode(der) {
            Ok(certificate) => certificates.push(certificate),
            Err(error) => {
                statuses.push(ValidationStatus::for_url(
                    codes.invalid,
                    url,
                    // Position 0 is the signer's own certificate (RFC 9360
                    // §2); the rest are named by index so a report says
                    // which link of the chain is unreadable.
                    if position == 0 {
                        format!("signer certificate: {error}")
                    } else {
                        format!("certificate {position} in the chain: {error}")
                    },
                ));
                return None;
            }
        }
    }

    // The signer's own certificate is first in the chain (RFC 9360 §2).
    let signer = certificates.first()?;

    let Some(validator) = validator_for_signing_alg(signature.alg.raw()) else {
        // Unreachable in this crate's build: `cose::parse` refuses any
        // algorithm outside the C2PA set, and
        // `types::tests::every_algorithm_maps_to_a_backend_validator`
        // pins that all seven of those have a validator. It survives for
        // the configuration where the backend is compiled with no
        // cryptography feature at all, in which case every lookup returns
        // `None` — and reporting that as "not checked" is the honest
        // answer, where reporting a mismatch would not be.
        statuses.push(ValidationStatus::for_url(
            codes.unsupported,
            url,
            format!("no validator available for {:?}", signature.alg),
        ));
        return None;
    };

    let to_be_signed = signature.to_be_signed(payload);

    match validator.validate(&signature.signature, &to_be_signed, &signer.public_key) {
        Ok(()) => {
            statuses.push(ValidationStatus::for_url(
                codes.validated,
                url,
                format!("{} verified against the signer's certificate", codes.noun),
            ));

            // The timestamp is taken off the header here, where the
            // protected bucket and the payload are still in hand: what a
            // token has to cover is built from both, and neither survives
            // to where the token is checked.
            let timestamp = match &signature.timestamp {
                TimestampHeader::Absent => None,

                TimestampHeader::Malformed(reason) => {
                    statuses.push(ValidationStatus::for_url(
                        status_code::TIMESTAMP_MALFORMED,
                        url,
                        *reason,
                    ));
                    None
                }

                TimestampHeader::Present { token, storage } => Some(PendingTimestamp {
                    token: token.clone(),
                    storage: *storage,
                    countersigned: signature.countersigned(payload, *storage),
                }),
            };

            Some(VerifiedSignature {
                certificates,
                timestamp,
                rvals: signature.rvals,
            })
        }

        Err(_) => {
            statuses.push(ValidationStatus::for_url(
                codes.mismatch,
                url,
                format!(
                    "{} does not verify against the signer's certificate",
                    codes.noun
                ),
            ));
            None
        }
    }
}

/// Checks a decoded claim against the field requirements the C2PA
/// specification places on a v2 claim, appending a failure per violation.
///
/// A v1 claim is not held to these (see
/// [`Claim::missing_required_fields`]); the one check that applies to
/// either version's `redacted_assertions` is that a claim never redacts
/// its own manifest's assertions.
pub(crate) fn check_claim_fields(
    manifest_label: &str,
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
) {
    let claim_url = format!("self#jumbf=/c2pa/{manifest_label}/{CLAIM_V2_LABEL}");

    let missing = claim.missing_required_fields();
    if !missing.is_empty() {
        statuses.push(ValidationStatus::for_url(
            status_code::CLAIM_MALFORMED,
            &claim_url,
            format!("claim is missing required field(s): {}", missing.join(", ")),
        ));
    }

    let own_prefix = format!("/c2pa/{manifest_label}/");
    for uri in &claim.redacted_assertions {
        let path = uri.rsplit_once('=').map_or(uri.as_str(), |(_, path)| path);

        // A relative reference resolves inside the claim's own manifest;
        // an absolute one does only when it names that manifest's label.
        if !path.starts_with('/') || path.starts_with(&own_prefix) {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_SELF_REDACTED,
                uri,
                "claim redacts an assertion in its own manifest",
            ));
        }
    }
}

/// Verifies every hashed URI in `claim` against the bytes actually present
/// in `manifest`, appending a status per reference.
///
/// The hash covers the referenced assertion's **superbox payload** — its
/// description box (including any salt) and content boxes, but not the
/// superbox's own header. This matches `Claim::calc_assertion_box_hash` in
/// c2pa-rs, and is verified against a real c2pa-rs-written manifest in
/// `tests/read_fixture.rs`.
pub(crate) fn check_assertion_hashes(
    manifest: &SuperBox<'_>,
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
) {
    let claim_algorithm = claim.alg.as_deref();

    for reference in claim.hashed_references() {
        let named = reference.alg.as_deref().or(claim_algorithm);

        // A claim that names no algorithm gets the specification's
        // default; one that names an algorithm we cannot compute is
        // reported rather than quietly checked with a different one.
        let algorithm = match named {
            None => DEFAULT_ALGORITHM,
            Some(name) => match HashAlgorithm::from_c2pa_name(name) {
                Some(algorithm) => algorithm,
                None => {
                    statuses.push(ValidationStatus::for_url(
                        status_code::ALGORITHM_UNSUPPORTED,
                        &reference.url,
                        format!("hash algorithm {name:?} is not supported"),
                    ));
                    continue;
                }
            },
        };

        let Some(payload) = assertion_payload(manifest, &reference.url) else {
            statuses.push(ValidationStatus::for_url(
                status_code::HASHED_URI_MISSING,
                &reference.url,
                "no assertion box with this URI is present in the manifest",
            ));
            continue;
        };

        let actual = algorithm.digest(payload);

        if actual == reference.hash {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_HASHEDURI_MATCH,
                &reference.url,
                "assertion hashed as recorded in the claim",
            ));
        } else {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_HASHEDURI_MISMATCH,
                &reference.url,
                "assertion does not hash to the value recorded in the claim",
            ));
        }
    }
}

/// Resolves a claim's hashed URI to the referenced assertion's superbox
/// payload.
fn assertion_payload<'a>(manifest: &SuperBox<'a>, url: &str) -> Option<&'a [u8]> {
    let assertion = manifest.find_by_label(assertion_path(url)?)?;

    // `original` is the whole `jumb` box; re-reading its header yields the
    // payload, which is what the hash covers. Deriving it this way reuses
    // the parser's header handling instead of assuming a header width.
    let (boxx, _rest) = DataBox::from_slice(assertion.original).ok()?;
    Some(boxx.data)
}

/// Extracts the assertion-store-relative path from a JUMBF URI.
///
/// Handles both the relative form a claim normally uses
/// (`self#jumbf=c2pa.assertions/<label>`) and the absolute form
/// (`self#jumbf=/c2pa/<manifest>/c2pa.assertions/<label>`), by anchoring on
/// the assertion store's label.
pub(crate) fn assertion_path(url: &str) -> Option<&str> {
    let path = url.rsplit_once('=').map_or(url, |(_, path)| path);
    let start = path.find(ASSERTIONS_LABEL)?;
    Some(&path[start..])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use c2pa_cbor::Value;

    use super::*;
    use crate::{
        manifest_store::{self, ParsedManifestStore},
        test_support::{
            self, claim_box, manifest_with_broken_signature, manifest_with_empty_signature_box,
            manifest_without_signature_box, TEST_SIGNER_CERT,
        },
    };

    #[test]
    fn extracts_assertion_paths_from_both_uri_forms() {
        assert_eq!(
            assertion_path("self#jumbf=c2pa.assertions/c2pa.actions"),
            Some("c2pa.assertions/c2pa.actions")
        );
        assert_eq!(
            assertion_path("self#jumbf=/c2pa/urn:uuid:abc/c2pa.assertions/c2pa.hash.data"),
            Some("c2pa.assertions/c2pa.hash.data")
        );

        // A URI that names something other than an assertion has no
        // assertion path.
        assert_eq!(assertion_path("self#jumbf=c2pa.signature"), None);
        assert_eq!(assertion_path(""), None);
    }

    #[test]
    fn only_mismatches_count_as_failures() {
        let failure = ValidationStatus::for_url(
            status_code::ASSERTION_HASHEDURI_MISMATCH,
            "self#jumbf=x",
            "",
        );
        assert!(failure.is_failure());

        // "Not checked" is weaker than "checked and wrong".
        for code in [
            status_code::ASSERTION_HASHEDURI_MATCH,
            status_code::HASHED_URI_MISSING,
            status_code::ALGORITHM_UNSUPPORTED,
        ] {
            assert!(
                !ValidationStatus::for_url(code, "self#jumbf=x", "").is_failure(),
                "{code} should not be a failure"
            );
        }
    }

    /// Runs the signature check over a manifest built by `build`, and
    /// returns the codes it recorded.
    fn signature_codes(manifest_bytes: Vec<u8>) -> Vec<String> {
        let parsed =
            manifest_store::parse(&test_support::manifest_store(&[manifest_bytes])).unwrap();

        signature_codes_of(&parsed)
    }

    /// The signature-related status codes a parsed store recorded.
    fn signature_codes_of(parsed: &ParsedManifestStore) -> Vec<String> {
        parsed
            .statuses
            .iter()
            .filter(|s| s.code.starts_with("claimSignature") || s.code.starts_with("signing"))
            .map(|s| s.code.clone())
            .collect()
    }

    #[test]
    fn a_signature_over_different_bytes_is_a_mismatch() {
        let codes = signature_codes(manifest_with_broken_signature(
            "urn:uuid:broken",
            &[],
            claim_box("broken.jpg"),
        ));

        assert_eq!(codes, [status_code::CLAIM_SIGNATURE_MISMATCH]);
    }

    #[test]
    fn signature_findings_are_failures_but_unsupported_is_not() {
        let mismatch = ValidationStatus::for_url(status_code::CLAIM_SIGNATURE_MISMATCH, "u", "");
        let missing = ValidationStatus::for_url(status_code::CLAIM_SIGNATURE_MISSING, "u", "");
        let invalid = ValidationStatus::for_url(status_code::SIGNING_CREDENTIAL_INVALID, "u", "");
        let validated = ValidationStatus::for_url(status_code::CLAIM_SIGNATURE_VALIDATED, "u", "");

        assert!(mismatch.is_failure());
        assert!(missing.is_failure());
        assert!(invalid.is_failure());
        assert!(!validated.is_failure());
    }

    #[test]
    fn a_missing_signature_box_is_reported() {
        let mut statuses = Vec::new();
        check_claim_signature("urn:uuid:x", b"claim", SignatureBox::Absent, &mut statuses);

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].code, status_code::CLAIM_SIGNATURE_MISSING);
        assert_eq!(
            statuses[0].url.as_deref(),
            Some("self#jumbf=/c2pa/urn:uuid:x/c2pa.signature")
        );
    }

    #[test]
    fn a_present_but_empty_signature_box_is_not_reported_as_missing() {
        // Driven through the real manifest walk, because the point of the
        // distinction is that it must agree with `Manifest::has_signature`
        // — which only the walk sets.
        let parsed = manifest_store::parse(&test_support::manifest_store(&[
            manifest_with_empty_signature_box("urn:uuid:empty", claim_box("empty.jpg")),
        ]))
        .unwrap();

        assert!(
            parsed.manifests[0].has_signature,
            "the manifest does carry a signature box"
        );
        assert_eq!(
            signature_codes_of(&parsed),
            [status_code::SIGNING_CREDENTIAL_INVALID],
            "a signature box that is present but unreadable is not a missing one"
        );

        // And the contrasting case: genuinely no signature box, which is
        // the finding the empty box must not be confused with.
        let parsed = manifest_store::parse(&test_support::manifest_store(&[
            manifest_without_signature_box("urn:uuid:none", claim_box("none.jpg")),
        ]))
        .unwrap();

        assert!(!parsed.manifests[0].has_signature);
        assert_eq!(
            signature_codes_of(&parsed),
            [status_code::CLAIM_SIGNATURE_MISSING]
        );
    }

    #[test]
    fn an_unreadable_signature_is_an_invalid_credential() {
        let mut statuses = Vec::new();
        check_claim_signature(
            "urn:uuid:x",
            b"claim",
            SignatureBox::Present(&[0xff, 0xff]),
            &mut statuses,
        );

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].code, status_code::SIGNING_CREDENTIAL_INVALID);
    }

    /// Builds a well-formed `COSE_Sign1` over a garbage signature, whose
    /// `x5chain` carries exactly the given entries.
    fn signature_with_chain(chain: Value) -> Vec<u8> {
        let mut protected = BTreeMap::new();
        protected.insert(Value::Integer(1), Value::Integer(-7));
        protected.insert(Value::Integer(33), chain);
        let protected = c2pa_cbor::to_vec(&Value::Map(protected)).unwrap();

        c2pa_cbor::to_vec(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(BTreeMap::new()),
                Value::Null,
                Value::Bytes(vec![0u8; 64]),
            ])),
        ))
        .unwrap()
    }

    #[test]
    fn a_signature_carrying_a_junk_certificate_is_an_invalid_credential() {
        // Well-formed COSE, but the x5chain entry is not a certificate.
        let signature = signature_with_chain(Value::Bytes(vec![0u8; 16]));

        let mut statuses = Vec::new();
        check_claim_signature(
            "urn:uuid:x",
            b"claim",
            SignatureBox::Present(&signature),
            &mut statuses,
        );

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].code, status_code::SIGNING_CREDENTIAL_INVALID);
        assert!(statuses[0]
            .explanation
            .as_deref()
            .unwrap()
            .contains("signer certificate"));
    }

    #[test]
    fn an_undecodable_certificate_further_up_the_chain_names_its_position() {
        // A perfectly good signer, followed by an entry that is not a
        // certificate. The signature could still be verified against the
        // signer's key — but the chain could never be walked, so the
        // finding is about the credential rather than about the signature,
        // and it says which link is unreadable.
        let signature = signature_with_chain(Value::Array(vec![
            Value::Bytes(TEST_SIGNER_CERT.to_vec()),
            Value::Bytes(vec![0u8; 16]),
        ]));

        let mut statuses = Vec::new();
        let chain = check_claim_signature(
            "urn:uuid:x",
            b"claim",
            SignatureBox::Present(&signature),
            &mut statuses,
        );

        assert!(chain.is_none());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].code, status_code::SIGNING_CREDENTIAL_INVALID);
        assert_eq!(
            statuses[0].explanation.as_deref(),
            Some("certificate 1 in the chain: not a well-formed X.509 certificate")
        );
    }

    #[test]
    fn a_malformed_timestamp_header_is_reported_but_does_not_spoil_the_signature() {
        // A `sigTst` value this crate cannot read as a timestamp header —
        // distinct from every other test here, which sends a genuinely
        // *broken* signature through: this one verifies just fine, and
        // only its optional timestamp is unreadable.
        let unprotected = Value::Map(BTreeMap::from([(
            Value::Text("sigTst".to_string()),
            Value::Null,
        )]));
        let signature = test_support::claim_signature_with_unprotected(b"claim", unprotected);

        let mut statuses = Vec::new();
        let chain = check_claim_signature(
            "urn:uuid:x",
            b"claim",
            SignatureBox::Present(&signature),
            &mut statuses,
        );

        // The signature itself still verifies.
        let chain = chain.unwrap();
        assert!(
            chain.timestamp.is_none(),
            "an unreadable timestamp is not carried forward as a pending one"
        );

        assert_eq!(
            statuses.iter().map(|s| s.code.as_str()).collect::<Vec<_>>(),
            [
                status_code::CLAIM_SIGNATURE_VALIDATED,
                status_code::TIMESTAMP_MALFORMED
            ]
        );
        assert_eq!(
            statuses[1].explanation.as_deref(),
            Some("timestamp header is not a map")
        );
    }

    #[test]
    fn stapled_ocsp_responses_are_carried_onto_the_pending_chain() {
        let mut ocsp_vals = BTreeMap::new();
        ocsp_vals.insert(
            Value::Text("ocspVals".to_string()),
            Value::Array(vec![Value::Bytes(vec![1, 2, 3])]),
        );
        let unprotected = Value::Map(BTreeMap::from([(
            Value::Text("rVals".to_string()),
            Value::Map(ocsp_vals),
        )]));
        let signature = test_support::claim_signature_with_unprotected(b"claim", unprotected);

        let mut statuses = Vec::new();
        let chain = check_claim_signature(
            "urn:uuid:x",
            b"claim",
            SignatureBox::Present(&signature),
            &mut statuses,
        )
        .unwrap();

        assert_eq!(chain.rvals, vec![vec![1, 2, 3]]);
        assert_eq!(
            statuses.iter().map(|s| s.code.as_str()).collect::<Vec<_>>(),
            [status_code::CLAIM_SIGNATURE_VALIDATED]
        );
    }
}
