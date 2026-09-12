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

//! Certificate path building, chain validation, and trust anchors.
//!
//! A verified claim signature says the claim was signed by whoever holds the
//! key in the first certificate of its chain. This module answers the next
//! question: *whose key is that?* It builds a path from the signer's
//! certificate up through the chain the signature carries, verifies that
//! each certificate really was signed by the one above it, holds each to the
//! part of the C2PA certificate profile that applies to its position, and
//! reports whether the path terminates at an anchor the host configured.
//!
//! # Why the evaluation time comes from outside
//!
//! Validity windows have to be compared against *something*, and the core
//! reads no clock. The instant is supplied by the host, which is also what
//! makes "this certificate expired" testable without shipping a fixture
//! that rots.
//!
//! Which instant that is depends on what the signature carries. C2PA judges
//! a signing certificate against the *time of signing*, established by an
//! RFC 3161 timestamp countersigned by a trusted authority: when
//! [`crate::timestamp`] can produce one, that is the instant used here, and
//! a manifest signed years ago with a since-expired certificate still reads
//! as valid. Without a usable timestamp there is nothing to fall back on but
//! the host's current time, which is stricter than the specification — and
//! is why a timestamp is worth carrying.
//!
//! # What is checked, and what is not
//!
//! Checked: path construction, per-certificate signature verification,
//! validity windows, the `cA` / `keyCertSign` / `pathLenConstraint`
//! constraints on issuing certificates, the C2PA end-entity profile (key
//! usage and extended key usage), and termination at a configured anchor.
//!
//! Revocation is checked, but only OCSP (the C2PA specification does not
//! permit CRLs) and only for a claim signer's own chain — see
//! [`ocsp_checks`] and [`crate::ocsp`], and [`crate::read::ReadSession`]
//! for how a pending check becomes a host round trip. It is deliberately
//! separate from [`validate`] itself: [`validate`] is synchronous, and an
//! OCSP check is not.
//!
//! Not checked, and each is a real gap rather than an oversight: name
//! constraints, policy constraints and policy mappings, unhandled critical
//! extensions, the certificate version and unique-ID rules, the
//! signature-algorithm and named-curve allowlists, and the RSA minimum
//! modulus size. The last three want detail that [`crate::cert::Certificate`]
//! does not surface today; the rest want machinery this crate does not have
//! yet.

use core::iter::once;

use c2pa_raw_crypto::{validator_for_sig_and_hash_algs, Oid};

use crate::{
    cert::Certificate,
    timestamp::PendingTimestamp,
    validation::{status_code, ValidationStatus},
};

/// A claim signature's certificate chain, held until the host supplies an
/// instant to evaluate it against.
///
/// Produced while reading a manifest store, consumed once the read session
/// has a time. It carries the manifest's label so that the outcome can be
/// attributed to the right manifest, and the signature box's URI so that
/// every status it produces points where the others do.
#[derive(Clone, Debug)]
pub(crate) struct PendingChain {
    /// JUMBF label of the manifest whose claim signature carried the chain.
    pub(crate) manifest_label: String,

    /// JUMBF URI of that manifest's claim signature box.
    pub(crate) url: String,

    /// The decoded chain, signer first.
    pub(crate) certificates: Vec<Certificate>,

    /// The RFC 3161 timestamp on the signature, if it carried one this
    /// core could take off the header.
    ///
    /// Checked before the chain, because a trusted one supplies the
    /// instant the chain is then judged against.
    pub(crate) timestamp: Option<PendingTimestamp>,

    /// DER-encoded `OCSPResponse` values "stapled" into the signature's
    /// `rVals` COSE header (C2PA spec §15.9.1), if it carried any.
    ///
    /// Always empty today: [`crate::cose`] does not read this header yet
    /// (its CBOR shape is not yet confirmed against the specification), so
    /// every chain reads as though it carried no staples — [`crate::ocsp::evaluate_stapled`]
    /// is exercised directly by this crate's own tests in the meantime,
    /// and [`crate::read::ReadSession`] already tries whatever is here
    /// before ever asking a host to query a responder online.
    pub(crate) rvals: Vec<Vec<u8>>,
}

/// The status codes one chain evaluation reports its findings under.
///
/// The rules for building and checking a path are the same whether the
/// credential at the bottom signed a claim or stamped a time — but the C2PA
/// status vocabulary names the two sets of findings differently. Rather
/// than duplicate the checks, the status code vocabulary is a parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Vocabulary {
    /// The path is broken, or a certificate is outside the profile.
    pub(crate) invalid: &'static str,

    /// Every certificate in the path was inside its validity window.
    pub(crate) inside_validity: &'static str,

    /// The credential at the bottom of the path was outside its window.
    pub(crate) outside_validity: &'static str,

    /// A certificate above it was outside its window.
    pub(crate) expired: &'static str,

    /// The path reached a configured anchor.
    pub(crate) trusted: &'static str,

    /// It did not.
    pub(crate) untrusted: &'static str,
}

/// The vocabulary for a claim signature's own certificate chain.
pub(crate) const CLAIM_SIGNER: Vocabulary = Vocabulary {
    invalid: status_code::SIGNING_CREDENTIAL_INVALID,
    inside_validity: status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY,
    outside_validity: status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
    expired: status_code::SIGNING_CREDENTIAL_EXPIRED,
    trusted: status_code::SIGNING_CREDENTIAL_TRUSTED,
    untrusted: status_code::SIGNING_CREDENTIAL_UNTRUSTED,
};

/// The vocabulary for a timestamping authority's chain.
///
/// `timeStamp.validated` stands in for "inside validity" because the C2PA
/// specification defines it as exactly that conjunction — the token is
/// well-formed, its message imprint is correct, and its validity holds —
/// and by the time a path reaches this check the first two have already
/// been established.
pub(crate) const TIMESTAMP_AUTHORITY: Vocabulary = Vocabulary {
    invalid: status_code::TIMESTAMP_MALFORMED,
    inside_validity: status_code::TIMESTAMP_VALIDATED,
    outside_validity: status_code::TIMESTAMP_OUTSIDE_VALIDITY,
    expired: status_code::TIMESTAMP_OUTSIDE_VALIDITY,
    trusted: status_code::TIMESTAMP_TRUSTED,
    untrusted: status_code::TIMESTAMP_UNTRUSTED,
};

/// How far trust could be established for one claim signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Trust {
    /// Every check passed and the path terminates at a configured anchor.
    Anchored,

    /// Every check passed, but no configured anchor terminates the path —
    /// including the case where no anchors were configured at all.
    Unanchored,

    /// A check came back negative. The statuses say which.
    Rejected,
}

/// Validates one claim signature's certificate chain.
///
/// `now` is the instant to judge validity windows against, and `anchors` the
/// trust anchors the host configured (possibly none). Findings are appended
/// to `statuses`, all carrying `url`.
///
/// At most one negative finding is recorded: the checks are ordered from
/// structural to circumstantial, and once a path is known to be broken the
/// findings that would follow describe a path that does not exist.
pub(crate) fn validate(
    chain: &[Certificate],
    anchors: &[Certificate],
    now: i64,
    url: &str,
    status_code_vocabulary: Vocabulary,
    statuses: &mut Vec<ValidationStatus>,
) -> Trust {
    let Some((leaf, rest)) = chain.split_first() else {
        // `cose::parse` refuses an empty `x5chain`, so a chain reaching here
        // always has a signer. Reported rather than assumed.
        statuses.push(invalid(
            url,
            status_code_vocabulary,
            "the credential carries no certificates",
        ));
        return Trust::Rejected;
    };

    if let Err(reason) = end_entity_profile(leaf) {
        statuses.push(invalid(url, status_code_vocabulary, reason));
        return Trust::Rejected;
    }

    let (path, anchored) = build_path(leaf, rest, anchors);

    // Each certificate must name the next one as its issuer, that issuer
    // must be allowed to issue it, and the signature must actually verify.
    for (below, pair) in path.windows(2).enumerate() {
        let (subject, issuer) = (pair[0], pair[1]);

        if subject.issuer != issuer.subject {
            statuses.push(invalid(
                url,
                status_code_vocabulary,
                format!(
                    "certificate {:?} names issuer {:?}, but the next certificate in the chain is {:?}",
                    subject.subject, subject.issuer, issuer.subject
                ),
            ));
            return Trust::Rejected;
        }

        // `below` is also the number of intermediates between `issuer` and
        // the end-entity certificate, which is what `pathLenConstraint`
        // bounds (RFC 5280 §4.2.1.9).
        if let Err(reason) = issuer_profile(issuer, below) {
            statuses.push(invalid(url, status_code_vocabulary, reason));
            return Trust::Rejected;
        }

        if let Err(reason) = verify(subject, issuer) {
            statuses.push(invalid(
                url,
                status_code_vocabulary,
                format!("certificate {:?}: {reason}", subject.subject),
            ));
            return Trust::Rejected;
        }
    }

    for (position, certificate) in path.iter().enumerate() {
        if now >= certificate.not_before && now <= certificate.not_after {
            continue;
        }

        // The signer's own window is what the C2PA vocabulary calls the
        // claim signature's validity; a certificate further up the path is
        // reported against the credential as a whole.
        let code = if position == 0 {
            status_code_vocabulary.outside_validity
        } else {
            status_code_vocabulary.expired
        };

        statuses.push(ValidationStatus::for_url(
            code,
            url,
            format!(
                "certificate {:?} is outside its validity window ({}..{}) at {now}",
                certificate.subject, certificate.not_before, certificate.not_after
            ),
        ));
        return Trust::Rejected;
    }

    statuses.push(ValidationStatus::for_url(
        status_code_vocabulary.inside_validity,
        url,
        "every certificate in the path was inside its validity window",
    ));

    if anchored {
        statuses.push(ValidationStatus::for_url(
            status_code_vocabulary.trusted,
            url,
            "the credential chains to a configured trust anchor",
        ));
        Trust::Anchored
    } else {
        statuses.push(ValidationStatus::for_url(
            status_code_vocabulary.untrusted,
            url,
            if anchors.is_empty() {
                "no trust anchors are configured, so the chain reaches none"
            } else {
                "the chain does not reach any configured trust anchor"
            },
        ));
        Trust::Unanchored
    }
}

/// One certificate's OCSP check, alongside whether it is asking about the
/// claim *signer's own* certificate or a CA further up the path.
///
/// The distinction matters to [`crate::read::ReadSession`] because C2PA
/// spec §15.9 reports the two under entirely different status
/// vocabularies, and only the signer's own revocation invalidates the
/// claim outright — see [`crate::validation::status_code::SIGNING_CREDENTIAL_OCSP_REVOKED`]
/// and [`crate::validation::status_code::SIGNING_CREDENTIAL_UNTRUSTED`].
#[derive(Debug)]
pub(crate) struct OcspCheckPlan {
    pub(crate) check: crate::ocsp::PendingOcspCheck,

    /// True for the certificate at position 0 of the path (the claim
    /// signer itself); false for any CA certificate above it.
    pub(crate) is_signer: bool,
}

/// Builds the OCSP checks available for one claim signer's chain.
///
/// Rebuilds exactly the path [`validate`] itself would build — cheap, and
/// it keeps [`validate`] itself unchanged rather than threading a second,
/// asynchronous concern through a function that already has plenty to do.
/// One check per link that has both a subject naming a responder and an
/// issuer above it in the path; a link the profile checks have already
/// rejected is still included; whether to bother asking is
/// [`crate::read::ReadSession`]'s call; this only reports what could be
/// asked.
pub(crate) fn ocsp_checks(chain: &[Certificate], anchors: &[Certificate]) -> Vec<OcspCheckPlan> {
    let Some((leaf, rest)) = chain.split_first() else {
        return vec![];
    };

    let (path, _anchored) = build_path(leaf, rest, anchors);

    path.windows(2)
        .enumerate()
        .filter_map(|(position, pair)| {
            crate::ocsp::build_check(pair[0], pair[1]).map(|check| OcspCheckPlan {
                check,
                is_signer: position == 0,
            })
        })
        .collect()
}

/// Builds the path to validate, and reports whether it reaches an anchor.
///
/// Two ways a path can terminate at an anchor, and both are ordinary: the
/// chain may *contain* the anchor (a signature that ships its root), or the
/// chain may stop below it and the anchor supply the last link (a signature
/// that ships only what the verifier could not already know).
/// The chain is taken as signer plus the rest rather than as one slice, so
/// that "there is always a signer" is a fact about the arguments instead of
/// a case to handle: the topmost certificate is then `rest.last()` or the
/// signer itself, with no empty chain to defend against.
fn build_path<'a>(
    leaf: &'a Certificate,
    rest: &'a [Certificate],
    anchors: &'a [Certificate],
) -> (Vec<&'a Certificate>, bool) {
    let mut path: Vec<&Certificate> = once(leaf).chain(rest).collect();

    // An anchor inside the chain ends the path there. Anything the chain
    // carries above an anchor is irrelevant, and the anchor's own signature
    // is deliberately not checked: trusting a certificate a priori is what
    // makes it an anchor.
    if let Some(at) = path.iter().position(|candidate| {
        anchors
            .iter()
            .any(|anchor| same_credential(candidate, anchor))
    }) {
        path.truncate(at + 1);
        return (path, true);
    }

    // Otherwise an anchor may still have issued the chain's topmost
    // certificate. Anchors can share a subject name — a CA rolling its key
    // produces exactly that — so the one whose key verifies the signature is
    // the one that counts, not the first whose name matches.
    let top = rest.last().unwrap_or(leaf);

    if let Some(anchor) = anchors
        .iter()
        .find(|anchor| anchor.subject == top.issuer && verify(top, anchor).is_ok())
    {
        path.push(anchor);
        return (path, true);
    }

    (path, false)
}

/// True if two certificates stand for the same credential.
///
/// Compared by subject name and public key rather than by DER: two encodings
/// of the same credential (a re-signed anchor, a certificate with a refreshed
/// validity window) name the same key holder, and an anchor list should not
/// have to carry every one of them.
fn same_credential(a: &Certificate, b: &Certificate) -> bool {
    a.subject == b.subject && a.public_key == b.public_key
}

/// Verifies that `issuer` signed `subject`.
///
/// Exposed beyond this module because picking the right issuer out of a
/// set of same-named candidates is the same problem wherever it arises,
/// and it can only be settled by the cryptography.
pub(crate) fn verify(subject: &Certificate, issuer: &Certificate) -> Result<(), &'static str> {
    // Algorithms that name their digest in the OID itself carry no separate
    // hash; the lookup matches on the signature OID alone for those, and the
    // empty OID passed here matches nothing on its own.
    let hash = subject.signature_hash.as_deref().unwrap_or(&[]);

    let Some(validator) =
        validator_for_sig_and_hash_algs(&Oid::new(&subject.signature_algorithm), &Oid::new(hash))
    else {
        // Not merely "unchecked": the C2PA profile names the algorithms a
        // certificate in a claim signature's chain may be signed with, so an
        // algorithm with no validator is outside the profile.
        return Err("signed with an algorithm outside the C2PA certificate profile");
    };

    validator
        .validate(&subject.signature, &subject.tbs, &issuer.public_key)
        .map_err(|_| "signature does not verify against its issuer's public key")
}

/// Holds the signer's certificate to the C2PA end-entity profile.
fn end_entity_profile(certificate: &Certificate) -> Result<(), String> {
    if certificate
        .basic_constraints
        .is_some_and(|constraints| constraints.is_ca)
    {
        return Err("the signer's certificate asserts cA=true, but a claim must be signed by an end-entity certificate".to_string());
    }

    let Some(key_usage) = certificate.key_usage else {
        return Err("the signer's certificate carries no key usage extension".to_string());
    };

    if !key_usage.digital_signature {
        return Err(
            "the signer's certificate does not assert the digitalSignature key usage".to_string(),
        );
    }

    if key_usage.key_cert_sign {
        return Err(
            "the signer's certificate asserts the keyCertSign key usage, which an end-entity certificate may not"
                .to_string(),
        );
    }

    let Some(purposes) = certificate.extended_key_usage.as_deref() else {
        // Absence is a violation in its own right, and distinguishable here
        // only because `cert.rs` keeps "extension absent" apart from
        // "extension present and empty".
        return Err("the signer's certificate carries no extended key usage extension".to_string());
    };

    if purposes.iter().any(|oid| oid == ANY_EXTENDED_KEY_USAGE) {
        return Err(
            "the signer's certificate names anyExtendedKeyUsage, which the C2PA profile forbids"
                .to_string(),
        );
    }

    let timestamping = purposes.iter().any(|oid| oid == TIME_STAMPING);
    let ocsp_signing = purposes.iter().any(|oid| oid == OCSP_SIGNING);

    // A credential for stamping time or answering revocation queries is a
    // credential for exactly that; pairing either with a second purpose
    // would let one role's certificate stand in for another's.
    if timestamping && ocsp_signing {
        return Err(
            "the signer's certificate names both id-kp-timeStamping and id-kp-OCSPSigning"
                .to_string(),
        );
    }

    if (timestamping || ocsp_signing) && purposes.len() > 1 {
        return Err(
            "the signer's certificate names id-kp-timeStamping or id-kp-OCSPSigning alongside another purpose"
                .to_string(),
        );
    }

    if !purposes
        .iter()
        .any(|oid| ALLOWED_PURPOSES.contains(&oid.as_str()))
    {
        return Err(format!(
            "the signer's certificate names no extended key usage the C2PA profile accepts (it names {purposes:?})"
        ));
    }

    Ok(())
}

/// Holds a certificate that issued another to the constraints on issuers.
///
/// `intermediates_below` counts the certificates between this one and the
/// end-entity certificate, exclusive of both — the quantity
/// `pathLenConstraint` bounds.
fn issuer_profile(certificate: &Certificate, intermediates_below: usize) -> Result<(), String> {
    let Some(constraints) = certificate.basic_constraints else {
        return Err(format!(
            "certificate {:?} carries no basic constraints extension, so it may not issue certificates",
            certificate.subject
        ));
    };

    if !constraints.is_ca {
        return Err(format!(
            "certificate {:?} asserts cA=false, so it may not issue certificates",
            certificate.subject
        ));
    }

    // Key usage is optional; where it is present it has to permit signing
    // certificates. Absence asserts nothing rather than denying it.
    if certificate
        .key_usage
        .is_some_and(|key_usage| !key_usage.key_cert_sign)
    {
        return Err(format!(
            "certificate {:?} does not assert the keyCertSign key usage",
            certificate.subject
        ));
    }

    if constraints
        .path_len
        .is_some_and(|limit| usize::from(limit) < intermediates_below)
    {
        return Err(format!(
            "certificate {:?} permits at most {} intermediate(s) beneath it, but the path has {intermediates_below}",
            certificate.subject,
            constraints.path_len.unwrap_or_default()
        ));
    }

    Ok(())
}

/// Builds the vocabulary's "this credential is not usable" status.
fn invalid(
    url: &str,
    status_code_vocabulary: Vocabulary,
    explanation: impl Into<String>,
) -> ValidationStatus {
    ValidationStatus::for_url(status_code_vocabulary.invalid, url, explanation)
}

/// `id-kp-emailProtection`.
const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";

/// `id-kp-timeStamping`.
const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

/// `id-kp-OCSPSigning`.
///
/// `pub(crate)` rather than private: `crate::ocsp` reuses this to hold a
/// delegated OCSP responder certificate to the same purpose this module
/// already requires of one appearing in a claim signer's own path.
pub(crate) const OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// `id-kp-documentSigning`, the purpose the C2PA specification names for
/// claim signing.
const DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";

/// `anyExtendedKeyUsage`, which the C2PA profile forbids: a certificate good
/// for every purpose is a certificate constrained to none.
const ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";

/// The extended key usages a claim-signing certificate may name.
///
/// `emailProtection` is here because the certificates in circulation use it
/// — including the one in this repository's c2pa-rs fixture — not because it
/// describes claim signing well.
const ALLOWED_PURPOSES: [&str; 4] = [
    EMAIL_PROTECTION,
    TIME_STAMPING,
    OCSP_SIGNING,
    DOCUMENT_SIGNING,
];

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        cert::{self, KeyUsage},
        test_support::{FIXTURE_ISSUER_CERT, FIXTURE_LEAF_CERT, TEST_SIGNER_CERT},
    };

    /// An instant inside every trust fixture's validity window, and inside
    /// the c2pa-rs fixture chain's too.
    const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z

    const ROOT: &[u8] = include_bytes!("../tests/fixtures/trust-root.der");
    const INTERMEDIATE: &[u8] = include_bytes!("../tests/fixtures/trust-intermediate.der");
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/trust-leaf.der");
    const WRONG_EKU: &[u8] = include_bytes!("../tests/fixtures/trust-leaf-wrong-eku.der");
    const LEAF_IS_CA: &[u8] = include_bytes!("../tests/fixtures/trust-leaf-is-ca.der");

    fn decode(der: &[u8]) -> Certificate {
        cert::decode(der).expect("fixture decodes")
    }

    /// The full three-level chain, signer first, as a signature would carry
    /// it without its root.
    fn chain() -> Vec<Certificate> {
        vec![decode(LEAF), decode(INTERMEDIATE)]
    }

    /// Runs a validation and returns the outcome alongside the codes it
    /// recorded.
    fn run(chain: &[Certificate], anchors: &[Certificate], now: i64) -> (Trust, Vec<String>) {
        let mut statuses = Vec::new();
        let trust = validate(
            chain,
            anchors,
            now,
            "self#jumbf=x",
            CLAIM_SIGNER,
            &mut statuses,
        );
        (
            trust,
            statuses.into_iter().map(|status| status.code).collect(),
        )
    }

    /// The explanation of the single status a rejecting run recorded.
    fn rejection(chain: &[Certificate], anchors: &[Certificate], now: i64) -> String {
        let mut statuses = Vec::new();
        assert_eq!(
            validate(
                chain,
                anchors,
                now,
                "self#jumbf=x",
                CLAIM_SIGNER,
                &mut statuses
            ),
            Trust::Rejected
        );
        assert_eq!(statuses.len(), 1, "{statuses:#?}");
        statuses[0].explanation.clone().unwrap_or_default()
    }

    #[test]
    fn a_chain_reaching_a_configured_anchor_is_trusted() {
        let (trust, codes) = run(&chain(), &[decode(ROOT)], NOW);

        assert_eq!(trust, Trust::Anchored);
        assert_eq!(
            codes,
            [
                status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY,
                status_code::SIGNING_CREDENTIAL_TRUSTED
            ]
        );
    }

    #[test]
    fn the_same_chain_without_anchors_is_valid_but_untrusted() {
        let (trust, codes) = run(&chain(), &[], NOW);

        assert_eq!(trust, Trust::Unanchored);
        assert_eq!(
            codes,
            [
                status_code::CLAIM_SIGNATURE_INSIDE_VALIDITY,
                status_code::SIGNING_CREDENTIAL_UNTRUSTED
            ]
        );

        // Not a failure: it says the signer is absent from *this verifier's*
        // list, which is a statement about configuration rather than about
        // the manifest.
        let mut statuses = Vec::new();
        validate(
            &chain(),
            &[],
            NOW,
            "self#jumbf=x",
            CLAIM_SIGNER,
            &mut statuses,
        );
        assert!(statuses.iter().all(|status| !status.is_failure()));
    }

    #[test]
    fn an_anchor_carried_inside_the_chain_terminates_the_path() {
        // The chain ships its own root, and the root is configured.
        let mut chain = chain();
        chain.push(decode(ROOT));

        assert_eq!(run(&chain, &[decode(ROOT)], NOW).0, Trust::Anchored);

        // With nothing configured, shipping the root proves nothing.
        assert_eq!(run(&chain, &[], NOW).0, Trust::Unanchored);
    }

    #[test]
    fn an_anchor_that_did_not_issue_the_chain_does_not_trust_it() {
        // A well-formed anchor with no relationship to this chain.
        let (trust, codes) = run(&chain(), &[decode(TEST_SIGNER_CERT)], NOW);

        assert_eq!(trust, Trust::Unanchored);
        assert_eq!(
            codes.last().map(String::as_str),
            Some(status_code::SIGNING_CREDENTIAL_UNTRUSTED)
        );
    }

    #[test]
    fn an_anchor_matching_by_name_but_not_by_key_does_not_trust_the_chain() {
        let stranger = decode(TEST_SIGNER_CERT).public_key;

        // Carrying the real root's name but somebody else's key: the chain
        // stops below this anchor, so it is reached through the "issued the
        // last certificate" route — and the signature is what refuses it.
        let mut impostor_root = decode(ROOT);
        impostor_root.public_key = stranger.clone();
        assert_eq!(run(&chain(), &[impostor_root], NOW).0, Trust::Unanchored);

        // Carrying the *intermediate's* name but somebody else's key: this
        // one would be found inside the chain, where no signature is
        // checked at all, so only comparing the key can refuse it.
        let mut impostor_intermediate = decode(INTERMEDIATE);
        impostor_intermediate.public_key = stranger;
        assert_eq!(
            run(&chain(), &[impostor_intermediate], NOW).0,
            Trust::Unanchored
        );

        // ...and the genuine intermediate, found the same way, is accepted
        // — so the refusals above are about the key rather than about the
        // route.
        assert_eq!(
            run(&chain(), &[decode(INTERMEDIATE)], NOW).0,
            Trust::Anchored
        );
    }

    #[test]
    fn a_chain_missing_its_intermediate_does_not_reach_the_anchor() {
        // The leaf alone, with the root configured: the root did not issue
        // the leaf, so nothing links them.
        let (trust, codes) = run(&[decode(LEAF)], &[decode(ROOT)], NOW);

        assert_eq!(trust, Trust::Unanchored);
        assert_eq!(
            codes.last().map(String::as_str),
            Some(status_code::SIGNING_CREDENTIAL_UNTRUSTED)
        );
    }

    #[test]
    fn a_certificate_whose_signature_does_not_verify_is_rejected() {
        let mut chain = chain();
        // Flip a bit of the signer's signature. The chain still links up by
        // name, so only the cryptography can notice.
        let last = chain[0].signature.len() - 1;
        chain[0].signature[last] ^= 0x01;

        let explanation = rejection(&chain, &[decode(ROOT)], NOW);
        assert!(
            explanation.contains("does not verify"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_chain_that_does_not_link_up_by_name_is_rejected() {
        // A leaf paired with an issuer that did not issue it.
        let chain = vec![decode(LEAF), decode(TEST_SIGNER_CERT)];

        let explanation = rejection(&chain, &[], NOW);
        assert!(
            explanation.contains("names issuer"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_signer_certificate_that_is_a_ca_is_rejected() {
        let chain = vec![decode(LEAF_IS_CA), decode(INTERMEDIATE)];

        let explanation = rejection(&chain, &[decode(ROOT)], NOW);
        assert!(explanation.contains("cA=true"), "unexpected: {explanation}");
    }

    #[test]
    fn a_signer_certificate_with_no_accepted_purpose_is_rejected() {
        // Its only EKU is TLS server authentication.
        let chain = vec![decode(WRONG_EKU), decode(INTERMEDIATE)];

        let explanation = rejection(&chain, &[decode(ROOT)], NOW);
        assert!(
            explanation.contains("no extended key usage"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn the_end_entity_profile_rejects_each_violation_by_name() {
        let good = decode(LEAF);

        // No key usage at all.
        let mut cert = good.clone();
        cert.key_usage = None;
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("no key usage extension"));

        // Key usage that does not permit signing.
        let mut cert = good.clone();
        cert.key_usage = Some(KeyUsage {
            digital_signature: false,
            ..good.key_usage.unwrap()
        });
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("digitalSignature"));

        // An end-entity certificate claiming it may sign certificates.
        let mut cert = good.clone();
        cert.key_usage = Some(KeyUsage {
            key_cert_sign: true,
            ..good.key_usage.unwrap()
        });
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("keyCertSign"));

        // No extended key usage at all.
        let mut cert = good.clone();
        cert.extended_key_usage = None;
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("no extended key usage extension"));

        // `anyExtendedKeyUsage`, alone or alongside an accepted purpose.
        for purposes in [
            vec![ANY_EXTENDED_KEY_USAGE.to_string()],
            vec![
                EMAIL_PROTECTION.to_string(),
                ANY_EXTENDED_KEY_USAGE.to_string(),
            ],
        ] {
            let mut cert = good.clone();
            cert.extended_key_usage = Some(purposes);
            assert!(end_entity_profile(&cert)
                .unwrap_err()
                .contains("anyExtendedKeyUsage"));
        }

        // Time stamping and OCSP signing are each exclusive.
        let mut cert = good.clone();
        cert.extended_key_usage = Some(vec![TIME_STAMPING.to_string(), OCSP_SIGNING.to_string()]);
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("both id-kp-timeStamping"));

        let mut cert = good.clone();
        cert.extended_key_usage = Some(vec![
            TIME_STAMPING.to_string(),
            EMAIL_PROTECTION.to_string(),
        ]);
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("alongside another purpose"));

        // Each accepted purpose on its own passes.
        for purpose in ALLOWED_PURPOSES {
            let mut cert = good.clone();
            cert.extended_key_usage = Some(vec![purpose.to_string()]);
            assert!(
                end_entity_profile(&cert).is_ok(),
                "{purpose} should be accepted"
            );
        }

        // An extension that is present but names nothing is not the same as
        // an absent one, and is also rejected.
        let mut cert = good.clone();
        cert.extended_key_usage = Some(vec![]);
        assert!(end_entity_profile(&cert)
            .unwrap_err()
            .contains("no extended key usage the C2PA profile accepts"));
    }

    #[test]
    fn an_issuer_that_is_not_a_ca_is_rejected() {
        // The self-signed test signer asserts cA=false, so it cannot stand
        // as anyone's issuer — even its own name-alike.
        let mut leaf = decode(LEAF);
        let signer = decode(TEST_SIGNER_CERT);
        leaf.issuer = signer.subject.clone();

        let explanation = rejection(&[leaf, signer], &[], NOW);
        assert!(
            explanation.contains("cA=false"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn an_issuer_without_basic_constraints_is_rejected() {
        // Absence is not neutral here, unlike key usage: `cA` defaults to
        // false, so a certificate that says nothing has not claimed the
        // right to issue.
        let mut chain = chain();
        chain[1].basic_constraints = None;

        let explanation = rejection(&chain, &[], NOW);
        assert!(
            explanation.contains("no basic constraints extension"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn an_issuer_without_key_cert_sign_is_rejected() {
        let mut chain = chain();
        chain[1].key_usage = Some(KeyUsage {
            key_cert_sign: false,
            ..chain[1].key_usage.unwrap()
        });

        let explanation = rejection(&chain, &[], NOW);
        assert!(
            explanation.contains("keyCertSign"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn an_issuer_with_no_key_usage_extension_may_still_issue() {
        // Absence asserts nothing rather than denying `keyCertSign`.
        let mut chain = chain();
        chain[1].key_usage = None;

        assert_eq!(run(&chain, &[decode(ROOT)], NOW).0, Trust::Anchored);
    }

    #[test]
    fn a_path_longer_than_path_len_permits_is_rejected() {
        // The intermediate carries `pathlen:0`, so it may issue the signer
        // but nothing between itself and the signer. Splicing a copy of
        // itself in gives it one intermediate too many.
        let mut chain = chain();
        let mut spliced = decode(INTERMEDIATE);
        spliced.issuer = spliced.subject.clone();
        chain.insert(1, spliced);

        let explanation = rejection(&chain, &[], NOW);
        assert!(
            explanation.contains("permits at most 0 intermediate"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_signer_outside_its_validity_window_is_reported_against_the_signature() {
        let chain = chain();
        let before = chain[0].not_before - 1;
        let after = chain[0].not_after + 1;

        for now in [before, after] {
            let mut statuses = Vec::new();
            assert_eq!(
                validate(
                    &chain,
                    &[decode(ROOT)],
                    now,
                    "self#jumbf=x",
                    CLAIM_SIGNER,
                    &mut statuses
                ),
                Trust::Rejected
            );
            assert_eq!(
                statuses[0].code,
                status_code::CLAIM_SIGNATURE_OUTSIDE_VALIDITY
            );
            assert!(statuses[0].is_failure());
        }

        // The boundaries themselves are inside the window.
        for now in [chain[0].not_before, chain[0].not_after] {
            assert_eq!(run(&chain, &[decode(ROOT)], now).0, Trust::Anchored);
        }
    }

    #[test]
    fn an_issuer_outside_its_validity_window_is_reported_against_the_credential() {
        let mut chain = chain();
        // Give the intermediate a window that closed before the signer's
        // opened, leaving the signer itself inside its own.
        chain[1].not_after = chain[0].not_before - 1;

        let mut statuses = Vec::new();
        assert_eq!(
            validate(
                &chain,
                &[],
                NOW,
                "self#jumbf=x",
                CLAIM_SIGNER,
                &mut statuses
            ),
            Trust::Rejected
        );
        assert_eq!(statuses[0].code, status_code::SIGNING_CREDENTIAL_EXPIRED);
        assert!(statuses[0].is_failure());
    }

    #[test]
    fn an_anchor_outside_its_own_validity_window_takes_the_path_down() {
        // An anchor's *signature* is never checked — that is what trusting
        // it a priori means — but its validity window is, so an expired
        // anchor stops vouching for anything rather than going on
        // indefinitely.
        let mut anchor = decode(ROOT);
        anchor.not_after = NOW - 1;

        let mut statuses = Vec::new();
        assert_eq!(
            validate(
                &chain(),
                &[anchor],
                NOW,
                "self#jumbf=x",
                CLAIM_SIGNER,
                &mut statuses
            ),
            Trust::Rejected
        );
        assert_eq!(statuses[0].code, status_code::SIGNING_CREDENTIAL_EXPIRED);
        assert!(statuses[0]
            .explanation
            .as_deref()
            .unwrap_or_default()
            .contains("Test Root CA"));
    }

    #[test]
    fn an_empty_chain_is_rejected_rather_than_panicking() {
        let explanation = rejection(&[], &[], NOW);
        assert!(explanation.contains("no certificates"));
    }

    #[test]
    fn ocsp_checks_is_empty_for_an_empty_chain() {
        assert!(ocsp_checks(&[], &[]).is_empty());
    }

    #[test]
    fn ocsp_checks_is_empty_when_no_certificate_names_a_responder() {
        // None of this crate's own trust fixtures carry an Authority
        // Information Access extension.
        assert!(ocsp_checks(&chain(), &[]).is_empty());
    }

    #[test]
    fn ocsp_checks_builds_one_check_per_link_that_names_a_responder() {
        let mut leaf = decode(LEAF);
        leaf.ocsp_responder_url = Some("http://ocsp.example/".to_string());

        // The intermediate has no responder URL of its own, so only the
        // leaf/intermediate link produces a check — there is no third
        // certificate above the intermediate in this two-element chain to
        // ask about *its* revocation status.
        let checks = ocsp_checks(&[leaf, decode(INTERMEDIATE)], &[]);
        assert_eq!(checks.len(), 1);
        assert!(
            checks[0].is_signer,
            "position 0 of the path is the claim signer"
        );
    }

    #[test]
    fn ocsp_checks_still_rebuilds_the_path_through_a_configured_anchor() {
        // Same as above, but with the root configured as an anchor: the
        // path `ocsp_checks` rebuilds must be the same one `validate`
        // would, anchor included.
        let mut leaf = decode(LEAF);
        leaf.ocsp_responder_url = Some("http://ocsp.example/".to_string());
        let mut intermediate = decode(INTERMEDIATE);
        intermediate.ocsp_responder_url = Some("http://ocsp.example/intermediate".to_string());

        let checks = ocsp_checks(&[leaf, intermediate], &[decode(ROOT)]);

        // leaf/intermediate and intermediate/root: two links, both named.
        assert_eq!(checks.len(), 2);
        assert!(checks[0].is_signer);
        assert!(
            !checks[1].is_signer,
            "the intermediate is a CA, not the signer"
        );
    }

    #[test]
    fn the_real_c2pa_rs_fixture_chain_validates() {
        // The RSASSA-PSS chain from `manifest_data.c2pa`: a leaf this core
        // did not build, signed by an intermediate it did not build, with
        // parameters it has to read out of the algorithm identifier. Its
        // root is not in the chain and this repository does not have it, so
        // the best reachable outcome is `Unanchored`.
        let chain = vec![decode(FIXTURE_LEAF_CERT), decode(FIXTURE_ISSUER_CERT)];

        let (trust, codes) = run(&chain, &[], NOW);

        assert_eq!(trust, Trust::Unanchored, "{codes:?}");

        // ...and configuring the intermediate itself as an anchor reaches
        // `Trusted`, which is the path an operator with a partial chain
        // takes.
        assert_eq!(
            run(&chain, &[decode(FIXTURE_ISSUER_CERT)], NOW).0,
            Trust::Anchored
        );
    }

    #[test]
    fn a_certificate_signed_with_an_unverifiable_algorithm_is_rejected() {
        let mut chain = chain();
        // An OID no validator answers to.
        chain[0].signature_algorithm = vec![0x2a, 0x03];
        chain[0].signature_hash = None;

        let explanation = rejection(&chain, &[], NOW);
        assert!(
            explanation.contains("outside the C2PA certificate profile"),
            "unexpected: {explanation}"
        );
    }
}
