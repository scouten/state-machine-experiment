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

//! RFC 3161 timestamps: what a trusted authority says about *when*.
//!
//! # What a timestamp buys
//!
//! Without one, "was this certificate valid when it signed?" can only be
//! answered against the reader's own clock — which reads every manifest
//! signed with a since-expired certificate as broken, however impeccable it
//! was on the day. A timestamp replaces that guess with a countersignature
//! from an authority that was watching the clock at the time.
//!
//! So the instant this module produces is not a detail: it is the input to
//! [`crate::chain`], and it decides whether a years-old manifest reads as
//! valid or expired.
//!
//! # Why only a *trusted* authority's time is used
//!
//! A timestamp is a claim about time made by whoever signed the token, and
//! an attacker who can mint tokens can name any instant they please —
//! including one that revives an expired credential. So [`validate`] hands
//! back a usable instant only when the authority's own certificate path
//! reaches an anchor the host configured. An unanchored token is still
//! reported (its findings say what was checked), but the evaluation falls
//! back to the host's current time.
//!
//! # The shape of a token
//!
//! ```text
//! sigTst / sigTst2 (COSE unprotected header)
//!   └─ { "tstTokens": [ { "val": <bytes> } ] }
//!        └─ TimeStampResp (sigTst) or TimeStampToken (sigTst2)
//!             └─ ContentInfo { signedData }
//!                  └─ SignedData
//!                       ├─ encapContentInfo: id-ct-TSTInfo ⊃ TSTInfo
//!                       │                                    ├─ messageImprint
//!                       │                                    └─ genTime
//!                       ├─ certificates: the authority's chain
//!                       └─ signerInfos[0]
//!                            ├─ signedAttrs (content-type, message-digest)
//!                            └─ signature over DER(signedAttrs)
//! ```
//!
//! Note where the signature actually lands: the authority signs its
//! *signed attributes*, not the `TSTInfo` directly. The `TSTInfo` is bound
//! in only through the `message-digest` attribute, so checking that
//! attribute is not a formality — skip it and the `genTime` this module
//! returns would be unauthenticated.
//!
//! # What is not checked
//!
//! Revocation of the authority's certificates, the `accuracy` and
//! `ordering` fields, the nonce (nothing here issued a request to match one
//! against), and the TSA name in the `[0]` field. Timestamp *creation* is
//! not implemented in this crate at all — it is a signing-side concern;
//! this module only reads.

use c2pa_raw_crypto::{validator_for_sig_and_hash_algs, Oid};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use der::{
    asn1::{BitString, GeneralizedTime, Int, OctetString},
    oid::ObjectIdentifier,
    Any, Decode, Encode, Sequence,
};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::{
    cert::{self, Certificate},
    chain,
    cose::TimestampStorage,
    types::HashAlgorithm,
    validation::{status_code, ValidationStatus},
};

/// A timestamp taken off a claim signature, held until it can be checked.
#[derive(Clone, Debug)]
pub(crate) struct PendingTimestamp {
    /// The token bytes, exactly as the header carried them.
    pub(crate) token: Vec<u8>,

    /// Which header carried it, which decides how the token is framed.
    pub(crate) storage: TimestampStorage,

    /// The bytes the token's message imprint has to cover.
    ///
    /// Built by [`crate::cose::ClaimSignature::countersigned`] while the
    /// manifest is still in hand, because the protected header and the
    /// claim it embeds are gone by the time this is checked.
    pub(crate) countersigned: Vec<u8>,
}

/// What a timestamp established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Timestamped {
    /// The token checked out and its authority chains to a configured
    /// anchor. This instant may be used as the time of signing.
    Trusted(i64),

    /// The token checked out, but nothing ties its authority to an anchor
    /// the host configured, so its word on the time is not taken.
    Untrusted,

    /// The token did not check out. The statuses say why.
    Rejected,
}

/// Validates one timestamp and reports whether its instant may be used.
///
/// `anchors` are the *timestamp* trust anchors — a different list from the
/// claim-signing ones, because the authorities that stamp time are not the
/// authorities that vouch for signers.
pub(crate) fn validate(
    pending: &PendingTimestamp,
    anchors: &[Certificate],
    url: &str,
    statuses: &mut Vec<ValidationStatus>,
) -> Timestamped {
    let signed_data = match signed_data(&pending.token, pending.storage) {
        Ok(signed_data) => signed_data,
        Err(reason) => {
            statuses.push(malformed(url, reason));
            return Timestamped::Rejected;
        }
    };

    let content = match tst_info_der(&signed_data) {
        Ok(content) => content,
        Err(reason) => {
            statuses.push(malformed(url, reason));
            return Timestamped::Rejected;
        }
    };

    let tst_info = match tst_info(&content) {
        Ok(tst_info) => tst_info,
        Err(reason) => return reject(url, reason, statuses),
    };

    // The authority's signature is checked before its word is repeated:
    // everything after this point is only worth reading because the
    // authority stands behind it.
    let signer = match verify_signature(&signed_data, &content) {
        Ok(signer) => signer,
        Err(reason) => return reject(url, reason, statuses),
    };

    // Does the token actually cover *this* signature?
    let Some(algorithm) =
        HashAlgorithm::from_oid(tst_info.message_imprint.hash_algorithm.oid.as_bytes())
    else {
        return reject(
            url,
            "the token's message imprint uses a hash this core cannot compute",
            statuses,
        );
    };

    let expected = algorithm.digest(&pending.countersigned);

    if expected != tst_info.message_imprint.hashed_message.as_bytes() {
        // Distinct from `malformed`: the token is perfectly well-formed,
        // it just stamps something else. A token lifted from another
        // manifest lands exactly here.
        statuses.push(ValidationStatus::for_url(
            status_code::TIMESTAMP_MISMATCH,
            url,
            "the timestamp's message imprint does not cover this claim signature",
        ));
        return Timestamped::Rejected;
    }

    let gen_time = gen_time_seconds(&tst_info.gen_time);

    // The authority's own certificates are judged at the instant the token
    // claims — the only instant that can be used here, since the point of
    // the exercise is to establish what time it was.
    let path = authority_path(&signed_data, &signer);

    match chain::validate(
        &path,
        anchors,
        gen_time,
        url,
        chain::TIMESTAMP_AUTHORITY,
        statuses,
    ) {
        chain::Trust::Anchored => Timestamped::Trusted(gen_time),
        chain::Trust::Unanchored => Timestamped::Untrusted,
        chain::Trust::Rejected => Timestamped::Rejected,
    }
}

/// Decodes a `TSTInfo` and holds it to the one version RFC 3161 defines.
///
/// A token naming a different version is not a token this code has been
/// written to read: its fields would be interpreted with v1 semantics and
/// its `genTime` repeated as if that meant the same thing. Refusing is the
/// only honest answer, and costs nothing — no version but 1 exists.
fn tst_info(der: &[u8]) -> Result<TstInfo, &'static str> {
    let tst_info =
        TstInfo::from_der(der).map_err(|_| "the token's TSTInfo could not be decoded")?;

    if tst_info.version != TST_INFO_VERSION {
        return Err("the token's TSTInfo names a version this core does not read");
    }

    Ok(tst_info)
}

/// The only `TSTInfo` version RFC 3161 defines.
const TST_INFO_VERSION: u32 = 1;

/// Records a `timeStamp.malformed` finding and rejects.
fn reject(url: &str, reason: &'static str, statuses: &mut Vec<ValidationStatus>) -> Timestamped {
    statuses.push(malformed(url, reason));
    Timestamped::Rejected
}

/// Builds a `timeStamp.malformed` status.
fn malformed(url: &str, reason: &'static str) -> ValidationStatus {
    ValidationStatus::for_url(status_code::TIMESTAMP_MALFORMED, url, reason)
}

/// Unwraps a token down to its CMS `SignedData`.
///
/// The two headers carry different things — `sigTst` a whole
/// `TimeStampResp` including the protocol status, `sigTst2` the bare
/// `TimeStampToken` — so which one carried it decides how far in the
/// unwrapping starts.
fn signed_data(token: &[u8], storage: TimestampStorage) -> Result<SignedData, &'static str> {
    let content_info = match storage {
        TimestampStorage::SigTst => {
            let response = TimeStampResp::from_der(token)
                .map_err(|_| "the token is not a well-formed TimeStampResp")?;

            // PKIStatus: 0 granted, 1 granted with modifications. Anything
            // else means the authority refused, and a refusal carries no
            // token to read.
            if response.status.status > 1 {
                return Err("the timestamp authority refused the request");
            }

            response
                .token
                .ok_or("the TimeStampResp carries no timestamp token")?
        }

        TimestampStorage::SigTst2 => ContentInfo::from_der(token)
            .map_err(|_| "the token is not a well-formed TimeStampToken")?,
    };

    if content_info.content_type != ID_SIGNED_DATA {
        return Err("the timestamp token does not wrap CMS SignedData");
    }

    let der = content_info
        .content
        .to_der()
        .map_err(|_| "the timestamp token's content could not be read")?;

    SignedData::from_der(&der).map_err(|_| "the timestamp token's SignedData could not be decoded")
}

/// Extracts the DER of the `TSTInfo` the token encapsulates.
fn tst_info_der(signed_data: &SignedData) -> Result<Vec<u8>, &'static str> {
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err("the timestamp token does not encapsulate a TSTInfo");
    }

    let content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("the timestamp token encapsulates no content")?;

    // eContent is an EXPLICIT [0] OCTET STRING whose bytes are the TSTInfo
    // DER. Those bytes are what the `message-digest` attribute covers, so
    // they are taken verbatim rather than re-encoded.
    Ok(content
        .decode_as::<OctetString>()
        .map_err(|_| "the timestamp token's content is not an octet string")?
        .as_bytes()
        .to_vec())
}

/// Verifies the authority's signature, and returns the certificate that
/// made it.
///
/// Three things have to line up, and all three matter:
///
/// * the `content-type` attribute names `id-ct-TSTInfo`, so a signature
///   made over some other kind of CMS content cannot be replayed as a
///   timestamp;
/// * the `message-digest` attribute matches the encapsulated `TSTInfo`,
///   which is the *only* thing binding the signature to the time it
///   claims; and
/// * the signature verifies over the attributes themselves.
fn verify_signature(
    signed_data: &SignedData,
    tst_info_der: &[u8],
) -> Result<Certificate, &'static str> {
    let signer_info = signed_data
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or("the timestamp token carries no signer")?;

    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or("the timestamp token's signer carries no signed attributes")?;

    let attribute = |oid: ObjectIdentifier| {
        signed_attrs
            .iter()
            .find(|attribute| attribute.oid == oid)
            .and_then(|attribute| attribute.values.get(0))
    };

    match attribute(ID_CONTENT_TYPE).map(Any::decode_as::<ObjectIdentifier>) {
        Some(Ok(content_type)) if content_type == ID_CT_TST_INFO => {}
        Some(_) => return Err("the timestamp token's content-type attribute is not a TSTInfo"),
        None => return Err("the timestamp token carries no content-type attribute"),
    }

    let Some(Ok(message_digest)) = attribute(ID_MESSAGE_DIGEST).map(Any::decode_as::<OctetString>)
    else {
        return Err("the timestamp token carries no message-digest attribute");
    };

    let Some(digest_algorithm) = HashAlgorithm::from_oid(signer_info.digest_alg.oid.as_bytes())
    else {
        return Err("the timestamp token names a digest this core cannot compute");
    };

    if digest_algorithm.digest(tst_info_der) != message_digest.as_bytes() {
        return Err("the timestamp token's message-digest attribute does not cover its TSTInfo");
    }

    let signer = signing_certificate(signed_data, signer_info)?;

    // The signature covers the DER of the attributes as a SET OF, which is
    // not how they appear inside the `SignerInfo` — there they carry an
    // implicit [0] tag. Re-encoding is therefore required rather than
    // avoidable, and it is safe here because a SET OF has one canonical
    // DER form.
    let to_verify = signed_attrs
        .to_der()
        .map_err(|_| "the timestamp token's signed attributes could not be re-encoded")?;

    let validator = validator_for_sig_and_hash_algs(
        &Oid::new(signer_info.signature_algorithm.oid.as_bytes()),
        &Oid::new(signer_info.digest_alg.oid.as_bytes()),
    )
    .ok_or("the timestamp token is signed with an algorithm this core cannot verify")?;

    validator
        .validate(
            signer_info.signature.as_bytes(),
            &to_verify,
            &signer.public_key,
        )
        .map_err(|_| "the timestamp token's signature does not verify")?;

    Ok(signer)
}

/// Finds the certificate the `SignerInfo` names, among those the token
/// carries.
fn signing_certificate(
    signed_data: &SignedData,
    signer_info: &SignerInfo,
) -> Result<Certificate, &'static str> {
    let SignerIdentifier::IssuerAndSerialNumber(wanted) = &signer_info.sid else {
        // A token identifying its signer by subject key identifier is
        // legal CMS, but nothing in the C2PA corpus produces one and
        // guessing at an untested path is worse than saying so.
        return Err("the timestamp token identifies its signer by key identifier, which this core does not resolve");
    };

    for der in certificates(signed_data) {
        let Ok(candidate) = x509_cert::Certificate::from_der(&der) else {
            continue;
        };

        if candidate.tbs_certificate.serial_number == wanted.serial_number
            && candidate.tbs_certificate.issuer == wanted.issuer
        {
            return cert::decode(&der)
                .map_err(|_| "the timestamp token's signing certificate could not be decoded");
        }
    }

    Err("the timestamp token does not carry the certificate that signed it")
}

/// Orders the certificates a token carries into a path, signer first.
///
/// They arrive as a `SET`, which is unordered by definition, so the chain
/// is rebuilt rather than trusted to arrive in any particular sequence.
///
/// # Why the name is not enough to pick the next link
///
/// A token may carry several certificates sharing a subject name — a CA
/// that rolled its key, or a cross-signed pair, produces exactly that — and
/// only one of them holds the key that signed the certificate below.
/// Choosing by name and hoping would build a path that then fails
/// verification, and nothing downstream can back up and try the other one:
/// a perfectly good timestamp would read as malformed.
///
/// So the candidate whose key actually verifies the link is preferred. A
/// name match with no verifying candidate is still taken, because that
/// produces the accurate finding — "this signature does not verify" —
/// rather than a path that merely stops short.
fn order_path(signer: &Certificate, mut pool: Vec<Certificate>) -> Vec<Certificate> {
    let mut path = vec![signer.clone()];

    // Each step consumes one member of the pool, so this terminates even
    // if the token carries a cycle of cross-signatures.
    while let Some(at) = path.last().and_then(|below| next_link(below, &pool)) {
        path.push(pool.remove(at));
    }

    path
}

/// Picks the certificate in `pool` that issued `below`, preferring the one
/// whose key verifies over one that merely carries the right name.
fn next_link(below: &Certificate, pool: &[Certificate]) -> Option<usize> {
    let named = |candidate: &&Certificate| candidate.subject == below.issuer;

    pool.iter()
        .position(|candidate| named(&candidate) && chain::verify(below, candidate).is_ok())
        .or_else(|| pool.iter().position(|candidate| named(&candidate)))
}

/// The certificates a token carries, ordered into a path from its signer.
fn authority_path(signed_data: &SignedData, signer: &Certificate) -> Vec<Certificate> {
    let pool = certificates(signed_data)
        .iter()
        .filter_map(|der| cert::decode(der).ok())
        .filter(|candidate| candidate.subject != signer.subject)
        .collect();

    order_path(signer, pool)
}

/// The DER of every X.509 certificate a token carries.
fn certificates(signed_data: &SignedData) -> Vec<Vec<u8>> {
    signed_data
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => certificate.to_der().ok(),

                    // Attribute certificates carry no public key and so can
                    // never be part of a path.
                    CertificateChoices::Other(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Converts the token's `genTime` to seconds since the Unix epoch.
fn gen_time_seconds(gen_time: &GeneralizedTime) -> i64 {
    // `as` is lossless for every representable time: GeneralizedTime tops
    // out at year 9999.
    gen_time.to_unix_duration().as_secs() as i64
}

/// `1.2.840.113549.1.7.2` — CMS `signedData`.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// `1.2.840.113549.1.9.16.1.4` — `id-ct-TSTInfo`.
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `1.2.840.113549.1.9.3` — the CMS `content-type` attribute.
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// `1.2.840.113549.1.9.4` — the CMS `message-digest` attribute.
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// `TimeStampResp` (RFC 3161 §2.4.2).
#[derive(Debug, Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,

    /// Absent when the authority refused the request.
    #[asn1(optional = "true")]
    token: Option<ContentInfo>,
}

/// `PKIStatusInfo` (RFC 2510).
///
/// Only `status` is read; the rest is decoded so that the surrounding
/// `SEQUENCE` consumes cleanly.
#[derive(Debug, Sequence)]
struct PkiStatusInfo {
    status: u32,

    #[asn1(optional = "true")]
    status_string: Option<Any>,

    #[asn1(optional = "true")]
    fail_info: Option<BitString>,
}

/// `TSTInfo` (RFC 3161 §2.4.2).
///
/// The trailing optional fields are declared even though nothing reads
/// them: a `SEQUENCE` has to decode in full, and a real token carries a
/// nonce and often an accuracy — the fixture in this repository carries
/// both a nonce and none of the rest.
#[derive(Debug, Sequence)]
struct TstInfo {
    version: u32,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,

    #[asn1(optional = "true")]
    accuracy: Option<Accuracy>,

    #[asn1(default = "bool::default")]
    ordering: bool,

    #[asn1(optional = "true")]
    nonce: Option<Int>,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    tsa: Option<Any>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    extensions: Option<Any>,
}

/// `MessageImprint` (RFC 3161 §2.4.1): what the token stamps.
#[derive(Debug, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `Accuracy` (RFC 3161 §2.4.2).
#[derive(Debug, Sequence)]
struct Accuracy {
    #[asn1(optional = "true")]
    seconds: Option<u64>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    millis: Option<u16>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    micros: Option<u16>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use core::time::Duration;

    use cms::{
        cert::{IssuerAndSerialNumber, OtherCertificateFormat},
        content_info::CmsVersion,
        signed_data::{CertificateSet, EncapsulatedContentInfo, SignerInfos},
    };
    use der::asn1::SetOfVec;
    use x509_cert::{
        attr::{Attribute, Attributes},
        ext::pkix::SubjectKeyIdentifier,
        serial_number::SerialNumber,
    };

    use super::*;
    use crate::test_support::{
        FIXTURE_ISSUER_CERT, FIXTURE_LEAF_CERT, TEST_SIGNER_CERT, TEST_SIGNER_KEY,
    };

    /// The `TimeStampResp` from the claim signature in
    /// `tests/fixtures/manifest_data.c2pa`, extracted verbatim.
    ///
    /// Held standalone so the token's own checks can be tested without
    /// going through the COSE layer first — the same reason
    /// `signer-leaf.der` exists. `tests/cert_contract.rs` pins that it has
    /// not drifted from the manifest it came from.
    const TOKEN: &[u8] = include_bytes!("../tests/fixtures/timestamp-token.der");

    /// The authority's own root, which the token also carries.
    const ANCHOR: &[u8] = include_bytes!("../tests/fixtures/digicert-trusted-root-g4.der");

    /// The instant the token attests to: 2024-08-06T21:53:37Z.
    const GEN_TIME: i64 = 1_722_981_217;

    fn pending(token: Vec<u8>, countersigned: &[u8]) -> PendingTimestamp {
        PendingTimestamp {
            token,
            storage: TimestampStorage::SigTst,
            countersigned: countersigned.to_vec(),
        }
    }

    /// Runs a validation and returns the outcome with the codes it
    /// recorded and the last explanation.
    fn run(
        pending: &PendingTimestamp,
        anchors: &[Certificate],
    ) -> (Timestamped, Vec<String>, String) {
        let mut statuses = Vec::new();
        let outcome = validate(pending, anchors, "self#jumbf=x", &mut statuses);
        let explanation = statuses
            .last()
            .and_then(|status| status.explanation.clone())
            .unwrap_or_default();

        (
            outcome,
            statuses.into_iter().map(|status| status.code).collect(),
            explanation,
        )
    }

    fn anchors() -> Vec<Certificate> {
        vec![cert::decode(ANCHOR).expect("the anchor decodes")]
    }

    /// A token that is intact but stamps something other than what it is
    /// checked against — which is what a token lifted from another
    /// manifest looks like.
    #[test]
    fn a_token_that_stamps_other_bytes_is_a_mismatch() {
        let (outcome, codes, _) = run(
            &pending(TOKEN.to_vec(), b"not what was stamped"),
            &anchors(),
        );

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MISMATCH]);
    }

    /// Corrupts one byte inside the encapsulated `TSTInfo`.
    ///
    /// The `message-digest` signed attribute is the only thing binding the
    /// authority's signature to the time it claims, so altering the
    /// `TSTInfo` without altering that attribute is exactly the shape an
    /// attacker rewriting the stamped instant would produce.
    fn token_with_altered_tst_info() -> Vec<u8> {
        let mut token = TOKEN.to_vec();

        // The serial number is inside the TSTInfo and is not read by any
        // check, so flipping a byte of it leaves everything structurally
        // intact and only the digest changes. It sits immediately after
        // the 32-byte message imprint.
        let imprint = [0x64u8, 0xd0, 0x55, 0xda, 0xf8, 0x9e, 0x30, 0x9d];
        let at = token
            .windows(imprint.len())
            .position(|window| window == imprint)
            .expect("the imprint is in the token");

        // 32 bytes of imprint, then the serial's tag and length.
        token[at + 32 + 4] ^= 0xff;
        token
    }

    #[test]
    fn a_token_whose_content_was_altered_is_rejected() {
        let (outcome, codes, explanation) = run(
            &pending(token_with_altered_tst_info(), b"anything"),
            &anchors(),
        );

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("message-digest"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_token_whose_signature_was_altered_is_rejected() {
        // The authority's signature is the last thing in the token, so its
        // final byte is a safe thing to flip without disturbing any
        // length.
        let mut token = TOKEN.to_vec();
        let last = token.len() - 1;
        token[last] ^= 0xff;

        let (outcome, codes, explanation) = run(&pending(token, b"anything"), &anchors());

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("does not verify"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn bytes_that_are_not_a_token_are_rejected() {
        for token in [vec![], vec![0u8; 8], TOKEN[..100].to_vec()] {
            let (outcome, codes, _) = run(&pending(token, b"anything"), &[]);
            assert_eq!(outcome, Timestamped::Rejected);
            assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        }
    }

    #[test]
    fn a_sigtst_token_read_as_sigtst2_is_rejected() {
        // The two headers frame their tokens differently — one a whole
        // `TimeStampResp`, the other a bare `TimeStampToken` — so reading
        // one as the other must fail rather than half-succeed.
        let mut pending = pending(TOKEN.to_vec(), b"anything");
        pending.storage = TimestampStorage::SigTst2;

        let (outcome, codes, explanation) = run(&pending, &[]);

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("TimeStampToken"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_refusal_carries_no_token_to_read() {
        // PKIStatus 2 is "rejection". A response saying the authority
        // declined is well-formed DER, and reporting it as malformed
        // structure would misdescribe what happened.
        let refusal = TimeStampResp {
            status: PkiStatusInfo {
                status: 2,
                status_string: None,
                fail_info: None,
            },
            token: None,
        };

        let (outcome, codes, explanation) = run(
            &pending(refusal.to_der().expect("encodes"), b"anything"),
            &[],
        );

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(explanation.contains("refused"), "unexpected: {explanation}");
    }

    #[test]
    fn a_response_wrapping_something_other_than_signed_data_is_rejected() {
        // Well-formed DER, a granted status, and a content type that is
        // not CMS `signedData`. Nothing here is structurally damaged, so
        // the refusal has to come from the type check rather than from a
        // decoder giving up.
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            token: Some(ContentInfo {
                // 1.2.840.113549.1.7.1 — `id-data`.
                content_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
                content: Any::null(),
            }),
        };

        let (outcome, codes, explanation) = run(
            &pending(response.to_der().expect("encodes"), b"anything"),
            &[],
        );

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("does not wrap CMS SignedData"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn a_granted_with_modifications_response_is_still_read() {
        // PKIStatus 1 means the authority granted the request but changed
        // something about it. The token is still a token, so refusing it
        // would discard a perfectly usable timestamp.
        let mut response = TimeStampResp::from_der(TOKEN).expect("the fixture response decodes");
        response.status.status = 1;

        let (outcome, codes, _) = run(
            &pending(
                response.to_der().expect("re-encodes"),
                b"not what was stamped",
            ),
            &[],
        );

        // It got as far as checking what the token covers, which is the
        // point: the status did not stop it.
        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MISMATCH]);
    }

    #[test]
    fn a_tst_info_of_another_version_is_refused() {
        // Re-encode the fixture's own TSTInfo with a version this code was
        // not written to read. Every other byte is the authority's.
        let signed_data = signed_data(TOKEN, TimestampStorage::SigTst).expect("unwraps");
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert!(
            tst_info(&content).is_ok(),
            "the fixture's own version is read"
        );

        let mut altered = TstInfo::from_der(&content).expect("decodes");
        altered.version = 2;
        let altered_der = altered.to_der().expect("re-encodes");

        assert_eq!(
            tst_info(&altered_der).err(),
            Some("the token's TSTInfo names a version this core does not read")
        );

        // And through the full `validate` pipeline, which is what actually
        // turns this into a `timeStamp.malformed` finding.
        let mut mutated = signed_data.clone();
        mutated.encap_content_info.econtent = Some(
            Any::encode_from(&OctetString::new(altered_der).expect("encodes")).expect("encodes"),
        );

        let (outcome, codes, explanation) =
            run(&pending(token_from(mutated), b"anything"), &anchors());
        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("names a version this core does not read"),
            "unexpected: {explanation}"
        );
    }

    /// A copy of `certificate` carrying somebody else's public key.
    ///
    /// Same subject, same issuer, wrong key — which is what a CA that has
    /// rolled its key leaves lying around, and what makes picking the next
    /// link by name alone a coin toss.
    fn same_name_wrong_key(certificate: &Certificate) -> Certificate {
        let mut impostor = certificate.clone();
        impostor.public_key = cert::decode(TEST_SIGNER_CERT)
            .expect("the test signer decodes")
            .public_key;
        impostor
    }

    #[test]
    fn the_path_picks_the_issuer_whose_key_actually_signed() {
        let leaf = cert::decode(FIXTURE_LEAF_CERT).expect("decodes");
        let issuer = cert::decode(FIXTURE_ISSUER_CERT).expect("decodes");

        // The impostor comes first, so a name-only match would take it.
        let pool = vec![same_name_wrong_key(&issuer), issuer.clone()];
        let path = order_path(&leaf, pool);

        assert_eq!(path.len(), 2);
        assert_eq!(
            path[1].public_key, issuer.public_key,
            "the path must follow the key that signed, not the first matching name"
        );

        // And the path it built actually verifies, which is the property
        // the choice exists to preserve.
        assert!(chain::verify(&path[0], &path[1]).is_ok());
    }

    #[test]
    fn a_path_with_no_verifying_issuer_still_names_the_signature() {
        // When nothing in the pool holds the right key, the name match is
        // still taken: "this signature does not verify" is a more accurate
        // finding than a path that quietly stops one link short.
        let leaf = cert::decode(FIXTURE_LEAF_CERT).expect("decodes");
        let issuer = cert::decode(FIXTURE_ISSUER_CERT).expect("decodes");

        let path = order_path(&leaf, vec![same_name_wrong_key(&issuer)]);

        assert_eq!(path.len(), 2, "the impostor is still placed in the path");
        assert!(chain::verify(&path[0], &path[1]).is_err());
    }

    #[test]
    fn the_authority_path_is_rebuilt_from_an_unordered_set() {
        // The token carries its three certificates as an ASN.1 SET, which
        // has no order. The path has to come out signer-first regardless,
        // and reach the root the token also ships.
        let signed_data = signed_data(TOKEN, TimestampStorage::SigTst).expect("unwraps");
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");
        let signer = verify_signature(&signed_data, &content).expect("verifies");

        let path = authority_path(&signed_data, &signer);

        let subjects: Vec<&str> = path.iter().map(|c| c.subject.as_str()).collect();
        assert_eq!(path.len(), 3, "{subjects:?}");
        assert!(
            subjects[0].contains("DigiCert Timestamp 2023"),
            "{subjects:?}"
        );
        assert!(subjects[1].contains("TimeStamping CA"), "{subjects:?}");
        assert!(subjects[2].contains("Trusted Root G4"), "{subjects:?}");

        // Each link names the one above it, which is what makes the order
        // a fact rather than a guess.
        for pair in path.windows(2) {
            assert_eq!(pair[0].issuer, pair[1].subject);
        }
    }

    #[test]
    fn the_token_is_untrusted_without_a_configured_anchor() {
        // Same token, same checks — the only thing missing is a reason to
        // believe the authority.
        let signed_data = signed_data(TOKEN, TimestampStorage::SigTst).expect("unwraps");
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");
        let tst_info = TstInfo::from_der(&content).expect("decodes");

        assert_eq!(gen_time_seconds(&tst_info.gen_time), GEN_TIME);

        let countersigned = b"whatever this token actually stamps";
        let stamped = pending(TOKEN.to_vec(), countersigned);

        // The imprint check refuses these bytes before trust is reached,
        // which is the ordering this test exists to pin: a token is never
        // called trusted on the strength of its authority alone.
        assert_eq!(run(&stamped, &anchors()).0, Timestamped::Rejected);
    }

    /// The token's `SignedData`, decoded fresh so mutations in one test
    /// cannot bleed into another.
    fn fixture_signed_data() -> SignedData {
        signed_data(TOKEN, TimestampStorage::SigTst).expect("unwraps")
    }

    /// Rewraps a `SignedData` into a `sigTst`-framed token, the reverse of
    /// [`fixture_signed_data`].
    fn token_from(signed_data: SignedData) -> Vec<u8> {
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            token: Some(ContentInfo {
                content_type: ID_SIGNED_DATA,
                content: Any::encode_from(&signed_data).expect("encodes"),
            }),
        };
        response.to_der().expect("encodes")
    }

    /// The token's own (single) `SignerInfo`, to mutate a copy of.
    fn fixture_signer_info(signed_data: &SignedData) -> SignerInfo {
        signed_data
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("the fixture carries a signer")
            .clone()
    }

    /// Replaces a token's one `SignerInfo` with a mutated copy.
    fn with_signer_info(mut signed_data: SignedData, info: SignerInfo) -> SignedData {
        signed_data.signer_infos = SignerInfos(SetOfVec::try_from(vec![info]).expect("orders"));
        signed_data
    }

    /// A copy of `attrs` with `oid`'s attribute, if any, removed.
    fn without_attribute(attrs: &Attributes, oid: ObjectIdentifier) -> Attributes {
        let kept: Vec<Attribute> = attrs.iter().filter(|a| a.oid != oid).cloned().collect();
        Attributes::try_from(kept).expect("orders")
    }

    /// A copy of `attrs` with `oid`'s attribute replaced by an OID value —
    /// the shape the `content-type` attribute takes.
    fn with_oid_attribute(
        attrs: &Attributes,
        oid: ObjectIdentifier,
        value: ObjectIdentifier,
    ) -> Attributes {
        let mut kept: Vec<Attribute> = attrs.iter().filter(|a| a.oid != oid).cloned().collect();
        kept.push(Attribute {
            oid,
            values: SetOfVec::try_from(vec![Any::encode_from(&value).expect("encodes")])
                .expect("orders"),
        });
        Attributes::try_from(kept).expect("orders")
    }

    #[test]
    fn tst_info_der_rejects_the_wrong_econtent_type() {
        let mut signed_data = fixture_signed_data();
        signed_data.encap_content_info.econtent_type = ID_SIGNED_DATA;

        assert_eq!(
            tst_info_der(&signed_data),
            Err("the timestamp token does not encapsulate a TSTInfo")
        );

        // And through the full `validate` pipeline, which is what actually
        // turns this into a `timeStamp.malformed` finding.
        let (outcome, codes, explanation) =
            run(&pending(token_from(signed_data), b"anything"), &anchors());
        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("does not encapsulate a TSTInfo"),
            "unexpected: {explanation}"
        );
    }

    #[test]
    fn tst_info_der_rejects_missing_content() {
        let mut signed_data = fixture_signed_data();
        signed_data.encap_content_info.econtent = None;

        assert_eq!(
            tst_info_der(&signed_data),
            Err("the timestamp token encapsulates no content")
        );
    }

    #[test]
    fn tst_info_der_rejects_content_that_is_not_an_octet_string() {
        let mut signed_data = fixture_signed_data();
        signed_data.encap_content_info.econtent = Some(Any::null());

        assert_eq!(
            tst_info_der(&signed_data),
            Err("the timestamp token's content is not an octet string")
        );
    }

    #[test]
    fn verify_signature_rejects_a_content_type_that_is_not_tst_info() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);
        info.signed_attrs = info
            .signed_attrs
            .as_ref()
            .map(|attrs| with_oid_attribute(attrs, ID_CONTENT_TYPE, ID_SIGNED_DATA));
        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err("the timestamp token's content-type attribute is not a TSTInfo")
        );
    }

    #[test]
    fn verify_signature_rejects_a_missing_content_type_attribute() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);
        info.signed_attrs = info
            .signed_attrs
            .as_ref()
            .map(|attrs| without_attribute(attrs, ID_CONTENT_TYPE));
        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err("the timestamp token carries no content-type attribute")
        );
    }

    #[test]
    fn verify_signature_rejects_a_missing_message_digest_attribute() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);
        info.signed_attrs = info
            .signed_attrs
            .as_ref()
            .map(|attrs| without_attribute(attrs, ID_MESSAGE_DIGEST));
        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err("the timestamp token carries no message-digest attribute")
        );
    }

    #[test]
    fn verify_signature_rejects_an_unsupported_digest_algorithm() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);
        info.digest_alg = AlgorithmIdentifierOwned {
            // 1.2.840.113549.2.5 - MD5, not a hash this core computes.
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
            parameters: None,
        };
        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err("the timestamp token names a digest this core cannot compute")
        );
    }

    #[test]
    fn verify_signature_rejects_a_signer_identified_by_key_identifier() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);
        info.sid = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
            OctetString::new(vec![0u8; 20]).expect("encodes"),
        ));
        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err(
                "the timestamp token identifies its signer by key identifier, which this core does not resolve"
            )
        );
    }

    #[test]
    fn verify_signature_rejects_a_signer_no_certificate_matches() {
        let signed_data = fixture_signed_data();
        let mut info = fixture_signer_info(&signed_data);

        let SignerIdentifier::IssuerAndSerialNumber(mut wanted) = info.sid.clone() else {
            panic!("the fixture identifies its signer by issuer and serial number");
        };
        wanted.serial_number = SerialNumber::new(&[0x7f]).expect("encodes");
        info.sid = SignerIdentifier::IssuerAndSerialNumber(wanted);

        let signed_data = with_signer_info(signed_data, info);
        let content = tst_info_der(&signed_data).expect("has a TSTInfo");

        assert_eq!(
            verify_signature(&signed_data, &content),
            Err("the timestamp token does not carry the certificate that signed it")
        );
    }

    #[test]
    fn certificates_filters_out_non_certificate_choices() {
        let mut signed_data = fixture_signed_data();
        let before = certificates(&signed_data).len();

        let mut choices: Vec<CertificateChoices> = signed_data
            .certificates
            .as_ref()
            .expect("the fixture carries certificates")
            .0
            .as_slice()
            .to_vec();

        // An attribute certificate carries no public key, so it can never
        // be part of a path — `certificates` drops it rather than passing
        // it through for `x509_cert::Certificate::from_der` to choke on.
        choices.push(CertificateChoices::Other(OtherCertificateFormat {
            other_cert_format: ObjectIdentifier::new_unwrap("1.2.3.4"),
            other_cert: Any::null(),
        }));
        signed_data.certificates =
            Some(CertificateSet(SetOfVec::try_from(choices).expect("orders")));

        assert_eq!(certificates(&signed_data).len(), before);
    }

    /// `2.16.840.1.101.3.4.2.1` — SHA-256, used to build the CMS
    /// `message-digest` attribute below.
    const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

    /// `1.2.840.10045.4.3.2` — `ecdsa-with-SHA256`, the CMS signature
    /// algorithm that matches [`TEST_SIGNER_KEY`].
    const ECDSA_WITH_SHA256_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// Builds a `sigTst`-framed token, signed for real with
    /// [`TEST_SIGNER_KEY`], whose `TSTInfo` is exactly `tst_info`.
    ///
    /// Unlike the other tests in this module, which mutate fields the real
    /// fixture's already-verified signature never covers, this one has to
    /// sign its own: every check `verify_signature` runs before the
    /// message-imprint-algorithm check below happens to reach passes only
    /// when the signature genuinely verifies, and altering the `TSTInfo`
    /// changes what the `message-digest` attribute must cover.
    fn self_signed_token(tst_info: &TstInfo) -> Vec<u8> {
        let tst_info_der = tst_info.to_der().expect("encodes");
        let digest = HashAlgorithm::Sha256.digest(&tst_info_der);

        let signed_attrs: Attributes = SetOfVec::try_from(vec![
            Attribute {
                oid: ID_CONTENT_TYPE,
                values: SetOfVec::try_from(vec![
                    Any::encode_from(&ID_CT_TST_INFO).expect("encodes")
                ])
                .expect("orders"),
            },
            Attribute {
                oid: ID_MESSAGE_DIGEST,
                values: SetOfVec::try_from(vec![Any::encode_from(
                    &OctetString::new(digest).expect("encodes"),
                )
                .expect("encodes")])
                .expect("orders"),
            },
        ])
        .expect("orders");

        let signer = c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .expect("the test key is valid");
        let signature = signer
            .sign(&signed_attrs.to_der().expect("encodes"))
            .expect("signs");

        let signer_cert = x509_cert::Certificate::from_der(TEST_SIGNER_CERT).expect("decodes");

        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: signer_cert.tbs_certificate.issuer.clone(),
                serial_number: signer_cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: AlgorithmIdentifierOwned {
                oid: SHA256_OID,
                parameters: None,
            },
            signed_attrs: Some(signed_attrs),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: OctetString::new(signature).expect("encodes"),
            unsigned_attrs: None,
        };

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![AlgorithmIdentifierOwned {
                oid: SHA256_OID,
                parameters: None,
            }])
            .expect("orders"),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(
                    Any::encode_from(&OctetString::new(tst_info_der).expect("encodes"))
                        .expect("encodes"),
                ),
            },
            certificates: Some(CertificateSet(
                SetOfVec::try_from(vec![CertificateChoices::Certificate(signer_cert)])
                    .expect("orders"),
            )),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info]).expect("orders")),
        };

        token_from(signed_data)
    }

    #[test]
    fn an_unsupported_message_imprint_algorithm_is_rejected() {
        let tst_info = TstInfo {
            version: TST_INFO_VERSION,
            policy: ObjectIdentifier::new_unwrap("1.2.3.4"),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    // 1.2.840.113549.2.5 - MD5, not a hash this core computes.
                    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
                    parameters: None,
                },
                hashed_message: OctetString::new(vec![0u8; 16]).expect("encodes"),
            },
            serial_number: Int::new(&[1]).expect("encodes"),
            gen_time: GeneralizedTime::from_unix_duration(Duration::from_secs(GEN_TIME as u64))
                .expect("encodes"),
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };

        let (outcome, codes, explanation) =
            run(&pending(self_signed_token(&tst_info), b"anything"), &[]);

        assert_eq!(outcome, Timestamped::Rejected);
        assert_eq!(codes, [status_code::TIMESTAMP_MALFORMED]);
        assert!(
            explanation.contains("uses a hash this core cannot compute"),
            "unexpected: {explanation}"
        );
    }
}
