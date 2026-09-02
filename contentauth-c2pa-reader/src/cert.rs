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

//! The X.509 boundary.
//!
//! # Why this module is a seam
//!
//! Everything the core knows about certificates enters through
//! [`decode`], and no type from the underlying ASN.1 library appears in
//! this module's signatures — not in [`Certificate`], not in
//! [`CertError`].
//! The decoder is an implementation detail on purpose.
//!
//! Today that decoder is [`x509_cert`], chosen because RustCrypto's `der`
//! is a hand-written codec rather than a parser-combinator library, and so
//! brings no `nom` — unlike `x509-parser`, `asn1-rs` and `rasn`, which all
//! reach a `nom` release from January 2023. The intent is to replace it
//! with a DER reader of our own, scoped to exactly the structures below.
//! That swap is meant to be a change to this file alone; if it ever needs
//! to be more than that, this seam has leaked.
//!
//! # What is decoded, and what is not
//!
//! Only the fields the C2PA certificate profile constrains, plus the
//! material needed to verify the certificate's own signature. The core has
//! no clock and no trust store of its own, so this module answers "what
//! does this certificate say", never "should it be trusted" — validity
//! windows are returned as instants to compare, not compared here, and
//! [`Certificate::tbs`] and [`Certificate::signature`] are handed out for
//! someone else to check.
//!
//! That someone is the crate's `chain` module, which builds paths,
//! verifies each link, and consults the host's anchors. Splitting it that
//! way keeps this module free of policy: it is the only place that knows
//! about ASN.1, and nothing here decides anything.
//!
//! Deliberately absent: revocation state, policy constraints and name
//! constraints (nothing consumes them yet), and the parts of the profile
//! that need detail this struct does not carry — the signature-algorithm
//! and named-curve allowlists, and the RSA minimum modulus size. Adding
//! those means widening [`Certificate`], which is a change to this seam and
//! so belongs in a slice of its own.

use der::{oid::ObjectIdentifier, Decode, Encode};
use pkcs1::RsaPssParams;
use x509_cert::ext::pkix::{BasicConstraints as X509BasicConstraints, KeyUsage as X509KeyUsage};

/// Reasons a certificate could not be decoded.
///
/// Deliberately a type of this module's own rather than the decoder's:
/// letting an ASN.1 library's error type surface here would make replacing
/// that library a breaking change to this crate.
///
/// These are *findings*, not workflow failures — a manifest signed with an
/// undecodable certificate produces a report saying so, in keeping with
/// the rest of this crate's validation model.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CertError {
    /// The bytes are not a well-formed X.509 certificate.
    #[error("not a well-formed X.509 certificate")]
    Malformed,

    /// An extension the C2PA profile relies on could not be decoded.
    #[error("malformed {extension} extension")]
    MalformedExtension {
        /// Name of the offending extension.
        extension: &'static str,
    },

    /// The subject public key could not be encoded as SPKI.
    #[error("subject public key could not be encoded")]
    MalformedPublicKey,

    /// The certificate's signature is not a whole number of bytes.
    #[error("certificate signature is not a whole number of bytes")]
    MalformedSignature,
}

/// One certificate from a claim signature's chain.
///
/// Field types are deliberately plain — no ASN.1 library types — so that
/// replacing the decoder cannot ripple outward. Times are Unix seconds
/// because the core has no clock of its own: it compares these against a
/// signing time the host supplies.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Certificate {
    /// Distinguished name of the certificate's subject, in RFC 4514 form.
    pub subject: String,

    /// Distinguished name of the issuer, in RFC 4514 form. Chain building
    /// matches this against the subject of the issuing certificate.
    pub issuer: String,

    /// DER-encoded `SubjectPublicKeyInfo`.
    ///
    /// This is the form the raw signature validators want, so it is kept
    /// as bytes rather than decomposed into curve and point.
    pub public_key: Vec<u8>,

    /// Start of the validity window, in seconds since the Unix epoch.
    pub not_before: i64,

    /// End of the validity window, in seconds since the Unix epoch.
    pub not_after: i64,

    /// The basic constraints extension, if present. Absent means the
    /// certificate asserts nothing, which for an end-entity certificate is
    /// different from asserting `cA=false`.
    pub basic_constraints: Option<BasicConstraints>,

    /// The key usage extension, if present.
    pub key_usage: Option<KeyUsage>,

    /// Extended key usage purposes, as dotted-decimal OIDs, if the
    /// extension is present. An empty vector means the extension was
    /// present but named no purposes.
    pub extended_key_usage: Option<Vec<String>>,

    /// The DER of this certificate's `TBSCertificate` — the exact bytes
    /// its issuer signed.
    ///
    /// Kept verbatim rather than re-derived: re-encoding could differ from
    /// what was signed and would fail verification for a certificate that
    /// is perfectly good.
    pub tbs: Vec<u8>,

    /// The issuer's signature over [`Self::tbs`].
    pub signature: Vec<u8>,

    /// How that signature was made, as the algorithm's DER-encoded OID
    /// value.
    ///
    /// Bytes rather than a parsed OID type, for the same reason the rest
    /// of this struct is plain: no decoder type crosses the seam. The
    /// caller pairs these with [`Self::signature_hash`] to pick a
    /// verifier.
    pub signature_algorithm: Vec<u8>,

    /// The digest the signature algorithm uses, where the algorithm
    /// carries it separately.
    ///
    /// RSASSA-PSS does: its `AlgorithmIdentifier` names only "PSS", and
    /// the hash lives in the parameters. Algorithms that name the hash in
    /// the OID itself — `ecdsa-with-SHA256`, say — leave this `None`.
    pub signature_hash: Option<Vec<u8>>,
}

/// The parts of the basic constraints extension the C2PA profile uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BasicConstraints {
    /// Whether the certificate may act as a certificate authority.
    pub is_ca: bool,

    /// Maximum number of intermediates that may follow it in a chain.
    pub path_len: Option<u8>,
}

/// The key usage bits the C2PA profile constrains.
///
/// Only the bits this core has a use for are surfaced; the others are
/// carried by neither the profile nor any check we make.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct KeyUsage {
    /// `digitalSignature` — required of a claim-signing certificate.
    pub digital_signature: bool,

    /// `nonRepudiation` (also called `contentCommitment`).
    pub non_repudiation: bool,

    /// `keyCertSign` — required of a certificate that signs others.
    pub key_cert_sign: bool,

    /// `crlSign`.
    pub crl_sign: bool,
}

/// Decodes one DER-encoded certificate.
///
/// Note that a certificate can decode perfectly and still be unacceptable
/// — that judgment belongs to the caller, which has the trust
/// configuration and the signing time this module deliberately lacks.
///
/// Public so that `tests/cert_contract.rs` can hold this seam against an
/// independent implementation; see that file.
pub fn decode(der: &[u8]) -> Result<Certificate, CertError> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| CertError::Malformed)?;
    let tbs = &cert.tbs_certificate;

    let public_key = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|_| CertError::MalformedPublicKey)?;

    let basic_constraints = tbs
        .get::<X509BasicConstraints>()
        .map_err(|_| CertError::MalformedExtension {
            extension: "basic constraints",
        })?
        .map(|(_critical, bc)| BasicConstraints {
            is_ca: bc.ca,
            path_len: bc.path_len_constraint,
        });

    let key_usage = tbs
        .get::<X509KeyUsage>()
        .map_err(|_| CertError::MalformedExtension {
            extension: "key usage",
        })?
        .map(|(_critical, ku)| KeyUsage {
            digital_signature: ku.digital_signature(),
            non_repudiation: ku.non_repudiation(),
            key_cert_sign: ku.key_cert_sign(),
            crl_sign: ku.crl_sign(),
        });

    let extended_key_usage = tbs
        .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
        .map_err(|_| CertError::MalformedExtension {
            extension: "extended key usage",
        })?
        .map(|(_critical, eku)| eku.0.iter().map(ObjectIdentifier::to_string).collect());

    let signature = cert
        .signature
        .as_bytes()
        .ok_or(CertError::MalformedSignature)?
        .to_vec();

    Ok(Certificate {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        public_key,
        not_before: unix_seconds(&tbs.validity.not_before),
        not_after: unix_seconds(&tbs.validity.not_after),
        basic_constraints,
        key_usage,
        extended_key_usage,
        tbs: tbs.to_der().map_err(|_| CertError::Malformed)?,
        signature,
        signature_algorithm: cert.signature_algorithm.oid.as_bytes().to_vec(),
        signature_hash: signature_hash(&cert.signature_algorithm)?,
    })
}

/// Extracts the digest an algorithm names separately from itself.
///
/// Only RSASSA-PSS does this, and its parameters are context-tagged
/// optionals with defaults — fiddly enough that they are decoded properly
/// rather than walked by hand.
fn signature_hash(
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
) -> Result<Option<Vec<u8>>, CertError> {
    if algorithm.oid != RSA_PSS_OID {
        return Ok(None);
    }

    let Some(parameters) = algorithm.parameters.as_ref() else {
        // PSS without parameters names no digest, so nothing can be
        // paired with it.
        return Err(CertError::MalformedExtension {
            extension: "RSASSA-PSS parameters",
        });
    };

    let der = parameters
        .to_der()
        .map_err(|_| CertError::MalformedExtension {
            extension: "RSASSA-PSS parameters",
        })?;

    let params = RsaPssParams::from_der(&der).map_err(|_| CertError::MalformedExtension {
        extension: "RSASSA-PSS parameters",
    })?;

    Ok(Some(params.hash.oid.as_bytes().to_vec()))
}

/// `1.2.840.113549.1.1.10` — RSASSA-PSS.
const RSA_PSS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// Converts an ASN.1 time to seconds since the Unix epoch.
///
/// The underlying representation cannot express a pre-1970 instant, so the
/// conversion is total.
fn unix_seconds(time: &x509_cert::time::Time) -> i64 {
    // `as` is lossless here for every representable certificate date:
    // GeneralizedTime tops out at year 9999.
    time.to_unix_duration().as_secs() as i64
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The end-entity certificate from `tests/fixtures/manifest_data.c2pa`,
    /// extracted from the claim signature's `x5chain`.
    fn leaf() -> Certificate {
        decode(crate::test_support::FIXTURE_LEAF_CERT).unwrap()
    }

    #[test]
    fn decodes_the_fixture_leaf_certificate() {
        let cert = leaf();

        assert!(cert.subject.contains("CN=C2PA Signer"));
        assert!(cert.issuer.contains("CN=Intermediate CA"));

        // 2022-06-10T18:46:28Z .. 2030-08-26T18:46:28Z
        assert_eq!(cert.not_before, 1_654_886_788);
        assert_eq!(cert.not_after, 1_914_000_388);
        assert!(cert.not_before < cert.not_after);

        // The public key is re-encoded SPKI, which the raw validators
        // consume as-is; 4096-bit RSA lands comfortably over 512 bytes.
        assert!(cert.public_key.len() > 512);
    }

    #[test]
    fn decodes_the_profile_extensions() {
        let cert = leaf();

        assert_eq!(
            cert.basic_constraints,
            Some(BasicConstraints {
                is_ca: false,
                path_len: None
            })
        );

        assert_eq!(
            cert.key_usage,
            Some(KeyUsage {
                digital_signature: true,
                non_repudiation: true,
                key_cert_sign: false,
                crl_sign: false,
            })
        );

        // 1.3.6.1.5.5.7.3.4 is emailProtection, one of the purposes the
        // C2PA profile allows for a claim-signing certificate.
        assert_eq!(
            cert.extended_key_usage.as_deref(),
            Some(["1.3.6.1.5.5.7.3.4".to_string()].as_slice())
        );
    }

    #[test]
    fn decodes_a_ca_certificate() {
        let cert = decode(crate::test_support::FIXTURE_ISSUER_CERT).unwrap();

        assert!(cert.subject.contains("CN=Intermediate CA"));
        assert_eq!(
            cert.basic_constraints,
            Some(BasicConstraints {
                is_ca: true,
                path_len: None
            })
        );

        let key_usage = cert.key_usage.unwrap();
        assert!(key_usage.key_cert_sign);
        assert!(key_usage.crl_sign);

        // A CA certificate in this chain carries no EKU at all, which is
        // why absence has to be distinguishable from an empty list.
        assert!(cert.extended_key_usage.is_none());
    }

    /// Corrupts the DER *inside* one extension's `extnValue`, leaving the
    /// certificate structurally intact so that only that extension fails
    /// to decode.
    ///
    /// Each of the three extensions is encoded as OID, critical flag, then
    /// an `OCTET STRING` wrapping the extension's own DER — so the first
    /// tag byte of that inner DER always sits ten bytes past the OID. It
    /// is replaced with `05` (NULL), which is well-formed DER of the wrong
    /// type.
    fn corrupt_extension(oid_suffix: [u8; 3]) -> Vec<u8> {
        let mut der = crate::test_support::TEST_SIGNER_CERT.to_vec();
        let needle = [0x06, 0x03, oid_suffix[0], oid_suffix[1], oid_suffix[2]];

        let at = der
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("extension is present in the fixture");

        der[at + 10] = 0x05;
        der
    }

    #[test]
    fn an_extension_that_does_not_decode_is_reported_per_extension() {
        // 2.5.29.19 basicConstraints, 2.5.29.15 keyUsage,
        // 2.5.29.37 extKeyUsage.
        for (oid, extension) in [
            ([0x55, 0x1d, 0x13], "basic constraints"),
            ([0x55, 0x1d, 0x0f], "key usage"),
            ([0x55, 0x1d, 0x25], "extended key usage"),
        ] {
            assert_eq!(
                decode(&corrupt_extension(oid)),
                Err(CertError::MalformedExtension { extension }),
                "corrupting {extension} should name {extension}"
            );
        }

        // The uncorrupted fixture still decodes, so the test is not simply
        // rejecting everything.
        assert!(decode(crate::test_support::TEST_SIGNER_CERT).is_ok());
    }

    #[test]
    fn rejects_bytes_that_are_not_a_certificate() {
        assert!(matches!(decode(&[0u8; 8]), Err(CertError::Malformed)));
        assert_eq!(decode(&[]), Err(CertError::Malformed));

        // A truncated certificate is structurally damaged, not merely
        // unacceptable.
        let truncated = &crate::test_support::FIXTURE_LEAF_CERT[..200];
        assert!(matches!(decode(truncated), Err(CertError::Malformed)));
    }
}
