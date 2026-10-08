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

//! A throwaway self-signed CA, and an end-entity certificate it issues,
//! both Ed25519 — real X.509 and real signatures, anchored to nothing.
//!
//! **For local testing and samples only.** No trust store knows this CA; a
//! verifier must be told to trust [`EphemeralChain::ca_pem`] explicitly.
//!
//! # Sans-I/O
//!
//! Generating a chain needs two things only a host has: **entropy** (key
//! seeds and serial numbers) and **the time** (validity window). Both are
//! parameters — a `fill` closure and [`Params::now_unix`] — so this crate
//! reads no clock, touches no RNG, and (given the same inputs) produces
//! the same chain every time, which makes its output testable.
//!
//! The end-entity certificate carries what C2PA's certificate profile
//! requires of a signer: digital-signature key usage, the e-mail
//! protection EKU, and an Authority Key Identifier.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use contentauth_c2pa_primitives::SigningAlg;
use ed25519_dalek::{Signer, SigningKey as Ed25519Key};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyUsagePurpose, PublicKeyData, SerialNumber, SignatureAlgorithm, SigningKey,
    PKCS_ED25519,
};
use time::{Duration, OffsetDateTime};

/// Why a chain could not be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `now_unix` is not a representable date.
    #[error("the supplied time is out of range")]
    TimeOutOfRange,

    /// Certificate construction failed.
    #[error("certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
}

/// Inputs to [`generate`].
#[derive(Clone, Debug)]
pub struct Params<'a> {
    /// The end-entity certificate's common name.
    pub common_name: &'a str,

    /// The current time, in seconds since the Unix epoch. Both certificates
    /// are valid from a day before this until `validity_days` after it.
    pub now_unix: i64,

    /// How long the certificates remain valid, in days.
    pub validity_days: i64,
}

impl<'a> Params<'a> {
    /// Parameters with a one-year validity.
    pub fn new(common_name: &'a str, now_unix: i64) -> Self {
        Self {
            common_name,
            now_unix,
            validity_days: 365,
        }
    }
}

/// An Ed25519 key in the shape `rcgen` writes certificates around.
struct KeyPair {
    key: Ed25519Key,
    public: [u8; 32],
}

impl KeyPair {
    fn generate(fill: &mut dyn FnMut(&mut [u8])) -> Self {
        let mut seed = [0u8; 32];
        fill(&mut seed);
        let key = Ed25519Key::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        Self { key, public }
    }
}

impl PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.key.sign(msg).to_bytes().to_vec())
    }
}

/// A generated chain, and the key that signs with its end-entity
/// certificate.
pub struct EphemeralChain {
    /// The end-entity certificate, DER.
    pub ee_der: Vec<u8>,

    /// The CA certificate, DER.
    pub ca_der: Vec<u8>,

    /// The CA certificate, PEM: what a verifier is told to trust.
    pub ca_pem: String,

    key: Ed25519Key,
}

impl EphemeralChain {
    /// The certificates in the order a COSE `x5chain` wants them:
    /// end-entity first.
    pub fn x5chain(&self) -> Vec<Vec<u8>> {
        vec![self.ee_der.clone(), self.ca_der.clone()]
    }

    /// The signing algorithm the end-entity key uses.
    pub fn alg(&self) -> SigningAlg {
        SigningAlg::Ed25519
    }

    /// Signs `message` with the end-entity key, returning the 64-byte
    /// signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).to_bytes().to_vec()
    }
}

impl std::fmt::Debug for EphemeralChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralChain")
            .field("ee_der", &format_args!("{} bytes", self.ee_der.len()))
            .field("ca_der", &format_args!("{} bytes", self.ca_der.len()))
            .field("key", &"<redacted>")
            .finish()
    }
}

fn name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// A positive 16-byte serial: `rcgen` has no RNG here, and a DER INTEGER's
/// sign is its high bit.
fn serial(fill: &mut dyn FnMut(&mut [u8])) -> SerialNumber {
    let mut bytes = [0u8; 16];
    fill(&mut bytes);
    bytes[0] &= 0x7f;
    SerialNumber::from_slice(&bytes)
}

/// Generates a fresh CA and an end-entity certificate it signs.
///
/// `fill` must fill its argument with unpredictable bytes — the key seeds
/// are drawn from it, so a predictable source makes a predictable key. It
/// is called four times (two seeds, two serials).
pub fn generate(
    params: &Params<'_>,
    fill: &mut dyn FnMut(&mut [u8]),
) -> Result<EphemeralChain, Error> {
    let now =
        OffsetDateTime::from_unix_timestamp(params.now_unix).map_err(|_| Error::TimeOutOfRange)?;
    let not_before = now - Duration::days(1);
    let not_after = now
        .checked_add(Duration::days(params.validity_days))
        .ok_or(Error::TimeOutOfRange)?;

    let ca_key = KeyPair::generate(fill);
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = name("C2PA ephemeral CA (local use only)");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.serial_number = Some(serial(fill));
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let ee_key = KeyPair::generate(fill);
    let mut ee_params = CertificateParams::default();
    ee_params.distinguished_name = name(params.common_name);
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.serial_number = Some(serial(fill));
    ee_params.not_before = not_before;
    ee_params.not_after = not_after;
    // C2PA's certificate profile requires an Authority Key Identifier on the
    // end-entity certificate; rcgen writes it only when asked.
    ee_params.use_authority_key_identifier_extension = true;
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let ee_cert = ee_params.signed_by(&ee_key, &issuer)?;

    Ok(EphemeralChain {
        ee_der: ee_cert.der().to_vec(),
        ca_der: ca_cert.der().to_vec(),
        ca_pem: ca_cert.pem(),
        key: ee_key.key,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use ed25519_dalek::Verifier;

    use super::*;

    /// A deterministic "entropy" source: fine for a test, unusable for
    /// anything else.
    fn counter() -> impl FnMut(&mut [u8]) {
        let mut n = 0u8;
        move |buf: &mut [u8]| {
            for b in buf {
                n = n.wrapping_add(37);
                *b = n;
            }
        }
    }

    #[test]
    fn same_inputs_same_chain() {
        let p = Params::new("signer.local", 1_800_000_000);
        let a = generate(&p, &mut counter()).unwrap();
        let b = generate(&p, &mut counter()).unwrap();
        assert_eq!(a.ee_der, b.ee_der);
        assert_eq!(a.ca_der, b.ca_der);
        assert!(a.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn different_entropy_different_chain() {
        let p = Params::new("signer.local", 1_800_000_000);
        let a = generate(&p, &mut counter()).unwrap();
        let mut other = |buf: &mut [u8]| buf.fill(0x5a);
        let b = generate(&p, &mut other).unwrap();
        assert_ne!(a.ee_der, b.ee_der);
    }

    #[test]
    fn the_key_signs_and_chain_is_ee_first() {
        let chain = generate(&Params::new("signer.local", 1_800_000_000), &mut counter()).unwrap();
        let sig = chain.sign(b"hello");
        assert_eq!(sig.len(), 64);
        let signature = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        chain
            .key
            .verifying_key()
            .verify(b"hello", &signature)
            .unwrap();
        assert_eq!(
            chain.x5chain(),
            vec![chain.ee_der.clone(), chain.ca_der.clone()]
        );
        assert_eq!(chain.alg(), SigningAlg::Ed25519);
    }

    #[test]
    fn an_unrepresentable_time_is_an_error() {
        let p = Params::new("x", i64::MAX);
        assert!(matches!(
            generate(&p, &mut counter()),
            Err(Error::TimeOutOfRange)
        ));
    }
}
