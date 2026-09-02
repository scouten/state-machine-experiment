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

//! The contract `src/cert.rs` must satisfy, whichever decoder backs it.
//!
//! # Why this file exists
//!
//! `cert.rs` is a seam (see its module docs): the plan is to replace
//! `x509-cert` with a DER reader of our own, scoped to exactly the
//! structures the C2PA certificate profile needs.
//! Hand-written parsing of attacker-controlled input is only responsible
//! if the replacement can be held against something. This is that
//! something.
//!
//! # Where the expected values come from
//!
//! **Not** from running our decoder and recording what it said — that
//! would freeze in whatever it gets wrong. Every value below was produced
//! by OpenSSL 3.0.13, an independent implementation:
//!
//! ```text
//! openssl x509 -in <f> -inform DER -noout -dates \
//!     -ext basicConstraints,keyUsage,extendedKeyUsage
//! openssl x509 -in <f> -inform DER -noout -pubkey \
//!     | openssl pkey -pubin -outform DER | openssl dgst -sha256
//! ```
//!
//! Validity instants were converted to Unix seconds independently of the
//! crate. A replacement decoder is correct, for our purposes, when this
//! file still passes untouched.
//!
//! # Why the public key is pinned by digest
//!
//! It is the one field a mistake in silently breaks *verification* rather
//! than parsing: a decoder that re-encodes `SubjectPublicKeyInfo` even
//! slightly differently produces a key the validators reject, and the
//! symptom is "this valid manifest is invalid". Comparing the exact bytes
//! leaves no room for that.

use contentauth_c2pa_reader::Certificate;
use sha2::{Digest, Sha256};

/// A certificate in the corpus, with what OpenSSL says about it.
struct Expected {
    name: &'static str,
    der: &'static [u8],
    subject_contains: &'static str,
    issuer_contains: &'static str,
    not_before: i64,
    not_after: i64,
    /// `(cA, pathLenConstraint)`.
    basic_constraints: Option<(bool, Option<u8>)>,
    /// `(digitalSignature, nonRepudiation, keyCertSign, crlSign)`.
    key_usage: Option<(bool, bool, bool, bool)>,
    extended_key_usage: Option<&'static [&'static str]>,
    spki_len: usize,
    spki_sha256: &'static str,
}

const CORPUS: &[Expected] = &[
    // The end-entity certificate that signed `manifest_data.c2pa`.
    // RSASSA-PSS, 4096-bit — the algorithm whose X.509 parameters are
    // context-tagged optionals with defaults, and so the one most likely
    // to trip a hand-written decoder.
    Expected {
        name: "signer-leaf",
        der: include_bytes!("fixtures/signer-leaf.der"),
        subject_contains: "CN=C2PA Signer",
        issuer_contains: "CN=Intermediate CA",
        not_before: 1_654_886_788,
        not_after: 1_914_000_388,
        basic_constraints: Some((false, None)),
        key_usage: Some((true, true, false, false)),
        // emailProtection, which the C2PA profile allows for claim signing.
        extended_key_usage: Some(&["1.3.6.1.5.5.7.3.4"]),
        spki_len: 602,
        spki_sha256: "873fe22e952da6cffcb199c4b577b70fef965cd6a2f710cf123f2a9dd54eb086",
    },
    // The intermediate that issued it: a CA, and carrying no EKU at all —
    // which is why absence has to stay distinguishable from an empty list.
    Expected {
        name: "signer-issuer",
        der: include_bytes!("fixtures/signer-issuer.der"),
        subject_contains: "CN=Intermediate CA",
        issuer_contains: "CN=Root CA",
        not_before: 1_654_886_786,
        not_after: 1_914_086_786,
        basic_constraints: Some((true, None)),
        key_usage: Some((true, false, true, true)),
        extended_key_usage: None,
        spki_len: 602,
        spki_sha256: "d95585540040ed4f07d69e965d91ea2de483a9147ffb3dfe1ed2a040ba881fec",
    },
    // The synthetic signer used by unit tests: ECDSA P-256, self-signed,
    // and so a different key encoding from the two above.
    Expected {
        name: "test-signer",
        der: include_bytes!("fixtures/test-signer.der"),
        subject_contains: "CN=Synthetic Test Signer",
        issuer_contains: "CN=Synthetic Test Signer",
        not_before: 1_788_010_370,
        not_after: 4_941_610_370,
        basic_constraints: Some((false, None)),
        key_usage: Some((true, true, false, false)),
        extended_key_usage: Some(&["1.3.6.1.5.5.7.3.4"]),
        spki_len: 91,
        spki_sha256: "b3f100913f58fce01665188acfc3982bab4a25de9a686b182747374ad92cc729",
    },
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_certificate_in_the_corpus_decodes_as_openssl_reads_it() {
    for expected in CORPUS {
        let cert: Certificate = contentauth_c2pa_reader::cert::decode(expected.der)
            .unwrap_or_else(|e| panic!("{}: {e}", expected.name));

        let name = expected.name;

        assert!(
            cert.subject.contains(expected.subject_contains),
            "{name}: subject {:?} does not contain {:?}",
            cert.subject,
            expected.subject_contains
        );
        assert!(
            cert.issuer.contains(expected.issuer_contains),
            "{name}: issuer {:?} does not contain {:?}",
            cert.issuer,
            expected.issuer_contains
        );

        assert_eq!(cert.not_before, expected.not_before, "{name}: not_before");
        assert_eq!(cert.not_after, expected.not_after, "{name}: not_after");
        assert_eq!(
            cert.basic_constraints.map(|bc| (bc.is_ca, bc.path_len)),
            expected.basic_constraints,
            "{name}: basic constraints"
        );
        assert_eq!(
            cert.key_usage.map(|ku| (
                ku.digital_signature,
                ku.non_repudiation,
                ku.key_cert_sign,
                ku.crl_sign
            )),
            expected.key_usage,
            "{name}: key usage"
        );
        assert_eq!(
            cert.extended_key_usage.as_deref(),
            expected
                .extended_key_usage
                .map(|eku| eku.iter().map(|o| o.to_string()).collect::<Vec<_>>())
                .as_deref(),
            "{name}: extended key usage"
        );

        assert_eq!(
            cert.public_key.len(),
            expected.spki_len,
            "{name}: SPKI size"
        );
        assert_eq!(
            hex(&Sha256::digest(&cert.public_key)),
            expected.spki_sha256,
            "{name}: SPKI bytes"
        );
    }
}

#[test]
fn the_corpus_certificates_are_the_ones_the_real_manifest_carries() {
    // The chain fixtures are kept as standalone files so that certificate
    // decoding can be tested without first going through the COSE layer.
    // That only buys independence if they really are the bytes the
    // manifest carries, so the duplication is checked rather than assumed:
    // each must appear verbatim inside the manifest store.
    let store: &[u8] = include_bytes!("fixtures/manifest_data.c2pa");

    let chain: [(&str, &[u8]); 4] = [
        ("signer-leaf", include_bytes!("fixtures/signer-leaf.der")),
        (
            "signer-issuer",
            include_bytes!("fixtures/signer-issuer.der"),
        ),
        // The timestamp token and the authority root inside it are held
        // standalone for the same reason and are checked the same way.
        (
            "timestamp-token",
            include_bytes!("fixtures/timestamp-token.der"),
        ),
        (
            "digicert-trusted-root-g4",
            include_bytes!("fixtures/digicert-trusted-root-g4.der"),
        ),
    ];

    for (name, der) in chain {
        assert!(
            store.windows(der.len()).any(|window| window == der),
            "{name}.der does not appear in manifest_data.c2pa; the fixture \
             has drifted from the manifest it was extracted from"
        );
    }
}
