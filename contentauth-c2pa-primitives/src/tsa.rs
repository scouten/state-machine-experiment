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
//! The two deterministic halves of an RFC 3161 timestamp authority round
//! trip, so that no host has to hand-roll DER: [`timestamp_request`]
//! encodes the `TimeStampReq` to send, and [`timestamp_token`] unwraps the
//! bare `TimeStampToken` out of the `TimeStampResp` that comes back.
//!
//! Neither performs any I/O. Sending the request is the host's job — an
//! HTTP `POST` with `Content-Type: application/timestamp-query` to the
//! authority's URL, whose body is the response (`application/timestamp-reply`)
//! — which is why this belongs next to the other shared encoders rather
//! than in any one host. The builder's `Timestamp` request asks the host
//! for exactly this round trip's result.
//!
//! Only what that round trip needs is implemented: a request over a
//! SHA-2 digest with `certReq` set (so the authority's certificate chain
//! travels inside the token, as C2PA validation needs), and a response
//! reader that checks the `PKIStatus` and hands back the token's DER
//! without interpreting it. Verifying the token is the reader's job.

use crate::{error::HostError, types::HashAlgorithm};

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;

/// The DER OID content bytes (`id-sha256`, `id-sha384`, `id-sha512`, in
/// the NIST arc 2.16.840.1.101.3.4.2) and the digest length of `alg`.
fn hash_params(alg: HashAlgorithm) -> (&'static [u8], usize) {
    match alg {
        HashAlgorithm::Sha256 => (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01], 32),
        HashAlgorithm::Sha384 => (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02], 48),
        HashAlgorithm::Sha512 => (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03], 64),
    }
}

/// Encodes a DER `TimeStampReq` asking for a timestamp over `digest`
/// (already computed with `hash_alg`), with `certReq` set.
///
/// The request carries no nonce: this crate has no randomness, and
/// checking one would mean decoding the returned token, which is the
/// reader's job (the token is bound to `digest` either way).
///
/// Fails if `digest` is not the length `hash_alg` produces.
pub fn timestamp_request(digest: &[u8], hash_alg: HashAlgorithm) -> Result<Vec<u8>, HostError> {
    let (oid, expected) = hash_params(hash_alg);
    if digest.len() != expected {
        return Err(HostError::new(format!(
            "a {hash_alg:?} digest is {expected} bytes, not {}",
            digest.len()
        )));
    }

    let algorithm = tlv(SEQUENCE, &[tlv(OID, oid), tlv(NULL, &[])].concat());
    let imprint = tlv(SEQUENCE, &[algorithm, tlv(OCTET_STRING, digest)].concat());

    let mut body = tlv(INTEGER, &[1]); // version v1
    body.extend(imprint);
    body.extend(tlv(BOOLEAN, &[0xff])); // certReq TRUE
    Ok(tlv(SEQUENCE, &body))
}

/// Extracts the bare `TimeStampToken` (a CMS `ContentInfo`, DER) from a
/// DER `TimeStampResp`, failing unless the authority granted the request
/// (`PKIStatus` 0, granted, or 1, granted with modifications).
///
/// The token is returned as the authority encoded it, byte for byte: what
/// goes into the manifest must be exactly what the authority signed.
pub fn timestamp_token(response: &[u8]) -> Result<Vec<u8>, HostError> {
    let (tag, resp, rest) = read_tlv(response)?;
    if tag != SEQUENCE || !rest.is_empty() {
        return Err(HostError::new("a TimeStampResp is a single SEQUENCE"));
    }

    let (tag, status_info, after_status) = read_tlv(resp)?;
    if tag != SEQUENCE {
        return Err(HostError::new("PKIStatusInfo is not a SEQUENCE"));
    }
    let (tag, status, _) = read_tlv(status_info)?;
    if tag != INTEGER {
        return Err(HostError::new("PKIStatus is not an INTEGER"));
    }
    match status {
        [0] | [1] => {}
        other => {
            return Err(HostError::new(format!(
                "the timestamp authority refused the request (PKIStatus {})",
                other.first().map_or(-1, |byte| i32::from(*byte))
            )))
        }
    }

    // The token is the next element, taken whole (header included).
    let (tag, content, _) = read_tlv(after_status)?;
    if tag != SEQUENCE {
        return Err(HostError::new(
            "the timestamp response carries no TimeStampToken",
        ));
    }
    let header = after_status.len() - read_tlv(after_status)?.2.len() - content.len();
    Ok(after_status[..header + content.len()].to_vec())
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Splits one DER element off the front of `input`: its tag, its content,
/// and whatever follows. Rejects indefinite lengths and truncation.
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), HostError> {
    let malformed = || HostError::new("malformed DER in the timestamp response");

    let (&tag, rest) = input.split_first().ok_or_else(malformed)?;
    let (&first, rest) = rest.split_first().ok_or_else(malformed)?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return Err(malformed());
        }
        let (len_bytes, rest) = rest.split_at(count);
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, rest)
    };
    if rest.len() < len {
        return Err(malformed());
    }
    let (content, rest) = rest.split_at(len);
    Ok((tag, content, rest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_sha256_request_has_the_canonical_encoding() {
        let request = timestamp_request(&[0xab; 32], HashAlgorithm::Sha256).unwrap();

        let mut expected = vec![
            0x30, 0x39, // TimeStampReq
            0x02, 0x01, 0x01, // version 1
            0x30, 0x31, // messageImprint
            0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, // sha-256, NULL
            0x04, 0x20,
        ];
        expected.extend([0xab; 32]);
        expected.extend([0x01, 0x01, 0xff]); // certReq
        assert_eq!(request, expected);
    }

    #[test]
    fn every_supported_algorithm_encodes_its_own_oid_and_length() {
        for (alg, len, last) in [
            (HashAlgorithm::Sha256, 32, 0x01),
            (HashAlgorithm::Sha384, 48, 0x02),
            (HashAlgorithm::Sha512, 64, 0x03),
        ] {
            let request = timestamp_request(&vec![7; len], alg).unwrap();
            let oid = [
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last, 0x05, 0x00,
            ];
            assert!(request.windows(oid.len()).any(|w| w == oid), "{alg:?}");
        }
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        assert!(timestamp_request(&[0; 31], HashAlgorithm::Sha256).is_err());
        assert!(timestamp_request(&[0; 32], HashAlgorithm::Sha512).is_err());
    }

    fn response(status: u8, token: Option<&[u8]>) -> Vec<u8> {
        let status_info = tlv(SEQUENCE, &tlv(INTEGER, &[status]));
        let mut body = status_info;
        if let Some(token) = token {
            body.extend(tlv(SEQUENCE, token));
        }
        tlv(SEQUENCE, &body)
    }

    #[test]
    fn the_token_is_returned_byte_for_byte() {
        let inner = vec![0x06, 0x01, 0x2a];
        let token = timestamp_token(&response(0, Some(&inner))).unwrap();
        assert_eq!(token, tlv(SEQUENCE, &inner));

        // Long-form length (a realistically sized token).
        let big = vec![7u8; 300];
        let token = timestamp_token(&response(1, Some(&big))).unwrap();
        assert_eq!(token, tlv(SEQUENCE, &big));
        assert_eq!(&token[..4], [0x30, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn a_refusal_or_a_missing_token_is_an_error() {
        let err = timestamp_token(&response(2, None)).unwrap_err();
        assert!(err.message.contains("refused"), "{err}");
        assert!(timestamp_token(&response(0, None)).is_err());
    }

    #[test]
    fn a_response_of_the_wrong_shape_is_an_error() {
        // PKIStatusInfo is not a SEQUENCE.
        let mut not_sequence = tlv(OCTET_STRING, &[0]);
        not_sequence.extend(tlv(SEQUENCE, &[1]));
        assert!(timestamp_token(&tlv(SEQUENCE, &not_sequence)).is_err());

        // PKIStatus is not an INTEGER.
        let status_info = tlv(SEQUENCE, &tlv(OCTET_STRING, &[0]));
        assert!(timestamp_token(&tlv(SEQUENCE, &status_info)).is_err());

        // Granted, but what follows is not a token SEQUENCE.
        let mut body = tlv(SEQUENCE, &tlv(INTEGER, &[0]));
        body.extend(tlv(OCTET_STRING, &[1]));
        let err = timestamp_token(&tlv(SEQUENCE, &body)).unwrap_err();
        assert!(err.message.contains("no TimeStampToken"), "{err}");
    }

    #[test]
    fn malformed_responses_are_errors_not_panics() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x80, 0x00, 0x00],
            &[0x30, 0x05, 0x30],
            &[0x04, 0x00],
        ] {
            assert!(timestamp_token(bad).is_err(), "{bad:?}");
        }
        let mut trailing = response(0, Some(&[1]));
        trailing.push(0);
        assert!(timestamp_token(&trailing).is_err());
    }
}
