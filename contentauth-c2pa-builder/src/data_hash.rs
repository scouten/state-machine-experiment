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

//! Encoder for the `c2pa.hash.data` assertion — a manifest's hard binding
//! to the asset it describes. The counterpart to
//! `contentauth-c2pa-reader`'s decoder of the same name.
//!
//! # Why this needs `pad`/`pad2` fields at all
//!
//! The assertion's `exclusions[0].start` names the offset the manifest
//! ends up embedded at — which is not known until *after* a placeholder
//! has actually been embedded and the host reports back where it landed.
//! But the placeholder's own size has to be decided *before* that, and
//! this assertion is part of what determines that size. [`encode`] breaks
//! the circularity by reserving room for the worst-case encoding up front
//! (see [`RESERVED_VARIABLE_LEN`]) and topping up two padding byte strings
//! — `pad` and `pad2`, a shape the reader's decoder already tolerates and
//! ignores — so that the real, almost always much smaller, encoding still
//! totals exactly the same number of bytes. Every integer stays ordinary
//! shortest-form CBOR throughout: see
//! [`contentauth_c2pa_primitives::cbor::pad_lens_for_target`] for why two
//! independent padding fields are used rather than one.

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::{
    cbor::{pad_lens_for_target, uint_head_len},
    ByteRange, HashAlgorithm,
};

use crate::error::Error;

/// Label of the data hash assertion (matches
/// `contentauth_c2pa_reader::data_hash::LABEL`, which is private to that
/// crate — this is this crate's own copy of the same C2PA-specified
/// value).
pub(crate) const LABEL: &str = "c2pa.hash.data";

/// The name recorded in a data hash assertion's `name` field.
///
/// Matches what `contentauth-c2pa-reader`'s own test fixtures use, which
/// in turn matches c2pa-rs's convention for a binding over the whole
/// JUMBF manifest.
const BINDING_NAME: &str = "jumbf manifest";

/// The widest a single shortest-form CBOR unsigned integer can ever be:
/// the one-byte head plus an 8-byte immediate, for values from 2^32 up to
/// [`i64::MAX`] (this assertion's wire format represents offsets as CBOR
/// integers, which this library represents as `i64`, so [`i64::MAX`] — not
/// `u64::MAX` — is the real ceiling; see
/// `contentauth_c2pa_reader::data_hash`'s decoder, which rejects a
/// negative `start`/`length` as malformed).
const MAX_INT_LEN: u64 = 9;

/// Total bytes reserved for "the two exclusion integers (`start`,
/// `length`), plus `pad` and `pad2`" — computed once, worst case, and
/// never revisited. An empty `pad` and `pad2` each cost one byte (their
/// own one-byte, zero-length head), so [`encode`]'s placeholder pass
/// reserves this many bytes regardless of the asset; every later pass
/// computes the real, typically much smaller, integer encodings and grows
/// `pad`/`pad2` to compensate, so this total never changes.
const RESERVED_VARIABLE_LEN: u64 = MAX_INT_LEN + MAX_INT_LEN + 1 + 1;

/// Encodes a `c2pa.hash.data` assertion.
///
/// `exclusion` is `None` for the placeholder pass, before the host has
/// reported where the manifest landed: a maximum-width placeholder
/// exclusion is encoded instead, sized so that the real exclusion —
/// reported once the placeholder has actually been embedded — never needs
/// more room than this reserves. `Some(exclusion)` produces the final,
/// real encoding, guaranteed to total the same length as the placeholder.
pub(crate) fn encode(
    hash_alg: HashAlgorithm,
    hash: &[u8],
    exclusion: Option<ByteRange>,
) -> Result<Vec<u8>, Error> {
    let (start, length) = match exclusion {
        Some(range) => (
            i64::try_from(range.start).map_err(|_| {
                Error::PlaceholderRangeInvalid("exclusion start does not fit a CBOR integer")
            })?,
            i64::try_from(range.len).map_err(|_| {
                Error::PlaceholderRangeInvalid("exclusion length does not fit a CBOR integer")
            })?,
        ),
        // The placeholder pass: any value whose shortest-form CBOR
        // encoding is the maximum width reserves the worst case. The
        // magnitude carries no other meaning and is overwritten before
        // this assertion is ever read.
        None => (i64::MAX, i64::MAX),
    };

    let real_ints_len = uint_head_len(start as u64) as u64 + uint_head_len(length as u64) as u64;
    let pads_target =
        RESERVED_VARIABLE_LEN
            .checked_sub(real_ints_len)
            .ok_or(Error::PlaceholderSizeMismatch(
                "exclusion integers exceeded the width reserved for them",
            ))?;
    let (pad_len, pad2_len) = pad_lens_for_target(pads_target).ok_or(
        Error::PlaceholderSizeMismatch("could not compute an exact padding length"),
    )?;

    let exclusion_map = Value::Map(BTreeMap::from([
        (Value::Text("start".to_string()), Value::Integer(start)),
        (Value::Text("length".to_string()), Value::Integer(length)),
    ]));

    let fields = BTreeMap::from([
        (
            Value::Text("exclusions".to_string()),
            Value::Array(vec![exclusion_map]),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(BINDING_NAME.to_string()),
        ),
        (
            Value::Text("alg".to_string()),
            Value::Text(hash_alg.c2pa_name().to_string()),
        ),
        (Value::Text("hash".to_string()), Value::Bytes(hash.to_vec())),
        (
            Value::Text("pad".to_string()),
            Value::Bytes(vec![0u8; pad_len as usize]),
        ),
        (
            Value::Text("pad2".to_string()),
            Value::Bytes(vec![0u8; pad2_len as usize]),
        ),
    ]);

    Ok(c2pa_cbor::to_vec(&Value::Map(fields))?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn placeholder_and_real_encodings_are_the_same_length() {
        let hash = vec![0xab; HashAlgorithm::Sha256.digest_len()];

        let placeholder = encode(HashAlgorithm::Sha256, &hash, None).unwrap();

        // A realistic small offset, far under the placeholder's reserved
        // worst-case width.
        let real_small = encode(
            HashAlgorithm::Sha256,
            &hash,
            Some(ByteRange {
                start: 20,
                len: 45884,
            }),
        )
        .unwrap();
        assert_eq!(placeholder.len(), real_small.len());

        // An offset crossing several CBOR width-class boundaries at once.
        let real_large = encode(
            HashAlgorithm::Sha256,
            &hash,
            Some(ByteRange {
                start: 5_000_000_000,
                len: 42,
            }),
        )
        .unwrap();
        assert_eq!(placeholder.len(), real_large.len());

        // The zero case: both integers as small as they can be.
        let real_zero = encode(
            HashAlgorithm::Sha256,
            &hash,
            Some(ByteRange { start: 0, len: 0 }),
        )
        .unwrap();
        assert_eq!(placeholder.len(), real_zero.len());
    }

    #[test]
    fn every_hash_algorithm_round_trips_through_the_reader_shaped_decoder() {
        // Exercise the same shapes contentauth-c2pa-reader's decoder
        // reads: a map with exclusions/name/alg/hash/pad/pad2.
        for hash_alg in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            let hash = vec![0x11; hash_alg.digest_len()];
            let bytes = encode(
                hash_alg,
                &hash,
                Some(ByteRange {
                    start: 1234,
                    len: 5678,
                }),
            )
            .unwrap();

            let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
            let map = decoded.as_map().unwrap();

            assert_eq!(
                map.get(&Value::Text("alg".to_string())),
                Some(&Value::Text(hash_alg.c2pa_name().to_string()))
            );
            assert_eq!(
                map.get(&Value::Text("hash".to_string())),
                Some(&Value::Bytes(hash))
            );

            let Some(Value::Array(exclusions)) = map.get(&Value::Text("exclusions".to_string()))
            else {
                panic!("expected an exclusions array");
            };
            assert_eq!(exclusions.len(), 1);
            let Value::Map(exclusion) = &exclusions[0] else {
                panic!("expected an exclusion map");
            };
            assert_eq!(
                exclusion.get(&Value::Text("start".to_string())),
                Some(&Value::Integer(1234))
            );
            assert_eq!(
                exclusion.get(&Value::Text("length".to_string())),
                Some(&Value::Integer(5678))
            );
        }
    }

    #[test]
    fn an_offset_that_does_not_fit_a_cbor_integer_is_refused() {
        let hash = vec![0u8; 32];
        let too_large = u64::try_from(i64::MAX).unwrap() + 1;

        assert!(matches!(
            encode(
                HashAlgorithm::Sha256,
                &hash,
                Some(ByteRange {
                    start: too_large,
                    len: 0
                })
            ),
            Err(Error::PlaceholderRangeInvalid(_))
        ));
    }
}
