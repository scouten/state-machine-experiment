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

//! A small, hand-rolled, deterministic CBOR encoder for the handful of
//! structures both the reader and the builder must agree on byte for byte.
//!
//! # Why this exists instead of going through a general encoder
//!
//! [`sig_structure`] builds the exact bytes a COSE signature covers (RFC
//! 9052's `Sig_structure`). The reader reconstructs these bytes to verify a
//! signature; the builder constructs the identical bytes to produce one to
//! sign. A byte-for-byte disagreement between those two computations would
//! be a serious bug — a signature that verifies against the wrong bytes, or
//! a correct signature that appears broken — so this function lives in one
//! place both crates share, rather than being reimplemented twice.
//!
//! RFC 9052 requires deterministic encoding, and the structures here are
//! fixed shapes, so the heads are written directly rather than through a
//! general-purpose serializer: this makes shortest-form lengths a property
//! of a few auditable lines instead of an assumption about an external
//! encoder.

/// CBOR major type 2: byte string.
const MAJOR_BYTES: u8 = 2;

/// CBOR major type 3: text string.
const MAJOR_TEXT: u8 = 3;

/// CBOR major type 4: array.
const MAJOR_ARRAY: u8 = 4;

/// Writes a CBOR definite-length head in shortest form.
pub fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;

    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// The number of bytes shortest-form CBOR spends on a head encoding
/// `argument` — i.e. `head(&mut Vec::new(), major, argument).len()` for any
/// `major`, since the argument's magnitude (not the major type) is what
/// determines the head's width.
///
/// Used by a two-pass encoding scheme (see `contentauth-c2pa-builder`'s
/// `data_hash.rs`) to compute exactly how much a placeholder value's
/// encoded width differs from the real value's, so the difference can be
/// absorbed by a padding field rather than by producing non-shortest-form
/// CBOR — which deterministic/canonical CBOR (RFC 8949 §4.2) forbids an
/// encoder from doing, even though most decoders would still accept it.
pub const fn uint_head_len(argument: u64) -> usize {
    match argument {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Writes a CBOR byte string.
pub fn byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    head(out, MAJOR_BYTES, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Total encoded length of a CBOR byte string with `content_len` content
/// bytes: the shortest-form head plus the content itself.
const fn byte_string_len(content_len: u64) -> u64 {
    uint_head_len(content_len) as u64 + content_len
}

/// Finds the content length of a padding byte string that makes a CBOR
/// byte string (head plus content) total exactly `target` bytes.
///
/// A two-pass encoder that must keep a structure's total length invariant
/// across passes, even though some value inside it is only known on the
/// second pass, can reserve a fixed `target` for "the real value plus a
/// padding field" on the first pass, then use this on the second pass to
/// compute exactly how long the padding field's own content must be, once
/// the real value's own encoded length is known and subtracted out of
/// `target`. Every length stays ordinary shortest-form CBOR throughout;
/// nothing here produces non-canonical encoding.
///
/// Not every `target` has a solution: shortest-form CBOR's head width
/// jumps at fixed points (24, 256, 65536, …), so — for example — no byte
/// string's total encoded length is ever exactly 25 bytes, only 24 or 26.
/// [`pad_lens_for_target`] covers those gaps by splitting the padding
/// across two independent fields; prefer it unless a single field is
/// known to suffice.
pub fn pad_len_for_target(target: u64) -> Option<u64> {
    const HEAD_LENS: [u64; 5] = [1, 2, 3, 5, 9];

    for head_len in HEAD_LENS {
        if target < head_len {
            continue;
        }

        let pad_len = target - head_len;
        if uint_head_len(pad_len) as u64 == head_len {
            return Some(pad_len);
        }
    }

    None
}

/// As [`pad_len_for_target`], but splits the padding across two
/// independent byte strings — the same `pad`/`pad2` shape a C2PA hard
/// binding assertion already carries — so that the narrow gaps a single
/// field cannot hit (see that function's docs) are covered too: the sum of
/// two fields' achievable totals is far denser than either field's alone.
///
/// Returns `(pad_len, pad2_len)`. `None` only for a `target` too small to
/// hold even two empty byte strings (`target < 2`).
pub fn pad_lens_for_target(target: u64) -> Option<(u64, u64)> {
    /// How far to search for a `pad2` length before giving up. Gaps in a
    /// single field's achievable totals are always 1–2 bytes wide, so a
    /// handful of candidates is always enough in practice; this bound
    /// only guards against searching forever.
    const SEARCH_WIDTH: u64 = 32;

    for pad2_len in 0..=SEARCH_WIDTH.min(target) {
        let pad2_total = byte_string_len(pad2_len);
        if pad2_total > target {
            break;
        }

        if let Some(pad_len) = pad_len_for_target(target - pad2_total) {
            return Some((pad_len, pad2_len));
        }
    }

    None
}

/// Context string of a `COSE_Sign1` signature (RFC 9052 §4.4).
pub const CONTEXT_SIGNATURE1: &str = "Signature1";

/// Context string of a countersignature (RFC 9052 §4.5), which is what an
/// RFC 3161 timestamp on a C2PA claim signature is.
pub const CONTEXT_COUNTERSIGNATURE: &str = "CounterSignature";

/// Builds the `Sig_structure` bytes a COSE signature or countersignature
/// covers.
///
/// `context` selects which structure this is — see [`CONTEXT_SIGNATURE1`]
/// and [`CONTEXT_COUNTERSIGNATURE`]. The countersignature form used here is
/// the four-element one, with no `sign_protected` bucket.
pub fn sig_structure(context: &str, protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + payload.len() + 32);

    // Sig_structure = [ context, body_protected, external_aad, payload ]
    head(&mut out, MAJOR_ARRAY, 4);
    head(&mut out, MAJOR_TEXT, context.len() as u64);
    out.extend_from_slice(context.as_bytes());
    byte_string(&mut out, protected);
    // C2PA supplies no external additional authenticated data.
    byte_string(&mut out, &[]);
    byte_string(&mut out, payload);

    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn head_uses_shortest_form_at_every_width() {
        let widths: [(u64, &[u8]); 5] = [
            (23, &[0x77]),
            (24, &[0x78, 24]),
            (0x100, &[0x79, 0x01, 0x00]),
            (0x1_0000, &[0x7a, 0x00, 0x01, 0x00, 0x00]),
            (0x1_0000_0000, &[0x7b, 0, 0, 0, 1, 0, 0, 0, 0]),
        ];

        for (argument, expected) in widths {
            let mut out = Vec::new();
            head(&mut out, MAJOR_TEXT, argument);
            assert_eq!(out, expected, "argument {argument}");
        }
    }

    #[test]
    fn uint_head_len_matches_what_head_actually_writes() {
        let samples = [
            0u64,
            1,
            23,
            24,
            25,
            0xff,
            0x100,
            0x101,
            0xffff,
            0x1_0000,
            0x1_0001,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ];

        for argument in samples {
            let mut out = Vec::new();
            head(&mut out, MAJOR_BYTES, argument);
            assert_eq!(out.len(), uint_head_len(argument), "argument {argument:#x}");
        }
    }

    #[test]
    fn sig_structure_matches_the_rfc_9052_layout() {
        let protected = b"\xa0"; // an empty CBOR map, as a stand-in
        let tbs = sig_structure(CONTEXT_SIGNATURE1, protected, b"claim");

        // [ "Signature1", protected, h'', h'claim' ]
        let mut expected = vec![0x84, 0x6a];
        expected.extend_from_slice(b"Signature1");
        expected.push(0x40 | protected.len() as u8);
        expected.extend_from_slice(protected);
        expected.push(0x40);
        expected.extend_from_slice(&[0x45]);
        expected.extend_from_slice(b"claim");

        assert_eq!(tbs, expected);
    }

    /// For every `pad_len_for_target` result, a byte string built with that
    /// content length really does total `target` bytes.
    #[test]
    fn pad_len_for_target_is_self_consistent() {
        let targets = [
            1u64, 2, 3, 17, 18, 19, 24, 100, 256, 257, 10_000, 10_001, 65_535, 65_536, 65_537,
            100_000,
        ];

        for target in targets {
            let pad_len = pad_len_for_target(target)
                .unwrap_or_else(|| panic!("expected a solution for target {target}"));

            let mut out = Vec::new();
            byte_string(&mut out, &vec![0u8; pad_len as usize]);
            assert_eq!(
                out.len() as u64,
                target,
                "pad_len {pad_len} for target {target}"
            );
        }
    }

    /// A target too small to hold even an empty byte string's head has no
    /// solution.
    #[test]
    fn pad_len_for_target_rejects_impossible_targets() {
        assert_eq!(pad_len_for_target(0), None);
    }

    /// Not every target is reachable with a single padding field: nothing
    /// encodes to exactly 25 bytes (24 and 26 are both possible, 25 is a
    /// gap between the one-byte and two-byte head widths). This is the
    /// exact gap [`pad_lens_for_target`] exists to cover.
    #[test]
    fn pad_len_for_target_has_real_gaps() {
        assert_eq!(pad_len_for_target(25), None);
        assert_eq!(pad_len_for_target(258), None);
    }

    /// For every `pad_lens_for_target` result, two byte strings built with
    /// those content lengths really do total `target` bytes — including at
    /// the exact targets a single field cannot reach.
    #[test]
    fn pad_lens_for_target_is_self_consistent() {
        let targets = [
            2u64, 3, 17, 24, 25, 26, 100, 256, 257, 258, 259, 10_000, 10_001, 65_535, 65_536,
            65_537, 65_538, 65_539, 100_000,
        ];

        for target in targets {
            let (pad_len, pad2_len) = pad_lens_for_target(target)
                .unwrap_or_else(|| panic!("expected a solution for target {target}"));

            let mut out = Vec::new();
            byte_string(&mut out, &vec![0u8; pad_len as usize]);
            byte_string(&mut out, &vec![0u8; pad2_len as usize]);
            assert_eq!(
                out.len() as u64,
                target,
                "pad_len {pad_len}, pad2_len {pad2_len} for target {target}"
            );
        }
    }

    #[test]
    fn pad_lens_for_target_rejects_impossible_targets() {
        assert_eq!(pad_lens_for_target(0), None);
        assert_eq!(pad_lens_for_target(1), None);
    }

    /// The scenario this function exists for: a placeholder pass reserves
    /// `target` bytes total for "the real value plus padding," and once
    /// the real value's own length is known, the padding shrinks or grows
    /// to keep the total exactly `target` — across a width-class boundary
    /// in either direction.
    #[test]
    fn compensates_across_a_width_class_boundary() {
        // Reserve enough for a value up to 300 bytes (needs a 3-byte
        // head), plus no padding at all.
        let mut dummy_value_encoding = Vec::new();
        byte_string(&mut dummy_value_encoding, &vec![0u8; 300]);
        let mut dummy_pad_encoding = Vec::new();
        byte_string(&mut dummy_pad_encoding, &[]);
        byte_string(&mut dummy_pad_encoding, &[]);
        let target = (dummy_value_encoding.len() + dummy_pad_encoding.len()) as u64;

        // The real value turns out to need only 10 bytes (a 1-byte head) —
        // crossing down from a 3-byte to a 1-byte head class — so the pads
        // must grow to absorb the difference.
        let real_value_len = 10u64;
        let mut real_value_encoding = Vec::new();
        byte_string(
            &mut real_value_encoding,
            &vec![0u8; real_value_len as usize],
        );

        let pad_target = target - real_value_encoding.len() as u64;
        let (pad_len, pad2_len) = pad_lens_for_target(pad_target).unwrap();

        let mut real_pad_encoding = Vec::new();
        byte_string(&mut real_pad_encoding, &vec![0u8; pad_len as usize]);
        byte_string(&mut real_pad_encoding, &vec![0u8; pad2_len as usize]);

        assert_eq!(
            (real_value_encoding.len() + real_pad_encoding.len()) as u64,
            target
        );
    }
}
