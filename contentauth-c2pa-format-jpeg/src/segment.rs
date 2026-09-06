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

//! JPEG marker constants and the byte layout of a C2PA `APP11` segment.
//!
//! # How a manifest store sits in a JPEG
//!
//! Per ISO/IEC 19566-5 (JUMBF) Annex B and the C2PA specification, the
//! manifest store — one JUMBF superbox — is carried in one or more `APP11`
//! (`0xFFEB`) marker segments. Each segment is:
//!
//! ```text
//! FF EB  Le(2)  'J' 'P'  En(2)  Z(4)  [LBox(4) TBox(4)]  payload…
//!        └── counts itself and everything after it
//! ```
//!
//! `CI` is the constant `"JP"`; `En` is a box instance number, the same for
//! every segment of one store; `Z` is a 1-based packet sequence number. The
//! superbox's own 8-byte header (`LBox`, `TBox = "jumb"`) is the first
//! thing in the first segment's payload — it is simply the start of the
//! store's bytes — and is *repeated* at the start of every continuation
//! segment's payload before the next slice of the store. Reassembling the
//! store means taking the first segment's payload whole and every later
//! segment's payload minus that repeated header.
//!
//! The constants that are conventions rather than specification —
//! [`C2PA_EN`] and [`CHUNK_LEN`] — follow c2pa-rs, so that what this crate
//! writes is byte-identical to what c2pa-rs writes for the same store.

use contentauth_c2pa_format::FormatError;

/// Every marker begins with this byte.
pub(crate) const MARKER_PREFIX: u8 = 0xff;

/// Start of image.
pub(crate) const SOI: u8 = 0xd8;

/// End of image.
pub(crate) const EOI: u8 = 0xd9;

/// Start of scan: entropy-coded data follows, and header parsing stops.
pub(crate) const SOS: u8 = 0xda;

/// `APP0` — JFIF.
pub(crate) const APP0: u8 = 0xe0;

/// `APP11` — the marker JUMBF (and so C2PA) rides in.
pub(crate) const APP11: u8 = 0xeb;

/// Temporary marker: standalone, no length field.
const TEM: u8 = 0x01;

/// Restart markers `RST0`..`RST7`: standalone, no length field.
const RST0: u8 = 0xd0;
const RST7: u8 = 0xd7;

/// The `CI` field that marks an `APP11` segment as carrying JUMBF.
pub(crate) const C2PA_CI: [u8; 2] = *b"JP";

/// The box instance number c2pa-rs writes for a C2PA manifest store.
pub(crate) const C2PA_EN: [u8; 2] = [0x02, 0x11];

/// `CI` + `En` + `Z`: what precedes the payload in every segment.
pub(crate) const PREAMBLE_LEN: usize = 8;

/// A JUMBF box header: `LBox` + `TBox`.
pub(crate) const BOX_HEADER_LEN: usize = 8;

/// How many bytes of the store each segment carries — the c2pa-rs value,
/// comfortably under the ~65 KiB a segment's 16-bit length field allows
/// once the preamble and repeated box header are accounted for.
pub(crate) const CHUNK_LEN: u64 = 64_000;

/// The type UUID of a C2PA manifest store superbox: the four-character
/// code `c2pa` followed by the C2PA UUID suffix.
pub(crate) const MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// True for markers that stand alone, with no length field after them.
pub(crate) fn is_standalone(marker: u8) -> bool {
    marker == TEM || (RST0..=RST7).contains(&marker)
}

/// A parsed `CI`/`En`/`Z` preamble.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Preamble {
    pub(crate) en: [u8; 2],
    pub(crate) z: u32,
}

/// Splits an `APP11` segment's contents (everything after `Le`) into its
/// JUMBF preamble and payload, or `None` if the segment does not carry
/// JUMBF at all.
pub(crate) fn parse_preamble(contents: &[u8]) -> Option<(Preamble, &[u8])> {
    let (preamble, payload) = contents.split_at_checked(PREAMBLE_LEN)?;
    if preamble[..2] != C2PA_CI {
        return None;
    }

    Some((
        Preamble {
            en: [preamble[2], preamble[3]],
            z: u32::from_be_bytes([preamble[4], preamble[5], preamble[6], preamble[7]]),
        },
        payload,
    ))
}

/// What the first bytes of a first segment's payload say it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoxHead {
    /// A C2PA manifest store superbox with this `LBox`.
    ManifestStore { lbox: u32 },

    /// A C2PA manifest store that uses JUMBF's 64-bit extended length
    /// field, which this crate does not handle.
    ExtendedLength,

    /// JUMBF, but not a C2PA manifest store — some other application's.
    OtherJumbf,

    /// Not a JUMBF box at all.
    NotJumbf,
}

/// Classifies the start of a payload.
///
/// A C2PA manifest store starts `LBox "jumb" LBox "jumd" <uuid>`, with the
/// description box's UUID naming it a `c2pa` store. That signature — not
/// the `En` value, which is a convention — is what distinguishes it from
/// any other JUMBF an `APP11` segment might carry.
pub(crate) fn classify_box_head(payload: &[u8]) -> BoxHead {
    const JUMB: &[u8; 4] = b"jumb";
    const JUMD: &[u8; 4] = b"jumd";

    if payload.len() < BOX_HEADER_LEN || &payload[4..8] != JUMB {
        return BoxHead::NotJumbf;
    }

    let lbox = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    // The description box follows the superbox header: immediately, or
    // after an 8-byte `XLBox` when `LBox == 1`.
    let (description, extended) = match lbox {
        1 => (16, true),
        _ => (8, false),
    };

    let is_manifest_store = payload
        .get(description + 4..description + 8)
        .is_some_and(|tbox| tbox == JUMD)
        && payload
            .get(description + 8..description + 24)
            .is_some_and(|uuid| uuid == MANIFEST_STORE_UUID);

    match (is_manifest_store, extended) {
        (false, _) => BoxHead::OtherJumbf,
        (true, true) => BoxHead::ExtendedLength,
        (true, false) => BoxHead::ManifestStore { lbox },
    }
}

/// The 8-byte JUMBF superbox header a store of `len` bytes begins with.
pub(crate) fn box_header(len: u32) -> [u8; BOX_HEADER_LEN] {
    let len = len.to_be_bytes();
    [len[0], len[1], len[2], len[3], b'j', b'u', b'm', b'b']
}

/// The marker, length, and preamble of a C2PA `APP11` segment whose
/// payload (everything after `Z`) is `payload_len` bytes.
pub(crate) fn segment_header(payload_len: usize, z: u32) -> Result<Vec<u8>, FormatError> {
    // `Le` counts itself, the preamble, and the payload.
    let le = u16::try_from(2 + PREAMBLE_LEN + payload_len).map_err(|_| {
        FormatError::InvalidPlan(
            "an APP11 segment's payload exceeds what its length field can express",
        )
    })?;

    let mut header = Vec::with_capacity(4 + PREAMBLE_LEN);
    header.extend_from_slice(&[MARKER_PREFIX, APP11]);
    header.extend_from_slice(&le.to_be_bytes());
    header.extend_from_slice(&C2PA_CI);
    header.extend_from_slice(&C2PA_EN);
    header.extend_from_slice(&z.to_be_bytes());
    Ok(header)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The first 32 bytes of a manifest store of `len` bytes.
    pub(crate) fn store_head(len: u32) -> Vec<u8> {
        let mut head = box_header(len).to_vec();
        head.extend_from_slice(&[0, 0, 0, 0x1e]);
        head.extend_from_slice(b"jumd");
        head.extend_from_slice(&MANIFEST_STORE_UUID);
        head
    }

    #[test]
    fn preambles_parse_and_non_jumbf_is_rejected() {
        let mut contents = b"JP".to_vec();
        contents.extend_from_slice(&[0x02, 0x11, 0, 0, 0, 3]);
        contents.extend_from_slice(b"payload");

        let (preamble, payload) = parse_preamble(&contents).unwrap();
        assert_eq!(
            preamble,
            Preamble {
                en: [0x02, 0x11],
                z: 3
            }
        );
        assert_eq!(payload, b"payload");

        assert!(parse_preamble(b"XX\x02\x11\0\0\0\x01").is_none());
        assert!(parse_preamble(b"JP\x02\x11").is_none());
    }

    #[test]
    fn box_heads_are_classified() {
        assert_eq!(
            classify_box_head(&store_head(1234)),
            BoxHead::ManifestStore { lbox: 1234 }
        );

        // Any other JUMBF: right box type, wrong description UUID.
        let mut other = store_head(1234);
        other[16] ^= 0xff;
        assert_eq!(classify_box_head(&other), BoxHead::OtherJumbf);

        // Extended length: LBox == 1, XLBox, then the description box.
        let mut extended = box_header(1).to_vec();
        extended.extend_from_slice(&[0; 8]);
        extended.extend_from_slice(&store_head(0)[8..]);
        assert_eq!(classify_box_head(&extended), BoxHead::ExtendedLength);

        assert_eq!(classify_box_head(b"not a box at all"), BoxHead::NotJumbf);
        assert_eq!(classify_box_head(b"\0\0\0\x08jum"), BoxHead::NotJumbf);
        assert_eq!(
            classify_box_head(&store_head(1234)[..20]),
            BoxHead::OtherJumbf
        );
    }

    #[test]
    fn segment_headers_encode_their_length() {
        let header = segment_header(100, 2).unwrap();
        assert_eq!(header.len(), 12);
        assert_eq!(&header[..2], &[0xff, 0xeb]);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 2 + 8 + 100);
        assert_eq!(&header[4..6], b"JP");
        assert_eq!(&header[6..8], &C2PA_EN);
        assert_eq!(&header[8..12], &[0, 0, 0, 2]);

        // The largest payload a segment can carry, and one more.
        assert!(segment_header(0xffff - 2 - PREAMBLE_LEN, 1).is_ok());
        assert!(matches!(
            segment_header(0xffff - 2 - PREAMBLE_LEN + 1, 1),
            Err(FormatError::InvalidPlan(_))
        ));
    }

    #[test]
    fn standalone_markers_are_recognized() {
        assert!(is_standalone(0x01));
        assert!(is_standalone(0xd0));
        assert!(is_standalone(0xd7));
        assert!(!is_standalone(0xd8));
        assert!(!is_standalone(0xe0));
    }
}
