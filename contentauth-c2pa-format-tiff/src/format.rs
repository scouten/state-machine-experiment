//! TIFF's byte-level vocabulary: byte order, the classic/BigTIFF split,
//! and decoding the few structures this crate reads.
//!
//! Everything here is a pure function of bytes already in hand.

use contentauth_c2pa_format::FormatError;

/// The IFD tag a C2PA manifest store lives under (`0xCD41`, 52545).
pub(crate) const C2PA_TAG: u16 = 0xcd41;

/// The tag type the specification gives it: `UNDEFINED`.
pub(crate) const TYPE_UNDEFINED: u16 = 7;

/// `BYTE`, which a tolerant reader also accepts for the store.
pub(crate) const TYPE_BYTE: u16 = 1;

/// The longest header, BigTIFF's.
pub(crate) const MAX_HEADER_LEN: u64 = 16;

pub(crate) fn malformed(message: impl Into<String>) -> FormatError {
    FormatError::Malformed(message.into())
}

/// The byte order the file declares for its own structures. (It does not
/// govern the manifest store's bytes.)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Endian {
    Little,
    Big,
}

impl Endian {
    /// Decodes an unsigned integer of `bytes.len()` bytes (at most 8).
    pub(crate) fn uint(self, bytes: &[u8]) -> u64 {
        let fold = |acc: u64, b: &u8| (acc << 8) | u64::from(*b);
        match self {
            Self::Big => bytes.iter().fold(0, fold),
            Self::Little => bytes.iter().rev().fold(0, fold),
        }
    }

    /// Encodes `value` in `width` bytes (at most 8). The caller has
    /// already checked it fits.
    pub(crate) fn encode(self, value: u64, width: usize) -> Vec<u8> {
        let be = value.to_be_bytes();
        let mut bytes = be[be.len() - width..].to_vec();
        if self == Self::Little {
            bytes.reverse();
        }
        bytes
    }
}

/// Classic TIFF (32-bit offsets) or BigTIFF (64-bit): the same structures
/// at different widths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flavor {
    Classic,
    Big,
}

impl Flavor {
    /// Bytes in an IFD's leading entry count.
    pub(crate) fn count_len(self) -> u64 {
        match self {
            Self::Classic => 2,
            Self::Big => 8,
        }
    }

    /// Bytes in one IFD entry.
    pub(crate) fn entry_len(self) -> u64 {
        match self {
            Self::Classic => 12,
            Self::Big => 20,
        }
    }

    /// Bytes in an offset, and in an entry's value field: the width of
    /// the entry's `count` field, too.
    pub(crate) fn word_len(self) -> u64 {
        match self {
            Self::Classic => 4,
            Self::Big => 8,
        }
    }

    /// The largest offset or count this flavor can express.
    pub(crate) fn max_word(self) -> u64 {
        match self {
            Self::Classic => u64::from(u32::MAX),
            Self::Big => u64::MAX,
        }
    }

    /// The alignment this crate gives what it writes: word (even) offsets
    /// for classic TIFF, as TIFF 6.0 requires, and 8 bytes for BigTIFF,
    /// whose design documentation asks that all values begin at an
    /// 8-byte-aligned address.
    pub(crate) fn alignment(self) -> u64 {
        match self {
            Self::Classic => 2,
            Self::Big => 8,
        }
    }

    /// Rounds `offset` up to [`Self::alignment`].
    pub(crate) fn align_up(self, offset: u64) -> u64 {
        offset.next_multiple_of(self.alignment())
    }

    /// Where this crate puts the store for a single-entry IFD at
    /// `ifd_start`: directly after it, but on the alignment — so BigTIFF
    /// leaves four bytes of padding after its 36-byte IFD.
    pub(crate) fn store_offset(self, ifd_start: u64) -> u64 {
        self.align_up(ifd_start + self.ifd_len(1))
    }

    /// The length of an IFD holding `entries` entries, next-IFD pointer
    /// included.
    pub(crate) fn ifd_len(self, entries: u64) -> u64 {
        self.count_len() + entries * self.entry_len() + self.word_len()
    }
}

/// What the file's first bytes say about the rest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub(crate) endian: Endian,
    pub(crate) flavor: Flavor,

    /// Offset of the first IFD.
    pub(crate) first_ifd: u64,
}

/// Decodes a header from the file's leading bytes: the 8 bytes classic
/// TIFF needs, or the 16 BigTIFF does, as far as the file goes.
pub(crate) fn parse_header(bytes: &[u8]) -> Result<Header, FormatError> {
    let endian = match bytes.get(..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err(malformed("does not begin with a TIFF byte-order mark")),
    };

    match bytes.get(2..4).map(|magic| endian.uint(magic)) {
        Some(42) => {
            let first = bytes
                .get(4..8)
                .ok_or_else(|| malformed("too short to hold a TIFF header"))?;
            Ok(Header {
                endian,
                flavor: Flavor::Classic,
                first_ifd: endian.uint(first),
            })
        }

        Some(43) => {
            let rest = bytes
                .get(4..16)
                .ok_or_else(|| malformed("too short to hold a BigTIFF header"))?;
            if endian.uint(&rest[..2]) != 8 || endian.uint(&rest[2..4]) != 0 {
                return Err(malformed("BigTIFF header declares an unusual offset size"));
            }
            Ok(Header {
                endian,
                flavor: Flavor::Big,
                first_ifd: endian.uint(&rest[4..]),
            })
        }

        _ => Err(malformed("does not carry the TIFF magic number")),
    }
}

/// The fields of one IFD entry this crate looks at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) tag: u16,
    pub(crate) kind: u16,
    pub(crate) count: u64,

    /// The value field: an offset to the data, or the data itself if it
    /// fits.
    pub(crate) value: u64,
}

/// Decodes one entry from exactly [`Flavor::entry_len`] bytes.
pub(crate) fn parse_entry(endian: Endian, flavor: Flavor, bytes: &[u8]) -> Entry {
    let word = flavor.word_len() as usize;
    Entry {
        tag: endian.uint(&bytes[..2]) as u16,
        kind: endian.uint(&bytes[2..4]) as u16,
        count: endian.uint(&bytes[4..4 + word]),
        value: endian.uint(&bytes[4 + word..4 + 2 * word]),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn integers_round_trip_in_both_byte_orders() {
        for endian in [Endian::Little, Endian::Big] {
            for (value, width) in [
                (0x1234_u64, 2),
                (0xdead_beef, 4),
                (0x0102_0304_0506_0708, 8),
            ] {
                assert_eq!(endian.uint(&endian.encode(value, width)), value);
            }
        }
        assert_eq!(Endian::Little.encode(0x0102, 2), [2, 1]);
        assert_eq!(Endian::Big.encode(0x0102, 2), [1, 2]);
    }

    #[test]
    fn parses_classic_headers_in_either_byte_order() {
        let little = parse_header(b"II\x2a\0\x08\0\0\0").unwrap();
        assert_eq!(
            little,
            Header {
                endian: Endian::Little,
                flavor: Flavor::Classic,
                first_ifd: 8
            }
        );

        let big = parse_header(b"MM\0\x2a\0\0\x01\0").unwrap();
        assert_eq!(big.endian, Endian::Big);
        assert_eq!(big.first_ifd, 256);
    }

    #[test]
    fn parses_bigtiff_headers() {
        let header = parse_header(b"II\x2b\0\x08\0\0\0\x10\0\0\0\0\0\0\0").unwrap();
        assert_eq!(header.flavor, Flavor::Big);
        assert_eq!(header.first_ifd, 16);

        assert!(parse_header(b"II\x2b\0\x04\0\0\0\x10\0\0\0\0\0\0\0").is_err());
        assert!(parse_header(b"II\x2b\0\x08\0\0\0").is_err());
    }

    #[test]
    fn refuses_what_is_not_tiff() {
        assert!(parse_header(b"").is_err());
        assert!(parse_header(b"JFIF").is_err());
        assert!(parse_header(b"II\x2c\0\0\0\0\0").is_err());
        assert!(parse_header(b"II\x2a\0").is_err());
    }

    #[test]
    fn ifd_lengths_follow_the_flavor() {
        assert_eq!(Flavor::Classic.ifd_len(1), 18);
        assert_eq!(Flavor::Big.ifd_len(1), 36);
    }

    #[test]
    fn what_is_written_is_aligned_per_flavor() {
        assert_eq!(Flavor::Classic.align_up(97), 98);
        assert_eq!(Flavor::Classic.align_up(98), 98);
        assert_eq!(Flavor::Big.align_up(98), 104);
        assert_eq!(Flavor::Big.align_up(104), 104);

        // A classic single-entry IFD ends on an even offset; BigTIFF's 36
        // bytes do not end on an 8-byte one, so the store is pushed out.
        assert_eq!(Flavor::Classic.store_offset(98), 98 + 18);
        assert_eq!(Flavor::Big.store_offset(104), 104 + 40);
    }
}
