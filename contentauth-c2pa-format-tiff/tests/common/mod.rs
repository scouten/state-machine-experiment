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

//! Test fixtures: a small TIFF writer, so tests can build the same image
//! in each byte order and flavor, and a stand-in manifest store.

#![allow(dead_code)]

use contentauth_c2pa_format::ByteRange;

/// A TIFF's two independent dimensions of variety.
#[derive(Clone, Copy, Debug)]
pub struct Kind {
    pub big: bool,
    pub little: bool,
}

pub const ALL_KINDS: [Kind; 4] = [
    Kind {
        big: false,
        little: true,
    },
    Kind {
        big: false,
        little: false,
    },
    Kind {
        big: true,
        little: true,
    },
    Kind {
        big: true,
        little: false,
    },
];

impl Kind {
    pub fn uint(self, value: u64, width: usize) -> Vec<u8> {
        let mut bytes = value.to_be_bytes()[8 - width..].to_vec();
        if self.little {
            bytes.reverse();
        }
        bytes
    }

    pub fn word(self) -> usize {
        if self.big {
            8
        } else {
            4
        }
    }

    pub fn header_len(self) -> usize {
        if self.big {
            16
        } else {
            8
        }
    }

    /// Where the handler puts the new IFD after `source_len` bytes: even
    /// for classic TIFF, 8-byte aligned for BigTIFF.
    pub fn ifd_start(self, source_len: usize) -> usize {
        source_len.next_multiple_of(if self.big { 8 } else { 2 })
    }

    /// Where it puts the store for an IFD at `ifd_start`.
    pub fn store_start(self, ifd_start: usize) -> usize {
        (ifd_start + self.ifd_len(1)).next_multiple_of(if self.big { 8 } else { 2 })
    }

    pub fn ifd_len(self, entries: usize) -> usize {
        let (count, entry) = if self.big { (8, 20) } else { (2, 12) };
        count + entries * entry + self.word()
    }

    /// The header, pointing at `first_ifd`.
    pub fn header(self, first_ifd: u64) -> Vec<u8> {
        let mut out = if self.little { b"II" } else { b"MM" }.to_vec();
        out.extend(self.uint(if self.big { 43 } else { 42 }, 2));
        if self.big {
            out.extend(self.uint(8, 2));
            out.extend(self.uint(0, 2));
            out.extend(self.uint(first_ifd, 8));
        } else {
            out.extend(self.uint(first_ifd, 4));
        }
        out
    }

    /// One IFD entry.
    pub fn entry(self, tag: u16, kind: u16, count: u64, value: u64) -> Vec<u8> {
        let mut out = self.uint(u64::from(tag), 2);
        out.extend(self.uint(u64::from(kind), 2));
        out.extend(self.uint(count, self.word()));
        out.extend(self.uint(value, self.word()));
        out
    }

    /// An IFD of `entries`, followed by a pointer to `next`.
    pub fn ifd(self, entries: &[Vec<u8>], next: u64) -> Vec<u8> {
        let mut out = self.uint(entries.len() as u64, if self.big { 8 } else { 2 });
        for entry in entries {
            out.extend(entry);
        }
        out.extend(self.uint(next, self.word()));
        out
    }
}

/// Bytes of "pixel data" each IFD of [`tiff`] owns.
pub const PIXELS: usize = 6;

/// A TIFF of `ifds` main IFDs, each followed by its own pixel data and
/// described by three entries, one of them (`StripOffsets`) an offset
/// into the file: so anything that shifts the file's contents would be
/// caught by a stale offset. `pad` extra bytes trail the file.
pub fn tiff(kind: Kind, ifds: usize, pad: usize) -> Vec<u8> {
    let block = kind.ifd_len(3) + PIXELS;
    let mut out = kind.header(kind.header_len() as u64);

    for n in 0..ifds {
        let at = out.len() as u64;
        let pixels = at + kind.ifd_len(3) as u64;
        let next = if n + 1 < ifds { at + block as u64 } else { 0 };

        out.extend(kind.ifd(
            &[
                kind.entry(256, 3, 1, PIXELS as u64),
                kind.entry(273, 4, 1, pixels),
                kind.entry(279, 4, 1, PIXELS as u64),
            ],
            next,
        ));
        out.extend([0xa0 + n as u8; PIXELS]);
    }

    out.extend(vec![0xee; pad]);
    out
}

/// A stand-in manifest store of `len` bytes: a JUMBF-looking header and
/// recognizable filler. Nothing here parses it.
pub fn store(len: usize) -> Vec<u8> {
    let mut out = (len as u32).to_be_bytes().to_vec();
    out.extend(b"jumb");
    out.extend((0..len.saturating_sub(8)).map(|i| (i % 251) as u8));
    out.truncate(len);
    out
}

/// The two ranges a hard binding excludes for the asset `kind` lays out
/// after `source_len` bytes: the new entry's `count` field, and the store.
pub fn expected_exclusions(kind: Kind, source_len: usize, store_len: usize) -> Vec<ByteRange> {
    let ifd_start = kind.ifd_start(source_len);
    let count_field = ifd_start + if kind.big { 8 } else { 2 } + 4;
    vec![
        ByteRange {
            start: count_field as u64,
            len: kind.word() as u64,
        },
        ByteRange {
            start: kind.store_start(ifd_start) as u64,
            len: store_len as u64,
        },
    ]
}
