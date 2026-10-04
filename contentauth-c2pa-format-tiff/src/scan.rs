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

//! The one scan both of this crate's operations share: read the header,
//! then follow the chain of main IFDs, looking for the entry tagged
//! [`C2PA_TAG`].
//!
//! Where JPEG's scan is a sequential walk that reads every marker in
//! turn, this one is *pointer-chasing*: each IFD lives wherever the
//! previous one's next-IFD pointer says, so the scan reads at offsets the
//! file dictates, in whatever order it dictates — and, since an offset
//! comes straight from the file, checks each against the asset's length
//! before asking the host for it. Only IFD headers and entries are read,
//! never image data, and the manifest store itself only for an operation
//! that wants its bytes.

use core::mem::{replace, take};
use std::collections::HashSet;

use contentauth_c2pa_format::{
    take_bytes, take_length, ByteRange, FormatError, IoRequest, ProtocolError, RequestId, StreamId,
};
use contentauth_state_machine::SessionCore;

use crate::format::{
    malformed, parse_entry, parse_header, Endian, Flavor, Header, C2PA_TAG, MAX_HEADER_LEN,
    TYPE_BYTE, TYPE_UNDEFINED,
};

/// An IFD with more entries than this is refused rather than read: the
/// count comes from the file, and the read it implies must stay modest.
const MAX_ENTRIES: u64 = 1 << 20;

/// A chain of more IFDs than this is refused. (Real multi-page files
/// have thousands; none has this many.)
const MAX_IFDS: usize = 1 << 16;

/// One IFD of the main chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ifd {
    pub(crate) offset: u64,
    pub(crate) entries: u64,

    /// Where the next IFD is; 0 ends the chain.
    pub(crate) next: u64,
}

impl Ifd {
    /// Where the pointer to the next IFD sits in the asset.
    pub(crate) fn next_field(&self, flavor: Flavor) -> u64 {
        self.offset + flavor.count_len() + self.entries * flavor.entry_len()
    }
}

/// The entry carrying the manifest store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct C2paEntry {
    /// Index into [`Layout::ifds`] of the IFD holding the entry.
    pub(crate) ifd: usize,

    /// Where the entry starts in the asset.
    pub(crate) entry_offset: u64,

    /// Where the store's bytes are.
    pub(crate) data: ByteRange,
}

/// What a completed scan found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    pub(crate) header: Header,
    pub(crate) source_len: u64,

    /// The main IFDs, in chain order; never empty.
    pub(crate) ifds: Vec<Ifd>,

    /// The manifest store's entry, if there is one.
    pub(crate) c2pa: Option<C2paEntry>,

    /// The store's bytes, if the scan was asked to read them.
    pub(crate) manifest: Option<Vec<u8>>,
}

impl Layout {
    /// If the store is laid out exactly as this crate lays one out — and
    /// as the specification recommends — returns the range from its
    /// entry's `count` field to the end of the asset.
    ///
    /// That is: the entry is the only one in the last IFD of the chain,
    /// and its data follows that IFD directly and runs to the end of the
    /// file. Such a store can be replaced by cutting the asset off at the
    /// `count` field and writing a new one there.
    ///
    /// A store anywhere else (an entry among a main IFD's others, data
    /// elsewhere in the file) is readable but not replaceable here.
    pub(crate) fn trailing_store(&self) -> Option<ByteRange> {
        let c2pa = self.c2pa.as_ref()?;
        let ifd = self.ifds.get(c2pa.ifd)?;

        let trailing = c2pa.ifd + 1 == self.ifds.len()
            && ifd.entries == 1
            && ifd.next == 0
            && [
                ifd.offset.saturating_add(self.header.flavor.ifd_len(1)),
                self.header.flavor.store_offset(ifd.offset),
            ]
            .contains(&c2pa.data.start)
            && c2pa.data.start.saturating_add(c2pa.data.len) == self.source_len;
        if !trailing {
            return None;
        }

        // The entry's `tag` and `type` fields come first.
        let start = c2pa.entry_offset + 4;
        Some(ByteRange {
            start,
            len: self.source_len - start,
        })
    }
}

enum Phase {
    Start,
    Length(RequestId),
    Header {
        id: RequestId,
        range: ByteRange,
    },
    IfdCount {
        id: RequestId,
        offset: u64,
    },
    IfdEntries {
        id: RequestId,
        offset: u64,
        entries: u64,
        range: ByteRange,
    },
    Manifest {
        id: RequestId,
        range: ByteRange,
    },

    /// Installed while a phase is being processed, and left behind by an
    /// error exit — or by the scan finishing, since [`Scanner::advance`]
    /// hands the [`Layout`] over exactly once.
    Poisoned,
}

/// The scan itself. Owned by an operation, which owns the
/// [`SessionCore`] and passes it in.
pub(crate) struct Scanner {
    stream: StreamId,
    read_manifest: bool,
    phase: Phase,

    source_len: u64,
    header: Option<Header>,
    ifds: Vec<Ifd>,
    seen: HashSet<u64>,
    found: Option<(usize, u64, ByteRange)>,
}

impl Scanner {
    pub(crate) fn new(stream: StreamId, read_manifest: bool) -> Self {
        Self {
            stream,
            read_manifest,
            phase: Phase::Start,
            source_len: 0,
            header: None,
            ifds: Vec::new(),
            seen: HashSet::new(),
            found: None,
        }
    }

    /// Makes as much progress as the host's replies allow. Returns the
    /// [`Layout`] once the chain has been followed to its end (and the
    /// store read, if asked to); `Ok(None)` means a request is
    /// outstanding.
    pub(crate) fn advance(
        &mut self,
        core: &mut SessionCore<IoRequest>,
    ) -> Result<Option<Layout>, FormatError> {
        // Each phase issues at most one request, so one reply advances
        // the scan by exactly one phase: no loop is needed here.
        match replace(&mut self.phase, Phase::Poisoned) {
            Phase::Start => {
                let id = core.issue(IoRequest::Length {
                    stream: self.stream,
                });
                self.phase = Phase::Length(id);
                Ok(None)
            }

            Phase::Length(id) => match take_length(core, id)? {
                None => {
                    self.phase = Phase::Length(id);
                    Ok(None)
                }
                Some(source_len) => {
                    if source_len < 8 {
                        return Err(malformed("too short to be a TIFF"));
                    }
                    self.source_len = source_len;
                    let range = ByteRange {
                        start: 0,
                        len: source_len.min(MAX_HEADER_LEN),
                    };
                    let id = self.read(core, range);
                    self.phase = Phase::Header { id, range };
                    Ok(None)
                }
            },

            Phase::Header { id, range } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::Header { id, range };
                    Ok(None)
                }
                Some(bytes) => {
                    let header = parse_header(&bytes)?;
                    self.header = Some(header);
                    self.issue_ifd(core, header.flavor, header.first_ifd)?;
                    Ok(None)
                }
            },

            Phase::IfdCount { id, offset } => {
                let flavor = self.flavor()?;
                let range = ByteRange {
                    start: offset,
                    len: flavor.count_len(),
                };
                match take_bytes(core, id, range)? {
                    None => {
                        self.phase = Phase::IfdCount { id, offset };
                        Ok(None)
                    }
                    Some(bytes) => {
                        let entries = self.endian()?.uint(&bytes);
                        if entries == 0 || entries > MAX_ENTRIES {
                            return Err(malformed(format!(
                                "the IFD at offset {offset} declares {entries} entries"
                            )));
                        }

                        let start = offset + flavor.count_len();
                        let len = entries * flavor.entry_len() + flavor.word_len();
                        if start
                            .checked_add(len)
                            .is_none_or(|end| end > self.source_len)
                        {
                            return Err(malformed(format!(
                                "the IFD at offset {offset} runs past the end of the file"
                            )));
                        }

                        let range = ByteRange { start, len };
                        let id = self.read(core, range);
                        self.phase = Phase::IfdEntries {
                            id,
                            offset,
                            entries,
                            range,
                        };
                        Ok(None)
                    }
                }
            }

            Phase::IfdEntries {
                id,
                offset,
                entries,
                range,
            } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::IfdEntries {
                        id,
                        offset,
                        entries,
                        range,
                    };
                    Ok(None)
                }
                Some(bytes) => self.handle_ifd(core, offset, entries, &bytes),
            },

            Phase::Manifest { id, range } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::Manifest { id, range };
                    Ok(None)
                }
                Some(manifest) => Ok(Some(self.layout(Some(manifest))?)),
            },

            Phase::Poisoned => Err(ProtocolError::SessionFailed.into()),
        }
    }

    fn flavor(&self) -> Result<Flavor, FormatError> {
        Ok(self.header.ok_or(ProtocolError::SessionFailed)?.flavor)
    }

    fn endian(&self) -> Result<Endian, FormatError> {
        Ok(self.header.ok_or(ProtocolError::SessionFailed)?.endian)
    }

    fn read(&self, core: &mut SessionCore<IoRequest>, range: ByteRange) -> RequestId {
        core.issue(IoRequest::Read {
            stream: self.stream,
            range,
        })
    }

    /// Starts reading the IFD at `offset`, after checking the pointer
    /// that led there.
    fn issue_ifd(
        &mut self,
        core: &mut SessionCore<IoRequest>,
        flavor: Flavor,
        offset: u64,
    ) -> Result<(), FormatError> {
        if offset == 0 {
            return Err(malformed("the file has no IFD"));
        }
        if !self.seen.insert(offset) {
            return Err(malformed(format!(
                "the IFD chain loops back to offset {offset}"
            )));
        }
        if self.ifds.len() >= MAX_IFDS {
            return Err(malformed("the IFD chain is implausibly long"));
        }
        if offset
            .checked_add(flavor.count_len())
            .is_none_or(|end| end > self.source_len)
        {
            return Err(malformed(format!(
                "an IFD pointer ({offset}) lies past the end of the file"
            )));
        }

        let id = self.read(
            core,
            ByteRange {
                start: offset,
                len: flavor.count_len(),
            },
        );
        self.phase = Phase::IfdCount { id, offset };
        Ok(())
    }

    /// Takes in one IFD's entries, and either follows its pointer to the
    /// next IFD or finishes the chain.
    fn handle_ifd(
        &mut self,
        core: &mut SessionCore<IoRequest>,
        offset: u64,
        entries: u64,
        bytes: &[u8],
    ) -> Result<Option<Layout>, FormatError> {
        let header = self.header.ok_or(ProtocolError::SessionFailed)?;
        let entry_len = header.flavor.entry_len() as usize;
        let index = self.ifds.len();

        for (i, raw) in bytes
            .chunks_exact(entry_len)
            .take(entries as usize)
            .enumerate()
        {
            let entry = parse_entry(header.endian, header.flavor, raw);
            if entry.tag != C2PA_TAG {
                continue;
            }

            if self.found.is_some() {
                return Err(malformed("more than one C2PA manifest store entry"));
            }
            let entry_offset =
                offset + header.flavor.count_len() + i as u64 * header.flavor.entry_len();
            let data = self.check_entry(entry.kind, entry.count, entry.value)?;
            self.found = Some((index, entry_offset, data));
        }

        let next = header.endian.uint(&bytes[entries as usize * entry_len..]);
        self.ifds.push(Ifd {
            offset,
            entries,
            next,
        });

        if next != 0 {
            self.issue_ifd(core, header.flavor, next)?;
            return Ok(None);
        }

        match self.found {
            Some((_, _, data)) if self.read_manifest => {
                let id = self.read(core, data);
                self.phase = Phase::Manifest { id, range: data };
                Ok(None)
            }
            _ => Ok(Some(self.layout(None)?)),
        }
    }

    /// Checks that an entry tagged [`C2PA_TAG`] describes a store that
    /// could exist, and returns where its bytes are.
    fn check_entry(&self, kind: u16, count: u64, value: u64) -> Result<ByteRange, FormatError> {
        let flavor = self.flavor()?;

        if kind != TYPE_UNDEFINED && kind != TYPE_BYTE {
            return Err(malformed(format!(
                "the C2PA manifest store entry has type {kind}, not UNDEFINED"
            )));
        }
        if count <= flavor.word_len() {
            return Err(malformed(
                "the C2PA manifest store entry is too short to be a store",
            ));
        }
        if value
            .checked_add(count)
            .is_none_or(|end| end > self.source_len)
        {
            return Err(malformed(
                "the C2PA manifest store reaches past the end of the file",
            ));
        }

        Ok(ByteRange {
            start: value,
            len: count,
        })
    }

    fn layout(&mut self, manifest: Option<Vec<u8>>) -> Result<Layout, FormatError> {
        let header = self.header.ok_or(ProtocolError::SessionFailed)?;
        Ok(Layout {
            header,
            source_len: self.source_len,
            ifds: take(&mut self.ifds),
            c2pa: self.found.map(|(ifd, entry_offset, data)| C2paEntry {
                ifd,
                entry_offset,
                data,
            }),
            manifest,
        })
    }
}
