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

//! The one scan both of this crate's operations share: read the 12-byte
//! RIFF header, then walk the top-level chunks, remembering where the end
//! of the RIFF chunk is and where the `C2PA` chunk (if any) sits.
//!
//! Chunk headers are 8 bytes and chunks are usually large, so the scan is
//! a handful of reads for a WAV or WebP and a few dozen for an AVI,
//! whatever the file's size: payloads are never read, except the `C2PA`
//! chunk's own when the operation wants it. A file with a great many tiny
//! chunks is not a round trip per chunk either: each read fetches a
//! [`WINDOW`] of bytes and as many chunk headers as lie inside it are
//! parsed from that.

use core::mem::{replace, take};

use contentauth_c2pa_format::{
    take_bytes, take_length, ByteRange, FormatError, IoRequest, ProtocolError, RequestId, StreamId,
};
use contentauth_state_machine::SessionCore;

/// The RIFF header: `RIFF`, the size of everything after it, the form type.
pub(crate) const HEADER_LEN: u64 = 12;

/// A chunk's header: its FourCC and its data size.
pub(crate) const CHUNK_HEADER_LEN: u64 = 8;

/// The FourCC of the chunk carrying the manifest store.
pub(crate) const C2PA_CHUNK_ID: [u8; 4] = *b"C2PA";

/// Bytes fetched per read while walking chunk headers.
const WINDOW: u64 = 4096;

/// The largest manifest store `locate` will read into memory: far beyond
/// any real one, and a bound on what a malformed file can make a host
/// allocate by declaring a huge `C2PA` chunk.
pub(crate) const MAX_MANIFEST_LEN: u64 = 256 * 1024 * 1024;

/// The `C2PA` chunk found in a file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredChunk {
    /// The whole chunk: header, data, and the pad byte that follows odd
    /// data (when the file has it).
    pub(crate) range: ByteRange,

    /// The size the chunk's header declares for its data.
    pub(crate) data_len: u64,

    /// The manifest store, if the scan was asked to read it.
    pub(crate) data: Vec<u8>,
}

/// What a completed scan found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    /// The asset's total length.
    pub(crate) source_len: u64,

    /// The end of the RIFF chunk: the offset its size field points at.
    /// Anything between here and `source_len` is not part of it.
    pub(crate) riff_end: u64,

    /// The RIFF form type (`WAVE`, `AVI `, `WEBP`, …).
    pub(crate) form: [u8; 4],

    /// The `C2PA` chunk, if the file has one.
    pub(crate) manifest: Option<StoredChunk>,
}

/// The bytes a hard binding written for a `C2PA` chunk excludes: its
/// 8-byte header and its data, but not the pad byte after odd data.
///
/// That is what c2pa-rs records, and it validates a file only against the
/// range it would itself have written — a data-only exclusion, with the
/// header hashed, reads as `Invalid` — so it is what this crate reports.
/// (`c2pa-rs-compat-conformance` holds it to that.)
pub(crate) fn exclusion_of(chunk: &StoredChunk) -> ByteRange {
    ByteRange {
        start: chunk.range.start,
        len: CHUNK_HEADER_LEN + chunk.data_len,
    }
}

enum Phase {
    Start,
    Length(RequestId),
    Header(RequestId),
    Window {
        id: RequestId,
        range: ByteRange,
    },
    Manifest {
        id: RequestId,
        data: ByteRange,
        chunk: ByteRange,
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
    riff_end: u64,
    form: [u8; 4],

    /// Offset of the next chunk header.
    pos: u64,

    /// The most recent read of chunk headers, and where it started.
    window: Vec<u8>,
    window_start: u64,

    manifest: Option<StoredChunk>,
}

impl Scanner {
    pub(crate) fn new(stream: StreamId, read_manifest: bool) -> Self {
        Self {
            stream,
            read_manifest,
            phase: Phase::Start,
            source_len: 0,
            riff_end: 0,
            form: [0; 4],
            pos: HEADER_LEN,
            window: Vec::new(),
            window_start: 0,
            manifest: None,
        }
    }

    /// Makes as much progress as the host's replies allow. Returns the
    /// [`Layout`] once the last chunk has been seen; `Ok(None)` means a
    /// request is outstanding.
    pub(crate) fn advance(
        &mut self,
        core: &mut SessionCore<IoRequest>,
    ) -> Result<Option<Layout>, FormatError> {
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
                    if source_len < HEADER_LEN {
                        return Err(malformed("too short to be a RIFF file"));
                    }
                    self.source_len = source_len;
                    let id = self.read(
                        core,
                        ByteRange {
                            start: 0,
                            len: HEADER_LEN,
                        },
                    );
                    self.phase = Phase::Header(id);
                    Ok(None)
                }
            },

            Phase::Header(id) => {
                let range = ByteRange {
                    start: 0,
                    len: HEADER_LEN,
                };
                match take_bytes(core, id, range)? {
                    None => {
                        self.phase = Phase::Header(id);
                        Ok(None)
                    }
                    Some(bytes) => {
                        self.handle_header(&bytes)?;
                        self.walk(core)
                    }
                }
            }

            Phase::Window { id, range } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::Window { id, range };
                    Ok(None)
                }
                Some(bytes) => {
                    self.window = bytes;
                    self.window_start = range.start;
                    self.walk(core)
                }
            },

            Phase::Manifest { id, data, chunk } => match take_bytes(core, id, data)? {
                None => {
                    self.phase = Phase::Manifest { id, data, chunk };
                    Ok(None)
                }
                Some(bytes) => {
                    self.manifest = Some(StoredChunk {
                        range: chunk,
                        data_len: data.len,
                        data: bytes,
                    });
                    self.pos = chunk.start + chunk.len;
                    self.walk(core)
                }
            },

            Phase::Poisoned => Err(ProtocolError::SessionFailed.into()),
        }
    }

    fn read(&self, core: &mut SessionCore<IoRequest>, range: ByteRange) -> RequestId {
        core.issue(IoRequest::Read {
            stream: self.stream,
            range,
        })
    }

    fn handle_header(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        let (signature, rest) = bytes.split_at(4);
        if signature != b"RIFF" {
            return Err(malformed("does not begin with a RIFF header"));
        }
        let (size, form) = rest.split_at(4);

        let size = u64::from(u32::from_le_bytes(
            size.try_into()
                .map_err(|_| malformed("truncated RIFF header"))?,
        ));
        self.form = form
            .try_into()
            .map_err(|_| malformed("truncated RIFF header"))?;

        let riff_end = size + CHUNK_HEADER_LEN;
        if riff_end < HEADER_LEN {
            return Err(malformed(
                "the RIFF size field is too small to hold a form type",
            ));
        }
        if riff_end > self.source_len {
            return Err(malformed(&format!(
                "the RIFF header declares {riff_end} bytes but the file has {}",
                self.source_len
            )));
        }
        self.riff_end = riff_end;
        Ok(())
    }

    /// Parses chunk headers from the window for as long as it holds them,
    /// asking for more when it runs out.
    fn walk(&mut self, core: &mut SessionCore<IoRequest>) -> Result<Option<Layout>, FormatError> {
        loop {
            // Fewer than 8 bytes left inside the RIFF chunk cannot hold a
            // chunk; whatever they are, they are copied through untouched.
            if self.pos.saturating_add(CHUNK_HEADER_LEN) > self.riff_end {
                return Ok(Some(Layout {
                    source_len: self.source_len,
                    riff_end: self.riff_end,
                    form: self.form,
                    manifest: take(&mut self.manifest),
                }));
            }

            let Some(head) = self.header_at(self.pos) else {
                let range = ByteRange {
                    start: self.pos,
                    len: WINDOW.min(self.riff_end - self.pos),
                };
                let id = self.read(core, range);
                self.phase = Phase::Window { id, range };
                return Ok(None);
            };
            let (id, size) = head;

            // Some encoders (VLC's AVI muxer, for one) leave four null
            // bytes between top-level chunks for DWORD alignment. They are
            // not a chunk; skip them.
            if id == [0; 4] {
                self.pos += 4;
                continue;
            }

            let data_start = self.pos + CHUNK_HEADER_LEN;
            let data_end = data_start + size;
            if data_end > self.riff_end {
                return Err(malformed(&format!(
                    "the chunk '{}' at offset {} runs past the end of the RIFF chunk",
                    String::from_utf8_lossy(&id),
                    self.pos
                )));
            }

            // Odd-sized data is followed by a pad byte not counted in the
            // size. A file that truncates the final chunk's pad is
            // tolerated: the chunk ends where the RIFF chunk does.
            let chunk_end = (data_end + (size & 1)).min(self.riff_end);
            let chunk = ByteRange {
                start: self.pos,
                len: chunk_end - self.pos,
            };

            if id == C2PA_CHUNK_ID {
                if self.manifest.is_some() {
                    return Err(malformed("more than one C2PA chunk"));
                }

                if self.read_manifest && size > 0 {
                    if size > MAX_MANIFEST_LEN {
                        return Err(FormatError::Unsupported(format!(
                            "a C2PA chunk of {size} bytes (the limit is {MAX_MANIFEST_LEN})"
                        )));
                    }
                    let data = ByteRange {
                        start: data_start,
                        len: size,
                    };
                    let id = self.read(core, data);
                    self.phase = Phase::Manifest { id, data, chunk };
                    return Ok(None);
                }

                self.manifest = Some(StoredChunk {
                    range: chunk,
                    data_len: size,
                    data: Vec::new(),
                });
            }

            self.pos = chunk_end;
        }
    }

    /// The chunk id and data size at `pos`, if the window holds them.
    fn header_at(&self, pos: u64) -> Option<([u8; 4], u64)> {
        let start = usize::try_from(pos.checked_sub(self.window_start)?).ok()?;
        let head = self.window.get(start..start.checked_add(8)?)?;
        let id: [u8; 4] = head.get(..4)?.try_into().ok()?;
        let size: [u8; 4] = head.get(4..)?.try_into().ok()?;
        Some((id, u64::from(u32::from_le_bytes(size))))
    }
}

fn malformed(why: &str) -> FormatError {
    FormatError::Malformed(why.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_format::{
        test_util::{MemoryHost, STREAM},
        IoReply, Session,
    };

    use super::*;
    use crate::op::{Goal, ScanOp};

    /// A RIFF file: `form`, then each chunk with its pad byte.
    pub(crate) fn riff(form: &[u8; 4], chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = form.to_vec();
        for (id, data) in chunks {
            body.extend_from_slice(*id);
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(data);
            if data.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut file = b"RIFF".to_vec();
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend(body);
        file
    }

    struct ReadingProbe;
    impl Goal for ReadingProbe {
        type Output = Layout;

        const READ_MANIFEST: bool = true;

        fn finalize(self, layout: Layout) -> Result<Layout, FormatError> {
            Ok(layout)
        }
    }

    struct SkippingProbe;
    impl Goal for SkippingProbe {
        type Output = Layout;

        const READ_MANIFEST: bool = false;

        fn finalize(self, layout: Layout) -> Result<Layout, FormatError> {
            Ok(layout)
        }
    }

    fn scan_reading(bytes: &[u8]) -> Result<Layout, FormatError> {
        MemoryHost::of(bytes).run(ScanOp::new(STREAM, ReadingProbe))
    }

    #[test]
    fn an_unsigned_file_has_no_manifest_and_its_riff_end() {
        let file = riff(b"WAVE", &[(b"fmt ", &[0; 16]), (b"data", &[1; 101])]);
        let layout = scan_reading(&file).unwrap();

        assert_eq!(layout.manifest, None);
        assert_eq!(layout.riff_end, file.len() as u64);
        assert_eq!(&layout.form, b"WAVE");
    }

    #[test]
    fn the_c2pa_chunk_is_found_wherever_it_is() {
        let file = riff(
            b"AVI ",
            &[(b"LIST", &[0; 8]), (b"C2PA", &[7; 33]), (b"idx1", &[0; 16])],
        );
        let layout = scan_reading(&file).unwrap();

        let chunk = layout.manifest.unwrap();
        // LIST: 12 + 16; C2PA starts at 28, 8 + 33 + 1 pad.
        assert_eq!(chunk.range, ByteRange { start: 28, len: 42 });
        assert_eq!(chunk.data, vec![7; 33]);
        // The header and the 33 bytes of data; not the pad byte.
        assert_eq!(exclusion_of(&chunk), ByteRange { start: 28, len: 41 });
    }

    #[test]
    fn the_manifest_is_only_read_when_asked_for() {
        let file = riff(b"WAVE", &[(b"C2PA", &[7; 10])]);
        let layout = MemoryHost::of(file.as_slice())
            .run(ScanOp::new(STREAM, SkippingProbe))
            .unwrap();
        let chunk = layout.manifest.unwrap();
        assert_eq!(chunk.range, ByteRange { start: 12, len: 18 });
        assert!(chunk.data.is_empty());
    }

    #[test]
    fn bytes_after_the_riff_chunk_are_not_scanned() {
        let mut file = riff(b"WAVE", &[(b"data", &[1; 10])]);
        let riff_end = file.len() as u64;
        file.extend_from_slice(b"C2PA\x04\0\0\0abcd");

        let layout = scan_reading(&file).unwrap();
        assert_eq!(layout.riff_end, riff_end);
        assert_eq!(layout.manifest, None);
    }

    #[test]
    fn null_alignment_between_chunks_is_skipped() {
        let mut file = riff(b"AVI ", &[(b"LIST", &[0; 4])]);
        file.extend_from_slice(&[0; 4]);
        file.extend_from_slice(b"C2PA\x02\0\0\0hi");
        let size = (file.len() - 8) as u32;
        file[4..8].copy_from_slice(&size.to_le_bytes());

        let layout = scan_reading(&file).unwrap();
        assert_eq!(layout.manifest.unwrap().data, b"hi");
    }

    #[test]
    fn a_missing_final_pad_byte_is_tolerated() {
        let mut file = riff(b"WAVE", &[(b"data", &[1; 5])]);
        file.pop();
        let size = (file.len() - 8) as u32;
        file[4..8].copy_from_slice(&size.to_le_bytes());

        let layout = scan_reading(&file).unwrap();
        assert_eq!(layout.riff_end, file.len() as u64);
    }

    #[test]
    fn many_tiny_chunks_take_few_reads() {
        let chunks: Vec<(&[u8; 4], &[u8])> = (0..5000).map(|_| (b"JUNK", &[0u8; 2][..])).collect();
        let file = riff(b"WAVE", &chunks);

        let mut op = ScanOp::new(STREAM, SkippingProbe);
        let mut reads = 0;
        loop {
            if op.advance().unwrap() == contentauth_c2pa_format::Step::Complete {
                break;
            }
            for request in op.outstanding_requests().to_vec() {
                let reply = match request.kind {
                    IoRequest::Length { .. } => IoReply::Length(file.len() as u64),
                    IoRequest::Read { range, .. } => {
                        reads += 1;
                        let start = range.start as usize;
                        IoReply::Bytes(file[start..start + range.len as usize].to_vec())
                    }
                    _ => panic!("unexpected request"),
                };
                op.fulfill(request.id, reply).unwrap();
            }
        }
        // 5000 chunks of 10 bytes in 4 KiB windows: ~13 reads, plus the
        // header — nowhere near one per chunk.
        assert!(reads < 30, "{reads} reads");
    }

    #[test]
    fn malformed_files_are_refused() {
        let err = |bytes: &[u8]| scan_reading(bytes).unwrap_err().to_string();

        assert!(err(b"RIFF").contains("too short"));
        assert!(err(b"RIFX\x04\0\0\0WAVE").contains("RIFF header"));

        // Declares more than the file holds.
        let mut file = riff(b"WAVE", &[]);
        file[4] = 200;
        assert!(err(&file).contains("declares"));

        // A chunk that runs past the end.
        let mut file = riff(b"WAVE", &[(b"data", &[0; 8])]);
        file[16] = 200;
        assert!(err(&file).contains("runs past"));

        // Two stores.
        let file = riff(b"WAVE", &[(b"C2PA", &[0; 8]), (b"C2PA", &[0; 8])]);
        assert!(err(&file).contains("more than one"));
    }
}
