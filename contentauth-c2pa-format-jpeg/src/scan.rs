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

//! The one scan both of this crate's operations share: walk the marker
//! segments from `SOI` to `SOS`, remembering where each is and collecting
//! the contents of every JUMBF `APP11` segment on the way.
//!
//! Sequential by design — one outstanding host request at a time, since
//! each segment's length is only known from its header — and cheap: only
//! segment headers and `APP11` contents are ever read, never the
//! entropy-coded image data, so scanning a large JPEG costs a few dozen
//! small reads regardless of its size.

use core::mem::{replace, take};

use contentauth_c2pa_format::{
    take_bytes, take_length, ByteRange, FormatError, IoRequest, ProtocolError, RequestId, StreamId,
};
use contentauth_state_machine::SessionCore;

use crate::segment::{
    classify_box_head, is_standalone, parse_preamble, BoxHead, Preamble, APP0, APP11,
    BOX_HEADER_LEN, EOI, MARKER_PREFIX, PREAMBLE_LEN, SOI, SOS,
};

/// One marker segment (or standalone marker) in the header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Segment {
    pub(crate) marker: u8,

    /// The whole segment: marker, length field, contents.
    pub(crate) range: ByteRange,
}

/// One `APP11` segment carrying JUMBF.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JumbfSegment {
    pub(crate) preamble: Preamble,

    /// The whole segment, as in [`Segment::range`].
    pub(crate) range: ByteRange,

    /// Everything after the preamble.
    pub(crate) payload: Vec<u8>,
}

/// What a completed scan found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Layout {
    /// Every segment before `SOS`, in file order.
    pub(crate) segments: Vec<Segment>,

    /// The JUMBF-carrying `APP11` segments among them, in file order.
    pub(crate) jumbf: Vec<JumbfSegment>,

    /// The asset's total length.
    pub(crate) source_len: u64,
}

/// A C2PA manifest store found in a [`Layout`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestRun {
    /// The span of the segments carrying it, framing included.
    pub(crate) range: ByteRange,

    /// The store's bytes, reassembled.
    pub(crate) jumbf: Vec<u8>,
}

impl Layout {
    /// Finds the manifest store, if there is one, and reassembles it.
    ///
    /// Recognizes a store by its content (see
    /// [`classify_box_head`]), groups its segments by `En`, and insists on
    /// what the C2PA specification requires: one store, its packets
    /// numbered `1..=n` without gaps, adjacent in the file, each
    /// continuation repeating the box header, and the whole adding up to
    /// the length its `LBox` declares. Anything else is
    /// [`FormatError::Malformed`].
    pub(crate) fn manifest_run(&self) -> Result<Option<ManifestRun>, FormatError> {
        let mut first: Option<(&JumbfSegment, u32)> = None;

        for segment in self.jumbf.iter().filter(|s| s.preamble.z == 1) {
            match classify_box_head(&segment.payload) {
                BoxHead::ManifestStore { lbox } => {
                    if first.is_some() {
                        return Err(FormatError::Malformed(
                            "more than one C2PA manifest store".to_string(),
                        ));
                    }
                    first = Some((segment, lbox));
                }
                BoxHead::ExtendedLength => {
                    return Err(FormatError::Unsupported(
                        "the manifest store uses a JUMBF extended (64-bit) length field"
                            .to_string(),
                    ));
                }
                BoxHead::OtherJumbf | BoxHead::NotJumbf => {}
            }
        }

        let Some((first, lbox)) = first else {
            return Ok(None);
        };

        let mut parts: Vec<&JumbfSegment> = self
            .jumbf
            .iter()
            .filter(|s| s.preamble.en == first.preamble.en)
            .collect();
        parts.sort_by_key(|s| s.preamble.z);

        // Validate every packet and total up the store's bytes *before*
        // allocating for them: `LBox` comes straight from the file, and a
        // tiny malformed JPEG must not be able to request gigabytes just
        // by declaring them. The total is bounded by segment contents
        // already in memory, so the allocation below can never exceed
        // what was actually read.
        let header = &first.payload[..BOX_HEADER_LEN];
        let mut slices: Vec<&[u8]> = Vec::with_capacity(parts.len());
        let mut total = 0usize;
        let mut range = first.range;

        for (index, part) in parts.iter().enumerate() {
            let expected_z = index as u32 + 1;
            if part.preamble.z != expected_z {
                return Err(FormatError::Malformed(format!(
                    "manifest store packet {expected_z} is missing or duplicated"
                )));
            }

            let slice = if index == 0 {
                part.payload.as_slice()
            } else {
                let previous_end = range.start.saturating_add(range.len);
                if part.range.start != previous_end {
                    return Err(FormatError::Malformed(format!(
                        "manifest store packet {expected_z} is not adjacent to the one before it"
                    )));
                }
                range.len += part.range.len;

                part.payload.strip_prefix(header).ok_or_else(|| {
                    FormatError::Malformed(format!(
                        "manifest store packet {expected_z} does not repeat the superbox header"
                    ))
                })?
            };

            total += slice.len();
            slices.push(slice);
        }

        if total as u64 != u64::from(lbox) {
            return Err(FormatError::Malformed(format!(
                "manifest store is {total} bytes but its box header declares {lbox}"
            )));
        }

        let mut jumbf = Vec::with_capacity(total);
        for slice in slices {
            jumbf.extend_from_slice(slice);
        }

        Ok(Some(ManifestRun { range, jumbf }))
    }

    /// Where a manifest store goes: where the existing one is, if there is
    /// one; otherwise right after the last `APP0` (JFIF) segment, so a
    /// JFIF file stays a JFIF file; otherwise right after `SOI`. The
    /// c2pa-rs rule.
    pub(crate) fn insertion_point(&self, run: Option<&ManifestRun>) -> u64 {
        if let Some(run) = run {
            return run.range.start;
        }

        self.segments
            .iter()
            .filter(|s| s.marker == APP0)
            .map(|s| s.range.start + s.range.len)
            .next_back()
            .unwrap_or(2)
    }
}

enum Phase {
    Start,
    Length(RequestId),
    Soi(RequestId),
    Marker {
        id: RequestId,
        range: ByteRange,
    },
    Contents {
        id: RequestId,
        range: ByteRange,
        segment: ByteRange,
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
    phase: Phase,

    /// Offset of the next marker to read.
    pos: u64,
    source_len: u64,
    segments: Vec<Segment>,
    jumbf: Vec<JumbfSegment>,
}

impl Scanner {
    pub(crate) fn new(stream: StreamId) -> Self {
        Self {
            stream,
            phase: Phase::Start,
            pos: 0,
            source_len: 0,
            segments: Vec::new(),
            jumbf: Vec::new(),
        }
    }

    /// Makes as much progress as the host's replies allow. Returns the
    /// [`Layout`] once the scan reaches `SOS` or `EOI`; `Ok(None)` means a
    /// request is outstanding.
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
                    if source_len < 2 {
                        return Err(malformed("too short to be a JPEG"));
                    }
                    self.source_len = source_len;
                    let id = self.read(core, ByteRange { start: 0, len: 2 });
                    self.phase = Phase::Soi(id);
                    Ok(None)
                }
            },

            Phase::Soi(id) => match take_bytes(core, id, ByteRange { start: 0, len: 2 })? {
                None => {
                    self.phase = Phase::Soi(id);
                    Ok(None)
                }
                Some(bytes) => {
                    if bytes != [MARKER_PREFIX, SOI] {
                        return Err(malformed("does not begin with an SOI marker"));
                    }
                    self.pos = 2;
                    self.issue_marker(core)?;
                    Ok(None)
                }
            },

            Phase::Marker { id, range } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::Marker { id, range };
                    Ok(None)
                }
                Some(bytes) => self.handle_marker(core, &bytes),
            },

            Phase::Contents { id, range, segment } => match take_bytes(core, id, range)? {
                None => {
                    self.phase = Phase::Contents { id, range, segment };
                    Ok(None)
                }
                Some(contents) => {
                    if let Some((preamble, payload)) = parse_preamble(&contents) {
                        self.jumbf.push(JumbfSegment {
                            preamble,
                            range: segment,
                            payload: payload.to_vec(),
                        });
                    }
                    self.segments.push(Segment {
                        marker: APP11,
                        range: segment,
                    });
                    self.pos = segment.start + segment.len;
                    self.issue_marker(core)?;
                    Ok(None)
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

    /// Asks for the marker at `pos` and, if there is room, its length
    /// field too.
    fn issue_marker(&mut self, core: &mut SessionCore<IoRequest>) -> Result<(), FormatError> {
        let available = self.source_len - self.pos;
        if available < 2 {
            return Err(malformed("ends without an SOS or EOI marker"));
        }

        let range = ByteRange {
            start: self.pos,
            len: available.min(4),
        };
        let id = self.read(core, range);
        self.phase = Phase::Marker { id, range };
        Ok(())
    }

    /// Acts on a marker (and length field) read at `pos`. Returns the
    /// layout if this marker ends the header.
    fn handle_marker(
        &mut self,
        core: &mut SessionCore<IoRequest>,
        bytes: &[u8],
    ) -> Result<Option<Layout>, FormatError> {
        if bytes[0] != MARKER_PREFIX {
            return Err(malformed(&format!(
                "expected a marker at offset {}, found 0x{:02x}",
                self.pos, bytes[0]
            )));
        }

        let marker = bytes[1];

        // Fill bytes: any number of 0xff may precede a marker.
        if marker == MARKER_PREFIX {
            self.pos += 1;
            self.issue_marker(core)?;
            return Ok(None);
        }

        if marker == SOS || marker == EOI {
            return Ok(Some(Layout {
                segments: take(&mut self.segments),
                jumbf: take(&mut self.jumbf),
                source_len: self.source_len,
            }));
        }

        if is_standalone(marker) {
            self.segments.push(Segment {
                marker,
                range: ByteRange {
                    start: self.pos,
                    len: 2,
                },
            });
            self.pos += 2;
            self.issue_marker(core)?;
            return Ok(None);
        }

        if bytes.len() < 4 {
            return Err(malformed(&format!(
                "segment at offset {} is truncated",
                self.pos
            )));
        }

        let le = u64::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if le < 2 {
            return Err(malformed(&format!(
                "segment at offset {} has an impossible length field",
                self.pos
            )));
        }

        let segment = ByteRange {
            start: self.pos,
            len: 2 + le,
        };
        let end = segment.start + segment.len;
        if end > self.source_len {
            return Err(malformed(&format!(
                "segment at offset {} runs past the end of the file",
                self.pos
            )));
        }

        if marker == APP11 && le - 2 >= PREAMBLE_LEN as u64 {
            let range = ByteRange {
                start: self.pos + 4,
                len: le - 2,
            };
            let id = self.read(core, range);
            self.phase = Phase::Contents { id, range, segment };
            return Ok(None);
        }

        self.segments.push(Segment {
            marker,
            range: segment,
        });
        self.pos = end;
        self.issue_marker(core)?;
        Ok(None)
    }
}

fn malformed(detail: &str) -> FormatError {
    FormatError::Malformed(format!("JPEG {detail}"))
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_format::{
        test_util::{MemoryHost, STREAM},
        HostRequest, Session, Step,
    };

    use super::*;
    use crate::segment::{box_header, C2PA_EN, MANIFEST_STORE_UUID};

    /// Wraps a scanner as a session so `MemoryHost` can drive it.
    struct ScanSession {
        core: SessionCore<IoRequest>,
        scanner: Scanner,
        layout: Option<Layout>,
    }

    impl ScanSession {
        fn new() -> Self {
            Self {
                core: SessionCore::default(),
                scanner: Scanner::new(STREAM),
                layout: None,
            }
        }
    }

    impl Session for ScanSession {
        type Error = FormatError;
        type Output = Layout;
        type Request = IoRequest;

        fn advance(&mut self) -> Result<Step, FormatError> {
            if self.core.is_complete() {
                return Ok(Step::Complete);
            }
            match self.scanner.advance(&mut self.core) {
                Ok(None) => Ok(Step::AwaitHost),
                Ok(Some(layout)) => {
                    self.layout = Some(layout);
                    self.core.mark_complete();
                    Ok(Step::Complete)
                }
                Err(err) => {
                    self.core.mark_failed();
                    Err(err)
                }
            }
        }

        fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
            self.core.outstanding_requests()
        }

        fn fulfill(
            &mut self,
            id: RequestId,
            reply: contentauth_c2pa_format::IoReply,
        ) -> Result<(), FormatError> {
            Ok(self.core.fulfill(id, reply)?)
        }

        fn finish(self) -> Result<Layout, FormatError> {
            self.core.finish_check()?;
            self.layout.ok_or(ProtocolError::SessionFailed.into())
        }
    }

    pub(crate) fn scan(asset: &[u8]) -> Result<Layout, FormatError> {
        MemoryHost::of(asset).run(ScanSession::new())
    }

    /// A segment with a length field.
    pub(crate) fn segment(marker: u8, contents: &[u8]) -> Vec<u8> {
        let le = u16::try_from(contents.len() + 2).unwrap();
        let mut bytes = vec![MARKER_PREFIX, marker];
        bytes.extend_from_slice(&le.to_be_bytes());
        bytes.extend_from_slice(contents);
        bytes
    }

    /// A C2PA `APP11` segment.
    pub(crate) fn app11(en: [u8; 2], z: u32, payload: &[u8]) -> Vec<u8> {
        let mut contents = b"JP".to_vec();
        contents.extend_from_slice(&en);
        contents.extend_from_slice(&z.to_be_bytes());
        contents.extend_from_slice(payload);
        segment(APP11, &contents)
    }

    /// A plausible manifest store of `len` bytes: a real-looking header,
    /// then a non-repeating fill.
    pub(crate) fn store(len: usize) -> Vec<u8> {
        assert!(len >= 32);
        let mut store = box_header(len as u32).to_vec();
        store.extend_from_slice(&[0, 0, 0, 0x1e]);
        store.extend_from_slice(b"jumd");
        store.extend_from_slice(&MANIFEST_STORE_UUID);
        store.extend((32..len).map(|i| (i % 251) as u8));
        store
    }

    /// `SOI`, optional `APP0`, `DQT`, `SOS`, some scan data, `EOI`.
    pub(crate) fn jpeg(with_app0: bool, middle: &[u8]) -> Vec<u8> {
        let mut bytes = vec![MARKER_PREFIX, SOI];
        if with_app0 {
            bytes.extend(segment(APP0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
        }
        bytes.extend_from_slice(middle);
        bytes.extend(segment(0xdb, &[0u8; 65]));
        bytes.extend(segment(SOS, &[1, 1, 0, 0, 0x3f, 0]));
        bytes.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]);
        bytes.extend_from_slice(&[MARKER_PREFIX, EOI]);
        bytes
    }

    #[test]
    fn a_plain_jpeg_scans_to_its_segments() {
        let layout = scan(&jpeg(true, &[])).unwrap();

        assert_eq!(
            layout.segments,
            [
                Segment {
                    marker: APP0,
                    range: ByteRange { start: 2, len: 18 }
                },
                Segment {
                    marker: 0xdb,
                    range: ByteRange { start: 20, len: 69 }
                },
            ]
        );
        assert!(layout.jumbf.is_empty());
        assert_eq!(layout.source_len, 89 + 10 + 7 + 2);
        assert_eq!(layout.manifest_run().unwrap(), None);
        assert_eq!(layout.insertion_point(None), 20);
        assert_eq!(scan(&jpeg(false, &[])).unwrap().insertion_point(None), 2);
    }

    #[test]
    fn fill_bytes_and_standalone_markers_are_tolerated() {
        let mut middle = vec![MARKER_PREFIX, MARKER_PREFIX];
        middle.extend(segment(0xfe, b"comment"));
        middle.extend_from_slice(&[MARKER_PREFIX, 0xd3]);

        let layout = scan(&jpeg(true, &middle)).unwrap();
        let markers: Vec<u8> = layout.segments.iter().map(|s| s.marker).collect();
        assert_eq!(markers, [APP0, 0xfe, 0xd3, 0xdb]);
        assert_eq!(layout.segments[1].range.start, 22);
        assert_eq!(layout.segments[2].range, ByteRange { start: 33, len: 2 });
    }

    #[test]
    fn a_manifest_store_in_one_segment_is_found() {
        let store = store(500);
        let layout = scan(&jpeg(true, &app11(C2PA_EN, 1, &store))).unwrap();

        let run = layout.manifest_run().unwrap().unwrap();
        assert_eq!(run.jumbf, store);
        assert_eq!(
            run.range,
            ByteRange {
                start: 20,
                len: 4 + 8 + 500
            }
        );
        assert_eq!(layout.insertion_point(Some(&run)), 20);
    }

    #[test]
    fn a_manifest_store_across_segments_is_reassembled() {
        let store = store(1000);
        let mut middle = app11(C2PA_EN, 1, &store[..400]);
        let mut second = store[..8].to_vec();
        second.extend_from_slice(&store[400..800]);
        middle.extend(app11(C2PA_EN, 2, &second));
        let mut third = store[..8].to_vec();
        third.extend_from_slice(&store[800..]);
        middle.extend(app11(C2PA_EN, 3, &third));

        let layout = scan(&jpeg(true, &middle)).unwrap();
        let run = layout.manifest_run().unwrap().unwrap();
        assert_eq!(run.jumbf, store);
        assert_eq!(run.range.start, 20);
        assert_eq!(run.range.len, middle.len() as u64);
    }

    #[test]
    fn any_box_instance_number_is_accepted() {
        // The store is recognized by its content, not by the c2pa-rs
        // `En` convention.
        let store = store(100);
        let mut second = store[..8].to_vec();
        second.extend_from_slice(&store[50..]);
        let mut middle = app11([9, 9], 1, &store[..50]);
        middle.extend(app11([9, 9], 2, &second));

        let run = scan(&jpeg(true, &middle))
            .unwrap()
            .manifest_run()
            .unwrap()
            .unwrap();
        assert_eq!(run.jumbf, store);
    }

    #[test]
    fn other_jumbf_and_non_jumbf_app11_segments_are_ignored() {
        let mut other = store(100);
        other[16] ^= 0xff;
        let mut middle = app11([1, 1], 1, &other);
        middle.extend(segment(APP11, b"not JUMBF at all"));
        middle.extend(segment(APP11, b"JP"));

        let layout = scan(&jpeg(true, &middle)).unwrap();
        assert_eq!(layout.jumbf.len(), 1);
        assert_eq!(layout.segments.len(), 5);
        assert_eq!(layout.manifest_run().unwrap(), None);
    }

    #[test]
    fn malformed_stores_are_reported() {
        let store = store(200);

        // Two stores.
        let mut middle = app11(C2PA_EN, 1, &store);
        middle.extend(app11([1, 1], 1, &store));
        assert!(matches!(
            scan(&jpeg(true, &middle)).unwrap().manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("more than one")
        ));

        // A missing packet.
        let mut third = store[..8].to_vec();
        third.extend_from_slice(&store[150..]);
        let mut middle = app11(C2PA_EN, 1, &store[..150]);
        middle.extend(app11(C2PA_EN, 3, &third));
        assert!(matches!(
            scan(&jpeg(true, &middle)).unwrap().manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("packet 2 is missing")
        ));

        // Packets separated by another segment.
        let mut second = store[..8].to_vec();
        second.extend_from_slice(&store[150..]);
        let mut middle = app11(C2PA_EN, 1, &store[..150]);
        middle.extend(segment(0xfe, b"in between"));
        middle.extend(app11(C2PA_EN, 2, &second));
        assert!(matches!(
            scan(&jpeg(true, &middle)).unwrap().manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("not adjacent")
        ));

        // A continuation that does not repeat the header.
        let mut middle = app11(C2PA_EN, 1, &store[..150]);
        middle.extend(app11(C2PA_EN, 2, &store[150..]));
        assert!(matches!(
            scan(&jpeg(true, &middle)).unwrap().manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("does not repeat")
        ));

        // A store shorter than its header claims.
        assert!(matches!(
            scan(&jpeg(true, &app11(C2PA_EN, 1, &store[..150])))
                .unwrap()
                .manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("declares 200")
        ));

        // A header claiming the largest length `LBox` can express, backed
        // by a few dozen bytes: rejected without allocating for the claim.
        let mut boastful = store[..64].to_vec();
        boastful[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            scan(&jpeg(true, &app11(C2PA_EN, 1, &boastful)))
                .unwrap()
                .manifest_run(),
            Err(FormatError::Malformed(m)) if m.contains("is 64 bytes but its box header declares 4294967295")
        ));

        // An extended-length box.
        let mut extended = box_header(1).to_vec();
        extended.extend_from_slice(&[0; 8]);
        extended.extend_from_slice(&store[8..]);
        assert!(matches!(
            scan(&jpeg(true, &app11(C2PA_EN, 1, &extended)))
                .unwrap()
                .manifest_run(),
            Err(FormatError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_files_are_reported() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0xff], "too short"),
            (b"\x89PNG\r\n".to_vec(), "SOI"),
            (vec![0xff, 0xd8], "ends without"),
            (vec![0xff, 0xd8, 0x00, 0xe0], "expected a marker"),
            (vec![0xff, 0xd8, 0xff, 0xe0, 0x00], "truncated"),
            (
                vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01],
                "impossible length",
            ),
            (vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0, 0], "runs past"),
        ];

        for (asset, expected) in cases {
            match scan(&asset) {
                Err(FormatError::Malformed(message)) => {
                    assert!(
                        message.contains(expected),
                        "{asset:02x?}: expected {expected:?} in {message:?}"
                    );
                }
                other => panic!("{asset:02x?}: expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_header_that_ends_at_eoi_is_a_complete_scan() {
        let mut asset = vec![MARKER_PREFIX, SOI];
        asset.extend(segment(APP0, b"JFIF\0"));
        asset.extend_from_slice(&[MARKER_PREFIX, EOI]);

        let layout = scan(&asset).unwrap();
        assert_eq!(layout.segments.len(), 1);
    }
}
