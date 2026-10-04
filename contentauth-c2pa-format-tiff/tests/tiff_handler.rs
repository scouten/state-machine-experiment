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

//! The TIFF handler against the contract's conformance suite, and on what
//! sets TIFF apart: byte order, BigTIFF, offsets that must not move, and
//! stores laid out by someone else.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod common;

use common::{expected_exclusions, store, tiff, Kind, ALL_KINDS, PIXELS};
use contentauth_c2pa_format::{
    test_util::{conformance, MemoryHost, STREAM},
    ByteRange, Edit, FormatError, FormatHandler, HostError, IoReply, ProtocolError, Session, Step,
};
use contentauth_c2pa_format_tiff::TiffFormat;

#[test]
fn passes_the_conformance_suite_in_every_byte_order_and_flavor() {
    for kind in ALL_KINDS {
        conformance::run_all(&TiffFormat, &tiff(kind, 1, 0), &store(500), &store(70_000));
    }
}

#[test]
fn passes_the_conformance_suite_with_several_ifds_and_odd_lengths() {
    for kind in ALL_KINDS {
        for (ifds, pad) in [(3, 0), (1, 1), (2, 3)] {
            conformance::run_all(
                &TiffFormat,
                &tiff(kind, ifds, pad),
                &store(32),
                &store(1001),
            );
        }
    }
}

#[test]
fn the_store_goes_in_a_new_ifd_and_nothing_already_in_the_file_moves() {
    for kind in ALL_KINDS {
        let source = tiff(kind, 2, 0);
        let manifest = store(100);
        let (plan, output) = conformance::embed(&TiffFormat, &source, &manifest);

        assert_eq!(
            plan.exclusions,
            expected_exclusions(kind, source.len(), 100)
        );
        // The store is last; the value offset and next pointer between the
        // two exclusions stay hashed.
        let [count_field, store_range] = plan.exclusions[..] else {
            panic!("expected two exclusions");
        };
        assert_eq!(output.len() as u64, store_range.start + store_range.len);
        assert_eq!(
            store_range.start - (count_field.start + count_field.len),
            2 * kind.word() as u64 + store_pad(kind)
        );
        assert!(output.ends_with(&manifest));

        // Exactly one run of the source's bytes changed: the last IFD's
        // next pointer, from zero to the new IFD's offset.
        let changed: Vec<usize> = (0..source.len())
            .filter(|&i| source[i] != output[i])
            .collect();
        let new_ifd = kind.ifd_start(source.len());
        let pointer = kind.uint(new_ifd as u64, kind.word());
        let at = source.len() - PIXELS - kind.word();
        assert!(changed.iter().all(|i| (at..at + kind.word()).contains(i)));
        assert_eq!(&output[at..at + kind.word()], &pointer[..]);

        // The new IFD: one entry, tag 0xCD41, type UNDEFINED, our length,
        // an offset to the store that is where the store is, no next IFD.
        let ifd = &output[new_ifd..];
        let expected = kind.ifd(
            &[kind.entry(0xcd41, 7, 100, kind.store_start(new_ifd) as u64)],
            0,
        );
        assert_eq!(&ifd[..expected.len()], &expected[..]);
        assert_eq!(new_ifd % 2, 0, "IFDs sit on word boundaries");
    }
}

#[test]
fn a_little_endian_classic_tiff_gets_exactly_these_bytes() {
    let kind = Kind {
        big: false,
        little: true,
    };
    let source = tiff(kind, 1, 0);
    let (_, output) = conformance::embed(&TiffFormat, &source, &store(16));

    let tail = &output[source.len()..];
    assert_eq!(
        &tail[..18],
        &[
            1,
            0, // one entry
            0x41,
            0xcd, // tag 0xCD41
            7,
            0, // UNDEFINED
            16,
            0,
            0,
            0, // count
            source.len() as u8 + 18,
            0,
            0,
            0, // offset of the store
            0,
            0,
            0,
            0, // no next IFD
        ]
    );
}

#[test]
fn replacing_a_store_cuts_the_old_one_off_and_leaves_the_rest_alone() {
    for kind in ALL_KINDS {
        let source = tiff(kind, 2, 1);
        let (first_plan, once) = conformance::embed(&TiffFormat, &source, &store(300));
        let (second_plan, twice) = conformance::embed(&TiffFormat, &once, &store(40));

        // What is cut off is everything from the old `count` field to the
        // end of the file.
        let cut = first_plan.exclusions[0].start;
        assert_eq!(
            second_plan.replaced,
            Some(ByteRange {
                start: cut,
                len: once.len() as u64 - cut
            })
        );
        // The new store is shorter, so the output is too; nothing else
        // about the old IFD moved.
        assert_eq!(twice.len(), once.len() - 260);
        assert_eq!(&twice[..cut as usize], &once[..cut as usize]);
    }
}

#[test]
fn a_plan_copies_the_source_around_its_one_rewritten_pointer() {
    let kind = ALL_KINDS[0];
    let source = tiff(kind, 1, 0);
    let plan = MemoryHost::of(source.clone())
        .run(TiffFormat.plan_embed(STREAM, 64))
        .unwrap();

    let emits = plan
        .edits
        .iter()
        .filter(|e| matches!(e, Edit::Emit(_)))
        .count();
    // Pointer, IFD lead-in, excluded count field, hashed offset and next
    // — and, in BigTIFF only, padding that aligns the store.
    assert_eq!(emits, 4 + usize::from(store_pad(kind) > 0));
    assert_eq!(plan.replaced, None);
}

/// A TIFF written by another tool: its C2PA entry sits among IFD 0's
/// others, with the store's data in the middle of the file.
fn foreign(kind: Kind, manifest: &[u8]) -> Vec<u8> {
    let ifd = kind.ifd_len(2) as u64;
    let hl = kind.header_len() as u64;
    let data = hl + ifd;
    let mut out = kind.header(hl);
    out.extend(kind.ifd(
        &[
            kind.entry(256, 3, 1, 1),
            kind.entry(0xcd41, 7, manifest.len() as u64, data),
        ],
        0,
    ));
    out.extend(manifest);
    out.extend([0u8; 10]);
    out
}

#[test]
fn reads_a_store_another_tool_laid_out_differently() {
    for kind in ALL_KINDS {
        let manifest = store(64);
        let asset = foreign(kind, &manifest);

        let embedded = conformance::locate(&TiffFormat, &asset).embedded.unwrap();
        assert_eq!(embedded.jumbf, manifest);
        // Not contiguous with its entry, so the range is the data alone.
        assert_eq!(embedded.range.len, 64);
        assert_eq!(
            embedded.range.start,
            (kind.header_len() + kind.ifd_len(2)) as u64
        );
    }
}

#[test]
fn will_not_replace_a_store_it_cannot_cut_out() {
    let asset = foreign(ALL_KINDS[0], &store(64));
    let err = MemoryHost::of(asset)
        .run(TiffFormat.plan_embed(STREAM, 64))
        .unwrap_err();
    assert!(matches!(err, FormatError::Unsupported(_)), "{err:?}");
}

#[test]
fn a_classic_tiff_cannot_be_asked_to_carry_a_4_gib_store() {
    let err = MemoryHost::of(tiff(ALL_KINDS[0], 1, 0))
        .run(TiffFormat.plan_embed(STREAM, u64::from(u32::MAX)))
        .unwrap_err();
    assert!(matches!(err, FormatError::Unsupported(_)), "{err:?}");

    // BigTIFF has the room.
    let plan = MemoryHost::of(tiff(ALL_KINDS[2], 1, 0))
        .run(TiffFormat.plan_embed(STREAM, u64::from(u32::MAX)))
        .unwrap();
    assert_eq!(plan.manifest_len, u64::from(u32::MAX));
}

#[test]
fn an_empty_store_is_refused() {
    let err = MemoryHost::of(tiff(ALL_KINDS[0], 1, 0))
        .run(TiffFormat.plan_embed(STREAM, 0))
        .unwrap_err();
    assert!(matches!(err, FormatError::Unsupported(_)), "{err:?}");
}

#[test]
fn commit_has_nothing_to_patch_but_checks_the_length() {
    let source = tiff(ALL_KINDS[0], 1, 0);
    let plan = MemoryHost::of(source)
        .run(TiffFormat.plan_embed(STREAM, 100))
        .unwrap();

    assert_eq!(TiffFormat.commit(&plan, &store(100)).unwrap(), []);
    assert!(matches!(
        TiffFormat.commit(&plan, &store(99)),
        Err(FormatError::ManifestMismatch(_))
    ));
}

fn locate_err(asset: Vec<u8>) -> FormatError {
    MemoryHost::of(asset)
        .run(TiffFormat.locate(STREAM))
        .unwrap_err()
}

#[test]
fn refuses_what_is_malformed() {
    let kind = ALL_KINDS[0];
    let good = tiff(kind, 2, 0);

    // Not a TIFF at all, and too short to be one.
    assert!(matches!(
        locate_err(b"\xff\xd8\xff\xe0 not tiff".to_vec()),
        FormatError::Malformed(_)
    ));
    assert!(matches!(
        locate_err(b"II*\0".to_vec()),
        FormatError::Malformed(_)
    ));

    // The first IFD lies past the end of the file.
    let mut bad = good.clone();
    bad[4..8].copy_from_slice(&kind.uint(10_000, 4));
    assert!(matches!(locate_err(bad), FormatError::Malformed(_)));

    // The chain loops: the second IFD points back at the first.
    let mut looped = good.clone();
    let second_next = good.len() - PIXELS - 4;
    looped[second_next..second_next + 4].copy_from_slice(&kind.uint(8, 4));
    assert!(matches!(locate_err(looped), FormatError::Malformed(m) if m.contains("loops")));

    // An IFD that declares more entries than the file could hold.
    let mut huge = good.clone();
    huge[8..10].copy_from_slice(&kind.uint(60_000, 2));
    assert!(matches!(locate_err(huge), FormatError::Malformed(m) if m.contains("past the end")));

    // An IFD that declares none.
    let mut empty = good.clone();
    empty[8..10].copy_from_slice(&kind.uint(0, 2));
    assert!(matches!(locate_err(empty), FormatError::Malformed(_)));
}

#[test]
fn refuses_a_malformed_store_entry() {
    let kind = ALL_KINDS[1];
    let manifest = store(64);

    let entry_at = kind.header_len() + 2 + 12;

    // Wrong type.
    let mut wrong_type = foreign(kind, &manifest);
    wrong_type[entry_at + 2..entry_at + 4].copy_from_slice(&kind.uint(3, 2));
    assert!(matches!(locate_err(wrong_type), FormatError::Malformed(m) if m.contains("type")));

    // Data reaching past the end of the file.
    let mut past = foreign(kind, &manifest);
    past[entry_at + 4..entry_at + 8].copy_from_slice(&kind.uint(1_000_000, 4));
    assert!(matches!(locate_err(past), FormatError::Malformed(m) if m.contains("past")));

    // Too short to be anything: the value would be stored inline.
    let mut tiny = foreign(kind, &manifest);
    tiny[entry_at + 4..entry_at + 8].copy_from_slice(&kind.uint(4, 4));
    assert!(matches!(locate_err(tiny), FormatError::Malformed(_)));

    // Two entries claiming to be the store.
    let ifd = kind.ifd_len(3) as u64;
    let hl = kind.header_len() as u64;
    let mut two = kind.header(hl);
    two.extend(kind.ifd(
        &[
            kind.entry(0xcd41, 7, 64, hl + ifd),
            kind.entry(0xcd41, 7, 64, hl + ifd),
            kind.entry(256, 3, 1, 1),
        ],
        0,
    ));
    two.extend(&manifest);
    assert!(matches!(locate_err(two), FormatError::Malformed(m) if m.contains("more than one")));
}

#[test]
fn a_host_failure_surfaces_rather_than_hanging() {
    let mut op = TiffFormat.locate(STREAM);
    assert_eq!(op.advance().unwrap(), Step::AwaitHost);
    let id = op.outstanding_requests()[0].id;
    op.fulfill(id, IoReply::Failed(HostError::new("disk on fire")))
        .unwrap();

    assert!(matches!(op.advance(), Err(FormatError::HostFailure { .. })));
    // The operation is spent.
    assert!(matches!(
        op.advance(),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));
}

/// Answers one request from `asset`.
fn answer(asset: &[u8], request: &contentauth_c2pa_format::IoRequest) -> IoReply {
    use contentauth_c2pa_format::IoRequest;
    match request {
        IoRequest::Length { .. } => IoReply::Length(asset.len() as u64),
        IoRequest::Read { range, .. } => {
            IoReply::Bytes(asset[range.start as usize..][..range.len as usize].to_vec())
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn an_operation_that_is_advanced_before_its_reply_arrives_just_waits() {
    // A foreign-layout store, so every phase (length, header, IFD count,
    // IFD entries, manifest) is passed through.
    let asset = foreign(ALL_KINDS[0], &store(64));
    let mut op = TiffFormat.locate(STREAM);

    loop {
        // Advancing again with the request still outstanding parks again.
        let first = op.advance().unwrap();
        if first == Step::Complete {
            break;
        }
        assert_eq!(op.advance().unwrap(), Step::AwaitHost);

        for request in op.outstanding_requests().to_vec() {
            op.fulfill(request.id, answer(&asset, &request.kind))
                .unwrap();
        }
    }

    // A finished operation stays finished, and yields its result.
    assert_eq!(op.advance().unwrap(), Step::Complete);
    assert!(op.finish().unwrap().embedded.is_some());
}

#[test]
fn finishing_an_operation_that_failed_reports_it() {
    let mut op = TiffFormat.locate(STREAM);
    op.advance().unwrap();
    let id = op.outstanding_requests()[0].id;
    op.fulfill(id, IoReply::Length(3)).unwrap(); // too short to be a TIFF

    assert!(matches!(op.advance(), Err(FormatError::Malformed(_))));
    assert!(op.finish().is_err());
}

#[test]
fn a_first_ifd_pointer_of_zero_means_no_ifd() {
    let kind = ALL_KINDS[0];
    let mut asset = kind.header(0);
    asset.extend([0u8; 16]);
    assert!(matches!(locate_err(asset), FormatError::Malformed(m) if m.contains("no IFD")));
}

#[test]
fn an_implausibly_long_ifd_chain_is_refused() {
    let kind = ALL_KINDS[0];
    let block = kind.ifd_len(1);
    let count = (1usize << 16) + 2;

    let mut asset = kind.header(kind.header_len() as u64);
    for n in 0..count {
        let next = if n + 1 < count {
            (kind.header_len() + (n + 1) * block) as u64
        } else {
            0
        };
        asset.extend(kind.ifd(&[kind.entry(256, 3, 1, 1)], next));
    }

    assert!(matches!(locate_err(asset), FormatError::Malformed(m) if m.contains("implausibly")));
}

#[test]
fn a_store_that_overlaps_its_own_entry_is_malformed() {
    let kind = ALL_KINDS[0];
    let hl = kind.header_len() as u64;

    // The store's data begins at the entry itself, so it covers the
    // entry's own `count` field.
    let entry_at = hl + kind.header_len() as u64 / 4; // inside the IFD
    let mut asset = kind.header(hl);
    asset.extend(kind.ifd(&[kind.entry(0xcd41, 7, 64, entry_at)], 0));
    asset.extend([0u8; 64]);

    assert!(matches!(
        locate_err(asset),
        FormatError::Malformed(m) if m.contains("overlaps")
    ));
}

/// Padding between a new IFD and its store: BigTIFF's 36-byte IFD leaves the
/// store off an 8-byte boundary, so four bytes push it onto one.
fn store_pad(kind: Kind) -> u64 {
    if kind.big {
        4
    } else {
        0
    }
}

#[test]
fn everything_written_is_aligned_for_its_flavor() {
    // For every source length mod 8, so every amount of leading padding.
    for kind in ALL_KINDS {
        let align = if kind.big { 8 } else { 2 };
        for extra in 0..8 {
            let source = tiff(kind, 1, extra);
            let (plan, output) = conformance::embed(&TiffFormat, &source, &store(100));

            let [count_field, store_range] = plan.exclusions[..] else {
                panic!("expected two exclusions");
            };
            let ifd_start = count_field.start as usize - (if kind.big { 8 } else { 2 }) - 4;
            assert_eq!(ifd_start % align, 0, "{kind:?} +{extra}: IFD");
            assert_eq!(
                store_range.start as usize % align,
                0,
                "{kind:?} +{extra}: store"
            );
            assert_eq!(output.len() as u64, store_range.start + store_range.len);
        }
    }
}

#[test]
fn a_store_laid_out_without_bigtiff_padding_is_still_replaceable() {
    // c2pa-rs writes the store directly after the IFD, unpadded; the
    // handler reads it as trailing and replaces it.
    let kind = ALL_KINDS[2]; // BigTIFF, little-endian
    let manifest = store(64);

    let hl = kind.header_len() as u64;
    let data = hl + kind.ifd_len(1) as u64;
    let mut asset = kind.header(hl);
    asset.extend(kind.ifd(&[kind.entry(0xcd41, 7, 64, data)], 0));
    asset.extend(&manifest);

    let embedded = conformance::locate(&TiffFormat, &asset).embedded.unwrap();
    assert_eq!(embedded.jumbf, manifest);
    assert_eq!(
        embedded.range.start + embedded.range.len,
        asset.len() as u64
    );

    let plan = MemoryHost::of(asset)
        .run(TiffFormat.plan_embed(STREAM, 80))
        .unwrap();
    assert_eq!(plan.replaced, Some(embedded.range));
}
