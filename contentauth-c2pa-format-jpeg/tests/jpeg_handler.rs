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

//! The JPEG handler against the contract's conformance suite, against a
//! JPEG signed by c2pa-rs, and on its own edge cases.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod common;

use common::{app11, segment, store, unsigned_jpeg, AFTER_APP0, C_JPG, C_MANIFEST_STORE};
use contentauth_c2pa_format::{
    test_util::{conformance, MemoryHost, STREAM},
    ByteRange, FormatError, FormatHandler, HostError, IoReply, ProtocolError, Session, Step,
};
use contentauth_c2pa_format_jpeg::JpegFormat;

/// The range of the `APP11` segment in `C.jpg`, as its own hard binding
/// records it.
const C_JPG_MANIFEST_RANGE: ByteRange = ByteRange {
    start: 20,
    len: 45884,
};

#[test]
fn passes_the_conformance_suite() {
    // A store that fits one segment, and one that needs two.
    conformance::run_all(
        &JpegFormat,
        &unsigned_jpeg(true, true),
        &store(500),
        &store(70_000),
    );
}

#[test]
fn passes_the_conformance_suite_without_a_jfif_segment() {
    conformance::run_all(
        &JpegFormat,
        &unsigned_jpeg(false, true),
        &store(32),
        &store(64_000 * 2 + 1),
    );
}

#[test]
fn locates_the_store_c2pa_rs_wrote() {
    let location = conformance::locate(&JpegFormat, C_JPG);

    let embedded = location.embedded.unwrap();
    assert_eq!(embedded.jumbf, C_MANIFEST_STORE);
    assert_eq!(embedded.range, C_JPG_MANIFEST_RANGE);
    assert_eq!(location.remote, None);
}

#[test]
fn re_signing_a_c2pa_rs_file_replaces_its_store() {
    let new_store = store(1000);
    let (plan, output) = conformance::embed(&JpegFormat, C_JPG, &new_store);

    assert_eq!(plan.replaced, Some(C_JPG_MANIFEST_RANGE));
    // The new store goes where the old one was, in one segment.
    assert_eq!(
        plan.exclusions[0],
        ByteRange {
            start: 20,
            len: 4 + 8 + 1000
        }
    );
    assert_eq!(
        output.len(),
        C_JPG.len() - C_JPG_MANIFEST_RANGE.len as usize + plan.exclusions[0].len as usize
    );

    let embedded = conformance::locate(&JpegFormat, &output).embedded.unwrap();
    assert_eq!(embedded.jumbf, new_store);

    // Everything outside the store is untouched.
    assert_eq!(&output[..20], &C_JPG[..20]);
    assert_eq!(
        &output[plan.exclusions[0].start as usize + plan.exclusions[0].len as usize..],
        &C_JPG[(C_JPG_MANIFEST_RANGE.start + C_JPG_MANIFEST_RANGE.len) as usize..]
    );
}

#[test]
fn the_store_goes_after_app0_or_after_soi() {
    let (plan, _) = conformance::embed(&JpegFormat, &unsigned_jpeg(true, true), &store(100));
    assert_eq!(plan.exclusions[0].start, AFTER_APP0);

    let (plan, _) = conformance::embed(&JpegFormat, &unsigned_jpeg(false, true), &store(100));
    assert_eq!(plan.exclusions[0].start, 2);
}

#[test]
fn a_large_store_is_written_the_way_c2pa_rs_writes_it() {
    let big = store(64_000 * 2 + 5);
    let (plan, output) = conformance::embed(&JpegFormat, &unsigned_jpeg(true, false), &big);

    let run = &output[plan.exclusions[0].start as usize..][..plan.exclusions[0].len as usize];

    // Three segments: 64,000 + 64,000 + 5 bytes of store.
    let mut pos = 0;
    let mut z = 1u32;
    let mut reassembled = Vec::new();
    while pos < run.len() {
        assert_eq!(&run[pos..pos + 2], &[0xff, 0xeb], "segment {z} marker");
        let le = u16::from_be_bytes([run[pos + 2], run[pos + 3]]) as usize;
        let contents = &run[pos + 4..pos + 2 + le];
        assert_eq!(&contents[..2], b"JP");
        assert_eq!(&contents[2..4], &[0x02, 0x11], "c2pa-rs's En");
        assert_eq!(&contents[4..8], &z.to_be_bytes());

        let payload = &contents[8..];
        if z == 1 {
            reassembled.extend_from_slice(payload);
        } else {
            assert_eq!(&payload[..8], &big[..8], "repeated superbox header");
            reassembled.extend_from_slice(&payload[8..]);
        }

        pos += 2 + le;
        z += 1;
    }
    assert_eq!(z, 4);
    assert_eq!(reassembled, big);
}

#[test]
fn non_c2pa_app11_segments_are_carried_through() {
    let mut other = store(100);
    other[16] ^= 0xff;

    let mut jpeg = vec![0xff, 0xd8];
    jpeg.extend(segment(0xe0, b"JFIF\0"));
    jpeg.extend(app11([1, 1], 1, &other));
    jpeg.extend(segment(0xda, &[0; 6]));
    jpeg.extend_from_slice(&[0xff, 0xd9]);

    conformance::an_unsigned_asset_locates_nothing(&JpegFormat, &jpeg);

    let (plan, output) = conformance::embed(&JpegFormat, &jpeg, &store(64));
    assert_eq!(plan.replaced, None);
    // Right after the 9-byte APP0 segment.
    assert_eq!(plan.exclusions[0].start, 2 + 9);
    assert!(
        output
            .windows(other.len())
            .any(|window| window == other.as_slice()),
        "the other application's JUMBF survived"
    );
}

#[test]
fn malformed_assets_are_reported_by_both_operations() {
    let mut split = vec![0xff, 0xd8];
    split.extend(app11([2, 0x11], 1, &store(100)[..60]));
    split.extend(segment(0xfe, b"in between"));
    let mut second = store(100)[..8].to_vec();
    second.extend_from_slice(&store(100)[60..]);
    split.extend(app11([2, 0x11], 2, &second));
    split.extend_from_slice(&[0xff, 0xd9]);

    assert!(matches!(
        MemoryHost::of(split.clone()).run(JpegFormat.locate(STREAM)),
        Err(FormatError::Malformed(_))
    ));
    assert!(matches!(
        MemoryHost::of(split).run(JpegFormat.plan_embed(STREAM, 100)),
        Err(FormatError::Malformed(_))
    ));

    assert!(matches!(
        MemoryHost::of(b"\x89PNG\r\n\x1a\n".to_vec()).run(JpegFormat.locate(STREAM)),
        Err(FormatError::Malformed(_))
    ));
}

#[test]
fn commit_refuses_a_store_that_does_not_fit_the_plan() {
    let (plan, _) = conformance::embed(&JpegFormat, &unsigned_jpeg(true, true), &store(100));

    assert_eq!(JpegFormat.commit(&plan, &store(100)).unwrap(), []);
    assert!(matches!(
        JpegFormat.commit(&plan, &store(101)),
        Err(FormatError::ManifestMismatch(_))
    ));

    let mut not_a_jumb = store(100);
    not_a_jumb[4..8].copy_from_slice(b"xxxx");
    assert!(matches!(
        JpegFormat.commit(&plan, &not_a_jumb),
        Err(FormatError::ManifestMismatch(_))
    ));
}

#[test]
fn a_failed_operation_stays_failed() {
    let mut op = JpegFormat.locate(STREAM);

    assert_eq!(op.advance().unwrap(), Step::AwaitHost);
    let id = op.outstanding_requests()[0].id;
    op.fulfill(id, IoReply::Failed(HostError::new("unreadable")))
        .unwrap();

    assert!(matches!(op.advance(), Err(FormatError::HostFailure { .. })));
    assert!(matches!(
        op.advance(),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));
    assert!(matches!(
        op.fulfill(id, IoReply::Length(0)),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));
    assert!(matches!(
        op.finish(),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));
}

#[test]
fn a_completed_operation_stays_complete() {
    let mut op = JpegFormat.locate(STREAM);
    let host = MemoryHost::of(unsigned_jpeg(true, true));

    // Drive it by hand so `finish` can be observed after `Complete`.
    loop {
        if op.advance().unwrap() == Step::Complete {
            break;
        }
        for request in op.outstanding_requests().to_vec() {
            let reply = match request.kind {
                contentauth_c2pa_format::IoRequest::Length { .. } => {
                    IoReply::Length(unsigned_jpeg(true, true).len() as u64)
                }
                contentauth_c2pa_format::IoRequest::Read { range, .. } => IoReply::Bytes(
                    unsigned_jpeg(true, true)[range.start as usize..][..range.len as usize]
                        .to_vec(),
                ),
                other => panic!("unexpected request: {other:?}"),
            };
            op.fulfill(request.id, reply).unwrap();
        }
    }
    drop(host);

    assert_eq!(op.advance().unwrap(), Step::Complete);
    assert!(op.outstanding_requests().is_empty());
    assert!(op.finish().unwrap().is_none());

    // And finishing early is refused.
    let op = JpegFormat.locate(STREAM);
    assert!(matches!(
        op.finish(),
        Err(FormatError::Protocol(ProtocolError::SessionNotComplete))
    ));
}
