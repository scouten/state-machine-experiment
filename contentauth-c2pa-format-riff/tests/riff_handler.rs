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

//! The RIFF handler against the contract's conformance suite, and on its
//! own edge cases.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod common;

use common::{avi, riff, store, wav};
use contentauth_c2pa_format::{
    test_util::{conformance, MemoryHost, STREAM},
    ByteRange, FormatError, FormatHandler,
};
use contentauth_c2pa_format_riff::{RiffFormat, DESCRIPTOR};

#[test]
fn passes_the_conformance_suite() {
    // An even store and an odd one, in each direction.
    conformance::run_all(&RiffFormat, &wav(1000), &store(500), &store(1001));
    conformance::run_all(&RiffFormat, &wav(1001), &store(1001), &store(500));
}

#[test]
fn passes_the_conformance_suite_for_an_avi() {
    conformance::run_all(&RiffFormat, &avi(), &store(64), &store(70_001));
}

#[test]
fn passes_the_conformance_suite_for_a_file_with_nothing_but_a_header() {
    conformance::run_all(&RiffFormat, &riff(b"WAVE", &[]), &store(32), &store(33));
}

#[test]
fn the_store_goes_last_and_everything_else_is_untouched() {
    let source = avi();
    let manifest = store(301);
    let (plan, output) = conformance::embed(&RiffFormat, &source, &manifest);

    // The chunk is the last 8 + 301 + 1 bytes of the RIFF chunk.
    let chunk = output.len() - 310;
    assert_eq!(&output[chunk..chunk + 4], b"C2PA");
    assert_eq!(&output[chunk + 8..chunk + 8 + 301], &manifest[..]);
    assert_eq!(output[output.len() - 1], 0, "pad byte");

    // Every other byte of the source is carried over, in order.
    assert_eq!(&output[12..chunk], &source[12..]);
    assert_eq!(&output[8..12], b"AVI ");
    assert_eq!(
        u32::from_le_bytes(output[4..8].try_into().unwrap()) as usize,
        output.len() - 8
    );

    // The hard binding excludes the chunk's header and data, and the pad
    // byte is hashed.
    assert_eq!(
        plan.exclusions,
        vec![ByteRange {
            start: chunk as u64,
            len: 309
        }]
    );
}

#[test]
fn bytes_after_the_riff_chunk_survive_a_re_embed() {
    let mut source = wav(100);
    source.extend_from_slice(b"ID3 trailing tag");

    let (_, signed) = conformance::embed(&RiffFormat, &source, &store(200));
    assert!(signed.ends_with(b"ID3 trailing tag"));

    let (plan, resigned) = conformance::embed(&RiffFormat, &signed, &store(300));
    assert!(resigned.ends_with(b"ID3 trailing tag"));
    assert!(plan.replaced.is_some());

    let located = conformance::locate(&RiffFormat, &resigned)
        .embedded
        .unwrap();
    assert_eq!(located.jumbf, store(300));
}

#[test]
fn a_store_in_the_middle_of_the_file_is_moved_to_the_end() {
    let source = riff(
        b"WAVE",
        &[
            (b"C2PA", store(64)),
            (b"data", vec![3; 10]),
            (b"LIST", vec![4; 6]),
        ],
    );
    let (plan, output) = conformance::embed(&RiffFormat, &source, &store(100));

    assert_eq!(plan.replaced, Some(ByteRange { start: 12, len: 72 }));
    assert_eq!(
        output,
        conformance::embed(
            &RiffFormat,
            &riff(b"WAVE", &[(b"data", vec![3; 10]), (b"LIST", vec![4; 6])]),
            &store(100)
        )
        .1
    );
}

#[test]
fn two_stores_are_refused() {
    let source = riff(b"WAVE", &[(b"C2PA", store(64)), (b"C2PA", store(64))]);
    let err = MemoryHost::of(source)
        .run(RiffFormat.locate(STREAM))
        .unwrap_err();
    assert!(matches!(err, FormatError::Malformed(_)), "{err}");
}

#[test]
fn files_that_are_not_riff_are_refused() {
    for bytes in [
        &b""[..],
        b"RIFF",
        b"\xff\xd8\xff\xe0\0\x10JFIF\0\x01\x02\0\0\x01\0\x01\0\0",
    ] {
        let err = MemoryHost::of(bytes)
            .run(RiffFormat.plan_embed(STREAM, 100))
            .unwrap_err();
        assert!(matches!(err, FormatError::Malformed(_)), "{err}");
    }
}

#[test]
fn the_descriptor_detects_riff_by_content() {
    assert!(DESCRIPTOR.matches(&wav(10)));
    assert!(DESCRIPTOR.matches(&avi()));
    assert!(!DESCRIPTOR.matches(b"\x89PNG\r\n\x1a\n"));
    assert!(DESCRIPTOR.serves_extension("WAV"));
    assert!(DESCRIPTOR.serves_mime("audio/x-wav; charset=binary"));
}
