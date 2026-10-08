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

//! The variants being timed must be doing the same job: the same bytes
//! out, bar the manifest itself. Correctness is not for sale in a
//! benchmark.

#![allow(clippy::unwrap_used)]

use asset_io_comparison::{
    asset_io, make_wav, one_pass, reads_back_trusted, scratch_dir, two_pass,
};

#[test]
fn the_variants_write_the_same_file_and_ours_reads_back_trusted() {
    let dir = scratch_dir(None);
    let source = dir.join("source.wav");
    make_wav(&source, 3 * 1024 * 1024 + 1000).unwrap();

    let one = dir.join("one.wav");
    let two = dir.join("two.wav");
    let theirs = dir.join("asset-io.wav");

    let run = one_pass(&source, &one).unwrap();
    two_pass(&source, &two).unwrap();
    asset_io(&source, &theirs, run.manifest_len).unwrap();

    // What this workspace writes, read back by this workspace's reader.
    assert!(reads_back_trusted(&one), "one pass");
    assert!(reads_back_trusted(&two), "two passes");

    let one_bytes = std::fs::read(&one).unwrap();
    let two_bytes = std::fs::read(&two).unwrap();
    let their_bytes = std::fs::read(&theirs).unwrap();

    // The source is `RIFF`, a size, `WAVE`, then chunks; every variant
    // appends a `C2PA` chunk of `manifest_len` bytes (even, so no pad) and
    // rewrites the size to match.
    let chunk = 8 + run.manifest_len;
    assert_eq!(one_bytes.len(), two_bytes.len());
    assert_eq!(one_bytes.len(), their_bytes.len());
    let at = one_bytes.len() - chunk;
    assert_eq!(&one_bytes[at..at + 4], b"C2PA");
    assert_eq!(&their_bytes[at..at + 4], b"C2PA");

    // Everything but the manifest's data is byte-identical across all
    // three — including asset-io's, written by someone else's code: the
    // header and its size field, every chunk, the `C2PA` chunk's header.
    assert_eq!(one_bytes[..at + 8], two_bytes[..at + 8]);
    assert_eq!(one_bytes[..at + 8], their_bytes[..at + 8]);

    let _ = std::fs::remove_dir_all(&dir);
}
