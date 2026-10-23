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

//! Drives `FileBuilderSession` over an in-memory JPEG, so two revisions of
//! the engine can be compared on identical work.
//!
//! ```sh
//! cargo run --release -p contentauth-c2pa-file-builder \
//!     --example bench_build -- <padding MB> <repetitions>
//! ```
//!
//! It pads the fixture JPEG with that many megabytes of `COM` segments
//! (0 leaves it as is), builds and signs it `<repetitions>` times, and
//! prints one line: output length and hash exclusions (identical output
//! means identical work), the number of requests the host answered, heap
//! allocations and bytes for the last build, and the best time spent
//! inside `advance`/`fulfill` and in total.
//!
//! Wall-clock time depends on CPU frequency, so compare revisions by
//! instruction count instead, which does not:
//!
//! ```sh
//! valgrind --tool=callgrind target/release/examples/bench_build 8 1
//! ```
//!
//! and, if timing matters, alternate the two binaries and compare the
//! per-pair ratios rather than absolute times. Allocation counts are
//! deterministic too.
//!
//! The host here is as plain as possible (no I/O, an ES256 signer built
//! once) so the numbers are the engine's own cost plus the hashing and
//! signing every build needs.

// A counting allocator needs `unsafe`, and an example is not held to the
// library's lint wall.
#![allow(
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};

use contentauth_c2pa_file_builder::*;
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_state_machine::{Session, Step};

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size() as u64, Relaxed);
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(n as u64, Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static A: Counting = Counting;

const CERT: &[u8] = include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");
const JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

fn source(mb: usize) -> Vec<u8> {
    let mut v = JPG[..2].to_vec();
    for _ in 0..(mb * 1024 * 1024 / 65_000) {
        v.extend_from_slice(&[0xff, 0xfe]);
        v.extend_from_slice(&(65_000u16 + 2).to_be_bytes());
        v.extend(std::iter::repeat_n(0x5au8, 65_000));
    }
    v.extend_from_slice(&JPG[2..]);
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mb: usize = args[1].parse().unwrap();
    let reps: usize = args[2].parse().unwrap();
    let src = source(mb);
    let signer =
        c2pa_raw_crypto::signer_from_private_key(KEY, c2pa_raw_crypto::SigningAlg::Es256).unwrap();
    let mut best_session_ns = u128::MAX;
    let mut best_total = u128::MAX;
    for rep in 0..reps {
        let mut settings = BuilderSettings::new(
            "xmp:iid:b",
            "urn:uuid:b",
            GeneratorInfo::new("bench", "0.1"),
            SigningAlg::Es256,
            vec![CERT.to_vec()],
        );
        settings.title = Some("b.jpg".into());
        let (mut source, mut output) = (Cursor::new(src.clone()), Cursor::new(Vec::new()));
        let (a0, b0) = (ALLOCS.load(Relaxed), BYTES.load(Relaxed));
        let t0 = Instant::now();
        let mut sess_ns = 0u128;
        let mut nreq = 0u64;
        let mut session = FileBuilderSession::new(JpegFormat, settings);
        let ss = FileBuilderSession::<JpegFormat>::SOURCE_STREAM;
        let report = loop {
            let t = Instant::now();
            let step = session.advance().unwrap();
            sess_ns += t.elapsed().as_nanos();
            if step == Step::Complete {
                break session.finish().unwrap();
            }
            let reqs = session.outstanding_requests().to_vec();
            for r in reqs {
                nreq += 1;
                let reply = match &r.kind {
                    FileBuilderRequest::Read { stream, range } => {
                        let s: &mut Cursor<Vec<u8>> = if *stream == ss {
                            &mut source
                        } else {
                            &mut output
                        };
                        s.seek(SeekFrom::Start(range.start)).unwrap();
                        let mut b = vec![0u8; range.len as usize];
                        s.read_exact(&mut b).unwrap();
                        FileBuilderReply::Bytes(b)
                    }
                    FileBuilderRequest::Length { stream } => {
                        let s = if *stream == ss {
                            &mut source
                        } else {
                            &mut output
                        };
                        FileBuilderReply::Length(s.seek(SeekFrom::End(0)).unwrap())
                    }
                    FileBuilderRequest::Write { offset, bytes, .. } => {
                        output.seek(SeekFrom::Start(*offset)).unwrap();
                        output.write_all(bytes).unwrap();
                        FileBuilderReply::Written
                    }
                    FileBuilderRequest::Sign { data, .. } => {
                        FileBuilderReply::Signature(signer.sign(data).unwrap())
                    }
                    _ => panic!("unexpected request"),
                };
                let t = Instant::now();
                session.fulfill(r.id, reply).unwrap();
                sess_ns += t.elapsed().as_nanos();
            }
        };
        let total = t0.elapsed().as_nanos();
        best_session_ns = best_session_ns.min(sess_ns);
        best_total = best_total.min(total);
        if rep == reps - 1 {
            println!("mb={mb} out_len={} excl={:?} requests={nreq} allocs={} alloc_bytes={} best_session_us={} best_total_us={}",
                output.get_ref().len(), report.exclusions, ALLOCS.load(Relaxed) - a0, BYTES.load(Relaxed) - b0, best_session_ns / 1000, best_total / 1000);
        }
    }
}
