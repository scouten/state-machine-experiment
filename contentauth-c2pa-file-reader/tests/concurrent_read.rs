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

//! `read_manifest_concurrent` against the same real, c2pa-rs-signed JPEG
//! `read_jpeg_file.rs` uses: it must reach exactly the verdict the
//! sequential host does, actually overlap reads when it has workers to
//! overlap them with, never overlap more than the session asked for, and
//! never hang or mis-hash when a read fails or an asset has been altered.

#![allow(clippy::unwrap_used)]

use std::{
    io::Cursor,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Duration,
};

use contentauth_c2pa_file_reader::{
    read_manifest, read_manifest_concurrent, ChunkSize, Error, RangeSource, ReadReport,
    ReadSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_reader::{validation::status_code, ByteRange, ValidationState};

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

const FIXTURE_ISSUER: &[u8] =
    include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/signer-issuer.der");

/// The most chunk requests the session keeps outstanding while hashing.
const SESSION_WINDOW: usize = 8;

/// Small chunks, so even this fixture's ~86 KB of hashed bytes is dozens of
/// requests and the session's window is what limits concurrency.
fn settings() -> ReadSettings {
    ReadSettings {
        trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
        hash_chunk_size: ChunkSize::MIN,
        ..ReadSettings::default()
    }
}

fn workers(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).unwrap()
}

/// A source that takes a moment to answer each read, and records how many
/// reads were ever in progress at once.
struct Probe<'a> {
    bytes: &'a [u8],
    delay: Duration,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    reads: AtomicUsize,
}

impl<'a> Probe<'a> {
    fn new(bytes: &'a [u8], delay: Duration) -> Self {
        Self {
            bytes,
            delay,
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
        }
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl RangeSource for Probe<'_> {
    fn length(&self) -> std::io::Result<u64> {
        self.bytes.length()
    }

    fn read_range(&self, range: ByteRange) -> std::io::Result<Vec<u8>> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.reads.fetch_add(1, Ordering::SeqCst);

        thread::sleep(self.delay);
        let result = self.bytes.read_range(range);

        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

/// A source whose reads past `fail_from` fail, as a dropped connection
/// would partway through an asset.
struct FailsPartway<'a> {
    bytes: &'a [u8],
    fail_from: u64,
}

impl RangeSource for FailsPartway<'_> {
    fn length(&self) -> std::io::Result<u64> {
        self.bytes.length()
    }

    fn read_range(&self, range: ByteRange) -> std::io::Result<Vec<u8>> {
        if range.start >= self.fail_from {
            return Err(std::io::Error::other("connection reset"));
        }
        self.bytes.read_range(range)
    }
}

fn statuses(report: &ReadReport) -> String {
    format!("{:?}", report.statuses)
}

#[test]
fn reaches_the_same_verdict_as_the_sequential_host() {
    let sequential = read_manifest(&JpegFormat, Cursor::new(C_JPG), settings()).unwrap();
    let concurrent = read_manifest_concurrent(&JpegFormat, C_JPG, settings(), workers(4)).unwrap();

    assert_eq!(concurrent.validation_state, Some(ValidationState::Trusted));
    assert_eq!(concurrent.validation_state, sequential.validation_state);
    assert_eq!(concurrent.active_manifest, sequential.active_manifest);
    assert_eq!(statuses(&concurrent), statuses(&sequential));
}

#[test]
fn overlaps_reads_when_given_workers_to_overlap_them_with() {
    let probe = Probe::new(C_JPG, Duration::from_millis(2));

    let report = read_manifest_concurrent(&JpegFormat, &probe, settings(), workers(4)).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(
        probe.reads() > SESSION_WINDOW,
        "the fixture should take more requests than one window, took {}",
        probe.reads()
    );
    assert!(
        (2..=4).contains(&probe.peak()),
        "reads should overlap but never exceed the workers: peak was {}",
        probe.peak()
    );
}

#[test]
fn a_single_worker_never_overlaps_reads() {
    let probe = Probe::new(C_JPG, Duration::from_millis(1));

    let report = read_manifest_concurrent(&JpegFormat, &probe, settings(), workers(1)).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert_eq!(probe.peak(), 1);
}

#[test]
fn workers_beyond_what_the_session_asks_for_stay_idle() {
    let probe = Probe::new(C_JPG, Duration::from_millis(2));

    let report = read_manifest_concurrent(&JpegFormat, &probe, settings(), workers(32)).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(
        probe.peak() <= SESSION_WINDOW,
        "the session only ever has {SESSION_WINDOW} chunk requests outstanding, peak was {}",
        probe.peak()
    );
}

#[test]
fn an_altered_asset_is_caught_however_the_chunks_arrive() {
    // Well inside the second hashed range, so it lands in a chunk that is
    // neither first nor last and arrives among others.
    let mut altered = C_JPG.to_vec();
    altered[100_000] ^= 0xff;
    let probe = Probe::new(&altered, Duration::from_millis(1));

    let report = read_manifest_concurrent(&JpegFormat, &probe, settings(), workers(4)).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Invalid));
    assert!(report
        .statuses
        .iter()
        .any(|status| status.code == status_code::ASSERTION_DATAHASH_MISMATCH));
}

#[test]
fn a_read_that_fails_partway_fails_the_read_rather_than_hanging() {
    let source = FailsPartway {
        bytes: C_JPG,
        fail_from: 90_000,
    };

    let result = read_manifest_concurrent(&JpegFormat, &source, settings(), workers(4));

    assert!(matches!(result, Err(Error::Read(_))), "{result:?}");
}

#[cfg(unix)]
#[test]
fn reads_a_file_by_position_without_a_shared_cursor() {
    let file = std::fs::File::open(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contentauth-c2pa-reader/tests/fixtures/C.jpg"
    ))
    .unwrap();

    let report = read_manifest_concurrent(&JpegFormat, &file, settings(), workers(4)).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}
