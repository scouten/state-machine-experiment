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

//! The point of this crate, demonstrated: the asynchrony lives in the
//! host, and the engine never notices.
//!
//! Every test here drives `Reader::from_blob` with a `Blob` whose reads
//! *genuinely suspend* — each returns `Pending` once before resolving, the
//! way a `Blob.slice().arrayBuffer()` promise would — and checks what that
//! buys: the read completes correctly across those suspensions, it
//! suspends once per host request and nowhere else (so a large asset is
//! hashed in cooperative slices), two reads on one thread interleave at
//! every request boundary, the answer is the one the synchronous
//! `contentauth-c2pa-file-reader` host gets for the same asset — same
//! engine, different host — and a host failure crosses the suspension
//! intact.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

mod support;

use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use contentauth_c2pa_file_reader::{read_manifest, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_js_compat::{Blob, C2paError, Error, Platform, Reader, ValidationState};
use contentauth_c2pa_primitives::{ByteRange, HostError};
use support::{block_on, build_and_embed, join_all_round_robin, FixedClock, C_JPG, FIXED_NOW};

/// A future that is `Pending` on its first poll and ready on its second —
/// the smallest thing that behaves like a real `Promise` from the
/// perspective of whatever awaits it.
struct YieldOnce<T> {
    value: Option<T>,
    yielded: bool,
}

impl<T> YieldOnce<T> {
    fn new(value: T) -> Self {
        Self {
            value: Some(value),
            yielded: false,
        }
    }
}

impl<T: Unpin> Future for YieldOnce<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if !self.yielded {
            self.yielded = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(self.value.take().expect("polled after completion"))
    }
}

/// A [`Blob`] over in-memory bytes whose every read suspends once before
/// answering, and which records each read it is asked for.
struct Yielding<'a> {
    name: &'static str,
    bytes: &'a [u8],
    reads: Cell<usize>,
    log: Option<&'a RefCell<Vec<&'static str>>>,
}

impl<'a> Yielding<'a> {
    fn new(name: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            name,
            bytes,
            reads: Cell::new(0),
            log: None,
        }
    }

    fn logging_to(mut self, log: &'a RefCell<Vec<&'static str>>) -> Self {
        self.log = Some(log);
        self
    }
}

impl Blob for Yielding<'_> {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
        self.reads.set(self.reads.get() + 1);
        if let Some(log) = self.log {
            log.borrow_mut().push(self.name);
        }

        let start = range.start as usize;
        let end = start + range.len as usize;
        let answer = self
            .bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| HostError::new("range past the end"));

        YieldOnce::new(answer).await
    }
}

/// A [`Platform`] whose clock answer also suspends once, and which counts
/// how often it was asked.
struct YieldingClock {
    asked: Cell<usize>,
}

impl Platform for YieldingClock {
    async fn current_date_time(&self) -> Result<i64, HostError> {
        self.asked.set(self.asked.get() + 1);
        YieldOnce::new(Ok(FIXED_NOW)).await
    }

    async fn ocsp(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("no network"))
    }
}

/// Polls `future` to completion, counting how many times it reported
/// `Pending` along the way.
fn block_on_counting_suspensions<F: Future>(future: F) -> (F::Output, usize) {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut suspensions = 0;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return (output, suspensions),
            Poll::Pending => suspensions += 1,
        }
    }
}

#[test]
fn a_blob_whose_reads_genuinely_suspend_is_read_correctly_across_every_suspension() {
    let blob = Yielding::new("C.jpg", C_JPG);
    let clock = YieldingClock {
        asked: Cell::new(0),
    };

    let (result, suspensions) =
        block_on_counting_suspensions(Reader::from_blob("image/jpeg", &blob, None, &clock));
    let reader = result.expect("reads cleanly across suspensions");

    assert_eq!(
        reader.manifest_store().validation_state,
        ValidationState::Valid
    );
    let expected = read_manifest(
        &JpegFormat,
        std::io::Cursor::new(C_JPG),
        ReadSettings::default(),
    )
    .expect("the synchronous host reads C.jpg");
    assert!(expected.active_manifest.is_some());
    assert_eq!(reader.active_label(), expected.active_manifest);

    // The future was not ready on its first poll: it suspended exactly
    // once per host request that suspends — every read, plus the clock —
    // and never anywhere else, since between two requests the engine runs
    // synchronously to the next thing it needs.
    let reads = blob.reads.get();
    assert!(
        reads > 1,
        "the engine reads an asset in more than one piece"
    );
    assert_eq!(clock.asked.get(), 1);
    assert_eq!(suspensions, reads + clock.asked.get());
}

#[test]
fn the_async_host_and_the_synchronous_host_agree_on_the_same_engines_answer() {
    // Same asset, same settings, same instant. The only variable is the
    // host: `contentauth-c2pa-file-reader`'s synchronous `Read + Seek`
    // loop, versus this crate's awaiting one.
    let (_plan, asset) = build_and_embed(C_JPG);
    let settings = || ReadSettings {
        trust_anchors: vec![support::TEST_SIGNER_CERT.to_vec()],
        check_ocsp: false,
        ..ReadSettings::default()
    };

    let synchronous = read_manifest(&JpegFormat, std::io::Cursor::new(&asset), settings())
        .expect("the synchronous host reads it");

    let blob = Yielding::new("built", &asset);
    let asynchronous = block_on(contentauth_c2pa_js_compat::read_manifest(
        &JpegFormat,
        &blob,
        &FixedClock,
        settings(),
    ))
    .expect("the asynchronous host reads it");

    assert_eq!(
        asynchronous.manifest_store_found,
        synchronous.manifest_store_found
    );
    assert_eq!(asynchronous.active_manifest, synchronous.active_manifest);
    assert_eq!(asynchronous.validation_state, synchronous.validation_state);
    assert_eq!(asynchronous.statuses, synchronous.statuses);
    assert_eq!(asynchronous.manifests.len(), synchronous.manifests.len());
    for (a, s) in asynchronous.manifests.iter().zip(&synchronous.manifests) {
        assert_eq!(a.label, s.label);
        assert_eq!(a.assertion_labels, s.assertion_labels);
        assert_eq!(a.claim.title, s.claim.title);
    }
}

#[test]
fn two_reads_on_one_thread_interleave_at_every_request_boundary() {
    // What a browser's event loop would see if `fromBlob` were called
    // twice without awaiting the first: neither read monopolizes the
    // thread. Each suspension in one hands control to the other, so their
    // host requests alternate rather than running back to back — the
    // cooperative yielding a `FileReaderSync`-backed stream can never do,
    // because it never yields at all.
    let (_plan, built) = build_and_embed(C_JPG);
    let log = RefCell::new(Vec::new());
    let first = Yielding::new("first", C_JPG).logging_to(&log);
    let second = Yielding::new("second", &built).logging_to(&log);

    let readers = join_all_round_robin(vec![
        Box::pin(Reader::from_blob("image/jpeg", &first, None, &FixedClock)),
        Box::pin(Reader::from_blob("image/jpeg", &second, None, &FixedClock)),
    ]);

    for reader in &readers {
        assert!(reader.is_ok(), "{reader:?}");
    }
    assert_eq!(
        readers[0].as_ref().unwrap().active_label(),
        block_on(Reader::from_blob("image/jpeg", C_JPG, None, &FixedClock))
            .unwrap()
            .active_label()
    );
    assert_eq!(
        readers[1].as_ref().unwrap().active_label().as_deref(),
        Some("urn:uuid:test-manifest")
    );

    let log = log.into_inner();
    let first_reads = log.iter().filter(|name| **name == "first").count();
    let second_reads = log.iter().filter(|name| **name == "second").count();
    assert!(first_reads > 1 && second_reads > 1, "{log:?}");

    // Strict alternation while both are still running: the round-robin
    // scheduler polls them in turn, and each suspends after every read.
    let both_running = log.len().saturating_sub(first_reads.abs_diff(second_reads));
    for pair in log[..both_running].chunks(2) {
        assert_eq!(
            pair,
            ["first", "second"],
            "reads did not interleave: {log:?}"
        );
    }
}

#[test]
fn a_read_the_blob_cannot_answer_mid_hash_is_a_hard_error_carrying_the_hosts_own_message() {
    /// A [`Blob`] that claims the asset's full length but can only
    /// actually serve its first half — the shape of a `Blob` whose backing
    /// file was truncated after `size` was read.
    struct Truncated<'a>(&'a [u8]);

    impl Blob for Truncated<'_> {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }

        async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
            let start = range.start as usize;
            let end = start + range.len as usize;
            let served = &self.0[..self.0.len() / 2];
            let answer = served
                .get(start..end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| HostError::new("that part of the file is gone"));
            YieldOnce::new(answer).await
        }
    }

    // The manifest store sits near the start of `C.jpg`, so it is located
    // fine; only the hard-binding hash over the rest of the asset cannot
    // be completed. The engine was told (by `size`) those bytes exist, so
    // a read it then cannot get is a hard failure — the same
    // `HostFailure` the synchronous host would surface — and the host's
    // own description of what went wrong rides along in it, across the
    // suspension, rather than being flattened into a generic message.
    let err = block_on(Reader::from_blob(
        "image/jpeg",
        &Truncated(C_JPG),
        None,
        &FixedClock,
    ))
    .expect_err("an asset that shrinks underneath the engine is an error");

    assert!(matches!(err, Error::C2pa(C2paError::Read(_))), "{err:?}");
    assert!(
        err.js_message().contains("that part of the file is gone"),
        "{}",
        err.js_message()
    );
}
