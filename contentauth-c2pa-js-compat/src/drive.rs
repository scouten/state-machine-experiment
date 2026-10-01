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

//! [`read_manifest`]: the asynchronous host, and the only place in this
//! crate anything is awaited.
//!
//! Compare [`contentauth_c2pa_file_reader::read_manifest`], the
//! synchronous host for the very same session. The two loops are
//! line-for-line the same shape — `advance`, answer every outstanding
//! request, `fulfill`, repeat — and the session they drive is literally
//! the same type. The only difference is that this one's `answer` has
//! `.await` points in it, because its [`Blob`] and [`Platform`] may take
//! their time. Nothing in [`FileReadSession`] knows or cares which loop
//! is driving it: that is what "sans-I/O" buys, and what lets the choice
//! of sync versus async be made at whichever layer actually has an
//! opinion — here, the c2pa-wasm-shaped one.

use contentauth_c2pa_file_reader::{
    Error, FileReadReply, FileReadRequest, FileReadSession, FormatHandler, ReadReport, ReadSettings,
};
use contentauth_c2pa_primitives::HostError;
use contentauth_state_machine::{Session, Step};

use crate::{blob::Blob, platform::Platform};

/// Locates and reads the C2PA manifest store embedded in `blob`,
/// validating it per `settings`, awaiting `blob` and `platform` for every
/// request the session makes.
///
/// `handler` locates the manifest store within `blob`'s container format,
/// and `blob` also serves every byte-range and length request the read
/// issues for hard-binding verification, since those cover the whole
/// asset rather than just the manifest store. `platform` answers for the
/// clock and, if it can, OCSP.
///
/// Every outstanding request is answered, in the order the session issued
/// them, before the session is advanced again; a host that would rather
/// answer several at once (say, to overlap the network round trips behind
/// them) can do so, since the engine accepts replies in any order — this
/// loop simply does not need to.
///
/// The future this returns suspends exactly when `blob` or `platform`
/// does — at least once per request, for a [`Blob`] backed by a real
/// `Promise` — and never otherwise: between two awaits the engine runs
/// synchronously, hashing and parsing, until it needs something else. A
/// browser host driving several reads from one thread therefore gets
/// them interleaved at every request boundary, which is the cooperative
/// yielding c2pa-wasm's `FileReaderSync`-backed stream can never offer.
pub async fn read_manifest<H, B, P>(
    handler: &H,
    blob: &B,
    platform: &P,
    settings: ReadSettings,
) -> Result<ReadReport, Error>
where
    H: FormatHandler,
    B: Blob + ?Sized,
    P: Platform + ?Sized,
{
    let mut session = FileReadSession::new(handler, settings);

    loop {
        if session.advance()? == Step::Complete {
            return session.finish();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(blob, platform, &request.kind).await;
            session.fulfill(request.id, reply)?;
        }
    }
}

/// Answers one request from `blob` or `platform`, whichever it concerns.
///
/// Never fails of its own accord: whatever the host cannot do becomes a
/// [`FileReadReply::Failed`], and the engine decides what that means for
/// the request in question — fail-open for OCSP, an unevaluated validity
/// window for a clock it cannot get, an unchecked hard binding for an
/// asset whose length it cannot learn, and a hard error
/// ([`contentauth_c2pa_reader::Error::HostFailure`]) for bytes it was
/// already told exist and then could not read.
async fn answer<B, P>(blob: &B, platform: &P, request: &FileReadRequest) -> FileReadReply
where
    B: Blob + ?Sized,
    P: Platform + ?Sized,
{
    match request {
        FileReadRequest::Read { range, .. } => match blob.bytes(*range).await {
            // A `Blob` implementation is documented to return exactly
            // `range.len` bytes, but this loop is the engine's last line
            // of defense against one that does not: a short (or long)
            // read handed through would be hashed as though it were the
            // real thing.
            Ok(bytes) if bytes.len() as u64 == range.len => FileReadReply::Bytes(bytes),
            Ok(bytes) => FileReadReply::Failed(HostError::new(format!(
                "asked for {} bytes at {}, but the blob returned {}",
                range.len,
                range.start,
                bytes.len()
            ))),
            Err(err) => FileReadReply::Failed(err),
        },

        FileReadRequest::Length { .. } => FileReadReply::Length(blob.size()),

        FileReadRequest::CurrentDateTime => match platform.current_date_time().await {
            Ok(time) => FileReadReply::CurrentDateTime(time),
            Err(err) => FileReadReply::Failed(err),
        },

        FileReadRequest::Ocsp { url, request_der } => match platform.ocsp(url, request_der).await {
            Ok(bytes) => FileReadReply::OcspResponse(bytes),
            Err(err) => FileReadReply::Failed(err),
        },

        // `FileReadRequest` is `#[non_exhaustive]`; a variant this host
        // does not yet know how to answer is reported as unsupported
        // rather than a compile error the next time it grows one.
        _ => FileReadReply::Failed(HostError::new("unsupported request")),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use contentauth_c2pa_primitives::{ByteRange, StreamId};

    use super::*;

    /// Polls `future` to completion on the current thread.
    ///
    /// Every future in these tests is ready on its first poll, so a
    /// no-op waker and a single poll are all that is needed — the
    /// integration tests in `tests/async_host.rs` are where futures that
    /// genuinely suspend are driven.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    /// A [`Blob`] that returns whatever it is told to for every read,
    /// regardless of the range asked for.
    struct Canned(Result<Vec<u8>, HostError>);

    impl Blob for Canned {
        fn size(&self) -> u64 {
            100
        }

        async fn bytes(&self, _range: ByteRange) -> Result<Vec<u8>, HostError> {
            self.0.clone()
        }
    }

    /// A [`Platform`] that fails everything.
    struct Nothing;

    impl Platform for Nothing {
        async fn current_date_time(&self) -> Result<i64, HostError> {
            Err(HostError::new("no clock"))
        }

        async fn ocsp(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, HostError> {
            Err(HostError::new("no network"))
        }
    }

    fn read(len: u64) -> FileReadRequest {
        FileReadRequest::Read {
            stream: StreamId::new(0),
            range: ByteRange { start: 0, len },
        }
    }

    #[test]
    fn a_read_returning_exactly_the_requested_length_is_passed_through() {
        let reply = block_on(answer(&Canned(Ok(vec![1, 2, 3])), &Nothing, &read(3)));
        assert!(matches!(reply, FileReadReply::Bytes(bytes) if bytes == [1, 2, 3]));
    }

    #[test]
    fn a_short_read_is_reported_as_failed_rather_than_passed_through() {
        let reply = block_on(answer(&Canned(Ok(vec![1, 2])), &Nothing, &read(3)));
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_long_read_is_reported_as_failed_rather_than_passed_through() {
        let reply = block_on(answer(&Canned(Ok(vec![1, 2, 3, 4])), &Nothing, &read(3)));
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_failed_read_is_reported_as_failed() {
        let blob = Canned(Err(HostError::new("disk on fire")));
        let reply = block_on(answer(&blob, &Nothing, &read(3)));
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn length_is_answered_from_the_blob_size_without_awaiting_anything() {
        let reply = block_on(answer(
            &Canned(Ok(vec![])),
            &Nothing,
            &FileReadRequest::Length {
                stream: StreamId::new(0),
            },
        ));
        assert!(matches!(reply, FileReadReply::Length(100)), "{reply:?}");
    }

    #[test]
    fn a_platform_without_a_clock_fails_the_time_request() {
        let reply = block_on(answer(
            &Canned(Ok(vec![])),
            &Nothing,
            &FileReadRequest::CurrentDateTime,
        ));
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_platform_without_a_network_fails_the_ocsp_request() {
        let reply = block_on(answer(
            &Canned(Ok(vec![])),
            &Nothing,
            &FileReadRequest::Ocsp {
                url: "http://ocsp.example/".to_string(),
                request_der: vec![1, 2, 3],
            },
        ));
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    /// A [`Platform`] that answers both requests, so the success paths
    /// through `answer` are covered too.
    struct Everything;

    impl Platform for Everything {
        async fn current_date_time(&self) -> Result<i64, HostError> {
            Ok(1_800_000_000)
        }

        async fn ocsp(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, HostError> {
            assert_eq!(url, "http://ocsp.example/");
            assert_eq!(request_der, [1, 2, 3]);
            Ok(vec![4, 5, 6])
        }
    }

    #[test]
    fn a_platform_with_a_clock_answers_the_time_request() {
        let reply = block_on(answer(
            &Canned(Ok(vec![])),
            &Everything,
            &FileReadRequest::CurrentDateTime,
        ));
        assert!(
            matches!(reply, FileReadReply::CurrentDateTime(1_800_000_000)),
            "{reply:?}"
        );
    }

    #[test]
    fn a_platform_with_a_network_answers_the_ocsp_request_with_what_the_responder_sent() {
        let reply = block_on(answer(
            &Canned(Ok(vec![])),
            &Everything,
            &FileReadRequest::Ocsp {
                url: "http://ocsp.example/".to_string(),
                request_der: vec![1, 2, 3],
            },
        ));
        assert!(
            matches!(reply, FileReadReply::OcspResponse(ref bytes) if *bytes == [4, 5, 6]),
            "{reply:?}"
        );
    }
}
