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

//! `NodeSession` driven by a plain synchronous loop — no runtime, no
//! threads, no futures anywhere in this file — and checked against what
//! the async host in `contentauth-c2pa-js-compat` makes of the same bytes:
//! same engine, a different (here: trivial) host.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use contentauth_c2pa_js_compat::Platform;
use contentauth_c2pa_node_compat::{
    C2paError, Error, NodeSession, PendingRequest, Reader, Reply, Step,
};
use contentauth_c2pa_primitives::HostError;

const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");
const NOW: i64 = 1_800_000_000;

/// Answers one request from `asset`.
fn answer(asset: &[u8], request: &PendingRequest) -> Reply {
    match request {
        PendingRequest::Read { start, len, .. } => {
            let (start, len) = (*start as usize, *len as usize);
            match asset.get(start..start + len) {
                Some(bytes) => Reply::Bytes(bytes.to_vec()),
                None => Reply::Failed("range past end".to_string()),
            }
        }
        PendingRequest::Length { .. } => Reply::Length(asset.len() as u64),
        PendingRequest::CurrentDateTime { .. } => Reply::Time(NOW),
        PendingRequest::Ocsp { .. } => Reply::Failed("offline".to_string()),
        _ => Reply::Failed("unsupported".to_string()),
    }
}

/// The whole conversation, synchronously. Returns the reader and how many
/// requests of each kind the engine made.
fn read(asset: &[u8], format: &str) -> Result<(Option<Reader>, Counts), Error> {
    let mut session = NodeSession::new(format, None)?;
    let mut counts = Counts::default();
    loop {
        match session.advance()? {
            Step::Complete => return Ok((session.finish()?, counts)),
            Step::Pending(requests) => {
                assert!(!requests.is_empty(), "stalled: nothing new, nothing done");
                counts.max_batch = counts.max_batch.max(requests.len());
                for request in &requests {
                    match request {
                        PendingRequest::Read { .. } => counts.reads += 1,
                        _ => counts.other += 1,
                    }
                    session.fulfill(request.id(), answer(asset, request))?;
                }
            }
        }
    }
}

#[derive(Default, Debug)]
struct Counts {
    reads: usize,
    other: usize,
    max_batch: usize,
}

struct Fixed;

impl Platform for Fixed {
    async fn current_date_time(&self) -> Result<i64, HostError> {
        Ok(NOW)
    }

    async fn ocsp(&self, _: &str, _: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("offline"))
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

#[test]
fn a_synchronous_loop_reads_a_signed_jpeg() {
    let (reader, counts) = read(C_JPG, "image/jpeg").unwrap();
    let reader = reader.expect("C.jpg carries a manifest store");

    assert!(reader.active_label().is_some());
    assert!(reader.active_manifest().is_some());
    assert!(reader.is_embedded());
    assert_eq!(reader.remote_url(), "");
    assert!(reader.json().contains("\"validation_state\""));
    assert!(counts.reads > 0, "{counts:?}");
}

#[test]
fn it_reports_exactly_what_the_async_host_reports_for_the_same_bytes() {
    let (reader, _) = read(C_JPG, "image/jpeg").unwrap();

    let via_js = block_on(contentauth_c2pa_js_compat::Reader::from_blob(
        "image/jpeg",
        C_JPG,
        None,
        &Fixed,
    ))
    .unwrap();

    assert_eq!(reader.unwrap().json(), via_js.json());
}

#[test]
fn several_requests_are_handed_up_at_once_for_the_host_to_overlap() {
    // The engine pipelines chunk reads of the asset; the sync surface
    // must expose that, or a host could never run them concurrently.
    let (_, counts) = read(C_JPG, "image/jpeg").unwrap();
    assert!(counts.max_batch > 1, "{counts:?}");
}

#[test]
fn each_request_is_reported_once_and_replies_may_arrive_in_any_order() {
    let mut session = NodeSession::new("image/jpeg", None).unwrap();
    let mut seen = std::collections::HashSet::new();

    loop {
        match session.advance().unwrap() {
            Step::Complete => break,
            Step::Pending(mut requests) => {
                for request in &requests {
                    assert!(seen.insert(request.id()), "{request:?} reported twice");
                }
                // Answer last-first, and only after a second advance has
                // had the chance to (wrongly) repeat them.
                let again = session.advance().unwrap();
                assert!(
                    matches!(again, Step::Pending(ref r) if r.is_empty()),
                    "{again:?}"
                );
                requests.reverse();
                for request in &requests {
                    session
                        .fulfill(request.id(), answer(C_JPG, request))
                        .unwrap();
                }
            }
        }
    }

    assert!(session.finish().unwrap().is_some());
}

#[test]
fn an_asset_without_a_manifest_store_finishes_with_no_reader() {
    let (reader, _) = read(&[0xff, 0xd8, 0xff, 0xd9], "image/jpeg").unwrap();
    assert!(reader.is_none());
}

#[test]
fn a_host_that_cannot_read_the_asset_is_an_error_not_a_hang() {
    let mut session = NodeSession::new("image/jpeg", None).unwrap();
    let outcome = loop {
        match session.advance() {
            Err(err) => break Err(err),
            Ok(Step::Complete) => break Ok(()),
            Ok(Step::Pending(requests)) => {
                for request in requests {
                    let _ = session.fulfill(request.id(), Reply::Failed("disk on fire".into()));
                }
            }
        }
    };
    assert!(outcome.is_err() || session.finish().unwrap().is_none());
}

#[test]
fn protocol_misuse_is_reported_not_trusted() {
    let mut session = NodeSession::new("image/jpeg", None).unwrap();
    assert!(session.fulfill(99, Reply::Length(1)).is_err());

    let Step::Pending(requests) = session.advance().unwrap() else {
        panic!("a fresh session needs the host");
    };
    let id = requests[0].id();
    // A reply of the wrong kind for the request is rejected...
    let wrong = match requests[0] {
        PendingRequest::Read { .. } => Reply::Time(0),
        _ => Reply::Bytes(vec![]),
    };
    assert!(session.fulfill(id, wrong).is_err());
    // ...and the request is still answerable afterwards.
    session.fulfill(id, answer(C_JPG, &requests[0])).unwrap();
}

#[test]
fn bad_format_and_bad_settings_fail_before_any_request() {
    assert!(matches!(
        NodeSession::new("image/png", None),
        Err(Error::C2pa(C2paError::UnsupportedType))
    ));
    assert!(matches!(
        NodeSession::new("image/jpeg", Some("{not json")),
        Err(Error::C2pa(C2paError::BadParam(_)))
    ));
}
