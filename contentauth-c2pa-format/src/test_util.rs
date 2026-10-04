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

//! Test scaffolding for format handler crates: an in-memory host that
//! drives any format operation over byte slices, and the conformance
//! suite every handler is expected to pass.
//!
//! Enabled by the `test-util` feature. Everything here asserts rather
//! than returns errors — it is meant to be called from a `#[test]`.

// Test scaffolding: a failed expectation *is* the report.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::collections::HashMap;

use contentauth_c2pa_primitives::{HostError, StreamId};
use contentauth_state_machine::{ProtocolError, Session, Step};

use crate::request::{IoReply, IoRequest};

/// The stream [`MemoryHost::of`] places its single asset on.
pub const STREAM: StreamId = StreamId::new(0);

/// A host whose streams are byte vectors, answering [`IoRequest`]s from
/// them.
#[derive(Debug, Default)]
pub struct MemoryHost {
    streams: HashMap<StreamId, Vec<u8>>,
}

impl MemoryHost {
    /// A host with no streams.
    pub fn new() -> Self {
        Self::default()
    }

    /// A host with a single asset on [`STREAM`].
    pub fn of(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new().with_stream(STREAM, bytes)
    }

    /// Adds (or replaces) the asset on `stream`.
    pub fn with_stream(mut self, stream: StreamId, bytes: impl Into<Vec<u8>>) -> Self {
        self.streams.insert(stream, bytes.into());
        self
    }

    /// Drives `session` to completion, answering every request from this
    /// host's streams, and returns its result.
    ///
    /// A request for a stream this host does not have, or a range past
    /// its end, is answered with [`IoReply::Failed`] — what a real host
    /// would do — so an operation's handling of host failure is exercised
    /// rather than short-circuited. A session that parks with nothing
    /// outstanding can never finish; that is reported as
    /// [`ProtocolError::SessionNotComplete`].
    pub fn run<S>(&self, mut session: S) -> Result<S::Output, S::Error>
    where
        S: Session<Request = IoRequest>,
    {
        loop {
            if session.advance()? == Step::Complete {
                return session.finish();
            }

            let requests = session.outstanding_requests().to_vec();
            if requests.is_empty() {
                return Err(ProtocolError::SessionNotComplete.into());
            }

            for request in requests {
                session.fulfill(request.id, self.reply(&request.kind))?;
            }
        }
    }

    fn reply(&self, request: &IoRequest) -> IoReply {
        match request {
            IoRequest::Read { stream, range } => {
                let Some(bytes) = self.streams.get(stream) else {
                    return IoReply::Failed(HostError::new(format!("no such stream: {stream}")));
                };
                let end = range.start.checked_add(range.len);
                match end.filter(|end| *end <= bytes.len() as u64) {
                    Some(end) => IoReply::Bytes(bytes[range.start as usize..end as usize].to_vec()),
                    None => IoReply::Failed(HostError::new(format!(
                        "range {}+{} lies past the end of {stream} ({} bytes)",
                        range.start,
                        range.len,
                        bytes.len()
                    ))),
                }
            }

            IoRequest::Length { stream } => match self.streams.get(stream) {
                Some(bytes) => IoReply::Length(bytes.len() as u64),
                None => IoReply::Failed(HostError::new(format!("no such stream: {stream}"))),
            },
        }
    }
}

/// Checks every format handler is expected to pass.
///
/// Each function takes an *unsigned* source asset — one that
/// [`FormatHandler::locate`](crate::FormatHandler::locate) finds nothing
/// in — and manifest store bytes
/// to embed. The stores need not be real C2PA manifests as far as this
/// suite is concerned, but a handler that recognizes its manifest
/// segments by their content (as a JPEG handler must, to tell a C2PA
/// `APP11` segment from any other JUMBF) will need them to start like
/// one; the handler's own tests know what that takes.
pub mod conformance {
    use crate::{
        handler::FormatHandler,
        location::ManifestLocation,
        plan::EmbedPlan,
        test_util::{MemoryHost, STREAM},
    };

    /// Embeds `manifest` into `source` the way a host would: plans, checks
    /// the plan, materializes it, commits, and applies the patches —
    /// asserting along the way that every patch lies within the exclusion
    /// range. Returns the plan and the output.
    pub fn embed<H: FormatHandler>(
        handler: &H,
        source: &[u8],
        manifest: &[u8],
    ) -> (EmbedPlan, Vec<u8>) {
        let host = MemoryHost::of(source);
        let plan = host
            .run(handler.plan_embed(STREAM, manifest.len() as u64))
            .expect("plan_embed failed");

        let output_len = plan
            .check(source.len() as u64)
            .expect("the plan failed its consistency check");
        let mut output = plan
            .materialize(source, manifest)
            .expect("the plan could not be materialized");
        assert_eq!(output.len() as u64, output_len);

        let patches = handler.commit(&plan, manifest).expect("commit failed");
        for patch in &patches {
            assert!(
                plan.excludes(patch.range()),
                "commit patch at offset {} ({} bytes) lies outside the exclusions {:?}",
                patch.offset,
                patch.bytes.len(),
                plan.exclusions
            );
            patch
                .apply(&mut output)
                .expect("a patch could not be applied");
        }

        (plan, output)
    }

    /// Locates the manifest store in `asset`.
    pub fn locate<H: FormatHandler>(handler: &H, asset: &[u8]) -> ManifestLocation {
        MemoryHost::of(asset)
            .run(handler.locate(STREAM))
            .expect("locate failed")
    }

    /// Embedding a store and locating it again yields the identical bytes,
    /// at the range the plan declared as its exclusion. Returns the signed
    /// output.
    pub fn embed_then_locate_round_trips<H: FormatHandler>(
        handler: &H,
        source: &[u8],
        manifest: &[u8],
    ) -> Vec<u8> {
        let (plan, output) = embed(handler, source, manifest);

        let embedded = locate(handler, &output)
            .embedded
            .expect("locate found no embedded manifest store after one was embedded");
        assert_eq!(
            embedded.jumbf, manifest,
            "the located manifest store differs from the one embedded"
        );
        assert_eq!(
            embedded.exclusions, plan.exclusions,
            "the located exclusions differ from the plan's"
        );

        output
    }

    /// Embedding into an already-signed asset replaces the store rather
    /// than adding a second one, reports the replaced range, and — for an
    /// asset this suite signed itself — yields exactly the bytes that
    /// embedding the new store into the unsigned source would have.
    ///
    /// That last property holds for any handler whose insertion point
    /// does not depend on what else the asset carries — every handler
    /// built on [`EmbedPlan::splice`] with a fixed insertion rule. A
    /// handler for which it genuinely cannot hold should call the other
    /// checks individually rather than [`run_all`].
    pub fn re_embedding_replaces_rather_than_duplicates<H: FormatHandler>(
        handler: &H,
        unsigned_source: &[u8],
        first: &[u8],
        second: &[u8],
    ) {
        let (first_plan, signed_once) = embed(handler, unsigned_source, first);
        assert_eq!(
            first_plan.replaced, None,
            "embedding into an unsigned asset reported a replaced range"
        );

        let located_once = locate(handler, &signed_once)
            .embedded
            .expect("locate found no embedded manifest store after one was embedded");

        let (second_plan, signed_twice) = embed(handler, &signed_once, second);
        assert_eq!(
            second_plan.replaced,
            Some(located_once.range),
            "re-embedding must report the range of the store it replaced"
        );

        let embedded = locate(handler, &signed_twice)
            .embedded
            .expect("locate found no embedded manifest store after re-embedding");
        assert_eq!(
            embedded.jumbf, second,
            "the located manifest store is not the one most recently embedded"
        );
        assert_eq!(embedded.exclusions, second_plan.exclusions);

        let (_, direct) = embed(handler, unsigned_source, second);
        assert_eq!(
            signed_twice, direct,
            "replacing a store must yield the same bytes as embedding it fresh"
        );
    }

    /// An unsigned asset locates as carrying no manifest store, embedded
    /// or remote.
    pub fn an_unsigned_asset_locates_nothing<H: FormatHandler>(
        handler: &H,
        unsigned_source: &[u8],
    ) {
        let location = locate(handler, unsigned_source);
        assert!(
            location.is_none(),
            "locate reported a manifest store in an unsigned asset: {location:?}"
        );
    }

    /// Runs every check in this module. `first` and `second` should
    /// differ in length as well as content, so a handler that sizes its
    /// framing from the store's length is exercised on a replacement that
    /// changes it.
    pub fn run_all<H: FormatHandler>(
        handler: &H,
        unsigned_source: &[u8],
        first: &[u8],
        second: &[u8],
    ) {
        an_unsigned_asset_locates_nothing(handler, unsigned_source);
        embed_then_locate_round_trips(handler, unsigned_source, first);
        embed_then_locate_round_trips(handler, unsigned_source, second);
        re_embedding_replaces_rather_than_duplicates(handler, unsigned_source, first, second);
    }
}

#[cfg(test)]
mod tests {
    use contentauth_c2pa_primitives::ByteRange;

    use super::*;

    #[test]
    fn a_memory_host_answers_from_its_streams() {
        let host = MemoryHost::of(vec![1, 2, 3, 4]).with_stream(StreamId::new(7), vec![9]);

        assert!(matches!(
            host.reply(&IoRequest::Length { stream: STREAM }),
            IoReply::Length(4)
        ));
        assert!(matches!(
            host.reply(&IoRequest::Read {
                stream: StreamId::new(7),
                range: ByteRange { start: 0, len: 1 }
            }),
            IoReply::Bytes(bytes) if bytes == [9]
        ));
        assert!(matches!(
            host.reply(&IoRequest::Read {
                stream: STREAM,
                range: ByteRange { start: 3, len: 2 }
            }),
            IoReply::Failed(_)
        ));
        assert!(matches!(
            host.reply(&IoRequest::Length {
                stream: StreamId::new(99)
            }),
            IoReply::Failed(_)
        ));
    }
}
