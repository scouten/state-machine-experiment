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

//! The smallest handler that can be written against this crate's
//! contract, used to exercise the conformance kit itself.
//!
//! The "trailer" format is made up for this test: an asset is arbitrary
//! bytes, and a signed asset is those bytes followed by the manifest
//! store, its length as a 4-byte big-endian integer, and the magic
//! `C2PA`. It is also the worked example the crate README points to for
//! how little a handler needs: one sequential scan over three host
//! requests, and a `splice`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use core::mem::replace;

use contentauth_c2pa_format::{
    take_bytes, take_length,
    test_util::{conformance, MemoryHost, STREAM},
    ByteRange, Edit, EmbedPlan, FormatDescriptor, FormatError, FormatHandler, HostRequest,
    IoRequest, ManifestLocation, Patch, ProtocolError, RequestId, Session, Signature, Step,
    StreamId,
};
use contentauth_state_machine::SessionCore;

const MAGIC: &[u8; 4] = b"C2PA";

/// Where the scan ended up: the source length, and the store's range and
/// bytes if the asset carried one.
struct Found {
    total: u64,
    store: Option<(ByteRange, Vec<u8>)>,
}

enum Phase {
    Start,
    Length(RequestId),
    Tail {
        id: RequestId,
        total: u64,
    },
    Store {
        id: RequestId,
        total: u64,
        len: u64,
    },
    Done(Found),

    /// Installed while a phase is being processed; left behind by an
    /// error exit.
    Poisoned,
}

/// The one scan both operations share: measure the asset, read its last
/// eight bytes, and if they end in the magic, read the store they
/// describe.
struct Scan {
    stream: StreamId,
    core: SessionCore<IoRequest>,
    phase: Phase,
}

impl Scan {
    fn new(stream: StreamId) -> Self {
        Self {
            stream,
            core: SessionCore::default(),
            phase: Phase::Start,
        }
    }

    fn advance(&mut self) -> Result<Step, FormatError> {
        if self.core.is_complete() {
            return Ok(Step::Complete);
        }

        match self.run() {
            Ok(step) => Ok(step),
            Err(err) => {
                self.core.mark_failed();
                Err(err)
            }
        }
    }

    fn run(&mut self) -> Result<Step, FormatError> {
        loop {
            match replace(&mut self.phase, Phase::Poisoned) {
                Phase::Start => {
                    let id = self.core.issue(IoRequest::Length {
                        stream: self.stream,
                    });
                    self.phase = Phase::Length(id);
                    return Ok(Step::AwaitHost);
                }

                Phase::Length(id) => match take_length(&mut self.core, id)? {
                    None => {
                        self.phase = Phase::Length(id);
                        return Ok(Step::AwaitHost);
                    }
                    Some(total) if total < 8 => {
                        self.phase = Phase::Done(Found { total, store: None });
                    }
                    Some(total) => {
                        let id = self.core.issue(IoRequest::Read {
                            stream: self.stream,
                            range: ByteRange {
                                start: total - 8,
                                len: 8,
                            },
                        });
                        self.phase = Phase::Tail { id, total };
                        return Ok(Step::AwaitHost);
                    }
                },

                Phase::Tail { id, total } => {
                    let range = ByteRange {
                        start: total - 8,
                        len: 8,
                    };
                    match take_bytes(&mut self.core, id, range)? {
                        None => {
                            self.phase = Phase::Tail { id, total };
                            return Ok(Step::AwaitHost);
                        }
                        Some(tail) if &tail[4..] != MAGIC => {
                            self.phase = Phase::Done(Found { total, store: None });
                        }
                        Some(tail) => {
                            let len =
                                u64::from(u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]));
                            if len + 8 > total {
                                return Err(FormatError::Malformed(
                                    "trailer names a store longer than the asset".to_string(),
                                ));
                            }
                            let id = self.core.issue(IoRequest::Read {
                                stream: self.stream,
                                range: ByteRange {
                                    start: total - 8 - len,
                                    len,
                                },
                            });
                            self.phase = Phase::Store { id, total, len };
                            return Ok(Step::AwaitHost);
                        }
                    }
                }

                Phase::Store { id, total, len } => {
                    let range = ByteRange {
                        start: total - 8 - len,
                        len,
                    };
                    match take_bytes(&mut self.core, id, range)? {
                        None => {
                            self.phase = Phase::Store { id, total, len };
                            return Ok(Step::AwaitHost);
                        }
                        Some(jumbf) => {
                            let carrier = ByteRange {
                                start: range.start,
                                len: len + 8,
                            };
                            self.phase = Phase::Done(Found {
                                total,
                                store: Some((carrier, jumbf)),
                            });
                        }
                    }
                }

                Phase::Done(found) => {
                    self.phase = Phase::Done(found);
                    self.core.mark_complete();
                    return Ok(Step::Complete);
                }

                Phase::Poisoned => return Err(ProtocolError::SessionFailed.into()),
            }
        }
    }

    fn finish(self) -> Result<Found, FormatError> {
        self.core.finish_check()?;
        match self.phase {
            Phase::Done(found) => Ok(found),
            _ => Err(ProtocolError::SessionFailed.into()),
        }
    }
}

struct Locate(Scan);

impl Session for Locate {
    type Error = FormatError;
    type Output = ManifestLocation;
    type Request = IoRequest;

    fn advance(&mut self) -> Result<Step, FormatError> {
        self.0.advance()
    }

    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
        self.0.core.outstanding_requests()
    }

    fn fulfill(
        &mut self,
        id: RequestId,
        reply: <IoRequest as contentauth_state_machine::Request>::Reply,
    ) -> Result<(), FormatError> {
        Ok(self.0.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<ManifestLocation, FormatError> {
        Ok(match self.0.finish()?.store {
            Some((range, jumbf)) => ManifestLocation::embedded(jumbf, range, vec![range]),
            None => ManifestLocation::none(),
        })
    }
}

struct PlanEmbed {
    scan: Scan,
    manifest_len: u64,
}

impl Session for PlanEmbed {
    type Error = FormatError;
    type Output = EmbedPlan;
    type Request = IoRequest;

    fn advance(&mut self) -> Result<Step, FormatError> {
        self.scan.advance()
    }

    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
        self.scan.core.outstanding_requests()
    }

    fn fulfill(
        &mut self,
        id: RequestId,
        reply: <IoRequest as contentauth_state_machine::Request>::Reply,
    ) -> Result<(), FormatError> {
        Ok(self.scan.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<EmbedPlan, FormatError> {
        let found = self.scan.finish()?;
        let replace = found.store.map(|(range, _)| range);
        let insert_at = replace.map_or(found.total, |range| range.start);

        let len = u32::try_from(self.manifest_len)
            .map_err(|_| FormatError::Unsupported("store longer than 4 GiB".to_string()))?;
        let mut trailer = len.to_be_bytes().to_vec();
        trailer.extend_from_slice(MAGIC);

        EmbedPlan::splice(
            found.total,
            replace,
            insert_at,
            self.manifest_len,
            vec![
                Edit::Placeholder(ByteRange {
                    start: 0,
                    len: self.manifest_len,
                }),
                Edit::Emit(trailer),
            ],
        )
    }
}

const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new(
    "trailer",
    &["application/x-trailer"],
    &["trl"],
    &[Signature::new(0, b"TRLR")],
);

struct TrailerFormat;

impl FormatHandler for TrailerFormat {
    type Locate = Locate;
    type PlanEmbed = PlanEmbed;

    fn descriptor(&self) -> &FormatDescriptor {
        &DESCRIPTOR
    }

    fn locate(&self, stream: StreamId) -> Locate {
        Locate(Scan::new(stream))
    }

    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> PlanEmbed {
        PlanEmbed {
            scan: Scan::new(stream),
            manifest_len,
        }
    }

    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
        if manifest.len() as u64 != plan.manifest_len {
            return Err(FormatError::ManifestMismatch(
                "store length differs from the plan's",
            ));
        }
        Ok(Vec::new())
    }
}

#[test]
fn the_trailer_format_passes_the_conformance_suite() {
    conformance::run_all(
        &TrailerFormat,
        b"an asset of no particular format",
        b"first store",
        b"the second store, which is longer",
    );
}

#[test]
fn the_signed_output_has_the_expected_shape() {
    let output = conformance::embed_then_locate_round_trips(&TrailerFormat, b"payload", b"store");

    let mut expected = b"payload".to_vec();
    expected.extend_from_slice(b"store");
    expected.extend_from_slice(&5u32.to_be_bytes());
    expected.extend_from_slice(MAGIC);
    assert_eq!(output, expected);
}

#[test]
fn a_trailer_that_overruns_the_asset_is_malformed() {
    let mut asset = b"short".to_vec();
    asset.extend_from_slice(&100u32.to_be_bytes());
    asset.extend_from_slice(MAGIC);

    let result = MemoryHost::of(asset).run(TrailerFormat.locate(STREAM));
    assert!(matches!(result, Err(FormatError::Malformed(_))));
}

#[test]
fn a_failed_operation_stays_failed() {
    // A stream the host does not have: the first request fails, the
    // operation poisons itself, and every later call says so.
    let host = MemoryHost::new();
    let mut op = TrailerFormat.locate(STREAM);

    assert_eq!(op.advance().unwrap(), Step::AwaitHost);
    let id = op.outstanding_requests()[0].id;
    op.fulfill(
        id,
        contentauth_c2pa_format::IoReply::Failed(contentauth_c2pa_format::HostError::new("no")),
    )
    .unwrap();
    assert!(matches!(op.advance(), Err(FormatError::HostFailure { .. })));
    assert!(matches!(
        op.advance(),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));
    assert!(matches!(
        op.finish(),
        Err(FormatError::Protocol(ProtocolError::SessionFailed))
    ));

    // And a host that can answer nothing drives the same path through
    // `MemoryHost::run`.
    assert!(matches!(
        host.run(TrailerFormat.locate(STREAM)),
        Err(FormatError::HostFailure { .. })
    ));
}
