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

//! The contract between the sans-I/O C2PA sessions in this workspace and
//! the container formats (JPEG, PNG, …) their manifests live inside.
//!
//! # Why a contract crate
//!
//! [`contentauth_c2pa_reader`](https://docs.rs/contentauth-c2pa-reader) and
//! `contentauth-c2pa-builder` know nothing about container formats: the
//! reader asks its host for "the manifest store's bytes" and the builder
//! asks its host to "embed this placeholder and tell me where it landed".
//! This crate is where that knowledge is meant to plug in — one crate per
//! format, each implementing [`FormatHandler`], none of which the reader,
//! the builder, or this crate ever depend on. Third parties can ship a
//! handler for a format this workspace has never heard of, and a host that
//! knows what it is reading or writing picks the handler itself.
//!
//! # What a handler is
//!
//! Three operations, all format-specific, all pure:
//!
//! * [`FormatHandler::locate`] — find the manifest store in an asset and
//!   return its exact bytes and the byte range of the container structure
//!   that carries it (a [`ManifestLocation`]).
//! * [`FormatHandler::plan_embed`] — describe, as an [`EmbedPlan`], how to
//!   rewrite the asset so that a manifest store of a given length is
//!   embedded in it — copying ranges of the original through, emitting
//!   container framing the handler computes, and leaving
//!   [`Edit::Placeholder`] slots for the manifest bytes themselves.
//! * [`FormatHandler::commit`] — once the final manifest bytes are known,
//!   name any container bytes that depend on them (a PNG chunk's CRC, say)
//!   as [`Patch`]es.
//!
//! The first two need to read the asset, so they are themselves sessions
//! built on `contentauth-state-machine` — each is a [`FormatOp`] speaking
//! the one request vocabulary this crate defines, [`IoRequest`]: read a
//! range, report a length. A handler never writes: it *describes* the
//! output, and the host (or an orchestrating session) materializes it.
//!
//! # Why plans rather than writes
//!
//! Everything that crosses the handler boundary is plain data: byte ranges,
//! byte vectors, plans, patches. There are no callbacks and no borrowed
//! streams. That is what makes a handler unit-testable against a byte
//! slice (see [`test_util`]), what lets an orchestrating session compute a
//! hard-binding hash straight from the plan without the output ever being
//! written first, and what keeps the boundary crossable by a handler
//! implemented in another language — the same contract, marshalled.
//!
//! # Invariants a handler must keep
//!
//! [`EmbedPlan::check`] enforces the structural ones: every
//! [`Edit::Placeholder`] lies inside the plan's declared exclusion range,
//! and together they cover the manifest exactly once, in order. Two more
//! are the handler's to honor and the conformance suite's to check:
//!
//! * Every [`Patch`] returned by [`FormatHandler::commit`] lands inside the
//!   plan's exclusion range. A patch outside it would change bytes the
//!   hard binding has already hashed and silently invalidate the
//!   signature.
//! * Embedding into an asset that already carries a manifest store
//!   *replaces* it, and reports the replaced range in
//!   [`EmbedPlan::replaced`]. Whether replacing is acceptable — or whether
//!   the old store should first be validated and carried forward as a
//!   parent — is a policy decision for the caller, not the handler, which
//!   is why the handler reports rather than decides.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod error;
mod handler;
mod location;
mod plan;
mod request;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use contentauth_c2pa_primitives::{ByteRange, HostError, StreamId};
pub use contentauth_state_machine::{HostRequest, ProtocolError, RequestId, Session, Step};
pub use error::FormatError;
pub use handler::{FormatHandler, FormatOp};
pub use location::{EmbeddedManifest, ManifestLocation};
pub use plan::{Edit, EmbedPlan, Patch};
pub use request::{take_bytes, take_length, IoReply, IoRequest};
