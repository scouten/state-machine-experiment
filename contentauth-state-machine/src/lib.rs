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

//! A reusable engine for building synchronous, sans-I/O state machines.
//!
//! This crate carries no domain logic of its own. It distills the session
//! shape of a fully synchronous core that never blocks, and externalizes
//! anything that might need to be asynchronous (I/O, the network, a clock,
//! signing) to its host through an explicit request/reply protocol carried
//! by a state machine struct handed back and forth, into pieces any
//! subcomponent of a larger workflow can build on, independently of what
//! that subcomponent actually does.
//!
//! Concretely, this crate provides:
//!
//! * [`Request`] — the trait a session's own request vocabulary implements,
//!   relating each request kind to the reply that answers it.
//! * [`HostRequest`] and [`RequestId`] — the request envelope and its
//!   correlation ID.
//! * [`RequestTracker`] — bookkeeping for requests a session has issued but
//!   its host has not yet fulfilled.
//! * [`ProtocolError`] — the host-binding-is-buggy error vocabulary common
//!   to every session (an unknown request ID, a mismatched reply, driving a
//!   session past a terminal state).
//! * [`Step`] and [`Session`] — the `advance` / `outstanding_requests` /
//!   `fulfill` / `finish` interaction contract itself, as a trait so
//!   host-side code can be written once against any session built here.
//! * [`SessionCore`] — a struct a concrete session embeds to get request
//!   tracking and terminal-state bookkeeping for free, leaving only its own
//!   workflow logic to write.
//! * [`Workflow`], [`Host`], and [`PendingReply`] — the alternative to
//!   [`SessionCore`]: write the workflow as an `async fn` that awaits its
//!   host's replies, and let the compiler generate the state machine. No
//!   async runtime is involved, and the host sees the same [`Session`]
//!   contract either way.
//! * [`Nested`] — a [`Session`] driven from inside a [`Workflow`], so a
//!   session that composes others can answer their requests itself or
//!   forward them to its own host from a plain `async` loop.
//!
//! A concrete workflow — reading and validating a C2PA manifest store,
//! generating and signing one, or an unrelated state machine entirely —
//! lives in its own crate built on top of this one, with its own request
//! vocabulary, its own settings, and its own result type. See [`SessionCore`]
//! for a complete (if trivial) example of assembling one.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod error;
mod nested;
mod recorder;
mod request;
mod session;
#[cfg(test)]
mod test_session;
mod tracker;
mod types;
mod workflow;

pub use error::{Failure, ProtocolError};
pub use nested::Nested;
pub use recorder::{replay, Divergence, Event, Outcome, Recorder, Transcript};
pub use request::{HostRequest, Request};
pub use session::{Session, SessionCore, Step};
pub use tracker::RequestTracker;
pub use types::RequestId;
pub use workflow::{Host, PendingReply, Workflow};
