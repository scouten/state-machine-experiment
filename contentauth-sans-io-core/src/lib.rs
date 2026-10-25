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

//! Host-driven, sans-I/O workflows for C2PA and CAWG crates.
//!
//! The host application owns I/O, concurrency, and scheduling, ideally in
//! its own language and runtime. A workflow exposes external operations
//! (files, networking, the clock, signing) through an explicit request/reply
//! protocol; it never performs I/O, blocks on a host operation, or spawns
//! threads itself.
//!
//! This is shared infrastructure for Content Authenticity's C2PA and CAWG
//! crates, not a general-purpose workflow framework. The core contains no
//! domain-specific validation or signing logic.
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
//! * [`Step`] and [`Workflow`] — the `advance` / `outstanding_requests` /
//!   `fulfill` / `finish` interaction contract itself, as a trait so
//!   host-side code can be written once against any session built here.
//! * [`ManualWorkflowCore`] — a struct a concrete session embeds to get request
//!   tracking and terminal-state bookkeeping for free, leaving only its own
//!   workflow logic to write.
//! * [`CoroutineWorkflow`], [`Host`], and [`PendingReply`] — the alternative to
//!   [`ManualWorkflowCore`]: write the workflow as an `async fn` that awaits its
//!   host's replies, and let the compiler generate the state machine. No
//!   async runtime is involved, and the host sees the same [`Workflow`]
//!   contract either way.
//! * [`Nested`] — a [`Workflow`] driven from inside a [`CoroutineWorkflow`], so a
//!   session that composes others can answer their requests itself or
//!   forward them to its own host from a plain `async` loop.
//!
//! A concrete workflow — reading and validating a C2PA manifest store or
//! generating and signing one — lives in its own crate built on top of
//! this one, with its own request vocabulary, settings, and result type.
//! See [`ManualWorkflowCore`] for a complete (if trivial) example of
//! assembling one.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod coroutine;
mod error;
mod nested;
mod recorder;
mod request;
#[cfg(test)]
mod test_session;
mod tracker;
mod types;
mod workflow;

pub use coroutine::{CoroutineWorkflow, Host, PendingReply};
pub use error::{Failure, ProtocolError};
pub use nested::Nested;
pub use recorder::{replay, Divergence, Event, Outcome, Recorder, Transcript};
pub use request::{HostRequest, Request};
pub use tracker::RequestTracker;
pub use types::RequestId;
pub use workflow::{ManualWorkflowCore, Step, Workflow};
