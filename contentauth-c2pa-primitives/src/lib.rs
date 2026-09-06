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

//! Shared vocabulary and deterministic encoders for the sans-I/O C2PA
//! crates in this workspace.
//!
//! [`contentauth_c2pa_reader`](https://docs.rs/contentauth-c2pa-reader) and
//! `contentauth-c2pa-builder` are independent sans-I/O sessions built on
//! `contentauth-state-machine`, each with its own request vocabulary and
//! settings/result types, per that crate's design. This crate holds the
//! narrow slice of the two that is genuinely the same thing in both
//! directions — the same algorithms, the same wire format, the same
//! deterministic encoding — rather than something either crate would
//! reasonably reimplement on its own:
//!
//! * [`types`] — [`StreamId`], [`ByteRange`], [`HashAlgorithm`], and
//!   [`SigningAlg`], the opaque handles and algorithm vocabulary both
//!   crates address the same host requests and COSE structures with.
//! * [`hash`] — digest computation. Verifying a hash and computing one to
//!   record are the same operation.
//! * [`cbor`] — a hand-rolled, deterministic CBOR encoder for the COSE
//!   `Sig_structure` a claim signature covers. The reader reconstructs
//!   these bytes to verify a signature; a builder constructs the identical
//!   bytes to produce one. A disagreement between two independent
//!   implementations of this one function would be a serious bug, so it
//!   lives here instead.
//! * [`error::HostError`] — the "the host couldn't do it" wrapper every
//!   sans-I/O session's reply vocabulary needs, regardless of what kind of
//!   work the session does.
//!
//! What is deliberately *not* here: anything about reading or writing a
//! manifest store itself (JUMBF/claim/assertion structure, certificate
//! chain validation, trust policy) — those are one-directional or
//! workflow-specific, and stay in the crate that needs them.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod cbor;
pub mod error;
pub mod hash;
pub mod types;

pub use error::HostError;
pub use types::{ByteRange, HashAlgorithm, SigningAlg, StreamId};
