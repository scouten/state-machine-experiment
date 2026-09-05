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

//! An experimental, fully-synchronous, sans-I/O crate for generating and
//! signing C2PA manifest stores.
//!
//! # The big idea
//!
//! This crate builds on [`contentauth_state_machine`], the same reusable
//! engine [`contentauth_c2pa_reader`](https://docs.rs/contentauth-c2pa-reader)
//! is built on: a session performs all of its work synchronously and
//! externalizes anything that might need to be asynchronous (embedding
//! bytes into a container format, signing, RFC 3161 timestamping, a clock)
//! to its host through an explicit request/reply protocol.
//!
//! [`BuilderSession`] is this crate's session: it implements the
//! [`contentauth_state_machine::Session`] trait, and builds and signs a
//! C2PA manifest store for a digital asset. (Compare to `Builder` in
//! c2pa-rs.) When it needs something that may require an asynchronous
//! action in the host environment — embedding a placeholder, signing,
//! timestamping — it parks itself and hands the host a request. The host
//! services it using whatever async machinery is natural in its own
//! runtime, then calls back into the session with the result — or with a
//! failure signal — and asks the state machine to advance again.
//!
//! # The two-pass hard binding
//!
//! A manifest's hard binding must hash the asset it describes while
//! excluding the manifest's own bytes — but where those bytes land in the
//! host's container format is not known until they are actually embedded,
//! and the manifest's *content* (its hash, its signature, its timestamp)
//! is not known until after that. This session resolves the circularity
//! in one round trip: it assembles a placeholder manifest — every
//! variable field zero-filled at exactly its final encoded length — asks
//! the host to embed it and report back where it landed
//! ([`BuilderRequest::ReservePlaceholder`]), hashes the asset outside that
//! range, signs, and patches the real values into the very same buffer
//! before asking the host to commit it
//! ([`BuilderRequest::CommitManifest`]). See the `jumbf`, `data_hash`, and
//! `cose` modules' documentation for how every value that changes between
//! the two passes is engineered to keep the buffer's length invariant.
//!
//! # Status
//!
//! Experimental, and incomplete by design — mirroring
//! `contentauth-c2pa-reader`'s own posture. What works today: a single
//! manifest (no ingredients, no update manifests), a `c2pa.hash.data`
//! hard binding (the only binding the reader crate validates today),
//! caller-supplied opaque assertions, every C2PA-permitted signing
//! algorithm, and an optional RFC 3161 timestamp. Every manifest this
//! crate builds is exercised, in its own test suite, by round-tripping it
//! through `contentauth-c2pa-reader` and checking that it reads back as
//! [`ValidationState::Trusted`].
//!
//! Deliberately out of scope for now: ingredients and update manifests,
//! BMFF/box-hash hard bindings, OCSP, claim v2's created/gathered-
//! assertions split, and certificate decoding or validation (certificates
//! are passed through opaquely into the COSE `x5chain`; the host vouches
//! for them).
//!
//! [`ValidationState::Trusted`]: https://docs.rs/contentauth-c2pa-reader/latest/contentauth_c2pa_reader/enum.ValidationState.html#variant.Trusted

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod builder;
mod claim;
mod cose;
mod data_hash;
mod error;
mod hash_stream;
mod jumbf;
mod request;

pub use builder::{
    Assertion, BuilderReport, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    TimestampSettings,
};
pub use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, HostError, SigningAlg, StreamId};
pub use contentauth_state_machine::{HostRequest, ProtocolError, RequestId, Session};
pub use error::Error;
pub use request::{BuilderHostReply, BuilderRequest};
