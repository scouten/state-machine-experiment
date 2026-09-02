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

//! An experimental, fully-synchronous, sans-I/O crate for reading and
//! validating C2PA manifest stores.
//!
//! # The big idea
//!
//! This crate builds on [`contentauth_state_machine`], a reusable engine
//! for sessions that never block: a session performs all of its work
//! synchronously and externalizes anything that might need to be
//! asynchronous (file I/O, container format parsing, network access, a
//! clock) to its host through an explicit request/reply protocol carried by
//! a state machine struct that is handed back and forth.
//!
//! [`ReadSession`] is this crate's session: it implements the
//! [`contentauth_state_machine::Session`] trait, and reads and validates a
//! C2PA manifest store from a digital asset. (Compare to `Reader` in
//! c2pa-rs.) When it needs something that may require an asynchronous
//! action in the host environment, it parks itself and hands the host a set
//! of requests. The host services those requests using whatever async
//! machinery is natural in its own runtime, then calls back into the
//! session with the results — or with a failure signal — and asks the
//! state machine to advance again.
//!
//! See this crate's README for the full interaction contract, the request
//! vocabulary, and what [`ReadSession`] validates today.
//!
//! # Status
//!
//! Experimental, and incomplete by design. What works today:
//!
//! * The request vocabulary and interaction contract are real and
//!   exercised by tests, built directly on
//!   [`contentauth_state_machine::SessionCore`].
//! * [`ReadSession`] reads a manifest store end to end: JUMBF box parsing
//!   (via the [`jumbf`] crate), claim decoding ([`claim`]), and report
//!   population ([`ReadReport`]).
//! * Validation covers *integrity* — assertion hashes against the claim,
//!   and the active manifest's hard binding against the asset, hashed
//!   in-crate from chunks the host streams in — the *claim signature*,
//!   verified in-crate against the signer's certificate ([`validation`]),
//!   and *trust*: the signer's certificate path is built and verified link
//!   by link, held to the C2PA certificate profile, and checked against
//!   validity windows and the trust anchors in [`ReadSettings`]. A report
//!   can reach [`ValidationState::Valid`] and [`ValidationState::Trusted`].
//!   RFC 3161 timestamps are read and verified in-crate — the CMS is
//!   unwrapped, the authority's signature checked, its message imprint
//!   matched against the signature it countersigns, and its own chain
//!   validated — so a manifest signed with a since-expired certificate
//!   still reads as valid when a *trusted* authority stamped it.
//!   Not yet checked, and able to change a verdict: revocation (OCSP and
//!   CRL).
//!
//! [c2pa-rs]: https://github.com/contentauth/c2pa-rs

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod cert;
pub(crate) mod chain;
pub mod claim;
pub(crate) mod cose;
pub mod data_hash;
pub mod error;
pub mod hash;
pub(crate) mod hash_stream;
pub mod manifest_store;
pub mod read;
pub mod request;
pub(crate) mod timestamp;
pub mod types;
pub mod validation;

#[cfg(test)]
pub(crate) mod test_support;

pub use cert::{BasicConstraints, CertError, Certificate, KeyUsage};
pub use claim::{Claim, ClaimError, GeneratorInfo, HashedUri};
pub use contentauth_state_machine::{HostRequest, ProtocolError, RequestId, Session};
pub use data_hash::DataHash;
pub use error::{Error, HostError};
pub use manifest_store::Manifest;
pub use read::{ReadReport, ReadSession, ReadSettings, ReadStep};
pub use request::{HostReply, RequestKind};
pub use types::{ByteRange, HashAlgorithm, SigningAlg, StreamId};
pub use validation::{ValidationState, ValidationStatus};
