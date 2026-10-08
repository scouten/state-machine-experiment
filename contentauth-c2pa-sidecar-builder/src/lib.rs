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

//! Build and sign a **sidecar** C2PA manifest store: a `.c2pa` file that
//! sits beside an asset and binds to it by hash, rather than living inside
//! it.
//!
//! This reproduces the use case of Gavin Peacock's `c2pa-sign-sample`
//! (c2pa-core): a `c2pa.hash.data` hard binding over the whole file, a
//! `c2pa.actions.v2` assertion recording `c2pa.created`, a v2 claim
//! referencing both, an Ed25519 `COSE_Sign1` over the claim — in the
//! sans-I/O state-machine style, as a composition of independent elements:
//!
//! | element | crate | knows |
//! |---|---|---|
//! | hard binding | `contentauth-c2pa-assertion-data-hash` | the assertion's fields, and how to hash a streamed asset |
//! | actions | `contentauth-c2pa-assertion-actions` | the assertion's fields |
//! | hashed URI | `contentauth-c2pa-primitives::hashed_uri` | box framing and digests |
//! | claim, signature | `contentauth-c2pa-claim` | the claim's fields and the COSE envelope |
//! | JUMBF | this crate's `store` module, over the `jumbf` crate | boxes |
//!
//! The session knows none of the assertion's fields: it is handed
//! [`EncodedAssertion`](contentauth_c2pa_primitives::EncodedAssertion)s —
//! labels and opaque CBOR — and drives the data hash as a sub-session.
//!
//! # Compared with embedding
//!
//! A sidecar has no placeholder, no exclusions, no second pass and no
//! container format: the asset is hashed whole, once, before the claim
//! exists, and the finished store is simply returned. So the session's host
//! vocabulary is three requests ([`SidecarRequest`]) and there is no
//! `FormatHandler` involved. To read a sidecar back, answer a
//! `ReadSession`'s `ManifestStore` request with the sidecar's bytes and its
//! asset requests with the asset's.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod request;
mod session;
mod store;

pub use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, HostError, SigningAlg, StreamId};
pub use contentauth_state_machine::{HostRequest, ProtocolError, RequestId, Session, Step};
pub use request::{SidecarReply, SidecarRequest};
pub use session::{SidecarReport, SidecarSession, SidecarSettings, ASSET_STREAM};

/// Why a sidecar could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The host used the session API incorrectly.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The host could not perform a request.
    #[error("the host failed: {0}")]
    Host(HostError),

    /// No signing certificate was supplied.
    #[error("no signing certificate supplied")]
    NoCertificates,

    /// Two assertions share a label, or one uses the label of the hard
    /// binding the session adds itself.
    #[error("duplicate or reserved assertion label {0:?}")]
    DuplicateLabel(String),

    /// The hard binding could not be computed.
    #[error(transparent)]
    DataHash(#[from] contentauth_c2pa_assertion_data_hash::Error),

    /// The claim or its signature could not be encoded.
    #[error(transparent)]
    Claim(#[from] contentauth_c2pa_claim::Error),

    /// A hashed URI could not be built.
    #[error(transparent)]
    HashedUri(#[from] contentauth_c2pa_primitives::hashed_uri::Error),

    /// The `jumbf` builder failed.
    #[error(transparent)]
    Jumbf(#[from] std::io::Error),
}
