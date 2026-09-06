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

//! The error vocabulary every format handler reports through.

use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_state_machine::{ProtocolError, RequestId};

/// Errors a format handler's operations can fail with.
///
/// Deliberately a single, closed-over-the-contract type rather than one
/// per handler: an orchestrating session composes handlers it has never
/// seen, and needs to tell "the asset is broken" from "the host is broken"
/// from "the handler is broken" without knowing which format it is talking
/// to. A handler that needs to say more than these variants allow should
/// say it in the message, not in a new type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    /// The host used the [`contentauth_state_machine::Session`] API
    /// incorrectly.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A host read failed and the operation cannot continue without it.
    #[error("host reported failure for {id}: {source}")]
    HostFailure {
        /// ID of the request the host could not fulfill.
        id: RequestId,

        /// Failure description reported by the host.
        source: HostError,
    },

    /// The host returned a different number of bytes than the range it was
    /// asked for.
    ///
    /// Never tolerated: a handler parses container structure from these
    /// bytes, and a short or long read would put every subsequent offset
    /// in the wrong place.
    #[error(
        "host returned {actual} bytes for a request of {} at offset {}",
        range.len, range.start
    )]
    ReadLengthMismatch {
        /// The range that was requested.
        range: ByteRange,

        /// How many bytes the host actually returned.
        actual: u64,
    },

    /// The asset is not a well-formed instance of the handler's format.
    ///
    /// Also covers a container that is well-formed as far as the format
    /// specification goes but carries a manifest store in a way the C2PA
    /// specification does not allow — split across non-adjacent segments,
    /// say.
    #[error("asset is malformed: {0}")]
    Malformed(String),

    /// The asset is well-formed, but uses a feature of its format that
    /// this handler does not implement.
    #[error("asset is not supported: {0}")]
    Unsupported(String),

    /// An [`EmbedPlan`](crate::EmbedPlan) failed its own consistency
    /// check.
    ///
    /// Indicates a bug in the handler that produced the plan, not a
    /// problem with the asset.
    #[error("embed plan is inconsistent: {0}")]
    InvalidPlan(&'static str),

    /// The manifest store handed to [`FormatHandler::commit`] or
    /// [`EmbedPlan::materialize`] does not fit the plan it is being
    /// committed against.
    ///
    /// [`FormatHandler::commit`]: crate::FormatHandler::commit
    /// [`EmbedPlan::materialize`]: crate::EmbedPlan::materialize
    #[error("manifest store does not match the plan it is being committed against: {0}")]
    ManifestMismatch(&'static str),
}
