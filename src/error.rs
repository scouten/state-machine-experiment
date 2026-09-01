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

//! The protocol-level error vocabulary common to every session built on
//! this engine.

use crate::types::RequestId;

/// A misuse of the [`Session`](crate::Session) API, as opposed to a failure
/// of the workflow the session carries out.
///
/// Every one of these means the host binding is buggy — fulfilling a
/// request that was never issued or was already answered, answering with
/// the wrong payload type, or driving a session past a terminal state —
/// never that the data the session is working on is somehow wrong. A
/// concrete session's own `Error` type is expected to fold this in (for
/// example, via `#[from]`) alongside whatever domain-specific failures its
/// own workflow can produce.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The host fulfilled a request ID that is not outstanding in this
    /// session (never issued, or already fulfilled).
    #[error("no outstanding request with ID {0}")]
    UnknownRequest(RequestId),

    /// The host's reply payload does not match what the request asked for.
    #[error("reply payload does not match {id}: expected {expected}")]
    ReplyMismatch {
        /// ID of the request that was incorrectly fulfilled.
        id: RequestId,

        /// Description of the reply payload the request expects.
        expected: &'static str,
    },

    /// The session has already reached a terminal state; it cannot be
    /// advanced and no further requests can be fulfilled.
    #[error("session is already complete")]
    SessionComplete,

    /// The session's result was requested before the session reached a
    /// terminal state.
    #[error("session has not reached a terminal state")]
    SessionNotComplete,

    /// The session ended in an error on an earlier call and cannot be used
    /// further.
    ///
    /// A failed workflow typically leaves a session's internal state
    /// half-built, so handing anything out as if it were a result would be
    /// misleading. Sessions built with [`SessionCore`](crate::SessionCore)
    /// poison themselves on error: the original error is returned when it
    /// happens, and every later call reports this instead.
    #[error("session failed on an earlier call")]
    SessionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_request_they_concern() {
        assert_eq!(
            ProtocolError::UnknownRequest(RequestId(3)).to_string(),
            "no outstanding request with ID request #3"
        );
        assert_eq!(
            ProtocolError::ReplyMismatch {
                id: RequestId(1),
                expected: "Widget",
            }
            .to_string(),
            "reply payload does not match request #1: expected Widget"
        );
    }
}
