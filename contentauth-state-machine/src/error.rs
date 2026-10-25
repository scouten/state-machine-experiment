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

use std::fmt;

use crate::types::RequestId;

/// A misuse of the [`Session`](crate::Session) API, as opposed to a failure
/// of the workflow the session carries out.
///
/// Every one of these but [`Self::WorkflowStalled`] means the host binding
/// is buggy — fulfilling a request that was never issued or was already
/// answered, answering with the wrong payload type, or driving a session past a terminal state —
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
    /// happens, and every later call reports this instead — carrying the
    /// phase the session failed in and the original error's message, so a
    /// host that only sees this later report still learns where and why.
    #[error("{0}")]
    SessionFailed(Failure),

    /// A [`Workflow`](crate::Workflow) is waiting, yet has nothing
    /// outstanding that the host could answer to unblock it.
    ///
    /// This is a bug in the workflow rather than its host: it awaited
    /// something other than a [`PendingReply`](crate::PendingReply).
    #[error("workflow is waiting on something other than its host")]
    WorkflowStalled,
}

/// Where and why a session failed, as remembered by
/// [`SessionCore::mark_failed`](crate::SessionCore::mark_failed) and
/// reported by [`ProtocolError::SessionFailed`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Failure {
    /// The phase the session was in when it failed, as reported by
    /// [`Session::phase`](crate::Session::phase). Empty if unknown.
    pub phase: String,

    /// The message of the error that ended the session. Empty if unknown.
    pub cause: String,
}

impl Failure {
    /// Records a failure in `phase` caused by `cause`.
    pub fn new(phase: impl Into<String>, cause: &dyn fmt::Display) -> Self {
        Self {
            phase: phase.into(),
            cause: cause.to_string(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("session failed on an earlier call")?;
        if !self.phase.is_empty() {
            write!(f, ", in {}", self.phase)?;
        }
        if !self.cause.is_empty() {
            write!(f, ": {}", self.cause)?;
        }
        Ok(())
    }
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

    #[test]
    fn session_failed_reports_where_and_why_when_known() {
        assert_eq!(
            ProtocolError::SessionFailed(Failure::default()).to_string(),
            "session failed on an earlier call"
        );
        assert_eq!(
            ProtocolError::SessionFailed(Failure::new("Reading > AwaitingOcsp", &"revoked"))
                .to_string(),
            "session failed on an earlier call, in Reading > AwaitingOcsp: revoked"
        );
        assert_eq!(
            ProtocolError::SessionFailed(Failure::new("", &"revoked")).to_string(),
            "session failed on an earlier call: revoked"
        );
    }
}
