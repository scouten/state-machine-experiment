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

//! Bookkeeping for outstanding host requests.

use crate::{
    error::ProtocolError,
    request::{HostRequest, Request},
    types::RequestId,
};

/// Tracks the requests a session has issued but the host has not yet
/// fulfilled, and holds fulfilled replies until the state machine consumes
/// them on its next `advance`.
///
/// Generic over the session's own request vocabulary `Req`, so every
/// concrete session built on this engine gets request issuance, ID
/// correlation, and reply-shape validation for free rather than
/// hand-rolling it.
#[derive(Debug)]
pub struct RequestTracker<Req: Request> {
    next_id: u64,
    outstanding: Vec<HostRequest<Req>>,
    replies: Vec<(RequestId, Req::Reply)>,
}

impl<Req: Request> Default for RequestTracker<Req> {
    fn default() -> Self {
        Self {
            next_id: 0,
            outstanding: Vec::new(),
            replies: Vec::new(),
        }
    }
}

impl<Req: Request> RequestTracker<Req> {
    /// Issues a new request with a session-unique ID and returns that ID.
    pub fn issue(&mut self, kind: Req) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        self.outstanding.push(HostRequest { id, kind });
        id
    }

    /// Returns the requests the host has not yet fulfilled.
    pub fn outstanding(&self) -> &[HostRequest<Req>] {
        &self.outstanding
    }

    /// Records the host's reply to an outstanding request.
    ///
    /// Fails if `id` is not outstanding or if the reply payload does not
    /// match what the request asked for, per [`Request::accepts`].
    pub fn fulfill(&mut self, id: RequestId, reply: Req::Reply) -> Result<(), ProtocolError> {
        let index = self
            .outstanding
            .iter()
            .position(|r| r.id == id)
            .ok_or(ProtocolError::UnknownRequest(id))?;

        if !self.outstanding[index].kind.accepts(&reply) {
            return Err(ProtocolError::ReplyMismatch {
                id,
                expected: self.outstanding[index].kind.expected_reply(),
            });
        }

        self.outstanding.remove(index);
        self.replies.push((id, reply));
        Ok(())
    }

    /// Removes and returns the reply for `id`, if the host has provided one.
    pub fn take_reply(&mut self, id: RequestId) -> Option<Req::Reply> {
        let index = self.replies.iter().position(|(rid, _)| *rid == id)?;
        Some(self.replies.remove(index).1)
    }

    /// Records a reply without the payload validation [`Self::fulfill`]
    /// performs.
    ///
    /// For tests that need to exercise a state machine's own
    /// defense-in-depth check against a mismatched stored reply — one that
    /// should be unreachable through [`Self::fulfill`], but that the state
    /// machine still guards against.
    #[cfg(any(test, feature = "test-util"))]
    pub fn fulfill_unchecked(&mut self, id: RequestId, reply: Req::Reply) {
        self.outstanding.retain(|r| r.id != id);
        self.replies.push((id, reply));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum TestRequest {
        Ping,
        Pong,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum TestReply {
        Ping,
        Pong,
        Failed,
    }

    impl Request for TestRequest {
        type Reply = TestReply;

        fn expected_reply(&self) -> &'static str {
            match self {
                Self::Ping => "Ping",
                Self::Pong => "Pong",
            }
        }

        fn accepts(&self, reply: &Self::Reply) -> bool {
            matches!(
                (self, reply),
                (_, TestReply::Failed)
                    | (Self::Ping, TestReply::Ping)
                    | (Self::Pong, TestReply::Pong)
            )
        }
    }

    #[test]
    fn issues_unique_ids_in_order() {
        let mut tracker = RequestTracker::default();

        let first = tracker.issue(TestRequest::Ping);
        let second = tracker.issue(TestRequest::Pong);

        assert_ne!(first, second);
        assert_eq!(tracker.outstanding().len(), 2);
    }

    #[test]
    fn fulfill_moves_a_request_from_outstanding_to_replies() {
        let mut tracker = RequestTracker::default();
        let id = tracker.issue(TestRequest::Ping);

        tracker.fulfill(id, TestReply::Ping).unwrap();

        assert!(tracker.outstanding().is_empty());
        assert_eq!(tracker.take_reply(id), Some(TestReply::Ping));
        assert_eq!(tracker.take_reply(id), None);
    }

    #[test]
    fn fulfill_rejects_unknown_request_id() {
        let mut tracker: RequestTracker<TestRequest> = RequestTracker::default();

        assert_eq!(
            tracker.fulfill(RequestId(42), TestReply::Ping),
            Err(ProtocolError::UnknownRequest(RequestId(42)))
        );
    }

    #[test]
    fn fulfill_rejects_mismatched_reply_payload() {
        let mut tracker = RequestTracker::default();
        let id = tracker.issue(TestRequest::Ping);

        assert_eq!(
            tracker.fulfill(id, TestReply::Pong),
            Err(ProtocolError::ReplyMismatch {
                id,
                expected: "Ping",
            })
        );

        // The request is still outstanding and can be fulfilled correctly.
        assert_eq!(tracker.outstanding().len(), 1);
        tracker.fulfill(id, TestReply::Ping).unwrap();
    }

    #[test]
    fn any_request_accepts_a_failure_reply() {
        let mut tracker = RequestTracker::default();
        let id = tracker.issue(TestRequest::Pong);

        tracker.fulfill(id, TestReply::Failed).unwrap();
        assert_eq!(tracker.take_reply(id), Some(TestReply::Failed));
    }

    #[test]
    fn fulfill_unchecked_bypasses_payload_validation() {
        let mut tracker = RequestTracker::default();
        let id = tracker.issue(TestRequest::Ping);

        tracker.fulfill_unchecked(id, TestReply::Pong);

        assert!(tracker.outstanding().is_empty());
        assert_eq!(tracker.take_reply(id), Some(TestReply::Pong));
    }
}
