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

//! The session interaction contract, and a helper for implementing it.

use crate::{
    error::ProtocolError,
    request::{HostRequest, Request},
    tracker::RequestTracker,
    types::RequestId,
};

/// The observable result of advancing a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Step {
    /// The session is blocked on one or more host requests. Inspect
    /// `outstanding_requests`, service at least one of them, report the
    /// outcome via `fulfill`, and advance again.
    AwaitHost,

    /// The workflow has finished. Consume the session with `finish` to
    /// obtain its result.
    Complete,
}

/// The interaction contract every session built on this engine offers its
/// host.
///
/// This is the "sans-I/O" pattern applied to a state machine: a session runs
/// entirely synchronously and never blocks. When it cannot make further
/// progress on its own, it parks itself and reports the operations
/// ([`Self::outstanding_requests`]) it needs the host to perform. The host
/// services them — concurrently and in any order, if it likes — and reports
/// each outcome via [`Self::fulfill`]. Calling [`Self::advance`] again lets
/// the session consume whatever outcomes have arrived and make further
/// progress.
///
/// ```text
///              ┌────────────────────────────────────────────────┐
///              │                      HOST                      │
///              │   owns files, the network, keys, the clock,    │
///              │            and all async scheduling            │
///              └────┬───────────────────────▲───────────────────┘
///         advance() │                       │ fulfill(id, reply)
///                   ▼                       │
///              ┌────────────────────────────────────────────────┐
///              │                    SESSION                     │
///              │  synchronous state machine + request tracker   │
///              └────────────────────────────────────────────────┘
/// ```
///
/// 1. Create the session (each implementation defines its own constructor
///    and settings).
/// 2. Call [`Self::advance`]. It returns [`Step::AwaitHost`] when blocked on
///    the host, or [`Step::Complete`] once the workflow has finished.
/// 3. While `AwaitHost`: service any subset of [`Self::outstanding_requests`]
///    and report each outcome via [`Self::fulfill`], then call
///    [`Self::advance`] again. Outcomes may be reported in any order.
/// 4. On `Complete`: consume the session with [`Self::finish`] to obtain its
///    result.
///
/// A session is a plain, `Send` value with no interior mutability — it is
/// meant to be handed across threads or tasks, not shared. This trait
/// carries no logic of its own; it exists so that host-side code (a test
/// harness, an FFI dispatcher, a generic driver loop) can be written once
/// against any session built on this engine, whatever workflow it carries
/// out.
pub trait Session: Send {
    /// This session's request vocabulary.
    type Request: Request;

    /// The workflow's product, returned by [`Self::finish`].
    type Output;

    /// This session's error type. Expected to fold in [`ProtocolError`] (for
    /// example, via `#[from]`) alongside whatever domain-specific failures
    /// its own workflow can produce.
    type Error: From<ProtocolError>;

    /// Performs as much synchronous work as possible.
    ///
    /// Returns [`Step::AwaitHost`] if the session is blocked on host
    /// requests, or [`Step::Complete`] once the workflow has finished
    /// (idempotently, on subsequent calls as well).
    fn advance(&mut self) -> Result<Step, Self::Error>;

    /// Returns the requests the host has not yet fulfilled.
    fn outstanding_requests(&self) -> &[HostRequest<Self::Request>];

    /// Reports the outcome of one outstanding request.
    ///
    /// Outcomes may be reported in any order and at any pace; call
    /// [`Self::advance`] afterward to let the session consume them.
    fn fulfill(
        &mut self,
        id: RequestId,
        reply: <Self::Request as Request>::Reply,
    ) -> Result<(), Self::Error>;

    /// Consumes the session and returns the completed result.
    ///
    /// Implementations should fail with [`ProtocolError::SessionNotComplete`]
    /// if the workflow has not reached [`Step::Complete`].
    fn finish(self) -> Result<Self::Output, Self::Error>;
}

/// Tracks whether a session is still running, has finished, or has failed.
///
/// Kept separate from a concrete session's own workflow-phase state (its
/// "where in the workflow am I" enum) so that phase enum never needs
/// `Complete` or `Failed` variants of its own — [`SessionCore`] is the single
/// place that decides whether [`SessionCore::fulfill`] and
/// [`SessionCore::finish_check`] should still succeed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Running,
    Complete,
    Failed,
}

/// The bookkeeping every [`Session`] implementation needs, factored out so a
/// concrete session only has to write the workflow logic itself.
///
/// A concrete session embeds one of these alongside its own workflow-phase
/// state and delegates [`Session::outstanding_requests`] and
/// [`Session::fulfill`] to it directly. Its `advance` method issues requests
/// through [`Self::issue`] and consumes replies through [`Self::take_reply`],
/// and calls [`Self::mark_complete`] or [`Self::mark_failed`] when the
/// workflow reaches a terminal state. Its `finish` method calls
/// [`Self::finish_check`] before handing over its result.
///
/// # Example
///
/// ```
/// use contentauth_state_machine::{
///     HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
/// };
///
/// #[derive(Clone, Debug)]
/// enum PingRequest {
///     Ping,
/// }
///
/// #[derive(Clone, Debug)]
/// enum PingReply {
///     Pong,
///     Failed,
/// }
///
/// impl Request for PingRequest {
///     type Reply = PingReply;
///
///     fn expected_reply(&self) -> &'static str {
///         "Pong"
///     }
///
///     fn accepts(&self, reply: &PingReply) -> bool {
///         matches!(reply, PingReply::Pong | PingReply::Failed)
///     }
/// }
///
/// #[derive(Debug, thiserror::Error)]
/// enum PingError {
///     #[error(transparent)]
///     Protocol(#[from] ProtocolError),
///
///     #[error("the host could not answer the ping")]
///     NoPong,
/// }
///
/// struct PingSession {
///     core: SessionCore<PingRequest>,
///     request: Option<RequestId>,
/// }
///
/// impl PingSession {
///     fn new() -> Self {
///         Self {
///             core: SessionCore::default(),
///             request: None,
///         }
///     }
/// }
///
/// impl Session for PingSession {
///     type Error = PingError;
///     type Output = ();
///     type Request = PingRequest;
///
///     fn advance(&mut self) -> Result<Step, PingError> {
///         let request = match self.request {
///             Some(request) => request,
///             None => {
///                 let request = self.core.issue(PingRequest::Ping);
///                 self.request = Some(request);
///                 return Ok(Step::AwaitHost);
///             }
///         };
///
///         match self.core.take_reply(request) {
///             None => Ok(Step::AwaitHost),
///             Some(PingReply::Pong) => {
///                 self.core.mark_complete();
///                 Ok(Step::Complete)
///             }
///             Some(PingReply::Failed) => {
///                 self.core.mark_failed();
///                 Err(PingError::NoPong)
///             }
///         }
///     }
///
///     fn outstanding_requests(&self) -> &[HostRequest<PingRequest>] {
///         self.core.outstanding_requests()
///     }
///
///     fn fulfill(&mut self, id: RequestId, reply: PingReply) -> Result<(), PingError> {
///         Ok(self.core.fulfill(id, reply)?)
///     }
///
///     fn finish(self) -> Result<(), PingError> {
///         self.core.finish_check()?;
///         Ok(())
///     }
/// }
///
/// let mut session = PingSession::new();
/// assert_eq!(session.advance()?, Step::AwaitHost);
///
/// let id = session.outstanding_requests()[0].id;
/// session.fulfill(id, PingReply::Pong)?;
///
/// assert_eq!(session.advance()?, Step::Complete);
/// session.finish()?;
/// # Ok::<(), PingError>(())
/// ```
#[derive(Debug)]
pub struct SessionCore<Req: Request> {
    tracker: RequestTracker<Req>,
    lifecycle: Lifecycle,
}

impl<Req: Request> Default for SessionCore<Req> {
    fn default() -> Self {
        Self {
            tracker: RequestTracker::default(),
            lifecycle: Lifecycle::Running,
        }
    }
}

impl<Req: Request> SessionCore<Req> {
    /// Issues a new request with a session-unique ID and returns that ID.
    pub fn issue(&mut self, kind: Req) -> RequestId {
        self.tracker.issue(kind)
    }

    /// Removes and returns the reply for `id`, if the host has provided one.
    pub fn take_reply(&mut self, id: RequestId) -> Option<Req::Reply> {
        self.tracker.take_reply(id)
    }

    /// Returns the requests the host has not yet fulfilled.
    pub fn outstanding_requests(&self) -> &[HostRequest<Req>] {
        self.tracker.outstanding()
    }

    /// Reports the outcome of one outstanding request.
    ///
    /// Rejects the reply with [`ProtocolError::SessionComplete`] or
    /// [`ProtocolError::SessionFailed`] once the session has reached a
    /// terminal state, before consulting the underlying
    /// [`RequestTracker`](crate::RequestTracker).
    pub fn fulfill(&mut self, id: RequestId, reply: Req::Reply) -> Result<(), ProtocolError> {
        match self.lifecycle {
            Lifecycle::Complete => return Err(ProtocolError::SessionComplete),
            Lifecycle::Failed => return Err(ProtocolError::SessionFailed),
            Lifecycle::Running => {}
        }

        self.tracker.fulfill(id, reply)
    }

    /// Marks the session complete. After this call, [`Self::fulfill`]
    /// rejects further replies and [`Self::finish_check`] succeeds.
    pub fn mark_complete(&mut self) {
        self.lifecycle = Lifecycle::Complete;
    }

    /// Marks the session failed. After this call, [`Self::fulfill`] and
    /// [`Self::finish_check`] both fail with
    /// [`ProtocolError::SessionFailed`].
    ///
    /// Call this from every error exit of a workflow's `advance` method — the
    /// same "poison on the way out" idiom [`core::mem::replace`] gives a
    /// workflow-phase enum applies here to the session's lifecycle, so a
    /// half-built result is never mistaken for a finished one.
    pub fn mark_failed(&mut self) {
        self.lifecycle = Lifecycle::Failed;
    }

    /// Reports whether the session has reached [`Step::Complete`].
    pub fn is_complete(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Complete)
    }

    /// Reports whether the session has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Failed)
    }

    /// Checks whether a session may hand over its result.
    ///
    /// A concrete session's `finish` method should call this first and
    /// propagate any error before consuming `self` for its own result.
    pub fn finish_check(&self) -> Result<(), ProtocolError> {
        match self.lifecycle {
            Lifecycle::Complete => Ok(()),
            Lifecycle::Failed => Err(ProtocolError::SessionFailed),
            Lifecycle::Running => Err(ProtocolError::SessionNotComplete),
        }
    }

    /// Records a reply without the payload validation [`Self::fulfill`]
    /// performs.
    ///
    /// For a concrete session's own tests that need to exercise its
    /// defense-in-depth check against a mismatched stored reply — one that
    /// should be unreachable through [`Self::fulfill`], but that the session
    /// still guards against.
    #[cfg(any(test, feature = "test-util"))]
    pub fn fulfill_unchecked(&mut self, id: RequestId, reply: Req::Reply) {
        self.tracker.fulfill_unchecked(id, reply);
    }
}
