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

use std::fmt;

use crate::{
    error::{Failure, ProtocolError},
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

/// The host-driven interaction contract, independent of implementation style.
///
/// Implement this with an explicit state machine using [`ManualWorkflowCore`],
/// or with a coroutine-style `async fn` using
/// [`CoroutineWorkflow`](crate::CoroutineWorkflow). Both expose the same
/// synchronous interface; the host owns external operations and scheduling.
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
///              │                    WORKFLOW                    │
///              │  host-driven progress + request/reply tracking │
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
/// A session is a `Send` value meant to be handed across threads or tasks,
/// not accessed concurrently. Implementations may use internal shared
/// state: [`CoroutineWorkflow`](crate::CoroutineWorkflow) uses a synchronized mailbox shared
/// with its future.
///
/// # Not re-entrant; host calls must be serialized
///
/// Sessions are **not re-entrant**. Internal synchronization does not lock
/// the session's API or replace host-side serialization. A host that employs
/// a thread model must ensure that the methods of a session (`advance`, `fulfill`,
/// `outstanding_requests`, `respond`, `finish`) are never called simultaneously from
/// multiple threads, nor re-entered from within a call already in progress
/// on the same session. In safe Rust the borrow checker does much of this
/// for you (`advance` and `fulfill` take `&mut self`, `finish` takes `self`),
/// but it is no substitute for the host's own serialization: wrapping a
/// session in a lock-free shared cell, or reaching it through an FFI or other
/// binding that hands out raw handles, bypasses it. Violating the constraint is
/// likely to cause crashes or unpredictable behavior.
///
/// Calls on *different* sessions may safely run at the same time; only calls
/// on the *same* session must not. Moving a session to another thread
/// between calls is also fine.
///
/// This trait provides a synchronous reply helper so that host-side code (a test
/// harness, an FFI dispatcher, a generic driver loop) can be written once
/// against any session built on this engine, whatever workflow it carries
/// out.
pub trait Workflow: Send {
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

    /// Describes where in its workflow the session is, for diagnostics.
    ///
    /// The name of the session's current workflow phase — for example,
    /// `AwaitingSigningTime`. A session that runs others inside it reports
    /// its own phase followed by theirs, separated by `" > "` (for example,
    /// `Reading > AwaitingOcspResponses`), so the most specific phase is
    /// always last.
    ///
    /// Once the session has failed, this reports the phase it failed *in*,
    /// not whatever internal placeholder it was left in — the same phase
    /// [`ProtocolError::SessionFailed`] names. Meant for logs, error reports,
    /// and transcripts (see [`Recorder`](crate::Recorder)); the wording is
    /// not a stable interface and should not be matched on.
    fn phase(&self) -> String;

    /// Reports the outcome of one outstanding request.
    ///
    /// Outcomes may be reported in any order and at any pace; call
    /// [`Self::advance`] afterward to let the session consume them.
    fn fulfill(
        &mut self,
        id: RequestId,
        reply: <Self::Request as Request>::Reply,
    ) -> Result<(), Self::Error>;

    /// Answers all outstanding requests synchronously, in their listed
    /// order, without cloning requests or allocating a reply batch.
    ///
    /// `answer` borrows each request only until it returns an owned reply;
    /// that borrow ends before [`Self::fulfill`] mutates the session.
    /// Host failures should be represented in the request vocabulary's
    /// reply type, just as with a direct call to `fulfill`.
    ///
    /// Stops at the first `fulfill` error. Earlier replies remain delivered
    /// and later requests have not been serviced. With no outstanding
    /// requests this is a no-op, including on a terminal session.
    ///
    /// Does not call [`Self::advance`]. For asynchronous work, partial
    /// fulfillment, or a different service order, use
    /// [`Self::outstanding_requests`] and [`Self::fulfill`] directly.
    fn respond(
        &mut self,
        mut answer: impl FnMut(&Self::Request) -> <Self::Request as Request>::Reply,
    ) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        while let Some(request) = self.outstanding_requests().first() {
            let id = request.id;
            let reply = answer(&request.kind);
            self.fulfill(id, reply)?;
        }
        Ok(())
    }

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
/// `Complete` or `Failed` variants of its own — [`ManualWorkflowCore`] is the single
/// place that decides whether [`ManualWorkflowCore::fulfill`] and
/// [`ManualWorkflowCore::finish_check`] should still succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Lifecycle {
    Running,
    Complete,
    Failed(Failure),
}

/// Request and lifecycle bookkeeping for a hand-written [`Workflow`].
///
/// This helper does not implement the workflow's state machine: the caller
/// writes its own explicit phases and transitions. For a compiler-generated
/// state machine written with `async`/`.await`, use
/// [`CoroutineWorkflow`](crate::CoroutineWorkflow) instead.
///
/// A concrete session embeds one of these alongside its own workflow-phase
/// state and delegates [`Workflow::outstanding_requests`] and
/// [`Workflow::fulfill`] to it directly. Its `advance` method issues requests
/// through [`Self::issue`] and consumes replies through [`Self::take_reply`],
/// and calls [`Self::mark_complete`] or [`Self::mark_failed`] when the
/// workflow reaches a terminal state. Its `finish` method calls
/// [`Self::finish_check`] before handing over its result.
///
/// # Example
///
/// ```
/// use contentauth_sans_io_core::{
///     HostRequest, ManualWorkflowCore, ProtocolError, Request, RequestId, Step, Workflow,
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
///     core: ManualWorkflowCore<PingRequest>,
///     request: Option<RequestId>,
/// }
///
/// impl PingSession {
///     fn new() -> Self {
///         Self {
///             core: ManualWorkflowCore::default(),
///             request: None,
///         }
///     }
/// }
///
/// impl Workflow for PingSession {
///     type Error = PingError;
///     type Output = ();
///     type Request = PingRequest;
///
///     fn advance(&mut self) -> Result<Step, PingError> {
///         if self.core.is_failed() {
///             return Err(self.core.failed_error().into());
///         }
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
///                 let err = PingError::NoPong;
///                 self.core.mark_failed(self.phase(), &err);
///                 Err(err)
///             }
///         }
///     }
///
///     fn outstanding_requests(&self) -> &[HostRequest<PingRequest>] {
///         self.core.outstanding_requests()
///     }
///
///     fn phase(&self) -> String {
///         if let Some(failure) = self.core.failure() {
///             return failure.phase.clone();
///         }
///         match self.request {
///             None => "Start".into(),
///             Some(_) if self.core.is_complete() => "Complete".into(),
///             Some(_) => "AwaitingPong".into(),
///         }
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
pub struct ManualWorkflowCore<Req: Request> {
    tracker: RequestTracker<Req>,
    lifecycle: Lifecycle,
}

impl<Req: Request> Default for ManualWorkflowCore<Req> {
    fn default() -> Self {
        Self {
            tracker: RequestTracker::default(),
            lifecycle: Lifecycle::Running,
        }
    }
}

impl<Req: Request> ManualWorkflowCore<Req> {
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
    /// [`RequestTracker`].
    pub fn fulfill(&mut self, id: RequestId, reply: Req::Reply) -> Result<(), ProtocolError> {
        match &self.lifecycle {
            Lifecycle::Complete => return Err(ProtocolError::SessionComplete),
            Lifecycle::Failed(failure) => {
                return Err(ProtocolError::SessionFailed(failure.clone()))
            }
            Lifecycle::Running => {}
        }

        self.tracker.fulfill(id, reply)
    }

    /// Marks the session complete. After this call, [`Self::fulfill`]
    /// rejects further replies and [`Self::finish_check`] succeeds.
    pub fn mark_complete(&mut self) {
        self.lifecycle = Lifecycle::Complete;
    }

    /// Marks the session failed in `phase`, because of `cause`. After this
    /// call, [`Self::fulfill`] and [`Self::finish_check`] both fail with
    /// [`ProtocolError::SessionFailed`], which reports `phase` and `cause`.
    ///
    /// Call this from every error exit of a workflow's `advance` method — the
    /// same "poison on the way out" idiom [`core::mem::replace`] gives a
    /// workflow-phase enum applies here to the session's lifecycle, so a
    /// half-built result is never mistaken for a finished one. Pass the
    /// phase the session was in *before* it began the work that failed
    /// (what [`Workflow::phase`] reported then), not the placeholder the
    /// failure left behind, and the error being returned as `cause`.
    ///
    /// Only the first failure is remembered: a later call (for example, an
    /// `advance` on a session already poisoned) does not overwrite where the
    /// session originally went wrong.
    pub fn mark_failed(&mut self, phase: impl Into<String>, cause: &dyn fmt::Display) {
        if !matches!(self.lifecycle, Lifecycle::Failed(_)) {
            self.lifecycle = Lifecycle::Failed(Failure::new(phase, cause));
        }
    }

    /// Where and why the session failed, if it has.
    pub fn failure(&self) -> Option<&Failure> {
        match &self.lifecycle {
            Lifecycle::Failed(failure) => Some(failure),
            _ => None,
        }
    }

    /// The [`ProtocolError::SessionFailed`] to report from a call made after
    /// the session failed, naming where and why it did.
    ///
    /// For a session's own "already poisoned" exits (an `advance` that finds
    /// its workflow phase left behind by an earlier failure, say). If the
    /// session has somehow not been marked failed, the report says so only
    /// generically rather than inventing a cause.
    pub fn failed_error(&self) -> ProtocolError {
        ProtocolError::SessionFailed(self.failure().cloned().unwrap_or_default())
    }

    /// Reports whether the session has reached [`Step::Complete`].
    pub fn is_complete(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Complete)
    }

    /// Reports whether the session has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Failed(_))
    }

    /// Checks whether a session may hand over its result.
    ///
    /// A concrete session's `finish` method should call this first and
    /// propagate any error before consuming `self` for its own result.
    pub fn finish_check(&self) -> Result<(), ProtocolError> {
        match &self.lifecycle {
            Lifecycle::Complete => Ok(()),
            Lifecycle::Failed(failure) => Err(ProtocolError::SessionFailed(failure.clone())),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::test_session::{Ping, PingSession, Pong};

    #[test]
    fn the_first_failure_is_the_one_remembered() {
        let mut core = ManualWorkflowCore::<Ping>::default();
        assert!(core.failure().is_none());

        core.mark_failed("Reading", &"the first thing that went wrong");
        core.mark_failed("Elsewhere", &"a consequence of it");

        let failure = core.failure().unwrap();
        assert_eq!(failure.phase, "Reading");
        assert_eq!(failure.cause, "the first thing that went wrong");
        assert!(core.is_failed());
    }

    #[test]
    fn every_later_call_reports_the_failure() {
        let mut core = ManualWorkflowCore::<Ping>::default();
        let id = core.issue(Ping::Ping(0));
        core.mark_failed("AwaitingPong", &"boom");

        let expected = ProtocolError::SessionFailed(Failure::new("AwaitingPong", &"boom"));
        assert_eq!(core.failed_error(), expected);
        assert_eq!(core.fulfill(id, Pong::Ok).unwrap_err(), expected);
        assert_eq!(core.finish_check().unwrap_err(), expected);
        assert_eq!(
            expected.to_string(),
            "session failed on an earlier call, in AwaitingPong: boom"
        );
    }

    #[test]
    fn failed_error_without_a_failure_reports_one_generically() {
        let core = ManualWorkflowCore::<Ping>::default();
        assert_eq!(
            core.failed_error(),
            ProtocolError::SessionFailed(Failure::default())
        );
        assert_eq!(core.finish_check(), Err(ProtocolError::SessionNotComplete));
    }

    #[test]
    fn unchecked_fulfillment_records_a_reply_without_validation() {
        let mut core = ManualWorkflowCore::<Ping>::default();
        let id = core.issue(Ping::Ping(0));

        core.fulfill_unchecked(id, Pong::Unrelated);

        assert!(core.outstanding_requests().is_empty());
        assert_eq!(core.take_reply(id), Some(Pong::Unrelated));
    }

    #[test]
    fn a_session_reports_its_phase_through_success_and_failure() {
        let mut session = PingSession::new(1);
        assert_eq!(session.phase(), "Start");
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(session.phase(), "AwaitingPong");
        let id = session.outstanding_requests()[0].id;
        session.fulfill(id, Pong::Ok).unwrap();
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.phase(), "Complete");

        let mut session = PingSession::new(1);
        session.advance().unwrap();
        let id = session.outstanding_requests()[0].id;
        session.fulfill(id, Pong::Failed("lost")).unwrap();
        let err = session.advance().unwrap_err();
        assert_eq!(err.to_string(), "no pong: lost");
        assert!(matches!(
            session.advance(),
            Err(crate::test_session::PingError::Protocol(
                ProtocolError::SessionFailed(_)
            ))
        ));
        assert_eq!(session.phase(), "AwaitingPong");
        assert!(matches!(
            session.finish(),
            Err(crate::test_session::PingError::Protocol(
                ProtocolError::SessionFailed(f)
            )) if f.cause == "no pong: lost"
        ));
    }

    // Deliberately not Clone: the helper must borrow the original payload.
    #[derive(Debug)]
    struct TestRequest(Vec<u8>);

    #[derive(Debug, PartialEq)]
    enum TestReply {
        Accepted,
        Failed,
        WrongKind,
    }

    impl Request for TestRequest {
        type Reply = TestReply;

        fn expected_reply(&self) -> &'static str {
            "Accepted or Failed"
        }

        fn accepts(&self, reply: &TestReply) -> bool {
            matches!(reply, TestReply::Accepted | TestReply::Failed)
        }
    }

    #[derive(Default)]
    struct TestSession {
        core: ManualWorkflowCore<TestRequest>,
        advances: usize,
    }

    impl Workflow for TestSession {
        type Error = ProtocolError;
        type Output = ();
        type Request = TestRequest;

        fn advance(&mut self) -> Result<Step, ProtocolError> {
            self.advances += 1;
            Ok(Step::AwaitHost)
        }

        fn outstanding_requests(&self) -> &[HostRequest<TestRequest>] {
            self.core.outstanding_requests()
        }

        fn phase(&self) -> String {
            "Test".into()
        }

        fn fulfill(&mut self, id: RequestId, reply: TestReply) -> Result<(), ProtocolError> {
            self.core.fulfill(id, reply)
        }

        fn finish(self) -> Result<(), ProtocolError> {
            self.core.finish_check()
        }
    }

    #[test]
    fn respond_borrows_original_requests_in_order_and_delivers_each_reply() {
        let mut session = TestSession::default();
        let payload = vec![1, 2, 3];
        let original = payload.as_ptr();
        let first = session.core.issue(TestRequest(payload));
        let second = session.core.issue(TestRequest(vec![4]));
        let mut calls = 0;

        session
            .respond(|request| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(request.0.as_ptr(), original);
                    assert_eq!(request.0, [1, 2, 3]);
                    TestReply::Accepted
                } else {
                    assert_eq!(request.0, [4]);
                    TestReply::Failed
                }
            })
            .unwrap();

        assert_eq!(calls, 2);
        assert_eq!(session.advances, 0);
        assert!(session.outstanding_requests().is_empty());
        assert_eq!(session.core.take_reply(first), Some(TestReply::Accepted));
        assert_eq!(session.core.take_reply(second), Some(TestReply::Failed));
    }

    #[test]
    fn session_trait_methods_expose_phase_and_running_finish_error() {
        let mut session = TestSession::default();

        assert_eq!(session.phase(), "Test");
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(session.advances, 1);
        assert_eq!(session.finish(), Err(ProtocolError::SessionNotComplete));
    }

    #[test]
    fn respond_stops_at_a_rejected_reply_preserving_progress_and_unserviced_requests() {
        let mut session = TestSession::default();
        let first = session.core.issue(TestRequest(vec![1]));
        let second = session.core.issue(TestRequest(vec![2]));
        let third = session.core.issue(TestRequest(vec![3]));
        let mut seen = Vec::new();

        let result = session.respond(|request| {
            seen.push(request.0[0]);
            if request.0[0] == 2 {
                TestReply::WrongKind
            } else {
                TestReply::Accepted
            }
        });

        assert_eq!(
            result,
            Err(ProtocolError::ReplyMismatch {
                id: second,
                expected: "Accepted or Failed",
            })
        );
        assert_eq!(seen, [1, 2]);
        assert_eq!(session.core.take_reply(first), Some(TestReply::Accepted));
        assert_eq!(session.outstanding_requests()[0].id, second);
        assert_eq!(session.outstanding_requests()[1].id, third);

        session.respond(|_| TestReply::Accepted).unwrap();
        assert!(session.outstanding_requests().is_empty());
    }

    #[test]
    fn respond_with_no_requests_is_a_no_op_even_after_completion_or_failure() {
        let mut session = TestSession::default();
        let mut calls = 0;
        for lifecycle in [
            Lifecycle::Running,
            Lifecycle::Complete,
            Lifecycle::Failed(Failure::default()),
        ] {
            session.core.lifecycle = lifecycle.clone();
            session
                .respond(|_| {
                    calls += 1;
                    TestReply::Accepted
                })
                .unwrap();
        }
        assert_eq!(calls, 0);
        assert_eq!(session.advances, 0);
    }

    #[test]
    fn respond_propagates_terminal_state_errors_without_servicing_later_requests() {
        for lifecycle in [Lifecycle::Complete, Lifecycle::Failed(Failure::default())] {
            let mut session = TestSession::default();
            session.core.issue(TestRequest(vec![1]));
            session.core.issue(TestRequest(vec![2]));
            session.core.lifecycle = lifecycle.clone();
            let mut calls = 0;

            let result = session.respond(|_| {
                calls += 1;
                TestReply::Accepted
            });

            let expected = if lifecycle == Lifecycle::Complete {
                ProtocolError::SessionComplete
            } else {
                ProtocolError::SessionFailed(Failure::default())
            };
            assert_eq!(result, Err(expected));
            assert_eq!(calls, 1);
            assert_eq!(session.outstanding_requests().len(), 2);
        }
    }
}
