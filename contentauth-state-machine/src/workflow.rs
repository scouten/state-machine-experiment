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

//! Writing a session's workflow as an `async fn`, so the compiler — not
//! a hand-written phase enum — generates its state machine.
//!
//! [`Workflow`] is a [`Session`] like any other: the host sees the same
//! `advance` / `outstanding_requests` / `fulfill` / `finish` contract, the
//! same request vocabulary, and the same [`RequestId`]s. Only the inside
//! differs. Instead of one enum variant per point where the workflow waits
//! on its host, each carrying every local that must survive the wait, the
//! workflow is an ordinary `async fn` that asks its [`Host`] for what it
//! needs and `.await`s the reply. Locals, loops, early returns via `?`,
//! borrows held across a wait, and calls into other `async fn`s (sub-
//! workflows) all work as they do in any Rust function.
//!
//! None of this needs an async runtime. A [`PendingReply`] is ready exactly
//! when the host has fulfilled its request, so there is never anything to
//! wake: [`Session::advance`] polls the workflow's future once, with a
//! no-op waker, and the future runs until every branch is waiting on the
//! host — which is precisely [`Step::AwaitHost`].
//!
//! A workflow must only `.await` [`PendingReply`]s (or futures built from
//! them, such as another workflow `async fn`). A future that waits on
//! anything else — a timer, a channel, an async runtime's I/O — would
//! never be woken, and [`Session::advance`] reports it as
//! [`ProtocolError::WorkflowStalled`] rather than hang.

use std::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use crate::{
    error::ProtocolError,
    request::{HostRequest, Request},
    session::{Session, Step},
    types::RequestId,
};

/// Requests issued and replies received, shared between a [`Workflow`] and
/// the [`Host`] handle its future holds.
///
/// Kept apart from [`Workflow::outstanding`] so that issuing a request
/// never needs the session itself: a request issued from inside the future
/// lands here, and the session moves it into its own outstanding list —
/// which it can then lend out by reference — once the poll returns.
struct Mailbox<Req: Request> {
    next_id: u64,
    issued: Vec<HostRequest<Req>>,
    replies: Vec<(RequestId, Req::Reply)>,
}

type Shared<Req> = Arc<Mutex<Mailbox<Req>>>;

/// Locks the mailbox. Poisoning cannot leave it inconsistent — every
/// critical section is a single push, pop, or increment — so a poisoned
/// lock is taken as is.
fn lock<Req: Request>(shared: &Shared<Req>) -> MutexGuard<'_, Mailbox<Req>> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The handle a workflow's `async fn` uses to ask its host for something.
///
/// Cheap to clone; every clone issues into the same session.
pub struct Host<Req: Request> {
    shared: Shared<Req>,
}

impl<Req: Request> Clone for Host<Req> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Req: Request> fmt::Debug for Host<Req> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl<Req: Request> Host<Req> {
    /// Issues a request and returns a future that resolves to the host's
    /// reply.
    ///
    /// The request is issued immediately, not when the future is first
    /// polled: issuing several before awaiting any of them is how a
    /// workflow puts several requests in front of its host at once.
    pub fn request(&self, kind: Req) -> PendingReply<Req> {
        let mut mailbox = lock(&self.shared);
        let id = RequestId(mailbox.next_id);
        mailbox.next_id += 1;
        mailbox.issued.push(HostRequest { id, kind });

        PendingReply {
            id,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// A request a workflow has issued, as a future that resolves to the
/// host's reply once [`Session::fulfill`] has delivered it.
///
/// The reply has already passed [`Request::accepts`] for this request by
/// the time it resolves.
#[must_use = "a request whose reply is never awaited is still sent to the host"]
pub struct PendingReply<Req: Request> {
    id: RequestId,
    shared: Shared<Req>,
}

impl<Req: Request> PendingReply<Req> {
    /// The ID the host will see this request under — for a workflow's own
    /// error reports.
    pub fn id(&self) -> RequestId {
        self.id
    }
}

impl<Req: Request> fmt::Debug for PendingReply<Req> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingReply")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<Req: Request> Future for PendingReply<Req> {
    type Output = Req::Reply;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Req::Reply> {
        let mut mailbox = lock(&self.shared);
        match mailbox.replies.iter().position(|(id, _)| *id == self.id) {
            Some(index) => Poll::Ready(mailbox.replies.remove(index).1),
            None => Poll::Pending,
        }
    }
}

type BoxedWorkflow<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

enum State<T, E> {
    Running(BoxedWorkflow<T, E>),
    Complete(T),
    Failed,
}

/// A [`Session`] whose workflow is an `async fn` rather than a hand-written
/// state machine.
///
/// A concrete session wraps one of these and delegates the four
/// [`Session`] methods to it:
///
/// ```
/// use contentauth_state_machine::{Host, ProtocolError, Request, Session, Step, Workflow};
///
/// #[derive(Debug)]
/// enum Ask {
///     Double(u32),
/// }
///
/// #[derive(Debug)]
/// enum Answer {
///     Doubled(u32),
/// }
///
/// impl Request for Ask {
///     type Reply = Answer;
///
///     fn expected_reply(&self) -> &'static str {
///         "Doubled"
///     }
///
///     fn accepts(&self, _: &Answer) -> bool {
///         true
///     }
/// }
///
/// // The whole workflow: ask for two numbers to be doubled at once, then
/// // add the results. No phase enum, no `take_reply`.
/// async fn sum_of_doubles(host: Host<Ask>, a: u32, b: u32) -> Result<u32, ProtocolError> {
///     let first = host.request(Ask::Double(a));
///     let second = host.request(Ask::Double(b));
///     let (Answer::Doubled(x), Answer::Doubled(y)) = (first.await, second.await);
///     Ok(x + y)
/// }
///
/// let mut session = Workflow::new(|host| sum_of_doubles(host, 2, 5));
/// assert_eq!(session.advance()?, Step::AwaitHost);
///
/// // Both requests are outstanding; answer them in reverse.
/// for request in session
///     .outstanding_requests()
///     .iter()
///     .rev()
///     .map(|r| {
///         (
///             r.id,
///             match r.kind {
///                 Ask::Double(n) => n * 2,
///             },
///         )
///     })
///     .collect::<Vec<_>>()
/// {
///     session.fulfill(request.0, Answer::Doubled(request.1))?;
/// }
///
/// assert_eq!(session.advance()?, Step::Complete);
/// assert_eq!(session.finish()?, 14);
/// # Ok::<(), ProtocolError>(())
/// ```
pub struct Workflow<Req: Request, T, E> {
    shared: Shared<Req>,
    outstanding: Vec<HostRequest<Req>>,
    state: State<T, E>,
}

impl<Req, T, E> Workflow<Req, T, E>
where
    Req: Request + Send + 'static,
    Req::Reply: Send,
{
    /// Creates a session that runs the workflow `start` returns.
    ///
    /// `start` is called at once, with the [`Host`] the workflow asks
    /// through; the future it returns is not polled until the first
    /// [`Session::advance`], so an `async fn` workflow does no work — and
    /// reports no error — before then.
    pub fn new<F, Fut>(start: F) -> Self
    where
        F: FnOnce(Host<Req>) -> Fut,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
    {
        let shared = Arc::new(Mutex::new(Mailbox {
            next_id: 0,
            issued: Vec::new(),
            replies: Vec::new(),
        }));

        let future = start(Host {
            shared: Arc::clone(&shared),
        });

        let mut workflow = Self {
            shared,
            outstanding: Vec::new(),
            state: State::Running(Box::pin(future)),
        };
        workflow.collect_issued();
        workflow
    }

    /// Records a reply without the payload validation [`Session::fulfill`]
    /// performs, for a concrete session's tests of its own
    /// defense-in-depth check against a reply of the wrong kind.
    #[cfg(any(test, feature = "test-util"))]
    pub fn fulfill_unchecked(&mut self, id: RequestId, reply: Req::Reply) {
        self.outstanding.retain(|r| r.id != id);
        lock(&self.shared).replies.push((id, reply));
    }

    /// Moves requests the future issued into the list the host sees.
    fn collect_issued(&mut self) {
        let issued = mem::take(&mut lock(&self.shared).issued);
        self.outstanding.extend(issued);
    }
}

impl<Req, T, E> Session for Workflow<Req, T, E>
where
    Req: Request + Send + 'static,
    Req::Reply: Send,
    T: Send,
    E: From<ProtocolError>,
{
    type Error = E;
    type Output = T;
    type Request = Req;

    /// Runs the workflow until it finishes or every branch of it is
    /// waiting on the host.
    ///
    /// An error from the workflow is returned once, and poisons the
    /// session: every later call reports [`ProtocolError::SessionFailed`].
    fn advance(&mut self) -> Result<Step, E> {
        let future = match &mut self.state {
            State::Running(future) => future,
            State::Complete(_) => return Ok(Step::Complete),
            State::Failed => return Err(ProtocolError::SessionFailed.into()),
        };

        let poll = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        self.collect_issued();

        match poll {
            Poll::Ready(Ok(output)) => {
                self.state = State::Complete(output);
                Ok(Step::Complete)
            }

            Poll::Ready(Err(err)) => {
                self.state = State::Failed;
                Err(err)
            }

            // Waiting, with nothing the host could answer to unblock it.
            Poll::Pending if self.outstanding.is_empty() => {
                self.state = State::Failed;
                Err(ProtocolError::WorkflowStalled.into())
            }

            Poll::Pending => Ok(Step::AwaitHost),
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<Req>] {
        &self.outstanding
    }

    /// Delivers a reply, after the same checks
    /// [`SessionCore::fulfill`](crate::SessionCore::fulfill) makes.
    fn fulfill(&mut self, id: RequestId, reply: Req::Reply) -> Result<(), E> {
        match self.state {
            State::Running(_) => {}
            State::Complete(_) => return Err(ProtocolError::SessionComplete.into()),
            State::Failed => return Err(ProtocolError::SessionFailed.into()),
        }

        let index = self
            .outstanding
            .iter()
            .position(|r| r.id == id)
            .ok_or(ProtocolError::UnknownRequest(id))?;

        if !self.outstanding[index].kind.accepts(&reply) {
            return Err(ProtocolError::ReplyMismatch {
                id,
                expected: self.outstanding[index].kind.expected_reply(),
            }
            .into());
        }

        self.outstanding.remove(index);
        lock(&self.shared).replies.push((id, reply));
        Ok(())
    }

    fn finish(self) -> Result<T, E> {
        match self.state {
            State::Complete(output) => Ok(output),
            State::Running(_) => Err(ProtocolError::SessionNotComplete.into()),
            State::Failed => Err(ProtocolError::SessionFailed.into()),
        }
    }
}

impl<Req: Request, T, E> fmt::Debug for Workflow<Req, T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.state {
            State::Running(_) => "Running",
            State::Complete(_) => "Complete",
            State::Failed => "Failed",
        };

        f.debug_struct("Workflow")
            .field("state", &state)
            .field("outstanding", &self.outstanding)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::future::pending;

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Ask {
        Number,
        Text,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Answer {
        Number(u32),
        Text(String),
        Failed,
    }

    impl Request for Ask {
        type Reply = Answer;

        fn expected_reply(&self) -> &'static str {
            match self {
                Self::Number => "Number",
                Self::Text => "Text",
            }
        }

        fn accepts(&self, reply: &Answer) -> bool {
            matches!(
                (self, reply),
                (_, Answer::Failed)
                    | (Self::Number, Answer::Number(_))
                    | (Self::Text, Answer::Text(_))
            )
        }
    }

    #[derive(Debug, PartialEq)]
    enum TestError {
        Protocol(ProtocolError),
        HostFailed,
    }

    impl From<ProtocolError> for TestError {
        fn from(err: ProtocolError) -> Self {
            Self::Protocol(err)
        }
    }

    type TestWorkflow<T> = Workflow<Ask, T, TestError>;

    async fn number(host: &Host<Ask>) -> Result<u32, TestError> {
        match host.request(Ask::Number).await {
            Answer::Number(n) => Ok(n),
            _ => Err(TestError::HostFailed),
        }
    }

    /// Asks for `count` numbers one after another and sums them.
    async fn sum_sequentially(host: Host<Ask>, count: usize) -> Result<u32, TestError> {
        let mut total = 0;
        for _ in 0..count {
            total += number(&host).await?;
        }
        Ok(total)
    }

    fn only_outstanding(session: &TestWorkflow<impl Send>) -> RequestId {
        assert_eq!(session.outstanding_requests().len(), 1);
        session.outstanding_requests()[0].id
    }

    #[test]
    fn a_sequential_workflow_asks_one_thing_at_a_time() {
        let mut session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 3));
        assert!(
            session.outstanding_requests().is_empty(),
            "nothing runs before the first advance"
        );

        for n in [1, 2, 3] {
            assert_eq!(session.advance().unwrap(), Step::AwaitHost);
            let id = only_outstanding(&session);
            session.fulfill(id, Answer::Number(n)).unwrap();
        }

        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.advance().unwrap(), Step::Complete, "idempotently");
        assert_eq!(session.finish().unwrap(), 6);
    }

    #[test]
    fn advancing_without_a_reply_waits() {
        let mut session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 1));

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let id = only_outstanding(&session);
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(
            only_outstanding(&session),
            id,
            "the same request, not a new one"
        );
    }

    #[test]
    fn requests_issued_together_are_outstanding_together_and_answerable_in_any_order() {
        let mut session: TestWorkflow<(u32, String)> = Workflow::new(|host| async move {
            let number = host.request(Ask::Number);
            let text = host.request(Ask::Text);
            match (text.await, number.await) {
                (Answer::Text(t), Answer::Number(n)) => Ok((n, t)),
                _ => Err(TestError::HostFailed),
            }
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let ids: Vec<_> = session
            .outstanding_requests()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids.len(), 2);

        // The number first, though the workflow awaits the text first.
        session.fulfill(ids[0], Answer::Number(7)).unwrap();
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        session.fulfill(ids[1], Answer::Text("x".into())).unwrap();

        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), (7, "x".to_string()));
    }

    #[test]
    fn a_request_issued_by_the_start_closure_is_outstanding_at_once() {
        let session: TestWorkflow<Answer> = Workflow::new(|host| {
            let reply = host.request(Ask::Text);
            async move { Ok(reply.await) }
        });

        assert_eq!(session.outstanding_requests()[0].kind, Ask::Text);
    }

    #[test]
    fn a_workflow_error_is_returned_once_and_poisons_the_session() {
        let mut session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 2));

        session.advance().unwrap();
        let id = only_outstanding(&session);
        session.fulfill(id, Answer::Failed).unwrap();

        assert_eq!(session.advance(), Err(TestError::HostFailed));
        assert_eq!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::SessionFailed))
        );
        assert_eq!(
            session.fulfill(id, Answer::Number(1)),
            Err(TestError::Protocol(ProtocolError::SessionFailed))
        );
        assert_eq!(
            session.finish(),
            Err(TestError::Protocol(ProtocolError::SessionFailed))
        );
    }

    #[test]
    fn fulfill_rejects_an_unknown_id_and_a_reply_of_the_wrong_kind() {
        let mut session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 1));
        session.advance().unwrap();
        let id = only_outstanding(&session);

        assert_eq!(
            session.fulfill(RequestId(99), Answer::Number(1)),
            Err(TestError::Protocol(ProtocolError::UnknownRequest(
                RequestId(99)
            )))
        );
        assert_eq!(
            session.fulfill(id, Answer::Text("no".into())),
            Err(TestError::Protocol(ProtocolError::ReplyMismatch {
                id,
                expected: "Number"
            }))
        );

        // Still outstanding, and answerable properly.
        session.fulfill(id, Answer::Number(4)).unwrap();
        assert_eq!(
            session.fulfill(id, Answer::Number(4)),
            Err(TestError::Protocol(ProtocolError::UnknownRequest(id))),
            "not twice"
        );
        assert_eq!(session.advance().unwrap(), Step::Complete);
    }

    #[test]
    fn a_finished_session_refuses_further_replies() {
        let mut session: TestWorkflow<u32> = Workflow::new(|_| async { Ok(1) });

        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(
            session.fulfill(RequestId(0), Answer::Number(1)),
            Err(TestError::Protocol(ProtocolError::SessionComplete))
        );
    }

    #[test]
    fn finishing_early_is_refused() {
        let session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 1));

        assert_eq!(
            session.finish(),
            Err(TestError::Protocol(ProtocolError::SessionNotComplete))
        );
    }

    #[test]
    fn waiting_on_something_the_host_cannot_answer_is_reported_not_hung() {
        let mut session: TestWorkflow<u32> = Workflow::new(|_| pending());

        assert_eq!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::WorkflowStalled))
        );
        assert_eq!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::SessionFailed))
        );
    }

    #[test]
    fn fulfill_unchecked_bypasses_payload_validation() {
        let mut session: TestWorkflow<Answer> =
            Workflow::new(|host| async move { Ok(host.request(Ask::Number).await) });
        session.advance().unwrap();
        let id = only_outstanding(&session);

        session.fulfill_unchecked(id, Answer::Text("wrong".into()));

        assert!(session.outstanding_requests().is_empty());
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), Answer::Text("wrong".into()));
    }

    #[test]
    fn debug_output_names_the_state_and_what_is_outstanding() {
        let mut session: TestWorkflow<u32> = Workflow::new(|host| sum_sequentially(host, 1));
        session.advance().unwrap();

        let host = Host::<Ask> {
            shared: Arc::clone(&session.shared),
        };
        let pending = host.clone().request(Ask::Text);

        assert!(format!("{session:?}").contains("Running"));
        assert!(format!("{session:?}").contains("Number"));
        assert_eq!(format!("{host:?}"), "Host { .. }");
        assert_eq!(
            format!("{pending:?}"),
            format!("PendingReply {{ id: {:?}, .. }}", pending.id())
        );

        let mut done: TestWorkflow<u32> = Workflow::new(|_| async { Ok(0) });
        done.advance().unwrap();
        assert!(format!("{done:?}").contains("Complete"));

        let mut failed: TestWorkflow<u32> = Workflow::new(|_| pending_forever());
        let _ = failed.advance();
        assert!(format!("{failed:?}").contains("Failed"));
    }

    async fn pending_forever() -> Result<u32, TestError> {
        pending().await
    }
}
