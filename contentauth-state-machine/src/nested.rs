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

//! Driving one [`Session`] from inside another session's [`Workflow`].
//!
//! A composing session — one that runs other sessions on its host's
//! behalf, answering some of their requests itself and forwarding the
//! rest — would otherwise need a hand-written translation layer: a map
//! from each request it issued to the inner request it stands in for, a
//! phase enum per inner session, and a loop that feeds replies down,
//! advances, and issues whatever comes back up. [`Nested`] is that layer,
//! written once, for a workflow's `async fn`: the inner session becomes a
//! stream of requests the workflow takes one at a time with
//! [`Nested::next`], and answers either itself, with [`Nested::fulfill`],
//! or by handing the [`PendingReply`] of a request it issued to its own
//! host to [`Nested::forward`].
//!
//! [`Workflow`]: crate::Workflow

use std::{
    collections::VecDeque,
    fmt,
    future::{poll_fn, Future},
    pin::Pin,
    task::Poll,
};

use crate::{
    error::ProtocolError,
    request::{HostRequest, Request},
    session::{Session, Step},
    types::RequestId,
    workflow::PendingReply,
};

/// Turns the outer host's reply to a forwarded request into the reply the
/// inner session expects.
type ReplyMap<S, Req> = fn(<Req as Request>::Reply) -> <<S as Session>::Request as Request>::Reply;

/// An inner request forwarded to the outer host, awaiting its reply.
struct Forward<S: Session, Req: Request> {
    inner: RequestId,
    reply: PendingReply<Req>,
    map: ReplyMap<S, Req>,
}

/// A [`Session`] run from inside a [`Workflow`](crate::Workflow)'s `async
/// fn`, whose requests the workflow answers itself or forwards to its own
/// host, issuing requests of type `Req`.
///
/// The inner session may be any [`Session`] — a hand-written state machine
/// or another [`Workflow`](crate::Workflow) — and it is driven exactly as
/// its contract requires; nothing about it needs to know it is nested.
///
/// ```
/// use contentauth_state_machine::{Host, Nested, ProtocolError, Request, Workflow};
///
/// // An inner vocabulary: one question, answered with a number.
/// #[derive(Clone, Debug)]
/// struct Ask;
///
/// impl Request for Ask {
///     type Reply = u32;
///
///     fn expected_reply(&self) -> &'static str {
///         "u32"
///     }
///
///     fn accepts(&self, _: &u32) -> bool {
///         true
///     }
/// }
///
/// // The outer vocabulary speaks in strings.
/// #[derive(Clone, Debug)]
/// struct AskText;
///
/// impl Request for AskText {
///     type Reply = String;
///
///     fn expected_reply(&self) -> &'static str {
///         "String"
///     }
///
///     fn accepts(&self, _: &String) -> bool {
///         true
///     }
/// }
///
/// async fn inner(host: Host<Ask>) -> Result<u32, ProtocolError> {
///     Ok(host.request(Ask).await + 1)
/// }
///
/// // The outer workflow forwards the inner session's question to its own
/// // host, translating the reply on its way back down.
/// async fn outer(host: Host<AskText>) -> Result<u32, ProtocolError> {
///     let mut nested = Nested::new(Workflow::new(inner));
///     while let Some(request) = nested.next().await? {
///         nested.forward(request.id, host.request(AskText), |text: String| {
///             text.parse().unwrap_or(0)
///         });
///     }
///     nested.finish()
/// }
///
/// // The outer host sees only its own vocabulary.
/// use contentauth_state_machine::{Session, Step};
///
/// let mut session = Workflow::new(outer);
/// assert_eq!(session.advance()?, Step::AwaitHost);
/// let id = session.outstanding_requests()[0].id;
/// session.fulfill(id, "41".to_owned())?;
/// assert_eq!(session.advance()?, Step::Complete);
/// assert_eq!(session.finish()?, 42);
/// # Ok::<(), ProtocolError>(())
/// ```
pub struct Nested<S: Session, Req: Request> {
    session: S,

    /// Inner requests already handed out by [`Self::next`] and not yet
    /// answered, as far as this adapter knows.
    taken: Vec<RequestId>,

    /// Inner requests the inner session has issued but [`Self::next`] has
    /// not yet handed out, in the order the inner session issued them.
    queued: VecDeque<HostRequest<S::Request>>,

    forwards: Vec<Forward<S, Req>>,
}

impl<S, Req> Nested<S, Req>
where
    S: Session,
    S::Request: Clone,
    S::Error: From<ProtocolError>,
    Req: Request,
{
    /// Wraps `session`, which has not yet been advanced.
    pub fn new(session: S) -> Self {
        Self {
            session,
            taken: Vec::new(),
            queued: VecDeque::new(),
            forwards: Vec::new(),
        }
    }

    /// The inner session's next request, or `None` once it has completed
    /// (after which [`Self::finish`] hands over its output).
    ///
    /// Every request returned must eventually be answered — with
    /// [`Self::fulfill`] or [`Self::forward`]. Requests may be collected
    /// across calls, but if nothing else could unblock the inner session,
    /// this fails with
    /// [`ProtocolError::UnansweredRequest`] rather than wait forever.
    ///
    /// Waits, returning [`Step::AwaitHost`] from the enclosing workflow's
    /// `advance`, only when the inner session is itself waiting on nothing
    /// but forwarded requests; a reply to any one of them is delivered as
    /// soon as it arrives, so forwarded requests are in flight with the
    /// outer host concurrently, in whatever order it answers them.
    ///
    /// # Errors
    ///
    /// Whatever the inner session's [`Session::advance`] or
    /// [`Session::fulfill`] reports, or [`ProtocolError::UnansweredRequest`].
    pub async fn next(&mut self) -> Result<Option<HostRequest<S::Request>>, S::Error> {
        loop {
            if let Some(request) = self.queued.pop_front() {
                self.taken.push(request.id);
                return Ok(Some(request));
            }

            if self.session.advance()? == Step::Complete {
                return Ok(None);
            }

            let outstanding = self.session.outstanding_requests();
            self.taken
                .retain(|id| outstanding.iter().any(|request| request.id == *id));
            for request in outstanding {
                if !self.taken.contains(&request.id) {
                    self.queued.push_back(request.clone());
                }
            }

            if !self.queued.is_empty() {
                continue;
            }

            if self.forwards.is_empty() {
                let id = self
                    .taken
                    .first()
                    .copied()
                    .ok_or(ProtocolError::WorkflowStalled)?;
                return Err(ProtocolError::UnansweredRequest(id).into());
            }

            for (inner, reply) in self.any_forward_ready().await {
                self.session.fulfill(inner, reply)?;
            }
        }
    }

    /// Answers `id`, a request [`Self::next`] returned, directly.
    ///
    /// # Errors
    ///
    /// Whatever the inner session's [`Session::fulfill`] reports.
    pub fn fulfill(
        &mut self,
        id: RequestId,
        reply: <S::Request as Request>::Reply,
    ) -> Result<(), S::Error> {
        self.session.fulfill(id, reply)
    }

    /// Answers `id`, a request [`Self::next`] returned, with whatever the
    /// outer host replies to `reply`'s request, translated by `map`.
    ///
    /// The reply is delivered to the inner session from within a later
    /// [`Self::next`], as soon as it has arrived.
    pub fn forward(&mut self, id: RequestId, reply: PendingReply<Req>, map: ReplyMap<S, Req>) {
        self.forwards.push(Forward {
            inner: id,
            reply,
            map,
        });
    }

    /// Consumes the adapter and returns the inner session's output, once
    /// [`Self::next`] has returned `None`.
    ///
    /// # Errors
    ///
    /// Whatever the inner session's [`Session::finish`] reports.
    pub fn finish(self) -> Result<S::Output, S::Error> {
        self.session.finish()
    }

    /// The inner session's diagnostic phase, for a composing workflow's
    /// own [`Host::set_phase`](crate::Host::set_phase) report.
    pub fn phase(&self) -> String {
        self.session.phase()
    }

    /// Waits until at least one forwarded request has its reply, then
    /// removes and returns every one that has, translated.
    fn any_forward_ready(
        &mut self,
    ) -> impl Future<Output = Vec<(RequestId, <S::Request as Request>::Reply)>> + '_ {
        poll_fn(|cx| {
            let mut ready = Vec::new();
            let mut index = 0;

            while index < self.forwards.len() {
                match Pin::new(&mut self.forwards[index].reply).poll(cx) {
                    Poll::Ready(reply) => {
                        let forward = self.forwards.remove(index);
                        ready.push((forward.inner, (forward.map)(reply)));
                    }
                    Poll::Pending => index += 1,
                }
            }

            if ready.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(ready)
            }
        })
    }
}

impl<S, Req> fmt::Debug for Nested<S, Req>
where
    S: Session + fmt::Debug,
    Req: Request,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nested")
            .field("session", &self.session)
            .field("taken", &self.taken)
            .field(
                "forwarded",
                &self.forwards.iter().map(|f| f.inner).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{Host, SessionCore, Workflow};

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Ask {
        Number(u32),
        Text,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Answer {
        Number(u32),
        Text(String),
    }

    impl Request for Ask {
        type Reply = Answer;

        fn expected_reply(&self) -> &'static str {
            match self {
                Self::Number(_) => "Number",
                Self::Text => "Text",
            }
        }

        fn accepts(&self, reply: &Answer) -> bool {
            matches!(
                (self, reply),
                (Self::Number(_), Answer::Number(_)) | (Self::Text, Answer::Text(_))
            )
        }
    }

    #[derive(Debug, PartialEq)]
    enum TestError {
        Protocol(ProtocolError),
        Inner(&'static str),
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Protocol(err) => err.fmt(f),
                Self::Inner(message) => f.write_str(message),
            }
        }
    }

    impl From<ProtocolError> for TestError {
        fn from(err: ProtocolError) -> Self {
            Self::Protocol(err)
        }
    }

    type Inner = Workflow<Ask, u32, TestError>;
    type Outer = Workflow<Ask, u32, TestError>;

    fn number(answer: Answer) -> u32 {
        match answer {
            Answer::Number(n) => n,
            Answer::Text(_) => 0,
        }
    }

    fn same(answer: Answer) -> Answer {
        answer
    }

    /// Asks for two numbers at once, and a third once both are in.
    async fn three_numbers(host: Host<Ask>) -> Result<u32, TestError> {
        let a = host.request(Ask::Number(1));
        let b = host.request(Ask::Number(2));
        let (a, b) = (number(a.await), number(b.await));
        let c = number(host.request(Ask::Number(3)).await);
        Ok(a + b + c)
    }

    /// Forwards every inner request to the outer host unchanged.
    async fn forward_all(host: Host<Ask>) -> Result<u32, TestError> {
        let mut nested = Nested::new(Inner::new(three_numbers));
        while let Some(request) = nested.next().await? {
            nested.forward(request.id, host.request(request.kind), same);
        }
        nested.finish()
    }

    fn outstanding(session: &Outer) -> Vec<(RequestId, Ask)> {
        session
            .outstanding_requests()
            .iter()
            .map(|r| (r.id, r.kind.clone()))
            .collect()
    }

    /// Answers `Number(n)` with `n * 10`.
    fn answer(n: &Ask) -> Answer {
        match n {
            Ask::Number(n) => Answer::Number(n * 10),
            Ask::Text => Answer::Text("text".into()),
        }
    }

    #[test]
    fn forwarded_requests_are_in_flight_concurrently_and_answer_in_any_order() {
        let mut session = Outer::new(forward_all);
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);

        let first = outstanding(&session);
        assert_eq!(
            first.iter().map(|(_, k)| k.clone()).collect::<Vec<_>>(),
            [Ask::Number(1), Ask::Number(2)],
            "both inner requests reach the outer host at once, in order"
        );

        // Answer the second first: the inner session still waits for both.
        session.fulfill(first[1].0, answer(&first[1].1)).unwrap();
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(outstanding(&session), [first[0].clone()]);

        session.fulfill(first[0].0, answer(&first[0].1)).unwrap();
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let second = outstanding(&session);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].1, Ask::Number(3));

        session.fulfill(second[0].0, answer(&second[0].1)).unwrap();
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), 60);
    }

    #[test]
    fn advancing_without_replies_reissues_nothing() {
        let mut session = Outer::new(forward_all);
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let first = outstanding(&session);
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        assert_eq!(outstanding(&session), first);
    }

    /// Answers even numbers itself and forwards odd ones, translating
    /// between vocabularies on the way.
    async fn answer_some(host: Host<Ask>) -> Result<u32, TestError> {
        let mut nested = Nested::new(Inner::new(three_numbers));
        while let Some(request) = nested.next().await? {
            match request.kind {
                Ask::Number(n) if n % 2 == 0 => {
                    nested.fulfill(request.id, Answer::Number(n * 100))?
                }
                Ask::Number(_) => {
                    nested.forward(request.id, host.request(Ask::Text), |reply| match reply {
                        Answer::Text(text) => Answer::Number(text.len() as u32),
                        number => number,
                    })
                }
                Ask::Text => nested.fulfill(request.id, Answer::Text(String::new()))?,
            }
        }
        nested.finish()
    }

    #[test]
    fn requests_can_be_answered_internally_or_forwarded() {
        let mut session = Outer::new(answer_some);

        let mut total_host_requests = 0;
        loop {
            match session.advance().unwrap() {
                Step::Complete => break,
                Step::AwaitHost => {
                    for (id, kind) in outstanding(&session) {
                        assert_eq!(kind, Ask::Text, "only odd numbers are forwarded");
                        total_host_requests += 1;
                        session.fulfill(id, Answer::Text("four".into())).unwrap();
                    }
                }
            }
        }

        assert_eq!(total_host_requests, 2);
        assert_eq!(session.finish().unwrap(), 4 + 200 + 4);
    }

    async fn nothing_to_ask(_: Host<Ask>) -> Result<u32, TestError> {
        Ok(7)
    }

    #[test]
    fn an_inner_session_that_never_asks_completes_at_once() {
        let mut session = Outer::new(|_| async {
            let mut nested: Nested<Inner, Ask> = Nested::new(Inner::new(nothing_to_ask));
            assert!(nested.next().await?.is_none());
            nested.finish()
        });
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), 7);
    }

    #[test]
    fn a_request_taken_and_never_answered_is_reported() {
        let mut session = Outer::new(|_| async {
            let mut nested: Nested<Inner, Ask> = Nested::new(Inner::new(three_numbers));
            let first = nested.next().await?.unwrap();
            let _second = nested.next().await?.unwrap();
            nested.fulfill(first.id, Answer::Number(0))?;
            nested.next().await?;
            Ok(0)
        });

        assert_eq!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::UnansweredRequest(
                RequestId(1)
            )))
        );
        assert!(matches!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::SessionFailed(_)))
        ));
    }

    #[test]
    fn an_inner_error_propagates_and_fails_the_outer_session() {
        async fn fails(host: Host<Ask>) -> Result<u32, TestError> {
            host.request(Ask::Number(1)).await;
            Err(TestError::Inner("boom"))
        }

        let mut session = Outer::new(|host| async move {
            let mut nested = Nested::new(Inner::new(fails));
            while let Some(request) = nested.next().await? {
                nested.forward(request.id, host.request(request.kind), same);
            }
            nested.finish()
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let (id, kind) = outstanding(&session).remove(0);
        session.fulfill(id, answer(&kind)).unwrap();
        assert_eq!(session.advance(), Err(TestError::Inner("boom")));
    }

    #[test]
    fn a_forwarded_reply_the_inner_session_rejects_fails_the_outer_one() {
        let mut session = Outer::new(|host| async move {
            let mut nested = Nested::new(Inner::new(three_numbers));
            while let Some(request) = nested.next().await? {
                // The wrong kind of reply for a `Number` request.
                nested.forward(request.id, host.request(request.kind), |_| {
                    Answer::Text(String::new())
                });
            }
            nested.finish()
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let (id, kind) = outstanding(&session).remove(0);
        session.fulfill(id, answer(&kind)).unwrap();
        assert!(matches!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::ReplyMismatch { .. }))
        ));
    }

    #[test]
    fn an_internal_answer_the_inner_session_rejects_is_reported() {
        let mut session = Outer::new(|_| async {
            let mut nested: Nested<Inner, Ask> = Nested::new(Inner::new(three_numbers));
            let request = nested.next().await?.unwrap();
            nested.fulfill(request.id, Answer::Text(String::new()))?;
            Ok(0)
        });

        assert!(matches!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::ReplyMismatch { .. }))
        ));
    }

    /// A hand-written session that waits without asking for anything —
    /// a bug in it, which the adapter must not turn into a hang.
    #[derive(Debug, Default)]
    struct WaitsOnNothing {
        core: SessionCore<Ask>,
    }

    impl Session for WaitsOnNothing {
        type Error = TestError;
        type Output = u32;
        type Request = Ask;

        fn advance(&mut self) -> Result<Step, TestError> {
            Ok(Step::AwaitHost)
        }

        fn outstanding_requests(&self) -> &[HostRequest<Ask>] {
            self.core.outstanding_requests()
        }

        fn phase(&self) -> String {
            "Waiting".into()
        }

        fn fulfill(&mut self, id: RequestId, reply: Answer) -> Result<(), TestError> {
            Ok(self.core.fulfill(id, reply)?)
        }

        fn finish(self) -> Result<u32, TestError> {
            Err(ProtocolError::SessionNotComplete.into())
        }
    }

    #[test]
    fn an_inner_session_waiting_on_nothing_is_reported_as_stalled() {
        let mut session = Outer::new(|_| async {
            let mut nested: Nested<WaitsOnNothing, Ask> = Nested::new(WaitsOnNothing::default());
            nested.next().await?;
            nested.finish()
        });

        assert_eq!(
            session.advance(),
            Err(TestError::Protocol(ProtocolError::WorkflowStalled))
        );
    }

    /// A hand-written inner session — the [`SessionCore`] shape, not a
    /// [`Workflow`] — is consumed exactly the same way.
    #[derive(Debug, Default)]
    struct Doubler {
        core: SessionCore<Ask>,
        asked: Option<RequestId>,
        result: Option<u32>,
    }

    impl Session for Doubler {
        type Error = TestError;
        type Output = u32;
        type Request = Ask;

        fn advance(&mut self) -> Result<Step, TestError> {
            match self.asked {
                None => {
                    self.asked = Some(self.core.issue(Ask::Number(21)));
                    Ok(Step::AwaitHost)
                }
                Some(id) => match self.core.take_reply(id) {
                    Some(reply) => {
                        self.result = Some(number(reply) * 2);
                        self.core.mark_complete();
                        Ok(Step::Complete)
                    }
                    None if self.result.is_some() => Ok(Step::Complete),
                    None => Ok(Step::AwaitHost),
                },
            }
        }

        fn outstanding_requests(&self) -> &[HostRequest<Ask>] {
            self.core.outstanding_requests()
        }

        fn phase(&self) -> String {
            if self.result.is_some() {
                "Complete".into()
            } else {
                "Asking".into()
            }
        }

        fn fulfill(&mut self, id: RequestId, reply: Answer) -> Result<(), TestError> {
            Ok(self.core.fulfill(id, reply)?)
        }

        fn finish(self) -> Result<u32, TestError> {
            self.core.finish_check()?;
            self.result.ok_or(ProtocolError::SessionNotComplete.into())
        }
    }

    #[test]
    fn a_hand_written_inner_session_is_driven_the_same_way() {
        let mut session = Outer::new(|host| async move {
            let mut nested = Nested::new(Doubler::default());
            while let Some(request) = nested.next().await? {
                nested.forward(request.id, host.request(request.kind), same);
            }
            nested.finish()
        });

        assert_eq!(session.advance().unwrap(), Step::AwaitHost);
        let (id, kind) = outstanding(&session).remove(0);
        assert_eq!(kind, Ask::Number(21));
        session.fulfill(id, Answer::Number(21)).unwrap();
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), 42);
    }

    #[test]
    fn debug_shows_the_inner_session_and_forwarded_requests() {
        let nested: Nested<Doubler, Ask> = Nested::new(Doubler::default());
        let text = format!("{nested:?}");
        assert!(text.contains("Nested"));
        assert!(text.contains("Doubler"));
        assert!(text.contains("forwarded"));
    }

    #[test]
    fn phase_reports_the_inner_workflows_current_stage() {
        let inner = Inner::new(|host| async move {
            host.set_phase("Asking");
            Ok(number(host.request(Ask::Number(1)).await))
        });
        let mut nested: Nested<Inner, Ask> = Nested::new(inner);
        assert_eq!(nested.phase(), "Start");

        {
            let mut next = std::pin::pin!(nested.next());
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                next.as_mut().poll(&mut context),
                Poll::Ready(Ok(Some(_)))
            ));
        }
        assert_eq!(nested.phase(), "Asking");
    }
}
