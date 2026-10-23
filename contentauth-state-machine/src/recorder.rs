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

//! Recording a session's conversation with its host, and replaying it.
//!
//! A session never performs I/O: everything it learns about the outside
//! world — asset bytes, the clock, the network, signatures — arrives as a
//! reply to a request. So the sequence of calls a host made, and the replies
//! it gave, is *all* a session's behavior depends on. Record that sequence
//! once (a [`Transcript`]) and the session's run can be printed for a human
//! to read, or [`replay`]ed against a fresh session — on another machine,
//! under a debugger, after a fix — and it will do exactly the same thing,
//! or [`replay`] reports the first place it did not.

use std::{collections::HashSet, fmt, fmt::Write as _};

use crate::{HostRequest, Request, RequestId, Session, Step};

/// What one call to [`Session::advance`] (or [`Session::fulfill`]) returned,
/// as recorded in a [`Transcript`].
///
/// Errors are kept as their [`Display`](fmt::Display) text: what matters for
/// diagnosing and replaying a run is what was reported, and recording the
/// text keeps [`Transcript`] free of any bound on a session's error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome<T> {
    /// The call succeeded with this value.
    Ok(T),

    /// The call failed with an error displaying as this text.
    Err(String),
}

impl<T> Outcome<T> {
    fn of<E: fmt::Display>(result: &Result<T, E>) -> Self
    where
        T: Clone,
    {
        match result {
            Ok(value) => Self::Ok(value.clone()),
            Err(err) => Self::Err(err.to_string()),
        }
    }
}

/// One call a host made on a recorded session.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event<Req: Request> {
    /// The host called [`Session::advance`].
    Advanced {
        /// [`Session::phase`] just before the call.
        phase: String,

        /// What the call returned.
        outcome: Outcome<Step>,

        /// Requests the session issued during the call, in the order
        /// [`Session::outstanding_requests`] lists them.
        issued: Vec<HostRequest<Req>>,
    },

    /// The host called [`Session::fulfill`].
    Fulfilled {
        /// The request being answered.
        id: RequestId,

        /// The reply the host gave.
        reply: Req::Reply,

        /// Whether the session accepted it.
        outcome: Outcome<()>,
    },
}

/// Every call a host made on a [`Recorder`]'s session, in order — enough to
/// read back what happened, or to [`replay`] it.
///
/// Holds every reply in full, asset bytes included, so it grows with the
/// asset, and may hold whatever a host would not want written to a log.
/// Its [`Display`](fmt::Display) form abbreviates long values for reading;
/// record only where the cost and the contents are acceptable.
#[derive(Debug)]
pub struct Transcript<Req: Request> {
    events: Vec<Event<Req>>,
}

// By hand rather than derived: a derive would require only `Req: Clone`,
// not the `Req::Reply: Clone` the replies held here need too.
impl<Req> Clone for Event<Req>
where
    Req: Request + Clone,
    Req::Reply: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Advanced {
                phase,
                outcome,
                issued,
            } => Self::Advanced {
                phase: phase.clone(),
                outcome: outcome.clone(),
                issued: issued.clone(),
            },
            Self::Fulfilled { id, reply, outcome } => Self::Fulfilled {
                id: *id,
                reply: reply.clone(),
                outcome: outcome.clone(),
            },
        }
    }
}

impl<Req> Clone for Transcript<Req>
where
    Req: Request + Clone,
    Req::Reply: Clone,
{
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
        }
    }
}

impl<Req: Request> Default for Transcript<Req> {
    fn default() -> Self {
        Self { events: Vec::new() }
    }
}

impl<Req: Request> Transcript<Req> {
    /// The recorded calls, oldest first.
    pub fn events(&self) -> &[Event<Req>] {
        &self.events
    }
}

/// The longest any one value's debug text is shown in a [`Transcript`].
const SHOWN: usize = 120;

struct BoundedDebug {
    text: String,
    shown: usize,
    truncated: bool,
}

impl fmt::Write for BoundedDebug {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = SHOWN - self.shown;
        if let Some((cut, _)) = value.char_indices().nth(remaining) {
            self.text.push_str(&value[..cut]);
            self.shown += remaining;
            self.truncated = true;
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        self.shown += value.chars().count();
        Ok(())
    }
}

/// Formats at most [`SHOWN`] characters of `value`'s [`Debug`](fmt::Debug) text.
fn abbreviated(value: &dyn fmt::Debug) -> Result<String, fmt::Error> {
    let mut output = BoundedDebug {
        text: String::new(),
        shown: 0,
        truncated: false,
    };
    match write!(&mut output, "{value:?}") {
        Ok(()) => {}
        Err(_) if output.truncated => {}
        Err(err) => return Err(err),
    }
    if output.truncated {
        output.text.push('…');
    }
    Ok(output.text)
}

impl<Req: Request> fmt::Display for Transcript<Req> {
    /// One line per call, for example:
    ///
    /// ```text
    /// #0 advance in Start -> AwaitHost, issued RequestId(0): Ping
    /// #1 fulfill RequestId(0) with Pong
    /// #2 advance in AwaitingPong -> error: no
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, event) in self.events.iter().enumerate() {
            write!(f, "#{index} ")?;
            match event {
                Event::Advanced {
                    phase,
                    outcome,
                    issued,
                } => {
                    write!(f, "advance in {phase} -> ")?;
                    match outcome {
                        Outcome::Ok(step) => write!(f, "{step:?}")?,
                        Outcome::Err(err) => write!(f, "error: {err}")?,
                    }
                    for (n, request) in issued.iter().enumerate() {
                        let lead = if n == 0 { ", issued" } else { ";" };
                        write!(
                            f,
                            "{lead} {:?}: {}",
                            request.id,
                            abbreviated(&request.kind)?
                        )?;
                    }
                }
                Event::Fulfilled { id, reply, outcome } => {
                    write!(f, "fulfill {id:?} with {}", abbreviated(reply)?)?;
                    if let Outcome::Err(err) = outcome {
                        write!(f, " -> rejected: {err}")?;
                    }
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Wraps a session, recording every call its host makes into a
/// [`Transcript`]. Is itself a [`Session`], so a host drives it exactly as it
/// would the session inside — recording is a one-line change to a host.
pub struct Recorder<S: Session> {
    session: S,
    transcript: Transcript<S::Request>,
    seen: HashSet<RequestId>,
}

impl<S: Session> Recorder<S> {
    /// Starts recording `session`.
    pub fn new(session: S) -> Self {
        Self {
            session,
            transcript: Transcript::default(),
            seen: HashSet::new(),
        }
    }

    /// Everything recorded so far — available at any point, including after
    /// the session has failed.
    pub fn transcript(&self) -> &Transcript<S::Request> {
        &self.transcript
    }

    /// The session and its transcript, separately.
    pub fn into_parts(self) -> (S, Transcript<S::Request>) {
        (self.session, self.transcript)
    }
}

impl<S> Session for Recorder<S>
where
    S: Session,
    S::Request: Clone + Send,
    <S::Request as Request>::Reply: Clone + Send,
    S::Error: fmt::Display,
{
    type Error = S::Error;
    type Output = S::Output;
    type Request = S::Request;

    fn advance(&mut self) -> Result<Step, S::Error> {
        let phase = self.session.phase();
        let result = self.session.advance();
        let issued = self
            .session
            .outstanding_requests()
            .iter()
            .filter(|request| self.seen.insert(request.id))
            .cloned()
            .collect();
        self.transcript.events.push(Event::Advanced {
            phase,
            outcome: Outcome::of(&result),
            issued,
        });
        result
    }

    fn outstanding_requests(&self) -> &[HostRequest<S::Request>] {
        self.session.outstanding_requests()
    }

    fn fulfill(
        &mut self,
        id: RequestId,
        reply: <S::Request as Request>::Reply,
    ) -> Result<(), S::Error> {
        let copy = reply.clone();
        let result = self.session.fulfill(id, reply);
        self.transcript.events.push(Event::Fulfilled {
            id,
            reply: copy,
            outcome: Outcome::of(&result),
        });
        result
    }

    fn phase(&self) -> String {
        self.session.phase()
    }

    fn finish(self) -> Result<S::Output, S::Error> {
        self.session.finish()
    }
}

/// Where a [`replay`] first behaved differently from its [`Transcript`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Divergence {
    /// Index into [`Transcript::events`] of the call that went differently.
    pub event: usize,

    /// [`Session::phase`] just before that call, in the replay.
    pub phase: String,

    /// What the transcript recorded.
    pub expected: String,

    /// What the replay did instead.
    pub actual: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "replay diverged at event #{} (in {}): expected {}, got {}",
            self.event, self.phase, self.expected, self.actual
        )
    }
}

impl std::error::Error for Divergence {}

/// Drives `session` — freshly constructed, the same way as the one that was
/// recorded — through the calls in `transcript`, checking at each that it
/// does what the recorded session did: returns the same step or error, and
/// issues the same requests (compared by their [`Debug`](fmt::Debug) text).
///
/// Returns the session as the transcript leaves it, so a caller can go on
/// to inspect it, keep driving it, or [`Session::finish`] it; or the first
/// [`Divergence`]. Since a session's every input arrives as a reply, a
/// faithful replay reproduces a failure exactly — under a debugger, with
/// added logging, or against a fix that should now behave differently.
pub fn replay<S>(mut session: S, transcript: &Transcript<S::Request>) -> Result<S, Divergence>
where
    S: Session,
    <S::Request as Request>::Reply: Clone,
    S::Error: fmt::Display,
{
    let mut seen = HashSet::new();
    for (index, event) in transcript.events.iter().enumerate() {
        let phase = session.phase();
        let diverged = |expected: String, actual: String| Divergence {
            event: index,
            phase: phase.clone(),
            expected,
            actual,
        };
        match event {
            Event::Advanced {
                outcome, issued, ..
            } => {
                let actual = Outcome::of(&session.advance());
                if actual != *outcome {
                    return Err(diverged(
                        format!("advance -> {outcome:?}"),
                        format!("advance -> {actual:?}"),
                    ));
                }
                let fresh: Vec<_> = session
                    .outstanding_requests()
                    .iter()
                    .filter(|request| seen.insert(request.id))
                    .map(|request| format!("{:?}", request))
                    .collect();
                let recorded: Vec<_> = issued
                    .iter()
                    .map(|request| format!("{:?}", request))
                    .collect();
                if fresh != recorded {
                    return Err(diverged(
                        format!("requests {recorded:?}"),
                        format!("requests {fresh:?}"),
                    ));
                }
            }
            Event::Fulfilled { id, reply, outcome } => {
                let actual = Outcome::of(&session.fulfill(*id, reply.clone()));
                if actual != *outcome {
                    return Err(diverged(
                        format!("fulfill {id:?} -> {outcome:?}"),
                        format!("fulfill {id:?} -> {actual:?}"),
                    ));
                }
            }
        }
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::{
        test_session::{Ping, PingSession, Pong},
        ProtocolError,
    };

    /// Drives `session` to the end, answering every ping with `answer`,
    /// and returns how it ended.
    fn drive<S: Session<Request = Ping>>(
        session: &mut S,
        answer: impl Fn(&Ping) -> Pong,
    ) -> Result<Step, S::Error> {
        loop {
            if session.advance()? == Step::Complete {
                return Ok(Step::Complete);
            }
            for request in session.outstanding_requests().to_vec() {
                session.fulfill(request.id, answer(&request.kind))?;
            }
        }
    }

    fn fails_second_ping(request: &Ping) -> Pong {
        match request {
            Ping::Ping(1) => Pong::Failed("timed out"),
            Ping::Ping(_) => Pong::Ok,
        }
    }

    #[test]
    fn a_recorder_is_transparent_to_its_host() {
        let mut recorder = Recorder::new(PingSession::new(2));
        assert_eq!(recorder.phase(), "Start");
        assert_eq!(drive(&mut recorder, |_| Pong::Ok).unwrap(), Step::Complete);
        assert_eq!(recorder.phase(), "Complete");
        assert_eq!(recorder.finish().unwrap(), 2);
    }

    #[test]
    fn a_transcript_records_every_call_and_reads_as_a_log() {
        let mut recorder = Recorder::new(PingSession::new(2));
        let err = drive(&mut recorder, fails_second_ping).unwrap_err();
        assert_eq!(err.to_string(), "no pong: timed out");

        let transcript = recorder.transcript();
        assert_eq!(transcript.events().len(), 4);
        assert!(matches!(
            &transcript.events()[0],
            Event::Advanced { phase, outcome: Outcome::Ok(Step::AwaitHost), issued }
                if phase == "Start" && issued.len() == 2
        ));
        assert!(matches!(
            &transcript.events()[2],
            Event::Fulfilled {
                reply: Pong::Failed("timed out"),
                outcome: Outcome::Ok(()),
                ..
            }
        ));
        assert_eq!(
            transcript.to_string(),
            "#0 advance in Start -> AwaitHost, issued RequestId(0): Ping(0); RequestId(1): Ping(1)\n\
             #1 fulfill RequestId(0) with Ok\n\
             #2 fulfill RequestId(1) with Failed(\"timed out\")\n\
             #3 advance in AwaitingPong -> error: no pong: timed out\n"
        );
    }

    #[test]
    fn a_rejected_reply_is_recorded_as_such() {
        let mut recorder = Recorder::new(PingSession::new(1));
        recorder.advance().unwrap();
        let id = recorder.outstanding_requests()[0].id;
        assert!(recorder.fulfill(id, Pong::Unrelated).is_err());

        let (_, transcript) = recorder.into_parts();
        assert!(transcript
            .to_string()
            .contains("#1 fulfill RequestId(0) with Unrelated -> rejected: "));
    }

    #[test]
    fn long_values_are_abbreviated_for_reading() {
        let long = "x".repeat(500);
        let text = abbreviated(&long).unwrap();
        assert!(text.ends_with('…'), "{text}");
        assert_eq!(text.chars().count(), SHOWN + 1);
        assert_eq!(abbreviated(&"short").unwrap(), "\"short\"");

        let unicode = "😀".repeat(200);
        let text = abbreviated(&unicode).unwrap();
        assert!(text.ends_with('…'), "{text}");
        assert_eq!(text.chars().count(), SHOWN + 1);
    }

    #[test]
    fn abbreviation_stops_debug_formatting_at_the_limit() {
        struct CountingDebug<'a>(&'a std::cell::Cell<usize>);

        impl fmt::Debug for CountingDebug<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..10_000 {
                    self.0.set(self.0.get() + 1);
                    write!(formatter, "x")?;
                }
                Ok(())
            }
        }

        let formatted = std::cell::Cell::new(0);
        let text = abbreviated(&CountingDebug(&formatted)).unwrap();

        assert_eq!(formatted.get(), SHOWN + 1);
        assert_eq!(text, format!("{}…", "x".repeat(SHOWN)));
    }

    #[test]
    fn replaying_a_failure_reproduces_it_exactly() {
        let mut recorder = Recorder::new(PingSession::new(2));
        drive(&mut recorder, fails_second_ping).unwrap_err();
        let (_, transcript) = recorder.into_parts();

        let replayed = replay(PingSession::new(2), &transcript).unwrap();
        assert_eq!(replayed.phase(), "AwaitingPong");
        assert!(matches!(
            replayed.finish(),
            Err(crate::test_session::PingError::Protocol(
                ProtocolError::SessionFailed(_)
            ))
        ));
    }

    #[test]
    fn replaying_a_success_leaves_a_session_ready_to_finish() {
        let mut recorder = Recorder::new(PingSession::new(3));
        drive(&mut recorder, |_| Pong::Ok).unwrap();
        let (_, transcript) = recorder.into_parts();

        let replayed = replay(PingSession::new(3), &transcript).unwrap();
        assert_eq!(replayed.finish().unwrap(), 3);
    }

    #[test]
    fn a_replay_that_issues_different_requests_diverges() {
        let mut recorder = Recorder::new(PingSession::new(2));
        drive(&mut recorder, |_| Pong::Ok).unwrap();
        let (_, transcript) = recorder.into_parts();

        let divergence = replay(PingSession::new(1), &transcript).unwrap_err();
        assert_eq!(divergence.event, 0);
        assert_eq!(divergence.phase, "Start");
        assert!(divergence.expected.contains("Ping(1)"), "{divergence}");
        assert!(!divergence.actual.contains("Ping(1)"), "{divergence}");
        assert!(divergence
            .to_string()
            .starts_with("replay diverged at event #0 (in Start): expected requests"));
    }

    #[test]
    fn a_replay_whose_step_differs_diverges() {
        let mut recorder = Recorder::new(PingSession::new(1));
        drive(&mut recorder, fails_second_ping).unwrap();
        let (_, transcript) = recorder.into_parts();

        // Completed where the recording was still waiting.
        let mut ahead = PingSession::new(1);
        drive(&mut ahead, |_| Pong::Ok).unwrap();
        let divergence = replay(ahead, &transcript).unwrap_err();
        assert_eq!(divergence.event, 0);
        assert_eq!(divergence.expected, "advance -> Ok(AwaitHost)");
        assert_eq!(divergence.actual, "advance -> Ok(Complete)");
    }

    #[test]
    fn a_replay_whose_fulfill_differs_diverges() {
        let mut recorder = Recorder::new(PingSession::new(1));
        recorder.advance().unwrap();
        let id = recorder.outstanding_requests()[0].id;
        recorder.fulfill(id, Pong::Ok).unwrap();
        let (_, transcript) = recorder.into_parts();

        // A session that has already failed rejects every reply.
        let mut failed = PingSession::new(1);
        failed.advance().unwrap();
        let first = failed.outstanding_requests()[0].id;
        failed.fulfill(first, Pong::Failed("x")).unwrap();
        failed.advance().unwrap_err();

        let mut events = transcript.events().to_vec();
        events.remove(0);
        let transcript = Transcript { events };
        let divergence = replay(failed, &transcript).unwrap_err();
        assert_eq!(divergence.event, 0);
        assert!(divergence.expected.ends_with("Ok(())"), "{divergence}");
        assert!(divergence.actual.contains("session failed"), "{divergence}");
    }
}
