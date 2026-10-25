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

//! Model-based harnesses for the engine's session machinery, shared by the
//! `proptest` suite (`tests/model_based.rs`) and the `cargo-fuzz` targets
//! (`fuzz/`), which both `#[path]`-include this file.
//!
//! Each harness takes a *script* — a sequence of host operations, including
//! deliberately illegal ones (unknown IDs, wrong payloads, driving a session
//! past its terminal state) — runs it against the real engine, runs the same
//! script against a deliberately naive reference model written from the
//! documented contract, and asserts the two agree after every step. Any
//! panic or disagreement is a finding.
//!
//! The harnesses are pure functions of their script, so a failing input
//! (from proptest's shrinker or libFuzzer's corpus) replays identically.
//!
//! The model records the contract as the engine currently implements it;
//! notably, the lifecycle is "last `mark_*` call wins", so a workflow that
//! marks a session failed and then complete is not stopped by the engine.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use contentauth_state_machine::{
    Failure, HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
};

/// A two-kind request vocabulary: enough to exercise reply-shape
/// validation, with a universal `Failed` reply as the real vocabularies have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    A,
    B,
}

/// Replies to [`Kind`]: each kind's own, plus the universal failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply {
    A,
    B,
    Failed,
}

impl Request for Kind {
    type Reply = Reply;

    fn expected_reply(&self) -> &'static str {
        match self {
            Kind::A => "A",
            Kind::B => "B",
        }
    }

    fn accepts(&self, reply: &Reply) -> bool {
        matches!(
            (self, reply),
            (_, Reply::Failed) | (Kind::A, Reply::A) | (Kind::B, Reply::B)
        )
    }
}

/// `RequestId` is opaque, so a harness cannot forge one. This mints them
/// from a throwaway core instead: the n-th ID it hands out is numerically
/// the n-th ID any fresh session hands out, which is exactly what a host
/// confusing two sessions' IDs would present.
pub struct Ids {
    mint: SessionCore<Kind>,
    pool: Vec<RequestId>,
}

/// The largest ID number a script can name by [`Target::Raw`].
const RAW_RANGE: u64 = 64;

fn core_failure() -> Failure {
    Failure::new("Model", &"requested failure")
}

impl Ids {
    pub fn new() -> Self {
        Self {
            mint: SessionCore::default(),
            pool: Vec::new(),
        }
    }

    /// The ID numbered `n`.
    pub fn id(&mut self, n: u64) -> RequestId {
        while self.pool.len() as u64 <= n {
            self.pool.push(self.mint.issue(Kind::A));
        }
        self.pool[n as usize]
    }
}

/// The number of an ID, recovered from its `Display` form (`request #N`).
pub fn number(id: RequestId) -> u64 {
    id.to_string()
        .trim_start_matches("request #")
        .parse()
        .unwrap()
}

/// How a script names a request ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// The n-th ID the session has handed out so far (wrapping), or an
    /// arbitrary one if none has been issued yet.
    Issued(u8),

    /// The ID with this number (modulo a small range) as some *other*
    /// session minted it: unknown to this session unless it happens to have
    /// issued that many.
    Raw(u64),
}

/// A byte cursor that yields zeros once exhausted, so any byte string
/// decodes to a script and truncation never fails.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    fn kind(&mut self) -> Kind {
        if self.byte().is_multiple_of(2) {
            Kind::A
        } else {
            Kind::B
        }
    }

    fn reply(&mut self) -> Reply {
        match self.byte() % 3 {
            0 => Reply::A,
            1 => Reply::B,
            _ => Reply::Failed,
        }
    }

    fn target(&mut self) -> Target {
        if self.byte().is_multiple_of(4) {
            let mut raw = [0u8; 8];
            raw.iter_mut().for_each(|b| *b = self.byte());
            Target::Raw(u64::from_le_bytes(raw))
        } else {
            Target::Issued(self.byte())
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------
// Harness 1: `SessionCore` driven directly, as a workflow would.
// ---------------------------------------------------------------------

/// One call on a [`SessionCore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreOp {
    Issue(Kind),
    Fulfill(Target, Reply),
    TakeReply(Target),
    MarkComplete,
    MarkFailed,
    FinishCheck,
    Inspect,
}

/// Decodes arbitrary bytes into a script (the `cargo-fuzz` entry point).
pub fn decode_core(bytes: &[u8]) -> Vec<CoreOp> {
    let mut cur = Cursor(bytes);
    let mut ops = Vec::new();
    while !cur.is_empty() {
        ops.push(match cur.byte() % 7 {
            0 | 1 => CoreOp::Issue(cur.kind()),
            2 | 3 => {
                let target = cur.target();
                CoreOp::Fulfill(target, cur.reply())
            }
            4 => CoreOp::TakeReply(cur.target()),
            5 => match cur.byte() % 3 {
                0 => CoreOp::MarkComplete,
                1 => CoreOp::MarkFailed,
                _ => CoreOp::FinishCheck,
            },
            _ => CoreOp::Inspect,
        });
    }
    ops
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Life {
    Running,
    Complete,
    Failed,
}

/// The reference model of a `SessionCore`: plain vectors and linear scans.
#[derive(Default)]
struct CoreModel {
    next: u64,
    outstanding: Vec<(u64, Kind)>,
    replies: Vec<(u64, Reply)>,
    issued: Vec<u64>,
    life: Option<Life>,
}

impl CoreModel {
    fn life(&self) -> Life {
        self.life.unwrap_or(Life::Running)
    }

    fn resolve(&self, target: Target) -> u64 {
        match target {
            Target::Issued(n) if !self.issued.is_empty() => {
                self.issued[n as usize % self.issued.len()]
            }
            Target::Issued(n) => u64::from(n),
            Target::Raw(raw) => raw % RAW_RANGE,
        }
    }
}

/// Runs `ops` against a real [`SessionCore`] and the reference model,
/// asserting they agree after every operation.
pub fn run_core(ops: &[CoreOp]) {
    let mut core: SessionCore<Kind> = SessionCore::default();
    let mut model = CoreModel::default();
    let mut ids = Ids::new();

    for op in ops {
        match *op {
            CoreOp::Issue(kind) => {
                let id = core.issue(kind);
                // IDs are session-unique and handed out in sequence.
                assert_eq!(id, ids.id(model.next));
                model.outstanding.push((model.next, kind));
                model.issued.push(model.next);
                model.next += 1;
            }

            CoreOp::Fulfill(target, reply) => {
                let raw = model.resolve(target);
                let expected = match model.life() {
                    Life::Complete => Err(ProtocolError::SessionComplete),
                    Life::Failed => Err(ProtocolError::SessionFailed(core_failure())),
                    Life::Running => match model.outstanding.iter().position(|(i, _)| *i == raw) {
                        None => Err(ProtocolError::UnknownRequest(ids.id(raw))),
                        Some(pos) if !model.outstanding[pos].1.accepts(&reply) => {
                            Err(ProtocolError::ReplyMismatch {
                                id: ids.id(raw),
                                expected: model.outstanding[pos].1.expected_reply(),
                            })
                        }
                        Some(pos) => {
                            model.outstanding.remove(pos);
                            model.replies.push((raw, reply));
                            Ok(())
                        }
                    },
                };
                assert_eq!(core.fulfill(ids.id(raw), reply), expected);
            }

            CoreOp::TakeReply(target) => {
                let raw = model.resolve(target);
                let expected = model
                    .replies
                    .iter()
                    .position(|(i, _)| *i == raw)
                    .map(|pos| model.replies.remove(pos).1);
                assert_eq!(core.take_reply(ids.id(raw)), expected);
            }

            CoreOp::MarkComplete => {
                core.mark_complete();
                model.life = Some(Life::Complete);
            }

            CoreOp::MarkFailed => {
                core.mark_failed("Model", &"requested failure");
                model.life = Some(Life::Failed);
            }

            CoreOp::FinishCheck => {
                let expected = match model.life() {
                    Life::Complete => Ok(()),
                    Life::Failed => Err(ProtocolError::SessionFailed(core_failure())),
                    Life::Running => Err(ProtocolError::SessionNotComplete),
                };
                assert_eq!(core.finish_check(), expected);
            }

            CoreOp::Inspect => {}
        }

        // Invariants that must hold between every pair of calls.
        let seen: Vec<(u64, Kind)> = core
            .outstanding_requests()
            .iter()
            .map(|r| (number(r.id), r.kind))
            .collect();
        assert_eq!(seen, model.outstanding, "outstanding set diverged");
        assert!(
            seen.windows(2).all(|w| w[0].0 < w[1].0),
            "outstanding IDs must stay in issue order"
        );
        assert_eq!(core.is_complete(), model.life() == Life::Complete);
        assert_eq!(core.is_failed(), model.life() == Life::Failed);
    }

    // Everything the model says is parked must still be retrievable, once.
    for (id, reply) in std::mem::take(&mut model.replies) {
        assert_eq!(core.take_reply(ids.id(id)), Some(reply));
        assert_eq!(core.take_reply(ids.id(id)), None);
    }
}

// ---------------------------------------------------------------------
// Harness 2: a whole `Session` through the public `Session` contract.
// ---------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum FanError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("the host reported a failure")]
    HostFailed,
}

/// A minimal real session: the first `advance` issues `n` requests, and it
/// completes once every one is answered, or fails on the first `Failed`
/// reply it consumes.
pub struct FanOut {
    core: SessionCore<Kind>,
    n: usize,
    ids: Option<Vec<RequestId>>,
    received: usize,
}

impl FanOut {
    pub fn new(n: usize) -> Self {
        Self {
            core: SessionCore::default(),
            n,
            ids: None,
            received: 0,
        }
    }
}

fn fan_failure() -> Failure {
    Failure::new("AwaitingReplies", &"the host reported a failure")
}

impl Session for FanOut {
    type Error = FanError;
    type Output = usize;
    type Request = Kind;

    fn advance(&mut self) -> Result<Step, FanError> {
        if self.core.is_failed() {
            return Err(self.core.failed_error().into());
        }
        if self.core.is_complete() {
            return Ok(Step::Complete);
        }

        if self.ids.is_none() {
            let ids = (0..self.n)
                .map(|i| self.core.issue(if i % 2 == 0 { Kind::A } else { Kind::B }))
                .collect();
            self.ids = Some(ids);
        }

        for id in self.ids.clone().unwrap_or_default() {
            match self.core.take_reply(id) {
                Some(Reply::Failed) => {
                    let error = FanError::HostFailed;
                    let phase = self.phase();
                    self.core.mark_failed(phase, &error);
                    return Err(error);
                }
                Some(_) => self.received += 1,
                None => {}
            }
        }

        if self.received == self.n {
            self.core.mark_complete();
            Ok(Step::Complete)
        } else {
            Ok(Step::AwaitHost)
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<Kind>] {
        self.core.outstanding_requests()
    }

    fn phase(&self) -> String {
        if let Some(failure) = self.core.failure() {
            return failure.phase.clone();
        }
        if self.core.is_complete() {
            "Complete".into()
        } else if self.ids.is_none() {
            "Start".into()
        } else {
            "AwaitingReplies".into()
        }
    }

    fn fulfill(&mut self, id: RequestId, reply: Reply) -> Result<(), FanError> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<usize, FanError> {
        self.core.finish_check()?;
        Ok(self.received)
    }
}

/// One host call on a [`FanOut`] session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOp {
    Advance,
    Fulfill(Target, Reply),
    Inspect,
}

/// A decoded session script: how many requests the session fans out to,
/// and the host's calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionScript {
    pub n: u8,
    pub ops: Vec<SessionOp>,
}

/// Decodes arbitrary bytes into a script (the `cargo-fuzz` entry point).
pub fn decode_session(bytes: &[u8]) -> SessionScript {
    let mut cur = Cursor(bytes);
    let n = cur.byte() % 6;
    let mut ops = Vec::new();
    while !cur.is_empty() {
        ops.push(match cur.byte() % 4 {
            0 => SessionOp::Advance,
            1 | 2 => {
                let target = cur.target();
                SessionOp::Fulfill(target, cur.reply())
            }
            _ => SessionOp::Inspect,
        });
    }
    SessionScript { n, ops }
}

/// Reference model of [`FanOut`], derived from the [`Session`] contract
/// alone (not from `FanOut`'s code).
struct FanModel {
    n: usize,
    issued: Option<Vec<u64>>,
    answered: Vec<(u64, Reply)>,
    life: Life,
}

impl FanModel {
    fn outstanding(&self) -> Vec<u64> {
        self.issued
            .iter()
            .flatten()
            .copied()
            .filter(|id| !self.answered.iter().any(|(a, _)| a == id))
            .collect()
    }

    fn resolve(&self, target: Target) -> u64 {
        match (target, &self.issued) {
            (Target::Issued(n), Some(ids)) if !ids.is_empty() => ids[n as usize % ids.len()],
            (Target::Issued(n), _) => u64::from(n),
            (Target::Raw(raw), _) => raw % RAW_RANGE,
        }
    }

    fn kind(id: u64) -> Kind {
        if id.is_multiple_of(2) {
            Kind::A
        } else {
            Kind::B
        }
    }
}

/// Drives a [`FanOut`] through `script` as a (possibly hostile) host,
/// checking every result against the model, then finishes it.
pub fn run_session(script: &SessionScript) {
    let n = script.n as usize % 6;
    let mut ids = Ids::new();
    let mut session = FanOut::new(n);
    let mut model = FanModel {
        n,
        issued: None,
        answered: Vec::new(),
        life: Life::Running,
    };

    for op in &script.ops {
        match *op {
            SessionOp::Advance => {
                let expected = match model.life {
                    Life::Failed => Err(FanError::Protocol(ProtocolError::SessionFailed(
                        fan_failure(),
                    ))),
                    Life::Complete => Ok(Step::Complete),
                    Life::Running => {
                        if model.issued.is_none() {
                            model.issued = Some((0..model.n as u64).collect());
                        }
                        if model
                            .answered
                            .iter()
                            .any(|(_, reply)| *reply == Reply::Failed)
                        {
                            model.life = Life::Failed;
                            Err(FanError::HostFailed)
                        } else if model.answered.len() == model.n {
                            model.life = Life::Complete;
                            Ok(Step::Complete)
                        } else {
                            Ok(Step::AwaitHost)
                        }
                    }
                };
                assert_eq!(session.advance(), expected);
            }

            SessionOp::Fulfill(target, reply) => {
                let raw = model.resolve(target);
                let expected = match model.life {
                    Life::Complete => Err(ProtocolError::SessionComplete),
                    Life::Failed => Err(ProtocolError::SessionFailed(fan_failure())),
                    Life::Running if !model.outstanding().contains(&raw) => {
                        Err(ProtocolError::UnknownRequest(ids.id(raw)))
                    }
                    Life::Running if !FanModel::kind(raw).accepts(&reply) => {
                        Err(ProtocolError::ReplyMismatch {
                            id: ids.id(raw),
                            expected: FanModel::kind(raw).expected_reply(),
                        })
                    }
                    Life::Running => {
                        model.answered.push((raw, reply));
                        Ok(())
                    }
                };
                assert_eq!(
                    session.fulfill(ids.id(raw), reply),
                    expected.map_err(FanError::from)
                );
            }

            SessionOp::Inspect => {}
        }

        let seen: Vec<u64> = session
            .outstanding_requests()
            .iter()
            .map(|r| number(r.id))
            .collect();
        assert_eq!(seen, model.outstanding(), "outstanding set diverged");
        for request in session.outstanding_requests() {
            assert_eq!(request.kind, FanModel::kind(number(request.id)));
        }
    }

    let expected = match model.life {
        Life::Complete => Ok(n),
        Life::Failed => Err(FanError::Protocol(ProtocolError::SessionFailed(
            fan_failure(),
        ))),
        Life::Running => Err(FanError::Protocol(ProtocolError::SessionNotComplete)),
    };
    assert_eq!(session.finish(), expected);
}
