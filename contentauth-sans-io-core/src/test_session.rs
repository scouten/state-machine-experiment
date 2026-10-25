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

//! A minimal session for this crate's own unit tests: it issues `count`
//! pings at once and completes when every one has been answered `Pong`.

use crate::{HostRequest, ManualWorkflowCore, ProtocolError, Request, RequestId, Step, Workflow};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Ping {
    Ping(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Pong {
    Ok,
    Failed(&'static str),
    Unrelated,
}

impl Request for Ping {
    type Reply = Pong;

    fn expected_reply(&self) -> &'static str {
        "Pong"
    }

    fn accepts(&self, reply: &Pong) -> bool {
        !matches!(reply, Pong::Unrelated)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PingError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("no pong: {0}")]
    NoPong(&'static str),
}

#[derive(Debug)]
pub(crate) struct PingSession {
    core: ManualWorkflowCore<Ping>,
    count: u32,
    waiting: Option<Vec<RequestId>>,
}

impl PingSession {
    pub(crate) fn new(count: u32) -> Self {
        Self {
            core: ManualWorkflowCore::default(),
            count,
            waiting: None,
        }
    }
}

impl Workflow for PingSession {
    type Error = PingError;
    type Output = u32;
    type Request = Ping;

    fn advance(&mut self) -> Result<Step, PingError> {
        if self.core.is_failed() {
            return Err(self.core.failed_error().into());
        }
        if self.core.is_complete() {
            return Ok(Step::Complete);
        }
        let Some(waiting) = &mut self.waiting else {
            let ids = (0..self.count)
                .map(|n| self.core.issue(Ping::Ping(n)))
                .collect();
            self.waiting = Some(ids);
            return Ok(Step::AwaitHost);
        };
        let mut still = Vec::new();
        for id in waiting.drain(..) {
            match self.core.take_reply(id) {
                None => still.push(id),
                Some(Pong::Failed(why)) => {
                    let err = PingError::NoPong(why);
                    self.core.mark_failed("AwaitingPong", &err);
                    return Err(err);
                }
                Some(_) => {}
            }
        }
        if still.is_empty() {
            self.core.mark_complete();
            return Ok(Step::Complete);
        }
        self.waiting = Some(still);
        Ok(Step::AwaitHost)
    }

    fn outstanding_requests(&self) -> &[HostRequest<Ping>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: Pong) -> Result<(), PingError> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn phase(&self) -> String {
        match (self.core.failure(), &self.waiting) {
            (Some(failure), _) => failure.phase.clone(),
            (None, None) => "Start".into(),
            (None, Some(_)) if self.core.is_complete() => "Complete".into(),
            (None, Some(_)) => "AwaitingPong".into(),
        }
    }

    fn finish(self) -> Result<u32, PingError> {
        self.core.finish_check()?;
        Ok(self.count)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{replay, CoroutineWorkflow, Host, Recorder, Transcript};

    fn coroutine(count: u32) -> CoroutineWorkflow<Ping, u32, PingError> {
        CoroutineWorkflow::new(move |host: Host<Ping>| async move {
            host.set_phase("AwaitingPong");
            let pending: Vec<_> = (0..count).map(|n| host.request(Ping::Ping(n))).collect();
            for reply in pending {
                let id = reply.id();
                match reply.await {
                    Pong::Ok => {}
                    Pong::Failed(why) => return Err(PingError::NoPong(why)),
                    Pong::Unrelated => {
                        return Err(ProtocolError::ReplyMismatch {
                            id,
                            expected: "Pong",
                        }
                        .into())
                    }
                }
            }
            Ok(count)
        })
    }

    fn record_success(
        workflow: impl Workflow<Request = Ping, Output = u32, Error = PingError>,
    ) -> Transcript<Ping> {
        let mut workflow = Recorder::new(workflow);
        assert!(workflow.outstanding_requests().is_empty());
        assert_eq!(workflow.phase(), "Start");
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        let ids: Vec<_> = workflow
            .outstanding_requests()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids.len(), 3);

        assert!(matches!(
            workflow.fulfill(ids[0], Pong::Unrelated),
            Err(PingError::Protocol(ProtocolError::ReplyMismatch { .. }))
        ));
        workflow.fulfill(ids[2], Pong::Ok).unwrap();
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        assert_eq!(workflow.outstanding_requests().len(), 2);
        assert!(matches!(
            workflow.fulfill(ids[2], Pong::Ok),
            Err(PingError::Protocol(ProtocolError::UnknownRequest(_)))
        ));
        workflow.respond(|_| Pong::Ok).unwrap();
        assert_eq!(workflow.advance().unwrap(), Step::Complete);
        assert_eq!(workflow.advance().unwrap(), Step::Complete);
        assert_eq!(workflow.phase(), "Complete");
        assert!(workflow.outstanding_requests().is_empty());
        assert!(matches!(
            workflow.fulfill(ids[0], Pong::Ok),
            Err(PingError::Protocol(ProtocolError::SessionComplete))
        ));
        let transcript = workflow.transcript().clone();
        assert_eq!(workflow.finish().unwrap(), 3);
        transcript
    }

    #[test]
    fn both_styles_share_the_host_contract_and_replay_each_other() {
        let manual = record_success(PingSession::new(3));
        let coroutine_transcript = record_success(coroutine(3));
        assert_eq!(manual.to_string(), coroutine_transcript.to_string());
        assert_eq!(replay(coroutine(3), &manual).unwrap().finish().unwrap(), 3);
        assert_eq!(
            replay(PingSession::new(3), &coroutine_transcript)
                .unwrap()
                .finish()
                .unwrap(),
            3
        );
    }

    fn record_failure(
        workflow: impl Workflow<Request = Ping, Output = u32, Error = PingError>,
    ) -> Transcript<Ping> {
        let mut workflow = Recorder::new(workflow);
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        workflow.respond(|_| Pong::Failed("lost")).unwrap();
        assert!(matches!(workflow.advance(), Err(PingError::NoPong("lost"))));
        assert_eq!(workflow.phase(), "AwaitingPong");
        assert!(matches!(
            workflow.advance(),
            Err(PingError::Protocol(ProtocolError::SessionFailed(f)))
                if f.phase == "AwaitingPong" && f.cause == "no pong: lost"
        ));
        let transcript = workflow.transcript().clone();
        assert!(matches!(
            workflow.finish(),
            Err(PingError::Protocol(ProtocolError::SessionFailed(_)))
        ));
        transcript
    }

    #[test]
    fn both_styles_preserve_the_same_failure_diagnostics() {
        let manual = record_failure(PingSession::new(1));
        let coroutine_transcript = record_failure(coroutine(1));
        assert_eq!(manual.to_string(), coroutine_transcript.to_string());
        assert!(replay(coroutine(1), &manual).unwrap().finish().is_err());
        assert!(replay(PingSession::new(1), &coroutine_transcript)
            .unwrap()
            .finish()
            .is_err());
    }
}
