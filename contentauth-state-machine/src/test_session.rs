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

use crate::{HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step};

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
    core: SessionCore<Ping>,
    count: u32,
    waiting: Option<Vec<RequestId>>,
}

impl PingSession {
    pub(crate) fn new(count: u32) -> Self {
        Self {
            core: SessionCore::default(),
            count,
            waiting: None,
        }
    }
}

impl Session for PingSession {
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
