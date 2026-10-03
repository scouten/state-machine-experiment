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

//! The session shape both of this crate's operations share: run the
//! [`Scanner`] to completion, then turn its [`Layout`] into the
//! operation's result.
//!
//! Crate-private: the public operation types ([`crate::Locate`] and
//! [`crate::PlanEmbed`]) wrap a [`ScanOp`] each, so that neither the
//! [`Goal`] trait nor the [`Layout`] it consumes is part of the crate's
//! API.

use core::mem::replace;

use contentauth_c2pa_format::{
    FormatError, HostRequest, IoReply, IoRequest, ProtocolError, RequestId, Session, Step, StreamId,
};
use contentauth_state_machine::SessionCore;

use crate::scan::{Layout, Scanner};

/// What an operation does with a completed scan.
pub(crate) trait Goal: Send {
    /// Whether the operation needs the manifest store's bytes, not just
    /// where they are.
    const READS_MANIFEST: bool;

    /// The operation's result.
    type Output: Send;

    /// Computes the result from the scan.
    fn finalize(self, layout: Layout) -> Result<Self::Output, FormatError>;
}

enum State<G: Goal> {
    Scanning {
        scanner: Scanner,
        goal: G,
    },
    Done(G::Output),

    /// Installed while a state is being processed, and left behind by an
    /// error exit.
    Poisoned,
}

/// A scan-then-finalize operation over one stream.
pub(crate) struct ScanOp<G: Goal> {
    core: SessionCore<IoRequest>,
    state: State<G>,
}

impl<G: Goal> ScanOp<G> {
    pub(crate) fn new(stream: StreamId, goal: G) -> Self {
        Self {
            core: SessionCore::default(),
            state: State::Scanning {
                scanner: Scanner::new(stream, G::READS_MANIFEST),
                goal,
            },
        }
    }

    fn run(&mut self) -> Result<Step, FormatError> {
        match replace(&mut self.state, State::Poisoned) {
            State::Scanning { mut scanner, goal } => match scanner.advance(&mut self.core)? {
                None => {
                    self.state = State::Scanning { scanner, goal };
                    Ok(Step::AwaitHost)
                }
                Some(layout) => {
                    self.state = State::Done(goal.finalize(layout)?);
                    self.core.mark_complete();
                    Ok(Step::Complete)
                }
            },

            State::Done(output) => {
                self.state = State::Done(output);
                Ok(Step::Complete)
            }

            State::Poisoned => Err(ProtocolError::SessionFailed.into()),
        }
    }
}

impl<G: Goal> Session for ScanOp<G> {
    type Error = FormatError;
    type Output = G::Output;
    type Request = IoRequest;

    /// Performs as much synchronous work as possible.
    ///
    /// If this returns an error the operation is spent: every later call
    /// reports [`ProtocolError::SessionFailed`].
    fn advance(&mut self) -> Result<Step, FormatError> {
        if self.core.is_complete() {
            return Ok(Step::Complete);
        }

        match self.run() {
            Ok(step) => Ok(step),
            Err(err) => {
                self.core.mark_failed();
                Err(err)
            }
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: IoReply) -> Result<(), FormatError> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<G::Output, FormatError> {
        self.core.finish_check()?;
        match self.state {
            State::Done(output) => Ok(output),
            _ => Err(ProtocolError::SessionFailed.into()),
        }
    }
}

/// Implements [`Session`] for a public newtype around a [`ScanOp`] by
/// delegation, keeping [`ScanOp`] and [`Goal`] out of the crate's API.
macro_rules! delegate_session {
    ($wrapper:ident, $output:ty) => {
        impl ::contentauth_c2pa_format::Session for $wrapper {
            type Error = ::contentauth_c2pa_format::FormatError;
            type Output = $output;
            type Request = ::contentauth_c2pa_format::IoRequest;

            /// Performs as much synchronous work as possible.
            ///
            /// If this returns an error the operation is spent: every
            /// later call reports
            /// [`ProtocolError::SessionFailed`](::contentauth_c2pa_format::ProtocolError::SessionFailed).
            fn advance(
                &mut self,
            ) -> Result<::contentauth_c2pa_format::Step, ::contentauth_c2pa_format::FormatError>
            {
                self.0.advance()
            }

            /// Returns the requests the host has not yet fulfilled.
            fn outstanding_requests(
                &self,
            ) -> &[::contentauth_c2pa_format::HostRequest<::contentauth_c2pa_format::IoRequest>]
            {
                self.0.outstanding_requests()
            }

            /// Reports the outcome of one outstanding request.
            fn fulfill(
                &mut self,
                id: ::contentauth_c2pa_format::RequestId,
                reply: ::contentauth_c2pa_format::IoReply,
            ) -> Result<(), ::contentauth_c2pa_format::FormatError> {
                self.0.fulfill(id, reply)
            }

            /// Consumes the operation and returns its result.
            fn finish(self) -> Result<$output, ::contentauth_c2pa_format::FormatError> {
                self.0.finish()
            }
        }
    };
}

pub(crate) use delegate_session;
