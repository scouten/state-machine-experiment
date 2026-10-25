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

//! The request/reply relationship a concrete session's vocabulary must
//! implement.

use std::fmt;

use crate::types::RequestId;

/// One kind of operation a session may ask its host to perform.
///
/// A concrete state machine (a read session, a sign session, or any other
/// subcomponent built on this engine) defines its own request vocabulary —
/// typically an enum with one variant per operation — and implements this
/// trait on it so the engine's [`RequestTracker`](crate::RequestTracker) can
/// validate replies without knowing what the requests mean.
pub trait Request: fmt::Debug {
    /// The reply payload that answers a request of this kind.
    ///
    /// Usually a sibling enum with one variant per [`Request`] variant, plus
    /// (by convention, not by anything this trait enforces) a way to report
    /// that the host could not perform the operation.
    type Reply: fmt::Debug;

    /// Describes the reply payload this request expects, for diagnostics.
    ///
    /// Used to build [`ProtocolError::ReplyMismatch`](crate::ProtocolError::ReplyMismatch)
    /// messages when a host answers with the wrong payload type.
    fn expected_reply(&self) -> &'static str;

    /// Reports whether `reply` is an acceptable fulfillment of this request.
    fn accepts(&self, reply: &Self::Reply) -> bool;
}

/// One operation a session's core needs its host to perform, paired with the
/// ID the host must echo back when reporting the outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HostRequest<K> {
    /// Identifies this request when the host reports its outcome.
    pub id: RequestId,

    /// The operation to perform.
    pub kind: K,
}
