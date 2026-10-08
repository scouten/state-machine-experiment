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

//! The request/reply vocabulary spoken between a
//! [`SidecarSession`](crate::SidecarSession) and its host.

use contentauth_c2pa_primitives::{ByteRange, HostError, SigningAlg, StreamId};
use contentauth_state_machine::Request;

/// What a sidecar session may ask its host for. Three things only: the
/// asset's bytes (to hash), and a signature. There is no "embed" request —
/// a sidecar manifest is not embedded in anything.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SidecarRequest {
    /// The total length of the asset. Reply with
    /// [`SidecarReply::AssetLength`].
    AssetLength {
        /// The stream to measure.
        stream: StreamId,
    },

    /// A range of the asset. Reply with [`SidecarReply::AssetBytes`].
    AssetBytes {
        /// The stream to read.
        stream: StreamId,

        /// The range wanted.
        range: ByteRange,
    },

    /// Sign `data` — a COSE `Sig_structure` — with `alg`. Reply with
    /// [`SidecarReply::Signature`].
    Sign {
        /// The algorithm to sign with.
        alg: SigningAlg,

        /// The exact bytes to sign.
        data: Vec<u8>,
    },
}

/// The host's answer to a [`SidecarRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum SidecarReply {
    /// Answers [`SidecarRequest::AssetLength`].
    AssetLength(u64),

    /// Answers [`SidecarRequest::AssetBytes`].
    AssetBytes(Vec<u8>),

    /// Answers [`SidecarRequest::Sign`]: the raw signature bytes.
    Signature(Vec<u8>),

    /// The host could not do it. Valid for any request.
    Failed(HostError),
}

impl Request for SidecarRequest {
    type Reply = SidecarReply;

    fn expected_reply(&self) -> &'static str {
        match self {
            Self::AssetLength { .. } => "AssetLength",
            Self::AssetBytes { .. } => "AssetBytes",
            Self::Sign { .. } => "Signature",
        }
    }

    fn accepts(&self, reply: &SidecarReply) -> bool {
        matches!(
            (self, reply),
            (_, SidecarReply::Failed(_))
                | (Self::AssetLength { .. }, SidecarReply::AssetLength(_))
                | (Self::AssetBytes { .. }, SidecarReply::AssetBytes(_))
                | (Self::Sign { .. }, SidecarReply::Signature(_))
        )
    }
}
