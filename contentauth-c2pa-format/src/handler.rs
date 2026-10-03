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

//! The trait a container-format handler implements.

use contentauth_c2pa_primitives::StreamId;
use contentauth_state_machine::Session;

use crate::{
    descriptor::FormatDescriptor,
    error::FormatError,
    location::ManifestLocation,
    plan::{EmbedPlan, Patch},
    request::IoRequest,
};

/// A format operation: a session that reads an asset through
/// [`IoRequest`]s and produces `Output`.
///
/// Blanket-implemented for every session with that shape; handlers name
/// their operations' concrete types through this bound rather than
/// spelling out the three associated types each time.
pub trait FormatOp<Output>:
    Session<Request = IoRequest, Output = Output, Error = FormatError>
{
}

impl<Output, S> FormatOp<Output> for S where
    S: Session<Request = IoRequest, Output = Output, Error = FormatError>
{
}

/// Knowledge of one container format: where a C2PA manifest store lives in
/// it, and how to put one there.
///
/// One implementation per format, each in its own crate. A handler holds
/// no asset state of its own — it is a factory for operations over a
/// stream the host names — so a single value serves any number of assets.
///
/// # Why associated types rather than trait objects
///
/// A host that knows what format it is handling (the assumption at this
/// layer) instantiates an orchestrating session generically, with no
/// allocation per operation and no loss of the operations' concrete
/// types. A registry that picks a handler at run time is a separate
/// concern for a separate crate, which can wrap any handler in an
/// object-safe adapter of its own; nothing here needs to change for it.
/// (`contentauth-c2pa-format-registry` is one.)
pub trait FormatHandler {
    /// The operation [`Self::locate`] returns.
    type Locate: FormatOp<ManifestLocation>;

    /// The operation [`Self::plan_embed`] returns.
    type PlanEmbed: FormatOp<EmbedPlan>;

    /// How this format identifies itself: plain data, with no code behind
    /// it, so a host can decide *which* handler an asset wants without
    /// running any of them. See [`FormatDescriptor`].
    fn descriptor(&self) -> &FormatDescriptor;

    /// Finds the manifest store in the asset on `stream`.
    ///
    /// Serves both reading — the reader's own host request for "the
    /// manifest store's bytes" — and signing an asset that may already be
    /// signed, where the existing store is what gets validated and
    /// carried forward as a parent. The stream is a parameter, not a
    /// convention, so the same operation locates the store in an
    /// ingredient file on another stream.
    fn locate(&self, stream: StreamId) -> Self::Locate;

    /// Describes how to embed a manifest store of `manifest_len` bytes
    /// into the asset on `stream`, replacing any store already there.
    ///
    /// Only the length is known at this point: a builder reserves its
    /// placeholder before it can compute a hash or sign, and the final
    /// store is the same length as the placeholder by construction. The
    /// plan's [`EmbedPlan::replaced`] reports whether a store was dropped;
    /// deciding whether that was acceptable is the caller's business.
    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> Self::PlanEmbed;

    /// Names the output bytes that depend on the manifest store's actual
    /// content, once that content is known.
    ///
    /// A pure function of the plan and the final store: a JPEG handler has
    /// nothing to patch, a PNG handler recomputes the chunk CRC. Every
    /// patch must lie within [`EmbedPlan::exclusion`] — bytes outside it
    /// have already been hashed into the hard binding — and a handler
    /// should also use this call to refuse a store that does not fit the
    /// assumptions its framing made ([`FormatError::ManifestMismatch`]).
    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError>;
}
