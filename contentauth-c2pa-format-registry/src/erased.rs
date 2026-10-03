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

//! Type-erasing adapters: what lets a host hold a handler it chose at
//! run time.
//!
//! [`FormatHandler`] uses associated types so that a host that knows its
//! format pays for nothing. A host that does *not* know — it is reading
//! whatever file it was handed — needs one type that stands for "some
//! handler". That is [`AnyFormat`]: a cheap, cloneable handle that is
//! itself a [`FormatHandler`], so every orchestrating session in the
//! workspace (`FileReadSession<AnyFormat>`, `FileBuilderSession<AnyFormat>`)
//! works with it unchanged — none of them know it is there.
//!
//! The price is one allocation per operation, which is nothing next to
//! the I/O round trips the operation exists to request.
//!
//! [`DynFormatHandler`] is the object-safe face of a handler, and the
//! seam for handlers that are not Rust types at all: anything that can
//! answer its four questions can be registered, whatever it is written
//! in (see the crate README).

use std::{fmt, sync::Arc};

use contentauth_c2pa_format::{
    EmbedPlan, FormatDescriptor, FormatError, FormatHandler, FormatOp, HostRequest, IoReply,
    IoRequest, ManifestLocation, Patch, RequestId, Session, Step, StreamId,
};

/// The object-safe core of [`FormatOp`]: [`Session`] with `finish` taking
/// a boxed `self`.
trait ErasedOp<Output>: Send {
    fn advance(&mut self) -> Result<Step, FormatError>;
    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>];
    fn fulfill(&mut self, id: RequestId, reply: IoReply) -> Result<(), FormatError>;
    fn finish_boxed(self: Box<Self>) -> Result<Output, FormatError>;
}

impl<Output, S: FormatOp<Output>> ErasedOp<Output> for S {
    fn advance(&mut self) -> Result<Step, FormatError> {
        Session::advance(self)
    }

    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
        Session::outstanding_requests(self)
    }

    fn fulfill(&mut self, id: RequestId, reply: IoReply) -> Result<(), FormatError> {
        Session::fulfill(self, id, reply)
    }

    fn finish_boxed(self: Box<Self>) -> Result<Output, FormatError> {
        Session::finish(*self)
    }
}

/// A format operation whose concrete type has been erased: a
/// [`FormatOp`] producing `Output`, whatever session is behind it.
pub struct BoxedOp<Output>(Box<dyn ErasedOp<Output>>);

impl<Output> BoxedOp<Output> {
    /// Erases `op`.
    pub fn new<S: FormatOp<Output> + 'static>(op: S) -> Self {
        Self(Box::new(op))
    }
}

impl<Output> Session for BoxedOp<Output> {
    type Error = FormatError;
    type Output = Output;
    type Request = IoRequest;

    fn advance(&mut self) -> Result<Step, FormatError> {
        self.0.advance()
    }

    fn outstanding_requests(&self) -> &[HostRequest<IoRequest>] {
        self.0.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: IoReply) -> Result<(), FormatError> {
        self.0.fulfill(id, reply)
    }

    fn finish(self) -> Result<Output, FormatError> {
        self.0.finish_boxed()
    }
}

/// [`FormatHandler`], object-safe.
///
/// Rust handlers need not implement this: [`AnyFormat::new`] wraps any
/// [`FormatHandler`]. It exists for handlers that are *not* Rust
/// [`FormatHandler`]s — an adapter over one written in another language,
/// say — which implement it directly and are wrapped with
/// [`AnyFormat::from_dyn`].
pub trait DynFormatHandler: Send + Sync {
    /// As [`FormatHandler::descriptor`].
    fn descriptor(&self) -> &FormatDescriptor;

    /// As [`FormatHandler::locate`].
    fn locate(&self, stream: StreamId) -> BoxedOp<ManifestLocation>;

    /// As [`FormatHandler::plan_embed`].
    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> BoxedOp<EmbedPlan>;

    /// As [`FormatHandler::commit`].
    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError>;
}

/// Adapts a Rust [`FormatHandler`] to [`DynFormatHandler`].
struct Native<H>(H);

impl<H> DynFormatHandler for Native<H>
where
    H: FormatHandler + Send + Sync,
    H::Locate: 'static,
    H::PlanEmbed: 'static,
{
    fn descriptor(&self) -> &FormatDescriptor {
        self.0.descriptor()
    }

    fn locate(&self, stream: StreamId) -> BoxedOp<ManifestLocation> {
        BoxedOp::new(self.0.locate(stream))
    }

    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> BoxedOp<EmbedPlan> {
        BoxedOp::new(self.0.plan_embed(stream, manifest_len))
    }

    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
        self.0.commit(plan, manifest)
    }
}

/// A handler chosen at run time: a shared handle to any
/// [`DynFormatHandler`], and itself a [`FormatHandler`].
#[derive(Clone)]
pub struct AnyFormat(Arc<dyn DynFormatHandler>);

impl AnyFormat {
    /// Wraps a Rust [`FormatHandler`].
    pub fn new<H>(handler: H) -> Self
    where
        H: FormatHandler + Send + Sync + 'static,
        H::Locate: 'static,
        H::PlanEmbed: 'static,
    {
        Self(Arc::new(Native(handler)))
    }

    /// Wraps a handler that implements [`DynFormatHandler`] directly.
    pub fn from_dyn(handler: impl DynFormatHandler + 'static) -> Self {
        Self(Arc::new(handler))
    }

    /// How the wrapped format identifies itself. (Also reachable through
    /// [`FormatHandler`]; this is here so callers need not import it.)
    pub fn descriptor(&self) -> &FormatDescriptor {
        self.0.descriptor()
    }
}

impl fmt::Debug for AnyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AnyFormat")
            .field(&self.0.descriptor().name)
            .finish()
    }
}

impl FormatHandler for AnyFormat {
    type Locate = BoxedOp<ManifestLocation>;
    type PlanEmbed = BoxedOp<EmbedPlan>;

    fn descriptor(&self) -> &FormatDescriptor {
        AnyFormat::descriptor(self)
    }

    fn locate(&self, stream: StreamId) -> Self::Locate {
        self.0.locate(stream)
    }

    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> Self::PlanEmbed {
        self.0.plan_embed(stream, manifest_len)
    }

    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
        self.0.commit(plan, manifest)
    }
}
