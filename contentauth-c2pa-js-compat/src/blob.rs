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

//! [`Blob`]: the asset, as an asynchronous source of byte ranges.

use contentauth_c2pa_primitives::{ByteRange, HostError};

/// An asset a [`crate::Reader`] can read, shaped after the two operations
/// a JavaScript `Blob` actually offers: `Blob.size`, which is synchronous,
/// and `Blob.slice(start, end).arrayBuffer()`, which is not.
///
/// This is the whole reason this crate's host is asynchronous. c2pa-rs
/// consumes an asset through a synchronous `Read + Seek` stream, so
/// c2pa-wasm has to *make* a `Blob` synchronous — via `FileReaderSync`,
/// which only exists inside a Web Worker. The engine underneath this crate
/// asks for byte ranges one request at a time instead
/// ([`FileReadRequest::Read`](contentauth_c2pa_file_reader::FileReadRequest::Read)),
/// so a host is free to answer each one with a `Promise`.
///
/// Every range a session asks for is absolute — never a position relative
/// to a previous request — and a session may ask for them in any order, so
/// an implementation must not assume forward-only access.
///
/// # No `Send` bound, on purpose
///
/// The future [`Self::bytes`] returns is not required to be `Send`: the
/// browser implementation (`web_sys::Blob`, under the `web` feature)
/// awaits a `JsFuture`, which is not, and the engine underneath never
/// needs one — a sans-I/O session is driven from a single task by
/// construction. The `async fn` form is used here for the same reason,
/// rather than spelling out the `impl Future` desugaring with bounds
/// nobody wants.
#[allow(async_fn_in_trait)]
pub trait Blob {
    /// The asset's total length in bytes — `Blob.size`.
    fn size(&self) -> u64;

    /// Reads exactly `range.len` bytes starting at `range.start` —
    /// `Blob.slice(start, end).arrayBuffer()`.
    ///
    /// A range that lies partly or wholly past the end of the asset is an
    /// error, not a short read: the engine asks only for ranges it has
    /// been told exist (from [`Self::size`], or from framing it has
    /// already parsed), so a shortfall means the asset changed underneath
    /// it. [`crate::read_manifest`] checks the length of whatever comes
    /// back regardless, so an implementation that does return fewer bytes
    /// is still reported as a failed read rather than trusted.
    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError>;
}

/// A [`Blob`] already in memory: always ready, never actually suspends.
///
/// This is what a caller with the whole asset in hand uses — and what
/// makes the async host in [`crate::read_manifest`] testable without a
/// browser: the same loop, with a [`Blob`] whose futures resolve
/// immediately.
impl Blob for [u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
        slice(self, range).map(<[u8]>::to_vec)
    }
}

impl Blob for Vec<u8> {
    fn size(&self) -> u64 {
        self.as_slice().size()
    }

    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
        self.as_slice().bytes(range).await
    }
}

/// `bytes[range]`, or a [`HostError`] describing why that range does not
/// exist — never a panic, whatever the range.
pub(crate) fn slice(bytes: &[u8], range: ByteRange) -> Result<&[u8], HostError> {
    let end = range
        .start
        .checked_add(range.len)
        .ok_or_else(|| HostError::new("byte range overflows"))?;

    // A bound that does not fit a `usize` (only possible on a 32-bit
    // target) cannot index a slice that does, so it is "past the end" by
    // the same token as a bound that fits but exceeds the length.
    usize::try_from(range.start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(start, end)| bytes.get(start..end))
        .ok_or_else(|| {
            HostError::new(format!(
                "range {}+{} lies past the end of the {}-byte asset",
                range.start,
                range.len,
                bytes.len()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, len: u64) -> ByteRange {
        ByteRange { start, len }
    }

    #[test]
    fn slice_returns_exactly_the_requested_range() {
        let bytes = [10u8, 11, 12, 13, 14];
        assert_eq!(slice(&bytes, range(1, 3)).ok(), Some(&bytes[1..4]));
        assert_eq!(slice(&bytes, range(0, 5)).ok(), Some(&bytes[..]));
        assert_eq!(slice(&bytes, range(5, 0)).ok(), Some(&bytes[5..]));
    }

    #[test]
    fn slice_reports_a_range_past_the_end_as_an_error() {
        let bytes = [10u8, 11, 12];
        assert!(slice(&bytes, range(2, 2)).is_err());
        assert!(slice(&bytes, range(3, 1)).is_err());
        assert!(slice(&bytes, range(4, 0)).is_err());
    }

    #[test]
    fn slice_reports_an_overflowing_range_as_an_error_rather_than_panicking() {
        let bytes = [10u8, 11, 12];
        assert!(slice(&bytes, range(u64::MAX, 1)).is_err());
        assert!(slice(&bytes, range(1, u64::MAX)).is_err());
    }
}
