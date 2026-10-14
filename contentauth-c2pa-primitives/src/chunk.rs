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

//! How large a piece of the asset a session asks its host for at a time
//! while hashing it.

/// The size, in bytes, of each chunk a session requests from its host when
/// it hashes an asset.
///
/// The host picks the value (a network-backed host wants large chunks to
/// amortize round trips; a memory-constrained one wants small ones), but
/// the engine bounds it: [`Self::MIN`] to [`Self::MAX`]. The bounds exist
/// so no setting can make a session misbehave, not as advice:
///
/// * below the minimum, a large asset would turn into an enormous number of
///   host round trips, each costing far more than the hashing it feeds;
/// * above the maximum, a session would hold an unreasonable amount of
///   memory, since several chunks (up to the session's request window, see
///   [`HashWindow`]) are in play at once — so hashing never holds more than
///   `window × chunk size`, at most `HashWindow::MAX × ChunkSize::MAX`.
///
/// A value outside the bounds is refused by [`Self::new`] rather than
/// silently adjusted, so a configuration mistake surfaces where it was
/// made; [`Self::clamped`] is there for a caller that would rather have
/// the nearest supported value (a size taken from user input, say).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChunkSize(u64);

impl ChunkSize {
    /// What a session uses unless the host chooses otherwise: 64 KiB.
    pub const DEFAULT: Self = Self(64 * 1024);
    /// The largest chunk a session will request: 8 MiB.
    pub const MAX: Self = Self(8 * 1024 * 1024);
    /// The smallest chunk a session will request: 4 KiB.
    pub const MIN: Self = Self(4 * 1024);

    /// Accepts `bytes` if it lies within [`Self::MIN`]`..=`[`Self::MAX`].
    pub fn new(bytes: u64) -> Result<Self, ChunkSizeError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&bytes) {
            Ok(Self(bytes))
        } else {
            Err(ChunkSizeError {
                requested: bytes,
                min: Self::MIN.0,
                max: Self::MAX.0,
            })
        }
    }

    /// The supported size nearest `bytes`.
    pub fn clamped(bytes: u64) -> Self {
        Self(bytes.clamp(Self::MIN.0, Self::MAX.0))
    }

    /// The size in bytes.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for ChunkSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TryFrom<u64> for ChunkSize {
    type Error = ChunkSizeError;

    fn try_from(bytes: u64) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

/// How many chunks a session keeps in play — outstanding at the host plus
/// buffered awaiting their turn — while hashing an asset.
///
/// This is the ceiling on how much a host can overlap: a host servicing
/// requests concurrently can have at most this many in flight at once, so a
/// high-latency, network-backed host wants it large to keep its pipeline
/// full, while a host that reads serially gains nothing above 1. Together
/// with [`ChunkSize`] it also sets the hash phase's peak memory, `window ×
/// chunk size`, which is why the engine bounds it: [`Self::MIN`] to
/// [`Self::MAX`]. A value outside the bounds is refused by [`Self::new`]
/// rather than silently adjusted; [`Self::clamped`] gives the nearest
/// supported value instead.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HashWindow(usize);

impl HashWindow {
    /// What a session uses unless the host chooses otherwise: 8.
    pub const DEFAULT: Self = Self(8);
    /// The largest window: 32. With [`ChunkSize::MAX`] this bounds hash
    /// phase memory at 256 MiB.
    pub const MAX: Self = Self(32);
    /// The smallest window: 1, a session that keeps a single chunk in play
    /// and so never overlaps.
    pub const MIN: Self = Self(1);

    /// Accepts `chunks` if it lies within [`Self::MIN`]`..=`[`Self::MAX`].
    pub fn new(chunks: usize) -> Result<Self, HashWindowError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&chunks) {
            Ok(Self(chunks))
        } else {
            Err(HashWindowError {
                requested: chunks,
                min: Self::MIN.0,
                max: Self::MAX.0,
            })
        }
    }

    /// The supported window nearest `chunks`.
    pub fn clamped(chunks: usize) -> Self {
        Self(chunks.clamp(Self::MIN.0, Self::MAX.0))
    }

    /// The window, in chunks.
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for HashWindow {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TryFrom<usize> for HashWindow {
    type Error = HashWindowError;

    fn try_from(chunks: usize) -> Result<Self, Self::Error> {
        Self::new(chunks)
    }
}

/// A requested [`HashWindow`] fell outside the range the engine supports.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "a hash window of {requested} chunks is outside the supported range of {min} to {max} chunks"
)]
#[non_exhaustive]
pub struct HashWindowError {
    /// What was asked for.
    pub requested: usize,

    /// The smallest window supported ([`HashWindow::MIN`]).
    pub min: usize,

    /// The largest window supported ([`HashWindow::MAX`]).
    pub max: usize,
}

/// A requested [`ChunkSize`] fell outside the range the engine supports.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("a hash chunk of {requested} bytes is outside the supported range of {min} to {max} bytes")]
#[non_exhaustive]
pub struct ChunkSizeError {
    /// What was asked for.
    pub requested: u64,

    /// The smallest size supported ([`ChunkSize::MIN`]).
    pub min: u64,

    /// The largest size supported ([`ChunkSize::MAX`]).
    pub max: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounds_themselves_are_accepted() {
        assert_eq!(ChunkSize::new(ChunkSize::MIN.get()), Ok(ChunkSize::MIN));
        assert_eq!(ChunkSize::new(ChunkSize::MAX.get()), Ok(ChunkSize::MAX));
    }

    #[test]
    fn one_byte_outside_either_bound_is_refused() {
        let below = ChunkSize::MIN.get() - 1;
        let above = ChunkSize::MAX.get() + 1;

        assert_eq!(
            ChunkSize::new(below),
            Err(ChunkSizeError {
                requested: below,
                min: ChunkSize::MIN.get(),
                max: ChunkSize::MAX.get(),
            })
        );
        assert_eq!(
            ChunkSize::try_from(above).map_err(|e| e.requested),
            Err(above)
        );
    }

    #[test]
    fn zero_is_refused() {
        assert!(ChunkSize::new(0).is_err());
    }

    #[test]
    fn clamping_lands_on_the_nearest_supported_size() {
        assert_eq!(ChunkSize::clamped(0), ChunkSize::MIN);
        assert_eq!(ChunkSize::clamped(u64::MAX), ChunkSize::MAX);
        assert_eq!(ChunkSize::clamped(100_000).get(), 100_000);
    }

    #[test]
    fn the_default_is_within_the_bounds() {
        assert_eq!(
            ChunkSize::new(ChunkSize::DEFAULT.get()),
            Ok(ChunkSize::DEFAULT)
        );
        assert_eq!(ChunkSize::default(), ChunkSize::DEFAULT);
    }

    #[test]
    fn the_error_names_the_requested_size_and_the_bounds() {
        let message = ChunkSize::new(1)
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();

        assert!(message.contains("1 bytes"), "{message}");
        assert!(message.contains("4096"), "{message}");
        assert!(message.contains("8388608"), "{message}");
    }

    #[test]
    fn a_window_outside_the_bounds_is_refused_but_the_bounds_are_accepted() {
        assert_eq!(HashWindow::new(HashWindow::MIN.get()), Ok(HashWindow::MIN));
        assert_eq!(HashWindow::new(HashWindow::MAX.get()), Ok(HashWindow::MAX));
        assert!(HashWindow::new(0).is_err());
        assert!(HashWindow::new(HashWindow::MAX.get() + 1).is_err());
    }

    #[test]
    fn a_window_clamps_to_the_nearest_supported_value() {
        assert_eq!(HashWindow::clamped(0), HashWindow::MIN);
        assert_eq!(HashWindow::clamped(usize::MAX), HashWindow::MAX);
        assert_eq!(HashWindow::clamped(16).get(), 16);
    }

    #[test]
    fn the_default_window_is_eight_and_within_the_bounds() {
        assert_eq!(HashWindow::default(), HashWindow::DEFAULT);
        assert_eq!(HashWindow::DEFAULT.get(), 8);
        assert_eq!(
            HashWindow::new(HashWindow::DEFAULT.get()),
            Ok(HashWindow::DEFAULT)
        );
    }
}
