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

//! A counting global allocator: what each operation allocated, in total and
//! at its peak, above what was already live when it started.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

/// Wraps the system allocator and counts.
pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(live, Relaxed);
    TOTAL.fetch_add(by, Relaxed);
    CALLS.fetch_add(1, Relaxed);
}

// SAFETY: defers every operation to `System`, only adding counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grow(l.size());
        System.alloc(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        grow(l.size());
        System.alloc_zeroed(l)
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new >= l.size() {
            grow(new - l.size());
        } else {
            LIVE.fetch_sub(l.size() - new, Relaxed);
        }
        System.realloc(p, l, new)
    }
}

/// What one measured operation cost.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cost {
    /// Bytes allocated in total (reallocation growth included).
    pub total: usize,
    /// Highest live bytes above the starting level.
    pub peak: usize,
    /// Number of allocation calls.
    pub calls: usize,
}

/// Runs `f`, returning its result and what it allocated. The result is kept
/// alive until after the measurement, so returned buffers count toward peak.
pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let (t0, c0) = (TOTAL.load(Relaxed), CALLS.load(Relaxed));
    let out = f();
    let cost = Cost {
        total: TOTAL.load(Relaxed) - t0,
        peak: PEAK.load(Relaxed).saturating_sub(base),
        calls: CALLS.load(Relaxed) - c0,
    };
    (out, cost)
}
