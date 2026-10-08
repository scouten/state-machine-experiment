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

//! Prints the comparison. Run with `cargo run --release`.

use std::time::Instant;

use c2pa_core_comparison::{
    alloc_count::{measure, Cost, Counting},
    walk_c2pa_store, walk_jumbf, write_c2pa_store, write_jumbf_as_sidecar_builder_does,
    write_jumbf_borrowed, write_jumbf_owned, write_jumbf_render_once, Scenario,
};

#[global_allocator]
static ALLOC: Counting = Counting;

/// Median wall time over enough runs to take about 300 ms, plus the
/// allocation cost of one run.
fn bench<T>(mut f: impl FnMut() -> T) -> (f64, Cost) {
    let (_, cost) = measure(&mut f);
    let probe = Instant::now();
    std::hint::black_box(f());
    let once = probe.elapsed().as_secs_f64().max(1e-7);
    let runs = ((0.3 / once) as usize).clamp(5, 20_000);
    let mut times: Vec<f64> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            std::hint::black_box(f());
            t.elapsed().as_secs_f64()
        })
        .collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (times[times.len() / 2], cost)
}

fn us(s: f64) -> String {
    if s >= 1e-3 {
        format!("{:.2} ms", s * 1e3)
    } else {
        format!("{:.1} µs", s * 1e6)
    }
}

fn kib(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MiB", n as f64 / (1 << 20) as f64)
    } else {
        format!("{:.1} KiB", n as f64 / 1024.0)
    }
}

fn row(name: &str, (t, c): (f64, Cost)) {
    println!(
        "| {name} | {} | {} | {} | {} |",
        us(t),
        kib(c.peak),
        kib(c.total),
        c.calls
    );
}

fn main() {
    let scenarios = [
        Scenario::new("typical: 2 assertions × 200 B", 2, 200),
        Scenario::new("many small: 1000 × 64 B", 1000, 64),
        Scenario::new("many medium: 100 × 4 KiB", 100, 4096),
        Scenario::new("few large: 8 × 4 MiB", 8, 4 << 20),
        Scenario::new("one huge: 1 × 32 MiB", 1, 32 << 20),
    ];

    for s in &scenarios {
        let (store, _) = write_c2pa_store(s);
        println!(
            "\n### {} — store {} ({} of payload)\n",
            s.name,
            kib(store.len()),
            kib(s.payload_bytes())
        );

        // Same bytes?
        let owned = write_jumbf_owned(s);
        println!(
            "Writers emit identical bytes: **{}**\n",
            if owned == store { "yes" } else { "NO" }
        );
        assert_eq!(walk_c2pa_store(&store), walk_jumbf(&store));

        println!("| write (incl. per-assertion SHA-256 where noted) | time | peak | total alloc | allocs |");
        println!("|---|---|---|---|---|");
        row(
            "c2pa-store (streams, hashes as it writes)",
            bench(|| write_c2pa_store(s)),
        );
        row(
            "jumbf, as sidecar-builder does (render to hash, then render store, owned)",
            bench(|| write_jumbf_as_sidecar_builder_does(s)),
        );
        row(
            "jumbf, render each assertion once, hash it, splice it (borrowed)",
            bench(|| write_jumbf_render_once(s)),
        );
        row(
            "jumbf, store only, owned children, no hashing",
            bench(|| write_jumbf_owned(s)),
        );
        row(
            "jumbf, store only, borrowed children, no hashing",
            bench(|| write_jumbf_borrowed(s)),
        );

        println!("\n| parse + visit every assertion | time | peak | total alloc | allocs |");
        println!("|---|---|---|---|---|");
        row("c2pa-store (zero-copy)", bench(|| walk_c2pa_store(&store)));
        row(
            "jumbf (zero-copy payloads, builds a tree)",
            bench(|| walk_jumbf(&store)),
        );
    }
}
