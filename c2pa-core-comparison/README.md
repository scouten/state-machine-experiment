# c2pa-core-comparison

Hand-coded JUMBF versus the `jumbf` crate, measured. Part of the sidecar
experiment: Gavin Peacock's
[`c2pa-core`](https://github.com/gpeacock/c2pa-core) hand-codes its JUMBF
(`c2pa-store`: a zero-copy `no_std` parser and a streaming, backpatching
writer); this workspace uses [`jumbf`](https://docs.rs/jumbf) 0.7.

Deliberately its own Cargo workspace (it takes a pinned git dependency on
`c2pa-core` and installs a counting global allocator, which needs `unsafe`).

```sh
cargo test                # byte-equality and cross-parse checks
cargo run --release       # prints the tables below
```

## What is compared

One logical manifest store (`c2pa` › manifest › assertions + claim +
signature) in five sizes, written and read both ways, with a counting
allocator for **peak live bytes**, **total bytes allocated** and
**allocation calls**, and wall time (median of repeated runs).

Write has four `jumbf` variants because `c2pa-store` *hashes each assertion
as it writes it* (SHA-256, fixed), while `jumbf` does not hash at all and a
signer must hash every assertion for the claim:

1. `c2pa-store` — streams, hashes as it goes.
2. `jumbf`, **as `contentauth-c2pa-sidecar-builder` first did it** — render
   each assertion to hash it, then build the store again with owned
   children.
3. `jumbf`, **render once, hash, splice** — what the sidecar builder does
   now: the hashed box is stored as-is, as a raw `jumb` box.
4. `jumbf`, assembly only, borrowed children, no hashing — the floor.

## Do they agree?

Yes, byte for byte. The two writers emit **identical bytes** for every
scenario (checked in `cargo test` and on every `cargo run`), the
assertion digests are identical, and each parser reads the other's output
to the same result. So the choice is not a compatibility question.

## Results

One container (shared CPU), `--release`; read the ratios, not the absolute
times. Peak is live bytes above the starting level, including the returned
buffer.

| scenario (store size) | write: c2pa-store | write: jumbf as first built | write: jumbf render-once | write: jumbf floor |
|---|---|---|---|---|
| typical, 2 × 200 B (4 KiB) | 2.9 µs · 4.3 KiB peak | 4.5 µs · 9.7 KiB | 3.1 µs · 5.4 KiB | 2.2 µs · 5.3 KiB |
| 1000 × 64 B (125 KiB) | 577 µs · 183 KiB | 1.22 ms · 541 KiB | 666 µs · 387 KiB | 321 µs · 420 KiB |
| 100 × 4 KiB (409 KiB) | 377 µs · 546 KiB | 472 µs · 980 KiB | 405 µs · 960 KiB | 50 µs · 570 KiB |
| 8 × 4 MiB (32 MiB) | 49.9 ms · 64 MiB | 111 ms · 96 MiB | 76.6 ms · 96 MiB | 24.8 ms · 64 MiB |
| 1 × 32 MiB (32 MiB) | 49.1 ms · 64 MiB | 120 ms · 96 MiB | 73.3 ms · 96 MiB | 23.6 ms · 64 MiB |

| parse + visit every assertion | c2pa-store | jumbf |
|---|---|---|
| typical (4 KiB) | 1.0 µs · 3.1 KiB · 7 allocs | 1.6 µs · 4.1 KiB · 14 allocs |
| 1000 × 64 B | 168 µs · 551 KiB · 1013 allocs | 353 µs · 747 KiB · 2026 allocs |
| 100 × 4 KiB | 308 µs · 60 KiB · 110 allocs | 319 µs · 80 KiB · 220 allocs |
| 8 × 4 MiB | 25.1 ms · 6 KiB · 14 allocs | 24.6 ms · 8 KiB · 28 allocs |
| 1 × 32 MiB | 25.0 ms · 2.6 KiB · 6 allocs | 24.9 ms · 3.5 KiB · 12 allocs |

## Reading the results

* **Parsing.** Both are zero-copy for payloads. `c2pa-store` is up to ~2×
  faster on stores with many boxes and uses about a quarter less
  memory and exactly half the allocations (`jumbf` builds an owned tree of
  `Vec`s per superbox; `c2pa-store` builds one flat list). With large
  payloads the two are indistinguishable — visiting the bytes dominates, and
  the structural overhead is KiB against MiB. Neither is a concern for a
  manifest store of ordinary size.
* **Writing, the floor.** Plain assembly with borrowed children is the
  *fastest* thing measured (`jumbf` memcpys each payload once); it is the
  hashing that `c2pa-store` interleaves that makes it look comparable. The
  gap in the large rows between "floor" (24 ms) and `c2pa-store` (49 ms) is
  the SHA-256 of 32 MiB, which `c2pa-store` pays and the floor does not.
* **Writing, for real.** A signer must hash. Doing it the obvious way with
  `jumbf` (render, hash, render again) cost **~2.3× the time and 1.5× the
  peak memory** of `c2pa-store` on large payloads — that was a real
  inefficiency in this workspace's first sidecar builder and is fixed:
  rendering once and splicing the hashed box in brings it to **~1.5× time**,
  with the same peak as before, at the cost of holding the rendered boxes
  until the store is assembled. What remains is that `jumbf` cannot hash
  while streaming: its builder holds every child and renders to a
  `Write + Seek`.
* **The 64 MiB peaks for a 32 MiB store are the `Vec` sink**, not the
  writer: a growing `Vec` doubles. `c2pa-store`'s `SeekSink` can target a
  file, where its streaming design would keep memory flat regardless of
  size; this harness uses `Vec` for both to compare like with like, so it
  **does not show** `c2pa-store`'s best case. `jumbf`'s builder has no
  equivalent: children are held in memory until `write_jumbf`.

## Bottom line

For this workspace's purposes (manifests are small; assets, which are the
large things, are streamed through `HashStream`, never through JUMBF) the
`jumbf` crate costs microseconds and a few KiB more than the hand-coded
version, and nothing at all in correctness. The hand-coded design is
genuinely better on three axes: allocation count, hash-while-streaming for
very large embedded assertions (thumbnails, ingredients), and `no_std`. If
this workspace grows to write multi-megabyte assertions, `c2pa-store`'s
writer is the one to borrow from; until then the `jumbf` crate is the
cheaper dependency to keep.

Caveats: single machine, shared container; one scenario shape; `c2pa-store`
at a pinned revision (`8f3e630`); timings are medians and short runs are
noisy (the 2–3 µs rows especially). Rerun before quoting.
