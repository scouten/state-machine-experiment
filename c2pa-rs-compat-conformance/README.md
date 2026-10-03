# c2pa-rs-compat-conformance

Differential test harness: does
[`contentauth-c2pa-rs-compat`](../contentauth-c2pa-rs-compat) report the
same thing as the real [c2pa-rs] `Reader` for the same file?

## Why this is its own, separate Cargo workspace

This crate depends on the real `c2pa` crate — heavy (native/pure-Rust
crypto backends, its own bundled trust list, an HTTP stack for remote
manifests) and not something the root `state-machine-experiment` workspace
wants swept into its own checks. Every one of that workspace's CI commands
(`cargo check --target wasm32-unknown-unknown`, the MSRV check, `cargo
llvm-cov`, `cargo-deny`) runs with no `-p`/package filter, so a virtual
workspace applies them to every listed member; `c2pa` is under no
obligation to build for Wasm, hold to that workspace's MSRV, or clear its
license/advisory policy, and it shouldn't have to. This directory has its
own `[workspace]` in `Cargo.toml`, which stops Cargo from treating it as
part of the parent — it is built and run entirely on its own, exactly like
the sibling crate it depends on via a plain path dependency.

## What's here

* `src/lib.rs` — [`ReadForComparison`], implemented for both `c2pa::Reader`
  and `contentauth_c2pa_rs_compat::Reader`, and [`read_and_summarize`]: the
  one function that drives either backend through identical code and
  extracts a comparable [`Summary`] (validation state, active label,
  title, format, instance ID, claim generator — the slice of fields the
  compat crate currently reproduces).
* `tests/compare_with_c2pa_rs.rs` — the one-file demonstration: reads a
  real, third-party-signed fixture (`C.jpg`, already in this repository,
  signed by an actual c2pa-rs release) through both backends and asserts
  the two `Summary` values are equal.
* `tests/compare_tiff_signed_by_c2pa_rs.rs` — a second container format:
  the real c2pa-rs signs a TIFF (its own layout, which differs from
  `contentauth-c2pa-format-tiff`'s), and this workspace's TIFF handler
  reads it to the same answer c2pa-rs gives, `Valid` included.
* `tests/compare_tiff.rs` — the other direction: c2pa-rs must at least
  *find* the store in a TIFF signed here. It stops at the claim, because
  this workspace's builder emits a claim c2pa-rs 0.91 rejects (for JPEG
  too); the test starts comparing outright once that is fixed.
* `examples/compare_corpus.rs` — the same comparison, generalized to a
  whole directory tree:

  ```sh
  cargo run --release --example compare_corpus -- /path/to/a/corpus
  ```

  Point it at a directory of C2PA-signed assets and it reports how many
  files were compared and lists every disagreement (including one backend
  succeeding while the other fails), exiting non-zero if any were found
  *or* if any path could not even be read — an unreadable path was never
  actually compared, so treating that as a pass would misreport how much
  of the corpus this run checked. This is the seam for running the
  comparison at the scale of a real corpus — hundreds or thousands of
  files — rather than one fixture: for instance, a checkout of c2pa-org's
  `public-testfiles` repository, or any other collection of C2PA-signed
  assets. Nothing about `compare_corpus` is specific to the one fixture the
  test above uses.

  The walk never follows symlinks, to a file or to a directory — a
  directory symlink pointing back at one of its own ancestors would
  otherwise send it in circles. Point it at wherever a corpus's symlinked
  assets actually resolve rather than relying on the walk to follow them.

  Two things it deliberately does *not* paper over, so don't be alarmed
  running it against a directory that isn't itself a curated corpus of
  signed assets (`contentauth-c2pa-reader/tests/fixtures`, say, which also
  holds bare certificates, keys, and a README): a "mismatch" includes two
  backends agreeing that a file is unreadable but disagreeing on *why*
  (their error strings are compared as-is, not normalized), and
  `contentauth-c2pa-rs-compat` only has a JPEG format handler wired up
  today (see its own README) — a bare `.c2pa` manifest file or a format
  neither backend even attempts is a real, expected difference in
  coverage, not a bug in the comparison.

## Running it

```sh
cargo test
cargo run --release --example compare_corpus -- <directory>
```

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE)
or the [MIT license](../LICENSE-MIT), at your option.

[c2pa-rs]: https://github.com/contentauth/c2pa-rs
