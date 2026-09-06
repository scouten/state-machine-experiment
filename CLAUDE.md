# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Cargo workspace prototyping synchronous, sans-I/O state machines for C2PA
(Content Credentials) workflows. Crates today:

- **`contentauth-state-machine`** — the reusable engine. Domain-agnostic:
  a request/reply vocabulary trait, request tracking, a protocol-error
  vocabulary, and the `advance` / `fulfill` / `finish` interaction
  contract. See [`src/session.rs`](contentauth-state-machine/src/session.rs)
  for `Session`/`SessionCore` and [`README.md`](contentauth-state-machine/README.md)
  for the interaction contract diagram.
- **`contentauth-c2pa-reader`** — a from-scratch, sans-I/O reader/validator
  for C2PA manifest stores, built on the engine above. An experimental
  alternative architecture to the [c2pa-rs](https://github.com/contentauth/c2pa-rs)
  SDK. `ReadSession` ([`src/read.rs`](contentauth-c2pa-reader/src/read.rs))
  implements `Session`; its own request vocabulary is in
  [`src/request.rs`](contentauth-c2pa-reader/src/request.rs). See its
  [README.md](contentauth-c2pa-reader/README.md) for what it validates
  (integrity, claim signature, trust chain, RFC 3161 timestamps) and the
  full request-vocabulary table.
- **`contentauth-c2pa-builder`** — the write-side counterpart: generates
  and signs a manifest store via a two-pass placeholder scheme
  (`BuilderSession` in [`src/builder.rs`](contentauth-c2pa-builder/src/builder.rs);
  see its [README.md](contentauth-c2pa-builder/README.md)).
- **`contentauth-c2pa-primitives`** — the narrow slice of vocabulary
  (`StreamId`, `ByteRange`, hash and signing algorithms, `HostError`) and
  deterministic encoders the reader and builder genuinely share.
- **`contentauth-c2pa-format`** — the contract between those sessions
  and container formats: the `FormatHandler` trait (`locate`,
  `plan_embed`, `commit`), the single `IoRequest` vocabulary every
  handler operation speaks, the `EmbedPlan`/`Patch` model, and (behind
  the `test-util` feature) an in-memory host plus a conformance suite.
  Format-specific knowledge never lives here.
- **`contentauth-c2pa-format-jpeg`** — the first format handler: locating
  and embedding manifest stores in a JPEG's `APP11` segments, following
  c2pa-rs's conventions byte for byte. The template for further
  `contentauth-c2pa-format-*` crates.

Container-format handling is deliberately *outside* the reader and
builder: they ask their host for "the manifest store's bytes" and to
"embed this placeholder and report the range of the container structure
carrying it, framing included". A format handler crate answers those
questions; a host that knows what format it is handling picks the
handler. New format = new crate implementing `FormatHandler` and passing
`contentauth_c2pa_format::test_util::conformance::run_all`; nothing in
the reader, builder, or contract crate changes.

## Stability

This is a very experimental prototype, not a shipping product: nothing
here has a compatibility guarantee. Feel free to revise, rename, or break
existing public APIs when it genuinely improves the design — do not
contort a change to preserve backward compatibility or add deprecation
shims for its own sake. Update call sites, tests, and docs to match
rather than layering on compatibility scaffolding.

## The core architectural pattern (sans-I/O sessions)

Both crates hinge on one idea, worth understanding before editing either:
a session is a synchronous state machine that never performs I/O, blocks,
or spawns. When it needs something that might be asynchronous — reading
bytes, the network, the clock, signing — it parks itself and returns the
outstanding requests via `Step::AwaitHost`. The host services any subset of
those requests, in any order, and reports outcomes back via `fulfill`.
Calling `advance` again lets the session consume whatever has arrived and
make further progress. `Step::Complete` means the workflow is done; consume
the session with `finish` to get its result.

A new concrete workflow (e.g. a future write/signing crate) is expected to
be its own crate depending on `contentauth-state-machine`, implementing
`Session` and defining its own `Request` vocabulary and settings/result
types — it should not need to modify the engine crate.

`contentauth-c2pa-reader` treats several submodules as deliberate seams
around specific decoding concerns (see the `Cargo.toml` dependency
comments for the reasoning): `cert.rs` is the only place that names an
`x509_cert` type, `cose.rs`/`timestamp.rs` own COSE and RFC 3161 decoding,
and `claim.rs` walks `c2pa_cbor::Value` by hand rather than using serde
derives, so the set of claim fields understood stays explicit.

Both crates deny `unsafe_code`, `missing_docs`, `clippy::unwrap_used`,
`clippy::expect_used`, and `clippy::panic` at the crate root — write
fallible code and propagate errors through the crate's `Error` type rather
than reaching for `.unwrap()`/`.expect()`/`panic!()`, including in new
non-test code.

## Commands

Build/test the whole workspace from the repo root:

```sh
cargo test
```

Run a single test:

```sh
cargo test -p contentauth-c2pa-reader test_name
```

Format (uses nightly-only rustfmt options — see `rustfmt.toml`; CI pins
`nightly-2026-01-16`):

```sh
rustup toolchain add nightly
cargo +nightly fmt --all
cargo +nightly fmt --all -- --check   # verify only
```

Lint (CI denies all warnings):

```sh
cargo clippy --all-features --all-targets -- -Dwarnings
```

Doc build (CI denies rustdoc warnings too):

```sh
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features
```

Code coverage (matches the CI job; requires `cargo-llvm-cov`):

```sh
cargo llvm-cov --all-features --tests --lcov --output-path lcov.info
```

License/vulnerability audit (config in `deny.toml`):

```sh
cargo deny check advisories bans licenses sources
```

Wasm target checks — the engine and reader are meant to build for Wasm
unmodified, enforced in CI:

```sh
cargo check --all-features --target wasm32-unknown-unknown
cargo check --all-features --target wasm32-wasip2
```

MSRV is 1.88.0 (kept in sync between `Cargo.toml`'s `rust-version` and the
`msrv` CI job).

## CI

`.github/workflows/ci.yml` runs, as separate jobs: unit tests + coverage
upload (Codecov), doc tests, Clippy, nightly `cargo fmt --check`, doc
build, Wasm target checks, an MSRV check, and `cargo-deny`. All must pass
on a PR into `main`.

## Merging PRs

This repository disallows merge commits (GitHub rejects them). Merge
pull requests with squash, not merge.
