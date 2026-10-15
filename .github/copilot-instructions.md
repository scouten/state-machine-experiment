# Repository instructions

This is an experimental Rust Cargo workspace prototyping synchronous, sans-I/O
state machines for C2PA (Content Credentials). Start with the
[README](../README.md) and [architecture walkthrough](../docs/walkthrough/02-architecture.md).
[CLAUDE.md](../CLAUDE.md) contains more detailed repository guidance.

## Build, test, and lint

Run workspace commands from the repository root. The MSRV is **1.96.0**, declared
in [Cargo.toml](../Cargo.toml) and checked by [CI](workflows/ci.yml).

```sh
cargo build
cargo test

# One crate, or one test selected by its name.
cargo test -p contentauth-c2pa-reader
cargo test -p contentauth-c2pa-reader test_name

# CI-style checks.
cargo check --all-features --all-targets
cargo test --doc --all-features
cargo clippy --all-features --all-targets -- -Dwarnings
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features
cargo deny check advisories bans licenses sources
```

Replace `test_name` with the actual test name or module-qualified name. Cargo
matches this as a filter; use `-- --exact` with the full name when necessary.

[rustfmt.toml](../rustfmt.toml) uses nightly-only options. Match CI's pinned
formatter rather than a floating nightly:

```sh
rustup toolchain install nightly-2026-01-16
cargo +nightly-2026-01-16 fmt --all
cargo +nightly-2026-01-16 fmt --all -- --check
```

Coverage uses `cargo-llvm-cov`:

```sh
cargo llvm-cov --all-features --tests --lcov --output-path lcov.info
```

Portable crates are also checked on both Wasm targets. The two blocking Rust
compatibility crates are excluded because they own the network transports:

```sh
cargo check --all-features --target wasm32-unknown-unknown --workspace --exclude contentauth-c2pa-rs-compat --exclude contentauth-c2pa-rs-compat-sign
cargo check --all-features --target wasm32-wasip2 --workspace --exclude contentauth-c2pa-rs-compat --exclude contentauth-c2pa-rs-compat-sign
```

Three projects have their own workspaces and are not covered by root
`cargo test`:

- [c2pa-rs-compat-conformance](../c2pa-rs-compat-conformance/README.md) compares
  this implementation against the real `c2pa` crate. Run
  `cargo test --manifest-path c2pa-rs-compat-conformance/Cargo.toml`.
- The Neon addons, [c2pa-node-compat-addon](../c2pa-node-compat-addon/) and
  [c2pa-node-sign-addon](../c2pa-node-sign-addon/), must be built and tested
  inside Node: run `npm run build && npm test` in each directory. Build the reader
  addon before running the signing addon's tests, which read back signed assets.

## Architecture

- **Engine:** `contentauth-state-machine` is domain-independent. A
  [Session](../contentauth-state-machine/src/session.rs) advances synchronously.
  `Step::AwaitHost` exposes outstanding typed requests; the host can fulfill any
  subset in any order. After `Step::Complete`, consume the session with `finish`
  to obtain its result. Sessions never perform I/O, block, or spawn.
- **C2PA domain:** `contentauth-c2pa-reader` validates manifest-store bytes;
  `contentauth-c2pa-builder` generates and signs stores using a two-pass
  placeholder scheme. Neither knows container formats. Shared vocabulary and
  deterministic encoders belong in `contentauth-c2pa-primitives`, not the engine.
- **Containers:** `contentauth-c2pa-format` defines `FormatHandler`
  (`descriptor`, `locate`, `plan_embed`, `commit`), `IoRequest`, and embedding
  plans. JPEG and TIFF implement that contract in separate crates. The
  `contentauth-c2pa-format-registry` belongs to the host side: descriptors support
  detection, but policy for combining content, extension, and MIME hints stays
  with the host.
- **File orchestration:** `contentauth-c2pa-file-reader` composes format location
  with domain validation; `contentauth-c2pa-file-builder` composes embedding with
  domain building. Both are themselves sans-I/O sessions. Their `drive.rs`
  convenience functions are concrete synchronous I/O hosts, not engine code.
- **Language bindings:** Rust compatibility crates drive sessions synchronously.
  Browser compatibility crates are async hosts using `Blob`/`Platform` and
  signer abstractions; their `web` bindings are Wasm-target-only. Node session
  wrappers remain synchronous and expose plain requests/replies so JavaScript
  owns the event loop, filesystem, network, and signing. Async belongs in the
  host, not in the underlying sessions.
- **Signing baseline:** `contentauth-c2pa-sign-baseline` shares the
  definition-to-settings conversion and signing fixtures across bindings.
  Read-side and sign-side compatibility surfaces are separate crates. The
  standalone conformance project checks behavior against c2pa-rs rather than
  becoming a dependency of the portable workspace.

## Repository-specific conventions

- A new workflow gets its own session and request vocabulary; do not put C2PA or
  platform-specific behavior into the generic engine. A new container gets a
  `FormatHandler` crate and passes
  `contentauth_c2pa_format::test_util::conformance::run_all`; the reader and
  builder remain format-independent.
- `EmbedPlan` hard-binding exclusions are a **list**, not one encompassing
  range. Preserve separate ranges: TIFF's count field and manifest store are
  deliberately nonadjacent.
- Preserve the file-builder's streaming behavior: validate the handler's plan
  against a freshly obtained source length, copy large ranges in bounded chunks,
  and hash the plan's output length rather than a reused stream's physical
  length. Do not replace this with whole-asset buffering or `materialize`.
- Signing and timestamps are host operations. If a requested timestamp cannot
  be supplied, fail the build rather than silently produce an untimestamped
  manifest.
- Keep reader decoding seams explicit: `cert.rs` owns `x509_cert` types,
  `cose.rs`/`timestamp.rs` own COSE/RFC 3161 decoding, and `claim.rs` walks
  `c2pa_cbor::Value` explicitly rather than hiding understood fields behind serde
  derives.
- The engine and reader deny `unsafe_code`, `missing_docs`, `clippy::unwrap_used`,
  `clippy::expect_used`, and `clippy::panic`. Non-test code propagates failures
  through the crate's error type.
- There is no public API compatibility guarantee. When revising an API, update
  callers, tests, and docs together; prefer extending an existing entry point
  over adding parallel `_with_x` variants or compatibility shims.
- Changes to crates, dependencies, formats, bindings, reader validation, or
  builder output must update the affected
  [walkthrough](../docs/walkthrough/README.md) pages in the same PR. Keep the crate
  table and Mermaid dependency graph in
  [02-architecture.md](../docs/walkthrough/02-architecture.md), and the
  done/next split in [09-future.md](../docs/walkthrough/09-future.md), current.
  When a diagram disagrees with code, fix the diagram.
- [reference/c2pa-spec](../reference/c2pa-spec/README.md) is a pinned C2PA 2.4
  specification snapshot, not a build dependency; it has separate CC-BY-4.0
  licensing.
- Merge pull requests with squash; this repository rejects merge commits.
