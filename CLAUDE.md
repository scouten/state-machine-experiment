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
  (integrity, claim signature, trust chain, RFC 3161 timestamps, and OCSP
  revocation per the spec's §15.9 process — stapled response first, then
  an online query on by default; fail-open only when a responder cannot
  be reached at all) and the full request-vocabulary table.
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
- **`contentauth-c2pa-file-reader`** — the missing glue between the two:
  `FileReadSession` (`src/session.rs`) is itself a sans-I/O session that
  composes a `FormatHandler`'s `locate` operation with a `ReadSession`,
  performing no I/O of its own — its host answers one merged vocabulary,
  `FileReadRequest::{Read, Length, CurrentDateTime}`, exactly as any
  other session's host would. `read_manifest`/`read_manifest_from_file`
  (`src/drive.rs`) are one such host, for a caller with plain
  synchronous `Read + Seek` access and no need for anything but the wall
  clock; a host with async, network-backed, or cached access, or its own
  clock, drives `FileReadSession` directly instead (see
  [`contentauth-c2pa-file-reader`](contentauth-c2pa-file-reader/examples/custom_host.rs)'s
  example). Read-only; a future orchestrator crate would cover writing.
- **`contentauth-c2pa-file-builder`** — the write-side mirror of the
  crate above: `FileBuilderSession` (`src/session.rs`) is a sans-I/O
  session that composes a `FormatHandler`'s `plan_embed`/`commit` with a
  `BuilderSession`, without ever buffering the source or output asset
  itself — it never calls `EmbedPlan::materialize` (the in-memory
  reference implementation), instead walking a plan's edits directly,
  after independently checking the plan itself (`EmbedPlan::check`
  against a freshly asked source length) rather than trusting a
  `FormatHandler` it does not control to have validated its own output.
  It answers `ReservePlaceholder` and `CommitManifest` by issuing
  `FileBuilderRequest::Read` against `SOURCE_STREAM` and
  `FileBuilderRequest::Write` against `OUTPUT_STREAM` for each edit, in
  bounded chunks for a large `Edit::Copy` rather than one host round trip
  sized to the whole range; forwards `AssetBytes` as plain reads of the
  output stream once it has been written (hashing it for the hard binding
  without holding it in memory), but answers `AssetLength` from the
  plan's own known output length rather than asking the host, so a
  reused, longer-than-needed output stream can never leak stale trailing
  bytes into the hash — though those bytes are still physically present
  in `output` afterward for anyone who reads it back directly rather than
  trusting only what the manifest declares; `build_and_sign`'s own doc
  comment tells a caller who cares to pass a stream that starts empty —
  and only `Sign`/`Timestamp` ever reach the host as themselves, since
  nothing in this workspace can sign or timestamp on a host's behalf.
  `build_and_sign`/`build_and_sign_file` (`src/drive.rs`) are one such
  host, for a caller with plain synchronous `Read + Seek` source access,
  `Read + Write + Seek` output access (read-back is needed for the
  hashing above), and a plain signing function; a host with async or
  network-backed access drives `FileBuilderSession` directly.
  `build_and_sign_with_timestamp`/`build_and_sign_file_with_timestamp`
  additionally take a function answering each `Timestamp` request (digest
  in, bare `TimeStampToken` out), while the plain entry points refuse one
  rather than silently produce an untimestamped manifest. The shared
  `contentauth_c2pa_primitives::tsa` module encodes the RFC 3161
  `TimeStampReq` and unwraps the `TimeStampResp`, so every binding below
  leaves only the HTTP `POST` to its host. `build_and_sign_file` builds into a
  freshly, exclusively created (`create_new`, never `create` +
  `truncate`) temporary file with an unpredictable name beside the
  requested output path — never a symlink-followable, guessable one — and
  renames it into place only once the build succeeds, cleaning up the
  temporary file on any failure, rename included, so a failed build never
  corrupts or partially overwrites an existing output file nor leaves
  debris behind. Its own test suite round-trips a signed asset through
  `contentauth-c2pa-file-reader` and checks it reads back as `Trusted` —
  the two crates' only relationship is that both implement the
  `contentauth-c2pa-format` contract.
- **`contentauth-c2pa-rs-compat`** — an experimental compatibility layer
  reproducing a slice of [c2pa-rs](https://github.com/contentauth/c2pa-rs)'s
  own public `Reader` API — same method names and signatures where
  Rust's ownership rules allow it, same `Error::JumbfNotFound`/JSON
  contracts — on top of `contentauth-c2pa-file-reader` and
  `contentauth-c2pa-format-jpeg`, instead of this workspace's own
  `Session` interaction contract. One use case only: `Context` (trust
  anchors) and `Reader::from_context(context).with_file(path)` on a local
  JPEG — the preferred shape, mirroring what c2pa-rs's own docs now
  recommend over its deprecated standalone `Reader::from_file` (kept here
  too, for the same reason) — through to `.json()`, `.validation_state()`,
  and the borrowed `Manifest` accessors it reports (see
  [`src/lib.rs`](contentauth-c2pa-rs-compat/src/lib.rs) for how a
  `Builder` counterpart or additional format handlers would extend this).
  Its own work is entirely that compatibility surface, plus one piece of
  genuinely new plumbing: `src/host.rs`, a [`reqwest`](https://docs.rs/reqwest)-backed
  host that `with_file` drives `FileReadSession` through directly (rather
  than `contentauth-c2pa-file-reader`'s own convenience function) so it
  can answer a live OCSP check with a real HTTP request — deliberately the
  only crate in this workspace with a network dependency; every other
  read/validation behavior underneath it already existed.
- **`contentauth-c2pa-js-compat`** — the same experiment for the *other*
  public surface built on c2pa-rs: the Rust side of the C2PA web SDK,
  [c2pa-js](https://github.com/contentauth/c2pa-js)'s `c2pa-wasm`
  package, whose `WasmReader::fromBlob(format, blob, contextJson)` is an
  `async fn` handed to JavaScript as a `Promise`. `Reader`
  ([`src/reader.rs`](contentauth-c2pa-js-compat/src/reader.rs)) mirrors
  `WasmReader` method for method (`from_blob`, `active_label`,
  `manifest_store`, `active_manifest`, `json`), and `Error` reproduces
  c2pa-wasm's error-string contract down to the `C2pa(JumbfNotFound)`
  string c2pa-web maps to `null`. The point of the crate is *where the
  async lives*: `read_manifest` (`src/drive.rs`) is an async host that
  drives a `FileReadSession` with an `.await` at every request — asset
  bytes included, through a `Blob` trait shaped after `Blob.size` and
  `Blob.slice().arrayBuffer()` — and a `Platform` trait for the clock
  and OCSP (what c2pa-rs gets from its platform implicitly, and a
  sans-I/O engine must be handed explicitly). Nothing below this crate
  is async, and nothing below it changed; the engine it drives is the
  very one `contentauth-c2pa-rs-compat` drives synchronously, which its
  tests check by comparing the two hosts' answers. Its `web` feature,
  compiled only for `wasm32-unknown-unknown` (the dependencies it
  enables are declared for that target alone), adds `src/web.rs`: `Blob`
  for `web_sys::Blob`, a `Date.now()`-backed `WebPlatform`, and a
  `#[wasm_bindgen]`-exported `WasmReader` with c2pa-wasm's own JavaScript
  names — the one module in the workspace that names a wasm-bindgen type.
  CI holds it to `cargo check --all-features --target
  wasm32-unknown-unknown`; there is no browser to run it in. Tests use a
  hand-rolled executor (no async runtime dependency anywhere) with a
  `Blob` whose reads genuinely suspend, and show that two reads on one
  thread interleave at every request boundary — the cooperative yielding
  c2pa-wasm's `FileReaderSync`-backed, Worker-only stream cannot do.
- **`contentauth-c2pa-node-compat`** — the same experiment for
  c2pa-node's Rust side (a Neon addon in
  [`c2pa-js/packages/c2pa-node`](https://github.com/contentauth/c2pa-js/tree/main/packages/c2pa-node)),
  made on the opposite premise from `contentauth-c2pa-js-compat`: Rust
  does *no* async work at all. `NodeSession` (`src/session.rs`) is a
  purely synchronous `advance`/`fulfill`/`finish` wrapper over
  `FileReadSession` with the engine's types flattened to plain data
  (`PendingRequest`, `Reply`); Node, which owns the event loop, the
  filesystem and `fetch`, runs the loop and every asynchronous operation
  itself. c2pa-node's own addon instead runs whole reads on a process-wide
  tokio pool behind a `Mutex<Reader>`. Settings, JSON reporting, and the
  error-string contract are reused from `contentauth-c2pa-js-compat`
  (which exports `for_format`, `ManifestStore::from_report` for this).
  Tests drive it with a plain synchronous loop and compare against the
  async host's output.
- **`c2pa-node-compat-addon`** — the Neon `cdylib` (four synchronous
  functions) and the JavaScript driver (`index.mjs`) for the crate above,
  with `node:test` tests and a lag demo. Deliberately **not** a workspace
  member (own `[workspace]`): a Neon `cdylib` cannot link outside Node, so
  CI builds and tests it in its own `node-addon` job
  (`npm run build && npm test` in that directory).
- **`contentauth-c2pa-sign-baseline`** — the *baseline signing case*
  every binding of the write path is held to: sign a JPEG with ES256 from
  a c2pa-rs-shaped JSON definition (title, one generator, one
  `c2pa.actions.v2`/`c2pa.created` assertion) and read it back `Trusted`.
  Holds only the language-free part (`Definition` → `BuilderSettings`) and
  shared test fixtures (`fixtures` feature). `instance_id`/`label` are
  required in the definition: the engine has no RNG. An optional `ta_url`
  (c2pa-rs's name) opts in to an RFC 3161 timestamp — the one extension
  every binding offers, outside the baseline bar. Each binding leaves only
  the HTTP `POST` to its host (a blocking `Signer` method with a `reqwest`
  default in `-rs-compat-sign`; an awaited `AsyncSigner` method, or a JS
  `sendTimestampRequest`, in `-js-compat-sign`; a `timestamp` request
  Node answers with `fetch` in `-node-compat-sign`).
- **`contentauth-c2pa-rs-compat-sign`**, **`contentauth-c2pa-js-compat-sign`**,
  **`contentauth-c2pa-node-compat-sign`** + **`c2pa-node-sign-addon`** —
  the baseline case through each binding, as new crates beside (not
  inside) the read-side ones: a blocking c2pa-rs-shaped `Builder`/`Signer`;
  an async `Builder` with an `AsyncSigner` (a JS `Promise` under the `web`
  feature's `WasmBuilder`, `wasm32-unknown-unknown` only, unrun in a
  browser); and a purely synchronous `NodeBuildSession` that Node drives,
  Node owning the files and the signing key. The addon is, like the reader
  addon, outside the workspace with its own CI job (`node-sign-addon`),
  whose tests load the reader addon to read back what was signed. Ordinary
  member crates pass the Wasm checks above, except `-rs-compat-sign`, whose
  default timestamp transport is a network dependency.
- **`c2pa-rs-compat-conformance`** — a differential test harness for the
  crate above, proving the same client code gets the same answer reading
  a file through the real `c2pa` crate as through
  `contentauth-c2pa-rs-compat`'s `Reader`, and generalizing that to a
  whole directory of assets (`examples/compare_corpus.rs`) as the seam for
  running the comparison at the scale of a real corpus. Deliberately
  **not** a member of this workspace (it has its own `[workspace]` in its
  `Cargo.toml`) — see its own README: the real `c2pa` crate is heavy and
  under no obligation to satisfy this workspace's Wasm/MSRV/`cargo-deny`
  checks, which all run unscoped over every listed member.

Container-format handling is deliberately *outside* the reader and
builder: they ask their host for "the manifest store's bytes" and to
"embed this placeholder and report the range of the container structure
carrying it, framing included". A format handler crate answers those
questions; a host that knows what format it is handling picks the
handler. New format = new crate implementing `FormatHandler` and passing
`contentauth_c2pa_format::test_util::conformance::run_all`; nothing in
the reader, builder, or contract crate changes.

## Specification reference

[`reference/c2pa-spec`](reference/c2pa-spec) holds a pinned
snapshot of the C2PA Technical Specification's `.adoc` source (currently
version `2.4`), for reference only — nothing in this workspace builds or
depends on it. See its own README for provenance and license (CC-BY-4.0,
distinct from the rest of this repository's MIT OR Apache-2.0 terms).

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
unmodified, enforced in CI over the whole workspace except
`contentauth-c2pa-rs-compat` and `contentauth-c2pa-rs-compat-sign`, which
are exempt: they deliberately own this workspace's only real network
dependencies (the former's default `reqwest`-backed OCSP host, the latter's
default `reqwest`-backed RFC 3161 timestamp transport), neither sans-I/O nor
Wasm-portable:

```sh
cargo check --all-features --target wasm32-unknown-unknown --workspace --exclude contentauth-c2pa-rs-compat --exclude contentauth-c2pa-rs-compat-sign
cargo check --all-features --target wasm32-wasip2 --workspace --exclude contentauth-c2pa-rs-compat --exclude contentauth-c2pa-rs-compat-sign
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
