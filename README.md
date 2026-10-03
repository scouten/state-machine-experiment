# state-machine-experiment

A suite of prototypes exploring synchronous, sans-I/O state machines for
C2PA workflows.

The foundation is [`contentauth-state-machine`](contentauth-state-machine),
a reusable engine for building sessions that never block: a session runs
entirely synchronously and externalizes anything that might need to be
asynchronous (I/O, the network, a clock, signing) to its host through an
explicit request/reply protocol, rather than blocking or spawning. It
carries no C2PA-specific logic of its own — it just distills the session
shape (a request/reply vocabulary trait, request tracking, a protocol-error
vocabulary, and the `advance` / `fulfill` / `finish` interaction contract)
into pieces any subcomponent of a larger workflow can build on
independently.

Concrete C2PA workflows built on top of that engine — reading and
validating a manifest store, generating and signing one, and so on — are
expected to live in their own crates alongside it in this workspace as the
experiment grows.

## Crates

* [`contentauth-state-machine`](contentauth-state-machine) — the
  sans-I/O session engine. See its
  [README](contentauth-state-machine/README.md) for the interaction
  contract and build instructions.
* [`contentauth-c2pa-reader`](contentauth-c2pa-reader) — reads and
  validates C2PA manifest stores, built on top of the engine above. See its
  [README](contentauth-c2pa-reader/README.md) for what it validates and its
  request vocabulary.
* [`contentauth-c2pa-builder`](contentauth-c2pa-builder) — generates and
  signs C2PA manifest stores, the write-side counterpart of the reader.
  See its [README](contentauth-c2pa-builder/README.md) for the two-pass
  hard binding and its request vocabulary.
* [`contentauth-c2pa-primitives`](contentauth-c2pa-primitives) — the
  narrow slice of vocabulary and encoders the reader and builder genuinely
  share.
* [`contentauth-c2pa-format`](contentauth-c2pa-format) — the contract
  between those sessions and the container formats their manifests live
  inside: a `FormatHandler` trait, an edit-plan model for embedding, and a
  conformance suite. Format-specific knowledge lives in one crate per
  format, none of which the reader, builder, or this crate depend on.
* [`contentauth-c2pa-format-jpeg`](contentauth-c2pa-format-jpeg) — the
  first such handler: locating and embedding manifest stores in a JPEG's
  `APP11` segments, byte-compatible with c2pa-rs.
* [`contentauth-c2pa-format-tiff`](contentauth-c2pa-format-tiff) — the
  second handler, for a format JPEG's segment model says nothing about:
  TIFF and BigTIFF (either byte order; DNG too), where the store is a tag
  in a graph of offsets, nothing already in the file may move, and the
  specification's hash exclusion is wider than a segment run.
* [`contentauth-c2pa-format-registry`](contentauth-c2pa-format-registry) —
  the *host's* side of choosing a format: detection by content, extension
  or media type from the plain-data descriptors handlers publish, and a
  type-erased `AnyFormat` that the file sessions take unchanged. Nothing
  below a host depends on it.
* [`contentauth-c2pa-file-reader`](contentauth-c2pa-file-reader) — a
  sans-I/O session gluing a `contentauth-c2pa-format` handler to the
  reader above, plus a `Read + Seek`-based host for it for the common
  case of a caller with plain synchronous file access.
* [`contentauth-c2pa-file-builder`](contentauth-c2pa-file-builder) — the
  write-side mirror: a sans-I/O session gluing a `contentauth-c2pa-format`
  handler to the builder above, plus a `Read + Seek` / `Read + Write +
  Seek` and signing-function host for the common case.
* [`contentauth-c2pa-rs-compat`](contentauth-c2pa-rs-compat) — an experimental
  compatibility layer reproducing a slice of [c2pa-rs]'s own `Reader` API
  (reading a manifest store from a file and reporting it as JSON) on top
  of the crates above, for a caller that wants c2pa-rs's existing surface
  rather than this workspace's `Session` contract.
* [`contentauth-c2pa-js-compat`](contentauth-c2pa-js-compat) — the same
  experiment for the Rust side of the C2PA web SDK, [c2pa-js]'s
  `c2pa-wasm` package: a `Reader` mirroring `WasmReader`'s
  `fromBlob`/`activeLabel`/`manifestStore`/`activeManifest`/`json`,
  whose asynchrony (`Promise`-shaped, asset bytes included) lives
  entirely in this interface-specific layer — an async host awaiting a
  `Blob` and a `Platform` at every request the sans-I/O engine makes —
  and, under a browser-only `web` feature, the `wasm-bindgen` end of it.

Outside the workspace (see its own README for why):

* [`c2pa-rs-compat-conformance`](c2pa-rs-compat-conformance) — a
  differential test harness proving `contentauth-c2pa-rs-compat` reports
  the same thing as the real c2pa-rs `Reader` for the same file, and a
  seam (`examples/compare_corpus.rs`) for running that comparison across a
  whole directory of assets rather than one fixture.

## Specification reference

[`reference/c2pa-spec`](reference/c2pa-spec) contains a pinned
snapshot of the C2PA Technical Specification's `.adoc` source (version `2.4`),
kept for reference alongside the reader and builder crates that implement
it. See its [README](reference/c2pa-spec/README.md) for provenance,
scope, and license — those files are CC-BY-4.0, separate from the MIT OR
Apache-2.0 terms covering the rest of this repository.

## Building

This repo is a Cargo workspace; the usual commands run across all members
from the repository root:

```sh
cargo test
```

Minimum supported Rust version: 1.88.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## License

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT license](LICENSE-MIT), at your option.

[c2pa-rs]: https://github.com/contentauth/c2pa-rs
[c2pa-js]: https://github.com/contentauth/c2pa-js
