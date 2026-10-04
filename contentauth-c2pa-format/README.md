# contentauth-c2pa-format

The contract between the sans-I/O C2PA sessions in this workspace and the
container formats (JPEG, PNG, …) their manifests live inside.

[`contentauth-c2pa-reader`](../contentauth-c2pa-reader) and
[`contentauth-c2pa-builder`](../contentauth-c2pa-builder) know nothing about
container formats: the reader asks its host for "the manifest store's
bytes", and the builder asks its host to "embed this placeholder and tell
me where it landed". This crate is where that knowledge plugs in — one
crate per format, each implementing `FormatHandler`, none of which the
reader, the builder, or this crate ever depend on. Third parties can ship a
handler for a format this workspace has never heard of, and a host that
knows what it is reading or writing picks the handler itself. (Sniffing a
format at run time is host-side work, in
[`contentauth-c2pa-format-registry`](../contentauth-c2pa-format-registry);
nothing here depends on it.)

## What a handler is

A `FormatDescriptor` — the format's name, media types, file extensions
and byte signatures, as plain data with no code behind it, so a host can
decide *which* handler an asset wants without running any of them — and
three operations, all format-specific, all pure:

| Operation | Produces | Purpose |
|---|---|---|
| `locate(stream)` | `ManifestLocation` | The manifest store's exact bytes and the range of the container structure carrying it (or a remote reference, or neither). |
| `plan_embed(stream, manifest_len)` | `EmbedPlan` | How to rewrite the asset so a store of that length is embedded: copy these source ranges, emit this framing, leave these `Placeholder` slots — replacing any store already present, and saying so. |
| `commit(plan, manifest)` | `Vec<Patch>` | Once the final store bytes are known, the output bytes that depend on them (a PNG chunk's CRC); nothing at all for JPEG. |

The first two read the asset, so each is itself a session built on
[`contentauth-state-machine`](../contentauth-state-machine), speaking the
one request vocabulary this crate defines — `IoRequest::Read` and
`IoRequest::Length`. A handler never writes: it *describes* the output,
and the host (or an orchestrating session) materializes it.

## Why plans rather than writes

Everything that crosses the handler boundary is plain data — byte ranges,
byte vectors, plans, patches. No callbacks, no borrowed streams. That is
what makes a handler testable against a byte slice, what lets an
orchestrating session compute a hard-binding hash straight from the plan
without the output ever being written, and what keeps the boundary
crossable by a handler implemented in another language.

## Invariants

`EmbedPlan::check` enforces the structural ones: every `Placeholder` slot
lies inside one of the plan's exclusions, no copied asset byte lies inside
any, and together the slots cover the manifest exactly once, in order.
A plan's `exclusions` are a *list* — one range for JPEG, two for TIFF,
whose specification excludes a length field apart from the store — because
real validators compare them exactly: a handler reports what its format's
specification calls for, not a convenient superset. Two more are the handler's to honor and
the conformance suite's to check:

* Every `Patch` from `commit` lands inside an exclusion
  (`EmbedPlan::excludes`) — anything outside them has already been hashed
  into the hard binding.
* Embedding into an already-signed asset *replaces* the store and reports
  the replaced range in `EmbedPlan::replaced`. Whether replacing is
  acceptable, or whether the old store should be validated and carried
  forward as a parent, is the caller's policy, not the handler's.

## Writing a handler

Implement `FormatHandler` in a crate of your own, depending only on this
crate (and `contentauth-state-machine` / `contentauth-c2pa-primitives` for
the session and range types). Enable this crate's `test-util` feature in
your dev-dependencies and run `test_util::conformance::run_all` against
your handler with an unsigned sample asset. See
[`contentauth-c2pa-format-jpeg`](../contentauth-c2pa-format-jpeg) for a
complete handler, and this crate's own
[`tests/conformance_kit.rs`](tests/conformance_kit.rs) for the smallest
possible one.

## Building

```sh
cargo test --features test-util
```

Minimum supported Rust version: 1.88.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.
