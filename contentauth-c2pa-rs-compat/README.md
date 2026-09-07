# contentauth-c2pa-rs-compat

An experimental compatibility layer: a slice of [c2pa-rs]'s public `Reader`
API, reproduced on top of this workspace's sans-I/O read engine instead of
c2pa-rs's own `Store`.

## Why this crate exists

Every other crate in this workspace exposes its own, new interaction
contract (`Session`/`advance`/`fulfill`/`finish` — see the root
[README](../README.md)). That is the right shape for a host willing to
adopt it, but it is not a drop-in replacement for an application already
written against c2pa-rs. This crate explores the other direction: how much
of c2pa-rs's existing, synchronous, blocking-I/O `Reader` surface can be
reproduced faithfully — same method names, same signatures where Rust's
ownership rules allow it, same error/JSON contracts — while everything
underneath it is this workspace's engine.

## What this covers

One use case, worked through end to end: **read and validate a C2PA
manifest store embedded in a local JPEG file, and report the result as
JSON.**

```rust,no_run
use contentauth_c2pa_rs_compat::{Context, Reader};

let reader = Reader::from_context(Context::new()).with_file("photo.jpg")?;
println!("{}", reader.json());
# Ok::<(), contentauth_c2pa_rs_compat::Error>(())
```

`Context`/`Reader::from_context`/`with_file` is the preferred shape here,
matching what c2pa-rs's own docs now recommend over its (deprecated, but
still present on both sides) standalone `Reader::from_file`. Configuring
trust anchors goes through the `Context`:

```rust,no_run
use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader};

let context = Context::new().with_settings(ReadSettings {
    trust_anchors: vec![/* DER-encoded certificates */],
    ..ReadSettings::default()
});
let reader = Reader::from_context(context).with_file("photo.jpg")?;
# Ok::<(), contentauth_c2pa_rs_compat::Error>(())
```

`with_file` locates and validates the manifest store (via
[`contentauth-c2pa-file-reader`](../contentauth-c2pa-file-reader) and
[`contentauth-c2pa-format-jpeg`](../contentauth-c2pa-format-jpeg)), fails
with `Error::JumbfNotFound` if there is none — matching c2pa-rs's own
`Reader::with_file` — and the rest of the API (`json`/`json_checked`,
`validation_state`, `validation_status`, `active_manifest`/`active_label`,
`get_manifest`, `iter_manifests`) is named and shaped after c2pa-rs's
`Reader` and `Manifest`. See `Context`'s own doc comment (`src/context.rs`)
for what it configures and what it deliberately leaves out of c2pa-rs's
own, much larger `Context` (HTTP resolvers, a signer, progress callbacks,
cancellation — none of which apply to this crate's read-only scope).

This crate's own work is entirely that compatibility surface; the read and
validation logic underneath it already existed in this workspace.

## What isn't covered yet, and how it would be

See the crate's top-level doc comment (`src/lib.rs`) for the full list —
`from_stream` and other constructors, more container formats (a new
`contentauth-c2pa-format-*` handler, wired in at `src/format.rs`), a
`Builder` counterpart for the write side, and the parts of c2pa-rs's
`Manifest`/`Ingredient` graph that depend on assertion values
`contentauth-c2pa-reader` does not decode yet.

## Building

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

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.

[c2pa-rs]: https://github.com/contentauth/c2pa-rs
