# contentauth-c2pa-file-reader

Reads and validates a C2PA manifest store directly from a file — or any
byte buffer already in memory — for any container format with a
[`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler`.

## Why this crate exists

[`contentauth-c2pa-reader`](../contentauth-c2pa-reader)'s `ReadSession`
never touches a container format: it asks its host for "the manifest
store's bytes" and expects an answer. A `FormatHandler` (such as
[`contentauth-c2pa-format-jpeg`](../contentauth-c2pa-format-jpeg))
answers exactly that question through `FormatHandler::locate` — but
nothing in either crate connects the two, by design (see the root
[README](../README.md)). Until now, that connection was hand-written host
glue duplicated in each format handler crate's own end-to-end tests.

This crate is that glue, generalized to any handler and published as
reusable code instead of test scaffolding: `read_manifest` and
`read_manifest_from_file` hold the whole asset in memory, run a handler's
`locate` operation over it to find the manifest store, then drive a
`ReadSession` over the same bytes — answering `ManifestStore`,
`AssetBytes`, `AssetLength`, and `CurrentDateTime` itself.

```rust,no_run
use contentauth_c2pa_file_reader::{read_manifest_from_file, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;

let report = read_manifest_from_file(&JpegFormat, "photo.jpg", ReadSettings::default())?;
println!("{:?}", report.validation_state);
# Ok::<(), contentauth_c2pa_file_reader::Error>(())
```

## What this does not do

It reads the whole asset into memory up front rather than streaming it,
and it only reads — nothing here embeds a manifest store. A production
host reading gigabyte-scale video, or writing as well as reading, wants
more than this: streaming I/O, and the two-stream (source/output) model a
future orchestrator crate would provide. For a manifest store in an
already-loaded image or document, this is enough.

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
