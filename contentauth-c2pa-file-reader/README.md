# contentauth-c2pa-file-reader

Reads and validates a C2PA manifest store for any container format with a
[`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler`,
without performing any I/O itself.

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
reusable code instead of test scaffolding.

## Two ways to use it

`FileReadSession` is the primary interface: a sans-I/O session, in the
same style as every other session in this workspace, that composes a
handler's `locate` operation with a `ReadSession` and speaks a single
merged request vocabulary — `FileReadRequest::{Read, Length,
CurrentDateTime, Ocsp}` — to whatever host drives it. `ReadRequest::ManifestStore`
never reaches that host at all: this session answers it internally, from
`locate`'s result. A host that fetches byte ranges over a network, that
already has the asset cached in some other shape, that wants to supply
its own clock instead of the wall clock, or that can answer `Ocsp` with a
real network request, drives `FileReadSession` directly — see
[`examples/custom_host.rs`](examples/custom_host.rs) for one that answers
from memory and reports a fixed instant instead of the wall clock, and
[`contentauth-c2pa-rs-compat`](../contentauth-c2pa-rs-compat)'s `src/host.rs`
for one that answers `Ocsp` with a real, `reqwest`-backed HTTP request:

```sh
cargo run --example custom_host -p contentauth-c2pa-file-reader
```

`read_manifest` and `read_manifest_from_file` are a host for exactly that
session, for the common case: a caller with plain, synchronous
`Read + Seek` access to the asset and no need for anything but the wall
clock. Neither has network access, so both answer `Ocsp` with
`FileReadReply::Failed` — safe, since OCSP checking is fail-open (see
`contentauth-c2pa-reader`'s `ReadSettings::check_ocsp`).

```rust,no_run
use contentauth_c2pa_file_reader::{read_manifest_from_file, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;

let report = read_manifest_from_file(&JpegFormat, "photo.jpg", ReadSettings::default())?;
println!("{:?}", report.validation_state);
# Ok::<(), contentauth_c2pa_file_reader::Error>(())
```

## Why `Read + Seek` rather than bytes

Both the format handler's `IoRequest` and the reader's `ReadRequest` name
an absolute byte range, in no particular order — a large asset can be
hashed out of sequence when its host answers that way, and
`contentauth-c2pa-reader` is explicitly tested against it. `Read + Seek`
is the smallest standard-library shape that answers any such range
without first loading the whole asset into memory: a `std::fs::File`, an
in-memory buffer wrapped in `std::io::Cursor`, or a host's own reader
over whatever storage it actually has, all satisfy it — which is the
point, since this crate does not get to assume what a caller has on
hand.

## What this does not do

It only reads — nothing here embeds a manifest store. A host that also
writes wants more than this: the two-stream (source/output) model a
future orchestrator crate would provide.

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
