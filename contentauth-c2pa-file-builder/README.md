# contentauth-c2pa-file-builder

Builds and signs a C2PA manifest store for any container format with a
[`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler` —
the write-side counterpart to
[`contentauth-c2pa-file-reader`](../contentauth-c2pa-file-reader).

## Why this crate exists

[`contentauth-c2pa-builder`](../contentauth-c2pa-builder)'s
`BuilderSession` never touches a container format: it asks its host to
embed a placeholder manifest and report where it landed
(`BuilderRequest::ReservePlaceholder`), then to commit the final one over
the same range (`BuilderRequest::CommitManifest`). A `FormatHandler`
answers exactly those questions through `FormatHandler::plan_embed` and
`FormatHandler::commit` — but nothing in either crate connects the two, by
the same design that keeps `contentauth-c2pa-reader` apart from its own
format handlers (see the root [README](../README.md)).

This crate is that glue for the write side.

## Two ways to use it

`FileBuilderSession` is the primary interface: a sans-I/O session that
composes a handler's `plan_embed`/`commit` with a `BuilderSession` and
speaks a small request vocabulary, `FileBuilderRequest`, to whatever host
drives it. `ReservePlaceholder`, `AssetLength`, `AssetBytes`, and
`CommitManifest` are all answered internally — this session holds the
source asset, and the output it is assembling, in memory once read, so
none of that needs to leave the session. Only `Sign` and `Timestamp` ever
reach the host: a signing key and an RFC 3161 authority round trip are
not things this crate, or any format handler, can stand in for.

`build_and_sign` and `build_and_sign_file` are a host for exactly that
session, for the common case: a caller with plain, synchronous
`Read + Seek` access to the source asset and a plain signing function —
no timestamping.

```rust,no_run
use contentauth_c2pa_builder::{BuilderSettings, GeneratorInfo, SigningAlg};
use contentauth_c2pa_file_builder::build_and_sign_file;
use contentauth_c2pa_format_jpeg::JpegFormat;

let settings = BuilderSettings::new(
    "image/jpeg",
    "xmp:iid:some-instance",
    "urn:uuid:some-manifest",
    GeneratorInfo::new("my-app", "1.0"),
    SigningAlg::Es256,
    vec![/* DER-encoded certificate chain, signer first */],
);

let report = build_and_sign_file(
    JpegFormat,
    "photo.jpg",
    "photo-signed.jpg",
    settings,
    |_alg, data| todo!("sign `data` with this host's private key"),
)?;
println!("wrote {} bytes", report.asset.len());
# Ok::<(), contentauth_c2pa_file_builder::Error>(())
```

## Why the whole asset, not `Read + Seek`, on the output side

Unlike the reader crate, this one cannot answer `AssetBytes`/`AssetLength`
from a `Read + Seek` source alone: `EmbedPlan::materialize` — the only way
this workspace's contract between a session and a format handler turns a
plan into bytes — takes the whole source asset and produces the whole
output asset, not a range at a time. So `FileBuilderSession` reads the
whole source into memory once (one `Length` and one `Read` to its host),
then holds the growing output itself. A future streaming orchestrator
that hashes straight from the plan, the way `contentauth-c2pa-format`'s
own docs describe, would lift this; nothing here needs the asset to stay
a reasonable size in the meantime except this design choice.

## What this does not do

It builds one manifest into one asset — no ingredients, no update
manifests, no policy for an asset that already carries a store
(`plan_embed` always replaces it). A host that needs any of that wants
the two-stream (source/output) model a future orchestrator crate would
provide.

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
