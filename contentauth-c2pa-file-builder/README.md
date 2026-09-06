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
drives it. It never buffers the source or output asset itself — it never
calls `EmbedPlan::materialize` (the in-memory reference implementation
for turning a plan into bytes); instead it walks a plan's edits directly,
issuing a `FileBuilderRequest::Read` against `SOURCE_STREAM` for each
range it needs to copy through and a `FileBuilderRequest::Write` against
`OUTPUT_STREAM` for every byte it produces. `AssetLength`/`AssetBytes` —
needed to hash the output for the hard binding — are forwarded the same
way, as plain reads of the output stream once it has been written. Only
`Sign` and `Timestamp` ever reach the host as themselves: a signing key
and an RFC 3161 authority round trip are not things this crate, or any
format handler, can stand in for.

`build_and_sign` and `build_and_sign_file` are a host for exactly that
session, for the common case: a caller with plain, synchronous
`Read + Seek` access to the source asset, `Read + Write + Seek` access to
write the output (read-back is needed for the hashing above), and a plain
signing function — no timestamping. `build_and_sign_file` additionally
never leaves a partial or corrupt file at the requested output path: it
builds into a temporary file beside it and renames that into place only
once the build succeeds, deleting the temporary file on any failure
instead.

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
println!("manifest store is {} bytes", report.manifest.len());
# Ok::<(), contentauth_c2pa_file_builder::Error>(())
```

## What this does not do

It builds one manifest into one asset — no ingredients, no update
manifests, no policy for an asset that already carries a store
(`plan_embed` always replaces it). A host that needs any of that wants a
future orchestrator crate able to juggle more than the two streams
(source, output) this one already does.

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
