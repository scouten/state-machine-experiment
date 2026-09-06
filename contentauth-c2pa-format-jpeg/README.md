# contentauth-c2pa-format-jpeg

JPEG container support for the sans-I/O C2PA sessions in this workspace:
a [`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler`
that locates a manifest store in a JPEG's `APP11` segments and plans
embedding one. The first — and the reference — format handler.

## What it does

A C2PA manifest store rides in a JPEG as one or more `APP11` marker
segments, each carrying a `JP` preamble, a box instance number, a packet
sequence number, and a slice of the store; continuation segments repeat
the store's 8-byte superbox header before their slice. `src/segment.rs`
has the byte layout, and the c2pa-rs conventions (`En = 0x0211`, 64,000
bytes of store per segment) this crate follows so that what it writes is
byte-identical to what c2pa-rs would write.

Both operations share one scan of the marker segments from `SOI` to
`SOS`, reading only headers and `APP11` contents — never image data — so
a large JPEG costs a few dozen small reads regardless of size:

| Operation | Behavior |
|---|---|
| `locate` | Reassembles the store from its segments, insisting on what the specification requires (one store, packets `1..=n`, adjacent, each continuation repeating the superbox header, the total matching `LBox`), and reports it with the range of the whole segment run — framing included, since that is what a `c2pa.hash.data` hard binding written for the file excludes. |
| `plan_embed` | The source with any existing store's segments dropped and new ones inserted where they were; in an unsigned file, right after the last `APP0` (JFIF) segment, or right after `SOI` if there is none. |
| `commit` | Nothing to patch: no byte of a JPEG's framing depends on the store's content except the superbox header continuation segments repeat, which the plan derived from the store's length and which `commit` verifies. |

## What it does not do

* Parse XMP: an `APP1` XMP packet's `dcterms:provenance` reference to a
  remote manifest store is not reported.
* Handle stores framed with JUMBF's 64-bit extended length field, or of
  4 GiB and up (`FormatError::Unsupported`).
* Look past `SOS`: a store placed after the first scan's data would not be
  found. The specification puts it in the header.

## Tests

* [`tests/jpeg_handler.rs`](tests/jpeg_handler.rs) runs the contract's
  conformance suite, locates the store in a JPEG signed by c2pa-rs
  (`contentauth-c2pa-reader`'s `C.jpg` fixture) and checks it is
  byte-identical to c2pa-rs's own copy of that store, and re-signs that
  file.
* [`tests/build_and_read_jpeg.rs`](tests/build_and_read_jpeg.rs) is the
  end-to-end proof: a manifest built and signed by
  `contentauth-c2pa-builder`, embedded through this crate — including one
  large enough to span two segments — and read back through this crate
  by `contentauth-c2pa-reader` as trusted, with the reader's hard-binding
  check confirming the declared exclusion range is the one the signed
  hash was computed over.

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
