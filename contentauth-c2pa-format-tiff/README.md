# contentauth-c2pa-format-tiff

TIFF container support for the sans-I/O C2PA sessions in this workspace: a
[`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler`
that locates a manifest store in a TIFF's IFD tag `0xCD41` and plans
embedding one. Classic TIFF and BigTIFF, either byte order; DNG and other
TIFF-based files too, which are the same structure. The second format
handler, chosen to exercise what JPEG does not.

## What TIFF exercises that JPEG does not

| | JPEG | TIFF |
|---|---|---|
| Shape | A sequence of marker segments | A graph of offsets: header → IFD → next IFD, entries → data anywhere |
| Reads | One sequential walk | Pointer-chasing at offsets *the file dictates*, each checked against the asset length first (loops, truncation and absurd counts are refused, not followed) |
| Byte order | One | Declared by the file, and not the store's own |
| Width | One | Classic (32-bit offsets) and BigTIFF (64-bit), same logic at two widths |
| Embedding | New segments inserted; no byte elsewhere changes | Existing offsets everywhere in the file must stay valid, so nothing may move: the store is *appended* and the one pointer that reaches it rewritten |
| Hard-binding exclusions | One: the segment run | Two, not adjacent: the entry's `count` field (so a later update manifest may change the store's size) and the store — the value offset and next pointer between them stay hashed |
| Alignment | None | IFDs on even offsets (classic) or 8-byte offsets (BigTIFF, whose design asks that all values begin at an 8-byte-aligned address — the store included, so a four-byte hashed pad follows its 36-byte IFD); the source is padded up to it |
| Existing store | Always replaceable | Replaceable only if laid out the way this crate lays one out; one written into the middle of another IFD is read but not replaced |

## The layout it writes

A new IFD holding only the C2PA entry, directly followed by the store,
linked onto the end of the main chain:

```text
 source bytes … │ pad │ entry count │ tag │ type │ count │ value │ next │ pad │ store
                (aligned) =1          CD41   7     └─ ✗ ─┘ ofs→    0   (BigTIFF)└─ ✗ ─┘
                                                 (✗ = excluded from the hash)
```

* Satisfies the specification for every case: a single-IFD file may hold the
  entry in a new IFD following the existing one; a multi-IFD file must
  have it alone in the last IFD; the store belongs at the end of the file.
* The only bytes of the source that change are the last IFD's next-IFD
  pointer, `0` → the new IFD's offset. That edit is *outside* the
  exclusion, so it is hashed into the hard binding: pointing it elsewhere
  to hide the store invalidates the signature (tested).
* Every byte of framing depends only on the store's *length*, which a plan
  is given, so `commit` has nothing to patch.

### What TIFF taught the contract

The specification excludes the entry's `count` field *and* the store from
the hash, and they are not adjacent. `EmbedPlan` first had room for one
exclusion range, so this crate reported one contiguous superset (the two
fields and the offset and next pointer between them). **c2pa-rs rejected
it** — its validator compares exclusions exactly (`assertion.dataHash.mismatch`:
"data hash exclusion does not match the manifest location in the asset") —
which only became visible once the workspace could write a claim c2pa-rs
reads at all.

So `EmbedPlan::exclusion` became `exclusions`, a list, and so did what
carries it: `ManifestLocation`'s `EmbeddedManifest::exclusions` (beside
`range`, which is what a re-embed replaces), the builder's
`PlaceholderReserved` / `CommitManifest` / `BuilderReport`, the
file-builder's report, and the Node signing binding's result
(`exclusions: [{ start, len }]`). The data-hash placeholder reserves room
for `MAX_EXCLUSIONS` of them and pads the difference, since it is embedded
before the host says how many there are. JPEG reports a list of one.

## What it does not do

* Parse XMP: a remote manifest reference is not reported.
* Replace a store that is not in a trailing IFD of its own
  (`FormatError::Unsupported`) — it would mean cutting an entry out of the
  middle of an IFD, or leaving the old store behind as dead bytes.
* Look in sub-IFDs (EXIF, GPS, SubIFD). The specification puts the store in
  the main chain.
* Convert classic TIFF to BigTIFF: a classic TIFF asked to carry a 4 GiB
  store fails `Unsupported`.

## Interoperability with c2pa-rs

`c2pa-rs-compat-conformance` checks both directions against the real
c2pa-rs:

* `tests/compare_tiff_signed_by_c2pa_rs.rs` — c2pa-rs signs a TIFF (its own
  layout, which differs: for a single-page file it clones the first IFD and
  adds the entry among the others), and this crate reads it, through
  `contentauth-c2pa-rs-compat`'s `Reader`, to the same answer c2pa-rs's own
  `Reader` gives, `Valid` included (classic and BigTIFF). So the handler's *reading* is the
  specification's, not just its own writer's. (c2pa-rs looks in the last
  IFD for the entry first and the first IFD second, which finds this
  crate's layout too.)
* `tests/compare_tiff.rs` — a TIFF (classic, multi-IFD, and a 98-byte
  BigTIFF, whose appended IFD and store need alignment padding) signed
  here: c2pa-rs reads it and validates it, to the same answer as this workspace's reader, so it
  accepts the two exclusions above.

## Tests

* [`tests/tiff_handler.rs`](tests/tiff_handler.rs) runs the contract's
  conformance suite in all four byte-order/flavor combinations and with
  several IFDs and odd lengths; checks nothing already in the file moves
  and the exact bytes written; reads a store another tool laid out;
  refuses what is malformed (loops, truncation, bad types, duplicates).
* [`tests/build_and_read_tiff.rs`](tests/build_and_read_tiff.rs) is the
  end-to-end proof: built and signed by `contentauth-c2pa-builder`,
  embedded through this crate, read back by `contentauth-c2pa-reader` as
  trusted — and broken by flipping image data or the rewritten pointer.

## Building

```sh
cargo test
```

Minimum supported Rust version: 1.96.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.
