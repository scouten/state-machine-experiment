# contentauth-c2pa-format-riff

RIFF container support for the sans-I/O C2PA sessions in this workspace: a
[`contentauth-c2pa-format`](../contentauth-c2pa-format) `FormatHandler`
that locates a manifest store in a WAV, AVI, or WebP file's `C2PA` chunk
and plans embedding one. The third format handler, chosen for **size**:
where JPEG and TIFF files are small, RIFF files can be gigabytes, and what
is cheap to do to them is what decides whether the whole pipeline is.

## Why RIFF is the simplest container to embed in

A RIFF file is a 12-byte header (`RIFF`, the size of everything after
those eight bytes, a form type) followed by chunks: a FourCC, a
little-endian `u32` data size, the data, and a pad byte if the size is
odd. The C2PA specification puts the manifest store in the data of a chunk
with the FourCC `C2PA`, "the last sub-chunk of the first RIFF header
chunk". So:

* nothing already in the file moves — the new chunk is appended;
* the only byte outside the new chunk that depends on the embedding is the
  header's size field, and it depends on the store's **length**, not its
  content, which is known from the moment the placeholder is chosen.

The output is therefore a pure function of the source and the length: a
rewritten 12-byte header, the source's chunks copied through, and the new
chunk's framing around the store. That is what lets
[`contentauth-c2pa-file-builder`](../contentauth-c2pa-file-builder) hash the
output as it writes it, in one pass, without reading it back — see
[`asset-io-comparison`](../asset-io-comparison) for what that buys.

## What it does

Both operations share one scan: read the 12-byte header, then walk the
top-level chunks, reading chunk *headers* only (many per read — a 4 KiB
window at a time, so a file of thousands of tiny chunks is not a round trip
each) and, for `locate`, the `C2PA` chunk's data.

| Operation | Behavior |
|---|---|
| `locate` | Reports the `C2PA` chunk's data, with the whole chunk (header, data, pad) as its range — what a re-embed replaces — and, as the hard binding's exclusion, the chunk's **8-byte header and data, but not the pad byte after odd data**. Refuses a second `C2PA` chunk, and a store over 256 MiB. |
| `plan_embed` | A rewritten header (the new size), `Copy` edits for every chunk but an existing `C2PA` one, a pad byte if the last chunk lost its own, then the new chunk — header, `Placeholder`, pad if odd — and finally whatever followed the RIFF chunk in the source. |
| `commit` | Nothing to patch; verifies the store's length. |

### The exclusion

c2pa-rs excludes the chunk's header and data and hashes the pad byte, and
it validates a file only against the range it would itself have written:
the alternative — hash the 8-byte header and exclude the data and pad byte,
as `asset-io` does — reads as `Invalid` in c2pa-rs 0.91. This crate follows
c2pa-rs, and `c2pa-rs-compat-conformance/tests/compare_riff.rs` pins it in
both directions, at both parities of the store's length.

## What it does not do

* Parse XMP: a `dcterms:provenance` reference to a remote store is not
  reported, and a WebP `VP8X` header's XMP flag is not touched (no XMP is
  written).
* RF64 / BW64, or any RIFF chunk past 4 GiB — sizes are 32-bit
  (`FormatError::Unsupported`).
* Files whose RIFF size field disagrees with their length other than by
  extra bytes after the RIFF chunk (`FormatError::Malformed`). Those extra
  bytes — a trailing tag, or a later `RIFF` chunk in an extended AVI — are
  carried through after the new chunk and stay outside the size field.

Four null bytes between top-level chunks (VLC's AVI muxer leaves them for
alignment) are skipped; a final chunk missing its pad byte is tolerated.

## Tests

* [`tests/riff_handler.rs`](tests/riff_handler.rs) runs the contract's
  conformance suite on a WAV, an AVI-shaped file, and a header-only file,
  each with an even and an odd store, and checks the layout byte for byte:
  the store last, everything else untouched, trailing bytes preserved, a
  mid-file store moved to the end.
* The unit tests in `src/` cover the scan (windowing, null alignment,
  missing pad, malformed input) and the plan (size field, pad, impossible
  stores).
* [`c2pa-rs-compat-conformance`](../c2pa-rs-compat-conformance) holds it to
  the real c2pa-rs, and
  [`contentauth-c2pa-file-builder`'s `tests/riff_one_pass.rs`](../contentauth-c2pa-file-builder/tests/riff_one_pass.rs)
  signs WAVs through it end to end and reads them back `Trusted`.

## Building

```sh
cargo test
```
