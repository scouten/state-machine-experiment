# JPEG — security fix porting status

Part of [Porting security fixes from c2pa-rs to the state-machine SDK](README.md).

Covers the JPEG handler
([`contentauth-c2pa-format-jpeg`](../../contentauth-c2pa-format-jpeg)). Regression
tests live in
[`tests/jpeg_handler.rs`](../../contentauth-c2pa-format-jpeg/tests/jpeg_handler.rs).

## Why most JPEG exploits don't reach this handler

The JPEG handler shares the TIFF handler's shape:

- **The reader is a minimal locator.** It walks marker segments `SOI`→`SOS`,
  reading only segment headers and `APP11` contents (never image/scan data), and
  reassembles the manifest store through a **single** path (`manifest_run`) that
  insists on exactly what the spec requires: one store, packets `1..=n` without
  gaps, **physically adjacent**, each continuation repeating the superbox header,
  and the total matching the box's `LBox`. Anything else is refused.
- **The writer splices.** `plan_embed` reproduces the source with the old store's
  segments dropped and new ones inserted; `commit` only verifies. Nothing is
  re-serialized.
- **Sans-I/O.** The host answers bounded `IoRequest::Read`s; the handler never
  allocates a read buffer from a length field.

## Summary

| c2pa-rs PR | Vulnerability (JPEG) | Verdict | Regression test |
|---|---|---|---|
| [#2610](https://github.com/contentauth/c2pa-rs/pull/2610) | Non-contiguous C2PA `APP11` segments widen a recomputed data-hash exclusion (validation bypass) | **Already enforced** | `a_foreign_app11_between_cai_segments_breaks_contiguity_and_is_refused` |
| [#2687](https://github.com/contentauth/c2pa-rs/pull/2687) | Panic encoding an oversized XMP `APP1` segment on the remote-URL write path | **Not applicable** + **already enforced** | `segment_headers_encode_their_length` (existing) |

## Details

### #2610 — non-contiguous `APP11` segments · Already enforced

**Exploit.** When an active update manifest inherits a data hash, c2pa-rs
recomputes the manifest-store exclusion by **summing the lengths of every
same-`EN` `APP11` segment** — but that measurement path did *not* enforce the
reader's `1..=n` packet sequence or physical contiguity. An attacker placing a
foreign `APP11` segment between two CAI continuation segments got its bytes
counted into the (unhashed) exclusion while the asset still validated — a
tampered asset reading valid (spec 15.12.1 bypass). The fix makes the
measurement reject an out-of-sequence or non-contiguous CAI continuation,
mirroring the reader.

**Why already enforced here.** The defensive check the fix adds is already the
behaviour of this handler's **single** locate path. `manifest_run` requires each
manifest-store continuation to be the next packet in sequence *and* physically
adjacent to the one before it:

```rust
// packet numbered 1..=n, no gaps:
if part.preamble.z != expected_z { /* "packet {expected_z} is missing or duplicated" */ }
// physically adjacent to the previous packet:
if part.range.start != previous_end { /* "packet {expected_z} is not adjacent to the one before it" */ }
```

plus the superbox-header-repeat and `LBox`-total checks. There is no separate,
weaker exclusion-measurement path to diverge from the reader. A foreign `APP11`
wedged between two CAI segments makes them non-adjacent, so the store **cannot be
located at all** — the attack's precondition (a validatable asset with foreign
bytes inside the store run) can't even be constructed.

This is stronger than the TIFF half of the same PR (tracked as *latent* on the
TIFF page, added by a separate PR): there, a forged IFD `count` still locates a valid-but-wider
store, so the bound matters once exclusion recomputation exists; here, the
non-contiguous run is rejected outright.

**Forward-looking.** Update manifests / inherited data hashes are not
implemented (see [09-future.md](../walkthrough/09-future.md)); when they are, the
recomputed exclusion must be derived from `locate`'s contiguous range rather than
re-summing `APP11` segments independently, so this enforcement keeps applying.

### #2687 — panic on oversized XMP `APP1` write · Not applicable + already enforced

**Exploit.** A write-path panic. On the remote-URL signing path, c2pa-rs enlarges
the XMP (adds the provenance URL) and builds a *single* `APP1` segment; when the
signature-prefixed XMP exceeds the `APP1` payload limit (65533 bytes), encoding
the `u16` length field overflowed and panicked (exit 101). The fix rejects
oversized XMP with an error. c2pa-rs notes its CAI/`APP11` write path already
chunks to 64000 bytes and is unaffected.

**Why not applicable / already enforced.** Two independent reasons:

- **No XMP/`APP1` write path exists.** This handler never writes XMP, `APP1`,
  provenance URLs, nor has a remote-URL signing path (it does not even parse
  XMP). The specific vulnerable code — enlarge XMP, build one oversized `APP1` —
  has no analogue.
- **The analogous `APP11` length encoding is already fallible.** The one place
  that encodes a JPEG segment's `u16` length, `segment_header`, does exactly what
  the fix prescribes — reject rather than panic:

  ```rust
  let le = u16::try_from(2 + PREAMBLE_LEN + payload_len)
      .map_err(|_| FormatError::InvalidPlan("an APP11 segment's payload exceeds what its length field can express"))?;
  ```

  reinforced by the crate's `#![deny(clippy::panic/unwrap/expect)]`, and the
  store write chunks at `CHUNK_LEN = 64_000` so it never approaches the limit
  (the same reason c2pa-rs's CAI/`APP11` path is "unaffected"). The existing unit
  test `segment_headers_encode_their_length` already pins the PR's exact boundary
  (largest payload succeeds; one byte over returns `InvalidPlan`), so no new test
  was added.
