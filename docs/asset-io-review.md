# Review of `gpeacock/asset-io`, and a plan for a one-pass RIFF handler

> **Update, after building it.** This review was written before the RIFF
> handler existed; the implementation changed three of its claims.
>
> * **The exclusion.** §2 reports asset-io excluding the `C2PA` chunk's data
>   and pad byte and hashing its header, and §5b proposed the same. The real
>   c2pa-rs disagrees: it excludes the chunk's **header and data** and hashes
>   the pad byte, and reads a file with the other convention as `Invalid`.
>   `contentauth-c2pa-format-riff` follows c2pa-rs
>   (`c2pa-rs-compat-conformance/tests/compare_riff.rs`). I did not test
>   asset-io's own output against c2pa-rs; this is about the convention.
> * **The tee.** §5a is implemented: `FileBuilderSession` hashes the output as
>   it is produced and hands the digest to `BuilderSession` in
>   `ReservePlaceholder`'s reply (the request now names the hash algorithm).
> * **The benchmark.** §7 is `asset-io-comparison/`, with results in its
>   README: one pass is at the speed of a bare read-hash-write loop, a few
>   percent ahead of asset-io's `write_with_processing`, and the old read-back
>   shape costs about 20% more. §6's "hash on another thread" row is measured
>   there too (about a third off) and is the obvious next step.
>
> The rest is left as written.

Scope: what `asset-io` does to avoid full-file rewrites and extra passes,
how that maps onto this workspace's `FormatHandler` / `EmbedPlan` /
`FileBuilderSession` contract (with #30 assumed to land roughly as is), and
what a RIFF handler with comparable performance would take.

Read at asset-io commit `d1be4bd`. I did **not** run its benchmarks (see
"Benchmarks"), so nothing below is a measured number.

## 1. How asset-io is built

**Structure.** `Asset::open` runs one `parse` per container and produces a
`Structure`: a `Vec<Segment>`, each with a `kind` (`Header`, `Xmp`, `Jumbf`,
`ImageData`, `Other`), a path, and one or more `ByteRange`s. Everything
downstream (read XMP/JUMBF, exclusion ranges, in-place update, size
prediction) is a query over that list. Bulk data is never loaded: RIFF's
parser seeks past every chunk it does not care about.

**Predicting the output without writing it.** `ContainerIO::
calculate_updated_structure(src_structure, updates)` returns the
*destination* `Structure` — segment offsets and total size — for a given
set of metadata updates. That is what makes one pass possible: everything
that depends on the manifest's *size* (RIFF's size field, BMFF's offset
deltas, the hash exclusion range) is known before a byte is written. A
manifest placeholder has the same length as the final manifest, so size
never changes between hashing and signing.

**Hash while writing.** `write_with_processing` wraps the output in a
`ProcessingWriter`, which calls a user callback with each chunk before
forwarding it to the real writer. `set_exclude_mode(true)` suppresses the
callback for bytes that must not be hashed (the manifest). Boundary and
BMFF-specific events (`begin_segment`, `process_offset`, `process_chunk`
with an mdat id) ride the same callback. The source is read once, the
output written once, and the hasher sees bytes in output order.

**Patch in place.** After the hash is turned into a signed manifest,
`Structure::update_segment` (or `Asset::update_segment_in_place`) seeks to
the placeholder and overwrites it — padding with zeros if shorter, refusing
if longer. Output is never re-read for the manifest.

## 2. RIFF vs BMFF

**RIFF (`containers/riff_io.rs`) needs no fixup pass.** The C2PA chunk is
appended last, so nothing in the file moves. The only manifest-dependent
bytes outside the chunk are the RIFF size field (bytes 4–8), and that is
computed up front from `calculate_updated_structure`:

```rust
pw.write_all(b"RIFF")?;
pw.write_u32::<LittleEndian>((dest.total_size - 8) as u32)?;
```

Existing chunks stream through `std::io::copy` into the `ProcessingWriter`.
The only chunk that is ever edited is WebP's `VP8X` (an XMP flag), and it is
10 bytes. The C2PA chunk's 8-byte header is hashed; its data and pad byte
are in exclude mode. `exclusion_range_for_segment` reports the same range
(data plus pad) for the `c2pa.hash.data` assertion. One read, one write, one
hash, no seek-back.

**BMFF (`containers/bmff_io.rs`) is where offsets bite.** Inserting the
XMP/C2PA `uuid` boxes after `ftyp` shifts `moov`/`mdat`, so `stco`/`co64`
chunk offsets must grow by `delta`, and BMFF v2/v3 hashes include each
top-level box's absolute offset (`offset || data`). His approach:

1. `process_offset(pw.stream_position())` feeds the *output* offset of each
   top-level box into the hash without writing it — so shifted positions
   are accounted for without re-reading.
2. `mdat` (the huge part) is split: its first 16 bytes go to the main hash;
   the rest goes to `process_chunk(MdatChunk{id,…})`, which the caller
   feeds to the Merkle builder (`hash_bmff_mdat_bytes`). Because the
   `mdat` leaves do not include offsets (spec: "the offset shall not be
   included for Merkle tree hashes"), they are valid whatever the shift.
3. After streaming, `bmff_adjust_chunk_offsets(pw.get_mut(), delta)` seeks
   back into the *output* and rewrites each `stco`/`co64` entry in place.
   That patch happens after the box bytes were already hashed from the
   source (unpatched).
4. In `benches/io.rs` the BMFF sign path therefore finishes with
   `builder.update_hash_from_stream(&native_format, &mut output_file)` — a
   second read of the finished output. I infer this is what reconciles the
   patched small boxes, with the multi-GB `mdat` already covered by the
   streaming Merkle pass. (Inference from the bench and write path; I did
   not trace c2pa-rs's implementation.)

So the BMFF trick is *not* "never touch the file twice"; it is "make the
second touch cover only the kilobytes of metadata, never the `mdat`".

Things I noticed that are worth confirming with Gavin, not conclusions:

- The BMFF path patches `stco`/`co64` only; I did not see `iloc`
  (HEIC items), `sidx`, or `tfhd` base offsets adjusted.
- `merkle_root` pairs an odd node with *itself*; the spec text for BMFF
  Merkle trees says balanced trees with NULL padding on the right.
- `read_chunks`/`parallel_hash` mark a whole fixed-size chunk `excluded` if
  it merely overlaps an exclusion, rather than splitting the chunk at the
  exclusion boundary.
- RIFF parse clamps to the declared RIFF size and write drops anything
  beyond it.

## 3. His parallel-hashing work

`parallel_hash`, `parallel_hash_mmap`, `parallel_hash_with` (own file handle
per rayon worker) and `read_with_processing_overlapped` hash fixed-size
chunks independently and combine with `merkle_root`. This is only
meaningful for assertions that *define* a Merkle structure; per the spec in
`reference/c2pa-spec`, that is BMFF (`c2pa.hash.bmff.v2/v3` with `merkle`).
A `c2pa.hash.data` (all of JPEG/PNG/RIFF/TIFF) is one digest over a
byte-stream and cannot be split across threads.

## 4. Where this workspace stands

Today a `FileBuilderSession` embed does, for the whole asset:

| Step | Source read | Output write | Output read |
|---|---|---|---|
| `ReservePlaceholder` (walk the plan's edits) | 1× | 1× | — |
| Hard-binding hash (`AssetBytes` → `HashStream` / `DataHashSession`) | — | — | 1× |
| `CommitManifest` (patches) | — | small | — |

so it is source-read + write + **read-back**, against asset-io's
source-read + write. The design already has what's needed to remove the
read-back: an `EmbedPlan` describes the *whole* output (`Copy` from source,
`Emit` bytes in hand, `Placeholder` excluded by construction — the plan's
own module docs say a host can hash the output without writing it). The
hash is therefore a pure function of the plan and the source; only the
current implementation obtains it by re-reading the written file.

`AssetLength` is already answered from the plan, so stale trailing bytes
can't leak in; that property must be kept.

## 5. Proposal

### 5a. Contract change: fold the hash while copying ("tee")

In `FileBuilderSession`, while walking a plan's edits to write the output,
also feed each piece into the hard-binding hasher *at its output
position*:

- `Copy(range)` chunk read from `SOURCE` → write to `OUTPUT` **and** hash
  (unless the output span of that chunk lies in a plan exclusion — by
  construction `Copy` never does).
- `Emit(bytes)` → write and hash.
- `Placeholder(range)` → write zeros, do not hash.

The builder then needs the digest *handed to it* rather than asking for
`AssetBytes`. The cleanest shape is a push-mode hashing sub-session (the
`DataHashSession` from #30 is pull-mode: it asks for `AssetLength` /
`AssetBytes`; add a mode where the parent supplies bytes in output order).
The existing `HashStream` already tolerates out-of-order arrival with a
bounded window, so reads can still be overlapped by the host; the fold stays
in order. Keep the pull mode for the sidecar and for read/verify.

Properties to preserve (these are things the current tests pin):

- never buffer the source or output (bounded windows only);
- bounded `Copy` chunks (`COPY_CHUNK_LEN`);
- `EmbedPlan::check` before trusting a handler's plan;
- `OUTPUT_STREAM` no longer needs to be readable for hashing (a real
  simplification for hosts: a write-only/streaming sink becomes possible,
  e.g. an HTTP upload), though `CommitManifest` still needs seek-write
  unless the manifest can be signed before the output is flushed (it can't
  here: the signature covers the hash of the bytes before it).

Expected effect: removes one full read of the asset per build. For RIFF/
WAV/AVI that is the whole difference to asset-io.

### 5b. RIFF handler (`contentauth-c2pa-format-riff`)

Fits the existing trait with no change:

- `descriptor`: `RIFF` signature at 0, `WEBP`/`WAVE`/`AVI ` at 8, MIME
  types and extensions as asset-io lists.
- `locate`: read the 12-byte header, then walk chunk headers (8 bytes each,
  skipping payloads) to find `C2PA`. Reads are `IoRequest::Read` of headers
  only; for a 2 GB WAV with a handful of chunks that is a handful of round
  trips. Handle odd-size padding, the VLC-style 4-zero-byte alignment
  asset-io skips, and truncation (clamp to actual length).
- `plan_embed(manifest_len)`: `Copy` of the source (minus any old `C2PA`
  chunk), then `Emit` the new chunk header + `Placeholder` + optional pad.
  The new RIFF size is `Emit`ted in a rewritten 12-byte header, computed
  from `manifest_len`. Exclusion = data + pad per asset-io's
  `exclusion_range_for_segment`, **to be checked against what real
  c2pa-rs writes and expects** (the conformance harness in
  `c2pa-rs-compat-conformance` already does this for TIFF; add RIFF).
  Spec: the chunk is "the last sub-chunk of the first RIFF header chunk".
- `commit`: no patches needed (a pad byte is inside the exclusion).

Limits to state explicitly: RIFF sizes are `u32` (4 GiB cap; RF64/BW64 out
of scope); WebP needs `VP8X` flag handling only if we also write XMP, which
the builder does not.

### 5c. Why RIFF first, and what comes after

RIFF is the right first target:

- WAV/AVI files are the large-file case among flat-hash formats, so it
  measures streaming throughput honestly (unlike JPEG/PNG, which are small
  enough that setup cost dominates).
- Its fixups are trivial (one size field, known in advance), so it isolates
  the contract change in 5a without BMFF's offset problem.
- It is cheap: ~1 crate, a conformance suite we already have.

BMFF/MP4 is the right second target, and the plan model suggests an
approach different from asset-io's. Because `manifest_len` is known at
`plan_embed`, the offset delta is also known then. A BMFF handler can read
`moov` once (small), compute patched `stco`/`co64` (and other offset-bearing
boxes), and `Emit` them already corrected. The output then contains no
post-write patches, the `offset || data` hash is a pure function of the plan,
and asset-io's trailing re-hash of the metadata boxes disappears too. This
needs `Edit` to carry "hash this as the 8-byte output offset, not as data"
for the v2/v3 offsets, which is the real contract question for that format.
Not proposing to design it now.

## 6. Parallel hashing

Honest summary:

| Idea | Applies to | Gain | Cost |
|---|---|---|---|
| Overlap host reads with hashing (reader thread / windowed async reads) | all flat hashes | hides I/O latency; up to ~min(read, hash) | already supported: `HashStream` accepts any-order replies in a window; it is a host choice |
| Hash while writing (5a) | all formats | removes the read-back | contract change above |
| Hash on one thread, write on another | all | hides write latency | host choice |
| Chunk-parallel SHA over a single stream | **none** — SHA-256 over a stream is inherently sequential | — | would change the assertion |
| Merkle leaf hashing in parallel | BMFF `mdat` only (spec-defined) | near-linear in cores until I/O-bound | needs a way to hand independent ranges to a pool; tree shape must match the spec (see §2 note) |
| Hardware SHA (SHA-NI / ARMv8) | all | often the biggest single factor (several×) | confirm the `sha2` backend picks it up in our build; no code |
| Parallelism *across* hashes (ingredients, multiple outputs, a batch) | multi-asset workflows | linear | a host/orchestrator concern |

The sans-I/O shape suggests where it would live: the session never spawns
threads. For Merkle formats it could emit independent `HashRange{stream,
range, alg}` requests and let the host answer them in parallel (a hosts
with rayon does; a Wasm host does not), then combine the replies in order.
That is a small request-vocabulary addition for BMFF later, not needed for
RIFF.

For RIFF the realistic ceiling is: wall time ≈ max(read, SHA-256 throughput,
write), single pass. That is what asset-io reaches, and what 5a reaches.

## 7. Benchmarks

What asset-io has (`benches/io.rs`, criterion): `read_{jpeg,png,heic,webp}`
(open + structure + xmp + jumbf) and `sign_{jpeg,png,heic}`. Observations:

- Fixtures are small (`FireflyTrain.jpg`, `sample1.png/heic/webp`); the
  README's "~10 ms for a 22 MB JPEG" is the only large-ish claim.
- RIFF has a read bench only — no sign bench.
- `sign_*` includes the c2pa crate's settings load, builder construction and
  signing, so it measures the whole stack, not asset-io's I/O.
- The throughput-at-scale story lives in `examples/parallel_hash.rs`
  (GB/s on a user-supplied file), not in criterion.
- I did not run them: the bench needs the `c2pa` 0.83 dependency tree and
  its fixtures; I have no numbers to quote.

Proposed benchmark for this work (a `criterion` bench plus a
`examples/`-style throughput report, in a separate workspace like
`c2pa-core-comparison` so asset-io can be a dev dependency without touching
this workspace's Wasm/MSRV/deny checks):

- Inputs: synthetic WAV at 1 MiB, 100 MiB, 2 GiB (deterministic, generated
  on the fly; a real small WebP/AVI for correctness).
- Variants: (A) current two-pass `build_and_sign_file` with the new RIFF
  handler; (B) same with 5a; (C) asset-io `write_with_processing` + sha2 +
  `update_segment` on the same input; (D) floors: `std::io::copy` of the
  file, and raw SHA-256 of the bytes.
- Metrics: wall time, MB/s, bytes read/written (a counting `Read`/`Write`
  wrapper), peak RSS, allocations (`c2pa-core-comparison` already has an
  `alloc_count` allocator).
- Pass criterion: (B) within ~10% of (C), and both within ~10% of
  max(D); (A) will show the cost of the read-back (≈ +1 read).
- Use a warm and a cold page cache run; the read-back is cheap warm and
  expensive cold, and that difference is the point.

Output equivalence is a precondition: the same input and the same fixed
signing key should give byte-identical manifests from (B) and (C) modulo
timestamps and claim ids, and c2pa-rs must read both as `Trusted`.

## 8. Suggested order

1. RIFF `locate` + `plan_embed` + `commit` against the format conformance
   suite; round-trip via `contentauth-c2pa-file-reader`; conformance
   against real c2pa-rs on WAV/WebP/AVI samples.
2. Baseline benchmark (variant A and D) on the existing two-pass design, so
   the improvement is measured, not asserted.
3. Push-mode hashing + tee in `FileBuilderSession` (5a); rerun.
4. Compare against asset-io (variant C).
5. Then BMFF, with the Emit-corrected-offsets approach.

## 9. Questions for you

- Is RF64/BW64 (>4 GiB) in scope? c2pa-rs and asset-io both stop at 4 GiB.
- OK to depend on asset-io as a dev-dependency (git) in the benchmark
  workspace only?
- Do you want the BMFF follow-up designed now, or only after RIFF numbers?
