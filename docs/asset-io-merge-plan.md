# Merging with `asset-io`: findings and a plan

**Status:** proposal for discussion between Eric and Gavin. Nothing here is
committed work.

**Basis:** a read-through of
[`gpeacock/asset-io`](https://github.com/gpeacock/asset-io) at commit
`d1be4bd` (a single-commit history, v0.1.0, ~15k lines of Rust). I read the
code and docs; I did **not** build it, run its tests, fuzz targets or
benchmarks. Every performance number quoted below is Gavin's claim from his
docs, not something I measured. Step 1 of the plan is to measure.

## 1. The two projects in one paragraph each

**asset-io** is a *format layer*: `Asset<R: Read + Seek>` auto-detects a
container (JPEG, PNG, BMFF/HEIC/AVIF/MP4, RIFF), parses it once into a
`Structure` of `Segment`s (byte ranges, possibly several per logical
segment), and reads or writes metadata (JUMBF, XMP, EXIF, thumbnails) against
that structure. It is C2PA-*aware* but not C2PA-*implementing*: `c2pa` is an
optional dependency used only by examples, and the library hands raw JUMBF
bytes across its boundary. Its performance work is the interesting part:
`memmap2` zero-copy slices, single-pass write-and-hash through a
`ProcessingWriter` callback, in-place patching of a same-size manifest
(`update_segment_in_place`), and rayon-based parallel chunk hashing with a
Merkle root, plus cargo-fuzz targets.

**This workspace** is a *protocol layer*: sans-I/O `Session`s (reader,
builder, file reader, file builder) that ask their host for bytes, the clock,
the network and signatures. It implements C2PA validation and generation
itself, keeps format knowledge behind the `FormatHandler` contract
(`locate` / `plan_embed` / `commit`, with plain-data `EmbedPlan`s), supports
JPEG and TIFF, and is bound to Rust, Wasm and Node hosts.

They overlap in exactly one place — "find the manifest in a container, and
embed a new one" — and are otherwise complementary: asset-io has the formats
and the speed work; we have the validation, the builder, the host-agnostic
engine and the bindings. That is why merging is plausible. The hard part is
that they get through the overlap in opposite ways (§3).

## 2. What to take from asset-io, by Gavin's four emphases

### 2.1 Minimal / no-copy reading

What he does: `LazyData::MemoryMapped` and `Structure::get_mmap_slice` return
`&[u8]` straight out of a memory map; segment data is loaded lazily and size
capped (`MAX_SEGMENT_SIZE`, 256 MB); chunk callbacks receive borrowed
`&[u8]`. Caveats worth knowing: `Asset::jumbf()` still returns an owned
`Vec<u8>` (a copy, and for JPEG a reassembly across APP11 segments);
`open_with_mmap` is `unsafe` (the file can change under the map); and
`read_chunks`/`parallel_hash` buffer the *whole file* in memory, which is at
odds with the "O(1) memory" claim in the README (the mmap and
file-handle-per-worker variants do not have this problem).

Where we copy today:

- `ReadHostReply::AssetBytes(Vec<u8>)` and `IoReply` bytes are **owned**
  vectors, so every 64 KiB hash chunk is an allocation plus a copy even when
  the host has the bytes mapped.
- `EmbeddedManifest::jumbf` is an owned `Vec<u8>`, then parsed again by the
  reader.
- `locate` and `plan_embed` each re-read and re-walk the container.

Proposals:

1. **Shared-bytes replies.** Replace `Vec<u8>` in replies with a cheap-clone
   byte handle (the `bytes::Bytes` shape: refcounted, sliceable, and
   constructible from an owner such as an mmap). A host with a map answers
   with a slice of the map; a host with a socket answers with a fresh buffer.
2. **Consume-in-place replies for streaming requests.** For requests whose
   bytes are only folded into a hasher and never retained, add a
   `fulfill_with(id, &[u8])` path that lets the session consume the slice
   immediately. No allocation, no lifetime problem, because the session never
   stores the borrow.
3. **Parse once.** See §2.3.

### 2.2 Fast writing

What he does: (a) single-pass write-and-hash — a `ProcessingWriter` wraps the
output and hands each chunk to a callback as it is written, so the output is
never re-read; (b) `update_segment_in_place` patches a same-size (padded)
manifest into the finished file, so signing a 6.7 GB file costs ~17 KB of
writes instead of a full rewrite (his figures: 21.5 s vs 9.1 s).

What we do: the file builder never buffers, plans before it writes and
chunks large copies, but it **re-reads the output** to compute the hard
binding (the `AssetBytes`-as-reads-of-`OUTPUT_STREAM` design, chosen so
stale trailing bytes in a reused output can never leak into the hash). That
is a full extra read of the asset. And the build always writes a new file.

Proposals:

1. **Tee hashing in `FileBuilderSession`.** The session already holds every
   byte it writes: `Edit::Emit` bytes are its own, and every `Edit::Copy`
   chunk passes through it as the reply to a `Read` before it issues the
   matching `Write`. Hash those bytes at that moment (skipping the plan's
   `exclusions`) and drop the read-back pass. The plan makes the order and the
   excluded ranges known up front, so the hash is identical. This is the
   sans-I/O equivalent of his `ProcessingWriter`, and it needs no callback.
   Keep the read-back as an opt-in "verify what was actually written" mode.
2. **In-place update plans.** Add an `EmbedPlan` shape (or a sibling method)
   meaning "the new store fits in the existing slot: touch nothing but the
   manifest bytes", reporting the slot's capacity. The two-pass builder
   already signs into a fixed-size reservation, so the pieces exist; what is
   missing is a way to skip rewriting the rest of the file when the source
   *is* the output.

### 2.3 Cheap reader → builder conversion

What he does: one `Structure` is produced by `parse`, then reused for reading
(`jumbf()`, `xmp()`), for writing (`write` takes it), and for predicting the
output (`calculate_updated_structure` returns the destination layout —
including where the JUMBF will land — *before* any byte is written). The
output's `Structure` is returned from `write` and used directly for
`update_segment`. Nothing is parsed twice.

What we do: reading and writing are separate crates joined only by the
`FormatHandler` contract. `locate` and `plan_embed` are independent
sessions; a read-then-resign workflow parses the container twice, and the
reader's decoded manifest store has no path into the builder at all (the
builder's biggest known gap is ingredients/parent manifests —
[09-future](walkthrough/09-future.md)). `EmbeddedManifest::jumbf` already
carries byte-exact store bytes for that purpose, but nothing consumes them.

Proposals:

1. **A plain-data `Layout`** in `contentauth-c2pa-format`: the parsed
   segment list (ranges, kinds, handler-private state as data), produced by a
   new `FormatHandler::parse` op and accepted by `locate` and `plan_embed`.
   A host or orchestrator may cache it; a handler that doesn't care can
   ignore it. Gavin's `Structure`/`Segment` is a good starting design, and
   adopting it largely as-is would make porting his parsers cheap.
2. **An orchestrator that does read → decide → build**, carrying the
   `Layout`, the replaced range and the old store forward (ingredient/parent
   policy lives here, as the file-builder README already anticipates).

### 2.4 Fuzzing

What he has: `fuzz/` with three libFuzzer targets (`fuzz_parse`,
`fuzz_write`, `fuzz_xmp`), a `fuzz.sh` wrapper, corpus seeded from test
fixtures, hardening against `unwrap`, size caps for segments/XMP/IFD tags.
His `FUZZING_SETUP.md` is a setup note rather than results: I found no
record of findings, and no CI job running the targets. Treat "hardened" as
"ready to fuzz".

What we have: `deny(clippy::unwrap_used, expect_used, panic)` on the engine
crates and parsers that refuse hostile input by design, but **nothing that
exercises it** (listed under "Proof at scale" in 09-future).

Fuzzing suits the sans-I/O design unusually well, and we can go further than
file-in/no-panic:

- **Session-protocol fuzzing.** Drive `ReadSession` / `BuilderSession` /
  `FileReadSession` with arbitrary host behaviour — arbitrary reply bytes,
  lengths that lie, out-of-order and partial fulfillment, wrong reply
  variants — with no file, thread or clock. The invariant: never panic, never
  allocate more than a bound proportional to *bytes actually received*
  (audit every place a length taken from the input sizes an allocation or a
  `Read` request), always terminate. Determinism makes failures trivially
  reproducible.
- **Handler fuzzing** against the conformance suite: for any bytes that
  `locate` accepts, `plan_embed` + `materialize` must satisfy
  `EmbedPlan::check`, and `locate` on the output must find exactly the
  exclusions the plan declared.
- **Differential fuzzing between the two parsers** on JPEG (and later PNG,
  BMFF): same bytes in, same manifest range and exclusions out, else one of
  us has a bug. Cheap, and it makes the merge's correctness checkable.
- CI: a short smoke run per PR (`cargo fuzz run … -max_total_time=60`) plus a
  scheduled longer run; revisit OSS-Fuzz later.

### 2.5 Multi-threaded hashing and box hash

What he has: three parallel shapes — `read_with_processing_overlapped`
(a reader thread feeding a hasher thread over a bounded channel);
`parallel_hash` (rayon over in-memory chunks); `parallel_hash_mmap` and
`parallel_hash_with` (each rayon worker reads its own range from a map or its
own file handle, the fastest and the only ones that avoid buffering the
file); `merkle_root` to combine leaves; `BmffIO::fragments` to align work to
fragmented-MP4 boundaries; and BoxHash / BmffHash examples in
`examples/c2pa_embeddable.rs`.

What we have: serial, in-order hashing (`hash_stream.rs` keeps up to a
window of chunks in flight but folds them strictly in order), and only
`c2pa.hash.data` is validated or written. Box hash, BMFF hash and Merkle
variants are all open ([03-read-path](walkthrough/03-read-path.md),
[09-future](walkthrough/09-future.md)).

This is the one emphasis where the architectures *conflict*, because our
core crates are required to build for `wasm32-unknown-unknown` and must not
spawn threads. §3.3 covers how to reconcile that; the short version is that
the parallelism lives in the host, and the session supplies independent work
units and combines the results.

## 3. Where Gavin's callbacks clash with this design

You asked specifically about callbacks. asset-io uses them in a handful of
distinct ways, and they are not equally problematic. Taking each in turn:

### 3.1 Inversion of control: the library owns the read loop

`read_with_processing(&updates, &mut |chunk| …)`,
`write_with_processing(writer, &updates, &mut |chunk| …)`, and
`ContainerIO::write_with_processor` all have the *library* drive: it seeks,
reads, writes and calls the user back. Every one of those is generic over
`Read + Seek` (and `Write`) and calls them synchronously.

**Problem:** this is precisely what the sans-I/O design exists to avoid. A
`Read + Seek` library cannot be hosted by a JavaScript `Blob`, an async
network source, or the Node addon (where Node owns the files), because the
library blocks on I/O itself. Everything built on those callbacks — and the
handlers' `parse<R: Read + Seek>` / `write<R, W>` signatures — has to be
re-expressed as requests to be hosted here. The callbacks themselves are not
the obstacle; the generic `Read + Seek` they ride on is (see §4.1).

### 3.2 Error smuggling through a thread-local

`ProcessingWriter::write` can only return `io::Error`, so a failing
callback stashes its real `Error` in a **`thread_local!`**
(`PENDING_PROCESSOR_ERROR`), returns a synthetic `io::Error` whose message
equals a magic string, and `From<io::Error> for Error` recovers the stashed
error by string comparison.

**Problems:**

- It breaks if the conversion happens on a different thread than the
  callback — e.g. any executor that migrates a task between awaits, or the
  overlapped/rayon paths if error conversion ever moves across threads.
  That makes it unusable in the async host (`contentauth-c2pa-js-compat`)
  and in anything that holds a session across an `.await`.
- A stale stashed error from one failed operation can be picked up by an
  unrelated later `io::Error` that happens to match the sentinel.
- It is a hidden coupling: correctness depends on a global rather than the
  type signature.

In our design errors are values: `advance`/`fulfill`/`finish` return
`Result`, and cancellation is "the host stops calling `advance`". This
pattern should *not* be carried over; it is the best argument for the
conversion, not a thing to port.

### 3.3 Callbacks that require threads (`Send + 'static`, `Arc<Mutex<…>>`)

`read_with_processing_overlapped` requires `F: Send + 'static`, spawns a
thread, and communicates over `sync_channel`; the doc example wraps the
hasher in `Arc<Mutex<…>>` and unwraps it afterwards. `parallel_hash*` pulls
in rayon.

**Problems for us:**

- The engine and every non-compat crate must build for `wasm32-unknown-unknown`
  and `wasm32-wasip2`, where there is no `std::thread` and rayon does not
  work without special setup. A session can't spawn.
- `Send + 'static` closures impose their ergonomics on callers (the
  `Arc<Mutex>` dance) and make the hasher *state* a thing the library must
  share across threads — wrong for a pure state machine.
- His own `read_with_processing` says in a comment that it only
  "structures the code for easy threading later" — it isn't actually
  overlapped. The threaded variant is a separate, differently-typed method
  (`F: Send + 'static`), so callers must choose by signature, not by need.
- A panic inside a processor thread would poison the `Mutex` it shares, and
  the surrounding `.lock().unwrap()` calls would then panic in the reader
  thread — contradicting the `deny(unwrap_used)` policy on our side.

**Resolution** (the key design decision of the merge): *work, not
callbacks.* Parallelism is a host capability, expressed in the protocol:

- Add a **digest request** — "hash these ranges of this stream with this
  algorithm; give me one digest per range" — to the file/read/build request
  vocabularies. The session emits it with many independent ranges (leaves of
  a Merkle tree, the boxes of a BoxHash, per-fragment ranges). The *host*
  decides how: a rayon pool over an mmap (Rust), `crypto.subtle.digest` on
  Workers (browser), `worker_threads`/native crypto (Node), or a serial loop
  (the default, and what runs everywhere today). Sessions already accept
  replies "in any order", so parallel completion needs no new machinery.
- The session combines the results (Merkle root, comparison against the
  claim) deterministically.
- **Trust note:** a digest reply asks the host to vouch for a hash. A host
  that controls the bytes can already lie about them, so this adds no new
  trust assumption for a reader; but state it explicitly in the request docs,
  and keep an in-session fallback (the session hashes bytes itself when the
  host answers `Read` instead) for hosts that want the engine to do it all.
- Rayon, mmap and file-handle-per-worker then live in *host* crates
  (`-file-reader`'s `drive.rs`, `-rs-compat`), behind a `parallel` feature,
  never in the engine.

### 3.4 Callbacks as a stream with in-band markers

For BoxHash, the single `ProcessChunkFn` receives a stream of
`&dyn ProcessChunk`, some of which are zero-length **segment-boundary
signals** (`chunk.segment()`), and `MdatChunk`s carrying an `id` and a
`large_size` flag for BMFF. The user closure (see `sign_box_hash`,
`sign_bmff` in `examples/c2pa_embeddable.rs`) is a small state machine that
starts a new hasher on each boundary, skips C2PA segments, and routes mdat
data to a BMFF-specific hasher.

**Problems:** the hard-binding logic is split between the library
(emitting markers) and every caller (interpreting them), the protocol
between the two is implicit in call order, and it is only reachable by
actually writing or reading the file — you can't ask "what will the boxes
be?" without running it. It also tightly couples handlers to the hashing
shape (each format handler must know how to toggle exclusion and emit
markers mid-write, e.g. `begin_segment` in `jpeg_io.rs`).

**Resolution:** make it data. A handler declares the *hash units* of an
asset — named byte ranges, which are excluded, which are BMFF mdat with
their ids/sizes — as part of its `Layout` and `EmbedPlan`; the session walks
them and issues digest requests. This matches how `EmbedPlan` already treats
exclusions (as plain data, testable against a byte slice, hashable before
anything is written) and replaces imperative `set_exclude_mode(true)` calls
interleaved with writes — the least testable part of the asset-io handler
contract.

### 3.5 Callbacks for progress and cancellation

`Error::UserCanceled` returned from a callback stops the operation;
`examples/progress_cancel.rs` shows a UI loop. This is a *good* use of a
callback in a synchronous library and is a feature we lack: 09-future notes
cancellation and progress as natural but untested.

**Mapping:** cancellation is free (stop calling `advance`; drop the
session). Progress becomes an observation rather than a callback: a session
reports `progress() -> {done: u64, total: Option<u64>}`, or a host computes
it from the requests it services. Worth a small test and an example so the
claim is verified rather than asserted.

### 3.6 What is *not* a problem

- Callbacks that are pure per-chunk consumers (`FnMut(&[u8])`) map directly
  onto the consume-in-place fulfillment of §2.1.
- `ProcessChunk::segment()` as *information* (is this C2PA? what are its
  ranges?) is already data on our side (`ManifestLocation`, `EmbedPlan`).
- Callbacks are optional conveniences in his API, not load-bearing for the
  parsers: `parse` and plain `write` have none. The parsing code ports
  cleanly; it is the generic stream access (§3.1) that needs a decision.

## 4. How to merge

### 4.1 The central technical decision: running `Read + Seek` parsers sans-I/O

asset-io's parsers are written as straight-line synchronous code over
`Read + Seek`, and BMFF alone is ~2,600 lines. Rewriting each as an explicit
state machine (as our JPEG/TIFF handlers were) is expensive and risks new
bugs. Three options:

| Option | Idea | Cost / risk |
|---|---|---|
| **A. Rewrite as `FormatOp` state machines** | What JPEG/TIFF did | Highest effort; best result; forks the parsers |
| **B. Restart-on-miss shim** | Run the existing parser against an in-memory cache; when it reads outside the cache, record a request, return to the host, re-run from the start | Cheap; worst case O(n²) for pointer-chasing formats (BMFF box trees); parsers must be deterministic |
| **C. Write parsers once as `async fn` over a `Source` trait** | The future suspends where it awaits a read; a trivial executor (we already hand-roll one in `-js-compat`) turns a suspension into an `IoRequest`; a `Read + Seek` source resolves every future immediately, so the same code is the fast synchronous path | One parser per format serves both worlds; needs a spike to confirm ergonomics, borrowing, and codegen cost |

**Recommendation:** spike **C** on PNG (§5, step 4). If it works, both
projects share one set of parsers, and asset-io's own `Asset<R: Read + Seek>`
API keeps working because a synchronous `Source` makes every await ready.
Fall back to A for formats where C is awkward. B is a stopgap for prototyping
only. This choice should be settled by evidence from the spike, not by
argument.

### 4.2 Repository and crate shape

A reasonable target, keeping `contentauth-state-machine` and the session
crates unchanged in spirit:

```
contentauth-c2pa-format            (contract: + Layout, hash units, digest/borrowed replies)
contentauth-c2pa-format-{jpeg,tiff}  (existing)
contentauth-c2pa-format-{png,riff,bmff}  (new; ported from asset-io)
contentauth-c2pa-format-registry   (existing; gains the new formats)
contentauth-c2pa-file-{reader,builder}   (existing; + tee hashing, digest requests, in-place plans)
asset-io                           (facade: Asset / Updates / Structure-shaped API as a *host*
                                    over the sessions; mmap and rayon live here)
contentauth-xmp / -exif / -thumbnail     (optional, non-C2PA metadata; ported MiniXmp, tiff.rs)
```

The facade matters for the merge: it lets Gavin's existing users keep a
one-call API (`Asset::open(..).write_to(..)`) while the work underneath is
done by sessions — the same relationship `-rs-compat` has to the c2pa-rs
`Reader`. It also keeps his C2PA-agnostic positioning: XMP/EXIF/thumbnail
handling is not C2PA and should stay outside the engine.

Where this lives (this workspace, `contentauth/asset-io`, or a new shared
repo) is a question for the two of you; the code needs only that both are
MIT/Apache-2.0, which they already are. His `Cargo.toml` names
`contentauth/asset-io` as the repository, so confirm the canonical home.

## 5. Plan of action

Ordered so each step is independently useful and the riskiest decisions come
from evidence. Effort is rough (S ≈ days, M ≈ 1–2 weeks, L ≈ several).

1. **Baseline benchmarks (S).** Put asset-io and our `file-reader` /
   `file-builder` behind one benchmark harness (criterion; asset-io's
   `benches/io.rs` is a start) on shared fixtures: a 22 MB JPEG, a large MOV,
   a fragmented MP4. Measure parse time, peak RSS, copies per byte
   (allocation counts), sign time, and hash throughput serial vs parallel.
   *Exit:* we know the real gap, and §2's proposals are ranked by measured
   cost. Gate for every later step: no regression, and the claimed win shows.
2. **Fuzzing, both sides (M, parallelizable with 1).** Port Gavin's
   `fuzz.sh`/corpus approach into this workspace; add the targets from §2.4
   (session-protocol, handler, differential) and a CI smoke job. Triage
   findings in both codebases. *Exit:* CI fuzz job green; allocation-bound
   audit of every untrusted-length path documented.
3. **Contract design doc, then changes (M).** Specify, with sketches and
   migration notes, the `format` and engine changes: shared-bytes replies and
   consume-in-place fulfillment (§2.1); `Layout` + `parse` op (§2.3); hash
   units and digest requests (§3.3, §3.4); tee hashing and in-place plans
   (§2.2); progress. Review together before coding. Per the Stability note in
   `CLAUDE.md`, change APIs in place rather than adding parallel variants.
4. **PNG as the proving spike (M).** Port asset-io's PNG parser (1.3k lines)
   using §4.1 option C, as `contentauth-c2pa-format-png`. PNG is already on
   our "next" list because its chunk CRCs are the first real use of
   `commit` patches. *Exit:* passes the conformance suite and the
   differential fuzzer against asset-io's own PNG output; a go/no-go on
   option C.
5. **Box hash end to end (M).** Implement `c2pa.hash.boxes` in the reader
   (validate) and builder (write) using hash units; JPEG and PNG first, and
   read the spec text in `reference/c2pa-spec` for the exact box-naming and
   exclusion rules rather than inheriting asset-io's reading of them.
   Extend the c2pa-rs differential suite to cover it. *Exit:* a box-hashed
   JPEG and PNG signed here validate in c2pa-rs and vice versa.
6. **Parallel digests (M).** Implement the digest request in
   `file-reader`/`file-builder` with a serial default and a `parallel`-feature
   rayon + mmap host; add a Merkle-tree hard-binding path as the first
   consumer that benefits (his `merkle_root` is a starting point — check it
   against the spec's Merkle rules, since it duplicates the last node on odd
   levels). *Exit:* the step-1 hash benchmark shows the speedup in the host
   and no change in the Wasm builds.
7. **Tee hashing and in-place re-sign (S–M).** Land §2.2. *Exit:* signing
   benchmark no longer re-reads the output; re-signing a same-size manifest
   in a large file writes only the manifest.
8. **BMFF (L).** Port the BMFF handler (HEIC/AVIF/MP4/MOV, fragments,
   `stco`/`co64` adjustment — which here are `Emit`s planned from the known
   store length, not post-write patches, since patches must stay inside the
   exclusions) and implement `c2pa.hash.bmff` including mdat hashing and
   fragment-aligned digest requests. The largest item and the biggest payoff
   (video; the 6.7 GB case). *Exit:* round trips with c2pa-rs; fuzzed.
9. **RIFF, then facade and metadata crates (M).** RIFF (rewrites an existing
   size field, which `Edit::Emit` anticipates); the `asset-io` facade over
   sessions; MiniXmp/EXIF/thumbnails as optional crates; XMP remote-reference
   parsing into `ManifestLocation::remote`.
10. **Retire duplication and update docs (S).** Remove superseded code from
    whichever side loses; update the crate table and dependency graph in
    [02-architecture](walkthrough/02-architecture.md), move done items from
    "next" to "done" in [09-future](walkthrough/09-future.md), and update
    `CLAUDE.md`, as the repo's own rules require for each landing PR.

## 6. Risks and open questions

- **Is the sans-I/O boundary worth its cost on the hot path?** Per-request
  overhead and chunk copies could erase asset-io's advantage for local files.
  Step 1 answers this before we commit; the shared-bytes replies and larger
  digest ranges (one request per megabyte, not per 64 KiB) are the levers.
- **Async-as-coroutine (option C)** may hit borrow-checker or code-size
  friction. Hence the spike, and option A as the fallback.
- **Mmap safety.** `unsafe` is denied in our crates; the map belongs in a
  host crate with a clear contract (file must not be modified while mapped),
  exactly as asset-io documents on `open_with_mmap`.
- **Trust in host-computed digests** (§3.3) must be an explicit, documented
  decision.
- **Scope of asset-io's non-C2PA features** (XMP editing, EXIF, thumbnails)
  are Gavin's call; this plan only keeps them out of the engine.
- **Who signs?** asset-io's examples rely on c2pa-rs's builder for signing
  and claim construction; ours replaces it. During the transition the
  facade should be able to use either, so Gavin's existing integration keeps
  working.
- **Unverified claims.** All of Gavin's performance figures and the fuzz
  hardening are untested by me. Step 1 and step 2 convert them into facts.

## 7. Questions for Gavin

1. Where should the merged code live, and who owns releases?
2. Is `Structure`/`Segment` something you would be happy to see become the
   shared `Layout` (with changes), or is there design intent behind them I
   have missed?
3. How much is the `Read + Seek` + callback API load-bearing for existing
   users (e.g. a c2pa-rs integration), versus a convenience we could provide
   through the facade?
4. Have the fuzz targets found anything yet, and what corpus/files should
   we treat as the fixture set for benchmarks?
5. Does the digest-request design (host-parallel, session-combined) cover the
   parallel shapes you care about, in particular BMFF fragments and Merkle
   hashing for very large files?
