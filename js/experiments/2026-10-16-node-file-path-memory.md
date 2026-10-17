# Node file-path input: parity and memory

Subsequent work implemented the destination-path capability proposed here;
see the separate [file-output proof](2026-10-16-node-file-output-memory.md).
The measurements below remain the original buffered-output comparison.

## Question and decision

Can the shared state-machine host accept an ordinary Node file path, avoid
whole-source loading/cloning, preserve the existing read/sign slice, and
compete with the current SDK on memory and latency?

**Yes for this input slice; not full SDK parity or constant-memory signing.**
The Node client now accepts the existing SDK's `{ path: string }` input shape.
Its Worker owns the file handle and fulfills positioned byte-range requests
through the same shared read/build loops used by bytes and browser File/Blob
sources. No Rust session, dependency, scheduler or native binding changes were
needed.

For a 64 MiB asset, the experimental path input reduced median process peak
RSS from **328.2 to 103.9 MiB for reads** and **743.7 to 492.0 MiB for signing**,
relative to loading a Buffer and calling the same API. Against the existing
SDK's path input, the experimental reader used less memory, but its signer
still used **about 24% more**. The next memory question is buffered output,
not Node Blob support.

This is a new experiment, not a revision of the historical
[File/Blob report](2026-10-16-file-blob-memory.md). The stronger isolation and
current SDK baseline mean its numbers should not be treated as a controlled
before/after comparison with that report.

## Implementation and API boundary

```js
const client = createClient(); // from src/node/client.mjs
try {
  const result = await client.read({ path: "./input.jpg" }, { settings });
  const signed = await client.sign({ path: "./input.jpg" }, definition, signer);
  // signed.asset / signed.manifest are still buffered Uint8Array values.
} finally {
  await client.dispose();
}
```

- The Node facade resolves the path before its first await and snapshots the
  descriptor, not the file contents. It sends only that descriptor to the
  Worker. Buffer/Uint8Array ownership and snapshot semantics are unchanged.
- The Worker opens the regular file when its operation reaches the front of
  the queue, obtains the length, reads exact ranges with explicit positions,
  handles partial reads, and closes before success/error replies.
- Invalid ranges, missing/non-file sources and short reads reject explicitly.
  Session errors and signer failures also close the source. Abrupt client
  disposal terminates the Worker; it rejects active/queued operations and
  the OS releases its file handles. No output file is written by this API.
- Keep the input unchanged until completion. A path is not an immutable
  snapshot: truncation is detected by short reads, but every concurrent
  same-length rewrite is not. Names/MIME hints still do not select a new
  format or set manifest titles; this slice remains JPEG-only.
- The shared service opens/closes a platform source. The shared driver owns
  session progression, not Node filesystem policy. Browser sources remain
  byte arrays or Blob slices. The input seam does not expose arbitrary caller
  functions across Workers.
- Tested reader requests are at most **64 KiB**; the existing Rust file
  builder's source-copy limit is **1 MiB** (`COPY_CHUNK_LEN`). The initial test
  incorrectly assumed both were 64 KiB; it was corrected to assert the actual
  existing bounds, not to change the Rust policy.

Relevant implementation: [Node facade](../src/node/client.mjs),
[file source](../src/node/source.mjs), [shared service](../src/shared/service.mjs)
and [shared driver](../src/shared/drive.mjs).

This matches an existing Node input shape, not the complete legacy
`Reader`/`Builder` API. File/Blob remains important for browsers; a Node
`fs.openAsBlob()` Worker path is neither required nor used.

## Reproduction and provenance

Run from `js`, after building the experiment bindings and the reference SDK:

```sh
npm run fixtures
# Establish the existing SDK benchmark definitions/settings and fixture metadata:
node benchmarks/sdk-node.mjs
npm run benchmark:path
```

The benchmark command refreshes the SDK preparation/provenance first. It does
not rebuild the reference native binary; use the
[baseline refresh instructions](2026-10-16-sdk-baseline-refresh.md) after
changing that checkout.

- Harness: [path-node.mjs](../benchmarks/path-node.mjs).
- Runtime: Node **24.18.0**, macOS arm64.
- Reference: c2pa-js `20531aa26a219fee35937d3a51a77ebf7a0c03ef`,
  c2pa-node **0.9.10**, c2pa-rs **0.91.3**, rebuilt release native artifact.
- Final run completed **2026-10-16T23:09:13.478Z**.
- Raw receipt: ignored `js/results/path-node.json`, including all 72 samples,
  source/binary/fixture fingerprints, input sizes, baseline/endpoint memory,
  process high-water RSS, externally sampled RSS, request counts, output
  sizes, signer counts and validation records.
- Receipt SHA-256:
  `c4404133bbd9b0b2ce1f33ddeae2259c8f4af6a0e125413b6a85c913f4db34b1`.

Selected recorded artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| Reference Node native binary | `f357e42770bc0e5c521a1593cdca966eb07eabd181c2b0ea75a1c3c3b28c650f` |
| Experimental reader native binary | `ac4a470c71eeff38fdac395cb083d7ecbe6a4538c6c9d91130ef545a0ef66f91` |
| Experimental signing native binary | `852a727a279ff5a9579ee2b05ab7ff7d3fc1b21ae32557605ba53eb3b377520a` |
| Benchmark source | `978e6486d3cc62a8986a2b85acb060f19077cefc9f4e448093dc323c4e0ea5cc` |

All recorded source and reference artifact hashes were checked against disk
after the final run. Temporary inputs/outputs were removed after validation;
input hashes and lengths remain in the receipt.

## Method

**72 measured operations**:
3 sizes x 2 operations x 2 SDKs x 2 input representations x 3 iterations.

1. Use the existing SDK's real 61,720-byte unsigned thumbnail JPEG, plus
   versions padded to 8 MiB and 64 MiB. Every variant hashes the full relevant
   asset, including padding. Generate trusted signed fixtures before measuring.
2. For each sample, start a **fresh Node process** loading only the SDK under
   test. Warm its matching operation on the small asset, then request main
   isolate GC before taking the baseline. No forced GC occurs in the interval.
   This is a warmed operation in a fresh process, not a cold-start measurement.
3. Alternate/reverse variant order by iteration. All cells use the same files.
   Bytes input includes `readFile` in the measured interval; path input passes
   `{ path }` directly. The old SDK receives its public path/Buffer shapes.
4. Time public read through JSON reporting, or builder creation/signing through
   buffered output return. Both signers use the same application-owned
   WebCrypto ES256 test key, raw-signature callback and public certificates.
   Both SDKs return memory-backed output; neither gets an output-file advantage.
5. Read child-process RSS externally with `ps` every 10 ms plus command latency,
   including baseline and completion endpoints while results are still held.
   This covers all Worker isolates in that PID and still runs when a native
   operation blocks its main JS thread. Also capture
   `process.resourceUsage().maxRSS`, normalized from KiB to bytes.
6. Stop timing/sampling **before** writing signed output for independent
   validation. A separate parent process reads every signed output using both
   SDKs. Its fixtures, validators and memory do not enter the child measurement.
   Dispose the experimental Worker and GC native handles only after measurement.
7. Do not run another test suite/build alongside the final measurement.

The peak tables below use **process-lifetime OS high-water RSS**, not JS heap,
an operation-only allocation counter or RSS delta. Lifetime includes startup
and the small warmup; for small inputs, those dominate. The receipt also
contains external sampled peaks and per-operation baselines. The two peak
measures were close in this run. Baseline RSS was roughly 70 MiB for reads and
experimental signing, and 76 MiB for existing signing.

## Acceptance and parity evidence

The run fails rather than recording success if any of these checks fail:

- Every measured read returns `Trusted` and the requested title/actions, with
  signature, trusted credential and data-hash success codes.
- Experimental path/bytes reads produce **identical complete reports and
  request accounting**. Existing SDK path/Buffer complete reports also match
  each other for every fixture.
- Unsigned files return `null` in both readers.
- Tampered files are `Invalid` with `assertion.dataHash.mismatch` in both.
- **All 36 measured signing outputs** are independently `Trusted` in both
  readers. Each invokes the application signer exactly once.
- Experimental signing request accounting is identical for paths and bytes,
  with source reads at most 1 MiB; reads stay at most 64 KiB.
- Output sizes match the persisted bytes used for cross-validation.

This adapts the current public SDK's file-asset contract, not a substitute
decoder or an internal Rust-only benchmark. The SDKs' reports are not asserted
identical **to each other**, nor are their generated manifests byte-identical.
For example, the large signed assets were 67,110,727 bytes experimental versus
67,169,584 existing; manifests were 1,851 versus 60,708 bytes. Existing SDK
defaults/reservation/reporting work are not normalized away.

Focused validation also passed:

- **12 Node tests**, including relative-path descriptor mutation, concurrent
  positioned reads, invalid ranges, truncation, missing/directory sources,
  malformed JPEG/definition, signer failure, queue recovery, unchanged input,
  cleanup before success/error replies, and disposal during a path-backed build.
- Node source coverage **100% lines/branches/functions**; tested Node/shared
  modules **98.16% lines** overall.
- Chromium, Firefox and WebKit: all **12 read + 14 signing checks**, both
  JSON/binary contracts and 16 paired boundary samples per browser.
  This protects the shared-source refactor; it is not a new browser memory run.

## Results: median latency

Milliseconds, three samples per cell. Loading bytes from disk is included;
fixture generation, validation, output persistence and teardown are excluded.

| Size / operation | Experimental bytes | Experimental path | Existing Buffer | Existing path |
| --- | ---: | ---: | ---: | ---: |
| 61,720 B read | 0.81 | 1.47 | 1.19 | 1.13 |
| 61,720 B sign | 0.83 | 1.53 | 14.94 | 14.97 |
| 8 MiB read | 8.83 | 7.25 | 8.39 | 7.01 |
| 8 MiB sign | 18.03 | 14.17 | 26.62 | 25.45 |
| 64 MiB read | 66.54 | 44.93 | 56.42 | 53.09 |
| 64 MiB sign | 122.87 | 100.24 | 103.39 | 106.79 |

For the experimental host, 64 MiB path input reduced median read time by
**32.5%** and signing time by **18.4%** versus its bytes input in this run.
Small paths pay more asynchronous filesystem round trips than in-memory
sources. Against existing paths, the large experimental read was about 15%
quicker and sign about 6% quicker here; three local samples and unequal
validation/output policies do **not** establish a general performance win.

## Results: median process peak RSS

MiB, including the process baseline, OS high-water measurement.

| Size / operation | Experimental bytes | Experimental path | Existing Buffer | Existing path |
| --- | ---: | ---: | ---: | ---: |
| 61,720 B read | 70.5 | 70.8 | 70.8 | 70.5 |
| 61,720 B sign | 71.1 | 70.7 | 76.5 | 76.4 |
| 8 MiB read | 103.4 | 78.9 | 94.9 | 79.0 |
| 8 MiB sign | 168.6 | 142.4 | 133.0 | 116.4 |
| 64 MiB read | 328.2 | 103.9 | 263.1 | 134.8 |
| 64 MiB sign | 743.7 | 492.0 | 524.6 | 396.5 |

For context, 64 MiB median external sampled peak **minus each sample's baseline**:

| Operation | Experimental bytes | Experimental path | Existing Buffer | Existing path |
| --- | ---: | ---: | ---: | ---: |
| Read | 257.8 | 33.8 | 192.6 | 64.3 |
| Sign | 673.6 | 422.0 | 448.8 | 320.7 |

These are deltas of independently sampled processes, not allocation counts.
They are substantially more interpretable than the earlier sequential
same-process Blob experiment's contaminated baselines, but still reflect
allocator/GC behavior and warmup.

### What this establishes

- **Use Node paths for disk inputs.** At 64 MiB the experimental path saved
  about **224 MiB / 68.4%** of total peak RSS for reading and
  **252 MiB / 33.8%** for signing versus bytes. The old SDK also benefits from
  paths: about 49% lower read peak and 24% lower signing peak.
- **Read-side memory is competitive on this slice.** At 64 MiB, experimental
  path read peak was about **23% lower** than the existing path reader.
  At 8 MiB, they were effectively equal.
- **Signing memory remains a concern.** Experimental path signing still used
  about **24% more total peak RSS** than existing path signing at 64 MiB.
  Avoiding input snapshots does not remove Worker output growth, final output
  copying/cloning, or JS/native request payload copies. This is an observable
  outcome, not a measured attribution of each allocation.
- **Bounded source requests do not prove constant total memory.** The large
  path reader still added roughly 34 MiB above baseline, and signing far more.
  Returned output size alone is not a good estimate of signing peak.

## Limits and next proof

- Three iterations, local sequential runs, warm filesystem cache, one Node/
  macOS/arm64 configuration, small JPEG corpus with synthetic padding. No
  confidence intervals, production throughput, concurrency or cold-disk claim.
- External sampling gives only 3-8 points per operation here; brief spikes can
  be missed. OS high-water helps, but includes startup/warmup and is not a
  resettable operation-only peak. RSS is not allocation volume, ownership,
  retained/leaked memory, or kernel filesystem-cache footprint.
- Endpoint JS heap/external/ArrayBuffer gauges in the receipt describe the
  main isolate, not a complete Worker/native breakdown. Only process RSS
  includes all isolates.
- No full c2pa-js feature or validation parity: ordinary action semantic
  validation remains a [known Rust gap](2026-10-16-validation-parity.md).
  These fixtures use a valid `digitalSourceType` to keep that gap out of the
  positive benchmark. Offline JPEG/ES256 is still the supported shared slice.
- No output sink, atomic output-file API, streaming returned asset, timestamp,
  identity, broader format support, compatibility facade, or Rust validation
  fix was introduced by this proof.

**Next bounded experiment:** compare file-input/file-output signing in both
SDKs, using the existing SDK's destination-path support as the control.
Keep bounded source/output requests and caller-owned signer callbacks, prove
trusted read-back and failure-safe destination handling, then repeat isolated
RSS/latency measurements. That tests the remaining material signing-copy
problem while adding another capability the existing SDK already has.
