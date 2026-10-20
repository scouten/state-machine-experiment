# File/Blob input: latency and memory

## Question and verdict

Does replacing whole-input byte-array snapshots with requested Blob/File slices
improve memory behavior without complicating the synchronous Rust architecture?

**The functionality works, but there is a tradeoff rather than a universal win.**
Blob/File inputs largely remove synchronous caller-side input-copy work.
File-backed browser slices introduce per-request asynchronous I/O overhead.
Chromium and Firefox provide evidence of smaller incremental read allocations,
not proof of a lower total peak-memory requirement. Signing still buffers and
copies its output. Node file-backed Blobs expose a separate runtime limitation.
No Rust session, scheduling or shared-memory changes are needed.

## Reproduction

From `js/`, with the real bindings, generated signing fixtures and the earlier
SDK benchmark prerequisites already available:

```sh
npm run benchmark:blob
```

Run `npm run benchmark:sdk` once first if `generated/benchmark.json`,
`benchmark-small.jpg` and the prepared existing-SDK artifacts are absent;
see the [SDK prerequisites](../README.md#sdk-to-sdk-benchmark).

The command runs [Node](../benchmarks/blob-node.mjs), prepares common signed and
unsigned assets, then runs [three browsers](../benchmarks/blob-browser.mjs).
Both use the same [experiment contract](../benchmarks/blob-experiment.mjs);
the browser adapters are in [blob-web.mjs](../benchmarks/blob-web.mjs).
It does not install dependencies or modify the sibling SDK checkout.

Raw samples are written to ignored `results/blob-{node,chromium,firefox,webkit}.json`.
They include timestamps, runtime/user agent, source/binary/input SHA-256 hashes,
SDK provenance, every duration, RSS baseline/peak and post-validation readings,
source request statistics and acceptance outcomes.

## Method

- macOS arm64, Node 24.18.0, Playwright 1.60.0; real Chromium, Firefox and WebKit.
- Existing SDK controls use the same prebuilt c2pa-node 0.9.9 and c2pa-web 0.15.3
  artifacts as the [earlier comparison](2026-10-16-sdk-performance.md).
  Recorded checkout/lockfile provenance does not certify their binary source.
- Inputs are the existing SDK's unsigned 61,720-byte JPEG, and the same JPEG
  padded after EOI to 8 MiB and 64 MiB. Signed fixtures are produced once by the
  experimental builder. These are hashing/copying workloads, not large-photo
  decoding benchmarks.
- Four variants: experimental byte array, Blob, File, and existing SDK.
  Browser Files are selected from actual disk paths through Playwright file
  inputs; the Blob variant is a slice of that File. Node Blob/File variants
  are **memory-backed**, constructed before measurement. Existing Node uses
  Buffer; existing web uses File. File/Blob representation is not an independent
  storage-backend choice in this experiment.
- Read and baseline ES256 sign; no OCSP, remote fetching or timestamp. Shared
  definition includes `digitalSourceType`; caller-owned WebCrypto signing.
- Three iterations per variant/size/operation/client-lifecycle: **576 measured
  operations** overall. Lifecycle is a newly created experimental Worker for
  each operation versus three operations reusing a Worker. All receive a small
  read warmup before measurement; these are not cold-start timings.
- The existing web control shares one SDK instance per size; rebuilding its
  reader/builder facade is **not** equivalent to restarting its Worker.
  Existing Node also retains its process-wide native execution environment.
  Do not use the control's lifecycle labels to compare Worker startup/release.
- Fixture construction, input conversion, module/Worker startup and warmup are
  excluded. Caller setup measures time until the async API returns its Promise;
  completion includes input posting, processing and result delivery. Signer
  execution is included. Validation and explicit frees are outside timing.
  Variants run sequentially in fixed order, not alternating randomized trials.
- Every experimental read must match the byte-array reference's full report
  and request counts, with maximum asset read at most 64 KiB. Build request
  accounting must match too. Every signed output is read `Trusted` by both
  implementations; each sign calls its signer once. Both readers reject a
  last-byte-tampered fixture at every size.

## Results

Final run: 2026-10-16. All **576 measured cases** passed their acceptance checks.
The Node regression suite also passed 7/7 tests, including clean rejection and
recovery for direct file-backed Blob input; source line coverage was 97.90%
overall and 99.13% in the shared driver.

### Instrumented duration

Median milliseconds from three **reused-client** samples per cell.
Each cell is **read / sign**. These small, fixed-order, memory-instrumented
samples are observations, not statistically established speed guarantees.
Small operations are particularly sensitive to timer resolution and runtime
state. Do not compare these values directly with the earlier benchmark as a
performance regression: warmup, pause, instrumentation and lifecycle differ.

| Environment | Source size | Byte array | Blob | File | Existing SDK |
| --- | --- | ---: | ---: | ---: | ---: |
| Node | 61,720 B | 1.47 / 2.08 | 1.32 / 2.14 | 2.14 / 1.67 | 2.88 / 21.92 |
| Node | 8 MiB | 10.82 / 24.54 | 12.28 / 20.95 | 13.23 / 23.74 | 11.79 / 33.59 |
| Node | 64 MiB | 54.23 / 116.99 | 46.47 / 86.58 | 55.69 / 89.05 | 53.09 / 74.87 |
| Chromium | 61,720 B | 1.90 / 1.30 | 4.80 / 4.20 | 5.70 / 4.40 | 3.30 / 4.10 |
| Chromium | 8 MiB | 29.40 / 35.30 | 45.80 / 40.50 | 45.70 / 38.90 | 33.70 / 37.50 |
| Chromium | 64 MiB | 211.80 / 265.50 | 320.10 / 316.10 | 319.30 / 314.20 | 330.60 / 336.70 |
| Firefox | 61,720 B | 12 / 4 | 16 / 6 | 14 / 6 | 24 / 7 |
| Firefox | 8 MiB | 211 / 208 | 225 / 219 | 225 / 223 | 241 / 228 |
| Firefox | 64 MiB | 1,628 / 1,673 | 1,699 / 1,718 | 1,693 / 1,746 | 1,858 / 1,866 |
| WebKit | 61,720 B | 3 / 3 | 8 / 9 | 8 / 8 | 3 / 6 |
| WebKit | 8 MiB | 37 / 42 | 65 / 50 | 66 / 54 | 47 / 50 |
| WebKit | 64 MiB | 272 / 324 | 461 / 345 | 493 / 361 | 440 / 436 |

For the 64 MiB File path versus bytes:

- Chromium read duration increased about **51%**, signing about **18%**.
- Firefox increased about **4%** for both operations.
- WebKit increased about **81%** reading and **11%** signing.
- Node's memory-backed File sign median was about **24% lower**, but its read
  median was close. This is not evidence about Node filesystem-backed sources.

The caller-side setup cost falls: 64 MiB byte-array reads took approximately
2.72 ms in Node, 6.60 ms in Chromium, 5 ms in Firefox and 2 ms in WebKit before
returning the Promise. Blob/File setup was approximately 0–0.02 ms in these
read samples. Zero means below the clock's resolution, not no work.

Fresh experimental Workers, after the same small-read warmup, showed the same
broad tradeoff rather than eliminating it. For example, Chromium 64 MiB reads
were 209.20 ms for bytes and 311.80 ms for File; Firefox 1,655 / 1,696 ms;
WebKit 282 / 459 ms. Startup is deliberately excluded.

At equivalent file input, the new browser path is not uniformly faster than
the existing SDK: Chromium and Firefox read medians were lower, but WebKit's
File read was slower. The engines still perform unequal validation and emit
different-sized manifests; retain the earlier SDK comparison's caveats.

### Sampled incremental RSS

Median **sampled peak minus pre-operation baseline**, in MiB, for 64 MiB
reused-client operations. This is not total peak memory or bytes allocated.

| Environment | Operation | Bytes | Blob | File | Existing SDK |
| --- | --- | ---: | ---: | ---: | ---: |
| Node | Read | 0.17 | 0.52 | 0.41 | 0.02 |
| Node | Sign | 4.19 | 112.52 | 10.50 | 0.00 |
| Chromium | Read | 128.27 | 3.56 | 1.84 | 190.23 |
| Chromium | Sign | 192.44 | 128.19 | 128.13 | 189.30 |
| Firefox | Read | 128.61 | 19.00 | 18.39 | 95.75 |
| Firefox | Sign | 352.23 | 245.16 | 281.09 | 83.83 |
| WebKit | Both | Unavailable | Unavailable | Unavailable | Unavailable |

Chromium and Firefox read deltas are consistent with avoiding full-input
snapshot/clone allocations. They do **not** establish smaller absolute memory:
for example, Chromium's read baseline was approximately 906 MiB for bytes
versus 2,393 MiB for File, reflecting previous operations, validation and GC.
Those baseline differences preclude treating the delta table as a ranking of
total SDK memory requirements.

Node's large read baselines grew from roughly 601 MiB in the byte group to
1,787 MiB in the File group, despite fresh Workers in part of the run.
The existing SDK handles, validation work, JS GC and allocator history are not
isolated. Tiny deltas therefore do not mean negligible allocations; **this run
does not establish a Node memory win or a leak diagnosis**.

Signing still shows substantial browser allocation growth with File inputs.
Post-validation deltas are unstable: Chromium's large signing readings included
about 396 MiB for bytes, 407 MiB for Blob and 191 MiB for File. These are affected
by validation and GC, not evidence of a stable retained-memory budget.

## What the memory measurements mean

Node uses process RSS, including all Worker isolates, sampled every 5 ms and at
the endpoint. A fresh process per size excludes fixture-generation allocation
history. Browser sampling sums the launched browser's descendant-process RSS
every 25 ms plus `ps` execution time and at the endpoint.

These are **sampled resident-memory observations, not exact allocation peaks**:

- Short-lived peaks may be missed; RSS includes allocator caches, native
  libraries, code and unrelated browser activity. Summed RSS may count shared
  pages more than once. Sampling itself can perturb duration.
- Variant and operation order, GC and cross-validation affect later baselines.
  A common signed byte fixture and validation clients remain resident.
  Absolute RSS values do not isolate the representation's cost.
- Post-validation readings occur after releasing the measured result, but
  validation itself allocates. They are not retained heap or leak measurements.
  No per-operation forced GC is performed; the Node child only forces GC after
  all samples to finalize existing native handles that have no public free API.
- Wasm memory capacity/high-water allocation is not separately exposed through
  the public client. Browser RSS cannot attribute retained memory to Wasm.
- **WebKit RSS is incomplete on this macOS setup.** Its WebContent, GPU and
  networking XPC processes are reparented to PID 1. A separate 128 MiB allocation
  probe confirmed the content process lies outside the launcher's descendant
  tree. Near-zero reported deltas are unusable, not evidence of low memory.

Thus we can report incremental Chromium/Firefox read-memory evidence and
latency, but cannot claim cross-engine peak-memory parity or a leak budget.

## Node file-backed Blob failure

`fs.openAsBlob()` cannot be cloned into a Worker on Node 24.18.0: it rejects
with `ERR_INVALID_STATE: File-backed Blobs are not cloneable`. The earlier
client normalized all Blob/File inputs with a full-range `slice`. For this
file-backed value, slicing bypassed Node's clone guard and reading it in the
Worker aborted the process with:

```text
FATAL ERROR: v8::HandleScope::CreateHandle() Cannot create a handle without a HandleScope
```

A minimal Worker-only JavaScript reproduction, without Neon or Rust, reproduced
the failure. The client now posts the immutable original Blob/File rather than
unnecessarily slicing it. Direct `openAsBlob()` input therefore rejects cleanly,
and a regression test verifies the client can subsequently read valid bytes.
No full-file buffering fallback silently replaces unsupported file-backed input.

Do not infer support for every Node filesystem-backed Blob wrapper: derived
values may still expose the runtime bug. Browser-selected Files and memory-backed
Node Blob/File values are the tested cases. A Node file-path host should be an
explicit host design, not a workaround that disguises whole-file buffering.

## Decisions and next trigger

1. Keep File/Blob support: it closes an input-surface gap and avoids eager
   whole-source materialization, but do not promise it is always faster.
2. Preserve byte arrays for callers already holding bytes. Do not silently
   convert them to Blobs or transfer/detach caller storage.
3. Investigate bounded read-ahead/coalescing if slice overhead matters for the
   workload. Preserve range validation and the bounded-memory source contract.
4. Before claiming memory parity, use allocator/GC-aware, isolated measurements
   and a method that includes WebKit XPC content processes. Add direct Wasm
   capacity observation in benchmark-only instrumentation if attribution is
   required.
5. Signing output buffering remains the next major memory surface. Measure
   output sinks separately rather than describe Blob input as end-to-end streaming.
6. Do not add shared memory, a custom scheduler or Rust async machinery based on
   these results. None addresses missing action semantic validation, which
   remains a separate [domain parity gap](2026-10-16-validation-parity.md).

## Original acceptance outline (historical)

Migrated from the combined findings. The completed results above supersede
this prospective outline; unresolved measurement limitations remain explicit.

The shared JS `read` and `sign` entry points now accept `File`/`Blob` as well as
byte arrays. The client sends the immutable Blob/File, and the Worker reads
requested ranges with `slice(...).arrayBuffer()`. Neither names nor MIME hints
change the JPEG-only handler or signing definition. Signing still returns
buffered byte arrays. The Rust sessions and bindings are unchanged.

The shared contracts cover small and 64 MiB Blob/File read and signing parity,
unchanged request accounting, tampering, malformed input, invalid definitions
and signer failure/recovery. Direct host tests prohibit whole-Blob materialization
and check requested ranges, short reads, failed source reads and session cleanup.
This establishes input support, not a measured memory or speed improvement.
Validation passed six Node tests and all 12 read / 14 signing contract checks
in Chromium, Firefox and WebKit, with both JSON and binary Wasm transport.
Each browser also passed the existing 16 paired boundary samples. Node's native
test coverage measured 97.90% source lines overall and 99.13% in the shared
driver; this is functional coverage, not memory or performance evidence.

Compare the current byte-array path against Blob/File-backed reads across input
sizes and baseline signing:

- Send the Blob to the Worker without an application-side whole-asset
  `arrayBuffer()` conversion. Answer session ranges using
  `slice(offset, offset + length).arrayBuffer()`.
- Keep output buffering explicit: a Blob input does not make a signing result
  streaming, nor remove the copy into Wasm. Bound temporary source reads rather
  than claim end-to-end zero-copy.
- Reuse the current complete-report, trusted read-back, tamper and failure
  contracts for byte arrays, Blobs and Files in Node and all three browsers.
  Preserve caller-owned input behavior and filename/MIME handling policy.
- Instrument range sizes and total requested/copied bytes. Verify the source
  path never requests the whole large asset and respects the current 64 KiB
  maximum asset-read size; do not count repeated hash reads as unique bytes.
- Measure warm latency, baseline/peak/retained memory and Wasm memory size
  across sizes and repeated operations, with one client and controlled
  concurrency. Include Worker memory; application JS heap alone is not a
  valid peak-memory proxy. Record measurement availability and limitations per
  engine instead of substituting an unsupported memory estimate.
- Repeat the existing SDK comparison with equivalent Blob/File inputs where
  supported. Keep validation-depth and output-policy differences visible.

Success means preserved functional contracts, verified bounded source requests,
and a measured memory/latency comparison, **not a predetermined memory win**.
Blob backing, browser storage and Wasm high-water allocation may limit the
benefit. No core async conversion, custom scheduler or shared-memory protocol
is required to test this.
