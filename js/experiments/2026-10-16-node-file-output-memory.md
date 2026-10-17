# Node file-output signing: parity and memory

## Question and result

Can the shared Node host sign directly to a destination file, preserving the
baseline signing contract without buffering/cloning the whole output, and how
does that compare with c2pa-node's existing file destination?

**Implemented and exercised.** A fourth argument supplies the destination:

```js
const result = await client.sign({ path: "./input.jpg" }, definition, signer,
  { path: "./signed.jpg" });
// result.path is absolute; result.outputBytes is the signed file length.
// manifest, exclusions and stats remain available; asset is absent.
```

For a 64 MiB source, the new architecture's median process peak RSS fell from
**502.7 MiB buffered to 157.8 MiB file-backed**, a **68.6% reduction** in this
run. Existing SDK file output peaked at **332.5 MiB**. The tradeoff was latency:
experimental file output took **110.43 ms**, versus **96.25 ms** buffered and
**104.73 ms** for the existing SDK's file output.

This is input/output capability parity for the shared offline JPEG/ES256 slice,
not full SDK, validation, filesystem-policy or byte-for-byte manifest parity.

## Implementation and ownership

- [Shared client](../src/shared/client.mjs): snapshots destination options
  before awaiting startup; default buffered return remains unchanged.
- [Node client](../src/node/client.mjs): resolves a nonempty destination path,
  assigns an unpredictable same-directory temporary name, and tracks active
  temporary paths so `dispose()` can clean them after terminating the Worker.
  Browser clients explicitly reject file destinations.
- [Shared service](../src/shared/service.mjs): opens/closes an output host
  alongside the input host. The same session loop runs in both environments.
- [Shared driver](../src/shared/drive.mjs): delegates positioned output writes,
  read-back for hard-binding hashing, length and completion to the output host.
  Its existing growable byte-array behavior is now the default memory host.
- [Node output host](../src/node/output.mjs): exclusively creates a `wx+`
  temporary file, mode `0600` subject to umask, reads/writes exact ranges,
  handles partial I/O, truncates to the logical length, closes and renames on
  successful finish. Returns path/length metadata, not asset bytes.

No Rust, native binding, dependency, scheduler or signing-algorithm changes.
The existing Rust builder still owns the embedding plan, bounded copy requests,
hard-binding hash and final manifest. The host never materializes the whole
signed asset in the file-output path. Individual request payloads and the
manifest remain owned/copied values; this is not zero-copy I/O.

### Destination and failure contract

- Parent directory must exist. Existing destination contents remain intact if
  the build, signer or final rename fails. Temporary files are removed.
- Successful signing replaces an existing destination by rename rather than
  truncating it first. Destination symlinks are replaced, not followed.
  Existing permissions/metadata are not preserved.
- Input and output can identify the same path on the tested macOS filesystem:
  source reads complete before replacement. Do not mutate source files during
  signing. Cross-platform rename semantics still need their own validation.
- `await client.dispose()` terminates the Worker, then removes its tracked
  temporary paths. A late caller-owned signing callback does not post back.
- Cancellation racing with commit may reject the operation after rename has
  succeeded; a committed destination is not rolled back. File output is an
  external side effect, unlike the buffered result.
- No `fsync`/crash-durability promise. Killing the whole process or a machine
  crash can leave a temporary file. Ordinary build failure/disposal cleanup
  is tested; recovery scanning/cleanup after process death is not implemented.
- No path-based output is added to browsers. No arbitrary stream interface,
  file-descriptor sharing, generalized filesystem abstraction or compatibility
  shim was needed for this slice.

## Reproduction and baseline

Run from `js`, with generated fixtures/benchmark metadata and both native SDK
bindings built, as described in the
[file-input proof](2026-10-16-node-file-path-memory.md):

```sh
npm test
npm run test:browser
npm run benchmark:output
```

The new command reuses [path-node.mjs](../benchmarks/path-node.mjs) with
`--file-output`; the original `benchmark:path` remains available. This avoids
duplicating the process-isolation and memory-sampling harness.

- Node **24.18.0**, macOS arm64.
- Reference c2pa-js commit
  `20531aa26a219fee35937d3a51a77ebf7a0c03ef`,
  c2pa-node **0.9.10**, c2pa-rs **0.91.3**, rebuilt release native binary.
- Reference native SHA-256:
  `f357e42770bc0e5c521a1593cdca966eb07eabd181c2b0ea75a1c3c3b28c650f`.
- Final run: **2026-10-16T23:29:05.203Z**.
- Raw receipt: ignored `js/results/output-node.json`.
- Receipt SHA-256:
  `c3f132fc5a1a438b9bb46ed9369f1965275b9aa967ea3c97a68ccbd2c123ad91`.
- Harness SHA-256:
  `b70805a4829b01b00c3c4e72cc3959f07648fae9269dac625a2f851602b789fc`.
- Node output host SHA-256:
  `f809d165de818f56be321475552543a49ce44d8ef066b0d251063d75fef60ad5`.

The receipt contains source/native artifact fingerprints, all individual
measurements, baseline/endpoint/high-water memory, external RSS samples,
input hashes, output sizes, signer counts and request statistics.
All recorded source/reference artifact hashes were verified against disk.
Benchmark temporary inputs, outputs and warmup files were removed on completion.

## Method and acceptance

**36 measured signing operations**:
3 sizes x 2 SDKs x 2 destinations x 3 iterations.

The source is the existing SDK's 61,720-byte thumbnail JPEG, also padded to
8 MiB and 64 MiB. All measured variants receive **file-path input**.

Each sample runs in a fresh child process loading only its measured SDK.
Warm its matching signing/destination path on the small file, request GC in
the main isolate, then take the baseline. No forced GC occurs during timing.
Variants are measured in alternating/reversed order.

Use each SDK's public callback signer with the same application-owned WebCrypto
ES256 test key/certificates and baseline definition. The definition includes a
valid created-action `digitalSourceType`. Existing SDK receives
`Builder.signAsync(..., { path: input }, { path: output })` for file output;
the experimental host receives the new fourth argument.

Time through signing completion, including builder creation, signing callback
and, for file destinations, all output I/O/close and experimental rename.
Buffer variants stop once bytes return; their later persistence is outside
timing. Thus the outputs reach their requested public endpoints, **not the
same durability endpoint**. Disk-flushed durability is not measured.

Sample process RSS externally using `ps` every 10 ms plus command latency and
endpoints. Capture OS process-lifetime high-water RSS with
`process.resourceUsage().maxRSS`, normalized from KiB. Main-thread native work
does not block the external sampler. No other test suite was run alongside
the measurement.

After sampling stops, persist buffered outputs if needed. A separate parent
process reads each output with both readers. Parent validation/fixture memory
is outside child RSS.

Acceptance passed:

- **All 36 signed outputs Trusted in both readers**, including signature,
  trusted credential and data-hash success codes, title and actions.
- Exactly **one signer callback per measured operation**.
- Experimental output host does not return `asset` for file destinations;
  path/length metadata matches the independently read file.
- Experimental request accounting is identical between buffered and file
  outputs; maximum source read is 1 MiB for large inputs.
- Existing path/Buffer reader results match for source fixtures; unsigned
  files return `null` and tampered fixtures produce data-hash mismatch in both.
- Experimental and reference large outputs remain 67,110,727 and 67,169,584
  bytes respectively. Different manifest reservation/default behavior is
  preserved, not normalized away.

Focused regression proof:

- **14 Node tests passed**, covering exact positioned read/write behavior,
  overwrite, missing parent, invalid destinations, exclusive-create collision,
  rename failure, signer/definition failure, destination preservation,
  symlink replacement, same input/output path, bytes-to-file signing,
  destination snapshotting, trusted read-back and disposal cleanup.
- Node/shared source coverage **98.52% lines** overall; output host **100%
  lines / 83.33% branches**. Short/failed native I/O branches are not all
  injected; real positioned operations and cleanup paths are exercised.
- Chromium, Firefox and WebKit passed all **12 read + 14 signing checks**,
  both JSON/binary contracts and 16 paired boundary samples per browser.
  These protect the extracted default memory-output host; no browser file
  destination or new browser memory result is claimed.

## Results

Medians of three samples. All variants use source file paths.

### Signing latency (milliseconds)

| Source size | Experimental buffered | Experimental file | Existing buffered | Existing file |
| --- | ---: | ---: | ---: | ---: |
| 61,720 B | 1.43 | 1.95 | 14.33 | 14.60 |
| 8 MiB | 13.14 | 14.73 | 24.95 | 25.40 |
| 64 MiB | 96.25 | 110.43 | 105.96 | 104.73 |

At 64 MiB, experimental file output costs about **14.7%** more time than its
buffered endpoint, while avoiding a whole-asset return. It was about **5.4%**
slower than the reference file-output endpoint in this local run.
The small/medium speed differences do not establish general SDK performance
equivalence: the existing SDK performs different default/reporting work and
the experimental validator retains known gaps.

### Process peak RSS (MiB)

OS process-lifetime high-water RSS, including startup and small warmup:

| Source size | Experimental buffered | Experimental file | Existing buffered | Existing file |
| --- | ---: | ---: | ---: | ---: |
| 61,720 B | 70.9 | 70.5 | 76.6 | 76.2 |
| 8 MiB | 144.1 | 111.0 | 116.7 | 108.3 |
| 64 MiB | 502.7 | 157.8 | 396.7 | 332.5 |

External sampled peak minus each sample's baseline, median MiB:

| Source size | Experimental buffered | Experimental file | Existing buffered | Existing file |
| --- | ---: | ---: | ---: | ---: |
| 8 MiB | 74.2 | 40.8 | 40.7 | 32.5 |
| 64 MiB | 432.7 | 87.5 | 320.7 | 256.6 |

RSS means resident set size: physical process memory, including the Node
Worker/native allocations, not just JS heap or output size.

### Interpretation

- File output removes the largest signing memory penalty in this experiment.
  At 64 MiB the experimental peak falls by about **345 MiB / 68.6%** versus
  its buffered destination, and is about **53% below** the existing SDK's
  file-output peak.
- At 8 MiB the file-output architectures are close: 111.0 versus 108.3 MiB.
  Small-file peaks mostly reflect runtime/warmup baselines.
- The existing SDK also benefits from avoiding a returned output buffer:
  about **16.2%** lower peak at 64 MiB. Do not attribute its remaining memory
  to a specific Rust buffer without allocation tracing.
- Bounded host I/O is **not constant total memory**. The experimental 64 MiB
  file-output case still adds roughly 88 MiB over baseline. Request payload
  conversions, native/Worker allocators, GC and native handle lifetimes remain;
  this experiment measures outcomes, not a full allocation breakdown.
- Unlike the earlier file-input-only proof, both SDKs now get their
  file-output capability in the comparison. Historical report measurements
  remain unchanged; compare columns within this run for the controlled result.

## Limits and next step

Three local samples per cell, one Node/macOS configuration, warm filesystem
cache, synthetic padding, no concurrent operations or cold-start measurement.
There are only 3-8 external RSS samples per operation; high-water RSS helps
catch spikes but includes process startup/warmup. Neither measure is a leak/
retained-memory test, allocation-volume counter, filesystem-cache budget or
durability measurement.

Full SDK parity remains blocked by broader formats/features and the
[known Rust action-validation gap](2026-10-16-validation-parity.md). This work
does not fix or conceal it.

Keep Node file input/output as the preferred large-file path. The next useful
parity work should target another existing SDK behavior with positive and
negative differential cases, especially validation correctness; further
memory optimization should be driven by allocation evidence rather than a
zero-copy or constant-memory claim.
